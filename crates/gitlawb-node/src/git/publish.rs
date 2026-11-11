//! The publication boundary: WHO wrote, and HOW FAR that write got.
//!
//! Four lifecycle defects on this branch shared one root cause. A resource was
//! tracked by a coarse state — "release started", "the path exists", "a row with
//! this name exists" — when the safety question was about the IDENTITY and the
//! PUBLICATION STAGE of one specific write attempt. A tail replicated refs from
//! an attempt that had not dispatched a PUT; a read served a tree whose
//! generation nobody had confirmed; a fork claimed a concurrent attempt's row and
//! deleted a successor's object; a response-loss failure was compensated as if it
//! proved non-publication.
//!
//! This module is the vocabulary that makes those questions answerable, and it is
//! deliberately free of any object-storage type:
//!
//! - [`PublishAttemptId`] — minted before the request is built, carried with the
//!   bytes as user metadata, read back off the store to decide whether what is
//!   published is THIS attempt's work.
//! - [`PublishStage`] / [`PublishStageCell`] — how far one attempt got, observable
//!   from outside the future that is performing it, so a CANCELLED attempt can
//!   still be classified.
//! - [`UploadError`] — what the client KNOWS about dispatch and commit, not just
//!   which HTTP status came back. Destructive compensation is licensed only by
//!   [`UploadError::proves_not_published`].
//!
//! # Porting note (#79)
//!
//! PR #79 (`feat/storage-abstraction`) deletes `git/tigris.rs` and replaces it
//! with a `BlobStore`/`RepoArchive` layer. Everything in this file is
//! backend-agnostic on purpose and is meant to survive that swap unchanged: a new
//! backend supplies its own error classifier (the one in `tigris.rs` is a single
//! private function) and keeps these types as the contract its callers read.

use std::sync::Mutex;

/// A durable identity for ONE publish attempt.
///
/// The point is reconciliation. A conditional PUT whose response was lost leaves
/// the client unable to say whether its bytes committed; an attempt id stored
/// alongside those bytes turns that into a question the store can answer, because
/// "is the published object mine?" is decidable where "did my request succeed?"
/// is not.
///
/// Fork creation passes the DB row id it is about to insert, so the object, the
/// on-disk clone and the database row are all stamped with the same attempt
/// identity and every cleanup can be made conditional on still owning all three.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishAttemptId(String);

impl PublishAttemptId {
    /// A fresh identity for an attempt that has nothing else to be named after.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Name the attempt after a caller-owned identity — fork creation uses the
    /// `record.id` it is about to insert, which is what ties the object back to
    /// the exact row rather than to the logical owner/name.
    pub fn from_owned(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for PublishAttemptId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PublishAttemptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The object user-metadata key an attempt id travels in.
///
/// S3 lowercases user-metadata keys, so this must already be lowercase or the
/// read back would never match what was written.
pub const ATTEMPT_METADATA_KEY: &str = "gitlawb-attempt";

/// The precondition an upload is fenced on.
///
/// Object storage is the only place a fence can hold. Dropping the future of an
/// in-flight PUT does not cancel the request the server is already processing,
/// so no amount of local locking stops an abandoned writer's bytes from landing
/// after a successor has published. A conditional PUT the store itself refuses
/// is what actually stops it.
#[derive(Clone, Debug)]
pub enum UploadPrecondition {
    /// Publish only if the stored object is still the generation we observed.
    IfMatch(String),
    /// Publish only if nothing is stored under the key yet.
    IfAbsent,
    /// No fence. Last writer wins.
    Unconditional,
}

/// What the store holds under a key right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredGeneration {
    /// The generation a later conditional upload can fence itself on.
    pub etag: Option<String>,
    /// The attempt that published it, when the object carries our metadata.
    /// `None` for anything written by something that does not stamp attempts
    /// (an operator upload, a pre-attempt-id archive).
    pub attempt: Option<String>,
}

impl StoredGeneration {
    /// Is what the store holds the work of `attempt`?
    ///
    /// This is the whole reconciliation primitive. It is deliberately a
    /// three-way question collapsed to a boolean only at the point of use: an
    /// object with no attempt metadata answers `false`, because "somebody else's
    /// bytes" and "bytes nobody stamped" license exactly the same caution.
    pub fn belongs_to(&self, attempt: &PublishAttemptId) -> bool {
        self.attempt.as_deref() == Some(attempt.as_str())
    }
}

/// The receipt of a publish the store ACKNOWLEDGED.
///
/// Only produced on a response the client actually read, so holding one is proof
/// of publication in a way that "the upload future returned" is not.
#[derive(Clone, Debug)]
pub struct UploadReceipt {
    pub attempt: PublishAttemptId,
    pub etag: Option<String>,
}

/// How far ONE publish attempt got.
///
/// Observable through [`PublishStageCell`] from outside the future doing the
/// work, which is the property the whole design turns on: a handler future that
/// is DROPPED never returns an outcome, so the only way to classify a cancelled
/// attempt is to read the stage it had reached when it was abandoned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishStage {
    /// Nothing has been attempted.
    Idle,
    /// No object-storage backend is configured, so there is no publication to
    /// confirm and the local write IS the durable copy. Distinct from `Idle`,
    /// which means an attempt was possible and had not started: a cancellation
    /// under `NoBackend` loses nothing, while a cancellation under `Idle` means
    /// a publish that could have happened never did.
    NoBackend,
    /// The archive is being built. The request has not been constructed, let
    /// alone sent. A cancellation here is a DEFINITE "no publication was
    /// attempted" — not an ambiguous in-flight PUT.
    PreparingArchive,
    /// The request is on the wire. Its fate is unknown until the store answers,
    /// and a cancellation here does NOT stop the server processing it.
    PutDispatched { attempt: PublishAttemptId },
    /// The store acknowledged the write. This is the ONLY stage that licenses
    /// replication, a 2xx, or treating the local tree as durable.
    Published {
        attempt: PublishAttemptId,
        etag: Option<String>,
    },
    /// The store definitively did not publish this attempt (a refused
    /// precondition, or a failure that proves the bytes never committed).
    Refused,
    /// The attempt may or may not have committed and has not been reconciled.
    /// Destructive compensation is NEVER licensed from here.
    Ambiguous { attempt: PublishAttemptId },
}

impl PublishStage {
    /// Did this attempt reach a state where the store may hold its bytes?
    ///
    /// True from dispatch onward. `false` is what makes deleting the attempt's
    /// object or local tree safe.
    pub fn may_have_published(&self) -> bool {
        matches!(
            self,
            PublishStage::PutDispatched { .. }
                | PublishStage::Published { .. }
                | PublishStage::Ambiguous { .. }
        )
    }

    /// The attempt whose fate is unresolved, when there is one. This is what a
    /// reconciliation HEAD is compared against.
    pub fn unresolved_attempt(&self) -> Option<&PublishAttemptId> {
        match self {
            PublishStage::PutDispatched { attempt } | PublishStage::Ambiguous { attempt } => {
                Some(attempt)
            }
            _ => None,
        }
    }
}

/// A [`PublishStage`] an in-flight upload writes and an outside observer reads.
///
/// `std::sync::Mutex` rather than an async lock on purpose: every write is a
/// field assignment with no await inside, and the reader that matters most runs
/// inside a `Drop` impl, where an async lock cannot be awaited at all.
#[derive(Debug)]
pub struct PublishStageCell(Mutex<PublishStage>);

impl PublishStageCell {
    pub fn new() -> Self {
        Self::seeded(PublishStage::Idle)
    }

    pub fn seeded(stage: PublishStage) -> Self {
        Self(Mutex::new(stage))
    }

    pub fn set(&self, stage: PublishStage) {
        *self.0.lock().expect("publish stage mutex poisoned") = stage;
    }

    pub fn get(&self) -> PublishStage {
        self.0.lock().expect("publish stage mutex poisoned").clone()
    }
}

impl Default for PublishStageCell {
    fn default() -> Self {
        Self::new()
    }
}

/// What the client knows about whether a request it could not complete ever
/// reached the wire.
///
/// The classifier that produces this is the ONLY backend-aware code in the
/// publish path; a pluggable store (#79) supplies its own and every caller below
/// keeps working off [`UploadError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchKnowledge {
    /// The request could not be built or sent. The store cannot hold these bytes.
    NeverSent,
    /// The request may have been sent, and may have committed.
    MaybeSent,
}

/// Why an upload did not publish, split by what it leaves the caller ENTITLED TO
/// DO — not by which HTTP status came back.
///
/// The split exists because the previous shape ("precondition lost" vs "some
/// other error") made every caller treat a lost response as proof of failure.
/// Smithy timeout, dispatch and response errors all allow that the request was
/// sent and committed: a server can accept a complete conditional PUT and lose
/// or corrupt the response before the client observes success. Compensating that
/// as a definite failure deletes state that IS published.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// The store explicitly refused the fence (412, or 409 under create-only).
    /// DEFINITE: this attempt did not publish, and a successor did.
    #[error("upload precondition lost (HTTP {status})")]
    PreconditionLost { status: u16 },
    /// The attempt provably never committed: it failed before the request could
    /// be dispatched, or the store answered a definite client-side refusal.
    /// Destructive compensation is safe here and ONLY here.
    #[error("upload did not reach the store: {0:#}")]
    NotPublished(#[source] anyhow::Error),
    /// The request may have been dispatched and may have committed; the client
    /// never learned which. The attempt id is carried so the caller can ask the
    /// store rather than guess.
    #[error("upload outcome is unknowable (attempt {attempt}): {source:#}")]
    Ambiguous {
        attempt: PublishAttemptId,
        #[source]
        source: anyhow::Error,
    },
}

impl UploadError {
    /// May this caller destroy state that would be needed if the write HAD
    /// landed — delete the object, drop the only local clone, invalidate the
    /// cache?
    ///
    /// Only a proven non-publication says yes. Every new variant must default to
    /// `false`, which is why this is a match on the safe arms rather than a
    /// negation of the unsafe one.
    pub fn proves_not_published(&self) -> bool {
        matches!(
            self,
            UploadError::PreconditionLost { .. } | UploadError::NotPublished(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_definite_outcomes_license_destructive_compensation() {
        assert!(UploadError::PreconditionLost { status: 412 }.proves_not_published());
        assert!(
            UploadError::NotPublished(anyhow::anyhow!("no route to host")).proves_not_published()
        );
        assert!(
            !UploadError::Ambiguous {
                attempt: PublishAttemptId::new(),
                source: anyhow::anyhow!("response body truncated"),
            }
            .proves_not_published(),
            "a response-loss failure must never license deleting state the write may own"
        );
    }

    #[test]
    fn a_stage_may_have_published_only_from_dispatch_onward() {
        let attempt = PublishAttemptId::new();
        assert!(!PublishStage::Idle.may_have_published());
        assert!(!PublishStage::NoBackend.may_have_published());
        assert!(
            !PublishStage::PreparingArchive.may_have_published(),
            "compression has not constructed a request, let alone sent one"
        );
        assert!(!PublishStage::Refused.may_have_published());
        assert!(PublishStage::PutDispatched {
            attempt: attempt.clone()
        }
        .may_have_published());
        assert!(PublishStage::Ambiguous {
            attempt: attempt.clone()
        }
        .may_have_published());
        assert!(PublishStage::Published {
            attempt,
            etag: None
        }
        .may_have_published());
    }

    #[test]
    fn an_unstamped_object_never_belongs_to_an_attempt() {
        let attempt = PublishAttemptId::new();
        assert!(StoredGeneration {
            etag: Some("\"e\"".into()),
            attempt: Some(attempt.as_str().to_string()),
        }
        .belongs_to(&attempt));
        assert!(
            !StoredGeneration {
                etag: Some("\"e\"".into()),
                attempt: None,
            }
            .belongs_to(&attempt),
            "bytes nobody stamped must not be claimed by this attempt"
        );
        assert!(!StoredGeneration {
            etag: Some("\"e\"".into()),
            attempt: Some("someone-else".into()),
        }
        .belongs_to(&attempt));
    }
}
