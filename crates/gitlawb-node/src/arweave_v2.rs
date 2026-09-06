//! #26 Split PR 2 — three-outcome recovery policy types.
//!
//! This module owns the recovery classification policy the reviewer
//! demanded: only a trustworthy, protocol-defined absence authorizes
//! a paid re-upload. Everything else stays non-terminal.
//!
//! Deliberately narrow: the ANS-104 codec lives in `ans104`, and the
//! gateway probe, the `verify_anchor` path, and the public verify
//! endpoint are deferred until the uploader, retrieval proof, and
//! recovery consumer can be proven as one vertical slice (reviewer 2,
//! round 5). A probe against a real provider contract — same-network
//! upload/read pair, redirect-safe client, envelope-supplying read
//! API, provider-documented absence evidence — belongs in that slice,
//! not here. What ships here is the policy type plus the rule that
//! only `DefinitivelyAbsent` permits spending another upload.

/// Outcome of a gateway probe for a persisted `item_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The persisted item was served back with a verifiable envelope
    /// bound to the requested id. No re-upload allowed.
    Present,
    /// Trustworthy, protocol-defined proof the item was never
    /// accepted. Authorizes re-upload. The exact evidence that
    /// establishes this is defined by the provider contract in the
    /// vertical slice that introduces the probe — never by a
    /// mock-only body shape.
    DefinitivelyAbsent,
    /// Anything else: transport failure, oversized body, bad
    /// signature, id mismatch, ambiguous gateway response. The
    /// outbox stays non-terminal.
    Indeterminate,
}

impl ProbeOutcome {
    /// True iff the recovery code is allowed to spend another paid
    /// upload request. Only `DefinitivelyAbsent` qualifies.
    #[allow(dead_code)] // the recovery consumer lives in a later slice
    pub fn permits_reupload(self) -> bool {
        matches!(self, ProbeOutcome::DefinitivelyAbsent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only `DefinitivelyAbsent` authorizes a paid re-upload. This is
    /// the policy the reviewer named: collapsing any ambiguous outcome
    /// to absent spends a second immutable upload for the same
    /// transition.
    #[test]
    fn only_definitively_absent_authorizes_reupload() {
        assert!(!ProbeOutcome::Present.permits_reupload());
        assert!(ProbeOutcome::DefinitivelyAbsent.permits_reupload());
        assert!(!ProbeOutcome::Indeterminate.permits_reupload());
    }
}
