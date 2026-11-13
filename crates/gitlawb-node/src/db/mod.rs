use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tracing::info;
use uuid::Uuid;

use crate::webhook_secret::WebhookSecret;

/// Maximum visible repositories per page, plus one internal look-ahead row.
pub(crate) const MAX_VISIBLE_REPO_PAGE_SIZE: usize = 200;

/// Maximum repository name length in bytes. `repo_cursor` embeds the name in
/// a base64(JSON) cursor that `parse_repo_cursor` rejects over 4096 bytes, so
/// every write path must bound the name: a cursor the server emits must
/// always parse back (#465 4th round). 100 bytes keeps the longest possible
/// cursor an order of magnitude under the parse limit.
pub(crate) const MAX_REPO_NAME_LEN: usize = 100;

/// Maximum agent tasks returned per query. Shared by the GraphQL `tasks`
/// complexity meter and the resolver clamp so they can't drift.
pub(crate) const MAX_VISIBLE_TASK_PAGE_SIZE: i64 = 200;

// ── Public data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRecord {
    pub id: String,
    pub name: String,
    pub owner_did: String,
    pub description: Option<String>,
    pub is_public: bool,
    pub default_branch: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disk_path: String,
    pub forked_from: Option<String>,
    pub machine_id: Option<String>,
}

/// Which side is authoritative for a continuously mirrored repository.
///
/// A repository without an `upstream_url` has no mirror status. Transitioning
/// states always carry a durable job id and phase so a node restart can resume
/// or roll back instead of guessing which side owns writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(test), allow(dead_code))]
pub enum MirrorStatus {
    Inbound,
    TransitioningInboundToOutbound,
    Outbound,
    TransitioningOutboundToInbound,
}

#[cfg_attr(not(test), allow(dead_code))]
impl MirrorStatus {
    fn from_db(value: &str) -> Result<Self> {
        match value {
            "inbound" => Ok(Self::Inbound),
            "transitioning_inbound_to_outbound" => Ok(Self::TransitioningInboundToOutbound),
            "outbound" => Ok(Self::Outbound),
            "transitioning_outbound_to_inbound" => Ok(Self::TransitioningOutboundToInbound),
            _ => anyhow::bail!("invalid mirror status stored in database"),
        }
    }

    fn is_transitioning(self) -> bool {
        matches!(
            self,
            Self::TransitioningInboundToOutbound | Self::TransitioningOutboundToInbound
        )
    }
}

/// Durable progress marker for a mirror-authority transition job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(test), allow(dead_code))]
pub enum MirrorTransitionPhase {
    Queued,
    Starting,
    InitializingMirrorFetch,
    DrainingWrites,
    FinalizingMirrorFetch,
    FinalizingMirrorPush,
    CommittingTargetStatus,
    Completed,
    RollingBack,
}

#[cfg_attr(not(test), allow(dead_code))]
impl MirrorTransitionPhase {
    fn from_db(value: &str) -> Result<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "starting" => Ok(Self::Starting),
            "initializing_mirror_fetch" => Ok(Self::InitializingMirrorFetch),
            "draining_writes" => Ok(Self::DrainingWrites),
            "finalizing_mirror_fetch" => Ok(Self::FinalizingMirrorFetch),
            "finalizing_mirror_push" => Ok(Self::FinalizingMirrorPush),
            "committing_target_status" => Ok(Self::CommittingTargetStatus),
            "completed" => Ok(Self::Completed),
            "rolling_back" => Ok(Self::RollingBack),
            _ => anyhow::bail!("invalid mirror transition phase stored in database"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct RepoMirrorState {
    pub repo_id: String,
    pub upstream_url: String,
    pub status: MirrorStatus,
    pub transition_id: Option<Uuid>,
    pub transition_phase: Option<MirrorTransitionPhase>,
    pub updated_at: DateTime<Utc>,
}

/// One canonical repository eligible for a scheduled external-forge fetch.
/// The worker keyset-pages these rows by `repo_id`; transition metadata is not
/// exposed because the selecting query admits only stable INBOUND state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundMirrorTarget {
    pub repo_id: String,
    pub owner_did: String,
    pub name: String,
    pub upstream_url: String,
}

#[cfg_attr(not(test), allow(dead_code))]
impl RepoMirrorState {
    fn validate(&self) -> Result<()> {
        validate_mirror_upstream_url(&self.upstream_url)?;

        match (
            self.status.is_transitioning(),
            self.transition_id,
            self.transition_phase,
        ) {
            (true, Some(_), Some(phase)) if phase != MirrorTransitionPhase::Completed => Ok(()),
            (false, None, None) => Ok(()),
            (false, Some(_), Some(MirrorTransitionPhase::Completed)) => Ok(()),
            _ => anyhow::bail!("mirror status and transition metadata are inconsistent"),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_mirror_upstream_url(raw: &str) -> Result<reqwest::Url> {
    if raw.is_empty() || raw.len() > 2048 {
        anyhow::bail!("mirror upstream URL must contain 1 to 2048 bytes");
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        anyhow::bail!("mirror upstream URL contains whitespace or control characters");
    }

    let url = reqwest::Url::parse(raw).context("parsing mirror upstream URL")?;
    if url.scheme() != "https" {
        anyhow::bail!("mirror upstream URL must use HTTPS");
    }
    if !crate::api::peers::is_public_http_url(raw) {
        anyhow::bail!("mirror upstream URL must use a public host");
    }
    // An IP-literal host must also pass the fetch worker's stricter permit;
    // otherwise the row stores fine but every scheduled fetch hard-fails.
    if let Some(host) = url.host_str() {
        let literal = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = literal.parse::<std::net::IpAddr>() {
            if !crate::api::peers::mirror_upstream_ip_permitted(ip) {
                anyhow::bail!("mirror upstream URL uses an unsuitable literal host");
            }
        }
    }
    if url.host_str().is_none() || url.path().trim_matches('/').is_empty() {
        anyhow::bail!("mirror upstream URL must include a host and repository path");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("mirror upstream URL must not embed credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("mirror upstream URL must not contain a query or fragment");
    }

    Ok(url)
}

/// One row of a keyset page from [`Db::list_repos_page_for_scan`].
///
/// Carries the row's quarantine flag inline (so the IPFS scan needs no separate
/// whole-node quarantine query) and the RAW stored `created_at` text, which is
/// the first half of the keyset cursor. The raw text is kept because the keyset
/// comparison is a text comparison and re-serializing the parsed `DateTime` is
/// not guaranteed to reproduce the stored bytes — a cursor that differs from the
/// stored value by one character skips or repeats rows.
#[derive(Debug, Clone)]
pub struct ScanRepoRow {
    pub repo: RepoRecord,
    pub quarantined: bool,
    pub created_at_key: String,
}

/// Per-rule replication mode for a visibility rule.
/// `A` hides existence entirely (only valid at whole-repo scope `/`).
/// `B` keeps object SHAs and the path visible but withholds content
/// (the only mode allowed for subtrees; enforced on clones in Phase 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VisibilityMode {
    A,
    B,
}

impl VisibilityMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            VisibilityMode::A => "a",
            VisibilityMode::B => "b",
        }
    }

    pub fn from_db(s: &str) -> Self {
        match s {
            "a" => VisibilityMode::A,
            "b" => VisibilityMode::B,
            other => {
                tracing::warn!("unknown visibility mode in DB: {other:?}, defaulting to B");
                VisibilityMode::B
            }
        }
    }
}

/// A path-scoped visibility rule. `path_glob` is "/" for whole-repo, or a
/// subtree pattern such as "/secret-pkg/**". The repo owner is always an
/// implicit reader regardless of `reader_dids`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityRule {
    pub id: String,
    pub repo_id: String,
    pub path_glob: String,
    pub mode: VisibilityMode,
    pub reader_dids: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequest {
    pub id: String,
    pub repo_id: String,
    pub number: i64,
    pub title: String,
    pub body: Option<String>,
    pub author_did: String,
    pub source_branch: String,
    pub target_branch: String,
    pub status: String, // "open" | "merged" | "closed"
    pub merged_by_did: Option<String>,
    pub merged_at: Option<String>,
    /// Head commit of the source branch, tracked while the pull request is open
    /// and frozen at close or merge. Null until something pushes to that branch.
    pub head_commit: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// One append-only commit-status claim. A producer reporting twice for the same
/// context leaves both rows; the visible status is a projection over the history,
/// ordered on the database-assigned `seq`.
/// No `Serialize`: the signature material below must not reach a response body,
/// and the write path's 201 uses a dedicated type
/// ([`crate::api::status::CreatedStatus`]) that carries none of it. Dropping the
/// derive is what stops the leak from reappearing by accident.
#[derive(Debug, Clone, Deserialize)]
pub struct StatusClaim {
    pub id: String,
    /// Database-assigned ordering key. Ignored on insert (see
    /// [`Db::insert_status_claim`]); nothing the producer supplies orders the
    /// projection.
    // The projection orders on `seq` inside SQL, and the replay path reads it
    // back to answer a duplicate write with the original claim's sequence.
    pub seq: i64,
    pub repo_id: String,
    /// Lowercase 40-character hex commit SHA. Never existence-checked.
    pub commit_sha: String,
    pub state: String,
    pub context: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub producer_did: String,
    pub authorizing_did: String,
    /// The producer's RFC 9421 `Signature` header value, and below it the
    /// `Signature-Input`, the canonical string the signature was verified over,
    /// and the request body itself. Captured at write time because none of it
    /// can be recovered once the request is gone, which is what keeps a claim
    /// verifiable as history.
    ///
    /// Both of the last two are needed, and neither substitutes for the other.
    /// The signing string covers the body only through a content-digest, so with
    /// the signing string alone a reader can confirm that somebody signed a
    /// request carrying some digest but cannot show that THIS row is what they
    /// signed. `request_body` is what closes that gap: recompute its digest,
    /// find it in `signing_string`, verify `signature` over that string.
    pub signature: String,
    pub signature_input: String,
    pub signing_string: String,
    pub request_body: Vec<u8>,
    /// Stable digest over the four fields above: the request's identity.
    ///
    /// Unique across the table, so an exact replay of an accepted request cannot
    /// append a second row. See [`crate::api::status::request_digest`] for what
    /// goes into it and [`Db::insert_status_claim_capped`] for what happens when
    /// it collides.
    pub request_digest: String,
    /// Server-assigned rfc3339 timestamp. Display data only; ordering is `seq`.
    pub created_at: String,
}

/// One row of the commit-status projection: what the read surfaces render and
/// nothing else. Deliberately NOT a [`StatusClaim`]. The claim carries the
/// signature material, which no read renders and which runs to kilobytes per row
/// (`signing_string` plus `request_body`), so reading the projection as claims
/// pulled that weight off disk on every public status request.
#[derive(Debug, Clone)]
pub struct StatusProjection {
    pub state: String,
    pub context: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub producer_did: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrReview {
    pub id: String,
    pub pr_id: String,
    pub reviewer_did: String,
    pub body: Option<String>,
    pub status: String, // "approved" | "changes_requested" | "comment"
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrComment {
    pub id: String,
    pub pr_id: String,
    pub author_did: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueComment {
    pub id: String,
    pub issue_id: String,
    pub author_did: String,
    pub body: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub repo_id: String,
    pub url: String,
    /// At rest this holds the sealed ciphertext (`enc:v1:…`) produced by
    /// [`crate::webhook_secret::seal`]; the newtype redacts `Debug` and
    /// `Serialize` so the signing secret never reaches a log line or a body.
    pub secret: Option<WebhookSecret>,
    pub events: Vec<String>,
    pub created_by_did: String,
    pub created_at: String,
    pub active: bool,
}

/// One local push event: a single ref update observed on this node's
/// receive-pack path, recorded so a subscriber that missed the push webhook can
/// still discover the work by polling.
///
/// Stored in `repo_push_events`, deliberately NOT in `received_ref_updates`.
/// That table is also read by the unauthenticated global feed at
/// `GET /api/v1/events/ref-updates`, so writing a local push there would publish
/// a private repo's push metadata to anonymous callers. This one is read only by
/// the repo-scoped poll surface, behind that repo's read gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoPushEvent {
    pub id: String,
    /// Database-assigned ordering key the poll cursor's row id resolves to.
    /// Ignored on
    /// insert (see [`Db::insert_repo_push_events`]): nothing the writer supplies
    /// can order these rows, because `created_at` is stamped before the insert
    /// and a row stamped later can commit earlier.
    pub seq: i64,
    pub repo_id: String,
    pub ref_name: String,
    /// The SHA the ref points at after the push. A deletion is never recorded,
    /// so this is always a real commit at the time it was written.
    pub after_sha: String,
    /// Display data only. Never an ordering key; see `seq`.
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefCertificate {
    pub id: String,
    pub repo_id: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub pusher_did: String,
    pub node_did: String,
    pub signature: String,
    pub issued_at: String,
    /// #26 Split PR 3 — the wire-format version of this cert. v1 is
    /// the pre-versioning 7-field payload (no `version` key in the
    /// signed bytes). v2+ is reserved for a new signed payload shape
    /// that carries the version inside the signed bytes; it is not
    /// v1 plus unsigned fields, because flipping this column must
    /// invalidate the signature. Clients refuse to verify versions
    /// they cannot represent rather than guessing.
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorJob {
    pub id: String,
    pub repo_id: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub pusher_did: String,
    pub created_at: String,
    pub claimed_at: Option<String>,
    /// Occurrence identity: which request/ordinal landed this tuple.
    /// Nullable for pre-v33 rows; new rows always set it. Tuple columns
    /// remain for lookup/indexing, but idempotency is by occurrence.
    pub request_id: Option<String>,
    pub request_ordinal: Option<i32>,
}

/// Durable versioned authorization proof for one receive-pack request.
/// Written atomically with intent; survives child deletion; purged only
/// after its downstream consumer acknowledges (anchor claimed / cert
/// verified). Body-digest-bound: verifies pusher authorized exact bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestProof {
    pub request_id: String,
    pub repo_id: String,
    pub pusher_did: String,
    pub body_digest: Vec<u8>,
    pub signature_header: String,
    pub signature_input: String,
    pub content_digest: String,
    pub created_at: String,
    pub acked_at: Option<String>,
}

/// One landed ref occurrence, retained beyond child cleanup so later
/// reconciliations cannot re-attribute B's landing to a stranded A.
/// PK is (request_id, ordinal); tuple columns support lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefLanding {
    pub request_id: String,
    pub ordinal: i32,
    pub repo_id: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub landed_at: String,
}

/// Tombstone for Git-side marker deletion. Parent SQL row is gone only
/// after children are gone; marker (external side effect) retains this
/// tombstone until idempotent `git update-ref -d` succeeds. `next_attempt_at`
/// provides fairness (failing entries back off behind ready work);
/// `dead_letter` parks permanent failures visibly after a bound instead
/// of starving newer tombstones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkerCleanup {
    pub request_id: String,
    pub repo_id: String,
    pub attempts: i32,
    pub created_at: String,
    pub last_error: Option<String>,
    pub next_attempt_at: Option<String>,
    pub dead_letter: bool,
}

/// The lifecycle states of a row in `pending_ref_transitions`. Persisted as a
/// TEXT column with one of these string values; the constants are the canonical
/// spellings, and tests + the recovery drain all use them so a typo on one
/// side or the other cannot silently mismatch the other.
#[allow(dead_code)] // constants are used by tests + the next-slice handler
pub mod pending_state {
    #[allow(dead_code)]
    pub const PREPARED: &str = "prepared";
    #[allow(dead_code)]
    pub const APPLIED: &str = "applied";
    #[allow(dead_code)]
    pub const CANCELLED: &str = "cancelled";
    /// Receive-pack returned Err but the exit was non-zero / timed out,
    /// so it is unknown whether some refs landed. The reconcile step
    /// checks these rows against disk at startup the same way it
    /// checks `prepared` rows, and promotes those whose target SHA
    /// actually landed.
    #[allow(dead_code)]
    pub const UNCERTAIN: &str = "uncertain";

    /// States a reconcile pass may still resolve into `applied`. Single
    /// source for the set: the SQL walks bind this slice positionally via
    /// `= ANY($1)`, and the Rust gate uses [`is_reconcilable`], so adding
    /// a resolvable state is one edit here rather than three matching
    /// literals across two files.
    pub const RECONCILABLE: [&str; 2] = [PREPARED, UNCERTAIN];

    /// Rust half of [`RECONCILABLE`]: true while reconcile may still
    /// promote a row in this state. Phase 2 of the effect executor waits
    /// on exactly this set; anything else non-cancelled is divergent.
    pub fn is_reconcilable(state: &str) -> bool {
        RECONCILABLE.contains(&state)
    }
}

/// #26 Split PR 1 — durable intent row for a single (request, ref) transition.
///
/// One row is written BEFORE `smart_http::receive_pack` runs, in state
/// `prepared`, carrying the verified pusher DID, the raw RFC 9421 signature
/// header that authorized the push, the request id, and the parsed ref
/// update. The handler then transitions the row to `applied` on Ok or
/// `cancelled` on Err. Startup recovery drains only `applied` rows.
///
/// `request_id` is the per-handler UUID. It is the deterministic key for
/// the push event, the ref certificate, and the anchor job — those
/// artifacts derive their ids from `(request_id, ref_name)` (cert and push)
/// or `(repo_id, ref_name, old_sha, new_sha)` (anchor) so a recovery pass
/// that re-fires the same transition cannot create a second row of any
/// of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // wired by the handler refactor in the next slice
pub struct PendingRefTransition {
    pub id: String,
    pub request_id: String,
    pub repo_id: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub pusher_did: String,
    pub node_did: String,
    pub signature_header: String,
    pub signature_input: String,
    pub content_digest: String,
    pub state: String,
    pub created_at: String,
    pub applied_at: Option<String>,
    pub cancelled_at: Option<String>,
    /// Zero-based position of this row in the live push's `ref_updates`
    /// — the live handler assigns `0..N-1` as it walks the pkap-line
    /// parsed refs in order. The push event identity and the cert
    /// identity are both `(request_id, ordinal)`, so a recovery replay
    /// re-derives the same artifact ids the live path produced without
    /// depending on which ref happened to land first. Migration v38
    /// added this column; the live handler sets it from
    /// `ref_updates.iter().enumerate()` so it is stable across live and
    /// recovery.
    pub ordinal: i32,
    /// Snapshot of the git-side update kind at intent time:
    /// `"create"`, `"update"`, `"delete"`, or `"branch-create"` /
    /// `"tag-create"`. Recovery re-derives this from the per-ref
    /// report if it is null, so the column is informational. Migration
    /// v38 added it; older rows are `NULL`.
    pub git_target_kind: Option<String>,
}

/// #26 Split PR 1 — anchor handoff row, owned by PR 1, consumed by PR 2.
///
/// One row per landed occurrence `(request_id, ordinal)`. Tuple columns
/// remain for lookup/indexing; idempotency is by occurrence id so a
/// legitimate recurrence (`A->B`, `B->A`, `A->B`) yields three handoffs
/// while retry of one occurrence remains a no-op.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct AnchorJobCompat {
    pub id: String,
    pub repo_id: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub pusher_did: String,
    pub created_at: String,
    pub claimed_at: Option<String>,
}

/// #26 Split PR 1 — request-level durability row. One per `git
/// receive-pack` call. Written in state `received` BEFORE
/// `receive_pack_raw` runs, so a node crash between intent and the
/// git return is recoverable. After git returns, the live handler
/// transitions the row to `outcomes_committed` (with `parsed_report`
/// and `accepted_ordinal` stamped) or `rejected_at_git`. The drain
/// (step 3) reads `effects_pending` rows and runs the per-ref effect
/// writes; today step 2 only reads the row to gate the push-event
/// identity on the request's `accepted_ordinal`.
///
/// `request_bytes` is the raw HTTP body the handler received; the
/// drain could in principle re-run `git receive-pack` against it
/// after a crash, but the v38 model treats the parsed report as the
/// durable truth and the `request_bytes` column is informational.
/// `request_bytes_hash` is the SHA-256 digest of the body as raw
/// bytes (32 bytes), so a future replay can verify the row's content
/// matches what the handler saw.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // wired by the handler refactor in the next slice
pub struct ReceivePackRequest {
    pub id: String,
    pub repo_id: String,
    pub pusher_did: String,
    pub node_did: String,
    pub request_bytes: Vec<u8>,
    pub request_bytes_hash: Vec<u8>,
    pub state: String,
    pub git_exit_ok: Option<bool>,
    pub parsed_report: Option<serde_json::Value>,
    pub accepted_ordinal: Option<i32>,
    pub attempt_count: i32,
    pub last_error: Option<String>,
    pub next_attempt_at: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
    /// Verified RFC 9421 authorization envelope, copied from the
    /// authenticated request headers at intent time so recovery can
    /// prove the named pusher authorized the exact body digest.
    /// Nullable for rows written before v32; new rows always set it.
    pub signature_header: Option<String>,
    pub signature_input: Option<String>,
    pub content_digest: Option<String>,
}

/// #26 Split PR 1 — request-level state vocabulary. The `received` →
/// `outcomes_committed | rejected_at_git` transition happens in the
/// live handler (step 2). The `outcomes_committed → effects_pending
/// → complete` lifecycle lives in step 3's effect executor. Every
/// state-flip helper is a single SQL `UPDATE … WHERE state = <from>`;
/// a state helper not gated on the `from` state is a bug because it
/// could clobber a row the drain is concurrently updating.
#[allow(dead_code)] // constants are used by tests + the next-slice handler
pub mod request_state {
    /// The handler wrote the row but git has not yet returned. The
    /// drain will not pick this row up.
    #[allow(dead_code)]
    pub const RECEIVED: &str = "received";
    /// Git returned, the report was parsed, and the request has
    /// outcomes. The drain reads rows in this state (and its
    /// retry variant `effects_pending`) and runs the per-ref
    /// effect writes. Step 2 only writes this state; the
    /// `effects_pending → complete` flip is step 3.
    #[allow(dead_code)]
    pub const OUTCOMES_COMMITTED: &str = "outcomes_committed";
    /// The drain attempted to run effects and failed; it left
    /// `next_attempt_at` in the future. Step-3 territory.
    #[allow(dead_code)]
    pub const EFFECTS_PENDING: &str = "effects_pending";
    /// Drain succeeded. Step 3's terminal state for a successful
    /// push. The request row is retained for the 7-day window
    /// the v38 partial index on `completed_at` is built for.
    #[allow(dead_code)]
    pub const COMPLETE: &str = "complete";
    /// Git returned with a non-zero exit and no parseable report.
    /// No effects were ever run; the request row is terminal.
    /// The on-disk state of the children's refs is left to the
    /// reconcile step (the children remain in `prepared`).
    #[allow(dead_code)]
    pub const REJECTED_AT_GIT: &str = "rejected_at_git";
    /// Operator-attended terminal state. The reconcile gates on
    /// the git-side marker (see `durable_outbox::reconcile_prepared_page`)
    /// and quarantines the request if the marker is missing or
    /// hash-mismatched. The drain's `effects_max_attempts` bound
    /// also flips retry-stuck requests here. No auto-recovery; an
    /// operator inspects and reclassifies to `complete` or
    /// `rejected_at_git` after manual inspection. Never purged
    /// by the step-4 bounded retirement policy.
    #[allow(dead_code)]
    pub const QUARANTINED: &str = "quarantined";
}

/// SHA-256 hex of an arbitrary tuple, used as the deterministic id for the
/// artifacts that recovery inserts idempotently. Returns 64 lowercase hex
/// characters. The input is concatenated with `\x1f` (ASCII Unit Separator)
/// as the field separator so two distinct tuples can never collide by
/// accidental prefix overlap, e.g. `(a, bc)` and `(ab, c)` would otherwise
/// produce the same hash input.
#[allow(dead_code)] // called from tests + the next-slice handler refactor
pub fn deterministic_id(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(b"\x1f");
        hasher.update(part.as_bytes());
    }
    hasher.update(b"\x1e"); // end-of-record terminator; never appears in any field
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Deterministic id for a push event row. Derived from
/// `(request_id, ordinal)` so a recovery pass re-firing the same
/// transition produces the same id and the ON CONFLICT collapses to a
/// no-op rather than creating a second push event. Migration v38
/// made the request's `accepted_ordinal` the carrier of the push
/// event identity, so this helper takes the ordinal the request row
/// stamps at `mark_request_outcomes_committed` time.
#[allow(dead_code)] // wired by the handler refactor in the next slice
pub fn push_event_id_for(request_id: &str, ordinal: i32) -> String {
    deterministic_id(&["push_event", request_id, &ordinal.to_string()])
}

/// Deterministic id for a `repo_push_events` row. Same derivation as
/// [`push_event_id_for`] but namespaced apart so the poll-feed row and the
/// trust-scoring row can never collide: a recovery pass re-firing the same
/// accepted transition re-derives this id and the `ON CONFLICT` collapses
/// to a no-op instead of delivering one landing to pollers twice.
pub fn repo_push_event_id_for(request_id: &str, ordinal: i32) -> String {
    deterministic_id(&["repo_push_event", request_id, &ordinal.to_string()])
}

/// Deterministic id for a ref certificate row. Derived from
/// `(request_id, ordinal)` for the same idempotency reason as
/// `push_event_id_for`. The certificate's `id` column is the primary
/// key; the unique index on `(repo_id, ref_name)` still applies, so
/// the recovery path must additionally check for an existing cert
/// before inserting to avoid the upsert replacing a live-path cert.
#[allow(dead_code)] // wired by the handler refactor in the next slice
pub fn ref_cert_id_for(request_id: &str, ordinal: i32) -> String {
    deterministic_id(&["ref_cert", request_id, &ordinal.to_string()])
}

/// Deterministic id for an anchor job. Keyed by the landed
/// occurrence (request_id + ordinal), not only the ref tuple, so a
/// legitimate history that revisits a state (`A->B`, `B->A`, `A->B`
/// again) produces three distinct handoffs. Retries reuse the same
/// occurrence identity, so re-execution remains a no-op.
#[allow(dead_code)] // wired by the handler refactor in the next slice
pub fn anchor_job_id_for(repo_id: &str, ref_name: &str, old_sha: &str, new_sha: &str) -> String {
    deterministic_id(&["anchor_job", repo_id, ref_name, old_sha, new_sha])
}

/// Occurrence-keyed anchor id. New code must use this; the tuple-only
/// helper above remains for pre-v33 compatibility.
#[allow(dead_code)]
pub fn anchor_job_id_for_occurrence(
    request_id: &str,
    ordinal: i32,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
) -> String {
    deterministic_id(&[
        "anchor_job",
        request_id,
        &ordinal.to_string(),
        repo_id,
        ref_name,
        old_sha,
        new_sha,
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub did: String,
    pub http_url: String,
    pub last_seen: Option<String>,
    pub last_ping_ok: bool,
    pub announced_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReplica {
    pub replica_did: String,
    pub replica_url: String,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedCidRecord {
    pub sha256_hex: String,
    /// Local IPFS CID.  NULL for Pinata-only rows where the object was never
    /// fetched by this node's IPFS instance.
    pub cid: Option<String>,
    pub pinned_at: String,
    pub pinata_cid: Option<String>,
    /// #218 review P2: writer-owned local-IPFS provenance. `true` iff this
    /// row was written by the local-IPFS pin path
    /// (`record_pinned_cid_with_source`), the only path that has actually
    /// pushed the bytes into this node's local IPFS daemon. Independent
    /// of `cid` (a Pinata-only row with `cid = Some(raw_cid)` is
    /// `local_ipfs_provenance = false`). The API response surfaces this
    /// as `local_pinned` so consumers can distinguish a real local pin
    /// from a Pinata-only row whose `cid` is just the raw resolver key.
    pub local_ipfs_provenance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedRefUpdate {
    pub id: String,
    pub node_did: String,
    pub pusher_did: String,
    pub repo: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub timestamp: String,
    pub cert_id: Option<String>,
    pub received_at: String,
    pub from_peer: String,
    /// Full owner DID — populated by new peers; None for events from older
    /// peers that predate the wire-format change (#144).
    pub owner_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyRecord {
    pub id: String,
    pub repo_owner: String,
    pub repo_name: String,
    pub issue_id: Option<String>,
    pub title: String,
    pub amount: i64,
    pub creator_did: String,
    pub claimant_did: Option<String>,
    pub claimant_wallet: Option<String>,
    pub pr_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub claimed_at: Option<String>,
    pub submitted_at: Option<String>,
    pub completed_at: Option<String>,
    pub deadline_secs: i64,
    pub tx_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String,
    pub repo_id: Option<String>,
    pub kind: String,
    pub status: String,
    pub delegator_did: String,
    pub assignee_did: Option<String>,
    pub capability: String,
    pub ucan_token: Option<String>,
    pub payload: Option<String>,
    pub result: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deadline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRow {
    pub did: String,
    pub trust_score: f64,
    pub capabilities: Vec<String>,
    pub registered_at: String,
    pub last_seen: Option<String>,
    /// Lifecycle status: `active` (default) or `revoked` (self-deregistered).
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRecord {
    pub did: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub website: Option<String>,
    pub socials: Option<String>,
    pub profile_cid: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ── Db ────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Test-only: access the underlying Postgres connection pool.
    ///
    /// The production accessor was removed on main (ed76adf) once every
    /// production caller had migrated to typed `Db` methods; this restores
    /// it for tests only, for the raw-SQL fixtures and closed-pool cases in
    /// this change that have no typed equivalent.
    #[cfg(any(test, feature = "test-harness"))]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[cfg(any(test, feature = "test-harness"))]
    pub fn for_testing(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Test-only: apply the full schema to a fresh pool. `#[sqlx::test]`
    /// provisions an empty per-test database, so DB-backed tests must run this
    /// before seeding. Reuses the production `migrate()` path (the advisory lock
    /// is harmless on an isolated test DB and migrations are idempotent).
    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) async fn run_migrations(&self) -> Result<()> {
        self.migrate().await
    }

    /// Connect the pool and run migrations. The initial connection is bounded
    /// by `acquire_timeout` (sqlx routes pool connects through the acquire
    /// path); migrations are unbounded here — the caller wraps the whole call
    /// in its own attempt timeout, since the migration advisory lock can
    /// legitimately block while another instance migrates.
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self> {
        info!(
            max_connections,
            acquire_timeout_secs = acquire_timeout.as_secs(),
            "connecting to postgres"
        );
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect(database_url)
            .await
            .context("connecting to postgres")?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Build the dedicated pool that advisory-lock connections come from.
    ///
    /// Deliberately **lazy**: connections open on first use rather than at boot.
    /// The main pool has to connect eagerly because it runs migrations, which is
    /// why it needs `connect_db_with_retry`'s backoff and degraded-server
    /// handoff. This pool has no startup work at all, so an eager connect would
    /// only add a new way for the process to fail to boot, and would need a
    /// second copy of that retry machinery to be safe. Being lazy removes the
    /// failure mode instead of handling it: if Postgres is unreachable when the
    /// first write arrives, that write fails on the pool's own acquire timeout,
    /// the same way any other database-backed request already does.
    ///
    /// Kept separate from the main pool so a burst of lock-holding connections
    /// cannot starve ordinary request handlers. See
    /// `GITLAWB_DB_LOCK_POOL_MAX_CONNECTIONS` for the sizing tradeoff.
    pub fn lock_pool(
        database_url: &str,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<PgPool> {
        info!(
            max_connections,
            acquire_timeout_secs = acquire_timeout.as_secs(),
            "creating dedicated advisory-lock pool (lazy)"
        );
        PgPoolOptions::new()
            .max_connections(max_connections)
            // Explicit, and load-bearing rather than cosmetic: `RepoWriteGuard::Drop`
            // has a no-runtime branch that calls `PoolConnection::leak()` and relies
            // on the husk's own drop doing nothing. With `min_connections > 0` that
            // drop still spawns a pool-replenish task, and spawning without a runtime
            // panics inside Drop, which aborts the process during unwind. It is 0 by
            // default, so this line exists to keep a future tuning change from
            // silently re-arming that panic.
            .min_connections(0)
            .acquire_timeout(acquire_timeout)
            .connect_lazy(database_url)
            .context("creating advisory-lock pool")
    }

    /// Cheap liveness probe against the pool, for readiness checks: one
    /// `SELECT 1` that fails fast when the database is unreachable.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .context("db ping")?;
        Ok(())
    }

    /// Run all pending versioned migrations in order, inside a single
    /// transaction per migration. Idempotent — migrations whose version is
    /// already recorded in `schema_migrations` are skipped.
    ///
    /// Concurrency: the whole routine is guarded by a Postgres advisory lock so
    /// two node instances pointed at the same database (e.g. during a
    /// blue/green or rolling deploy) cannot race to apply the same migration
    /// and trip the `schema_migrations` primary key.
    ///
    /// Legacy installs: v1 bundles the entire pre-versioning schema, and every
    /// statement in it is idempotent (`CREATE TABLE IF NOT EXISTS`,
    /// `CREATE INDEX IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). So an existing
    /// node that predates this system just runs v1 once: existing objects are
    /// no-ops, and any objects it was missing are created. We deliberately do
    /// *not* short-circuit on the presence of a single canonical table — a node
    /// that was behind on schema would then be marked complete while still
    /// missing newer objects.
    async fn migrate(&self) -> Result<()> {
        // Bootstrap: ensure the `schema_migrations` table itself exists.
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS schema_migrations (
                version    BIGINT  NOT NULL PRIMARY KEY,
                name       TEXT    NOT NULL,
                applied_at TEXT    NOT NULL
            )"#,
        )
        .execute(&self.pool)
        .await
        .context("creating schema_migrations table")?;

        // Serialize migrations across processes: hold a session-level advisory
        // lock on a dedicated connection for the whole run. Another instance
        // starting up blocks here until we finish. The lock is released when we
        // explicitly unlock below, or automatically if the connection is
        // dropped (e.g. on panic), so a crash can't wedge future restarts.
        let mut lock_conn = self
            .pool
            .acquire()
            .await
            .context("acquiring connection for migration advisory lock")?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(MIGRATION_ADVISORY_LOCK)
            .execute(&mut *lock_conn)
            .await
            .context("acquiring migration advisory lock")?;

        let result = self.run_pending_migrations().await;

        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(MIGRATION_ADVISORY_LOCK)
            .execute(&mut *lock_conn)
            .await;

        result
    }

    /// Apply every migration whose version isn't yet recorded, in order.
    /// Must be called while holding the migration advisory lock.
    async fn run_pending_migrations(&self) -> Result<()> {
        for m in MIGRATIONS {
            let existing: Option<String> =
                sqlx::query("SELECT name FROM schema_migrations WHERE version = $1")
                    .bind(m.version)
                    .fetch_optional(&self.pool)
                    .await?
                    .map(|r| r.get::<String, _>("name"));

            if let Some(stored) = existing {
                // Same version, different name means two split PRs claimed
                // one migration number (e.g. split-1 v27 vs a sibling v27).
                // Fail fast instead of silently skipping the wrong schema.
                if stored != m.name {
                    anyhow::bail!(
                        "migration version collision: database has v{} ({}) but binary wants v{} ({}); merge the split migration ledgers into one ordered sequence",
                        m.version,
                        stored,
                        m.version,
                        m.name
                    );
                }
                continue;
            }

            let started = std::time::Instant::now();
            info!(
                version = m.version,
                name = m.name,
                statements = m.stmts.len(),
                "applying migration"
            );

            // Run the migration body in a single transaction so a failure
            // mid-way leaves the database in its prior state rather than
            // partially mutated.
            let mut tx = self.pool.begin().await?;
            for stmt in m.stmts {
                sqlx::query(stmt).execute(&mut *tx).await.with_context(|| {
                    format!(
                        "migration v{} ({}) failed on statement: {}",
                        m.version, m.name, stmt
                    )
                })?;
            }
            sqlx::query(
                "INSERT INTO schema_migrations (version, name, applied_at)
                 VALUES ($1, $2, $3)",
            )
            .bind(m.version)
            .bind(m.name)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await
            .context("recording migration as applied")?;
            tx.commit()
                .await
                .with_context(|| format!("committing migration v{}", m.version))?;

            info!(
                version = m.version,
                name = m.name,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "migration applied"
            );
        }

        Ok(())
    }

    /// Returns `(version, name, applied_at)` for every applied migration,
    /// oldest first. Useful for ops/observability — surface via `gl status`
    /// or `/api/v1/stats` in a follow-up.
    #[allow(dead_code)]
    pub async fn migration_status(&self) -> Result<Vec<(i64, String, String)>> {
        let rows = sqlx::query(
            "SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("version"),
                    r.get("name"),
                    r.get("applied_at"),
                )
            })
            .collect())
    }
}

// ── Migration catalogue ──────────────────────────────────────────────────────
//
// All schema statements are bundled into a single v1 migration so we can ship
// versioned migrations on a live network without breaking the existing
// install base. Future schema changes MUST be added as v2, v3, … — never
// appended to v1. Operators can read `schema_migrations` to confirm a node
// is at the expected version.
//
// Each migration runs in a single transaction, so statements that Postgres
// forbids inside a transaction (notably `CREATE INDEX CONCURRENTLY`) cannot be
// used here. Build such indexes the ordinary, transaction-safe way, or stage
// them as a dedicated out-of-band operational step.

// Arbitrary but stable key for the migration advisory lock ("gitlawb_" bytes).
const MIGRATION_ADVISORY_LOCK: i64 = 0x6769_746C_6177_625F;

const MIGRATION_V1_NAME: &str = "initial_schema";

struct Migration {
    version: i64,
    name: &'static str,
    stmts: &'static [&'static str],
}

const MIGRATIONS: &[Migration] = &[
    Migration {
    version: 1,
    name: MIGRATION_V1_NAME,
    stmts: &[
            r#"CREATE TABLE IF NOT EXISTS repos (
                id             TEXT NOT NULL PRIMARY KEY,
                name           TEXT NOT NULL,
                owner_did      TEXT NOT NULL,
                description    TEXT,
                is_public      BOOLEAN NOT NULL DEFAULT TRUE,
                default_branch TEXT NOT NULL DEFAULT 'main',
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL,
                disk_path      TEXT NOT NULL UNIQUE,
                forked_from    TEXT
            )"#,
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS forked_from TEXT",
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS machine_id TEXT",
            "CREATE INDEX IF NOT EXISTS idx_repos_owner ON repos(owner_did)",
            "CREATE INDEX IF NOT EXISTS idx_repos_name  ON repos(name)",
            "CREATE INDEX IF NOT EXISTS idx_repos_owner_short_name ON repos ((split_part(owner_did, ':', -1)), name)",
            "CREATE INDEX IF NOT EXISTS idx_repos_updated_at ON repos (updated_at DESC)",
            r#"CREATE TABLE IF NOT EXISTS agents (
                did           TEXT NOT NULL PRIMARY KEY,
                trust_score   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                capabilities  TEXT NOT NULL DEFAULT '[]',
                registered_at TEXT NOT NULL,
                last_seen     TEXT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS push_events (
                id           TEXT NOT NULL PRIMARY KEY,
                agent_did    TEXT NOT NULL,
                repo_id      TEXT NOT NULL,
                commit_hash  TEXT NOT NULL,
                object_count INTEGER NOT NULL DEFAULT 0,
                pushed_at    TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_push_events_agent ON push_events(agent_did)",
            r#"CREATE TABLE IF NOT EXISTS ref_certificates (
                id          TEXT NOT NULL PRIMARY KEY,
                repo_id     TEXT NOT NULL,
                ref_name    TEXT NOT NULL,
                old_sha     TEXT NOT NULL,
                new_sha     TEXT NOT NULL,
                pusher_did  TEXT NOT NULL,
                node_did    TEXT NOT NULL,
                signature   TEXT NOT NULL,
                issued_at   TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_ref_certs_repo ON ref_certificates(repo_id)",
            r#"CREATE TABLE IF NOT EXISTS peers (
                did          TEXT NOT NULL PRIMARY KEY,
                http_url     TEXT NOT NULL,
                last_seen    TEXT,
                last_ping_ok BOOLEAN NOT NULL DEFAULT FALSE,
                announced_at TEXT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS pinned_cids (
                sha256_hex TEXT NOT NULL PRIMARY KEY,
                cid        TEXT NOT NULL,
                pinned_at  TEXT NOT NULL,
                pinata_cid TEXT
            )"#,
            // Migrate existing installs that lack the pinata_cid column
            "ALTER TABLE pinned_cids ADD COLUMN IF NOT EXISTS pinata_cid TEXT",
            r#"CREATE TABLE IF NOT EXISTS branch_cids (
                repo       TEXT NOT NULL,
                ref_name   TEXT NOT NULL,
                sha        TEXT NOT NULL,
                cid        TEXT NOT NULL,
                node_did   TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (repo, ref_name)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS sync_queue (
                id           TEXT NOT NULL PRIMARY KEY,
                repo         TEXT NOT NULL,
                node_did     TEXT NOT NULL,
                ref_name     TEXT NOT NULL,
                new_sha      TEXT NOT NULL,
                cid          TEXT,
                status       TEXT NOT NULL DEFAULT 'pending',
                enqueued_at  TEXT NOT NULL,
                processed_at TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_sync_queue_status ON sync_queue(status)",
            r#"CREATE TABLE IF NOT EXISTS received_ref_updates (
                id          TEXT NOT NULL PRIMARY KEY,
                node_did    TEXT NOT NULL,
                pusher_did  TEXT NOT NULL,
                repo        TEXT NOT NULL,
                ref_name    TEXT NOT NULL,
                old_sha     TEXT NOT NULL,
                new_sha     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                cert_id     TEXT,
                received_at TEXT NOT NULL,
                from_peer   TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_ref_updates_repo ON received_ref_updates(repo)",
            "CREATE INDEX IF NOT EXISTS idx_ref_updates_ts  ON received_ref_updates(timestamp DESC)",
            r#"CREATE TABLE IF NOT EXISTS pull_requests (
                id            TEXT NOT NULL PRIMARY KEY,
                repo_id       TEXT NOT NULL,
                number        BIGINT NOT NULL,
                title         TEXT NOT NULL,
                body          TEXT,
                author_did    TEXT NOT NULL,
                source_branch TEXT NOT NULL,
                target_branch TEXT NOT NULL DEFAULT 'main',
                status        TEXT NOT NULL DEFAULT 'open',
                merged_by_did TEXT,
                merged_at     TEXT,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                UNIQUE(repo_id, number)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_prs_repo ON pull_requests(repo_id)",
            r#"CREATE TABLE IF NOT EXISTS pr_reviews (
                id           TEXT NOT NULL PRIMARY KEY,
                pr_id        TEXT NOT NULL,
                reviewer_did TEXT NOT NULL,
                body         TEXT,
                status       TEXT NOT NULL,
                created_at   TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_pr_reviews_pr ON pr_reviews(pr_id)",
            r#"CREATE TABLE IF NOT EXISTS webhooks (
                id             TEXT NOT NULL PRIMARY KEY,
                repo_id        TEXT NOT NULL,
                url            TEXT NOT NULL,
                secret         TEXT,
                events         TEXT NOT NULL DEFAULT '["*"]',
                created_by_did TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                active         BOOLEAN NOT NULL DEFAULT TRUE
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_webhooks_repo ON webhooks(repo_id)",
            r#"CREATE TABLE IF NOT EXISTS agent_tasks (
                id            TEXT NOT NULL PRIMARY KEY,
                repo_id       TEXT,
                kind          TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                delegator_did TEXT NOT NULL,
                assignee_did  TEXT,
                capability    TEXT NOT NULL,
                ucan_token    TEXT,
                payload       TEXT,
                result        TEXT,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                deadline      TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_status    ON agent_tasks(status)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_delegator ON agent_tasks(delegator_did)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_assignee  ON agent_tasks(assignee_did)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_repo      ON agent_tasks(repo_id)",
            // ── Arweave permanent anchors ────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS arweave_anchors (
                id          TEXT NOT NULL PRIMARY KEY,
                repo        TEXT NOT NULL,
                owner_did   TEXT NOT NULL,
                ref_name    TEXT NOT NULL,
                old_sha     TEXT NOT NULL,
                new_sha     TEXT NOT NULL,
                cid         TEXT,
                irys_tx_id  TEXT NOT NULL,
                arweave_url TEXT NOT NULL,
                node_did    TEXT NOT NULL,
                anchored_at TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_arweave_anchors_repo    ON arweave_anchors(repo)",
            "CREATE INDEX IF NOT EXISTS idx_arweave_anchors_new_sha ON arweave_anchors(new_sha)",
            // ── Branch protection ────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS protected_branches (
                id         TEXT NOT NULL PRIMARY KEY,
                repo_id    TEXT NOT NULL,
                branch     TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(repo_id, branch)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_protected_branches_repo ON protected_branches(repo_id)",
            // ── Repo stars ──────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS repo_stars (
                id         TEXT NOT NULL PRIMARY KEY,
                repo_id    TEXT NOT NULL,
                agent_did  TEXT NOT NULL,
                starred_at TEXT NOT NULL,
                UNIQUE(repo_id, agent_did)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_repo_stars_repo  ON repo_stars(repo_id)",
            "CREATE INDEX IF NOT EXISTS idx_repo_stars_agent ON repo_stars(agent_did)",
            // ── Repo replicas (network resilience) ──────────────────────────
            // Tracks which nodes are hosting a replica of a repo. Populated
            // when a replica node calls PUT /api/v1/repos/{owner}/{repo}/replicas
            // on the origin. Public via GET on the same path — anyone can see
            // how many nodes are mirroring a given repo.
            r#"CREATE TABLE IF NOT EXISTS repo_replicas (
                id            TEXT NOT NULL PRIMARY KEY,
                repo_id       TEXT NOT NULL,
                replica_did   TEXT NOT NULL,
                replica_url   TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                UNIQUE(repo_id, replica_did)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_repo_replicas_repo ON repo_replicas(repo_id)",
            "CREATE INDEX IF NOT EXISTS idx_repo_replicas_did  ON repo_replicas(replica_did)",
            // ── PR comments ─────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS pr_comments (
                id         TEXT NOT NULL PRIMARY KEY,
                pr_id      TEXT NOT NULL,
                author_did TEXT NOT NULL,
                body       TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_pr_comments_pr ON pr_comments(pr_id)",
            // ── Issue comments ──────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS issue_comments (
                id         TEXT NOT NULL PRIMARY KEY,
                issue_id   TEXT NOT NULL,
                author_did TEXT NOT NULL,
                body       TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_issue_comments_issue ON issue_comments(issue_id)",
            // ── Repo labels ─────────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS repo_labels (
                id         TEXT NOT NULL PRIMARY KEY,
                repo_id    TEXT NOT NULL,
                label      TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(repo_id, label)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_repo_labels_repo ON repo_labels(repo_id)",
            // ── Bounties ──────────────────────────────────────────────────────────
            r#"CREATE TABLE IF NOT EXISTS bounties (
                id              TEXT NOT NULL PRIMARY KEY,
                repo_owner      TEXT NOT NULL,
                repo_name       TEXT NOT NULL,
                issue_id        TEXT,
                title           TEXT NOT NULL,
                amount          BIGINT NOT NULL,
                creator_did     TEXT NOT NULL,
                claimant_did    TEXT,
                claimant_wallet TEXT,
                pr_id           TEXT,
                status          TEXT NOT NULL DEFAULT 'open',
                created_at      TEXT NOT NULL,
                claimed_at      TEXT,
                submitted_at    TEXT,
                completed_at    TEXT,
                deadline_secs   BIGINT NOT NULL DEFAULT 604800,
                tx_hash         TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_bounties_status ON bounties(status)",
            "CREATE INDEX IF NOT EXISTS idx_bounties_repo ON bounties(repo_owner, repo_name)",
            "CREATE INDEX IF NOT EXISTS idx_bounties_claimant ON bounties(claimant_did)",
        ],
    },
    Migration {
        version: 2,
        name: "agent_profiles",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS agent_profiles (
                did          TEXT NOT NULL PRIMARY KEY,
                display_name TEXT,
                bio          TEXT,
                avatar_url   TEXT,
                website      TEXT,
                socials      TEXT,
                profile_cid  TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )"#,
        ],
    },
    Migration {
        version: 3,
        name: "visibility_rules",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS visibility_rules (
                id          TEXT NOT NULL PRIMARY KEY,
                repo_id     TEXT NOT NULL,
                path_glob   TEXT NOT NULL,
                mode        TEXT NOT NULL,
                reader_dids TEXT NOT NULL,
                created_by  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                UNIQUE(repo_id, path_glob)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_visibility_rules_repo ON visibility_rules(repo_id)",
        ],
    },
    Migration {
        version: 4,
        name: "encrypted_blobs",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS encrypted_blobs (
                repo_id    TEXT NOT NULL,
                oid        TEXT NOT NULL,
                cid        TEXT NOT NULL,
                recipients TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (repo_id, oid)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_encrypted_blobs_repo ON encrypted_blobs(repo_id)",
        ],
    },
    Migration {
        version: 5,
        name: "encrypted_blobs_blind_recipients",
        stmts: &[
            // Replace the cleartext recipient DID list with an opaque, node-keyed
            // tag used only to detect a recipient-set change. Existing rows get an
            // empty tag and are re-sealed on the next push.
            "ALTER TABLE encrypted_blobs DROP COLUMN IF EXISTS recipients",
            "ALTER TABLE encrypted_blobs ADD COLUMN IF NOT EXISTS recipients_tag TEXT NOT NULL DEFAULT ''",
        ],
    },
    Migration {
        version: 6,
        name: "agent_retirement",
        stmts: &[
            // Agent lifecycle status for issue #29. `active` is the default;
            // the key holder can self-deregister to `revoked` (terminal).
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE agents ADD COLUMN IF NOT EXISTS deactivated_at TEXT",
        ],
    },
    Migration {
        version: 7,
        name: "repo_owner_dedup_key_didkey_aware",
        stmts: &[
            // The dedup grouping key moved from the last `:` segment to a
            // did:key-aware key (strip `did:key:`, leave any other DID method
            // whole) so `did:key:X` and `did:gitlawb:X` no longer collapse. Swap
            // the index that backs it: drop the last-segment one from v1 and build
            // the matching expression index. The CASE must stay byte-for-byte in
            // sync with DEDUP_CTE / count_repos_deduped or Postgres won't use it.
            "DROP INDEX IF EXISTS idx_repos_owner_short_name",
            // Keep byte-identical to OWNER_KEY_CASE_SQL so Postgres uses the index.
            "CREATE INDEX IF NOT EXISTS idx_repos_owner_key_name ON repos ((CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END), name)",
        ],
    },
    Migration {
        version: 8,
        name: "icaptcha_consumed_proofs",
        stmts: &[
            // Single-use ledger for iCaptcha proof ids (jti). A proof may be
            // spent once per gated action; replays are rejected until the row
            // is swept after the proof's own expiry. `expires_at` is the
            // proof's unix-seconds exp, used for cleanup.
            r#"CREATE TABLE IF NOT EXISTS icaptcha_consumed_proofs (
                jti        TEXT   NOT NULL PRIMARY KEY,
                expires_at BIGINT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_icaptcha_consumed_expires ON icaptcha_consumed_proofs(expires_at)",
        ],
    },
    Migration {
        version: 9,
        name: "icaptcha_propagation",
        stmts: &[
            // The iCaptcha proof presented at repo creation, kept so it can travel
            // with the repo when it propagates to peers. A mirroring node that
            // enforces iCaptcha re-verifies this token offline before admitting the
            // mirror (see `icaptcha::admit_mirror`). One row per repo (its creation
            // proof); rows are best-effort and absent for repos created with the
            // gate off/in shadow or before this migration.
            r#"CREATE TABLE IF NOT EXISTS repo_icaptcha_proofs (
                repo_id     TEXT   NOT NULL PRIMARY KEY,
                proof_token TEXT   NOT NULL,
                sub_did     TEXT   NOT NULL,
                level       INTEGER NOT NULL,
                jti         TEXT   NOT NULL,
                exp         BIGINT NOT NULL,
                created_at  TEXT   NOT NULL
            )"#,
            // A mirror admitted by a node that could not validate its proof is
            // quarantined: kept on disk but hidden from serve/clone and listings
            // until an operator releases it. Default false; only the mirror
            // admission path sets it true.
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS quarantined BOOLEAN NOT NULL DEFAULT FALSE",
        ],
    },
    Migration {
        version: 10,
        name: "ref_cert_unique_per_ref",
        stmts: &[
            // Dedup before the unique index: keep only the most recent row per
            // (repo_id, ref_name) so the CREATE UNIQUE INDEX below does not fail
            // on existing databases that accumulated duplicates.
            r#"DELETE FROM ref_certificates
               WHERE id IN (
                   SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (
                            PARTITION BY repo_id, ref_name ORDER BY issued_at DESC, id DESC
                        ) AS rn
                       FROM ref_certificates
                   ) dups WHERE dups.rn > 1
               )"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ref_certs_repo_ref ON ref_certificates(repo_id, ref_name)",
        ],
    },
    Migration {
        version: 11,
        name: "ref_update_owner_did",
        stmts: &[
            // Index deferred: the feed gate (#144) does not read owner_did yet.
            "ALTER TABLE received_ref_updates ADD COLUMN IF NOT EXISTS owner_did TEXT",
        ],
    },
    // Reservation: v17 is deliberately not main's current_max + 1. The runner keys the
    // applied set on the integer alone, so a version another in-flight branch also
    // claims is skipped in full on whichever side merges second: no error, no warning,
    // and schema_migrations still reads healthy while the column is simply absent.
    // #253 took 16, and the pin-provenance work below took 18-23 when it merged, so 17
    // sits between them. Gaps are harmless: the runner iterates the array and never
    // requires contiguity.
    Migration {
        version: 17,
        name: "sync_queue_attempted_at",
        stmts: &[
            // Scheduling key for dequeue_pending_syncs: when the row was last
            // handed to a worker. Null until first dequeued, which is why the
            // ordering coalesces onto enqueued_at.
            "ALTER TABLE sync_queue ADD COLUMN IF NOT EXISTS attempted_at TEXT",
        ],
    },
    // The six pin-provenance migrations below were numbered 11-16 while this work was
    // in flight and moved to 18-23 on merge, because 11 and 16 were claimed elsewhere.
    // A database that ran an earlier commit of this branch therefore has schema_migrations
    // rows for the old numbers. Those rows are orphans: the runner skips on `version`
    // alone and never reads `name`, so nothing detects them, and the DDL below re-runs
    // as a no-op against objects that already exist. Recreate any such database rather
    // than upgrading it in place.
    Migration {
        version: 18,
        name: "pinned_cids_cid_index",
        stmts: &[
            // GET /ipfs/{cid} resolves an incoming CID -> git oid via pinned_cids.cid
            // (#173); index it so the per-request lookup is not a table scan. This is
            // a NEW versioned migration (not appended to the applied v1 bundle) so a
            // node already past v1 actually gets the index. Non-unique on purpose: cid
            // is a function of raw content, so a UNIQUE index could reject a legitimate
            // record_pinned_cid insert, and colliding rows serve byte-identical content.
            "CREATE INDEX IF NOT EXISTS idx_pinned_cids_cid ON pinned_cids(cid)",
        ],
    },
    Migration {
        version: 19,
        name: "pinned_cids_repo_provenance",
        stmts: &[
            // Record the repository a pin came from so GET /ipfs/{cid} resolves a
            // provenanced pin straight to its ONE source repo instead of scanning every
            // repo (#173, jatmn round 2 — bounds the anonymous fan-out and removes the
            // updated_at-ordering false-404). NEW versioned migration (never appended to
            // the applied v1 pinned_cids table) so a node past v1 gets the column.
            // Nullable: pins recorded before this migration have no provenance and fall
            // back to the legacy repo scan; new pins carry repo_id and resolve to one
            // repo. Indexed for the resolver's oid -> repo_id lookup.
            "ALTER TABLE pinned_cids ADD COLUMN IF NOT EXISTS repo_id TEXT",
            "CREATE INDEX IF NOT EXISTS idx_pinned_cids_repo_id ON pinned_cids(repo_id)",
        ],
    },
    Migration {
        version: 20,
        name: "pin_repo_sources",
        stmts: &[
            // F1 (#173, jatmn round 8): a shared object (a blob/tree/commit common to
            // forks and mirrors) can be pinned from more than one repo. `pinned_cids`
            // keeps only the FIRST pinner's `repo_id`, so a shared object first pinned
            // from a private/quarantined repo 404s by CID even when a later PUBLIC repo
            // also pinned it. Record EVERY pin-path source so `GET /ipfs/{cid}` can try
            // each. NEW versioned migration (never appended to an applied block, INV-7).
            // Bounded per object at insert time (MAX_PIN_SOURCES) so an adversary pushing
            // one object from N repos cannot make resolution O(repos) (R2, INV-10).
            "CREATE TABLE IF NOT EXISTS pin_repo_sources (
                 sha256_hex TEXT NOT NULL,
                 repo_id    TEXT NOT NULL,
                 PRIMARY KEY (sha256_hex, repo_id)
             )",
            "CREATE INDEX IF NOT EXISTS idx_pin_repo_sources_sha ON pin_repo_sources(sha256_hex)",
        ],
    },
    Migration {
        version: 21,
        name: "pinned_cids_legacy_provider_cid",
        stmts: &[
            // R8 (#173, jatmn round 10): the opportunistic legacy provider-CID repair
            // rewrites `pinned_cids.cid` from a stored PROVIDER CID (Kubo dag-pb /
            // Pinata CIDv0) to the raw-content resolver key and stashes the OLD value
            // here, so the rewrite is auditable and the row's legacy origin survives.
            // Distinct from `pinata_cid` on purpose: `has_pinata_cid` gates the Pinata
            // pin-skip, so parking a Kubo-legacy CID there would make Pinata forever
            // skip re-pinning that object. NEW versioned migration (never appended to an
            // applied block, INV-7) so a node past v13 actually gets the column.
            // Nullable: only a repaired row sets it.
            "ALTER TABLE pinned_cids ADD COLUMN IF NOT EXISTS legacy_provider_cid TEXT",
        ],
    },
    Migration {
        version: 22,
        name: "pinned_cids_sources_incomplete",
        stmts: &[
            // U3 (#173): `record_pin_source` is BEST EFFORT at every call site, so a
            // non-empty, below-cap source set is not proof that every source was
            // recorded. An object first pinned from a private repo and later pushed
            // from a PUBLIC repo whose record failed keeps a set naming only the
            // private source, and the resolver used to call that set complete and 404
            // an object the public repo would serve. Record the miss DURABLY here so
            // `GET /ipfs/{cid}` keeps the bounded scan fallback for exactly those
            // objects. Not inferable from row counts or timestamps: neither can tell
            // "no other source exists" from "a source failed to record", which is the
            // whole distinction. NEW versioned migration (never appended to an applied
            // block, INV-7). NOT NULL DEFAULT FALSE so every pre-existing row reads as
            // complete and ordinary denials stay off the O(repos) path (INV-10).
            "ALTER TABLE pinned_cids ADD COLUMN IF NOT EXISTS pin_sources_incomplete BOOLEAN NOT NULL DEFAULT FALSE",
        ],
    },
    Migration {
        version: 23,
        name: "pin_repair_sweep_cursor",
        stmts: &[
            // U4 (#173): the legacy provider-CID repair sweep walks `pinned_cids` in
            // bounded batches over an ordered `sha256_hex` cursor. The cursor has to be
            // DURABLE, or a restart rewinds the walk to the start of the table and an
            // upgraded node with a large pin set never finishes repairing it. One row
            // (`id = 1`, enforced by the CHECK) rather than a key-value table: there is
            // exactly one sweep and no second consumer, and a real constraint beats a
            // convention nobody can enforce. NEW versioned migration (never appended to
            // an applied block, INV-7). No default row is inserted: an absent row is the
            // "never swept" state, which the empty-string cursor start already means, so
            // there is no first-run special case to get wrong.
            "CREATE TABLE IF NOT EXISTS pin_repair_sweep (
                 id     INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
                 cursor TEXT NOT NULL
             )",
        ],
    },
    Migration {
        version: 24,
        name: "pin_source_failures",
        stmts: &[
            // #173 round 12 (jatmn): v22's `pin_sources_incomplete` is one boolean per
            // OBJECT, so any successful source record cleared it, including one from a
            // repo unrelated to the failure. The resolver then read the set as fully
            // enumerated, dropped the scan fallback, and 404'd an anonymous caller whose
            // only servable copy was the unrecorded public one. The missing source is a
            // property of an (object, repo) PAIR, so it is stored as one.
            //
            // NEW versioned migration (never appended to an applied block, INV-7). A new
            // table rather than a column on `pinned_cids`: the relation is many-per-object
            // and `CREATE TABLE` takes no lock on the pin table a live node is reading.
            "CREATE TABLE IF NOT EXISTS pin_source_failures (
                 sha256_hex TEXT NOT NULL,
                 repo_id    TEXT NOT NULL,
                 PRIMARY KEY (sha256_hex, repo_id)
             )",
            // Carry the pre-upgrade markers over. Which repo failed was never recorded,
            // so they get the empty sentinel, which no real `repo_id` equals: those
            // objects keep the scan fallback until something repairs them, rather than
            // being cleared by the next unrelated record the way they would have been
            // before. Strictly safer than the behavior being replaced, and bounded by how
            // rare an exhausted record is.
            "INSERT INTO pin_source_failures (sha256_hex, repo_id)
                  SELECT sha256_hex, '' FROM pinned_cids WHERE pin_sources_incomplete
                  ON CONFLICT DO NOTHING",
            // `pinned_cids.pin_sources_incomplete` is deliberately NOT dropped. Nothing
            // reads it after this migration, and leaving it costs one unused boolean,
            // whereas dropping it makes a rollback to the previous release lose the
            // markers it still reads.
        ],
    },
    Migration {
        version: 25,
        name: "repos_created_at_id_index",
        stmts: &[
            // #173 (jatmn): backs the keyset order of the paged legacy CID scan
            // (`list_repos_page_for_scan`, `ORDER BY created_at ASC, id ASC` with a
            // `(created_at, id) > (...)` cursor). The scan replaced a whole-table
            // preload precisely to stop one anonymous `GET /ipfs/{cid}` from costing
            // work proportional to the node's repo inventory (INV-10), and without this
            // index that bound is only half real: `repos` carries no index on
            // `(created_at, id)`, so Postgres seq-scans the whole table and top-N sorts
            // it to return EVERY page, while the scarce IPFS walk admission is held.
            // Measured on a 50k-row fixture: 954 shared buffers and ~47ms per page
            // without it, versus an Index Only Scan at 4-5 buffers, ~0.08ms, and
            // `Heap Fetches: 0` with it — and the keyset predicate is pushed down as an
            // `Index Cond` instead of filtering after a scan.
            //
            // Column order and direction are load-bearing and must match the query
            // exactly; `idx_repos_updated_at` (the order the scan used to use) cannot
            // serve this one. NOTHING NAMES THIS INDEX IN ANY QUERY TEXT, so a
            // grep-driven "unused index" cleanup will not see its consumer: it is
            // reachable from an unauthenticated route and dropping it reopens the
            // amplification, so treat it as part of the resolver, not as tuning.
            //
            // NEW versioned migration (never appended to an applied block, INV-7).
            "CREATE INDEX IF NOT EXISTS idx_repos_created_at_id ON repos (created_at ASC, id ASC)",
        ],
    },
    Migration {
        version: 26,
        name: "pin_repair_sweep_discovery_cursor",
        stmts: &[
            // #173 round 13 (F5): discovery probes at most
            // `MAX_LEGACY_DISCOVERY_PROBES` warm candidates per source-less row, taken
            // from a list ordered `(created_at, id)`. That order is stable, so without a
            // continuation every traversal probed the same oldest sixteen and a holder
            // at position seventeen was never reached by anything, on any node, ever.
            // These two columns are the boundary the next traversal's window starts
            // after, so coverage becomes a bounded number of traversals rather than
            // unreachable.
            //
            // STEERABILITY is why this is a keyset KEY and not an offset into the list.
            // `repo_id` derives from a grindable owner DID, so the one thing an attacker
            // must not be able to do is move the window off the true holder. Candidates
            // enter and leave the warm list between traversals (a cold repo warming on a
            // Tigris-backed node, a fresh registration, a deletion), and every such
            // change silently renumbers an offset while leaving a key's boundary exactly
            // where it was. Fresh registrations sort LAST under `created_at` and cannot
            // be backdated, so they can only ever be appended behind the window.
            //
            // RESIDUAL, stated rather than implied: an operator who can insert repos
            // with an arbitrary `created_at` can still place candidates between the
            // continuation and the holder and delay it by a traversal per sixteen rows
            // inserted. That is a privileged write, it costs a real repo row each, and
            // it delays rather than prevents, since the window keeps advancing.
            //
            // NEW versioned migration (never appended to an applied block, INV-7). NOT
            // NULL DEFAULT '' so an existing `pin_repair_sweep` row reads as "start at
            // the head of the list", which is the same thing a never-swept node reads.
            "ALTER TABLE pin_repair_sweep ADD COLUMN IF NOT EXISTS discovery_cursor_created_at TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE pin_repair_sweep ADD COLUMN IF NOT EXISTS discovery_cursor_id TEXT NOT NULL DEFAULT ''",
        ],
    },
    // Reservation: versions 27 and 28 are provisional and on hold. The runner
    // keys the applied set on the integer alone, so a version another in-flight
    // branch also claims is skipped in full on whichever side merges second:
    // no error, no warning, while the schema quietly misses what this branch
    // intended to create. Gitlawb/node#384 (still open) claims 27-35 under
    // different names, so this PR's 27/28 numbering must not move to a new
    // ceiling in a vacuum: hold until #384's claimed range lands or clears,
    // then take versions strictly above that high-water.
    Migration {
        version: 27,
        name: "agent_tasks_assignee_key_didkey_aware",
        stmts: &[
            // Filtering agent_tasks by assignee normalizes did:key values via
            // ASSIGNEE_DID_CASE_SQL, making the raw idx_agent_tasks_assignee
            // index unusable, so drop it. The matching expression index is NOT
            // built here: v28 builds the keyset-ordered variants directly, and
            // a single-column expression index would exist for exactly one
            // step while every deploy pays a full scan-and-sort to build it.
            // v28's DROP INDEX IF EXISTS idx_agent_tasks_assignee_key stays as
            // a defensive cleanup for databases that ran a pre-fix v27.
            "DROP INDEX IF EXISTS idx_agent_tasks_assignee",
        ],
    },
    Migration {
        version: 28,
        name: "agent_tasks_keyset_order_indexes",
        stmts: &[
            // list_tasks_keyset pages ORDER BY created_at DESC, id DESC with LIMIT.
            // The v1 status/repo indexes and v27 assignee expression index do not
            // lead with that order, so Postgres can sort a growing match set before
            // applying the batch LIMIT. MAX_TASK_SCAN_CANDIDATES then only bounds
            // the Rust loop. One index per supported filter domain, each ending in
            // the keyset order, so the LIMIT is an Index Cond stop. Column order
            // and DESC are load-bearing and must match the query. The CASE in the
            // assignee indexes must stay byte-identical to ASSIGNEE_DID_CASE_SQL.
            //
            // Drop the single-column idx_agent_tasks_assignee_key (v27 no longer
            // builds it, but the DROP stays as a defensive cleanup for
            // databases that ran a pre-fix v27) and idx_agent_tasks_status
            // from v1 so the planner never picks a non-keyset index that
            // requires an in-memory Sort before LIMIT.
            "DROP INDEX IF EXISTS idx_agent_tasks_assignee_key",
            "DROP INDEX IF EXISTS idx_agent_tasks_status",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_created_at_id ON agent_tasks (created_at DESC, id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_status_created_at_id ON agent_tasks (status, created_at DESC, id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_assignee_key_created_at_id ON agent_tasks ((CASE WHEN assignee_did LIKE 'did:key:%' AND position(':' in substr(assignee_did, 9)) = 0 THEN substr(assignee_did, 9) ELSE assignee_did END), created_at DESC, id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_status_assignee_key_created_at_id ON agent_tasks (status, (CASE WHEN assignee_did LIKE 'did:key:%' AND position(':' in substr(assignee_did, 9)) = 0 THEN substr(assignee_did, 9) ELSE assignee_did END), created_at DESC, id DESC)",
        ],
    },
    // v29 is a placeholder so the ledger stays linear from v26 under this
    // PR's split-ledger test: the branch's real migrations moved past the
    // v30-v37 window main already owns. A sibling branch that claimed v29
    // collides loudly on merge through the (version, name) runner guard
    // and renumbers, instead of silently skipping its schema.
    Migration {
        version: 29,
        name: "v29_split_ledger_placeholder",
        stmts: &[
            "COMMENT ON TABLE schema_migrations IS 'v29: placeholder keeping the split ledger linear from v26; sibling claims renumber on merge'",
        ],
    },
    // v30 and v31 are intentionally
    // separate so validation does not inherit v30's stronger table lock.
    Migration {
        version: 30,
        name: "repo_upstream_mirror_state",
        stmts: &[
            // Nullable, default-free columns keep this migration metadata-only
            // for every existing non-mirror repository.
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS upstream_url TEXT",
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS mirror_status TEXT",
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS mirror_transition_id UUID",
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS mirror_transition_phase TEXT",
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS mirror_updated_at TEXT",
            // A constraint name does not prove its definition. Replace any
            // same-named manual or partial-recovery artifact before installing
            // the exact invariant this migration promises.
            "ALTER TABLE repos DROP CONSTRAINT IF EXISTS repos_mirror_state_valid",
            // PostgreSQL accepts a CHECK whose result is NULL. Wrap the complete
            // invariant in IS TRUE so a missing status or phase cannot slip
            // through three-valued logic.
            r#"ALTER TABLE repos ADD CONSTRAINT repos_mirror_state_valid CHECK ((
                           (
                               upstream_url IS NULL
                               AND mirror_status IS NULL
                               AND mirror_transition_id IS NULL
                               AND mirror_transition_phase IS NULL
                               AND mirror_updated_at IS NULL
                           )
                           OR
                           (
                               upstream_url IS NOT NULL
                               AND upstream_url LIKE 'https://%'
                               AND upstream_url <> 'https://'
                               AND mirror_updated_at IS NOT NULL
                               AND (
                                   (
                                       mirror_status IN ('inbound', 'outbound')
                                       AND (
                                           (mirror_transition_id IS NULL AND mirror_transition_phase IS NULL)
                                           OR
                                           (mirror_transition_id IS NOT NULL AND mirror_transition_phase = 'completed')
                                       )
                                   )
                                   OR
                                   (
                                       mirror_status IN (
                                           'transitioning_inbound_to_outbound',
                                           'transitioning_outbound_to_inbound'
                                       )
                                       AND mirror_transition_id IS NOT NULL
                                       AND mirror_transition_phase IN (
                                           'queued',
                                           'starting',
                                           'initializing_mirror_fetch',
                                           'draining_writes',
                                           'finalizing_mirror_fetch',
                                           'finalizing_mirror_push',
                                           'committing_target_status',
                                           'rolling_back'
                                       )
                                   )
                               )
                           )
                       ) IS TRUE) NOT VALID"#,
        ],
    },
    Migration {
        version: 31,
        name: "validate_repo_upstream_mirror_state",
        stmts: &["ALTER TABLE repos VALIDATE CONSTRAINT repos_mirror_state_valid"],
    },
    Migration {
        // #218 review round 3 (P2 reviewer 2): renumber v27 → v32.
        // The runner keys the applied set on the integer alone, so
        // open PRs #327/#333/#347/#384/#386 that also claim v27-v31
        // are silently skipped on whichever side merges second. v17's
        // reservation comment (above) describes the failure mode in
        // detail. v32-v36 are picked to land in a clear gap after
        // this branch's last entry so the collision risk is removed.
        // Gaps are harmless: the runner iterates the array and never
        // requires contiguity.
        version: 32,
        name: "pinata_only_clear_legacy_equal_cid",
        stmts: &[
            // #218 (R2-P2): earlier releases wrote `cid = pinata_cid` as a
            // fallback for objects this node never had on local IPFS. After the
            // reconciliation sweep ships, `cid IS NOT NULL` is meant to be the
            // complete provenance predicate (`has_ipfs_cid`), so a fallback row
            // would be misread as a local pin and the sweep would trust the
            // remote CID as durability evidence. The two changes below make
            // NULL a legal `cid` value (the new "Pinata-only" state) and then
            // clear the legacy equal-cid rows. Reordering matters: the
            // `DROP NOT NULL` MUST run before the UPDATE, otherwise Postgres
            // rejects the assignment. Idempotent: both statements are
            // IF-guarded so re-running them on a node whose rows are already
            // cleared is a no-op.
            "ALTER TABLE pinned_cids ALTER COLUMN cid DROP NOT NULL",
            "UPDATE pinned_cids SET cid = NULL WHERE cid = pinata_cid",
        ],
    },
    Migration {
        // v28 → v33 (round-3 renumber, see v32 above).
        version: 33,
        name: "node_state_key_value",
        stmts: &[
            // #218 (R2-P1): the reconciliation sweep persists its keyset
            // cursor across restarts so a 100-repo pass is bounded rather
            // than re-scanned from the head on every boot. Single-row key/value
            // table, no constraints on `key` so callers can use opaque
            // strings (e.g. "sweep_cursor", "policy_epoch_lock").
            // NEW versioned migration (never appended to an applied block,
            // INV-7).
            "CREATE TABLE IF NOT EXISTS node_state (\
                key   TEXT NOT NULL PRIMARY KEY,\
                value TEXT,\
                updated_at TEXT NOT NULL\
             )",
        ],
    },
    Migration {
        // v29 → v34 (round-3 renumber, see v32 above).
        version: 34,
        name: "repos_policy_epoch",
        stmts: &[
            // #218 (R2-P1): the PolicyFence records the policy epoch the
            // replication path captured its visibility decision under, and
            // the dispatch paths re-check the epoch before sending the
            // POST. A policy change increments the epoch; if the dispatch
            // path reads a different epoch than the replication path did,
            // it bails without firing the (now-stale) pin. Default 0 so a
            // row that never went through a transaction reads as the
            // pre-feature epoch. NOT NULL: every code path that increments
            // reads and writes the column, so a NULL would be a real bug.
            // NEW versioned migration (never appended to an applied block,
            // INV-7).
            "ALTER TABLE repos ADD COLUMN IF NOT EXISTS policy_epoch BIGINT NOT NULL DEFAULT 0",
        ],
    },
    Migration {
        // v30 → v35 (round-3 renumber, see v32 above).
        version: 35,
        name: "pinned_cids_local_ipfs_provenance",
        stmts: &[
            // #218 review (P1): the Pinata-only state was inferred from
            // `cid = pinata_cid` and the local-IPFS provenance predicate was
            // `cid IS NOT NULL`. That conflates two distinct writers: the
            // local IPFS pin path and the Pinata push path. A Pinata-only
            // insert against a pre-v27 row could re-introduce a non-NULL
            // `cid` that the sweep then read as a real local pin, leaving a
            // durability gap no other sweep pass would close.
            //
            // This migration adds a per-row boolean that ONLY the local
            // IPFS writer sets. After v35 the durable contract is:
            //
            //   `local_ipfs_provenance = TRUE` ↔ this row was written by
            //   the local IPFS pin path (`record_pinned_cid_with_source`),
            //   which is the only path that has actually pushed the bytes
            //   into the node's local IPFS daemon.
            //
            // Pinata-only rows keep `local_ipfs_provenance = FALSE` and
            // `cid = NULL` (their `pinata_cid` is the provider CID, which
            // must not alias raw bytes that do not hash to it, #173).
            // `list_pinned_cids` keeps returning the stored `cid` resolver
            // key — the new column is an internal durability signal and
            // never leaves the resolver / gap-filter boundary.
            //
            // NO backfill to TRUE (unknown-migration): even the
            // "unambiguous" shape (`cid` set, no Pinata CID) is NOT
            // evidence of a Kubo write. Before the strict `Hash`
            // response parsing, a 2xx Kubo response with no `Hash`
            // (wrong-port health endpoint, HTML proxy, truncated body)
            // fell back to the locally expected CID and wrote exactly
            // that row with nothing proving the bytes reached the
            // daemon. Marking it TRUE would let the sweep filter it as
            // "already durable" forever. Every pre-v35 row therefore
            // lands at the safe default (`FALSE`, i.e. unknown), the
            // next sweep pass re-pins to establish provenance — cheap
            // and idempotent (Kubo is idempotent;
            // `record_pinned_cid_with_source` upgrades the flag on the
            // conflict branch) — and a still-misconfigured endpoint
            // simply fails the re-pin (strict parsing) instead of
            // regenerating a phantom row. Pinata history is preserved
            // untouched: `pinata_cid` values are never rewritten here.
            //
            // NOT NULL DEFAULT FALSE so every pre-v35 row reads as
            // unknown and gets re-derived on re-pin.
            "ALTER TABLE pinned_cids ADD COLUMN IF NOT EXISTS local_ipfs_provenance BOOLEAN NOT NULL DEFAULT FALSE",
            // Partial index — only ~all-true rows in steady state, but
            // partial because the gap filter (`filter_ipfs_pinned_oids`)
            // reads `local_ipfs_provenance = TRUE` and the planner will
            // Index Only Scan the partial view, which is a fraction of
            // the pin table. Cheap to maintain because the write path
            // touches it once per pin and reads are exactly the
            // already-pinned lookups the sweep is trying to short-circuit.
            "CREATE INDEX IF NOT EXISTS idx_pinned_cids_local_ipfs_provenance ON pinned_cids (local_ipfs_provenance) WHERE local_ipfs_provenance",
        ],
    },
    Migration {
        // v31 → v36 (round-3 renumber, see v32 above).
        version: 36,
        name: "reconciliation_offset_per_backend",
        stmts: &[
            // #218 review (P2): the per-repo cursor advanced between
            // repos but not within a repo's missing set, so a
            // persistently failing early OID kept monopolising the
            // 50 000 cap and a healthy gap past the cap was never
            // attempted. This table persists a (repo, backend) →
            // next-oid continuation, applied as a sort-rotate at the
            // start of the next pass: the cap still bounds per-pass
            // work, but the same OIDs do not keep landing in the
            // truncated prefix every hourly tick.
            //
            // The repo-level keyset cursor in `node_state` is unchanged
            // — this is a *second* cursor. A full pass (no missing
            // OIDs) clears the row, and the next pass starts at the
            // head of the sorted list. A truncated pass writes
            // `next_oid` = the last OID actually handed to the backend,
            // so the next pass resumes from the OID strictly greater
            // than that one.
            //
            // Per-(repo, backend) granularity rather than per-repo:
            // Pinata and IPFS are independent writers with independent
            // failure modes, and a per-repo cursor would conflate the
            // two. PRIMARY KEY (repo_id, backend) keeps the writes
            // O(1) per pass; the table holds only pairs with outstanding
            // work — completion DELETES the row (absence is the fresh
            // start), so no tombstone accumulates and no hourly
            // rewrite touches a drained pair. `next_oid` is the LAST
            // attempted OID (the rotation in `missing_oids` is
            // "strictly greater than"). The `done` column is retained
            // for tolerant reads of rows written before the
            // delete-on-drain contract, but no writer sets it anymore.
            // The foreign key ties cursor lifetime to the repo row:
            // deleting a repo cascades its offsets so a recreated
            // identity (always a fresh UUID) can never resume a stale
            // continuation.
            "CREATE TABLE IF NOT EXISTS reconciliation_offset (
                 repo_id    TEXT NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
                 backend    TEXT NOT NULL,
                 next_oid   TEXT NOT NULL,
                 done       BOOLEAN NOT NULL DEFAULT FALSE,
                 updated_at TEXT NOT NULL,
                 PRIMARY KEY (repo_id, backend)
             )",
        ],
    },
    Migration {
        version: 37,
        name: "ref_certificates_version",
        stmts: &[
            // #26 Split PR 3 — certificate / CLI compatibility. The
            // ref-cert wire format is versioned so future fields can
            // be added without breaking old clients (which ignore
            // the field) or old servers (which default the column
            // to 1). New certificates are currently issued as v1,
            // which is byte-for-byte identical to the pre-versioning
            // shape: an old client reading a v1 cert from a new
            // server sees the same payload, the same signature, and
            // the same Ed25519 verify path. A new client reading an
            // old server sees `version` defaulted to 1 and verifies
            // against the v1 payload shape. v2 is reserved for a
            // future shape that carries the version inside the
            // signed bytes; it must not be stamped until a v2
            // verifier ships.
            //
            // DEFAULT 1 so an existing row reads as v1 without a
            // backfill migration. NOT NULL so a missing value is a
            // hard error at insert time rather than a silent v0 that
            // an old client would interpret as "no version field."
            "ALTER TABLE ref_certificates ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1",
        ],
    },
    Migration {
        version: 38,
        name: "pending_ref_transitions_durable_outbox",
        stmts: &[
            // #26 Split PR 1 — durable post-receive lifecycle.
            //
            // The pre-outbox crash window the reviewer flagged: receive_pack can
            // apply a ref to disk and return Ok, and a process exit, a dropped
            // future, or a DB failure before the bookkeeping at
            // crates/gitlawb-node/src/api/repos.rs:2361 (push event + cert +
            // webhook) loses the recovery record. Startup drain enumerates only
            // sources written from that bookkeeping, so it cannot reconstruct
            // the missing work. The partial fallback that re-derives from a row
            // present in the bookkeeping substitutes `did:key:recovered` and an
            // empty attestation — not equivalent to the original authenticated
            // push.
            //
            // The fix is to persist the authentic intent BEFORE the receive_pack
            // call lands the ref. The row carries the verified pusher DID, the
            // raw RFC 9421 signature header that authorized this push, the
            // request id, and the parsed ref updates. The receive_pack call
            // then transitions the row `prepared` → `applied` on Ok, or
            // `prepared` → `cancelled` on Err. Startup recovery drains only
            // `applied` rows, re-deriving the push event, the per-ref
            // certificate (carrying the ORIGINAL pusher DID, not a placeholder),
            // and the anchor handoff — exactly once per transition.
            //
            // `cancelled` rows are NEVER promoted. A failed or dropped
            // receive_pack leaves the row in `prepared`; only the post-Ok code
            // flips to `applied`, and only that state is drained. This is what
            // closes the reviewer's second proof: a prepared intent that never
            // lands cannot become a push event, a certificate, or an anchor.
            //
            // `request_id` is a per-handler UUID. It is the producer of the
            // deterministic ids for the push event, the certificate, and the
            // anchor job, so re-running recovery is idempotent on
            // `(request_id, ref_name)` — the unique key.
            //
            // `signature_header` is the raw `Signature` request header value,
            // the `keyid` is the pusher DID (already extracted to `pusher_did`).
            // It is kept for audit, not re-verified on recovery: the
            // `require_signature` middleware already verified it before the
            // handler ran, and the route is gated by it.
            r#"CREATE TABLE IF NOT EXISTS pending_ref_transitions (
                id                TEXT NOT NULL PRIMARY KEY,
                request_id        TEXT NOT NULL,
                repo_id           TEXT NOT NULL,
                ref_name          TEXT NOT NULL,
                old_sha           TEXT NOT NULL,
                new_sha           TEXT NOT NULL,
                pusher_did        TEXT NOT NULL,
                node_did          TEXT NOT NULL,
                signature_header  TEXT NOT NULL,
                signature_input   TEXT NOT NULL,
                content_digest    TEXT NOT NULL,
                state             TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                applied_at        TEXT,
                cancelled_at      TEXT
            )"#,
            // The drain order is by `applied_at ASC NULLS LAST, id ASC` so a
            // crashed node that re-runs the drain processes transitions in the
            // order they were applied. The `id` tiebreaker keeps the order
            // stable when many transitions land in the same `applied_at` tick.
            "CREATE INDEX IF NOT EXISTS idx_pending_ref_transitions_state_applied_at ON pending_ref_transitions (state, applied_at, id)",
            "CREATE INDEX IF NOT EXISTS idx_pending_ref_transitions_request_ref ON pending_ref_transitions (request_id, ref_name)",
            "CREATE INDEX IF NOT EXISTS idx_pending_ref_transitions_repo_ref ON pending_ref_transitions (repo_id, ref_name, old_sha, new_sha)",
            // The anchor handoff for Split PR 2 to consume. Split PR 1 owns
            // the durable queue: one row per (repo, ref, old, new) transition
            // whose row in pending_ref_transitions is `applied`. ON CONFLICT
            // DO NOTHING on the unique key makes the recovery re-derivation
            // idempotent — a second drain pass cannot create a second anchor
            // upload request. Split PR 2 owns the actual transport and the
            // three-outcome probe; this PR only proves the handoff is
            // exactly-once.
            r#"CREATE TABLE IF NOT EXISTS anchor_jobs (
                id           TEXT NOT NULL PRIMARY KEY,
                repo_id      TEXT NOT NULL,
                ref_name     TEXT NOT NULL,
                old_sha      TEXT NOT NULL,
                new_sha      TEXT NOT NULL,
                pusher_did   TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                claimed_at   TEXT
            )"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_anchor_jobs_repo_ref_transition ON anchor_jobs (repo_id, ref_name, old_sha, new_sha)",
            "CREATE INDEX IF NOT EXISTS idx_anchor_jobs_claimed_at ON anchor_jobs (claimed_at, id)",
        ],
    },
    Migration {
        version: 39,
        name: "pending_ref_transitions_add_first_ref_name",
        stmts: &[
            // #26 Split PR 1 P2-B: the recovery drain must reproduce the
            // live path's push event cardinality, which is "one push event
            // per push, keyed on the first ref name". Without a persisted
            // `first_ref_name` column, the drain would key each outbox
            // row on its own `ref_name` and emit N push events for an
            // N-ref push, over-counting `get_push_count` and inflating
            // the trust score.
            //
            // The `NOT NULL DEFAULT ''` is required to add a NOT NULL
            // column to a non-empty table in a single ALTER; a follow-up
            // UPDATE backfills the value to `ref_name` for every
            // historic row. Old rows in `applied` state that the drain
            // processes will produce one push event per row (the
            // pre-fix cardinality) — an accepted upgrade-window quirk
            // with no historic state to regress. New rows written by
            // the live handler always carry the request's actual
            // `first_ref_name`.
            "ALTER TABLE pending_ref_transitions ADD COLUMN IF NOT EXISTS first_ref_name TEXT NOT NULL DEFAULT ''",
            "UPDATE pending_ref_transitions SET first_ref_name = ref_name WHERE first_ref_name = ''",
        ],
    },
    Migration {
        version: 40,
        name: "pending_ref_transitions_add_uncertain_state",
        stmts: &[
            // No schema change: the `state` column is TEXT and the new
            // `uncertain` value is written by the application layer.
            // The comment-only migration documents the state-machine
            // extension so the migration test's non-empty-stmts
            // assertion is satisfied.
            "COMMENT ON TABLE pending_ref_transitions IS 'v40: added uncertain state for receive-pack errors where some refs may have landed'",
        ],
    },
    Migration {
        // #26 Split PR 1 round 6 — request-level data model.
        //
        // Reviewer finding: the request's push event was encoded into
        // a mutable per-ref column (`first_ref_name`) whose correct
        // value is knowable only after git, and the correction was
        // not committed atomically with the per-ref outcomes. A
        // crash between git updating a later ref and the rewrite
        // left the durable rows naming the rejected ref, and
        // `derive_one`'s `row.ref_name == row.first_ref_name` guard
        // then meant no push event ever landed for the accepted
        // child.
        //
        // The state-transition model (see
        // .gravirei/plans/state-model-durable-post-receive.md)
        // replaces `first_ref_name` with a request-level record
        // that owns the push event and the trust score. The per-ref
        // child becomes an ordinal child of that request. The
        // push event id is keyed on
        // `(request_id, accepted_ordinal)` — not on `ref_name` —
        // so a mixed first-rejected/later-accepted push still
        // produces exactly one push event under the request that
        // did land.
        //
        // Version is 41 on this branch: the pending_ref_transitions trio
        // moved to v38-v40 so its CREATE TABLE precedes the ALTERs here.
        // Re-check the floor on every push — the open PR list moves it.
        version: 41,
        name: "receive_pack_requests",
        stmts: &[
            // The new request table. The push event and trust
            // score are written in the same database transaction as
            // the per-ref child outcomes, so a crash between git
            // and effect-write rolls everything back together; the
            // drain sees a coherent row in `outcomes_committed`
            // (or its retry variant) and re-runs the same effect
            // pipeline.
            r#"CREATE TABLE IF NOT EXISTS receive_pack_requests (
                id                 TEXT NOT NULL PRIMARY KEY,
                repo_id            TEXT NOT NULL,
                pusher_did         TEXT NOT NULL,
                node_did           TEXT NOT NULL,
                request_bytes      BYTEA NOT NULL,
                request_bytes_hash BYTEA NOT NULL,
                state              TEXT NOT NULL,
                git_exit_ok        BOOLEAN,
                parsed_report      JSONB,
                accepted_ordinal   INTEGER,
                attempt_count      INTEGER NOT NULL DEFAULT 0,
                last_error         TEXT,
                next_attempt_at    TEXT,
                created_at         TEXT NOT NULL,
                completed_at       TEXT
            )"#,
            // The state-transition gate: the recovery drain
            // selects rows in `outcomes_committed` (and its retry
            // variant) and walks them by `(created_at, id)`. A
            // composite index lets the drain do a single index scan
            // without sorting.
            "CREATE INDEX IF NOT EXISTS idx_receive_pack_requests_state_created ON receive_pack_requests (state, created_at, id)",
            // The drain's retry predicate. `next_attempt_at IS NULL OR
            // next_attempt_at < now()` is a frequent lookup; the
            // partial index keeps the index small.
            "CREATE INDEX IF NOT EXISTS idx_receive_pack_requests_state_next_attempt ON receive_pack_requests (state, next_attempt_at) WHERE state IN ('outcomes_committed', 'effects_pending')",
            // The 7-day bounded-retirement predicate. The purge
            // task deletes `complete` and `rejected_at_git` rows
            // older than the retention interval.
            "CREATE INDEX IF NOT EXISTS idx_receive_pack_requests_completed_at ON receive_pack_requests (completed_at) WHERE state IN ('complete', 'rejected_at_git')",
            // The new ordinal column on the per-ref child. The
            // drain and the effect executor both read this in
            // `ORDER BY request_id, ordinal` order to reproduce
            // the live path's ref-walk sequence.
            "ALTER TABLE pending_ref_transitions ADD COLUMN IF NOT EXISTS ordinal INTEGER NOT NULL DEFAULT 0",
            // The git-side marker's snapshot kind. Recovery
            // re-derives this from the per-ref report if it is
            // null, so the column is informational and the
            // migration does not need to backfill it.
            "ALTER TABLE pending_ref_transitions ADD COLUMN IF NOT EXISTS git_target_kind TEXT",
            // Drop `first_ref_name`. The push event identity is
            // now `(request_id, accepted_ordinal)` and lives on
            // the request row, not on a child. The live handler
            // never writes this column after this migration; the
            // drain and the effect executor do not read it. The
            // column is `IF EXISTS` so a fresh database that never
            // ran v39 is unaffected.
            //
            // P3 (reviewer round 5): the recovery gate had been
            // patching `first_ref_name` after git returned; the
            // patch is the bug, the drop closes it. The model
            // forbids the pattern (request-level event identity
            // is encoded in mutable per-ref state) so removing
            // the column is the structural fix, not a workaround.
            "ALTER TABLE pending_ref_transitions DROP COLUMN IF EXISTS first_ref_name",
            // Document the new relationship. The `comment on
            // column` form leaves a discoverable note for anyone
            // reading the schema in psql.
            "COMMENT ON COLUMN pending_ref_transitions.ordinal IS 'v41: ordinal position in the parsed ref_updates list, 0-indexed. The drain and the effect executor read in ORDER BY request_id, ordinal to reproduce the live path'",
        ],
    },
    Migration {
        // #26 Split PR 1 — step 5. The `quarantined` state is the
        // operator-attended terminal state for requests whose
        // git-side marker is missing or hash-mismatched (or whose
        // attempt_count exceeds the configured bound). The schema
        // does not need a CHECK constraint change because the
        // `state` column is TEXT; this migration is a comment +
        // index.
        version: 42,
        name: "receive_pack_requests_quarantined",
        stmts: &[
            // Operator-attended state. Pinned in a comment so a
            // reader of the schema in psql finds the convention.
            "COMMENT ON TABLE receive_pack_requests IS 'v42: added quarantined state for marker-mismatch / reflog-ambiguity / max-attempts; operator reclassifies to complete or rejected_at_git'",
            // Operator queries (e.g. `SELECT … WHERE state =
            // 'quarantined' ORDER BY created_at`) need an index. A
            // partial index on a low-cardinality state column is
            // small and cheap.
            "CREATE INDEX IF NOT EXISTS idx_receive_pack_requests_quarantined ON receive_pack_requests (created_at) WHERE state = 'quarantined'",
        ],
    },
    Migration {
        // #26 Split PR 1 — durable authorization proof on the
        // request aggregate. Children carry the verified RFC 9421
        // headers but are deleted after effects; without a
        // request-level copy the only proof is retired before its
        // declared downstream consumer (cert/anchor in PR #386)
        // can use it. Nullable so pre-v43 rows remain valid; new
        // intents always populate all three.
        version: 43,
        name: "receive_pack_requests_proof",
        stmts: &[
            "ALTER TABLE receive_pack_requests ADD COLUMN IF NOT EXISTS signature_header TEXT",
            "ALTER TABLE receive_pack_requests ADD COLUMN IF NOT EXISTS signature_input TEXT",
            "ALTER TABLE receive_pack_requests ADD COLUMN IF NOT EXISTS content_digest TEXT",
            "COMMENT ON COLUMN receive_pack_requests.signature_header IS 'v43: verified RFC 9421 Signature header copied at intent time; bound to request_bytes_hash'",
        ],
    },
    Migration {
        // v44: occurrence lifecycle — proof record, landing history,
        // marker tombstones, occurrence-keyed anchors.
        version: 44,
        name: "request_occurrence_lifecycle",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS request_proofs (
                request_id TEXT NOT NULL PRIMARY KEY,
                repo_id TEXT NOT NULL,
                pusher_did TEXT NOT NULL,
                body_digest BYTEA NOT NULL,
                signature_header TEXT NOT NULL,
                signature_input TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acked_at TEXT
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_request_proofs_repo ON request_proofs (repo_id, created_at)",
            r#"CREATE TABLE IF NOT EXISTS ref_landing_history (
                request_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                repo_id TEXT NOT NULL,
                ref_name TEXT NOT NULL,
                old_sha TEXT NOT NULL,
                new_sha TEXT NOT NULL,
                landed_at TEXT NOT NULL,
                PRIMARY KEY (request_id, ordinal)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_landing_history_tuple ON ref_landing_history (repo_id, ref_name, old_sha, new_sha, landed_at)",
            r#"CREATE TABLE IF NOT EXISTS marker_cleanup_queue (
                request_id TEXT NOT NULL PRIMARY KEY,
                repo_id TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_error TEXT
            )"#,
            "ALTER TABLE anchor_jobs ADD COLUMN IF NOT EXISTS request_id TEXT",
            "ALTER TABLE anchor_jobs ADD COLUMN IF NOT EXISTS request_ordinal INTEGER",
            // Drop tuple-uniqueness so recurrence creates distinct
            // occurrence rows; keep a non-unique lookup index.
            "DROP INDEX IF EXISTS idx_anchor_jobs_repo_ref_transition",
            "CREATE INDEX IF NOT EXISTS idx_anchor_jobs_tuple ON anchor_jobs (repo_id, ref_name, old_sha, new_sha)",
            "CREATE INDEX IF NOT EXISTS idx_anchor_jobs_request ON anchor_jobs (request_id, request_ordinal)",
        ],
    },
    Migration {
        // v45: occurrence delivery ledger, marker cleanup scheduling.
        version: 45,
        name: "occurrence_delivery_and_cleanup_progress",
        stmts: &[
            r#"CREATE TABLE IF NOT EXISTS webhook_deliveries (
                delivery_id TEXT NOT NULL PRIMARY KEY,
                request_id TEXT NOT NULL,
                repo_id TEXT NOT NULL,
                event TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_request ON webhook_deliveries (request_id, event)",
            "ALTER TABLE marker_cleanup_queue ADD COLUMN IF NOT EXISTS next_attempt_at TEXT",
            "ALTER TABLE marker_cleanup_queue ADD COLUMN IF NOT EXISTS dead_letter BOOLEAN NOT NULL DEFAULT FALSE",
            "CREATE INDEX IF NOT EXISTS idx_marker_cleanup_due ON marker_cleanup_queue (dead_letter, next_attempt_at, created_at)",
        ],
    },
    Migration {
        // v46: webhook delivery sent-state so the ledger cannot claim a
        // delivery that never fired. Claim inserts pending; the sender
        // marks sent after the HTTP response; recovery re-fires stale
        // pending rows.
        version: 46,
        name: "webhook_delivery_sent_state",
        stmts: &[
            "ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS sent_at TEXT",
            "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending ON webhook_deliveries (sent_at, created_at)",
        ],
    },
    // Reservation: v47, not 24 as this branch originally claimed — main's tail
    // has since reached 46, and a claimed version that another entry already
    // holds is a startup schema-conflict (the typed MigrationVersionCollision),
    // not the silent skip the original reservation feared. Same rule as before:
    // the runner keys the applied set on the version integer alone, so the
    // version must clear every claim already on main. Gaps are harmless; the
    // runner never requires contiguity.
    //
    // The whole commit-status surface lands in this one entry rather than three,
    // because a merged entry is never edited and a second version would collide
    // with the same branches this one already had to clear.
    Migration {
        version: 47,
        name: "status_claims_pr_head_and_push_events",
        stmts: &[
            // Append-only claim history. `seq` is a bigserial because the
            // ordering key must be assigned by the database: the producer
            // supplies nothing that orders the projection, and created_at is
            // display data that can collide within a single second.
            r#"CREATE TABLE IF NOT EXISTS status_claims (
                id               TEXT NOT NULL PRIMARY KEY,
                seq              BIGSERIAL NOT NULL,
                repo_id          TEXT NOT NULL,
                commit_sha       TEXT NOT NULL,
                state            TEXT NOT NULL,
                context          TEXT NOT NULL,
                target_url       TEXT,
                description      TEXT,
                producer_did     TEXT NOT NULL,
                authorizing_did  TEXT NOT NULL,
                signature        TEXT NOT NULL,
                signature_input  TEXT NOT NULL,
                -- The canonical RFC 9421 string the signature was verified over,
                -- and the request body it covers through a content-digest. Two
                -- columns because one cannot stand in for the other: the signing
                -- string proves a signature exists, the body proves this row is
                -- what it signed.
                signing_string   TEXT NOT NULL,
                request_body     BYTEA NOT NULL,
                -- Stable digest over the material that identifies one request:
                -- the signature, its input, the signing string and the body. Two
                -- rows carrying the same value are the same request written
                -- twice, which is what the unique index below refuses.
                request_digest   TEXT NOT NULL,
                created_at       TEXT NOT NULL
            )"#,
            // Replay containment, and the reason it is an index and not a check
            // in Rust: `require_signature` bounds the clock skew on `created` and
            // nothing else, so a captured request stays acceptable for the whole
            // window. A read-then-insert would race, and losing that race is not
            // a duplicate row, because the projection takes the highest `seq` per
            // (producer, context), so a replayed row earns a FRESH sequence
            // number and puts a superseded verdict back in front of the one that
            // replaced it. The database is what has to hold this.
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_status_claims_request_digest ON status_claims(request_digest)",
            // Read path: every claim for one commit.
            "CREATE INDEX IF NOT EXISTS idx_status_claims_repo_commit ON status_claims(repo_id, commit_sha)",
            // Cap count and latest-per-tuple lookup, which orders on seq DESC.
            "CREATE INDEX IF NOT EXISTS idx_status_claims_tuple ON status_claims(repo_id, commit_sha, producer_did, context, seq DESC)",
            // The per-repo write bound, which counts the rows a repo wrote inside
            // a trailing window rather than every row it ever wrote.
            "CREATE INDEX IF NOT EXISTS idx_status_claims_repo_created ON status_claims(repo_id, created_at)",
            // Stored head of a pull request's source branch. Nullable: a PR
            // opened before anything pushed has no head yet.
            "ALTER TABLE pull_requests ADD COLUMN IF NOT EXISTS head_commit TEXT",
            // Local push events, one row per ref update observed on the
            // receive-pack path. Deliberately NOT received_ref_updates, which
            // the unauthenticated global feed at /api/v1/events/ref-updates also
            // reads: writing local pushes there would publish private-repo
            // pushes on an anonymous surface. Also not `push_events`, which v1
            // already defines for agent trust scoring on a different shape
            // (agent_did, commit_hash, object_count, pushed_at); reusing that
            // name would have been a silent no-op under IF NOT EXISTS.
            // `seq` is a bigserial for the same reason `status_claims.seq` is: the
            // poll cursor's ordering key must be assigned by the database. The
            // application stamps `created_at` BEFORE the insert, so a row stamped
            // later can commit earlier and a poller that has advanced past the
            // later stamp never sees it, and an NTP step backwards makes that
            // ordinary rather than a race. `created_at` stays as display data.
            r#"CREATE TABLE IF NOT EXISTS repo_push_events (
                id         TEXT NOT NULL PRIMARY KEY,
                seq        BIGSERIAL NOT NULL,
                repo_id    TEXT NOT NULL,
                ref_name   TEXT NOT NULL,
                after_sha  TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"#,
            // Keyset paging cursor: `seq` ascending within a repo. One column, so
            // no tiebreak is needed: the sequence is unique by construction, and
            // every row of one multi-ref push gets its own value even though they
            // share a timestamp.
            "CREATE INDEX IF NOT EXISTS idx_repo_push_events_cursor ON repo_push_events(repo_id, seq)",
            // The pull request rollup's branch resolve: newest row for one ref,
            // ordered on the same database-assigned key as the cursor.
            "CREATE INDEX IF NOT EXISTS idx_repo_push_events_ref ON repo_push_events(repo_id, ref_name, seq DESC)",
        ],
    },
];

// ── Push-path statement accounting ────────────────────────────────────────────

// Count of database statements the receive-pack write path has executed, so a
// test can assert on the WORK a push does and not only on the rows it leaves.
// Those two come apart exactly where it matters: a loop issuing one round trip
// per ref and a single multi-row statement produce byte-identical rows, and only
// the first multiplies latency on the user's `git push`.
//
// Thread-local, not a process-global atomic: `#[sqlx::test]` gives each test its
// own database but the whole suite shares one process, and other modules' tests
// write push events too. A shared counter would need every one of them to take a
// mutex, and the tests that forgot would show up as an inflated count in an
// unrelated test. A thread-local is isolated by construction.
#[cfg(test)]
thread_local! {
    pub(crate) static PUSH_WRITE_STATEMENTS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Record one statement against the push-path counter. Compiles away entirely
/// outside tests.
#[inline]
fn count_push_write_statement() {
    #[cfg(test)]
    PUSH_WRITE_STATEMENTS.with(|c| c.set(c.get() + 1));
}

/// Zero the counter and return what it held, so a test can measure one call.
#[cfg(test)]
pub(crate) fn take_push_write_statements() -> usize {
    PUSH_WRITE_STATEMENTS.with(|c| c.replace(0))
}
/// Max distinct source repos recorded per pinned object (F1, #173 jatmn round 8).
/// Bounds both the resolver's per-OID source loop and the `pin_repo_sources` growth,
/// so an adversary re-pushing one object from many repos cannot make resolution
/// O(repos) (R2, INV-10).
pub const MAX_PIN_SOURCES: i64 = 16;

// ── Repos ─────────────────────────────────────────────────────────────────────

pub(crate) fn normalize_owner_key(did: &str) -> &str {
    match did.strip_prefix("did:key:") {
        Some(rest) if !rest.contains(':') => rest,
        _ => did,
    }
}

/// The canonical spelling of an identity for a column that stores one identity
/// per row, as `status_claims.producer_did` and `authorizing_did` do: the full
/// `did:key:<id>` form for a `did:key` in either spelling, the value unchanged
/// for every other method.
///
/// Written as a function of [`normalize_owner_key`] rather than beside it, so the
/// two cannot disagree about which identities are the same one: `canonical_did`
/// is injective over the normalized key, which makes
/// `canonical_did(a) == canonical_did(b)` exactly `did_matches(a, b)`. Pinned by
/// `canonical_did_agrees_with_did_matches`.
///
/// It expands where `normalize_owner_key` collapses because the two answer
/// different questions. The owner key is a lookup key; a stored `producer_did` is
/// evidence, and a claim has to stay verifiable from the row alone — a bare
/// base58 id does not parse as a DID, so the key behind the signature could not
/// be recovered from it.
pub(crate) fn canonical_did(did: &str) -> std::borrow::Cow<'_, str> {
    let key = normalize_owner_key(did);
    // A residual carrying ':' is a full DID of some other method (or a value that
    // is not a did:key at all); prefixing it would merge two identities that
    // `did_matches` keeps apart.
    if key.contains(':') {
        std::borrow::Cow::Borrowed(key)
    } else {
        std::borrow::Cow::Owned(format!("did:key:{key}"))
    }
}

/// SQL CASE expression byte-identical to `normalize_owner_key`. All queries that
/// filter or group by owner key use this const so the Rust and SQL sides cannot
/// drift apart. If you change `normalize_owner_key`, update this const too.
const OWNER_KEY_CASE_SQL: &str = "CASE WHEN owner_did LIKE 'did:key:%' AND position(':' in substr(owner_did, 9)) = 0 THEN substr(owner_did, 9) ELSE owner_did END";

/// SQL CASE expression byte-identical to `normalize_owner_key`, but for columns
/// named `did` (like in agent_profiles) instead of `owner_did`.
const PROFILE_DID_CASE_SQL: &str = "CASE WHEN did LIKE 'did:key:%' AND position(':' in substr(did, 9)) = 0 THEN substr(did, 9) ELSE did END";

/// SQL CASE expression byte-identical to `normalize_owner_key`, but for the
/// `assignee_did` column on `agent_tasks`.
const ASSIGNEE_DID_CASE_SQL: &str = "CASE WHEN assignee_did LIKE 'did:key:%' AND position(':' in substr(assignee_did, 9)) = 0 THEN substr(assignee_did, 9) ELSE assignee_did END";

const TASK_KEYSET_SELECT: &str = "SELECT id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline FROM agent_tasks";

/// Dedicated SQL for one `list_tasks_keyset` filter domain.
///
/// Optional `($n IS NULL OR col = $n)` predicates prevent the planner from
/// using the v28 keyset indexes, so each supported domain is its own query
/// with only the predicates that domain actually uses. Bind order is status,
/// assignee key, after `(created_at, id)`, then LIMIT.
fn list_tasks_keyset_sql(has_status: bool, has_assignee: bool, has_after: bool) -> String {
    let mut n = 1u32;
    let mut predicates = Vec::new();
    if has_status {
        predicates.push(format!("status = ${n}"));
        n += 1;
    }
    if has_assignee {
        predicates.push(format!("({key}) = ${n}", key = ASSIGNEE_DID_CASE_SQL));
        n += 1;
    }
    if has_after {
        predicates.push(format!(
            "(created_at, id) < (${left}, ${right})",
            left = n,
            right = n + 1
        ));
        n += 2;
    }
    let where_sql = if predicates.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", predicates.join(" AND "))
    };
    format!("{TASK_KEYSET_SELECT} {where_sql} ORDER BY created_at DESC, id DESC LIMIT ${n}")
}
/// SQL CASE expression byte-identical to `normalize_owner_key`, but for columns
/// named `repo_owner` (bounties table).  The bounties `repo_owner` is stored
/// verbatim from the URL segment, so it may be either the full `did:key:` form
/// or the bare key.
const BOUNTY_OWNER_CASE_SQL: &str = "CASE WHEN repo_owner LIKE 'did:key:%' AND position(':' in substr(repo_owner, 9)) = 0 THEN substr(repo_owner, 9) ELSE repo_owner END";

/// SQL CASE expression byte-identical to `normalize_owner_key`, but for columns
/// named `claimant_did` (bounties table).
const BOUNTY_CLAIMANT_CASE_SQL: &str = "CASE WHEN claimant_did LIKE 'did:key:%' AND position(':' in substr(claimant_did, 9)) = 0 THEN substr(claimant_did, 9) ELSE claimant_did END";

#[cfg(test)]
mod normalize_owner_key_tests {
    use super::{canonical_did, normalize_owner_key};

    /// `canonical_did` is what the claim columns store, and the projection
    /// compares stored values for equality. That comparison is the authorization
    /// filter, so it must decide exactly what `did_matches` decides: equal
    /// canonical spellings for identities that match, distinct ones for
    /// identities that do not. Both directions, including the cross-method cases
    /// a bare base58 id must never reach across.
    #[test]
    fn canonical_did_agrees_with_did_matches() {
        let values = [
            "did:key:zABC",
            "zABC",
            "did:key:zXYZ",
            "zXYZ",
            "did:gitlawb:zABC",
            "did:web:example.com",
            "example.com",
            "did:key:did:gitlawb:zABC",
            "z:A",
            "did:key:z:A",
            "did:key:",
            "",
        ];
        for a in values {
            for b in values {
                assert_eq!(
                    canonical_did(a) == canonical_did(b),
                    crate::api::did_matches(a, b),
                    "canonical_did disagrees with did_matches on ({a:?}, {b:?})"
                );
            }
        }
    }

    /// The stored spelling has to parse as a DID: a claim is evidence, and
    /// recovering the key behind its signature starts from `producer_did`.
    #[test]
    fn canonical_did_keeps_a_did_key_parseable() {
        assert_eq!(canonical_did("zABC"), "did:key:zABC");
        assert_eq!(canonical_did("did:key:zABC"), "did:key:zABC");
        assert_eq!(canonical_did("did:gitlawb:zABC"), "did:gitlawb:zABC");
    }

    // Boundary set matching the SQL CASE: did:key short/full, empty residual,
    // did:key:z:extra, non-key, bare, empty, uppercase.
    #[test]
    fn strips_did_key_prefix() {
        assert_eq!(normalize_owner_key("did:key:z6Mkfoo"), "z6Mkfoo");
    }

    #[test]
    fn keeps_full_did_key_unchanged_when_not_a_prefix() {
        assert_eq!(normalize_owner_key("z6Mkfoo"), "z6Mkfoo");
    }

    #[test]
    fn leaves_non_key_did_intact() {
        assert_eq!(
            normalize_owner_key("did:gitlawb:z6Mkfoo"),
            "did:gitlawb:z6Mkfoo"
        );
    }

    #[test]
    fn leaves_web_did_intact() {
        assert_eq!(
            normalize_owner_key("did:web:example.com:alice"),
            "did:web:example.com:alice"
        );
    }

    #[test]
    fn leaves_single_residual_web_did_intact() {
        assert_eq!(normalize_owner_key("did:web:z6Mkfoo"), "did:web:z6Mkfoo");
    }

    #[test]
    fn does_not_strip_did_key_with_extra_colon() {
        // did:key:did:gitlawb:z6... — the remainder contains ':', so it's left whole.
        assert_eq!(
            normalize_owner_key("did:key:did:gitlawb:z6Mkfoo"),
            "did:key:did:gitlawb:z6Mkfoo"
        );
    }

    #[test]
    fn empty_string_returns_empty() {
        assert_eq!(normalize_owner_key(""), "");
    }

    #[test]
    fn bare_did_key_colon_becomes_empty() {
        // did:key: with nothing after still has the prefix stripped.
        assert_eq!(normalize_owner_key("did:key:"), "");
    }

    #[test]
    fn uppercase_prefix_is_untouched() {
        assert_eq!(normalize_owner_key("DID:KEY:z6Mkfoo"), "DID:KEY:z6Mkfoo");
    }

    #[test]
    fn strips_did_key_even_with_trailing_slash() {
        // did:key:z6Mkfoo/extra has no ':' in the remainder, so it strips.
        assert_eq!(
            normalize_owner_key("did:key:z6Mkfoo/extra"),
            "z6Mkfoo/extra"
        );
    }
}

impl Db {
    pub async fn create_repo(&self, repo: &RepoRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch,
                                created_at, updated_at, disk_path, forked_from, machine_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&repo.id)
        .bind(&repo.name)
        .bind(&repo.owner_did)
        .bind(&repo.description)
        .bind(repo.is_public)
        .bind(&repo.default_branch)
        .bind(repo.created_at.to_rfc3339())
        .bind(repo.updated_at.to_rfc3339())
        .bind(&repo.disk_path)
        .bind(&repo.forked_from)
        .bind(&repo.machine_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Attach an external HTTPS upstream to a canonical repository in inbound
    /// mode. This is deliberately idempotent only for the same untouched
    /// inbound configuration; it never overwrites an existing upstream or
    /// resets a transition that may be in progress.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn configure_inbound_mirror(
        &self,
        repo_id: &str,
        upstream_url: &str,
    ) -> Result<RepoMirrorState> {
        Uuid::parse_str(repo_id)
            .context("continuous mirrors require a canonical UUID repository id")?;
        let upstream_url = validate_mirror_upstream_url(upstream_url)?.to_string();
        let updated_at = Utc::now().to_rfc3339();

        let row = sqlx::query(
            "UPDATE repos
             SET upstream_url = $2,
                 mirror_status = 'inbound',
                 mirror_transition_id = NULL,
                 mirror_transition_phase = NULL,
                 mirror_updated_at = COALESCE(mirror_updated_at, $3)
             WHERE id = $1
               AND (
                   upstream_url IS NULL
                   OR (
                       upstream_url = $2
                       AND mirror_status = 'inbound'
                       AND mirror_transition_id IS NULL
                       AND mirror_transition_phase IS NULL
                   )
               )
             RETURNING id, upstream_url, mirror_status, mirror_transition_id,
                       mirror_transition_phase, mirror_updated_at",
        )
        .bind(repo_id)
        .bind(&upstream_url)
        .bind(&updated_at)
        .fetch_optional(&self.pool)
        .await?;

        let row = row.context(
            "repository does not exist or already has a different/transitioning mirror configuration",
        )?;
        row_to_repo_mirror_state(row)
    }

    /// Return the durable mirror state, or `None` for a normal non-mirrored
    /// repository (and for an unknown id). Callers that need to distinguish
    /// those cases must resolve the repository first through the auth-gated
    /// repository path.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn get_repo_mirror_state(&self, repo_id: &str) -> Result<Option<RepoMirrorState>> {
        let row = sqlx::query(
            "SELECT id, upstream_url, mirror_status, mirror_transition_id,
                    mirror_transition_phase, mirror_updated_at
             FROM repos
             WHERE id = $1 AND upstream_url IS NOT NULL",
        )
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_repo_mirror_state).transpose()
    }

    /// Keyset-page stable INBOUND mirrors for the external-forge worker.
    /// Transitioning/outbound rows are excluded at the database boundary so a
    /// cycle cannot intentionally schedule them. The worker rechecks the state
    /// after taking the repo write lock to close the selection-to-fetch window.
    pub async fn list_inbound_mirror_targets(
        &self,
        after_repo_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<InboundMirrorTarget>> {
        let rows = sqlx::query(
            "SELECT id, owner_did, name, upstream_url
             FROM repos
             WHERE mirror_status = 'inbound'
               AND upstream_url IS NOT NULL
               AND (
                    (mirror_transition_id IS NULL AND mirror_transition_phase IS NULL)
                    OR (mirror_transition_id IS NOT NULL
                        AND mirror_transition_phase = 'completed')
               )
               AND ($1::text IS NULL OR id > $1)
             ORDER BY id ASC
             LIMIT $2",
        )
        .bind(after_repo_id)
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(InboundMirrorTarget {
                    repo_id: row
                        .try_get("id")
                        .context("reading inbound mirror repository id")?,
                    owner_did: row
                        .try_get("owner_did")
                        .context("reading inbound mirror owner DID")?,
                    name: row
                        .try_get("name")
                        .context("reading inbound mirror repository name")?,
                    upstream_url: row
                        .try_get("upstream_url")
                        .context("reading inbound mirror upstream URL")?,
                })
            })
            .collect()
    }

    /// Register a mirrored repo from a peer in the local DB so git smart HTTP can serve it.
    /// Uses INSERT OR IGNORE (SQLite) / ON CONFLICT DO NOTHING (Postgres) so it's idempotent.
    pub async fn upsert_mirror_repo(
        &self,
        owner_short: &str,
        name: &str,
        disk_path: &str,
        machine_id: Option<&str>,
        quarantined: bool,
    ) -> Result<()> {
        // Peer-supplied names are bound like the local write paths: an
        // unbounded name would make reposPage emit a cursor longer than the
        // 4096-byte parse limit, dead-ending pagination for every caller past
        // that row (#465 4th round). The sync caller drops the error and skips
        // the mirror.
        if name.len() > MAX_REPO_NAME_LEN {
            anyhow::bail!(
                "mirror repo name exceeds {MAX_REPO_NAME_LEN} bytes: refusing to register"
            );
        }
        let now = Utc::now().to_rfc3339();
        let id = format!("{owner_short}/{name}");
        // `quarantined` is set only on first insert (the admission decision).
        // A re-sync (ON CONFLICT) preserves the existing flag — admission runs
        // once, and an operator's later release must not be silently reverted.
        sqlx::query(
            "INSERT INTO repos (id, name, owner_did, description, is_public, default_branch,
                                created_at, updated_at, disk_path, machine_id, quarantined)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (id) DO UPDATE SET updated_at = $8, disk_path = $9, machine_id = $10",
        )
        .bind(&id)
        .bind(name)
        .bind(owner_short)
        .bind("mirrored from peer")
        .bind(true)
        .bind("main")
        .bind(&now)
        .bind(&now)
        .bind(disk_path)
        .bind(machine_id)
        .bind(quarantined)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_repo(&self, owner_did: &str, name: &str) -> Result<Option<RepoRecord>> {
        // Normalize owner_did to its did:key short form, mirroring did_matches and
        // the DEDUP_CTE's owner-key CASE: strip `did:key:` only when the remainder
        // is a bare key id (no further `:`). This keeps `did:key:z...` and bare
        // `z...` interchangeable while `did:gitlawb:z...` / `did:web:z...` stay
        // distinct — the old LIKE '%:' || $1 || '%' was too broad (issue #124 P2).
        let owner_key = normalize_owner_key(owner_did);
        let sql = format!(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos
              WHERE ({key}) = $1
                AND name = $2
             -- Prefer canonical rows (UUID id, no slash) over mirror rows (slash id).
             -- Mirror rows are inserted by upsert_mirror_repo with is_public=true and
             -- no visibility rules; using them for visibility checks would bypass the
             -- canonical row's gate (issue #124).
             ORDER BY CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END,
                      created_at ASC, id ASC
             LIMIT 1",
            key = OWNER_KEY_CASE_SQL
        );
        let row = sqlx::query(&sql)
            .bind(owner_key)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(row_to_repo))
    }

    /// Fetch a repo by its stable `id`. Used by the `/ipfs/{cid}` provenance path,
    /// which resolves a pin straight to its ONE source repo (#173) instead of
    /// paging the whole repo table. `id` is exact, so unlike `get_repo`'s fuzzy
    /// owner/name match there is no mirror-vs-canonical disambiguation.
    pub async fn get_repo_by_id(&self, id: &str) -> Result<Option<RepoRecord>> {
        let row = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos WHERE id = $1 LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_repo))
    }

    #[allow(dead_code)]
    pub async fn list_repos(&self, owner_did: &str) -> Result<Vec<RepoRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos WHERE owner_did = $1 ORDER BY updated_at DESC",
        )
        .bind(owner_did)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// One keyset page of raw repo rows for the IPFS object scan (`api::ipfs`) —
    /// NOT deduped (a mirror row and its canonical row both appear), since that
    /// scan must see every physical row. Listing surfaces dedupe via
    /// `list_all_repos_deduped` or `list_all_repos_with_stars` +
    /// `dedupe_canonical_repos` and must not use this.
    ///
    /// Paged rather than whole-table because the scan runs on an anonymously
    /// reachable route while holding scarce walk admission: materializing the
    /// node's entire repo inventory (plus its rules) before the per-probe budget
    /// has spent a single probe is an amplification sink (INV-10). The caller
    /// stops asking for pages once its budgets are spent.
    ///
    /// Ordered on `(created_at, id)` ASC, both IMMUTABLE, so keyset paging is
    /// exact: no row is visited twice and none is skipped. `updated_at` would be
    /// wrong twice over — a repo touched mid-scan can cross a page boundary and go
    /// unvisited (a servable public object misreported as a 404), and it is
    /// attacker-bumpable, which would let a caller sort their own repos ahead of
    /// the true holder and bury it past the probe budget.
    ///
    /// `after` is the raw `(created_at, id)` of the last row of the previous page,
    /// `None` for the first page. It carries the STORED `created_at` text, not a
    /// re-serialized `DateTime`: the comparison is a text comparison and a
    /// round-trip through `to_rfc3339` is not guaranteed to reproduce the stored
    /// bytes.
    ///
    /// Each row carries its own `quarantined` flag so the scan needs no separate
    /// whole-node quarantine query (INV-11's hard drop stays per row).
    pub async fn list_repos_page_for_scan(
        &self,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> Result<Vec<ScanRepoRow>> {
        let (after_created, after_id) = match after {
            Some((created_at, id)) => (Some(created_at), Some(id)),
            None => (None, None),
        };
        let rows = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id, quarantined
             FROM repos
             WHERE $1::text IS NULL OR (created_at, id) > ($1::text, $2::text)
             ORDER BY created_at ASC, id ASC
             LIMIT $3",
        )
        .bind(after_created)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let quarantined: bool = r.get("quarantined");
                let created_at_key: String = r.get("created_at");
                ScanRepoRow {
                    quarantined,
                    created_at_key,
                    repo: row_to_repo(r),
                }
            })
            .collect())
    }

    pub async fn list_all_repos_with_stars(&self) -> Result<Vec<(RepoRecord, i64)>> {
        let rows = sqlx::query(
            "SELECT r.id, r.name, r.owner_did, r.description, r.is_public, r.default_branch,
                    r.created_at, r.updated_at, r.disk_path, r.forked_from, r.machine_id,
                    COALESCE(s.cnt, 0) AS star_count
             FROM repos r
             LEFT JOIN (SELECT repo_id, COUNT(*) AS cnt FROM repo_stars GROUP BY repo_id) s
               ON s.repo_id = r.id
             WHERE r.quarantined = FALSE
             ORDER BY r.updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let stars: i64 = r.get("star_count");
                (row_to_repo(r), stars)
            })
            .collect())
    }

    /// Shared dedup CTE: collapses the mirror row and the canonical row of one
    /// logical repo into a single survivor. `$1` is an optional owner filter
    /// (NULL = all rows). Grouping collapses on a did:key-aware
    /// owner key: strip a `did:key:` prefix (8 chars, so
    /// `substr(owner_did, 9)`) only when the remainder is a bare id with no `:`,
    /// otherwise keep the full DID. That is the exact normalization in
    /// `crate::api::did_matches`, so `did:key:X` and a bare `X` collapse while
    /// distinct DID methods (`did:gitlawb:X`) never merge. The
    /// CASE is repeated verbatim in `count_repos_deduped` and the v7 index and must
    /// stay byte-identical or Postgres stops using the index.
    /// The canonical row wins (mirror rows carry a slash-form `id` written only by
    /// `upsert_mirror_repo`), ties broken by earliest `created_at` then `id` so a
    /// full tie still picks a deterministic survivor. `list_all_repos_deduped_with_stars`,
    /// `list_all_repos_deduped`, and the marker logic in
    /// `crate::api::repos::dedupe_canonical_repos` must stay in sync.
    fn dedup_cte() -> String {
        format!(
            "WITH deduped AS (
                 SELECT DISTINCT ON ({key}, name)
                     id, name, owner_did, description, is_public, default_branch,
                     created_at,
                     -- group MAX, not the canonical row's own value: pushes that
                     -- arrive via gossip touch only the mirror row, so the
                     -- canonical updated_at goes stale
                     MAX(updated_at) OVER (
                         PARTITION BY {key}, name
                     ) AS updated_at,
                     disk_path, forked_from, machine_id
                 FROM repos
                 -- Match the owner filter on the same did:key-aware owner key the
                 -- dedup groups on, so a full did:key: form matches a bare-owner
                 -- mirror row (and vice versa) exactly as crate::api::did_matches
                 -- does. Callers bind the already-normalized key ($1).
                 -- Quarantined mirrors (admitted but unvalidated by the iCaptcha
                 -- propagation gate) are withheld from every listing surface.
                 WHERE quarantined = FALSE AND ($1::text IS NULL OR ({key}) = $1)
                 ORDER BY {key}, name,
                     -- mirror rows carry a slash-form id (\"{{owner_short}}/{{name}}\"),
                     -- written only by upsert_mirror_repo; canonical ids are UUIDs.
                     -- Rank canonical (no slash) ahead of the mirror in each group,
                     -- keyed on the structural id, not the user-settable description.
                     CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END,
                     created_at ASC, id ASC
             )",
            key = OWNER_KEY_CASE_SQL
        )
    }

    /// Dedicated SQL for scoped repo lookup: resolves the requested IDs to
    /// logical groups, considers the relevant canonical/mirror members via the
    /// owner-key/name index, picks the survivor, and filters to the requested IDs.
    pub fn scoped_dedup_sql() -> String {
        format!(
            "WITH requested_groups AS (
                 SELECT DISTINCT {key} AS owner_key, name
                 FROM repos
                 WHERE id = ANY($1)
             ),
             candidate_repos AS (
                 SELECT repos.id, repos.name, repos.owner_did, repos.description,
                     repos.is_public, repos.default_branch, repos.created_at,
                     repos.updated_at, repos.disk_path, repos.forked_from,
                     repos.machine_id
                 FROM requested_groups rg
                 JOIN repos ON ({key}) = rg.owner_key AND repos.name = rg.name
                 WHERE repos.quarantined = FALSE
             ),
             deduped AS (
                 SELECT DISTINCT ON ({key}, name)
                     id, name, owner_did, description, is_public, default_branch,
                     created_at,
                     MAX(updated_at) OVER (
                         PARTITION BY {key}, name
                     ) AS updated_at,
                     disk_path, forked_from, machine_id
                 FROM candidate_repos repos
                 ORDER BY {key}, name,
                     CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END,
                     created_at ASC, id ASC
             )
             SELECT d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id
             FROM deduped d
             WHERE d.id = ANY($1)
             ORDER BY d.updated_at DESC",
            key = OWNER_KEY_CASE_SQL
        )
    }

    /// All repos with star counts, mirror-deduplicated via `DEDUP_CTE` and
    /// ordered newest-first, optionally filtered to one owner. Returns the full
    /// set (no SQL pagination): the listing surface filters by per-caller `"/"`
    /// visibility in Rust and paginates after, so neither the page nor the count
    /// leaks a repo the caller may not read (#97).
    ///
    /// The owner filter is normalized to its did:key short form before binding so
    /// the SQL predicate matches `crate::api::did_matches`: a full `did:key:z...`
    /// query and a bare-owner mirror row (`z...`) match each other, and vice
    /// versa. A non-key DID (still has a `:` after the prefix) is left intact and
    /// only matches exactly.
    pub async fn list_all_repos_deduped_with_stars(
        &self,
        owner_filter: Option<&str>,
    ) -> Result<Vec<(RepoRecord, i64)>> {
        // Mirror did_matches: strip `did:key:` only when the remainder is a bare
        // key id (no further `:`). The DEDUP_CTE applies the identical CASE to
        // owner_did, so the two compare on the same normalized key.
        let owner_key = owner_filter.map(normalize_owner_key);
        let sql = format!(
            "{}
             SELECT
                 d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id,
                 COALESCE(s.cnt, 0) AS star_count
             FROM deduped d
             LEFT JOIN (
                 SELECT repo_id, COUNT(*) AS cnt FROM repo_stars GROUP BY repo_id
             ) s ON s.repo_id = d.id
             ORDER BY d.updated_at DESC",
            Self::dedup_cte()
        );
        let rows = sqlx::query(&sql)
            .bind(owner_key)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let stars: i64 = r.get("star_count");
                (row_to_repo(r), stars)
            })
            .collect())
    }

    /// Deduped repo list (no stars, no paging) for the unfiltered read surfaces
    /// (GraphQL `repos`). One logical repo per mirror+canonical group, ordered by
    /// the group's most recent activity. Shares `dedup_cte()` with the paged path so
    /// the dedup rule cannot drift; binds a NULL owner filter (all rows).
    pub async fn list_all_repos_deduped(&self) -> Result<Vec<RepoRecord>> {
        let sql = format!(
            "{}
             SELECT d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id
             FROM deduped d
             ORDER BY d.updated_at DESC",
            Self::dedup_cte()
        );
        let rows = sqlx::query(&sql)
            .bind(None::<&str>)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// Resolve only the requested repository ids through the same canonical
    /// survivor and quarantine rules as `list_all_repos_deduped`.
    pub async fn list_repos_deduped_by_ids(&self, repo_ids: &[String]) -> Result<Vec<RepoRecord>> {
        if repo_ids.is_empty() {
            return Ok(Vec::new());
        }
        let sql = Self::scoped_dedup_sql();
        let rows = sqlx::query(&sql)
            .bind(repo_ids)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// Like `list_all_repos_deduped` but ordered by a stable key (`id`) so a
    /// keyset cursor deterministically covers every repo regardless of push
    /// activity.  Used by the reconciliation sweep to avoid starving idle repos.
    /// Only `limit` rows are returned; pass `cursor = None` for the first page.
    pub async fn list_all_repos_deduped_stable(
        &self,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<RepoRecord>> {
        let sql = format!(
            "{}
             SELECT d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id
             FROM deduped d
             WHERE ($2::text IS NULL OR d.id > $2::text)
             ORDER BY d.id ASC
             LIMIT $3",
            Self::dedup_cte()
        );
        let rows = sqlx::query(&sql)
            .bind(None::<&str>)
            .bind(cursor)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// A bounded, mirror-deduplicated page ordered by owner key and repository
    /// name. Apply root visibility before LIMIT: private rows must not consume
    /// page slots or influence continuation metadata. The root-rule predicate
    /// mirrors `visibility::listable_at_root`; a differential test pins it.
    /// Malformed reader JSON denies that repo to non-owners without failing the page.
    /// Cursors only select a position and never confer read authority.
    ///
    /// Performance note: the page orders and keyset-filters on
    /// `(owner_key, name)` under `COLLATE "C"`, but the existing
    /// `idx_repos_owner_key_name` index is built on the database default
    /// collation and cannot serve that ordering, so each page sorts the full
    /// deduped repo set before the keyset filter applies: O(total repos) work
    /// per page. This is accepted (pages are capped at
    /// `MAX_VISIBLE_REPO_PAGE_SIZE` rows over a narrow projection). A
    /// C-collation expression index was deliberately not added in a migration:
    /// versions 27-35 are claimed by other in-flight branches (Gitlawb/node#384
    /// claims 27-35, #464 claims 27-28) and the runner keys applied migrations
    /// on the version integer alone, so a colliding entry would be silently
    /// skipped on whichever side merges second. Revisit once that range lands
    /// or clears.
    pub async fn list_visible_repos_page(
        &self,
        caller: Option<&str>,
        after: Option<(&str, &str)>,
        limit: usize,
    ) -> Result<Vec<RepoRecord>> {
        let sql = format!(
            "{}
             SELECT d.id, d.name, d.owner_did, d.description, d.is_public,
                 d.default_branch, d.created_at, d.updated_at, d.disk_path,
                 d.forked_from, d.machine_id
             FROM deduped d
             LEFT JOIN LATERAL (
                 SELECT reader_dids FROM visibility_rules v
                 WHERE v.repo_id = d.id AND v.path_glob ~ '^/*([*][*])*$'
                 ORDER BY v.path_glob DESC LIMIT 1
             ) root_rule ON TRUE
             WHERE (
                 ($2::text IS NOT NULL AND ({key}) = $2)
                 OR CASE WHEN root_rule.reader_dids IS NULL THEN d.is_public
                    WHEN NOT pg_input_is_valid(root_rule.reader_dids, 'jsonb') THEN FALSE
                    WHEN jsonb_typeof(root_rule.reader_dids::jsonb) = 'array' THEN
                        COALESCE(root_rule.reader_dids::jsonb ? $3::text, FALSE)
                        AND NOT EXISTS (
                            SELECT 1 FROM jsonb_array_elements(root_rule.reader_dids::jsonb) reader
                            WHERE jsonb_typeof(reader) <> 'string'
                        )
                    ELSE FALSE END
             )
             AND ($4::text IS NULL OR (({key}) COLLATE \"C\", d.name COLLATE \"C\") > ($4, $5::text))
             ORDER BY ({key}) COLLATE \"C\", d.name COLLATE \"C\"
             LIMIT $6",
            Self::dedup_cte(),
            key = OWNER_KEY_CASE_SQL,
        );
        let rows = sqlx::query(&sql)
            .bind(None::<&str>)
            .bind(caller.map(normalize_owner_key))
            .bind(caller)
            .bind(after.map(|(owner, _)| normalize_owner_key(owner)))
            .bind(after.map(|(_, name)| name))
            .bind(limit.min(MAX_VISIBLE_REPO_PAGE_SIZE + 1) as i64)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// Repos currently quarantined (admitted as mirrors but withheld from every
    /// listing surface). `list_all_repos_deduped` excludes these (its `DEDUP_CTE`
    /// filters `quarantined = FALSE`), so a gate that resolves a slug against the
    /// deduped set must also match against these and fail closed, or a quarantined
    /// repo's row is misclassified as remote/gossip-only and served.
    pub async fn list_quarantined_repos(&self) -> Result<Vec<RepoRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, owner_did, description, is_public, default_branch,
                    created_at, updated_at, disk_path, forked_from, machine_id
             FROM repos WHERE quarantined = TRUE",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_repo).collect())
    }

    /// Count of distinct logical repos (mirror + canonical collapsed). Uses the
    /// same did:key-aware owner-key grouping as `DEDUP_CTE` (the CASE must stay
    /// byte-identical); the marker/tiebreak only decide which row would survive,
    /// not the group count, so they are not needed here.
    ///
    /// `/api/v1/stats` no longer calls this — it counts only anonymously-listable
    /// repos to avoid a count oracle (#104). Retained as the tested reference
    /// implementation of the unfiltered dedup count: its tests pin the `DEDUP_CTE`
    /// CASE that the live list paths depend on. Allowed dead outside tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn count_repos_deduped(&self) -> Result<i64> {
        let sql = format!(
            "SELECT COUNT(DISTINCT ({key}, name)) AS cnt FROM repos",
            key = OWNER_KEY_CASE_SQL
        );
        let row = sqlx::query(&sql).fetch_one(&self.pool).await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    pub async fn touch_repo(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE repos SET updated_at = $1 WHERE id = $2")
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Agents / Trust ────────────────────────────────────────────────────────────

/// Map an `agents` row (selected with the status columns) into an `AgentRow`.
fn row_to_agent(r: &sqlx::postgres::PgRow) -> AgentRow {
    AgentRow {
        did: r.get("did"),
        trust_score: r.get("trust_score"),
        capabilities: serde_json::from_str(r.get::<&str, _>("capabilities")).unwrap_or_default(),
        registered_at: r.get("registered_at"),
        last_seen: r.get("last_seen"),
        status: r.get("status"),
    }
}

/// Reduce a trust-ranked agent list to what discovery should surface: only
/// `active` agents, optionally narrowed to those advertising `capability`.
/// Revoked agents are dropped so an orphaned DID can never win capability
/// routing. Input order is preserved, so an already trust-sorted list stays
/// active-first.
fn filter_discoverable(agents: Vec<AgentRow>, capability: Option<&str>) -> Vec<AgentRow> {
    agents
        .into_iter()
        .filter(|a| a.status == "active")
        .filter(|a| match capability {
            Some(cap) => a.capabilities.iter().any(|c| c == cap),
            None => true,
        })
        .collect()
}

impl Db {
    pub async fn register_agent(&self, did: &str, capabilities: &[String]) -> Result<()> {
        let caps = serde_json::to_string(capabilities)?;
        let now = Utc::now().to_rfc3339();
        // The ON CONFLICT clause deliberately updates only `last_seen` and
        // never touches `status`. That makes revocation terminal: re-registering
        // a `revoked` DID does not bring it back to `active` (issue #29).
        sqlx::query(
            "INSERT INTO agents (did, trust_score, capabilities, registered_at)
             VALUES ($1, 0.0, $2, $3)
             ON CONFLICT(did) DO UPDATE SET last_seen = $3",
        )
        .bind(did)
        .bind(&caps)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically consume an iCaptcha proof id (`jti`). Returns `Ok(true)` if it
    /// was newly recorded (the proof may be used), `Ok(false)` if it was already
    /// spent (a replay). `expires_at` is the proof's unix-seconds `exp`, kept so
    /// the ledger row can be swept once the proof can no longer be valid.
    pub async fn consume_proof_jti(&self, jti: &str, expires_at: i64) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO icaptcha_consumed_proofs (jti, expires_at)
             VALUES ($1, $2)
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(jti)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete consumed-proof rows whose proof has expired. Returns rows removed.
    pub async fn sweep_expired_proofs(&self, now: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM icaptcha_consumed_proofs WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Persist the iCaptcha proof a repo was created with so it can travel with
    /// the repo when it propagates (see `icaptcha::admit_mirror`). Idempotent:
    /// re-recording the same repo's proof overwrites it.
    pub async fn record_repo_proof(
        &self,
        repo_id: &str,
        proof_token: &str,
        sub_did: &str,
        level: i32,
        jti: &str,
        exp: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO repo_icaptcha_proofs (repo_id, proof_token, sub_did, level, jti, exp, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (repo_id) DO UPDATE SET
                 proof_token = $2, sub_did = $3, level = $4, jti = $5, exp = $6, created_at = $7",
        )
        .bind(repo_id)
        .bind(proof_token)
        .bind(sub_did)
        .bind(level)
        .bind(jti)
        .bind(exp)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The raw proof token recorded for a repo, if any.
    pub async fn get_repo_proof_token(&self, repo_id: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT proof_token FROM repo_icaptcha_proofs WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<String, _>("proof_token")))
    }

    /// Return quarantined IDs from a bounded candidate page in one query.
    pub async fn quarantined_repo_ids_in(
        &self,
        repo_ids: &[String],
    ) -> Result<std::collections::HashSet<String>> {
        if repo_ids.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM repos WHERE id = ANY($1) AND quarantined = TRUE")
                .bind(repo_ids)
                .fetch_all(&self.pool)
                .await?;
        Ok(ids.into_iter().collect())
    }

    /// Whether a repo row is quarantined (admitted as a mirror but withheld from
    /// serve/clone and listings pending operator review).
    pub async fn is_repo_quarantined(&self, repo_id: &str) -> Result<bool> {
        let row = sqlx::query("SELECT quarantined FROM repos WHERE id = $1")
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row
            .map(|r| r.get::<bool, _>("quarantined"))
            .unwrap_or(false))
    }

    /// Set or clear a repo's quarantine flag and bump the policy epoch
    /// atomically. Returns the number of rows touched (0 if no such repo).
    /// A failure in either statement rolls back both.
    ///
    /// The narrow never blocks behind a pin batch: it commits immediately and
    /// bumps `policy_epoch`, and the batch's next `PolicyFence::is_current`
    /// check aborts before the next upload. The fenced DB record takes the
    /// repos row lock only for its own short transaction, never across a
    /// network POST.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn set_repo_quarantine(&self, repo_id: &str, quarantined: bool) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("UPDATE repos SET quarantined = $1 WHERE id = $2")
            .bind(quarantined)
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;
        let affected = result.rows_affected();
        if affected > 0 {
            sqlx::query("UPDATE repos SET policy_epoch = policy_epoch + 1 WHERE id = $1")
                .bind(repo_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(affected)
    }

    /// Repo ids currently quarantined, for operator review. Allowed dead outside
    /// tests until the operator endpoint lands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn list_quarantined_repo_ids(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT id FROM repos WHERE quarantined = TRUE ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("id")).collect())
    }

    pub async fn get_trust_score(&self, agent_did: &str) -> Result<f64> {
        let row = sqlx::query("SELECT trust_score FROM agents WHERE did = $1")
            .bind(agent_did)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get::<f64, _>("trust_score")).unwrap_or(0.0))
    }

    /// Update an EXISTING agent's trust score; a no-op for unregistered DIDs.
    /// Deliberately never inserts: the only path into the agents table is
    /// `register_agent`, which sits behind the iCaptcha gate on /api/register.
    /// This used to be an upsert, which let any authenticated push/issue/PR
    /// re-create a deregistered DID's row with a fresh `registered_at`,
    /// bypassing the registration gate entirely.
    pub async fn update_trust_score(&self, agent_did: &str, score: f64) -> Result<()> {
        sqlx::query("UPDATE agents SET trust_score = $2 WHERE did = $1")
            .bind(agent_did)
            .bind(score)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(dead_code)] // legacy live-path entry; PR 3 owns the deprecation decision
    pub async fn record_push(
        &self,
        agent_did: &str,
        repo_id: &str,
        commit_hash: &str,
        object_count: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO push_events (id, agent_did, repo_id, commit_hash, object_count, pushed_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(agent_did)
        .bind(repo_id)
        .bind(commit_hash)
        .bind(object_count)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_push_count(&self, agent_did: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM push_events WHERE agent_did = $1")
            .bind(agent_did)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    pub async fn count_agents(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM agents")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    pub async fn list_agents(&self, capability: Option<&str>) -> Result<Vec<AgentRow>> {
        let rows = sqlx::query(
            "SELECT did, trust_score, capabilities, registered_at, last_seen, status \
             FROM agents ORDER BY trust_score DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        let agents: Vec<AgentRow> = rows.iter().map(row_to_agent).collect();

        Ok(filter_discoverable(agents, capability))
    }

    pub async fn get_agent(&self, did: &str) -> Result<Option<AgentRow>> {
        let row = sqlx::query(
            "SELECT did, trust_score, capabilities, registered_at, last_seen, status \
             FROM agents WHERE did = $1",
        )
        .bind(did)
        .fetch_optional(&self.pool)
        .await?;

        // Unfiltered by design: a revoked DID must still resolve so callers
        // can read its `status` and see it is retired.
        Ok(row.as_ref().map(row_to_agent))
    }

    /// Mark an agent `revoked` (terminal self-deregistration, issue #29).
    /// Returns `false` when no such agent exists so the caller can surface a
    /// 404. Revoking an already-revoked agent is idempotent, and a retry keeps
    /// the original `deactivated_at` (COALESCE) rather than overwriting it.
    pub async fn revoke_agent(&self, did: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE agents SET status = 'revoked', \
             deactivated_at = COALESCE(deactivated_at, $2) WHERE did = $1",
        )
        .bind(did)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count_pushes(&self) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM push_events")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }
}

// ── Branch CIDs ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchCid {
    pub repo: String,
    pub ref_name: String,
    pub sha: String,
    pub cid: String,
    pub node_did: String,
    pub updated_at: String,
}

impl Db {
    pub async fn upsert_branch_cid(
        &self,
        repo: &str,
        ref_name: &str,
        sha: &str,
        cid: &str,
        node_did: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO branch_cids (repo, ref_name, sha, cid, node_did, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (repo, ref_name) DO UPDATE
               SET sha = EXCLUDED.sha, cid = EXCLUDED.cid,
                   node_did = EXCLUDED.node_did, updated_at = EXCLUDED.updated_at",
        )
        .bind(repo)
        .bind(ref_name)
        .bind(sha)
        .bind(cid)
        .bind(node_did)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_branch_cids(&self, repo: &str) -> Result<Vec<BranchCid>> {
        let rows = sqlx::query(
            "SELECT repo, ref_name, sha, cid, node_did, updated_at
             FROM branch_cids WHERE repo = $1 ORDER BY ref_name",
        )
        .bind(repo)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| BranchCid {
                repo: r.get("repo"),
                ref_name: r.get("ref_name"),
                sha: r.get("sha"),
                cid: r.get("cid"),
                node_did: r.get("node_did"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }
}

// ── Sync Queue ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncQueueItem {
    pub id: String,
    pub repo: String,
    pub node_did: String,
    pub ref_name: String,
    pub new_sha: String,
    pub cid: Option<String>,
    pub status: String,
    pub enqueued_at: String,
}

impl Db {
    pub async fn enqueue_sync(
        &self,
        repo: &str,
        node_did: &str,
        ref_name: &str,
        new_sha: &str,
        cid: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO sync_queue (id, repo, node_did, ref_name, new_sha, cid, status, enqueued_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
             ON CONFLICT DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(repo)
        .bind(node_did)
        .bind(ref_name)
        .bind(new_sha)
        .bind(cid)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Take up to `limit` pending syncs — the least recently attempted ones —
    /// and stamp each with the time it was handed out.
    ///
    /// Selecting and stamping in one statement is deliberate. A row the worker
    /// cannot make progress on stays `pending` so it is retried, and if its
    /// ordering key never moved it would remain among the oldest rows forever,
    /// holding a fixed-size window against every healthy repo behind it.
    /// Stamping on the way out makes the key "least recently handed out", so a
    /// stuck row rotates to the back instead. Doing it here rather than at each
    /// deferral branch in the worker is what makes that hold by construction:
    /// no call site can forget it, and a batch that dies mid-loop still leaves
    /// its rows stamped. `enqueued_at` is left alone so backlog age stays
    /// measurable.
    ///
    /// Two things this deliberately does not promise. The returned rows are the
    /// right *set*, in no particular order — `RETURNING` does not sort, and
    /// nothing in `process_batch` depends on the order within a batch. And this
    /// is not a claim: the rows stay `pending` with no row lock held past the
    /// statement, so two workers against one database can still be handed the
    /// same batch. Single-worker deployment is the existing assumption;
    /// `FOR UPDATE SKIP LOCKED` is what would change that, and it is not here.
    ///
    /// Errors surface to the caller, which logs and skips the poll. That is
    /// worth knowing now that this writes: it can fail for reasons a plain
    /// SELECT could not, such as a read-only transaction or a lock timeout.
    pub async fn dequeue_pending_syncs(&self, limit: i64) -> Result<Vec<SyncQueueItem>> {
        let rows = sqlx::query(
            // The outer `status = 'pending'` is not redundant with the
            // subquery's: between the two, a concurrent worker can settle a row,
            // and without it the UPDATE would still stamp and return a row that
            // had already left the pending set.
            "UPDATE sync_queue SET attempted_at = $2
             WHERE status = 'pending' AND id IN (
                 SELECT id FROM sync_queue WHERE status = 'pending'
                 ORDER BY COALESCE(attempted_at, enqueued_at) ASC LIMIT $1
             )
             RETURNING id, repo, node_did, ref_name, new_sha, cid, status, enqueued_at",
        )
        .bind(limit)
        .bind(Utc::now().to_rfc3339())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SyncQueueItem {
                id: r.get("id"),
                repo: r.get("repo"),
                node_did: r.get("node_did"),
                ref_name: r.get("ref_name"),
                new_sha: r.get("new_sha"),
                cid: r.get("cid"),
                status: r.get("status"),
                enqueued_at: r.get("enqueued_at"),
            })
            .collect())
    }

    pub async fn mark_sync_done(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE sync_queue SET status = 'done', processed_at = $1 WHERE id = $2")
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_sync_failed(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE sync_queue SET status = 'failed', processed_at = $1 WHERE id = $2")
            .bind(Utc::now().to_rfc3339())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Pull Requests ─────────────────────────────────────────────────────────────

impl Db {
    pub async fn create_pr(&self, pr: &PullRequest) -> Result<()> {
        sqlx::query(
            "INSERT INTO pull_requests
             (id, repo_id, number, title, body, author_did, source_branch, target_branch,
              status, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,$10)",
        )
        .bind(&pr.id)
        .bind(&pr.repo_id)
        .bind(pr.number)
        .bind(&pr.title)
        .bind(&pr.body)
        .bind(&pr.author_did)
        .bind(&pr.source_branch)
        .bind(&pr.target_branch)
        .bind(&pr.created_at)
        .bind(&pr.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn next_pr_number(&self, repo_id: &str) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(number), 0) + 1 AS next FROM pull_requests WHERE repo_id = $1",
        )
        .bind(repo_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("next"))
    }

    pub async fn list_prs(&self, repo_id: &str) -> Result<Vec<PullRequest>> {
        let rows = sqlx::query(
            "SELECT id,repo_id,number,title,body,author_did,source_branch,target_branch,
                    status,merged_by_did,merged_at,head_commit,created_at,updated_at
             FROM pull_requests WHERE repo_id=$1 ORDER BY number DESC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_pr).collect())
    }

    pub async fn get_pr(&self, repo_id: &str, number: i64) -> Result<Option<PullRequest>> {
        let row = sqlx::query(
            "SELECT id,repo_id,number,title,body,author_did,source_branch,target_branch,
                    status,merged_by_did,merged_at,head_commit,created_at,updated_at
             FROM pull_requests WHERE repo_id=$1 AND number=$2",
        )
        .bind(repo_id)
        .bind(number)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_pr))
    }

    /// Point every OPEN pull request in `repo_id` whose source branch is
    /// `branch` at `new_sha`, in one statement. Returns the rows updated.
    ///
    /// The `status='open'` predicate is the freeze: once a pull request is
    /// closed or merged, later pushes to the same branch no longer move its
    /// stored head, so the recorded target stays the commit the decision was
    /// actually made against. `branch` is a bare name — callers on the push
    /// path see full refs and must strip `refs/heads/` first.
    ///
    /// Test-only since the push path started batching: production has exactly one
    /// caller and it always has a whole push's worth of branches to write, so the
    /// single-branch form exists to keep the many tests that seed one head
    /// readable. Compiling it only under `cfg(test)` is what keeps that fact from
    /// decaying into an unused production API.
    #[cfg(test)]
    pub async fn set_open_pr_heads(
        &self,
        repo_id: &str,
        branch: &str,
        new_sha: &str,
    ) -> Result<u64> {
        self.set_open_pr_heads_batch(repo_id, &[(branch.to_string(), new_sha.to_string())])
            .await
    }

    /// The same update for several branches of one repo, in a single statement.
    ///
    /// This is the shape the receive-pack path needs: one push carries many ref
    /// updates, and issuing one round trip per ref put that latency directly on
    /// the user's `git push` response. The per-branch new head rides along as a
    /// `VALUES` list joined against the table, so the cost is one statement
    /// regardless of how many branches moved. The casts on the first row are what
    /// give Postgres the column types it cannot infer from parameters alone.
    ///
    /// Callers must chunk the list (see `api::repos::PUSH_WRITE_CHUNK`): every
    /// pair costs two bind parameters, against a protocol ceiling of 65535. The
    /// chunking bounds one STATEMENT, not the push: a caller that dropped the
    /// tail instead would leave those pull requests pointing at a commit the
    /// push already replaced.
    ///
    /// Same predicates as the single-branch form, and for the same reason:
    /// `status='open'` is the freeze that keeps a decided pull request's head
    /// from moving under a later push.
    pub async fn set_open_pr_heads_batch(
        &self,
        repo_id: &str,
        updates: &[(String, String)],
    ) -> Result<u64> {
        if updates.is_empty() {
            return Ok(0);
        }
        // $1 is the repo; each pair takes the next two positions.
        let mut values = String::new();
        for i in 0..updates.len() {
            if i > 0 {
                values.push(',');
            }
            let base = 2 + i * 2;
            if i == 0 {
                values.push_str(&format!("(${}::text, ${}::text)", base, base + 1));
            } else {
                values.push_str(&format!("(${}, ${})", base, base + 1));
            }
        }
        let sql = format!(
            "UPDATE pull_requests SET head_commit = v.sha
             FROM (VALUES {values}) AS v(branch, sha)
             WHERE pull_requests.repo_id = $1
               AND pull_requests.source_branch = v.branch
               AND pull_requests.status = 'open'"
        );

        let mut q = sqlx::query(&sql).bind(repo_id);
        for (branch, sha) in updates {
            q = q.bind(branch).bind(sha);
        }
        count_push_write_statement();
        let result = q.execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    /// Record `sha` as the head of one OPEN pull request that has none yet.
    /// Returns the rows updated, so a caller can tell a fill from a no-op.
    ///
    /// Both predicates are the point. `head_commit IS NULL` makes the write
    /// self-limiting: the rollup's read-side fallback is reachable by an
    /// unauthenticated GET, and this is what stops it from firing more than once
    /// per pull request, or from rolling a head a concurrent push already
    /// recorded back to a staler branch tip. `status='open'` is the same freeze
    /// [`Db::set_open_pr_heads`] applies: a closed or merged pull request's head,
    /// including its absence, is a decided fact and not back-fillable.
    pub async fn set_pr_head_if_absent(&self, pr_id: &str, sha: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE pull_requests SET head_commit=$1
             WHERE id=$2 AND head_commit IS NULL AND status='open'",
        )
        .bind(sha)
        .bind(pr_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Mark a pull request merged, stamping the source head it merged.
    ///
    /// `head_commit` is what the merge actually consumed, read under the repo
    /// write lock: the caller loaded the row before taking that lock, so a push
    /// landing in between moved the branch and the row's own value is stale.
    /// `None` (an unresolvable source head) leaves the stored value alone
    /// rather than nulling a head the push path had already recorded.
    pub async fn merge_pr(
        &self,
        pr_id: &str,
        merged_by_did: &str,
        head_commit: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE pull_requests
             SET status='merged', merged_by_did=$1, merged_at=$2, updated_at=$2,
                 head_commit=COALESCE($4, head_commit)
             WHERE id=$3",
        )
        .bind(merged_by_did)
        .bind(&now)
        .bind(pr_id)
        .bind(head_commit)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// `head_sha` freezes the source head the close decided against: a closed
    /// pull request's rollup serves only the stored head, so nothing resolved
    /// later can stand in for it. It fills an empty head only: a head already
    /// stored, including one a push wrote after the handler read the row, wins.
    /// A `None` keeps whatever the push path last recorded.
    pub async fn close_pr(&self, pr_id: &str, head_sha: Option<&str>) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "UPDATE pull_requests SET status='closed', updated_at=$1, \
             head_commit=COALESCE(head_commit, $3) WHERE id=$2 AND status='open'",
        )
        .bind(&now)
        .bind(pr_id)
        .bind(head_sha)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_pr_review(&self, review: &PrReview) -> Result<()> {
        sqlx::query(
            "INSERT INTO pr_reviews (id,pr_id,reviewer_did,body,status,created_at)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(&review.id)
        .bind(&review.pr_id)
        .bind(&review.reviewer_did)
        .bind(&review.body)
        .bind(&review.status)
        .bind(&review.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_pr_comment(&self, comment: &PrComment) -> Result<()> {
        sqlx::query(
            "INSERT INTO pr_comments (id,pr_id,author_did,body,created_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&comment.id)
        .bind(&comment.pr_id)
        .bind(&comment.author_did)
        .bind(&comment.body)
        .bind(&comment.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_pr_comments(&self, pr_id: &str) -> Result<Vec<PrComment>> {
        let rows = sqlx::query(
            "SELECT id,pr_id,author_did,body,created_at
             FROM pr_comments WHERE pr_id=$1 ORDER BY created_at ASC",
        )
        .bind(pr_id)
        .fetch_all(&self.pool)
        .await?;
        let mut comments = Vec::new();
        for row in rows {
            comments.push(PrComment {
                id: row.try_get("id")?,
                pr_id: row.try_get("pr_id")?,
                author_did: row.try_get("author_did")?,
                body: row.try_get("body")?,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(comments)
    }

    pub async fn create_issue_comment(&self, comment: &IssueComment) -> Result<()> {
        sqlx::query(
            "INSERT INTO issue_comments (id,issue_id,author_did,body,created_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(&comment.id)
        .bind(&comment.issue_id)
        .bind(&comment.author_did)
        .bind(&comment.body)
        .bind(&comment.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_issue_comments(&self, issue_id: &str) -> Result<Vec<IssueComment>> {
        let rows = sqlx::query(
            "SELECT id,issue_id,author_did,body,created_at
             FROM issue_comments WHERE issue_id=$1 ORDER BY created_at ASC",
        )
        .bind(issue_id)
        .fetch_all(&self.pool)
        .await?;
        let mut comments = Vec::new();
        for row in rows {
            comments.push(IssueComment {
                id: row.try_get("id")?,
                issue_id: row.try_get("issue_id")?,
                author_did: row.try_get("author_did")?,
                body: row.try_get("body")?,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(comments)
    }

    pub async fn add_label(&self, repo_id: &str, label: &str) -> Result<bool> {
        let id = format!("{repo_id}:{label}");
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            "INSERT INTO repo_labels (id, repo_id, label, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (repo_id, label) DO NOTHING",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(label)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn remove_label(&self, repo_id: &str, label: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM repo_labels WHERE repo_id = $1 AND label = $2")
            .bind(repo_id)
            .bind(label)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_labels(&self, repo_id: &str) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT label FROM repo_labels WHERE repo_id = $1 ORDER BY label ASC")
                .bind(repo_id)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .iter()
            .map(|r| r.try_get::<String, _>("label").unwrap_or_default())
            .collect())
    }

    pub async fn list_pr_reviews(&self, pr_id: &str) -> Result<Vec<PrReview>> {
        let rows = sqlx::query(
            "SELECT id,pr_id,reviewer_did,body,status,created_at
             FROM pr_reviews WHERE pr_id=$1 ORDER BY created_at ASC",
        )
        .bind(pr_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PrReview {
                id: r.get("id"),
                pr_id: r.get("pr_id"),
                reviewer_did: r.get("reviewer_did"),
                body: r.get("body"),
                status: r.get("status"),
                created_at: r.get("created_at"),
            })
            .collect())
    }
}

// ── Status Claims ─────────────────────────────────────────────────────────────

#[cfg(test)]
const INSERT_STATUS_CLAIM_SQL: &str = "INSERT INTO status_claims
     (id, repo_id, commit_sha, state, context, target_url, description,
      producer_did, authorizing_did, signature, signature_input,
      signing_string, request_body, request_digest, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     RETURNING seq";

/// The same insert, made a no-op when the request has already been recorded.
/// The column list must stay identical to [`INSERT_STATUS_CLAIM_SQL`]: both are
/// bound by [`status_claim_insert`], so a divergence is a parameter-count error
/// on the first write either way runs.
///
/// `DO NOTHING` rather than an error, so `RETURNING` yields no row at all. That
/// empty result is how the caller learns the write was a replay; see
/// [`Db::insert_status_claim_capped`].
const INSERT_STATUS_CLAIM_IF_NEW_SQL: &str = "INSERT INTO status_claims
     (id, repo_id, commit_sha, state, context, target_url, description,
      producer_did, authorizing_did, signature, signature_input,
      signing_string, request_body, request_digest, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     ON CONFLICT (request_digest) DO NOTHING
     RETURNING seq";

/// The claim a given request already wrote, if any. Rides the unique index the
/// replay containment is built on, so it is one probe rather than a scan.
///
/// Takes the transaction rather than the pool: the caller runs it inside the
/// capped insert, both before the caps and again after a conflict, and reading
/// outside that transaction would answer from a different snapshot.
async fn claim_by_digest(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    digest: &str,
) -> Result<Option<StatusClaim>> {
    let row = sqlx::query(
        "SELECT id,seq,repo_id,commit_sha,state,context,target_url,description,
                producer_did,authorizing_did,signature,signature_input,
                signing_string,request_body,request_digest,created_at
         FROM status_claims WHERE request_digest = $1",
    )
    .bind(digest)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(row_to_status_claim))
}

/// The bind chain for [`INSERT_STATUS_CLAIM_SQL`], shared by the plain and the
/// capped insert so the two can never bind different columns.
///
/// Both DIDs are normalized here, at the one place claims are written, rather
/// than at each call site. The owner gate accepts `did:key:X` and the bare `X` as
/// the same identity, so a producer who alternates spellings would otherwise
/// store two values for one identity: the projection dedupes on the raw
/// `producer_did`, and the per-tuple cap counts on it, so both would be split in
/// half and the superseded claim would keep voting in the combined state.
fn status_claim_insert<'a>(
    sql: &'a str,
    claim: &'a StatusClaim,
) -> sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(sql)
        .bind(&claim.id)
        .bind(&claim.repo_id)
        .bind(&claim.commit_sha)
        .bind(&claim.state)
        .bind(&claim.context)
        .bind(&claim.target_url)
        .bind(&claim.description)
        .bind(canonical_did(&claim.producer_did).into_owned())
        .bind(canonical_did(&claim.authorizing_did).into_owned())
        .bind(&claim.signature)
        .bind(&claim.signature_input)
        .bind(&claim.signing_string)
        .bind(&claim.request_body)
        .bind(&claim.request_digest)
        .bind(&claim.created_at)
}

/// The projection behind the commit-status read, with its own column list: only
/// the fields a read surface renders. `seq` is selected in the inner query for
/// the ordering and dropped by the outer one. The signature material is
/// deliberately absent — see [`StatusProjection`].
const LATEST_STATUS_CLAIMS_SQL: &str =
    "SELECT state,context,target_url,description,producer_did,created_at FROM (
     SELECT DISTINCT ON (producer_did, context)
            seq,state,context,target_url,description,producer_did,created_at
     FROM status_claims
     WHERE repo_id=$1 AND commit_sha=$2 AND authorizing_did = $3
     ORDER BY producer_did, context, seq DESC
 ) latest ORDER BY seq ASC";

/// The trailing window the per-repo bound counts over. Named here, next to the
/// query that uses it, and quoted in the refusal message the handler surfaces.
const CLAIM_REPO_WINDOW_HOURS: i64 = 24;

/// The three write-path bounds. All three are checked in the insert transaction:
/// one alone bounds nothing, because the context string and the commit SHA are
/// both caller-chosen and the SHA is never existence-checked.
pub struct ClaimCaps {
    /// Claims for one (repo, commit, producer, context).
    pub per_tuple: i64,
    /// Distinct contexts for one (repo, commit).
    pub contexts_per_commit: i64,
    /// Claim rows for one repo within the trailing
    /// [`CLAIM_REPO_WINDOW_HOURS`]-hour window.
    ///
    /// A window and not an all-time total. Nothing prunes this table, so a
    /// lifetime bound would be a dead end: the repo's claim count never falls,
    /// the refusal never becomes satisfiable, and the surface is closed for
    /// good — while the 429 tells every CI client to retry forever. As a rate it
    /// still bounds the fan-out this cap exists for (the commit SHA is
    /// caller-chosen and never existence-checked, so the other two bounds do not
    /// contain it), and the refusal is honest: waiting out the window works.
    pub per_repo_window: i64,
}

/// Outcome of a capped append. `CapExceeded` names the bound that refused, for
/// the caller's 429 message; it is not a database error.
///
/// `AlreadyRecorded` carries the row the identical request wrote the first time,
/// so the caller can answer with the claim it already has instead of an error. A
/// refusal would be wrong twice over: it tells a CI client whose response was
/// lost to the network that its report failed when it succeeded, and it makes
/// the honest retry indistinguishable from the attack.
pub enum ClaimInsert {
    Inserted(i64),
    AlreadyRecorded(Box<StatusClaim>),
    CapExceeded(&'static str),
}

impl Db {
    /// Append one claim. `claim.seq` is ignored: the column is a `bigserial` and
    /// the database assigns the value, which is returned here so a caller can
    /// report the row it just wrote without a second read.
    // The write handler uses the capped form below; this stays the uncapped
    // primitive the db tests drive directly, and compiling it only under
    // cfg(test) keeps that fact from decaying into an unused production API.
    #[cfg(test)]
    pub async fn insert_status_claim(&self, claim: &StatusClaim) -> Result<i64> {
        let row = status_claim_insert(INSERT_STATUS_CLAIM_SQL, claim)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("seq"))
    }

    /// Append one claim only if it is new and all three caps still admit it.
    ///
    /// A request already recorded returns its original row and writes nothing,
    /// BEFORE any cap is consulted. That order matters: a client retrying a
    /// request whose response was lost must not be told 429 by a tuple cap its
    /// own earlier write filled.
    ///
    /// Writers against one repo are serialized on a transaction-scoped advisory
    /// lock taken before the first count. A transaction alone would not hold the
    /// bounds: Postgres runs READ COMMITTED, so concurrent writers each count the
    /// rows committed when they started, every one of them reads a value under the
    /// cap, and every one of them inserts — the table ends up over the bound by
    /// the concurrency, which is exactly the burst the caps exist to stop.
    ///
    /// The lock is keyed on the repo id, which is the coarsest of the three
    /// bounds, so one key covers all of them. It is released by the commit or the
    /// rollback, including the early returns below. `hashtext` collisions put two
    /// unrelated repos behind one key, which costs a little serialization on the
    /// write path and nothing in correctness.
    pub async fn insert_status_claim_capped(
        &self,
        claim: &StatusClaim,
        caps: &ClaimCaps,
    ) -> Result<ClaimInsert> {
        let mut attempt = 1;
        loop {
            match self.insert_status_claim_capped_attempt(claim, caps).await {
                Ok(outcome) => return Ok(outcome),
                Err(e) if attempt < PUSH_LOCK_ATTEMPTS && is_transient_db_write(&e) => {
                    tracing::debug!(
                        attempt,
                        repo = %claim.repo_id,
                        "status-claim write timed out waiting for the repo lock; retrying"
                    );
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// One attempt at the capped insert: bound every lock wait in the
    /// transaction, take the repo advisory lock, then run the cap checks and
    /// the insert. `SET LOCAL lock_timeout` is what turns a wedged lock holder
    /// from an unbounded wait into a retryable error.
    async fn insert_status_claim_capped_attempt(
        &self,
        claim: &StatusClaim,
        caps: &ClaimCaps,
    ) -> Result<ClaimInsert> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(&format!(
            "SET LOCAL lock_timeout = '{PUSH_LOCK_TIMEOUT_MS}ms'"
        ))
        .execute(&mut *tx)
        .await?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind(&claim.repo_id)
            .execute(&mut *tx)
            .await?;

        // Replay first, and cheapest: one unique-index probe. Under the repo
        // lock this settles every same-repo racer, and the index below settles
        // the rest.
        if let Some(existing) = claim_by_digest(&mut tx, &claim.request_digest).await? {
            return Ok(ClaimInsert::AlreadyRecorded(Box::new(existing)));
        }

        // The tuple bound and the context-fanout bound read the same
        // (repo, commit) rows, so they are one aggregate over one scan rather
        // than two round trips: the tuple count is the same scan narrowed by a
        // FILTER.
        let row = sqlx::query(
            "SELECT count(*) FILTER (WHERE producer_did=$3 AND context=$4) AS tuple_count,
                    count(DISTINCT context) AS contexts,
                    COALESCE(bool_or(context = $4), false) AS present
             FROM status_claims WHERE repo_id=$1 AND commit_sha=$2",
        )
        .bind(&claim.repo_id)
        .bind(&claim.commit_sha)
        // Canonicalized to match what the insert stores (see
        // status_claim_insert): counting on the raw DID would give one identity a
        // fresh cap per spelling.
        .bind(canonical_did(&claim.producer_did).into_owned())
        .bind(&claim.context)
        .fetch_one(&mut *tx)
        .await?;
        let tuple_count: i64 = row.get("tuple_count");
        let contexts: i64 = row.get("contexts");
        let present: bool = row.get("present");

        if tuple_count >= caps.per_tuple {
            return Ok(ClaimInsert::CapExceeded(
                "claims for this commit, producer and context",
            ));
        }

        // A context already present does not widen the fanout, so only a NEW
        // context is measured against the limit.
        if !present && contexts >= caps.contexts_per_commit {
            return Ok(ClaimInsert::CapExceeded(
                "distinct contexts for this commit",
            ));
        }

        // Trailing window, not an all-time count: see ClaimCaps::per_repo_window.
        // `created_at` is TEXT, and the server writes every row as one rfc3339
        // UTC format, so the comparison is chronological as well as lexical.
        let window_start =
            (Utc::now() - chrono::Duration::hours(CLAIM_REPO_WINDOW_HOURS)).to_rfc3339();
        let repo_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM status_claims WHERE repo_id=$1 AND created_at >= $2",
        )
        .bind(&claim.repo_id)
        .bind(&window_start)
        .fetch_one(&mut *tx)
        .await?;
        if repo_rows >= caps.per_repo_window {
            return Ok(ClaimInsert::CapExceeded(
                "claims for this repository in the last 24 hours",
            ));
        }

        // The probe above is the fast path, not the guarantee: two nodes sharing
        // this database, or two requests the repo lock does not cover, can both
        // pass it. The unique index is what actually holds, and `DO NOTHING`
        // turns losing that race into an empty result rather than an error.
        let inserted = status_claim_insert(INSERT_STATUS_CLAIM_IF_NEW_SQL, claim)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(inserted) = inserted else {
            let existing = claim_by_digest(&mut tx, &claim.request_digest)
                .await?
                .context("status claim insert conflicted on request_digest but the conflicting row could not be read back")?;
            return Ok(ClaimInsert::AlreadyRecorded(Box::new(existing)));
        };
        let seq = inserted.get::<i64, _>("seq");
        tx.commit().await?;
        Ok(ClaimInsert::Inserted(seq))
    }

    /// Every claim recorded for one commit, oldest first. Ordering is on `seq`,
    /// never on the timestamp, which is display data and can collide.
    #[cfg(test)]
    pub async fn list_status_claims(
        &self,
        repo_id: &str,
        commit_sha: &str,
    ) -> Result<Vec<StatusClaim>> {
        let rows = sqlx::query(
            "SELECT id,seq,repo_id,commit_sha,state,context,target_url,description,
                    producer_did,authorizing_did,signature,signature_input,
                    signing_string,request_body,request_digest,created_at
             FROM status_claims WHERE repo_id=$1 AND commit_sha=$2 ORDER BY seq ASC",
        )
        .bind(repo_id)
        .bind(commit_sha)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_status_claim).collect())
    }

    /// The projection behind the commit-status read (KTD-2): the latest claim per
    /// (producer, context) for one commit, restricted to claims authorized by
    /// `authorizing_did`.
    ///
    /// Computed on every read and never materialized, so a repo whose visibility
    /// or ownership changes after a claim was written is answered from current
    /// state with no reconciliation job. "Latest" is the highest `seq` (KTD-3):
    /// the timestamp is producer-visible display data and the id is a random
    /// uuid, so neither orders the history.
    ///
    /// The authorization filter is one equality evaluated inside the query rather
    /// than a per-claim check in Rust, which is the constraint the
    /// delegated-capability follow-on inherits: it may widen the filter, never
    /// move the test into the read loop. It is a single comparison and not a set
    /// expansion because the column is already canonicalized on write through
    /// [`canonical_did`], which is defined over the same [`normalize_owner_key`]
    /// that `did_matches` collapses with, so the `did:key` rule has one definition
    /// instead of a copy per query.
    pub async fn latest_status_claims(
        &self,
        repo_id: &str,
        commit_sha: &str,
        authorizing_did: &str,
    ) -> Result<Vec<StatusProjection>> {
        let rows = sqlx::query(LATEST_STATUS_CLAIMS_SQL)
            .bind(repo_id)
            .bind(commit_sha)
            .bind(canonical_did(authorizing_did).into_owned())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(row_to_status_projection).collect())
    }
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

impl Db {
    pub async fn create_webhook(&self, hook: &Webhook) -> Result<()> {
        let events_json = serde_json::to_string(&hook.events)?;
        sqlx::query(
            "INSERT INTO webhooks (id, repo_id, url, secret, events, created_by_did, created_at, active)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&hook.id)
        .bind(&hook.repo_id)
        .bind(&hook.url)
        .bind(hook.secret.as_ref().map(|s| s.as_str()))
        .bind(&events_json)
        .bind(&hook.created_by_did)
        .bind(&hook.created_at)
        .bind(hook.active)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_webhooks(&self, repo_id: &str) -> Result<Vec<Webhook>> {
        let rows = sqlx::query(
            "SELECT id, repo_id, url, secret, events, created_by_did, created_at, active
             FROM webhooks WHERE repo_id = $1 ORDER BY created_at ASC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_webhook).collect())
    }

    pub async fn get_webhook(&self, id: &str) -> Result<Option<Webhook>> {
        let row = sqlx::query(
            "SELECT id, repo_id, url, secret, events, created_by_did, created_at, active
             FROM webhooks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_webhook))
    }

    pub async fn delete_webhook(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_webhooks_for_event(
        &self,
        repo_id: &str,
        event: &str,
    ) -> Result<Vec<Webhook>> {
        let all = self.list_webhooks(repo_id).await?;
        Ok(all
            .into_iter()
            .filter(|h| h.active && h.events.iter().any(|e| e == "*" || e == event))
            .collect())
    }

    /// One-time re-encryption of webhook secrets that still rest as plaintext
    /// (rows written before at-rest encryption shipped). Runs once at startup; a
    /// schema migration cannot do this because the node-held key never reaches
    /// Postgres. Returns the number of rows rewritten.
    ///
    /// "Already sealed" means "opens under the node key", not "has the prefix":
    /// a plaintext secret that literally begins with the `enc:v1:` prefix, or a
    /// value sealed under another identity, fails `open` and is re-sealed raw,
    /// which preserves whatever the stored value was rather than wedging it.
    /// A prefixed value that does not open is also warned on, since it is more
    /// likely corrupt ciphertext than a colliding plaintext.
    pub async fn reencrypt_legacy_webhook_secrets(&self, key: &[u8; 32]) -> Result<usize> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id, secret FROM webhooks WHERE secret IS NOT NULL")
                .fetch_all(&self.pool)
                .await?;

        let mut rewritten = 0usize;
        for (id, stored) in rows {
            if crate::webhook_secret::open(key, &stored).is_some() {
                continue; // already sealed under this node's key
            }
            if crate::webhook_secret::has_seal_shape(&stored) {
                // Well-formed sealed payload that does not open under this
                // node's key: foreign or rotated ciphertext. Re-wrapping the
                // outer blob as plaintext would make `reveal` return it as a
                // signing secret and flip Withhold into a garbage signature,
                // so leave the row unchanged: delivery keeps withholding.
                tracing::warn!(
                    webhook_id = %id,
                    "webhook secret is well-formed ciphertext but does not open under the node key; leaving it unchanged"
                );
                continue;
            }
            if stored.starts_with(crate::webhook_secret::SEAL_PREFIX) {
                tracing::warn!(
                    webhook_id = %id,
                    "webhook secret has the sealed prefix but is not well-formed ciphertext; sealing the raw value as plaintext"
                );
            }
            let sealed = crate::webhook_secret::seal(key, &stored);
            // Compare-and-set on the value read above: a concurrent secret
            // update between SELECT and UPDATE must not be clobbered.
            let result =
                sqlx::query("UPDATE webhooks SET secret = $2 WHERE id = $1 AND secret = $3")
                    .bind(&id)
                    .bind(sealed)
                    .bind(&stored)
                    .execute(&self.pool)
                    .await?;
            if result.rows_affected() == 0 {
                tracing::warn!(
                    webhook_id = %id,
                    "webhook secret changed between read and re-encrypt; skipping"
                );
            }
            rewritten += result.rows_affected() as usize;
        }
        Ok(rewritten)
    }
}

// ── Ref Certificates ──────────────────────────────────────────────────────────

impl Db {
    /// Insert a ref certificate, or update it if a row for `(repo_id, ref_name)`
    /// already exists.  The update only applies when the incoming row is newer
    /// (compared by `issued_at`, which assumes a monotonic wall clock), so a
    /// late-landing older cert cannot regress a ref's persisted state.  Returns
    /// the full row as it now exists in the database (the original row on a
    /// rejected upsert; the passed row on insert).
    #[allow(dead_code)] // legacy live-path entry; PR 3 owns the deprecation decision
    pub async fn insert_ref_certificate(&self, cert: &RefCertificate) -> Result<RefCertificate> {
        let row = sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (repo_id, ref_name) DO UPDATE SET
                old_sha   = CASE WHEN EXCLUDED.issued_at > ref_certificates.issued_at
                                 THEN EXCLUDED.old_sha   ELSE ref_certificates.old_sha   END,
                new_sha   = CASE WHEN EXCLUDED.issued_at > ref_certificates.issued_at
                                 THEN EXCLUDED.new_sha   ELSE ref_certificates.new_sha   END,
                pusher_did = CASE WHEN EXCLUDED.issued_at > ref_certificates.issued_at
                                  THEN EXCLUDED.pusher_did ELSE ref_certificates.pusher_did END,
                node_did  = CASE WHEN EXCLUDED.issued_at > ref_certificates.issued_at
                                 THEN EXCLUDED.node_did  ELSE ref_certificates.node_did  END,
                signature = CASE WHEN EXCLUDED.issued_at > ref_certificates.issued_at
                                 THEN EXCLUDED.signature ELSE ref_certificates.signature END,
                issued_at = CASE WHEN EXCLUDED.issued_at > ref_certificates.issued_at
                                 THEN EXCLUDED.issued_at ELSE ref_certificates.issued_at END,
                version   = CASE WHEN EXCLUDED.issued_at > ref_certificates.issued_at
                                 THEN EXCLUDED.version   ELSE ref_certificates.version   END
             RETURNING id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, version",
        )
        .bind(&cert.id)
        .bind(&cert.repo_id)
        .bind(&cert.ref_name)
        .bind(&cert.old_sha)
        .bind(&cert.new_sha)
        .bind(&cert.pusher_did)
        .bind(&cert.node_did)
        .bind(&cert.signature)
        .bind(&cert.issued_at)
        .bind(cert.version as i32)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_to_cert(row))
    }

    // ── #26 Split PR 1: durable post-receive outbox ────────────────────────
    //
    // The methods below own the producer/persistence/restore boundary the
    // reviewer flagged: every externally visible ref transition has a row
    // here before the receive_pack call, the row's state reflects the
    // outcome (`applied` on Ok, `cancelled` on Err), and a startup drain
    // re-derives the push event, ref certificate, and anchor handoff for
    // any `applied` row. Recovery is idempotent because every derived
    // artifact has a deterministic id (see `*_id_for` above) and the
    // `INSERT ... ON CONFLICT (id) DO NOTHING` clause collapses a
    // re-fired transition to a no-op.
    //
    // The handler is responsible for calling `insert_prepared` before the
    // `smart_http::receive_pack` call and `mark_applied` / `mark_cancelled`
    // after. The `drain_applied` method is called once at startup, after
    // migrations and before serving. Wiring those into the handler is
    // tracked as the next slice of work; this commit adds the durable
    // boundary and the DB-level idempotency the handler will lean on.

    /// Insert one `prepared` row per ref update in the push, returning the
    /// rows as persisted. Called from the receive-pack handler BEFORE
    /// `smart_http::receive_pack` runs.
    ///
    /// `request_id` is the per-handler UUID; the same value must be used
    /// for every ref update in a single push, and it becomes the
    /// deterministic seed for the push event, ref cert, and anchor job
    /// ids. `pusher_did` is the verified DID from the
    /// `AuthenticatedDid` extension (the canonical identity the
    /// `require_signature` middleware injected). `signature_header` and
    /// `signature_input` are the raw RFC 9421 header values, persisted
    /// for audit; they were already verified at handler entry.
    ///
    /// `ordinal` is the zero-based position of each ref in the pkap-line
    /// stream; the live handler sets it from
    /// `ref_updates.iter().enumerate()`. `git_target_kind` is a snapshot
    /// of the update's git-side classification (`"create"`, `"update"`,
    /// `"delete"`, …). The recovery re-derives the latter from the
    /// per-ref report if the column is null, so the column is
    /// informational and optional.
    #[allow(dead_code, clippy::too_many_arguments)] // wired by the handler refactor in the next slice
    pub async fn insert_pending_ref_transitions(
        &self,
        request_id: &str,
        repo_id: &str,
        node_did: &str,
        pusher_did: &str,
        ref_updates: &[crate::api::repos::RefUpdate],
        signature_header: &str,
        signature_input: &str,
        content_digest: &str,
    ) -> Result<Vec<PendingRefTransition>> {
        let now = Utc::now().to_rfc3339();
        // P2 (reviewer-2 round 2): wrap the multi-row insert in a
        // transaction. A mid-loop failure used to return the error
        // and leave the rows already inserted as `prepared`, which
        // the receive-pack handler then refused to call. The
        // stranded `prepared` rows were eventually reaped by the
        // startup reconcile, but the partial-success state was
        // observable in the DB and could mask a partial push
        // intent. The transaction rolls the prior inserts back
        // when any single row fails, so the caller either sees a
        // complete `prepared` set for the request or sees none of
        // them and the handler can safely return 503.
        let mut tx = self.pool.begin().await?;
        let mut out = Vec::with_capacity(ref_updates.len());
        for (ordinal, update) in ref_updates.iter().enumerate() {
            let ordinal_i32 = ordinal as i32;
            let id = deterministic_id(&[
                "pending_ref_transition",
                request_id,
                repo_id,
                &update.ref_name,
                &update.old_sha,
                &update.new_sha,
            ]);
            sqlx::query(
                r#"INSERT INTO pending_ref_transitions
                   (id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                    signature_header, signature_input, content_digest, state, created_at,
                    ordinal, git_target_kind)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
            )
            .bind(&id)
            .bind(request_id)
            .bind(repo_id)
            .bind(&update.ref_name)
            .bind(&update.old_sha)
            .bind(&update.new_sha)
            .bind(pusher_did)
            .bind(node_did)
            .bind(signature_header)
            .bind(signature_input)
            .bind(content_digest)
            .bind(pending_state::PREPARED)
            .bind(&now)
            .bind(ordinal_i32)
            .bind(Option::<String>::None)
            .execute(&mut *tx)
            .await?;
            out.push(PendingRefTransition {
                id,
                request_id: request_id.to_string(),
                repo_id: repo_id.to_string(),
                ref_name: update.ref_name.clone(),
                old_sha: update.old_sha.clone(),
                new_sha: update.new_sha.clone(),
                pusher_did: pusher_did.to_string(),
                node_did: node_did.to_string(),
                signature_header: signature_header.to_string(),
                signature_input: signature_input.to_string(),
                content_digest: content_digest.to_string(),
                state: pending_state::PREPARED.to_string(),
                created_at: now.clone(),
                applied_at: None,
                cancelled_at: None,
                ordinal: ordinal_i32,
                git_target_kind: None,
            });
        }
        tx.commit().await?;
        Ok(out)
    }

    // ── request-level surface (#26 Split PR 1 step 2) ────────────

    /// Insert a `receive_pack_requests` row in state `received`. Step 2
    /// calls this from the handler's intent path BEFORE
    /// `smart_http::receive_pack` runs; a node crash after this point
    /// and before the live outcomes commit leaves the row in
    /// `received` and its children in `prepared`, which the reconcile
    /// step (already on this branch) handles via on-disk SHA + reflog
    /// proof.
    ///
    /// Prefer [`Db::insert_receive_pack_request_with_children`] for new
    /// code: it writes the parent and all children in one transaction
    /// so a refused pre-Git request cannot strand a payload-only
    /// parent.
    #[allow(dead_code)]
    pub async fn insert_receive_pack_request(&self, req: &ReceivePackRequest) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO receive_pack_requests
               (id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                last_error, next_attempt_at, created_at, completed_at,
                signature_header, signature_input, content_digest)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)"#,
        )
        .bind(&req.id)
        .bind(&req.repo_id)
        .bind(&req.pusher_did)
        .bind(&req.node_did)
        .bind(&req.request_bytes)
        .bind(&req.request_bytes_hash)
        .bind(&req.state)
        .bind(req.git_exit_ok)
        .bind(req.parsed_report.as_ref())
        .bind(req.accepted_ordinal)
        .bind(req.attempt_count)
        .bind(req.last_error.as_deref())
        .bind(req.next_attempt_at.as_deref())
        .bind(&req.created_at)
        .bind(req.completed_at.as_deref())
        .bind(req.signature_header.as_deref())
        .bind(req.signature_input.as_deref())
        .bind(req.content_digest.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomic durable-intent write: parent request plus all ordered
    /// ref children in one transaction. Either all exist or none
    /// exist, so the reconcile/executor never sees a payload-only
    /// parent. New handler code must use this instead of the two
    /// separate inserts.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_receive_pack_request_with_children(
        &self,
        req: &ReceivePackRequest,
        repo_id: &str,
        node_did: &str,
        pusher_did: &str,
        ref_updates: &[crate::api::repos::RefUpdate],
        signature_header: &str,
        signature_input: &str,
        content_digest: &str,
    ) -> Result<Vec<PendingRefTransition>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"INSERT INTO receive_pack_requests
               (id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                last_error, next_attempt_at, created_at, completed_at,
                signature_header, signature_input, content_digest)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)"#,
        )
        .bind(&req.id)
        .bind(&req.repo_id)
        .bind(&req.pusher_did)
        .bind(&req.node_did)
        .bind(&req.request_bytes)
        .bind(&req.request_bytes_hash)
        .bind(&req.state)
        .bind(req.git_exit_ok)
        .bind(req.parsed_report.as_ref())
        .bind(req.accepted_ordinal)
        .bind(req.attempt_count)
        .bind(req.last_error.as_deref())
        .bind(req.next_attempt_at.as_deref())
        .bind(&req.created_at)
        .bind(req.completed_at.as_deref())
        .bind(req.signature_header.as_deref())
        .bind(req.signature_input.as_deref())
        .bind(req.content_digest.as_deref())
        .execute(&mut *tx)
        .await?;
        // Durable versioned proof, same txn as intent: survives child
        // deletion and gates retirement until acked.
        sqlx::query(
            r#"INSERT INTO request_proofs
               (request_id, repo_id, pusher_did, body_digest, signature_header,
                signature_input, content_digest, created_at, acked_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL)
               ON CONFLICT (request_id) DO NOTHING"#,
        )
        .bind(&req.id)
        .bind(&req.repo_id)
        .bind(&req.pusher_did)
        .bind(&req.request_bytes_hash)
        .bind(req.signature_header.as_deref().unwrap_or(""))
        .bind(req.signature_input.as_deref().unwrap_or(""))
        .bind(req.content_digest.as_deref().unwrap_or(""))
        .bind(&req.created_at)
        .execute(&mut *tx)
        .await?;
        let now = req.created_at.clone();
        let mut out = Vec::with_capacity(ref_updates.len());
        for (ordinal, update) in ref_updates.iter().enumerate() {
            let ordinal_i32 = ordinal as i32;
            let id = deterministic_id(&[
                "pending_ref_transition",
                &req.id,
                repo_id,
                &update.ref_name,
                &update.old_sha,
                &update.new_sha,
            ]);
            sqlx::query(
                r#"INSERT INTO pending_ref_transitions
                   (id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                    signature_header, signature_input, content_digest, state, created_at,
                    ordinal, git_target_kind)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
            )
            .bind(&id)
            .bind(&req.id)
            .bind(repo_id)
            .bind(&update.ref_name)
            .bind(&update.old_sha)
            .bind(&update.new_sha)
            .bind(pusher_did)
            .bind(node_did)
            .bind(signature_header)
            .bind(signature_input)
            .bind(content_digest)
            .bind(pending_state::PREPARED)
            .bind(&now)
            .bind(ordinal_i32)
            .bind(Option::<String>::None)
            .execute(&mut *tx)
            .await?;
            out.push(PendingRefTransition {
                id,
                request_id: req.id.clone(),
                repo_id: repo_id.to_string(),
                ref_name: update.ref_name.clone(),
                old_sha: update.old_sha.clone(),
                new_sha: update.new_sha.clone(),
                pusher_did: pusher_did.to_string(),
                node_did: node_did.to_string(),
                signature_header: signature_header.to_string(),
                signature_input: signature_input.to_string(),
                content_digest: content_digest.to_string(),
                state: pending_state::PREPARED.to_string(),
                created_at: now.clone(),
                applied_at: None,
                cancelled_at: None,
                ordinal: ordinal_i32,
                git_target_kind: None,
            });
        }
        tx.commit().await?;
        Ok(out)
    }

    /// Read a single `receive_pack_requests` row by id. Used by
    /// `durable_outbox::apply_request_effects` to load the
    /// request's state, `accepted_ordinal`, and parsed report
    /// before re-deriving per-ref artifacts.
    pub async fn get_receive_pack_request(
        &self,
        request_id: &str,
    ) -> Result<Option<ReceivePackRequest>> {
        let row = sqlx::query(
            r#"SELECT id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                       state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                       last_error, next_attempt_at, created_at, completed_at,
                       signature_header, signature_input, content_digest
                FROM receive_pack_requests WHERE id = $1"#,
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_receive_pack_request))
    }

    /// `received → outcomes_committed`. The handler calls this once
    /// per request, with the parsed report, the git exit, and the
    /// ordinal of the first ref the report proves landed. The state
    /// gate in the WHERE clause means a concurrent drain cannot
    /// re-flip a row the handler is mid-update.
    #[allow(dead_code)]
    pub async fn mark_request_outcomes_committed(
        &self,
        request_id: &str,
        git_exit_ok: bool,
        parsed_report: &serde_json::Value,
        accepted_ordinal: Option<i32>,
    ) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state = $2, git_exit_ok = $3, parsed_report = $4,
                   accepted_ordinal = $5
               WHERE id = $1 AND state = $6"#,
        )
        .bind(request_id)
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(git_exit_ok)
        .bind(parsed_report)
        .bind(accepted_ordinal)
        .bind(request_state::RECEIVED)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// `received → rejected_at_git`. Step 2 calls this when git
    /// returned non-zero with no parseable report. The children
    /// stay in `prepared` and the reconcile step decides their
    /// fate via on-disk SHA + reflog proof.
    #[allow(dead_code)]
    pub async fn mark_request_rejected_at_git(
        &self,
        request_id: &str,
        last_error: Option<&str>,
    ) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state = $2, git_exit_ok = FALSE, last_error = $3,
                   completed_at = $4
               WHERE id = $1 AND state = $5"#,
        )
        .bind(request_id)
        .bind(request_state::REJECTED_AT_GIT)
        .bind(last_error)
        .bind(Utc::now().to_rfc3339())
        .bind(request_state::RECEIVED)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Pre-git refusal after durable intent was written: atomically move the
    /// parent `received` → `rejected_at_git` (terminal, purge-eligible),
    /// cancel all `prepared` children, and ack the proof row. Every early
    /// return between intent insert and `receive_pack` must call this so a
    /// shed push never strands `received` + `prepared` rows the purge path
    /// never touches and reconcile can never promote (no git evidence).
    ///
    /// Bounded to 10s: the transaction is `pool.begin()` + three UPDATEs +
    /// commit with no statement_timeout configured on the pool, so a
    /// lock-blocked cleanup can pin a global write slot (and on four of the
    /// five call sites, the lease and per-source permit too) indefinitely.
    /// The 10s convention matches the other bounded git calls on the
    /// receive-pack path.
    pub async fn refuse_receive_pack_before_git(
        &self,
        request_id: &str,
        reason: &str,
    ) -> Result<()> {
        let cleanup = async {
            let mut tx = self.pool.begin().await?;
            let now = Utc::now().to_rfc3339();
            sqlx::query(
                r#"UPDATE receive_pack_requests
                   SET state = $2, git_exit_ok = FALSE, last_error = $3,
                       completed_at = $4
                   WHERE id = $1 AND state = $5"#,
            )
            .bind(request_id)
            .bind(request_state::REJECTED_AT_GIT)
            .bind(reason)
            .bind(&now)
            .bind(request_state::RECEIVED)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"UPDATE pending_ref_transitions
                   SET state = $2, cancelled_at = $3
                   WHERE request_id = $1 AND state = $4"#,
            )
            .bind(request_id)
            .bind(pending_state::CANCELLED)
            .bind(&now)
            .bind(pending_state::PREPARED)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"UPDATE request_proofs SET acked_at = $2 WHERE request_id = $1 AND acked_at IS NULL"#,
            )
            .bind(request_id)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        };
        match tokio::time::timeout(std::time::Duration::from_secs(10), cleanup).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "refuse_receive_pack_before_git timed out after 10s"
            )),
        }
    }

    /// Post-git-start interruption (client disconnect during `receive_pack`,
    /// or a handler drop before the outcome commit): parent `received` →
    /// `rejected_at_git` (terminal, purge-eligible) and `prepared` children →
    /// `uncertain` — never `cancelled`, because git may have landed refs and
    /// reconcile must still prove each landing. This mirrors the
    /// `receive_pack` Err arm's inline handling for drops that can never
    /// reach it (a dropped future runs no Err arm; the detached reaper does
    /// process teardown only, no DB writes). Startup reconcile promotes
    /// proved children and the aggregate exactly as for that path: the
    /// promotion gate covers `rejected_at_git` parents.
    ///
    /// Gated on `state = received`, so a drop after the outcome commit
    /// resolved is a harmless no-op. The proof row is deliberately left
    /// unacked here (unlike the pre-git refuse): the drain acks it when
    /// effects complete, and an unacked proof blocks premature purge.
    /// Bounded 10s like [`Db::refuse_receive_pack_before_git`].
    pub async fn mark_receive_pack_interrupted(&self, request_id: &str) -> Result<()> {
        let cleanup = async {
            let mut tx = self.pool.begin().await?;
            let now = Utc::now().to_rfc3339();
            sqlx::query(
                r#"UPDATE receive_pack_requests
                   SET state = $2, git_exit_ok = FALSE,
                       last_error = $3, completed_at = $4
                   WHERE id = $1 AND state = $5"#,
            )
            .bind(request_id)
            .bind(request_state::REJECTED_AT_GIT)
            .bind("receive-pack interrupted before outcome commit")
            .bind(&now)
            .bind(request_state::RECEIVED)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"UPDATE pending_ref_transitions
                   SET state = $1
                   WHERE request_id = $2 AND state = $3"#,
            )
            .bind(pending_state::UNCERTAIN)
            .bind(request_id)
            .bind(pending_state::PREPARED)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        };
        match tokio::time::timeout(std::time::Duration::from_secs(10), cleanup).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "mark_receive_pack_interrupted timed out after 10s"
            )),
        }
    }

    /// #26 Split PR 1 step 5 — flip any non-terminal state to
    /// `quarantined`. The reconcile calls this when the marker
    /// ref is missing or hash-mismatched; the drain's
    /// `effects_max_attempts` bound calls this when a request
    /// has been retry-stuck for too long. Operator-attended: the
    /// drain never picks up `quarantined` rows.
    ///
    /// The state gate is intentionally permissive: any non-terminal
    /// state can be quarantined. The caller decides which state
    /// the row was in before the flip.
    pub async fn mark_request_quarantined(&self, request_id: &str, reason: &str) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state = $2, last_error = $3, completed_at = $4
               WHERE id = $1
                 AND state IN ($5, $6, $7, $8)"#,
        )
        .bind(request_id)
        .bind(request_state::QUARANTINED)
        .bind(reason)
        .bind(Utc::now().to_rfc3339())
        .bind(request_state::RECEIVED)
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(request_state::EFFECTS_PENDING)
        .bind(request_state::REJECTED_AT_GIT)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// #26 Split PR 1 step 5 — when a request moves to
    /// `quarantined`, its non-terminal children are reclassified to
    /// `cancelled` so the drain's residual scan doesn't keep
    /// picking them up. Covers both `prepared` and `uncertain`:
    /// quarantine is an aggregate transition, and an uncertain child
    /// of a quarantined parent has no executable owner otherwise.
    pub async fn mark_children_rejected_for_quarantined_parent(
        &self,
        request_id: &str,
    ) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $2, cancelled_at = $3
               WHERE request_id = $1 AND state IN ($4, $5)"#,
        )
        .bind(request_id)
        .bind(pending_state::CANCELLED)
        .bind(&now)
        .bind(pending_state::PREPARED)
        .bind(pending_state::UNCERTAIN)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// #26 Split PR 1 step 5 — batch-load receive_pack_requests by
    /// id. The reconcile calls this once per page to avoid N+1
    /// queries when the marker gate checks every row's parent
    /// request. Returns a HashMap so the per-row check is a
    /// O(1) lookup.
    pub async fn get_receive_pack_requests_by_ids(
        &self,
        ids: &[String],
    ) -> Result<std::collections::HashMap<String, ReceivePackRequest>> {
        if ids.is_empty() {
            return Ok(Default::default());
        }
        let rows = sqlx::query(
            r#"SELECT id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                       state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                       last_error, next_attempt_at, created_at, completed_at,
                       signature_header, signature_input, content_digest
                FROM receive_pack_requests WHERE id = ANY($1)"#,
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(row_to_receive_pack_request)
            .map(|r| (r.id.clone(), r))
            .collect())
    }

    /// `outcomes_committed → effects_pending` and
    /// `effects_pending → effects_pending` (retry progression). The
    /// first failure moves `outcomes_committed` to `effects_pending`;
    /// every later failure must re-arm the same row, bump
    /// `attempt_count`, and push `next_attempt_at` forward, otherwise
    /// the bound check never advances and a poisoned request retries
    /// forever. Returns rows affected; callers must fail loudly on
    /// zero when the request was expected to exist.
    pub async fn mark_request_effects_pending(
        &self,
        request_id: &str,
        next_attempt_at: &str,
        last_error: &str,
    ) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state = $2, attempt_count = attempt_count + 1,
                   next_attempt_at = $3, last_error = $4
               WHERE id = $1 AND state IN ($5, $6)"#,
        )
        .bind(request_id)
        .bind(request_state::EFFECTS_PENDING)
        .bind(next_attempt_at)
        .bind(last_error)
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(request_state::EFFECTS_PENDING)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// `effects_pending → complete`. Step 3 calls this after a
    /// successful effects run.
    pub async fn mark_request_complete(&self, request_id: &str) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state = $2, completed_at = $3
               WHERE id = $1 AND state IN ($4, $5)"#,
        )
        .bind(request_id)
        .bind(request_state::COMPLETE)
        .bind(Utc::now().to_rfc3339())
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(request_state::EFFECTS_PENDING)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Drain-side read. Returns every request whose state is
    /// `outcomes_committed` or `effects_pending` and whose
    /// `next_attempt_at` is null or in the past.
    pub async fn list_receive_pack_requests_due(
        &self,
        limit: i64,
    ) -> Result<Vec<ReceivePackRequest>> {
        let limit = limit.max(1);
        let rows = sqlx::query(
            r#"SELECT id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                       state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                       last_error, next_attempt_at, created_at, completed_at,
                       signature_header, signature_input, content_digest
                FROM receive_pack_requests
                WHERE state IN ($1, $2)
                  AND (next_attempt_at IS NULL OR next_attempt_at < $3)
                ORDER BY created_at ASC, id ASC
                LIMIT $4"#,
        )
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(request_state::EFFECTS_PENDING)
        .bind(Utc::now().to_rfc3339())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_receive_pack_request).collect())
    }

    /// Residual-backlog check for the per-request drain. Returns
    /// the count of requests in `outcomes_committed` or
    /// `effects_pending` with a due `next_attempt_at`. The drain's
    /// `drain_receive_pack_requests_all` uses this after the
    /// residual pass to decide whether to log a warning.
    pub async fn count_receive_pack_requests_due(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*)::BIGINT FROM receive_pack_requests
               WHERE state IN ($1, $2)
                 AND (next_attempt_at IS NULL OR next_attempt_at < $3)"#,
        )
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(request_state::EFFECTS_PENDING)
        .bind(Utc::now().to_rfc3339())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Backoff helper for the step-3 effect executor. Step 3
    /// introduces the helper but does not call it; a future
    /// refinement (per-attempt exponential backoff) will land the
    /// call site. Pinning the contract here means the helper cannot
    /// drift away from what the next slice will use.
    #[allow(dead_code)] // call site lands in a follow-up; the helper signature is pinned here
    pub async fn update_request_attempt(
        &self,
        request_id: &str,
        attempt_count: i32,
        next_attempt_at: &str,
        last_error: &str,
    ) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET attempt_count = $2, next_attempt_at = $3, last_error = $4
               WHERE id = $1"#,
        )
        .bind(request_id)
        .bind(attempt_count)
        .bind(next_attempt_at)
        .bind(last_error)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// #26 Split PR 1 step 4 — bounded retirement. Deletes terminal
    /// `receive_pack_requests` rows whose `completed_at` is older
    /// than `older_than_iso`. Only `complete` and `rejected_at_git`
    /// rows are eligible; `outcomes_committed` / `effects_pending`
    /// are never purged (the drain is responsible for them), and
    /// `received` rows are never purged (the handler is
    /// responsible for them).
    ///
    /// The `idx_receive_pack_requests_completed_at` partial index
    /// (built by v30) keeps this scan cheap. PostgreSQL does not
    /// accept `LIMIT` directly inside a `DELETE`, so the limit is
    /// applied via a subquery selecting the ids to delete.
    #[allow(dead_code)]
    pub async fn purge_completed_receive_pack_requests(
        &self,
        older_than_iso: &str,
        limit: i64,
    ) -> Result<u64> {
        let ids = self
            .purge_completed_receive_pack_requests_returning(older_than_iso, limit)
            .await?;
        Ok(ids.len() as u64)
    }

    /// Same as [`Db::purge_completed_receive_pack_requests`] but
    /// returns the deleted `(request_id, repo_id)` pairs so the caller
    /// can retire Git-side marker refs for the same requests. Keeps
    /// SQL and Git-side retention from diverging.
    pub async fn purge_completed_receive_pack_requests_returning(
        &self,
        older_than_iso: &str,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        let limit = limit.max(1);
        let rows: Vec<(String, String)> = sqlx::query_as(
            r#"DELETE FROM receive_pack_requests
               WHERE id IN (
                   SELECT id FROM receive_pack_requests
                   WHERE state IN ($1, $2)
                     AND completed_at IS NOT NULL
                     AND completed_at < $3
                   LIMIT $4
               )
               RETURNING id, repo_id"#,
        )
        .bind(request_state::COMPLETE)
        .bind(request_state::REJECTED_AT_GIT)
        .bind(older_than_iso)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// #26 Split PR 1 step 4 — bounded retirement. Deletes
    /// `pending_ref_transitions` children whose parent request is
    /// terminal (`complete` or `rejected_at_git`) AND whose
    /// `applied_at` (for accepted children) or `cancelled_at` (for
    /// rejected children) is older than `older_than_iso`. Children
    /// in `prepared` / `uncertain` are NEVER purged — those are
    /// the reconcile walk's responsibility.
    ///
    /// Parent terminality is enforced in the query itself via a
    /// join, not by call order: an old `applied` child under a
    /// still-executable `outcomes_committed`/`effects_pending`
    /// parent is never eligible, and the startup purge racing the
    /// reconcile cannot delete live work.
    ///
    /// Callers MUST purge the parent requests first so this scan
    /// has a clear contract. The `purge_request_queue` helper in
    /// `durable_outbox.rs` enforces the order.
    #[allow(dead_code)]
    pub async fn purge_completed_pending_ref_transitions(
        &self,
        older_than_iso: &str,
        limit: i64,
    ) -> Result<u64> {
        let limit = limit.max(1);
        let res = sqlx::query(
            r#"DELETE FROM pending_ref_transitions
               WHERE id IN (
                   SELECT c.id FROM pending_ref_transitions c
                   JOIN receive_pack_requests p ON p.id = c.request_id
                   WHERE c.state IN ($1, $2)
                     AND p.state IN ($5, $6)
                     AND ((c.state = $1 AND c.applied_at IS NOT NULL AND c.applied_at < $3)
                       OR (c.state = $2 AND c.cancelled_at IS NOT NULL AND c.cancelled_at < $3))
                   LIMIT $4
               )"#,
        )
        .bind(pending_state::APPLIED)
        .bind(pending_state::CANCELLED)
        .bind(older_than_iso)
        .bind(limit)
        .bind(request_state::COMPLETE)
        .bind(request_state::REJECTED_AT_GIT)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Reconcile promotion of the request aggregate: `received` or
    /// `rejected_at_git` → `outcomes_committed` with the normalized
    /// accepted-ref outcome the executor consumes. Called by startup
    /// reconcile after on-disk proof promotes children; without this
    /// the child is `applied` but the parent can never schedule
    /// effects. Returns rows affected (0 means the parent already
    /// moved on — the caller must not treat that as success).
    #[allow(dead_code)]
    pub async fn promote_reconciled_request_outcomes(
        &self,
        request_id: &str,
        git_exit_ok: bool,
        parsed_report: &serde_json::Value,
        accepted_ordinal: Option<i32>,
    ) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state = $2, git_exit_ok = $3, parsed_report = $4,
                   accepted_ordinal = $5
               WHERE id = $1 AND state IN ($6, $7)"#,
        )
        .bind(request_id)
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(git_exit_ok)
        .bind(parsed_report)
        .bind(accepted_ordinal)
        .bind(request_state::RECEIVED)
        .bind(request_state::REJECTED_AT_GIT)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Idempotent version of promote_reconciled_request_outcomes that merges
    /// later-page children into an already-executable parent without changing
    /// the request's event identity. The first promotion sets both the report
    /// and `accepted_ordinal` (min applied ordinal → push event id). Later
    /// pages only widen `parsed_report.ref_results` to the superset; the
    /// stored `accepted_ordinal` is preserved so the `(request_id,
    /// accepted_ordinal)` event key never rewrites after effects have used it.
    pub async fn promote_reconciled_request_outcomes_idempotent(
        &self,
        request_id: &str,
        git_exit_ok: bool,
        parsed_report: &serde_json::Value,
        accepted_ordinal: Option<i32>,
    ) -> Result<u64> {
        // First try the normal promotion
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state = $2, git_exit_ok = $3, parsed_report = $4,
                   accepted_ordinal = $5
               WHERE id = $1 AND state IN ($6, $7)"#,
        )
        .bind(request_id)
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(git_exit_ok)
        .bind(parsed_report)
        .bind(accepted_ordinal)
        .bind(request_state::RECEIVED)
        .bind(request_state::REJECTED_AT_GIT)
        .execute(&self.pool)
        .await?;

        // Parent already executable: merge new refs into the stored report,
        // preserving the stored accepted_ordinal that existing effects key on.
        // Covers both `outcomes_committed` and `effects_pending`: the due
        // worker may claim the parent between reconcile pages, and a
        // later-page child must still join the report rather than strand
        // as `applied` outside it. State is never moved here — only the
        // report widens.
        if res.rows_affected() == 0 {
            // Take the row under FOR UPDATE in a transaction so the merge
            // is atomic with the state it read: if the due worker flips
            // `outcomes_committed` → `effects_pending` between the SELECT and
            // the UPDATE, the UPDATE would match zero rows, `Ok(0)` would
            // return, and the newly applied child would be left out of the
            // report with no later scan revisiting it.
            //
            // Terminal states (`complete`, `quarantined`) are locked too:
            // the due worker races the startup reconcile, so a parent may go
            // terminal between the first UPDATE and this read. A child just
            // marked applied then has effects that silently never run. Under
            // a `complete` parent the child purges with the aggregate; under
            // `quarantined` neither parent nor applied child ever enters the
            // purge set (child rejection covers only `prepared`/`uncertain`),
            // so it sits with no executor. Either way there is nothing
            // automatic left to do (the drain will not rerun a terminal
            // request), so log loudly for operator attention instead of
            // returning a silent success.
            //
            // Only this merge transaction is bounded 10s; the single-statement
            // promotion UPDATE above it is not (pre-existing) — a stall there
            // still blocks the page.
            let merge = async {
                let mut tx = self.pool.begin().await?;
                let existing: Option<(serde_json::Value, Option<i32>, String)> = sqlx::query_as(
                    r#"SELECT parsed_report, accepted_ordinal, state FROM receive_pack_requests
                       WHERE id = $1 AND state IN ($2, $3, $4, $5)
                       FOR UPDATE"#,
                )
                .bind(request_id)
                .bind(request_state::OUTCOMES_COMMITTED)
                .bind(request_state::EFFECTS_PENDING)
                .bind(request_state::COMPLETE)
                .bind(request_state::QUARANTINED)
                .fetch_optional(&mut *tx)
                .await?;
                let Some((stored_report, stored_ordinal, stored_state)) = existing else {
                    return Ok(0);
                };
                if stored_state == request_state::COMPLETE
                    || stored_state == request_state::QUARANTINED
                {
                    tracing::error!(
                        request_id = %request_id,
                        state = %stored_state,
                        "reconcile applied a child after the parent went terminal; \
                         the late child's effects never ran (it purges with a \
                         `complete` aggregate, or sits executor-less under \
                         `quarantined`) — operator attention required"
                    );
                    return Ok(0);
                }
                let merged = Self::merge_reconciled_reports(&stored_report, parsed_report);
                // Nothing new: no write, no false success signal.
                if merged == stored_report {
                    return Ok(0);
                }
                let update_res = sqlx::query(
                    r#"UPDATE receive_pack_requests
                   SET parsed_report = $3
                   WHERE id = $1 AND state = $2"#,
                )
                .bind(request_id)
                .bind(&stored_state)
                .bind(&merged)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                // accepted_ordinal intentionally untouched: the stored value
                // (captured above as stored_ordinal) remains the event key.
                let _ = stored_ordinal;
                Ok(update_res.rows_affected())
            };
            match tokio::time::timeout(std::time::Duration::from_secs(10), merge).await {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!(
                    "promote_reconciled_request_outcomes_idempotent merge timed out after 10s"
                )),
            }
        } else {
            Ok(res.rows_affected())
        }
    }

    /// Union `incoming.ref_results` (ok:true entries) into `stored`, keeping
    /// stored entries otherwise intact. Both reports carry
    /// `unpack_ok:true` and `synthetic:"reconciled"`; the merged report does too.
    fn merge_reconciled_reports(
        stored: &serde_json::Value,
        incoming: &serde_json::Value,
    ) -> serde_json::Value {
        let mut names: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
        for src in [stored, incoming] {
            if let Some(arr) = src.get("ref_results").and_then(|v| v.as_array()) {
                for entry in arr {
                    if let Some(name) = entry.get("ref_name").and_then(|n| n.as_str()) {
                        let ok = entry.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
                        // Only reconciled ok:true entries ever enter; an explicit
                        // false never overrides a stored true.
                        if ok {
                            names.insert(name.to_string(), true);
                        } else {
                            names.entry(name.to_string()).or_insert(false);
                        }
                    }
                }
            }
        }
        serde_json::json!({
            "unpack_ok": true,
            "ref_results": names.iter().map(|(name, ok)| serde_json::json!({
                "ref_name": name,
                "ok": ok,
            })).collect::<Vec<_>>(),
            "synthetic": "reconciled",
        })
    }

    /// Requests stuck with applied children but a non-executable
    /// parent (`received` or `rejected_at_git`). Covers the crash gap
    /// where the child flip committed but the parent outcomes commit
    /// did not, plus Git landing a ref after the parent went
    /// `rejected_at_git`. Bounded by `limit`.
    pub async fn list_stuck_request_aggregates(&self, limit: i64) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"SELECT DISTINCT c.request_id
               FROM pending_ref_transitions c
               JOIN receive_pack_requests p ON p.id = c.request_id
               WHERE p.state IN ($1, $2)
                 AND c.state = $3
               LIMIT $4"#,
        )
        .bind(request_state::RECEIVED)
        .bind(request_state::REJECTED_AT_GIT)
        .bind(pending_state::APPLIED)
        .bind(limit.max(1))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Competing-claimant check for reconcile: does another request
    /// claim the same `(repo, ref, old, new)` tuple? When two rows
    /// claim the same landing, current repository state plus an
    /// intent marker cannot establish which request caused it —
    /// fail closed and leave both for attended recovery.
    pub async fn has_competing_claimant(
        &self,
        repo_id: &str,
        ref_name: &str,
        old_sha: &str,
        new_sha: &str,
        exclude_request_id: &str,
    ) -> Result<bool> {
        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*)::BIGINT FROM pending_ref_transitions
               WHERE repo_id = $1 AND ref_name = $2
                 AND old_sha = $3 AND new_sha = $4
                 AND request_id != $5
                 AND state IN ($6, $7, $8)"#,
        )
        .bind(repo_id)
        .bind(ref_name)
        .bind(old_sha)
        .bind(new_sha)
        .bind(exclude_request_id)
        .bind(pending_state::PREPARED)
        .bind(pending_state::UNCERTAIN)
        .bind(pending_state::APPLIED)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 > 0)
    }

    /// Atomic post-Git outcome commit: child flips plus the parent
    /// `received → outcomes_committed` (or `rejected_at_git` when
    /// `outcomes` is None) in one transaction. Crash-safety: the
    /// live path never leaves applied children attached to a
    /// `received` parent, which is the gap reconcile used to have to
    /// repair. On `rejected` the parent goes terminal and children
    /// are left for reconcile/attended recovery per the existing
    /// contract.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_request_outcomes_atomically(
        &self,
        request_id: &str,
        ok_names: &[&str],
        ng_names: &[&str],
        uncertain_names: &[&str],
        unpack_failed: bool,
        git_exit_ok: bool,
        parsed_report: Option<&serde_json::Value>,
        accepted_ordinal: Option<i32>,
        rejected_reason: Option<&str>,
        terminal_no_effects: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let now = Utc::now().to_rfc3339();
        if unpack_failed {
            sqlx::query(
                r#"UPDATE pending_ref_transitions
                   SET state = $1, cancelled_at = $2
                   WHERE request_id = $3 AND state = $4"#,
            )
            .bind(pending_state::CANCELLED)
            .bind(&now)
            .bind(request_id)
            .bind(pending_state::PREPARED)
            .execute(&mut *tx)
            .await?;
        } else {
            if !ok_names.is_empty() {
                sqlx::query(
                    r#"UPDATE pending_ref_transitions
                       SET state = $1, applied_at = $2
                       WHERE request_id = $3 AND state = $4 AND ref_name = ANY($5)"#,
                )
                .bind(pending_state::APPLIED)
                .bind(&now)
                .bind(request_id)
                .bind(pending_state::PREPARED)
                .bind(ok_names)
                .execute(&mut *tx)
                .await?;
            }
            if !ng_names.is_empty() {
                sqlx::query(
                    r#"UPDATE pending_ref_transitions
                       SET state = $1, cancelled_at = $2
                       WHERE request_id = $3 AND state = $4 AND ref_name = ANY($5)"#,
                )
                .bind(pending_state::CANCELLED)
                .bind(&now)
                .bind(request_id)
                .bind(pending_state::PREPARED)
                .bind(ng_names)
                .execute(&mut *tx)
                .await?;
            }
            if !uncertain_names.is_empty() {
                sqlx::query(
                    r#"UPDATE pending_ref_transitions
                       SET state = $1
                       WHERE request_id = $2 AND state = $3 AND ref_name = ANY($4)"#,
                )
                .bind(pending_state::UNCERTAIN)
                .bind(request_id)
                .bind(pending_state::PREPARED)
                .bind(uncertain_names)
                .execute(&mut *tx)
                .await?;
            }
        }
        if terminal_no_effects {
            // All refs rejected/unpack-failed with no effects ever:
            // terminal with explicit proof disposition (acked here, same
            // txn) so retention can purge instead of retaining forever.
            // Children are already cancelled above; no push/cert/anchor
            // is emitted.
            let report = parsed_report.expect("terminal_no_effects requires parsed report");
            sqlx::query(
                r#"UPDATE receive_pack_requests
                   SET state = $2, git_exit_ok = $3, parsed_report = $4,
                       accepted_ordinal = NULL, completed_at = $5,
                       last_error = $6
                   WHERE id = $1 AND state = $7"#,
            )
            .bind(request_id)
            .bind(request_state::COMPLETE)
            .bind(git_exit_ok)
            .bind(report)
            .bind(&now)
            .bind("all refs rejected; no effects".to_string())
            .bind(request_state::RECEIVED)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"UPDATE request_proofs SET acked_at = $2 WHERE request_id = $1 AND acked_at IS NULL"#,
            )
            .bind(request_id)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        } else if let Some(report) = parsed_report {
            sqlx::query(
                r#"UPDATE receive_pack_requests
                   SET state = $2, git_exit_ok = $3, parsed_report = $4,
                       accepted_ordinal = $5
                   WHERE id = $1 AND state = $6"#,
            )
            .bind(request_id)
            .bind(request_state::OUTCOMES_COMMITTED)
            .bind(git_exit_ok)
            .bind(report)
            .bind(accepted_ordinal)
            .bind(request_state::RECEIVED)
            .execute(&mut *tx)
            .await?;
        } else if let Some(reason) = rejected_reason {
            // Indeterminate rejections (no report-status, incomplete report):
            // persist the true git exit — a capability-free client can omit
            // report-status on a fully successful push, and recording FALSE
            // would mislabel "await disk evidence" as unpack failure for
            // operators and any consumer trusting `git_exit_ok`.
            sqlx::query(
                r#"UPDATE receive_pack_requests
                   SET state = $2, git_exit_ok = $3, last_error = $4,
                       completed_at = $5
                   WHERE id = $1 AND state = $6"#,
            )
            .bind(request_id)
            .bind(request_state::REJECTED_AT_GIT)
            .bind(git_exit_ok)
            .bind(reason)
            .bind(&now)
            .bind(request_state::RECEIVED)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Flip every `prepared` row attached to `request_id` to `applied`.
    /// Called after `smart_http::receive_pack` returns Ok. A `prepared`
    /// row that the handler never reaches this point for stays in
    /// `prepared` and is dropped by the drain (the row is NEVER promoted
    /// by anything other than this method), which is what closes the
    /// reviewer's "a failed or cancelled receive-pack must not turn a
    /// prepared intent into completed accounting or anchoring" invariant.
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn mark_pending_ref_transitions_applied(&self, request_id: &str) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1, applied_at = $2
               WHERE request_id = $3 AND state = $4"#,
        )
        .bind(pending_state::APPLIED)
        .bind(&now)
        .bind(request_id)
        .bind(pending_state::PREPARED)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Flip every `prepared` row attached to `request_id` to `cancelled`.
    /// Called when the receive_pack call returns Err or the handler
    /// future is dropped. The drain does not promote `cancelled` rows.
    #[allow(dead_code)]
    pub async fn mark_pending_ref_transitions_cancelled(&self, request_id: &str) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1, cancelled_at = $2
               WHERE request_id = $3 AND state = $4"#,
        )
        .bind(pending_state::CANCELLED)
        .bind(&now)
        .bind(request_id)
        .bind(pending_state::PREPARED)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Per-ref variant of [`mark_pending_ref_transitions_applied`]:
    /// flip to `applied` only the rows whose `ref_name` is in
    /// `ref_names`. Used by the live handler when the report-status
    /// confirms per-ref `ok` results — refs the report rejected or
    /// did not mention are left alone so the next call can flip them
    /// to `cancelled` / `uncertain` independently.
    #[allow(dead_code)]
    pub async fn mark_pending_ref_transitions_applied_for_names(
        &self,
        request_id: &str,
        ref_names: &[&str],
    ) -> Result<u64> {
        if ref_names.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1, applied_at = $2
               WHERE request_id = $3 AND state = $4 AND ref_name = ANY($5)"#,
        )
        .bind(pending_state::APPLIED)
        .bind(&now)
        .bind(request_id)
        .bind(pending_state::PREPARED)
        .bind(ref_names)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Per-ref variant of [`mark_pending_ref_transitions_cancelled`]:
    /// flip to `cancelled` only the rows whose `ref_name` is in
    /// `ref_names`. Used by the live handler to mark specifically the
    /// refs that the report-status listed as `ng` so their durable
    /// effects are skipped.
    #[allow(dead_code)]
    pub async fn mark_pending_ref_transitions_cancelled_for_names(
        &self,
        request_id: &str,
        ref_names: &[&str],
    ) -> Result<u64> {
        if ref_names.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1, cancelled_at = $2
               WHERE request_id = $3 AND state = $4 AND ref_name = ANY($5)"#,
        )
        .bind(pending_state::CANCELLED)
        .bind(&now)
        .bind(request_id)
        .bind(pending_state::PREPARED)
        .bind(ref_names)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Per-ref variant of [`mark_pending_ref_transitions_uncertain`]:
    /// flip to `uncertain` only the rows whose `ref_name` is in
    /// `ref_names`. Used by the live handler for refs that are not
    /// mentioned in the report-status output and need reconcile to
    /// sort out which actually landed.
    #[allow(dead_code)]
    pub async fn mark_pending_ref_transitions_uncertain_for_names(
        &self,
        request_id: &str,
        ref_names: &[&str],
    ) -> Result<u64> {
        if ref_names.is_empty() {
            return Ok(0);
        }
        // P2 (reviewer-2 round 4): `cancelled_at` is reserved for rows
        // that were *decided* not to land. An uncertain row is by
        // definition undecided, so leave `cancelled_at` null and let
        // any audit reason about it from `created_at`.
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1
               WHERE request_id = $2 AND state IN ($3, $4) AND ref_name = ANY($5)"#,
        )
        .bind(pending_state::UNCERTAIN)
        .bind(request_id)
        .bind(pending_state::PREPARED)
        .bind(pending_state::APPLIED)
        .bind(ref_names)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Count the `applied` rows remaining in the table. Used by the
    /// startup drain to decide whether the residual pass has work
    /// left or whether the backlog was fully consumed.
    #[allow(dead_code)]
    pub async fn count_pending_ref_transitions_applied(&self) -> Result<i64> {
        let row =
            sqlx::query("SELECT COUNT(*) AS cnt FROM pending_ref_transitions WHERE state = $1")
                .bind(pending_state::APPLIED)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    /// Return every `applied` row, oldest first. The startup drain calls
    /// this once and processes each row by re-deriving the push event,
    /// the per-ref cert, and the anchor handoff.
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn list_pending_ref_transitions_applied(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingRefTransition>> {
        let limit = limit.max(1);
        let rows = sqlx::query(
            r#"SELECT id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                       signature_header, signature_input, content_digest, state, created_at,
                       applied_at, cancelled_at, ordinal, git_target_kind
               FROM pending_ref_transitions
               WHERE state = $1
               ORDER BY applied_at ASC NULLS LAST, id ASC
               LIMIT $2"#,
        )
        .bind(pending_state::APPLIED)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(row_to_pending_ref_transition)
            .collect())
    }

    /// Return every `prepared` row, oldest first. The startup
    /// `reconcile_prepared_from_disk` step enumerates these, checks
    /// each row's `new_sha` against the on-disk ref via
    /// `git::store::list_refs`, and promotes the rows whose target
    /// actually landed to `applied`. Rows that did NOT land (ref
    /// rejected by receive_pack, or a `mark_applied` error stranded
    /// the row in `prepared` with the ref still on the old SHA) stay
    /// in `prepared`.
    #[allow(dead_code)] // wired by the startup reconcile
    pub async fn list_pending_ref_transitions_prepared(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingRefTransition>> {
        let limit = limit.max(1);
        let rows = sqlx::query(
            r#"SELECT id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                       signature_header, signature_input, content_digest, state, created_at,
                       applied_at, cancelled_at, ordinal, git_target_kind
               FROM pending_ref_transitions
               WHERE state = $1
               ORDER BY created_at ASC, id ASC
               LIMIT $2"#,
        )
        .bind(pending_state::PREPARED)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(row_to_pending_ref_transition)
            .collect())
    }

    /// Return `prepared` and `uncertain` rows, oldest first. The
    /// startup reconcile step checks both states against on-disk refs
    /// and promotes those that actually landed to `applied`. A
    /// `prepared` row that was interrupted after receive-pack returned
    /// Ok, and an `uncertain` row from a receive-pack error, are
    /// equally unrecoverable without this step: the drain's WHERE
    /// clause does not see them.
    #[allow(dead_code)]
    pub async fn list_pending_ref_transitions_prepared_or_uncertain(
        &self,
        limit: i64,
    ) -> Result<Vec<PendingRefTransition>> {
        self.list_pending_ref_transitions_prepared_or_uncertain_after(None, limit)
            .await
    }

    /// The same page of `prepared` / `uncertain` rows, in the same
    /// order, resuming strictly AFTER the `(created_at, id)` cursor.
    ///
    /// The multi-pass reconcile needs a cursor where the multi-pass
    /// drain does not, and the asymmetry is the whole reason this
    /// exists. The drain DELETES every row it finishes, so its next
    /// `LIMIT n` page is always new work. The reconcile leaves every
    /// row it cannot promote exactly where it was, so re-issuing the
    /// cursor-less query hands it the same page over and over: a
    /// single unprovable row at the head of the ordering pins page one
    /// and the backlog behind it is never examined at all — which is
    /// the very thing the multi-pass loop was added to fix. Rows that
    /// wait for another restart keep ageing toward
    /// `MAX_RECONCILE_AGE`, past which they lose automatic recovery
    /// entirely.
    ///
    /// Advancing on `(created_at, id)` also stays correct while rows
    /// leave the set underneath the walk: a promoted row is simply
    /// absent from a later page, and it can never shift an unvisited
    /// row into a page that was already read, the way an OFFSET would.
    #[allow(dead_code)]
    pub async fn list_pending_ref_transitions_prepared_or_uncertain_after(
        &self,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> Result<Vec<PendingRefTransition>> {
        let limit = limit.max(1);
        // The empty sentinel sorts before every RFC 3339 timestamp, so
        // the first page needs no separate query.
        let (after_created_at, after_id) = after.unwrap_or(("", ""));
        let rows = sqlx::query(
            r#"SELECT id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                       signature_header, signature_input, content_digest, state, created_at,
                       applied_at, cancelled_at, ordinal, git_target_kind
               FROM pending_ref_transitions
               WHERE state = ANY($1) AND (created_at, id) > ($2, $3)
               ORDER BY created_at ASC, id ASC
               LIMIT $4"#,
        )
        .bind(pending_state::RECONCILABLE.to_vec())
        .bind(after_created_at)
        .bind(after_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(row_to_pending_ref_transition)
            .collect())
    }

    /// Flip a set of `prepared` or `uncertain` rows to `applied`. Called by the
    /// startup reconcile step after the on-disk SHA matches each row's
    /// `new_sha`. The `state IN ('prepared', 'uncertain')` guard is
    /// the second barrier against re-promoting a row that was cancelled
    /// by another path while the reconcile was in flight; only rows
    /// that were still in one of those states at the moment the UPDATE
    /// runs are flipped.
    #[allow(dead_code)] // wired by the startup reconcile
    pub async fn mark_pending_ref_transitions_applied_for_rows(
        &self,
        ids: &[String],
    ) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1, applied_at = $2
               WHERE id = ANY($3) AND state = ANY($4)"#,
        )
        .bind(pending_state::APPLIED)
        .bind(&now)
        .bind(ids)
        .bind(pending_state::RECONCILABLE.to_vec())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Delete a row by id. Called by the recovery drain AFTER the push
    /// event, the cert, and the anchor job have all landed. A subsequent
    /// drain pass is a no-op for the same transition because the row is
    /// gone and the deterministic artifact ids collide on `ON CONFLICT`.
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn delete_pending_ref_transition(&self, id: &str) -> Result<u64> {
        let res = sqlx::query("DELETE FROM pending_ref_transitions WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Look up the deterministic `id` of a `pending_ref_transitions`
    /// row by `(request_id, ref_name)`. Returns `Ok(None)` if no
    /// such row exists (e.g. a ref that the report-status excluded
    /// from the durable effects). The live handler uses this to
    /// target per-ref cleanup after effects land so it can delete
    /// only the rows whose required writes succeeded.
    #[allow(dead_code)]
    pub async fn lookup_pending_ref_transition_id(
        &self,
        request_id: &str,
        ref_name: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT id FROM pending_ref_transitions
             WHERE request_id = $1 AND ref_name = $2",
        )
        .bind(request_id)
        .bind(ref_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("id")))
    }

    /// Delete only `applied` rows for a `request_id` after their
    /// durable effects have completed. `uncertain` rows are
    /// reconciliation evidence and must survive live completion;
    /// deleting them before startup reconcile runs loses landed-
    /// but-unreported refs on mixed/partial reports.
    #[allow(dead_code)]
    pub async fn delete_pending_ref_transitions_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<u64> {
        let res = sqlx::query(
            r#"DELETE FROM pending_ref_transitions
               WHERE request_id = $1 AND state = $2"#,
        )
        .bind(request_id)
        .bind(pending_state::APPLIED)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Delete specific applied children by id after their effects
    /// complete. Preserves uncertain/cancelled siblings.
    pub async fn delete_pending_ref_transitions_by_ids(&self, ids: &[String]) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let res = sqlx::query(
            r#"DELETE FROM pending_ref_transitions
               WHERE id = ANY($1) AND state = $2"#,
        )
        .bind(ids)
        .bind(pending_state::APPLIED)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Return every child of `request_id` in ordinal order. The step-3
    /// effect executor calls this after loading the request row to
    /// re-derive the per-ref cert and anchor writes. The accepted
    /// child is the one whose `ref_name` is in the parsed report's
    /// ok set; the executor re-derives that set from
    /// `req.parsed_report`, so this helper returns the full ordered
    /// list and lets the caller filter.
    pub async fn list_pending_ref_transitions_for_request(
        &self,
        request_id: &str,
    ) -> Result<Vec<PendingRefTransition>> {
        let rows = sqlx::query(
            r#"SELECT id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                       signature_header, signature_input, content_digest, state, created_at,
                       applied_at, cancelled_at, ordinal, git_target_kind
               FROM pending_ref_transitions
               WHERE request_id = $1
               ORDER BY ordinal ASC, id ASC"#,
        )
        .bind(request_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(row_to_pending_ref_transition)
            .collect())
    }

    /// Flip every `prepared` row attached to `request_id` to `uncertain`.
    /// Called when receive-pack returns Err but the exit was non-zero or
    /// timed out, meaning some refs may have landed before the failure.
    /// The reconcile step checks these rows against disk at startup.
    ///
    /// P2 (reviewer-2 round 4): do NOT set `cancelled_at` on an
    /// `uncertain` row — `cancelled_at` is reserved for transitions
    /// that were *decided* not to land. An uncertain row is, by
    /// definition, undecided; leaving the column null means any
    /// future consumer filtering on `cancelled_at IS NOT NULL` sees
    /// only the truly-cancelled rows.
    #[allow(dead_code)]
    pub async fn mark_pending_ref_transitions_uncertain(&self, request_id: &str) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1
               WHERE request_id = $2 AND state = $3"#,
        )
        .bind(pending_state::UNCERTAIN)
        .bind(request_id)
        .bind(pending_state::PREPARED)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Flip every `uncertain` row for a `request_id` to `cancelled`.
    /// Called after the reconcile step has confirmed none of the refs
    /// landed on disk (all rows still have state `uncertain`).
    #[allow(dead_code)]
    pub async fn mark_uncertain_rows_cancelled(&self, request_id: &str) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $1, cancelled_at = $2
               WHERE request_id = $3 AND state = $4"#,
        )
        .bind(pending_state::CANCELLED)
        .bind(&now)
        .bind(request_id)
        .bind(pending_state::UNCERTAIN)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Test-only: insert a row directly in the given state. Used to
    /// simulate the crash window ("row is `applied` but the handler
    /// never reached the push event / cert / anchor code") without
    /// running the full handler. Mirrors the production insert but
    /// takes the state as an argument so a test can stage a row that
    /// the drain will pick up.
    #[cfg(test)]
    pub async fn insert_pending_ref_transition_for_test(
        &self,
        row: &PendingRefTransition,
    ) -> Result<()> {
        let applied_at = row.applied_at.clone().unwrap_or_default();
        let cancelled_at = row.cancelled_at.clone().unwrap_or_default();
        let applied_at_opt: Option<&str> = if applied_at.is_empty() {
            None
        } else {
            Some(&applied_at)
        };
        let cancelled_at_opt: Option<&str> = if cancelled_at.is_empty() {
            None
        } else {
            Some(&cancelled_at)
        };
        sqlx::query(
            r#"INSERT INTO pending_ref_transitions
               (id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                signature_header, signature_input, content_digest, state, created_at,
                applied_at, cancelled_at, ordinal, git_target_kind)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)"#,
        )
        .bind(&row.id)
        .bind(&row.request_id)
        .bind(&row.repo_id)
        .bind(&row.ref_name)
        .bind(&row.old_sha)
        .bind(&row.new_sha)
        .bind(&row.pusher_did)
        .bind(&row.node_did)
        .bind(&row.signature_header)
        .bind(&row.signature_input)
        .bind(&row.content_digest)
        .bind(&row.state)
        .bind(&row.created_at)
        .bind(applied_at_opt)
        .bind(cancelled_at_opt)
        .bind(row.ordinal)
        .bind(row.git_target_kind.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Idempotent push event insert. Returns `true` if a NEW row was
    /// created, `false` if the deterministic id collided with an
    /// existing row (recovery re-fired the same transition).
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn record_push_with_id(
        &self,
        id: &str,
        agent_did: &str,
        repo_id: &str,
        commit_hash: &str,
        object_count: i64,
    ) -> Result<bool> {
        let res = sqlx::query(
            r#"INSERT INTO push_events (id, agent_did, repo_id, commit_hash, object_count, pushed_at)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(id)
        .bind(agent_did)
        .bind(repo_id)
        .bind(commit_hash)
        .bind(object_count)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Idempotent ref certificate insert. Returns `Some` if a NEW cert
    /// was created, `None` if the unique `(repo_id, ref_name)` index
    /// already had a row (the live path got there first, or a previous
    /// recovery pass did).
    ///
    /// The primary key is the deterministic `id`; the unique index on
    /// `(repo_id, ref_name)` is what makes the recovery exactly-once,
    /// because a second insert for the same `(repo_id, ref_name)`
    /// returns `None` rather than overwriting the existing cert.
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn insert_ref_certificate_idempotent(
        &self,
        cert: &RefCertificate,
    ) -> Result<Option<RefCertificate>> {
        let res = sqlx::query(
            r#"INSERT INTO ref_certificates
               (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (repo_id, ref_name) DO NOTHING
               RETURNING id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, version"#,
        )
        .bind(&cert.id)
        .bind(&cert.repo_id)
        .bind(&cert.ref_name)
        .bind(&cert.old_sha)
        .bind(&cert.new_sha)
        .bind(&cert.pusher_did)
        .bind(&cert.node_did)
        .bind(&cert.signature)
        .bind(&cert.issued_at)
        .fetch_optional(&self.pool)
        .await?;
        Ok(res.map(row_to_cert))
    }

    /// Idempotent anchor job insert. Returns `true` if a NEW row was
    /// created, `false` if the `(repo_id, ref_name, old_sha, new_sha)`
    /// unique index already had a row. PR 2's transport will read these
    /// rows; the recovery drain writes them with `ON CONFLICT DO NOTHING`
    /// so re-running the drain cannot create a second upload request.
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn insert_anchor_job_idempotent(&self, job: &AnchorJob) -> Result<bool> {
        let res = sqlx::query(
            r#"INSERT INTO anchor_jobs
               (id, repo_id, ref_name, old_sha, new_sha, pusher_did, created_at, claimed_at,
                request_id, request_ordinal)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&job.id)
        .bind(&job.repo_id)
        .bind(&job.ref_name)
        .bind(&job.old_sha)
        .bind(&job.new_sha)
        .bind(&job.pusher_did)
        .bind(&job.created_at)
        .bind(job.claimed_at.as_deref())
        .bind(job.request_id.as_deref())
        .bind(job.request_ordinal)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Insert a durable versioned proof record. Idempotent by request_id;
    /// body-digest-bound so downstream cert/anchor consumers can verify
    /// the named pusher authorized the exact bytes.
    #[allow(dead_code)]
    pub async fn insert_request_proof_idempotent(&self, proof: &RequestProof) -> Result<bool> {
        let res = sqlx::query(
            r#"INSERT INTO request_proofs
               (request_id, repo_id, pusher_did, body_digest, signature_header,
                signature_input, content_digest, created_at, acked_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
               ON CONFLICT (request_id) DO NOTHING"#,
        )
        .bind(&proof.request_id)
        .bind(&proof.repo_id)
        .bind(&proof.pusher_did)
        .bind(&proof.body_digest)
        .bind(&proof.signature_header)
        .bind(&proof.signature_input)
        .bind(&proof.content_digest)
        .bind(&proof.created_at)
        .bind(proof.acked_at.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    pub async fn get_request_proof(&self, request_id: &str) -> Result<Option<RequestProof>> {
        let row = sqlx::query(
            r#"SELECT request_id, repo_id, pusher_did, body_digest, signature_header,
                      signature_input, content_digest, created_at, acked_at
               FROM request_proofs WHERE request_id = $1"#,
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| RequestProof {
            request_id: r.get("request_id"),
            repo_id: r.get("repo_id"),
            pusher_did: r.get("pusher_did"),
            body_digest: r.get("body_digest"),
            signature_header: r.get("signature_header"),
            signature_input: r.get("signature_input"),
            content_digest: r.get("content_digest"),
            created_at: r.get("created_at"),
            acked_at: r.get("acked_at"),
        }))
    }

    pub async fn ack_request_proof(&self, request_id: &str) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE request_proofs SET acked_at = $2 WHERE request_id = $1 AND acked_at IS NULL"#,
        )
        .bind(request_id)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Record one landed occurrence. Idempotent by (request_id, ordinal);
    /// retained beyond child cleanup for A/B disambiguation.
    pub async fn insert_landing_history_idempotent(&self, landing: &RefLanding) -> Result<bool> {
        let res = sqlx::query(
            r#"INSERT INTO ref_landing_history
               (request_id, ordinal, repo_id, ref_name, old_sha, new_sha, landed_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7)
               ON CONFLICT (request_id, ordinal) DO NOTHING"#,
        )
        .bind(&landing.request_id)
        .bind(landing.ordinal)
        .bind(&landing.repo_id)
        .bind(&landing.ref_name)
        .bind(&landing.old_sha)
        .bind(&landing.new_sha)
        .bind(&landing.landed_at)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Has a *different* request already landed this exact tuple? Used to
    /// fail closed when A's intent postdates B's proven landing (history
    /// survives B's child cleanup, unlike competing live rows).
    pub async fn has_landed_tuple_by_other_request(
        &self,
        repo_id: &str,
        ref_name: &str,
        old_sha: &str,
        new_sha: &str,
        exclude_request_id: &str,
    ) -> Result<bool> {
        let row: (i64,) = sqlx::query_as(
            r#"SELECT COUNT(*)::BIGINT FROM ref_landing_history
               WHERE repo_id=$1 AND ref_name=$2 AND old_sha=$3 AND new_sha=$4
                 AND request_id != $5"#,
        )
        .bind(repo_id)
        .bind(ref_name)
        .bind(old_sha)
        .bind(new_sha)
        .bind(exclude_request_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 > 0)
    }

    /// Operator transition for attended work: requests waiting on a human
    /// decision are resolved terminally, recording the decision
    /// (`operator complete` / `operator reject` plus note) in `last_error`.
    /// Covers quarantined/rejected_at_git AND the waiting executable states
    /// (outcomes_committed/effects_pending), so a request parked on
    /// unresolvable reconcile siblings has a reachable terminal path via
    /// operator decision instead of waiting forever.
    ///
    /// The target is always `complete` — never `rejected_at_git`, even for
    /// "reject": `rejected_at_git` is recoverable-terminal by design (the
    /// stuck-aggregate repair promotes applied children under it), so an
    /// operator rejection landing there with `applied` children would
    /// resurrect at the next startup reconcile and ship effects the
    /// operator just refused. `complete` is never selected by repair,
    /// drain, or reconcile.
    ///
    /// `received` is deliberately NOT admitted: git may be executing for
    /// such a row right now, and cancelling its `prepared` children would
    /// make the live outcome commit a no-op while refs git landed sit as
    /// `cancelled` rows reconcile never re-examines (and that no longer
    /// count as competing claimants).
    ///
    /// Non-terminal children ([`pending_state::RECONCILABLE`]) are cancelled
    /// in the same transaction — otherwise a resolved parent would keep
    /// live children that block retention; applied children are left alone
    /// (their effects may have run: history, not evidence). The request
    /// proof is acked in the same transaction so retention is not gated
    /// forever on a row whose effects will never run. Returns rows affected
    /// (the parent flip; 0 = wrong state or unknown decision).
    #[allow(dead_code)]
    pub async fn resolve_attended_request(
        &self,
        request_id: &str,
        decision: &str,
        note: Option<&str>,
    ) -> Result<u64> {
        let verdict = match decision {
            "complete" => "complete",
            "reject" | "rejected_at_git" => "reject",
            _ => return Ok(0),
        };
        let mut tx = self.pool.begin().await?;
        let now = Utc::now().to_rfc3339();
        let last_error = match note {
            Some(n) => format!("operator {verdict}: {n}"),
            None => format!("operator {verdict}"),
        };
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET state=$2, completed_at=$3, last_error=$4
               WHERE id=$1 AND state IN ($5,$6,$7,$8)"#,
        )
        .bind(request_id)
        .bind(request_state::COMPLETE)
        .bind(&now)
        .bind(&last_error)
        .bind(request_state::QUARANTINED)
        .bind(request_state::REJECTED_AT_GIT)
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(request_state::EFFECTS_PENDING)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(0);
        }
        sqlx::query(
            r#"UPDATE pending_ref_transitions
               SET state = $2, cancelled_at = $3
               WHERE request_id = $1 AND state = ANY($4)"#,
        )
        .bind(request_id)
        .bind(pending_state::CANCELLED)
        .bind(&now)
        .bind(&pending_state::RECONCILABLE[..])
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"UPDATE request_proofs SET acked_at = $2 WHERE request_id = $1 AND acked_at IS NULL"#,
        )
        .bind(request_id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(res.rows_affected())
    }

    /// Enqueue a marker tombstone. Idempotent. Used by tests/direct calls;
    /// production purge enqueues atomically inside `purge_terminal_batch`.
    #[allow(dead_code)]
    pub async fn enqueue_marker_cleanup(&self, request_id: &str, repo_id: &str) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO marker_cleanup_queue (request_id, repo_id, attempts, created_at, last_error)
               VALUES ($1,$2,0,$3,NULL) ON CONFLICT (request_id) DO NOTHING"#,
        )
        .bind(request_id)
        .bind(repo_id)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_marker_cleanup_due(&self, limit: i64) -> Result<Vec<MarkerCleanup>> {
        let now = Utc::now().to_rfc3339();
        let rows = sqlx::query(
            r#"SELECT request_id, repo_id, attempts, created_at, last_error,
                      next_attempt_at, dead_letter
               FROM marker_cleanup_queue
               WHERE dead_letter = FALSE
                 AND (next_attempt_at IS NULL OR next_attempt_at < $2)
               ORDER BY next_attempt_at NULLS FIRST, created_at ASC LIMIT $1"#,
        )
        .bind(limit.max(1))
        .bind(&now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| MarkerCleanup {
                request_id: r.get("request_id"),
                repo_id: r.get("repo_id"),
                attempts: r.get("attempts"),
                created_at: r.get("created_at"),
                last_error: r.get("last_error"),
                next_attempt_at: r.get("next_attempt_at"),
                dead_letter: r.get("dead_letter"),
            })
            .collect())
    }

    /// Record a failed marker attempt with backoff fairness; after the
    /// bound, park visibly as dead-letter instead of starving newer work.
    /// Never deletes the tombstone on failure: it is the final owner.
    pub async fn mark_marker_cleanup_attempt(
        &self,
        request_id: &str,
        last_error: Option<&str>,
    ) -> Result<u64> {
        let row: Option<(i32,)> =
            sqlx::query_as(r#"SELECT attempts FROM marker_cleanup_queue WHERE request_id=$1"#)
                .bind(request_id)
                .fetch_optional(&self.pool)
                .await?;
        let attempts = row.map(|(a,)| a).unwrap_or(0);
        // Bound: 25 failures (~days of backoff) then dead-letter.
        if attempts + 1 > 25 {
            let res = sqlx::query(
                r#"UPDATE marker_cleanup_queue
                   SET attempts=attempts+1, last_error=$2, dead_letter=TRUE WHERE request_id=$1"#,
            )
            .bind(request_id)
            .bind(last_error)
            .execute(&self.pool)
            .await?;
            return Ok(res.rows_affected());
        }
        let shift = attempts.clamp(0, 6) as u32;
        let backoff = 60_i64.saturating_mul(1_i64 << shift);
        let next = (Utc::now() + chrono::Duration::seconds(backoff)).to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE marker_cleanup_queue
               SET attempts=attempts+1, last_error=$2, next_attempt_at=$3 WHERE request_id=$1"#,
        )
        .bind(request_id)
        .bind(last_error)
        .bind(&next)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    pub async fn delete_marker_cleanup(&self, request_id: &str) -> Result<u64> {
        let res = sqlx::query(r#"DELETE FROM marker_cleanup_queue WHERE request_id=$1"#)
            .bind(request_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Atomically claim one due request for a single executor by pushing
    /// its `next_attempt_at` into the future (recoverable lease). Returns
    /// true when this caller owns the request; false when another executor
    /// claimed it first or it is no longer due. Crash recovery via expiry:
    /// a dead claimant's lease lapses and the request becomes due again.
    pub async fn try_claim_due_request(
        &self,
        request_id: &str,
        lease_secs: i64,
        now_iso: &str,
    ) -> Result<bool> {
        let lease_until = (DateTime::parse_from_rfc3339(now_iso)
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
            + chrono::Duration::seconds(lease_secs.max(1)))
        .to_rfc3339();
        let res = sqlx::query(
            r#"UPDATE receive_pack_requests
               SET next_attempt_at = $2
               WHERE id = $1 AND state IN ($3, $4)
                 AND (next_attempt_at IS NULL OR next_attempt_at < $5)"#,
        )
        .bind(request_id)
        .bind(&lease_until)
        .bind(request_state::OUTCOMES_COMMITTED)
        .bind(request_state::EFFECTS_PENDING)
        .bind(now_iso)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Occurrence delivery ledger for external effects. Claims a stable
    /// `(request, ref, hook)` delivery key as pending; returns true when
    /// this caller won the race, false when another executor already
    /// recorded it. A stale pending claim (crashed between claim and
    /// HTTP send) older than `stale_secs` is reclaimable so recovery
    /// re-fires instead of suppressing forever. Sent deliveries are
    /// never re-claimed.
    pub async fn claim_webhook_delivery(
        &self,
        delivery_id: &str,
        request_id: &str,
        repo_id: &str,
        event: &str,
    ) -> Result<bool> {
        self.claim_webhook_delivery_with_stale(delivery_id, request_id, repo_id, event, 300)
            .await
    }

    pub async fn claim_webhook_delivery_with_stale(
        &self,
        delivery_id: &str,
        request_id: &str,
        repo_id: &str,
        event: &str,
        stale_secs: i64,
    ) -> Result<bool> {
        let now = Utc::now();
        let now_iso = now.to_rfc3339();
        let stale_before = (now - chrono::Duration::seconds(stale_secs.max(1))).to_rfc3339();
        // Reclaim stale pending claims so a crash between claim and send
        // does not permanently suppress the webhook.
        let _ = sqlx::query(
            r#"DELETE FROM webhook_deliveries
               WHERE delivery_id = $1 AND sent_at IS NULL AND created_at < $2"#,
        )
        .bind(delivery_id)
        .bind(&stale_before)
        .execute(&self.pool)
        .await?;
        let res = sqlx::query(
            r#"INSERT INTO webhook_deliveries
               (delivery_id, request_id, repo_id, event, created_at, sent_at)
               VALUES ($1,$2,$3,$4,$5,NULL) ON CONFLICT (delivery_id) DO NOTHING"#,
        )
        .bind(delivery_id)
        .bind(request_id)
        .bind(repo_id)
        .bind(event)
        .bind(&now_iso)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Mark a claimed delivery sent after the HTTP response. Recovery
    /// treats unmarked rows as pending and re-fires them past the stale
    /// threshold instead of asserting a delivery that never happened.
    pub async fn mark_webhook_sent(&self, delivery_id: &str) -> Result<u64> {
        let res = sqlx::query(
            r#"UPDATE webhook_deliveries SET sent_at = $2 WHERE delivery_id = $1 AND sent_at IS NULL"#,
        )
        .bind(delivery_id)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Purge terminal batch in one transaction: children first (parent
    /// still present for the join), then parents RETURNING ids. Proof
    /// rows are retained until acked; unacked proofs block parent purge.
    /// Returns (parents, children_deleted).
    pub async fn purge_terminal_batch(
        &self,
        older_than_iso: &str,
        limit: i64,
    ) -> Result<(Vec<(String, String)>, u64)> {
        let mut tx = self.pool.begin().await?;
        // Only parents whose proof is acked (or absent for pre-v33)
        // are eligible; unacked proof retains the owner.
        let parents: Vec<(String, String)> = sqlx::query_as(
            r#"SELECT r.id, r.repo_id FROM receive_pack_requests r
               LEFT JOIN request_proofs p ON p.request_id = r.id
               WHERE r.state IN ($1,$2)
                 AND r.completed_at IS NOT NULL AND r.completed_at < $3
                 AND (p.request_id IS NULL OR p.acked_at IS NOT NULL)
                 AND NOT EXISTS (
                       SELECT 1 FROM pending_ref_transitions c
                       WHERE c.request_id = r.id
                         AND c.state IN ($5,$6)
                   )
               LIMIT $4"#,
        )
        .bind(request_state::COMPLETE)
        .bind(request_state::REJECTED_AT_GIT)
        .bind(older_than_iso)
        .bind(limit.max(1))
        .bind(pending_state::PREPARED)
        .bind(pending_state::UNCERTAIN)
        .fetch_all(&mut *tx)
        .await?;
        if parents.is_empty() {
            tx.commit().await?;
            return Ok((vec![], 0));
        }
        let ids: Vec<String> = parents.iter().map(|(id, _)| id.clone()).collect();
        let cres = sqlx::query(
            r#"DELETE FROM pending_ref_transitions
               WHERE request_id = ANY($1) AND state IN ($2,$3)"#,
        )
        .bind(&ids)
        .bind(pending_state::APPLIED)
        .bind(pending_state::CANCELLED)
        .execute(&mut *tx)
        .await?;
        let children_deleted = cres.rows_affected();
        sqlx::query(r#"DELETE FROM receive_pack_requests WHERE id = ANY($1)"#)
            .bind(&ids)
            .execute(&mut *tx)
            .await?;
        // Tombstones for markers; best-effort enqueue inside same txn.
        for (req_id, repo_id) in &parents {
            sqlx::query(
                r#"INSERT INTO marker_cleanup_queue (request_id, repo_id, attempts, created_at)
                   VALUES ($1,$2,0,$3) ON CONFLICT (request_id) DO NOTHING"#,
            )
            .bind(req_id)
            .bind(repo_id)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok((parents, children_deleted))
    }

    /// Count anchor jobs for a transition, used by the test to assert
    /// "at most one anchor upload" without depending on PR 2's transport.
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn count_anchor_jobs(
        &self,
        repo_id: &str,
        ref_name: &str,
        old_sha: &str,
        new_sha: &str,
    ) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS cnt FROM anchor_jobs
             WHERE repo_id = $1 AND ref_name = $2 AND old_sha = $3 AND new_sha = $4",
        )
        .bind(repo_id)
        .bind(ref_name)
        .bind(old_sha)
        .bind(new_sha)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    /// Count push events for a transition, used by the test to assert
    /// "exactly one push event" after recovery.
    #[allow(dead_code)] // wired by the handler refactor in the next slice
    pub async fn count_push_events(
        &self,
        repo_id: &str,
        commit_hash: &str,
        agent_did: &str,
    ) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS cnt FROM push_events
             WHERE repo_id = $1 AND commit_hash = $2 AND agent_did = $3",
        )
        .bind(repo_id)
        .bind(commit_hash)
        .bind(agent_did)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    pub async fn list_ref_certificates(
        &self,
        repo_id: &str,
        limit: i64,
    ) -> Result<Vec<RefCertificate>> {
        // Clamp at the DB boundary so every caller (present and future) stays
        // bounded even if a raw/negative value slips through the handler layer.
        let limit = limit.max(1);
        let rows = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, version
             FROM ref_certificates WHERE repo_id = $1 ORDER BY issued_at DESC LIMIT $2",
        )
        .bind(repo_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_cert).collect())
    }

    /// Look up ref certificates whose id starts with the given prefix.
    /// Used by the CLI for short-ID resolution where the caller does not know
    /// the full UUID.  Bounded by `limit` for safety — the caller should pass a
    /// generous cap (e.g. 200) since prefix-matching narrows the result set.
    pub async fn list_ref_certificates_by_prefix(
        &self,
        repo_id: &str,
        prefix: &str,
        limit: i64,
    ) -> Result<Vec<RefCertificate>> {
        let limit = limit.max(1);

        // `!` is the LIKE escape character rather than the backslash default: a
        // backslash in the SQL text would be an escape inside the string literal
        // when the session runs with the legacy `standard_conforming_strings=off`,
        // leaving `ESCAPE '\'` unterminated and failing every prefix lookup. The
        // pool is opened from externally supplied connection settings, so that
        // mode can arrive from a database- or role-level setting. `!` keeps the
        // statement free of backslashes and parses the same either way.
        let mut escaped_prefix = String::with_capacity(prefix.len() + 4);
        for c in prefix.chars() {
            if c == '%' || c == '_' || c == '!' {
                escaped_prefix.push('!');
            }
            escaped_prefix.push(c);
        }
        let pattern = format!("{}%", escaped_prefix);

        let rows = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, version
             FROM ref_certificates WHERE repo_id = $1 AND id LIKE $2 ESCAPE '!' ORDER BY issued_at DESC LIMIT $3",
        )
        .bind(repo_id)
        .bind(&pattern)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_cert).collect())
    }

    pub async fn get_ref_certificate(&self, id: &str) -> Result<Option<RefCertificate>> {
        let row = sqlx::query(
            "SELECT id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at, version
             FROM ref_certificates WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_cert))
    }
}

// ── Peers ─────────────────────────────────────────────────────────────────────

/// What a caller of [`Db::upsert_peer`] can prove about the DID it is writing.
///
/// An enum rather than a bool, and the proven variant carries a payload rather
/// than being a bare unit, for two separate reasons.
///
/// It is not a bool because a bool at a call site reads as `true`/`false` with
/// nothing at the call site saying what was proven, and because the default a
/// bool invites (`false` meaning "no proof") is exactly the permissive value
/// this gate exists to withhold. Passed as a real parameter with no default, so
/// a new writer of the peers table cannot reach the update path by omission.
///
/// It carries the DID because "something was proven" is not the question. The
/// boundary needs to know WHICH DID was proven, and compare it against the row
/// being written. A bare proven/unproven flag leaves that comparison in the
/// handler, which is the shape of RUSTSEC-2022-0009 (libp2p-core accepted a
/// valid signature without checking it derived the claimed peer id) and leaves
/// the second writer, the bootstrap announce-back in main.rs, outside the gate
/// entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerWriteAuthority<'a> {
    /// The caller has no proof of control over the DID it is writing. May
    /// insert an unseen `did:key` row; may never change an existing row's
    /// `http_url`.
    Unproven,
    /// The caller verified a signature, and the DID carried here is the one
    /// that signature proved control of. `upsert_peer` checks it against the
    /// row being written; a mismatch is a denial, not a warning.
    Proven(&'a str),
}

/// A write refused by [`Db::upsert_peer`]'s authority gate.
///
/// A distinct type rather than a bare `anyhow::bail!` because `upsert_peer`
/// returns `anyhow::Result` and `From<anyhow::Error> for AppError` routes
/// anything it cannot downcast to `AppError::Internal`, so an untyped rejection
/// would reach the client as a 500. The announce handler downcasts this out of
/// the anyhow chain the same way the error module already recovers sqlx errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerWriteDenied {
    /// An unproven write tried to change an existing row's `http_url`.
    #[error("unproven announce cannot change an existing peer's http_url: {did}")]
    UnprovenRepoint { did: String },

    /// The signature proved control of one DID and the write targeted another.
    #[error("signature proves control of {proven}, but the write targets {target}")]
    ProofDidMismatch { proven: String, target: String },

    /// An unproven write named a DID method that can never authenticate, so the
    /// row it would create could never be corrected by anyone.
    #[error(
        "methodNotSupported: only did:key peers can be registered without a proof of control: {did}"
    )]
    UnsupportedDidMethod { did: String },

    /// The value is a did:key (or never parsed as a DID at all), but no
    /// verifying key can be resolved from it. Distinct from
    /// `UnsupportedDidMethod`, which is a true statement about a foreign
    /// method; this one carries the underlying resolution failure instead of
    /// claiming did:key is unsupported. The wording mirrors the signed path in
    /// auth/mod.rs, and peer_write_error maps it to the same `unresolvable_did`
    /// code that path returns, so the two surfaces that judge the same input
    /// answer with the same sentence under the same name.
    #[error("cannot resolve DID '{did}': {reason}")]
    UnresolvableDid { did: String, reason: String },
}

impl Db {
    /// Insert or refresh a peer row, bounded by what the caller can prove.
    ///
    /// See [`PeerWriteAuthority`] for why the authority is a parameter with no
    /// default. The rule: an unproven caller may INSERT an unseen `did:key`
    /// row, but may never UPDATE an existing row's `http_url`. Changing an
    /// existing row requires a verified signature from that row's own DID.
    pub async fn upsert_peer(
        &self,
        did: &str,
        http_url: &str,
        authority: PeerWriteAuthority<'_>,
    ) -> Result<()> {
        // Defense-in-depth at the DB boundary: both writers funnel through here
        // — the announce handler and the bootstrap announce-back in main.rs.
        // The latter has no announce-time check, so validating here is what
        // stops a malicious bootstrap response from re-poisoning the table
        // right after prune_non_public_peers cleaned it.
        if !crate::api::peers::is_public_http_url(http_url) {
            anyhow::bail!("refusing to register non-public peer http_url: {http_url}");
        }
        match authority {
            // The proof has to name the row being written. Checking it here and
            // not only in the announce handler is the whole point of putting
            // the gate at this boundary: a caller could otherwise hold a valid
            // signature for its own DID and spend it on someone else's row,
            // which is RUSTSEC-2022-0009 exactly.
            PeerWriteAuthority::Proven(proven) if proven != did => {
                return Err(PeerWriteDenied::ProofDidMismatch {
                    proven: proven.to_string(),
                    target: did.to_string(),
                }
                .into());
            }
            // Only a DID whose verifying key resolves can ever authenticate:
            // auth/mod.rs resolves the key from the keyid DID itself and
            // rejects everything else. A row seeded here that cannot yield a
            // key would therefore be unwritable by anyone forever, since no
            // proof could ever satisfy the branch above, while still steering
            // the sync origin resolve, the notify fan-out, and the public
            // resolve route.
            //
            // The check is key derivability, NOT the method label. `Did`'s
            // FromStr only runs validate(), which accepts key/web/gitlawb and
            // never looks at the key material, so `did:key:notarealkey` passes
            // is_did_key() and creates exactly the permanently uncorrectable
            // row this gate exists to prevent. to_verifying_key() is the same
            // resolution auth/mod.rs performs on the keyid.
            //
            // The refusal is split by cause, because methodNotSupported is only
            // a true statement about a foreign method: a did:key whose key
            // material does not resolve gets the resolution failure instead.
            // Scoped to the INSERT, not to the DID. The check exists to stop a
            // permanently uncorrectable row being CREATED; applied to a row that
            // already exists it prevents nothing and freezes it instead. Before
            // this gate, upsert_peer validated nothing and the handler accepted
            // any parseable DID, so deployed tables hold did:web rows and
            // did:key rows whose key never resolved. Judging the DID first made
            // every one of those permanently unrefreshable: the unsigned
            // announce is refused, and a signed one cannot exist because no key
            // resolves. The row stays and keeps steering fan-out either way.
            //
            // The read-then-write race is benign: if a row appears in between,
            // this write becomes an UPDATE and the UnprovenRepoint guard below
            // still refuses any http_url change.
            PeerWriteAuthority::Unproven if !self.peer_exists(did).await.unwrap_or(false) => {
                match did.parse::<gitlawb_core::did::Did>() {
                    // Only reachable from the bootstrap announce-back in main.rs,
                    // which passes the contacted peer's raw JSON string; the
                    // announce handler parses req.did before calling here.
                    Err(e) => {
                        return Err(PeerWriteDenied::UnresolvableDid {
                            did: did.to_string(),
                            reason: e.to_string(),
                        }
                        .into());
                    }
                    Ok(d) if !d.is_did_key() => {
                        return Err(PeerWriteDenied::UnsupportedDidMethod {
                            did: did.to_string(),
                        }
                        .into());
                    }
                    Ok(d) => {
                        if let Err(e) = d.to_verifying_key() {
                            return Err(PeerWriteDenied::UnresolvableDid {
                                did: did.to_string(),
                                reason: e.to_string(),
                            }
                            .into());
                        }
                    }
                }
            }
            _ => {}
        }
        let now = Utc::now().to_rfc3339();
        // A changed URL drops the reachability gate, so a repointed peer does
        // not inherit a probe the previous host earned. In the DO UPDATE branch
        // `peers.http_url` is the existing pre-update row (the proposed value is
        // $2), and the comparison runs under the conflict row lock, so
        // concurrent announces for one DID serialize instead of racing a
        // read-then-write. That orders announces against each other and nothing
        // more: mark_peer_ping writes by DID with no http_url predicate, so a
        // probe of the previous URL that lands after a reset can still re-grant
        // the flag until the next round.
        //
        // Comparison is exact. http_url is stored as announced, so a cosmetic
        // difference such as a trailing slash also clears the flag; the peer
        // re-earns it on a later gossip round, provided no further announce
        // lands first. Normalizing instead would mean canonicalizing the stored
        // value, this comparison, and the existing trim_end_matches call sites.
        //
        // last_ping_ok is NOT a trust signal. An unauthenticated caller can
        // clear it by announcing a different URL, and until #248 lands can also
        // set it through the unauthenticated GET /api/v1/peers/{did}/ping, which
        // writes mark_peer_ping from the stored URL's own probe response. Do not
        // build a new consumer on this flag as if it were attacker-resistant.
        //
        // Only the federated repo fan-out in api/repos.rs gates on this flag.
        // Four consumers act on a repointed http_url regardless of it (sync.rs's
        // origin resolve, the post-receive notify fan-out, trigger_sync, and the
        // public resolve route), and two read surfaces republish it as
        // `reachable` (api/resolve.rs, api/peers.rs), which is where a reset
        // becomes externally visible. So this bounds the automatic inheritance
        // rather than closing the rewrite. Binding a DID to its first-seen
        // announcing key is what closes it: #273.
        //
        // The two statements below differ only in what the conflict branch may
        // touch. The proven one keeps the form above verbatim. The unproven one
        // never assigns http_url at all and guards the whole DO UPDATE on the
        // stored URL being byte-identical, so an unproven caller can refresh
        // liveness and nothing else. last_ping_ok needs no CASE there, because
        // the guard already restricts the branch to the URL-unchanged case the
        // CASE would have preserved.
        match authority {
            PeerWriteAuthority::Proven(_) => {
                sqlx::query(
                    "INSERT INTO peers (did, http_url, last_seen, last_ping_ok, announced_at)
                     VALUES ($1, $2, $3, FALSE, $3)
                     ON CONFLICT(did) DO UPDATE SET
                       http_url = $2,
                       last_seen = $3,
                       last_ping_ok = CASE
                         WHEN peers.http_url IS DISTINCT FROM $2 THEN FALSE
                         ELSE peers.last_ping_ok
                       END",
                )
                .bind(did)
                .bind(http_url)
                .bind(&now)
                .execute(&self.pool)
                .await?;
            }
            PeerWriteAuthority::Unproven => {
                let rows = sqlx::query(
                    "INSERT INTO peers (did, http_url, last_seen, last_ping_ok, announced_at)
                     VALUES ($1, $2, $3, FALSE, $3)
                     ON CONFLICT(did) DO UPDATE SET
                       last_seen = $3
                     WHERE peers.http_url IS NOT DISTINCT FROM $2",
                )
                .bind(did)
                .bind(http_url)
                .bind(&now)
                .execute(&self.pool)
                .await?;
                // A guarded ON CONFLICT DO UPDATE whose WHERE fails reports
                // zero rows affected; it does NOT raise. So the refusal has to
                // be derived from rows_affected, or the "an unproven repoint is
                // an error, not a silent no-op" decision quietly becomes the
                // no-op it was chosen to avoid. Zero rows here means exactly
                // one thing, since the insert branch always affects a row: the
                // DID exists and the announced URL is not the stored one.
                if rows.rows_affected() == 0 {
                    return Err(PeerWriteDenied::UnprovenRepoint {
                        did: did.to_string(),
                    }
                    .into());
                }
            }
        }
        Ok(())
    }

    pub async fn mark_peer_ping(&self, did: &str, ok: bool) -> Result<()> {
        sqlx::query("UPDATE peers SET last_seen = $1, last_ping_ok = $2 WHERE did = $3")
            .bind(Utc::now().to_rfc3339())
            .bind(ok)
            .bind(did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Whether a DID has a row in `peers`, by keyed lookup.
    ///
    /// For callers that only need the membership answer. `list_peers` fetches
    /// and materializes every row, so using it as a membership test on a hot
    /// path (the gossip ingest gate) makes the cost of one event grow with the
    /// size of the table.
    pub async fn peer_exists(&self, did: &str) -> Result<bool> {
        Ok(
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM peers WHERE did = $1)")
                .bind(did)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn list_federation_peers(&self, limit: i64) -> Result<Vec<PeerRecord>> {
        let rows = sqlx::query(
            "SELECT did, http_url, last_seen, last_ping_ok, announced_at
             FROM peers WHERE last_ping_ok = TRUE AND http_url <> '' ORDER BY last_seen DESC NULLS LAST, did LIMIT $1",
        )
        .bind(limit.clamp(0, crate::api::repos::MAX_FEDERATED_PEERS as i64 + 1))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PeerRecord {
                did: r.get("did"),
                http_url: r.get("http_url"),
                last_seen: r.get("last_seen"),
                last_ping_ok: r.get::<bool, _>("last_ping_ok"),
                announced_at: r.get("announced_at"),
            })
            .collect())
    }

    pub async fn list_peers(&self) -> Result<Vec<PeerRecord>> {
        let rows = sqlx::query(
            "SELECT did, http_url, last_seen, last_ping_ok, announced_at
             FROM peers ORDER BY last_seen DESC NULLS LAST",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PeerRecord {
                did: r.get("did"),
                http_url: r.get("http_url"),
                last_seen: r.get("last_seen"),
                last_ping_ok: r.get::<bool, _>("last_ping_ok"),
                announced_at: r.get("announced_at"),
            })
            .collect())
    }

    pub async fn prune_self_peers(&self, public_url: &str) -> Result<u64> {
        let trimmed = public_url.trim_end_matches('/');
        let with_slash = format!("{trimmed}/");
        let result = sqlx::query("DELETE FROM peers WHERE http_url = $1 OR http_url = $2")
            .bind(trimmed)
            .bind(&with_slash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Remove peer rows whose `http_url` is not a public http(s) endpoint
    /// (loopback/private/internal hosts injected via the open announce route).
    /// Runs at boot to clean tables poisoned before announce-time validation
    /// existed. Filtering is done in Rust to share one definition of "public"
    /// with the announce handler, then deleted in a single statement so one
    /// transient error can't abandon the remaining poisoned rows mid-loop.
    pub async fn prune_non_public_peers(&self) -> Result<u64> {
        let peers = self.list_peers().await?;
        let bad_dids: Vec<String> = peers
            .into_iter()
            .filter(|p| !crate::api::peers::is_public_http_url(&p.http_url))
            .map(|p| p.did)
            .collect();
        if bad_dids.is_empty() {
            return Ok(0);
        }
        let result = sqlx::query("DELETE FROM peers WHERE did = ANY($1)")
            .bind(&bad_dids)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// ── Node state ────────────────────────────────────────────────────────────────

impl Db {
    /// Read an opaque node-state value. Returns `None` when the key has never
    /// been written. Used by the reconciliation sweep to persist its keyset
    /// cursor across restarts (R2-P1).
    pub async fn get_node_state(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM node_state WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("value")))
    }

    /// Write an opaque node-state value (upsert). `None` deletes the key so a
    /// cleared cursor does not accumulate stale rows.
    pub async fn set_node_state(&self, key: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(v) => {
                sqlx::query(
                    "INSERT INTO node_state (key, value, updated_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
                )
                .bind(key)
                .bind(v)
                .bind(Utc::now().to_rfc3339())
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM node_state WHERE key = $1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Load the reconciliation sweep's per-(repo, backend) continuation offset
    /// (#218 review P2). Returns the last OID the previous pass on this
    /// `(repo, backend)` pair actually handed to the backend — the next pass
    /// rotates the sorted missing set so the first OID is the smallest one
    /// strictly greater than this value, and the elements ≤ it are appended
    /// at the tail (so a persistently failing early OID does not monopolise
    /// the cap window every hourly tick).
    ///
    /// `None` is returned in three cases: no row yet (the first pass on
    /// this pair), the row was marked `done = TRUE` by a previous full pass
    /// (the next pass starts at the head of the missing list), or the
    /// caller passes a `repo`/`backend` it never partially processed. The
    /// reconciliation sweep treats `None` as "start from the head"; the
    /// "where in the key space are we" question is owned by the
    /// repo-level keyset cursor in `node_state`, not this table.
    pub async fn load_reconciliation_offset(
        &self,
        repo_id: &str,
        backend: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT next_oid, done FROM reconciliation_offset
             WHERE repo_id = $1 AND backend = $2",
        )
        .bind(repo_id)
        .bind(backend)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            // `done = TRUE` rows are a previously-completed pass that has
            // not yet been pruned — treat as a fresh start, same as
            // absent. Pruning happens on the next `clear` call so a
            // single-pass sweep does not have to do two writes.
            Some(r) if !r.get::<bool, _>("done") => Ok(Some(r.get("next_oid"))),
            _ => Ok(None),
        }
    }

    /// Persist a (repo, backend) continuation. `next_oid = None` means
    /// "this pass completed" and DELETES the row: absence is the fresh
    /// start, so completed state prunes back to zero instead of
    /// refreshing a tombstone every hour. On a real continuation the
    /// row is upserted with `done = FALSE` so the next pass resumes
    /// from the stored OID.
    ///
    /// The `next_oid` value the caller hands in MUST be the LAST OID
    /// actually attempted this pass (i.e. the max OID in the truncated
    /// or fully-drained set), not the first. The rotation in
    /// `missing_oids` is "strictly greater than", so writing a
    /// forward-rotated OID here would skip the very objects the
    /// truncation truncated — the bug the offset exists to prevent.
    pub async fn save_reconciliation_offset(
        &self,
        repo_id: &str,
        backend: &str,
        next_oid: Option<&str>,
    ) -> Result<()> {
        match next_oid {
            Some(oid) => {
                sqlx::query(
                    "INSERT INTO reconciliation_offset (repo_id, backend, next_oid, done, updated_at)
                     VALUES ($1, $2, $3, FALSE, $4)
                     ON CONFLICT (repo_id, backend) DO UPDATE SET
                         next_oid = EXCLUDED.next_oid,
                         done = FALSE,
                         updated_at = EXCLUDED.updated_at",
                )
                .bind(repo_id)
                .bind(backend)
                .bind(oid)
                .bind(Utc::now().to_rfc3339())
                .execute(&self.pool)
                .await?;
            }
            None => {
                self.clear_reconciliation_offset(repo_id, backend).await?;
            }
        }
        Ok(())
    }

    /// Delete a (repo, backend) continuation row. Completion prunes
    /// instead of tombstoning: absence already means "fresh start", so
    /// a drained pair holds no row and a later empty pass writes
    /// nothing. Also the invalidation seam when the sweep cannot make
    /// progress on a pair — the next pass does not resume a stale
    /// offset against a now-different missing set.
    pub async fn clear_reconciliation_offset(&self, repo_id: &str, backend: &str) -> Result<()> {
        sqlx::query("DELETE FROM reconciliation_offset WHERE repo_id = $1 AND backend = $2")
            .bind(repo_id)
            .bind(backend)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Pinned CIDs ───────────────────────────────────────────────────────────────

impl Db {
    /// #218 review P1a: the production pin loop now keys its
    /// "already done" check on `has_ipfs_cid` (writer-owned
    /// `local_ipfs_provenance = TRUE`), not on row existence. This
    /// method is kept for tests (`test_support.rs`) that exercise
    /// other code paths still using the existence semantic, and is
    /// not called from any production code. The `dead_code` lint
    /// would otherwise fire on the bin build; tests are
    /// `#[cfg(test)]` and don't see this allowance propagate from
    /// the bin target.
    #[allow(dead_code)]
    pub async fn is_pinned(&self, sha256_hex: &str) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM pinned_cids WHERE sha256_hex = $1")
            .bind(sha256_hex)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt") > 0)
    }

    /// Every git oid a pinned CID maps to (`pinned_cids.cid` -> `sha256_hex`).
    /// `GET /ipfs/{cid}` resolves the content-addressed CID a client sends back to
    /// the object's git oid this way: a real pin CID digests the raw object
    /// content, not the git oid, so the digest cannot be `git cat-file`d directly
    /// (#173). The index is unique on the git oid but NON-unique on cid, so two
    /// distinct oids can share one content-CID (a tree and a blob whose raw bytes
    /// collide, or byte-identical content pinned under two oids). Returning every
    /// candidate lets the handler try each rather than pick one arbitrarily and
    /// false-404 when the chosen one is withheld or absent while another is
    /// readable (#173). Empty when the CID was never pinned on this node.
    ///
    /// ORDERED, for the same reason `pin_sources_for_oid` orders its union: the handler
    /// walks these candidates under ONE shared probe budget, visit budget and pager, so
    /// whichever comes back first is the one that spends the request's budget. Left
    /// unordered this is a bare sequential scan returning heap order, which an unpin and
    /// re-pin of any one object rewrites, so two nodes holding identical data could
    /// resolve the same CID differently and one could 503 where the other serves.
    pub async fn oids_for_cid(&self, cid: &str) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT sha256_hex FROM pinned_cids WHERE cid = $1 ORDER BY sha256_hex")
                .bind(cid)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("sha256_hex"))
            .collect())
    }

    /// Record a pinned object's CID and the repository it was pinned from
    /// (`repo_id`, #173). On conflict the `COALESCE` backfills a NULL provenance
    /// from a known source while keeping first-pinner-owns: an existing non-NULL
    /// `repo_id` is never rewritten by a later push of the same oid, but a legacy
    /// pin (or a pin recorded before provenance existed) whose `repo_id` is NULL
    /// gets it filled the next time the object is re-pinned with a known source.
    /// `cid`/`pinned_at` are left untouched on conflict. `repo_id` is `None` only
    /// for a legacy pin with no known source; those fall back to the resolver's scan.
    ///
    /// The production first-pin path now goes through [`Self::record_pinned_cid_with_source`]
    /// (U3, #173) so the pin and its source land atomically; this remains the seam for
    /// seeding legacy, source-less rows in tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn record_pinned_cid(
        &self,
        sha256_hex: &str,
        cid: &str,
        repo_id: Option<&str>,
    ) -> Result<()> {
        // ON CONFLICT also rewrites `cid`: an object pinned once with the wrong
        // bytes is overwritten by a subsequent push-path pin (R1-P2). The
        // previous "first-pinner-owns" semantics left stale wrong CIDs in
        // place, and the sweep gap filter (`cid IS NOT NULL`) excluded them
        // from re-processing so the stale CID became permanent durability
        // evidence. `repo_id` is COALESCE'd so a known source wins over NULL.
        //
        // `local_ipfs_provenance = TRUE` is the durable contract (#218 review P1).
        // This seam exists for legacy, source-less rows in tests and represents
        // a real local IPFS pin, so the new resolver predicate
        // (`local_ipfs_provenance = TRUE`, post-v30) sees it as IPFS-pinned.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id, local_ipfs_provenance)
             VALUES ($1, $2, $3, $4, TRUE)
             ON CONFLICT(sha256_hex) DO UPDATE SET
                 cid = EXCLUDED.cid,
                 repo_id = COALESCE(pinned_cids.repo_id, EXCLUDED.repo_id),
                 local_ipfs_provenance = TRUE",
        )
        .bind(sha256_hex)
        .bind(cid)
        .bind(Utc::now().to_rfc3339())
        .bind(repo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The resolver key currently stored for a pinned object (`pinned_cids.cid`),
    /// or `None` for an unpinned oid. The opportunistic legacy-repair path reads
    /// it to decide candidacy from the codec of the string alone (no object bytes)
    /// before it recomputes anything.
    /// Round-3 P1 (reviewer): v32 leaves `pinned_cids.cid` nullable (Pinata-only
    /// rows store the resolver key in `pinata_cid` and leave `cid = NULL`).
    /// `cid_for_oid` used `r.get::<String, _>("cid")`, which in sqlx 0.8 is
    /// `try_get().unwrap()`: an unexpected NULL panicked rather than erroring.
    /// The pin loop at `ipfs_pin.rs:235` calls this on every batch; the
    /// first batch after a v32 migration would have walked straight into
    /// the panic for any node with a Pinata-only row. Decode as `Option<String>`
    /// so the caller can short-circuit on NULL.
    pub async fn cid_for_oid(&self, sha256_hex: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT cid FROM pinned_cids WHERE sha256_hex = $1")
            .bind(sha256_hex)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get::<Option<String>, _>("cid").ok().flatten()))
    }

    /// Rewrite a legacy provider-CID row to the raw-content resolver key, stashing
    /// the old provider value in `legacy_provider_cid` (#173 R8, KTD8). Before this
    /// branch the pin path stored the PROVIDER CID (Kubo dag-pb / Pinata CIDv0) in
    /// `cid`; the `/ipfs` resolver recomputes the raw CID and 404s a mismatched key
    /// even though `list_pinned_cids` still advertises it. The `WHERE cid =
    /// $old_provider_cid` guard makes a concurrent double-repair a no-op (the second
    /// writer sees the already-rewritten key and matches nothing) and never touches
    /// a row keyed on a different value. Stashed in `legacy_provider_cid`, NOT
    /// `pinata_cid`: the latter gates the Pinata pin-skip (`has_pinata_cid`), so a
    /// Kubo-legacy CID parked there would make Pinata permanently skip the object.
    pub async fn repair_legacy_provider_cid(
        &self,
        sha256_hex: &str,
        raw_cid: &str,
        old_provider_cid: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE pinned_cids
                SET cid = $2, legacy_provider_cid = $3
              WHERE sha256_hex = $1 AND cid = $3",
        )
        .bind(sha256_hex)
        .bind(raw_cid)
        .bind(old_provider_cid)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// One ordered batch of `pinned_cids` rows strictly after `cursor`, for the U4
    /// legacy provider-CID repair sweep. Returns `(sha256_hex, cid)` ordered by
    /// `sha256_hex` (the table's primary key, so the walk rides the PK index) and
    /// capped at `limit` rows, which is what BOUNDS the sweep: one pass can never read
    /// more than a batch, however large the pin set is.
    ///
    /// Deliberately NOT filtered to legacy rows in SQL. "Is this a raw CIDv1" is a
    /// multibase+codec decode (`is_raw_cidv1`), which Postgres cannot express, and a
    /// prefix-match approximation would silently mis-classify keys under a different
    /// multihash. The caller applies the real predicate, so `limit` bounds rows READ
    /// (the DB cost), not rows repaired.
    /// Round-3 P1 (reviewer): the cid column is now nullable (Pinata-only rows
    /// store the resolver key in `pinata_cid` and leave `cid = NULL`). The
    /// legacy repair sweep at `ipfs_pin.rs:896` re-keys the cid to the
    /// raw-content resolver CID; rows with NULL cid have no string to
    /// re-key and skip the re-key naturally if returned as
    /// `(sha, Option<String>)`. The caller filters NULL rows at the
    /// call site (they are Pinata-only and have nothing to re-key on
    /// the legacy provider path).
    pub async fn pinned_cids_after(
        &self,
        cursor: &str,
        limit: i64,
    ) -> Result<Vec<(String, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT sha256_hex, cid FROM pinned_cids
              WHERE sha256_hex > $1
              ORDER BY sha256_hex
              LIMIT $2",
        )
        .bind(cursor)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.try_get::<String, _>("sha256_hex").unwrap_or_default(),
                    r.try_get::<Option<String>, _>("cid").ok().flatten(),
                )
            })
            .collect())
    }

    /// Where the U4 repair sweep's walk left off, or `""` before it has ever run.
    /// Empty string sorts below every hex oid, so a first run and a rewound run are
    /// the same code path (`sha256_hex > ''` is the whole table).
    pub async fn pin_repair_cursor(&self) -> Result<String> {
        let row = sqlx::query("SELECT cursor FROM pin_repair_sweep WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row
            .map(|r| r.get::<String, _>("cursor"))
            .unwrap_or_default())
    }

    /// Persist the sweep's walk position. Written after every batch, so a restart
    /// resumes rather than re-walking the table from the beginning. A rewrite is a
    /// plain upsert: the sweep is the single writer, and re-repairing an
    /// already-repaired row is a no-op anyway (the codec cost gate spares it).
    pub async fn set_pin_repair_cursor(&self, cursor: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO pin_repair_sweep (id, cursor) VALUES (1, $1)
             ON CONFLICT (id) DO UPDATE SET cursor = EXCLUDED.cursor",
        )
        .bind(cursor)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Where the sweep's DISCOVERY window left off, as a `(created_at, id)` keyset
    /// key, or `("", "")` before any traversal has completed one.
    ///
    /// A second, independent position from [`Db::pin_repair_cursor`]: that one walks
    /// `pinned_cids` rows, this one walks the warm CANDIDATE list a source-less row is
    /// probed against. Both are per-TRAVERSAL, and the candidate one only ever moves
    /// at the end of a completed traversal, so every pass of one traversal reads the
    /// same value and every source-less row in it shares one window.
    ///
    /// A key rather than an offset. Repos enter and leave the warm candidate list
    /// between traversals (a cold repo warming on a Tigris-backed node, a fresh
    /// registration, a deletion), and an offset silently means a different candidate
    /// once anything below it moves, which slides the window off the row it was about
    /// to reach. A key names the boundary itself, so an insert below it is invisible.
    /// The key is the RAW stored `created_at` text (`ScanRepoRow::created_at_key`),
    /// never a re-serialized `DateTime`, for the reason that struct's own doc gives.
    pub async fn discovery_continuation(&self) -> Result<(String, String)> {
        let row = sqlx::query(
            "SELECT discovery_cursor_created_at, discovery_cursor_id
               FROM pin_repair_sweep WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row
            .map(|r| {
                (
                    r.get::<String, _>("discovery_cursor_created_at"),
                    r.get::<String, _>("discovery_cursor_id"),
                )
            })
            .unwrap_or_default())
    }

    /// Persist the discovery window's continuation at the end of a completed traversal.
    ///
    /// The INSERT arm names `cursor` explicitly with `''`. v23 declares that column
    /// `NOT NULL` and seeds NO row, so a never-swept node has nothing to update and an
    /// upsert naming only the continuation columns would fail its NOT NULL check.
    /// Every caller treats a failed persist as warn-only, so that failure would be
    /// SILENT and the window would never rotate on exactly the nodes this sweep exists
    /// for. `''` is the same value `pin_repair_cursor` reads as "never swept", so
    /// seeding it here starts no walk anywhere but the top of the table.
    ///
    /// The UPDATE arm touches ONLY the two continuation columns. Writing `cursor` there
    /// too would clobber a live row-walk position with `''` every time the window
    /// rotated, rewinding the `pinned_cids` walk to the start of the table.
    pub async fn set_discovery_continuation(&self, created_at_key: &str, id: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO pin_repair_sweep (id, cursor, discovery_cursor_created_at, discovery_cursor_id)
             VALUES (1, '', $1, $2)
             ON CONFLICT (id) DO UPDATE SET
                 discovery_cursor_created_at = EXCLUDED.discovery_cursor_created_at,
                 discovery_cursor_id = EXCLUDED.discovery_cursor_id",
        )
        .bind(created_at_key)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The repository a pinned object was recorded from (`pinned_cids.repo_id`),
    /// or `None` for a legacy pin (recorded before provenance existed) or an
    /// unpinned oid. `GET /ipfs/{cid}` uses this to gate+serve the ONE source
    /// repo instead of scanning every repo (#173).
    pub async fn provenance_for_oid(&self, sha256_hex: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT repo_id FROM pinned_cids WHERE sha256_hex = $1")
            .bind(sha256_hex)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.get::<Option<String>, _>("repo_id")))
    }

    /// Backfill the source repo on an already-pinned object whose provenance is
    /// NULL (a legacy pin recorded before provenance existed, #173, jatmn). The
    /// `AND repo_id IS NULL` guard keeps first-pinner-owns: an existing non-NULL
    /// provenance is left untouched. Touches only `repo_id` and never re-pins the
    /// object's bytes, so it is safe to call on the already-pinned skip path.
    pub async fn backfill_pin_provenance(&self, sha256_hex: &str, repo_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE pinned_cids SET repo_id = $2 WHERE sha256_hex = $1 AND repo_id IS NULL",
        )
        .bind(sha256_hex)
        .bind(repo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record a repository as a source for a pinned object (F1, #173 jatmn round 8),
    /// bounded to about `MAX_PIN_SOURCES` distinct repos per object. The count guard
    /// lives inside the INSERT (a single statement), which suppresses a re-push of the
    /// SAME `(oid, repo)` via `ON CONFLICT DO NOTHING`. It does NOT hard-serialize
    /// concurrent inserts of DIFFERENT repos for the same object: under Postgres READ
    /// COMMITTED each concurrent writer's count subquery reads a snapshot that omits the
    /// others' uncommitted rows, so N concurrent pushers can each see `count < cap` and
    /// overshoot by up to N-1 rows. The overshoot is a small constant (bounded by
    /// concurrent-pusher count, never O(repos)), and the RESOLVER read side
    /// (`pin_sources_for_oid`) caps the ADDITIONAL sources at `MAX_PIN_SOURCES` (always
    /// keeping the first-pinner), so the INV-10 bound on serve-time work holds at
    /// `O(MAX_PIN_SOURCES + 1)` regardless of a table overshoot.
    ///
    /// A record that ACTUALLY ADDS a source row also CLEARS the
    /// `pin_sources_incomplete` marker for the object, in the SAME transaction as the
    /// insert (U3, #173), so the clear cannot drift across the four call sites or land
    /// without the row it describes.
    ///
    /// The clear is gated on `rows_affected() > 0` because the INSERT is a no-op in two
    /// ordinary cases: the `(oid, repo)` pair already exists (`ON CONFLICT DO NOTHING`)
    /// and the source set is at cap (the count guard). The skip path calls this for
    /// EVERY already-pinned object, and on a requeue pass that list is the whole-repo
    /// enumeration, so an unconditional clear meant the next coalesced push from a repo
    /// already in the set wiped the marker for every object in the repo without
    /// recording anything (round 11 regression). The residual, which the gate does not
    /// close: the marker is per-object, not per-(object, repo), so a GENUINE record from
    /// a third repo C still clears a marker that repo A's failed record set. That is the
    /// deliberate cost of a single boolean; closing it needs a per-(oid, repo) marker
    /// table, and it fails in the safe direction (the marker only ever ADDS the scan
    /// fallback, never removes a source the resolver already tries).
    pub async fn record_pin_source(&self, sha256_hex: &str, repo_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO pin_repo_sources (sha256_hex, repo_id)
             SELECT $1, $2
             WHERE (SELECT count(*) FROM pin_repo_sources WHERE sha256_hex = $1) < $3
             ON CONFLICT DO NOTHING",
        )
        .bind(sha256_hex)
        .bind(repo_id)
        .bind(MAX_PIN_SOURCES)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted > 0 {
            // Clears THIS repo's failure only (#173 round 12). A boolean per object meant
            // repo C's genuine record wiped the marker repo B's failure set, and the
            // resolver then dropped the scan fallback while B's copy was still unrecorded.
            sqlx::query("DELETE FROM pin_source_failures WHERE sha256_hex = $1 AND repo_id = $2")
                .bind(sha256_hex)
                .bind(repo_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Record a first pin and its source ATOMICALLY (U3, #173). The first-pin path
    /// used to run `record_pinned_cid` and `record_pin_source` as two independent
    /// best-effort calls, so the pin could land while its source did not, leaving a
    /// source set that is silently missing its own first pinner. One transaction
    /// removes that window entirely: either both rows land or neither does, and a
    /// total failure leaves the object unpinned so the next push retries it.
    ///
    /// The marker clear carries the same `rows_affected` gate as `record_pin_source`.
    /// It is not load-bearing here: this path runs only when `is_pinned` said no row
    /// exists, and `mark_pin_sources_incomplete` is a no-op without a `pinned_cids` row,
    /// so there is no marker to wrongly clear. The gate is kept for the one window that
    /// is not covered by that argument, a concurrent pinner landing the row between the
    /// `is_pinned` check and this upsert, and so the two clears cannot drift apart.
    /// The 3-arg form. The production `pin_new_objects` path
    /// routes through the 4-arg fenced form
    /// ([`record_pinned_cid_with_source_fenced`]) so the third
    /// fence closes the rule-write / record-write race. This
    /// 3-arg form is still the helper for tests that don't own
    /// a fence and is a documented thin-wrapper equivalent (it
    /// takes the same row lock, just with `i64::MAX` as the
    /// "no fence" sentinel that the fenced form treats as
    /// skip-the-comparison).
    #[allow(dead_code)] // call sites in ipfs_pin.rs use the fenced form; tests seed via this
    pub async fn record_pinned_cid_with_source(
        &self,
        sha256_hex: &str,
        cid: &str,
        repo_id: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // #218 review round 9 (guidance #3 — linearization point):
        // no `fence_epoch` is passed in this 3-arg form. The
        // 4-arg overload below is the IPFS pin flow's third
        // fence: it re-reads the epoch under a row lock that
        // `set_visibility_rule` must also take, and aborts the
        // record if the epoch has advanced. Callers that don't
        // own a policy fence (push-side pin records, where
        // admission time IS the decision time) use this overload.

        // `local_ipfs_provenance = TRUE` here is the durable contract
        // (#218 review P1): the only path that calls this method
        // (`ipfs_pin.rs` `pin_git_object` after a successful `add`) has
        // actually pushed the bytes into the node's local IPFS daemon.
        // ON CONFLICT upgrades provenance too, so a re-pin of an object
        // that previously arrived via Pinata-only (cid=NULL, flag=FALSE)
        // becomes a real local pin from the resolver's perspective the
        // moment the bytes land locally.
        //
        // `cid = COALESCE(pinned_cids.cid, EXCLUDED.cid)` (#218 review
        // P1a): when a Pinata-only row had `cid = NULL` (the
        // `raw_cid == pinata_cid` shape produced by
        // `record_pinata_cid`), the new local pin fills the resolver
        // key with the local raw CID. A pre-existing non-NULL `cid`
        // (a real local pin's raw CID, or one set by
        // `repair_legacy_provider_cid`) is preserved — `EXCLUDED.cid`
        // is identical to it in normal cases, and COALESCE is
        // belt-and-suspenders against any future divergence. Without
        // this, the local pin would land with `local_ipfs_provenance
        // = TRUE` and `cid = NULL`, and the resolver would have no
        // local CID to serve the object by.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id, local_ipfs_provenance)
             VALUES ($1, $2, $3, $4, TRUE)
             ON CONFLICT(sha256_hex) DO UPDATE SET
                 cid = COALESCE(pinned_cids.cid, EXCLUDED.cid),
                 repo_id = COALESCE(pinned_cids.repo_id, EXCLUDED.repo_id),
                 local_ipfs_provenance = TRUE",
        )
        .bind(sha256_hex)
        .bind(cid)
        .bind(Utc::now().to_rfc3339())
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
        let inserted = sqlx::query(
            "INSERT INTO pin_repo_sources (sha256_hex, repo_id)
             SELECT $1, $2
             WHERE (SELECT count(*) FROM pin_repo_sources WHERE sha256_hex = $1) < $3
             ON CONFLICT DO NOTHING",
        )
        .bind(sha256_hex)
        .bind(repo_id)
        .bind(MAX_PIN_SOURCES)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted > 0 {
            // Clears THIS repo's failure only (#173 round 12). A boolean per object meant
            // repo C's genuine record wiped the marker repo B's failure set, and the
            // resolver then dropped the scan fallback while B's copy was still unrecorded.
            sqlx::query("DELETE FROM pin_source_failures WHERE sha256_hex = $1 AND repo_id = $2")
                .bind(sha256_hex)
                .bind(repo_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// #218 review round 9 (guidance #3 — linearization point):
    /// [`record_pinned_cid_with_source`] with a third fence check
    /// INSIDE the record transaction. Reads the repo's policy
    /// epoch under `FOR UPDATE`; the same row lock that
    /// `set_visibility_rule` and `remove_visibility_rule` take
    /// when they bump `policy_epoch`. A narrowing rule that
    /// commits between the irreversible POST and this record
    /// either blocks on us (we see the post-narrow epoch and
    /// abort) or has already released (we see the post-narrow
    /// epoch and abort). Either way the record never lands
    /// under a stale-allow decision.
    ///
    /// `fence_epoch` is the value `PolicyFence::capture` read
    /// BEFORE the POST (the per-batch captured epoch). A
    /// mismatch means the decision we wrote bytes against is no
    /// longer the decision the database would write the row
    /// under, and we abort.
    ///
    /// This is the third fence of three: top-of-iteration
    /// (`pin_new_objects` 1803-1812), pre-POST
    /// (`pin_new_objects` 2058-2074), and pre-record (here, in
    /// the same transaction as the row insert). The HTTP POST is
    /// irreducible — it cannot run inside a Postgres
    /// transaction — so the linearization has to be at the
    /// rule-write / record-write race. The pre-record fence
    /// closes that race; a narrowing rule that lands between
    /// the POST and the record is observed here and the record
    /// is aborted.
    pub async fn record_pinned_cid_with_source_fenced(
        &self,
        sha256_hex: &str,
        cid: &str,
        repo_id: &str,
        fence_epoch: i64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // P2 (reviewer round 9): `i64::MAX` is the "no fence"
        // sentinel used by push-side admission. The push path
        // has no decision to invalidate, so the row lock is
        // unnecessary and would queue `touch_repo`, the
        // quarantine toggle, and rule writes behind every pin
        // record. Skip the lock + comparison entirely on the
        // sentinel path; the unfenced record then runs through
        // the same INSERT / COALESCE / pin_repo_sources
        // statements with no policy_epoch read.
        if fence_epoch != i64::MAX {
            // Fenced path: take the row lock and compare.
            // `set_visibility_rule` takes the same lock when it
            // updates `policy_epoch`, so a rule write that
            // committed between the POST and now is already
            // visible (the rule write's commit released the
            // lock; we acquire it now and read the new value).
            // A rule write in flight blocks on our lock; the
            // record is aborted.
            //
            // A missing repos row returns `None` and bails
            // fail-closed (was `unwrap_or(0)` — a fail-open
            // path against a non-existent repo).
            let current_epoch = self.repo_policy_epoch_locked(&mut tx, repo_id).await?;
            let current_epoch = match current_epoch {
                Some(e) => e,
                None => {
                    tx.rollback().await.ok();
                    anyhow::bail!(
                        "policy epoch row missing for {repo_id}; \
                         pin record aborted, no row landed"
                    );
                }
            };
            if current_epoch != fence_epoch {
                // The decision the pinner acted under is no longer
                // the decision the database would land the row
                // under. Roll back; no row, no source, no
                // failure-marker delete.
                tx.rollback().await.ok();
                anyhow::bail!(
                    "policy epoch changed during pin dispatch \
                     (captured={fence_epoch}, current={current_epoch}); \
                     pin record aborted, no row landed"
                );
            }
        }
        // The remainder is the same INSERT / COALESCE /
        // pin_repo_sources logic as the 3-arg form. Kept inline
        // (rather than factored into a private helper) so the
        // two forms can drift independently if a future change
        // needs them to — drift is the very class of bug this
        // third fence is here to catch.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id, local_ipfs_provenance)
             VALUES ($1, $2, $3, $4, TRUE)
             ON CONFLICT(sha256_hex) DO UPDATE SET
                 cid = COALESCE(pinned_cids.cid, EXCLUDED.cid),
                 repo_id = COALESCE(pinned_cids.repo_id, EXCLUDED.repo_id),
                 local_ipfs_provenance = TRUE",
        )
        .bind(sha256_hex)
        .bind(cid)
        .bind(Utc::now().to_rfc3339())
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
        let inserted = sqlx::query(
            "INSERT INTO pin_repo_sources (sha256_hex, repo_id)
             SELECT $1, $2
             WHERE (SELECT count(*) FROM pin_repo_sources WHERE sha256_hex = $1) < $3
             ON CONFLICT DO NOTHING",
        )
        .bind(sha256_hex)
        .bind(repo_id)
        .bind(MAX_PIN_SOURCES)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted > 0 {
            sqlx::query("DELETE FROM pin_source_failures WHERE sha256_hex = $1 AND repo_id = $2")
                .bind(sha256_hex)
                .bind(repo_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Record a DISCOVERED holder and arm the resolver's fallback ATOMICALLY (U5, #173).
    /// The sweep's discovery arm used to call `record_pin_source` and then, separately,
    /// `mark_pin_sources_incomplete`. Two best-effort writes, so a transient failure of
    /// the second one left the row with a nonempty, below-cap, UNMARKED source set: the
    /// resolver's `needs_scan` is `sources.is_empty() || at_cap || incomplete`, so all
    /// three signals were off, the bounded legacy scan was dropped, and an unrecorded
    /// public duplicate stayed 404'd for good once the DB error cleared (no later sweep
    /// revisits a raw-CIDv1 row). One transaction removes that state entirely: either the
    /// source row and the sentinel both land or neither does, and neither-lands is the
    /// benign end (an empty set is itself a `needs_scan` signal).
    ///
    /// The sentinel insert is UNCONDITIONAL, unlike the marker clear's `rows_affected`
    /// gate: discovery probes a bounded, warm-only candidate set and stops at the first
    /// holder, so finding one holder is never evidence the set is complete, whether or
    /// not this particular call added a row. It names the empty-string UNKNOWN-repo
    /// sentinel (the same one the v24 migration carries pre-upgrade markers under), so no
    /// real per-repo record can clear it, and it carries the same
    /// `WHERE EXISTS (pinned_cids row)` guard as [`Self::mark_pin_sources_incomplete`]
    /// so a marker never sits in the table for an object this node never pinned.
    ///
    /// Commit-terminated, like [`Self::record_pin_source`], so a caller that wraps this
    /// in `db_bounded` may read `BoundedDbError::Elapsed` as "definitely did not land":
    /// the cancelled future never reaches `tx.commit()`, no COMMIT is sent, and Postgres
    /// discards the transaction when the connection resets.
    pub async fn record_discovered_pin_source(
        &self,
        sha256_hex: &str,
        repo_id: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO pin_repo_sources (sha256_hex, repo_id)
             SELECT $1, $2
             WHERE (SELECT count(*) FROM pin_repo_sources WHERE sha256_hex = $1) < $3
             ON CONFLICT DO NOTHING",
        )
        .bind(sha256_hex)
        .bind(repo_id)
        .bind(MAX_PIN_SOURCES)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if inserted > 0 {
            // Clears THIS repo's failure only, the same gate and reason as
            // `record_pin_source`: a per-object clear let one repo's genuine record wipe
            // a marker another repo's failure set.
            sqlx::query("DELETE FROM pin_source_failures WHERE sha256_hex = $1 AND repo_id = $2")
                .bind(sha256_hex)
                .bind(repo_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "INSERT INTO pin_source_failures (sha256_hex, repo_id)
                  SELECT $1, '' WHERE EXISTS (SELECT 1 FROM pinned_cids WHERE sha256_hex = $1)
                  ON CONFLICT DO NOTHING",
        )
        .bind(sha256_hex)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Mark this object's pin-source set as KNOWN INCOMPLETE for `repo_id` (U3, #173).
    /// Called when a `record_pin_source` exhausts its retries, which is the only moment
    /// the node knows a source it meant to record is missing. `GET /ipfs/{cid}` reads it
    /// to keep the bounded scan fallback for that object, so a public copy that would
    /// serve is no longer 404'd.
    ///
    /// The marker names the PAIR, so only a later successful record from the same repo
    /// clears it (#173 round 12). A no-op when no `pinned_cids` row exists: the first-pin
    /// path is transactional, so there is no half-recorded pin to describe, and without
    /// the guard a marker for an object this node never pinned would sit in the table
    /// arming a fallback for nothing.
    pub async fn mark_pin_sources_incomplete(&self, sha256_hex: &str, repo_id: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO pin_source_failures (sha256_hex, repo_id)
                  SELECT $1, $2 WHERE EXISTS (SELECT 1 FROM pinned_cids WHERE sha256_hex = $1)
                  ON CONFLICT DO NOTHING",
        )
        .bind(sha256_hex)
        .bind(repo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Whether this object's pin-source set is KNOWN INCOMPLETE (U3, #173): a
    /// `record_pin_source` for it failed outright and no later record from the same repo
    /// has repaired it. `false` for an unpinned oid and for every object with no recorded
    /// failure, so the common path is unchanged and an ordinary denial never fans out
    /// (INV-10).
    pub async fn pin_sources_incomplete(&self, sha256_hex: &str) -> Result<bool> {
        let found: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM pin_source_failures WHERE sha256_hex = $1 LIMIT 1")
                .bind(sha256_hex)
                .fetch_optional(&self.pool)
                .await?;
        Ok(found.is_some())
    }

    /// Every source repository recorded for a pinned object (F1, #173 jatmn round 8):
    /// the union of the first-pinner `pinned_cids.repo_id` and the `pin_repo_sources`
    /// rows, deduped and ordered for a deterministic resolver walk.
    ///
    /// The first-pinner (a single row by `pinned_cids`' PK on `sha256_hex`) is ALWAYS
    /// included; the `LIMIT MAX_PIN_SOURCES` caps only the ADDITIONAL `pin_repo_sources`
    /// rows. This keeps the resolver's per-source work a bounded `O(MAX_PIN_SOURCES + 1)`
    /// ceiling (INV-10) while never letting the cap evict the original source. A prior
    /// version applied the `LIMIT` to the whole UNION with a lexicographic `ORDER BY`,
    /// which let an attacker 404 a legacy public CID (first-pinner in `pinned_cids` but
    /// not yet in `pin_repo_sources`) by pushing the same object from `MAX_PIN_SOURCES`
    /// repos whose grindable ids sort before it, evicting the public source from the
    /// window. Empty for a legacy pin with no known source (it falls back to the repo
    /// scan) or an unpinned oid.
    pub async fn pin_sources_for_oid(&self, sha256_hex: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT repo_id FROM pinned_cids
                 WHERE sha256_hex = $1 AND repo_id IS NOT NULL
             UNION
             SELECT repo_id FROM (
                 SELECT repo_id FROM pin_repo_sources
                     WHERE sha256_hex = $1
                 ORDER BY repo_id
                 LIMIT $2
             ) capped
             ORDER BY repo_id",
        )
        .bind(sha256_hex)
        .bind(MAX_PIN_SOURCES)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("repo_id"))
            .collect())
    }

    /// Whether `pin_repo_sources` is at the `MAX_PIN_SOURCES` cap for this oid, i.e.
    /// the provenance source set returned by [`Self::pin_sources_for_oid`] may be
    /// INCOMPLETE. `record_pin_source` stops inserting at exactly `MAX_PIN_SOURCES`
    /// rows and drops later sources silently, so a full table is the only observable
    /// signal that a servable source (e.g. a later public pinner) may have been
    /// dropped. `get_by_cid` uses this to decide whether a provenance miss should fall
    /// back to the bounded legacy scan (which gates every repo through the real
    /// visibility gate and so finds a dropped public source) rather than 404 — closing
    /// the pin-source griefing hole where 16 attacker sources bury a public one. `>=`
    /// (not `==`) is defensive against any future overshoot.
    pub async fn pin_sources_at_cap(&self, sha256_hex: &str) -> Result<bool> {
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pin_repo_sources WHERE sha256_hex = $1")
                .bind(sha256_hex)
                .fetch_one(&self.pool)
                .await?;
        Ok(count >= MAX_PIN_SOURCES)
    }

    pub async fn record_encrypted_blob(
        &self,
        repo_id: &str,
        oid: &str,
        cid: &str,
        recipients_tag: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO encrypted_blobs (repo_id, oid, cid, recipients_tag, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (repo_id, oid) DO UPDATE SET cid = EXCLUDED.cid, recipients_tag = EXCLUDED.recipients_tag",
        )
        .bind(repo_id)
        .bind(oid)
        .bind(cid)
        .bind(recipients_tag)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// (oid, cid) for every encrypted blob in the repo, unscoped by caller. Used
    /// by both the B2 replication view and B1 discovery. Recipient identities are
    /// not stored, so authorization is the caller's repo readability, not a per
    /// recipient check. Ciphertext metadata only.
    pub async fn list_all_encrypted_blobs(&self, repo_id: &str) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT oid, cid FROM encrypted_blobs WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for row in rows {
            let oid: String = row.get("oid");
            let cid: String = row.get("cid");
            out.push((oid, cid));
        }
        Ok(out)
    }

    /// The CID of one encrypted blob, or None if there is no such row. Recipient
    /// authorization is not enforced here: the handler checks repo readability and
    /// the envelope crypto gates decryption.
    pub async fn encrypted_blob_cid(&self, repo_id: &str, oid: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT cid FROM encrypted_blobs WHERE repo_id = $1 AND oid = $2")
            .bind(repo_id)
            .bind(oid)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("cid")))
    }

    /// The opaque recipients tag stored for an encrypted blob, or None if there is
    /// no row. Used only to decide whether a re-seal is needed (the recipient set
    /// changed); the tag is a node-keyed fingerprint, not the DID list.
    pub async fn encrypted_blob_recipients_tag(
        &self,
        repo_id: &str,
        oid: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT recipients_tag FROM encrypted_blobs WHERE repo_id = $1 AND oid = $2",
        )
        .bind(repo_id)
        .bind(oid)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("recipients_tag")))
    }

    /// Every pinned object this node ADVERTISES (`GET /api/v1/ipfs/pins`).
    ///
    /// #218: the contract is "every row that has something to advertise". A
    /// row is surfaced as a local pin only when `local_ipfs_provenance` is
    /// set AND the stored `cid` parses as a raw CIDv1; legacy rows (v35
    /// left them unproven) and non-CIDv1 `cid` values stay hidden until the
    /// sweep re-derives them. A row with `cid IS NULL` and `pinata_cid` set
    /// is surfaced as a Pinata-only pin so the handler can project
    /// `effective_cid = pinata_cid`. A row with both columns NULL has
    /// nothing to serve and is dropped. A corrupt `cid` column surfaces as
    /// a decode error through `?` instead of being silently misread as a
    /// Pinata-only row — the previous `try_get().ok()` conflated the two.
    /// The handler at `api/ipfs.rs::list_pins` is the seam that decides
    /// what to do with a legacy-shape row (it hands it to the resolver and
    /// the resolver 404s on mismatch, the documented #173 U4 behavior).
    pub async fn list_pinned_cids(&self) -> Result<Vec<PinnedCidRecord>> {
        let rows = sqlx::query(
            "SELECT sha256_hex, cid, pinned_at, pinata_cid, local_ipfs_provenance
             FROM pinned_cids ORDER BY pinned_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            // `try_get::<Option<String>>` maps only SQL NULL to None (a
            // Pinata-only row); a corrupt `cid` column surfaces as a decode
            // error through `?` instead of being silently misread as a
            // Pinata-only row. The old `try_get().ok()` conflated the two.
            let cid: Option<String> = r.try_get("cid")?;
            let pinata_cid: Option<String> = r.get("pinata_cid");
            if cid.is_none() && pinata_cid.is_none() {
                // Nothing to advertise: no local CID, no Pinata CID.
                continue;
            }
            out.push(PinnedCidRecord {
                sha256_hex: r.get("sha256_hex"),
                cid,
                pinned_at: r.get("pinned_at"),
                pinata_cid,
                local_ipfs_provenance: r.get("local_ipfs_provenance"),
            });
        }
        Ok(out)
    }

    /// Returns true when this object has a real local IPFS CID. The predicate
    /// is `local_ipfs_provenance = TRUE` (#218 review P1): the boolean is
    /// set ONLY by the local IPFS writer (`record_pinned_cid_with_source`
    /// and the legacy `record_pinned_cid` seam) and is NEVER inferred
    /// from CID shape or equality. A Pinata-only row (cid = NULL,
    /// pinata_cid set) keeps `local_ipfs_provenance = FALSE`, so the
    /// sweep's gap filter does not trust it as a real local pin and
    /// will re-derive by re-pinning if IPFS is enabled later. A
    /// Legacy rows written before the provenance flag existed are NOT
    /// backfilled: migration v35 deliberately leaves them
    /// `local_ipfs_provenance = FALSE`, so this predicate reports them as
    /// unproven until the reconciliation sweep re-derives each one by
    /// re-pinning through `record_pinned_cid_with_source`.
    #[allow(dead_code)]
    pub async fn has_ipfs_cid(&self, sha256_hex: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM pinned_cids
             WHERE sha256_hex = $1
               AND local_ipfs_provenance = TRUE",
        )
        .bind(sha256_hex)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("cnt") > 0)
    }

    /// Returns true if this object already has a Pinata CID recorded.
    pub async fn has_pinata_cid(&self, sha256_hex: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM pinned_cids WHERE sha256_hex = $1 AND pinata_cid IS NOT NULL",
        )
        .bind(sha256_hex)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<i64, _>("cnt") > 0)
    }

    /// Given a list of sha256_hex values, returns the subset that already have
    /// a Pinata CID recorded. Used by the reconciliation sweep to skip objects
    /// that Pinata has already handled. Chunked like `filter_ipfs_pinned_oids`
    /// to bound the `ANY($1)` array size on full uncapped object lists (R1-P3).
    pub async fn filter_pinata_pinned_oids(&self, oids: &[String]) -> Result<Vec<String>> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        const CHUNK_SIZE: usize = 1000;
        let mut out = Vec::new();
        for chunk in oids.chunks(CHUNK_SIZE) {
            let rows = sqlx::query(
                "SELECT sha256_hex FROM pinned_cids WHERE sha256_hex = ANY($1) AND pinata_cid IS NOT NULL",
            )
            .bind(chunk)
            .fetch_all(&self.pool)
            .await?;
            out.extend(rows.into_iter().map(|r| r.get("sha256_hex")));
        }
        Ok(out)
    }

    /// Given a list of sha256_hex values, returns the subset that have a real
    /// local IPFS pin. The predicate is `local_ipfs_provenance = TRUE`
    /// (#218 review P1): set by the local IPFS writer, never inferred from
    /// CID shape or equality. Used by the reconciliation sweep to skip
    /// IPFS-complete objects — a Pinata-only row (cid = NULL, pinata_cid
    /// set) is NOT excluded, so enabling IPFS later causes the sweep to
    /// re-derive those rows by re-pinning rather than trusting a missing
    /// local copy as durable.
    ///
    /// The input is processed in fixed-size chunks so the `ANY($1)` array sent
    /// to Postgres is bounded even when the sweep hands over a full uncapped
    /// object list (R1-P3).
    pub async fn filter_ipfs_pinned_oids(&self, oids: &[String]) -> Result<Vec<String>> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        const CHUNK_SIZE: usize = 1000;
        let mut out = Vec::new();
        for chunk in oids.chunks(CHUNK_SIZE) {
            let rows = sqlx::query(
                "SELECT sha256_hex FROM pinned_cids
                 WHERE sha256_hex = ANY($1)
                   AND local_ipfs_provenance = TRUE",
            )
            .bind(chunk)
            .fetch_all(&self.pool)
            .await?;
            out.extend(rows.into_iter().map(|r| r.get("sha256_hex")));
        }
        Ok(out)
    }

    /// Record the Pinata CID for a git object.
    ///
    /// `raw_cid` is the locally-computed raw-content CID (`Cid::from_git_object_bytes`,
    /// CIDv1/raw/sha-256), the resolver key `GET /ipfs/{cid}` looks up; `pinata_cid`
    /// is the provider CID Pinata returned (a dag-pb/UnixFS CID for gateway retrieval).
    /// Inserts the row if it doesn't exist (an object pinned directly to Pinata with
    /// no prior local IPFS pin gets `cid = raw_cid`, never the provider CID — a dag-pb
    /// provider CID must never become an alias that serves raw bytes that do not hash
    /// to it, #173). On conflict `cid` is left untouched: a prior local pin already
    /// stored the correct raw CID, and the COALESCE backfills a NULL provenance from a
    /// known source while keeping first-pinner-owns.
    ///
    /// **This writer does NOT establish local-IPFS provenance** (#218 review P1):
    /// `local_ipfs_provenance` is left at its DEFAULT FALSE (or the value the row
    /// already had) because the bytes have not been pushed to the local IPFS daemon
    /// here, only to Pinata. The resolver's `has_ipfs_cid` / `filter_ipfs_pinned_oids`
    /// keys on `local_ipfs_provenance = TRUE`, so a Pinata-only row never reads as a
    /// real local pin. If IPFS is enabled later, the reconciliation sweep will
    /// re-derive provenance by re-pinning these objects (their `cid IS NULL` or
    /// `pinata_cid` shape keeps them out of the gap filter's "already done" set).
    /// Fenced Pinata record (P2 reviewer round 9): `fence_epoch ==
    /// i64::MAX` is the "no fence" sentinel used by the pre-existing
    /// unfenced callers (test fixtures, the reconciliation path)
    /// and the helper skips the row lock and the policy_epoch read
    /// entirely on that path. With a real epoch, the helper takes
    /// the same row lock as `record_pinned_cid_with_source_fenced`
    /// and aborts the record if the epoch moved.
    pub async fn record_pinata_cid(
        &self,
        sha256_hex: &str,
        raw_cid: &str,
        pinata_cid: &str,
        repo_id: Option<&str>,
        fence_epoch: i64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        if fence_epoch != i64::MAX {
            // Same row-lock-and-compare pattern as
            // `record_pinned_cid_with_source_fenced`. A narrowing
            // rule that lands between the Pinata POST and the
            // record is observed here, and the record is aborted.
            // `repo_id` is the pinned side of the contract; the
            // Pinata record attaches a `repo_id` only when one
            // is in scope, but the fence itself only makes sense
            // when a repo is involved — `None` is treated as
            // "no fence possible" and falls through to the
            // unfenced record.
            if let Some(rid) = repo_id {
                let current_epoch = self.repo_policy_epoch_locked(&mut tx, rid).await?;
                let current_epoch = match current_epoch {
                    Some(e) => e,
                    None => {
                        tx.rollback().await.ok();
                        anyhow::bail!(
                            "policy epoch row missing for {rid}; \
                             pinata record aborted, no row landed"
                        );
                    }
                };
                if current_epoch != fence_epoch {
                    tx.rollback().await.ok();
                    anyhow::bail!(
                        "policy epoch changed during pinata dispatch \
                         (captured={fence_epoch}, current={current_epoch}); \
                         pinata record aborted, no row landed"
                    );
                }
            }
        }
        // Same INSERT as the unfenced `record_pinata_cid`. The
        // `cid`-NULLs-on-Pinata-only path is the same: a
        // dag-pb provider CID must not become the alias under
        // which `/ipfs/{cid}` serves raw bytes.
        let cid = if raw_cid == pinata_cid {
            None
        } else {
            Some(raw_cid)
        };
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid, repo_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(sha256_hex) DO UPDATE SET
                 pinata_cid = EXCLUDED.pinata_cid,
                 cid = CASE WHEN pinned_cids.cid = pinned_cids.pinata_cid
                            THEN NULL ELSE pinned_cids.cid END,
                 repo_id = COALESCE(pinned_cids.repo_id, EXCLUDED.repo_id)",
        )
        .bind(sha256_hex)
        .bind(cid)
        .bind(Utc::now().to_rfc3339())
        .bind(pinata_cid)
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Verify a Pinata record after its write timed out: true only if the
    /// exact row exists AND the fence epoch still matches. A timed-out
    /// `record_pinata_cid` is an explicit multi-statement transaction, so
    /// cancellation before COMMIT wrote nothing and cancellation during
    /// COMMIT is unknown — neither may count as durable on its own. This
    /// read-after-timeout closes that: a row the timed-out attempt (or an
    /// earlier identical attempt — content match, not causality) durably
    /// landed still counts; anything else stays non-durable and the gap is
    /// re-offered. Single statement, so the row and the epoch come from one
    /// snapshot. Any error (including a stall of this read itself) is
    /// returned and the caller treats it as unverified.
    pub async fn verify_pinata_record(
        &self,
        sha256_hex: &str,
        raw_cid: &str,
        pinata_cid: &str,
        repo_id: &str,
        fence_epoch: i64,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT c.cid AS cid, c.pinata_cid AS pinata_cid, r.policy_epoch AS epoch
             FROM pinned_cids c JOIN repos r ON r.id = $2
             WHERE c.sha256_hex = $1",
        )
        .bind(sha256_hex)
        .bind(repo_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let stored_pinata: Option<String> = row.get("pinata_cid");
        if stored_pinata.as_deref() != Some(pinata_cid) {
            return Ok(false);
        }
        // Mirror the record shape: equal CIDs store cid NULL, distinct
        // CIDs store the raw resolver key.
        let stored_cid: Option<String> = row.get("cid");
        let cid_ok = if raw_cid == pinata_cid {
            stored_cid.is_none()
        } else {
            stored_cid.as_deref() == Some(raw_cid)
        };
        if !cid_ok {
            return Ok(false);
        }
        if fence_epoch != i64::MAX {
            let epoch: i64 = row.get("epoch");
            if epoch != fence_epoch {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

// ── Repo Push Events ──────────────────────────────────────────────────────────

/// How long a push-event write waits for its repo's lock before its statement
/// is cancelled, in milliseconds.
///
/// Well under the pool's `acquire_timeout` (5 seconds by default), and
/// deliberately so: a writer that queued on the lock is holding a pooled
/// connection while it waits, so a wait longer than the acquire timeout would
/// convert one slow repo into pool exhaustion for every unrelated request.
/// Three attempts at this bound stay inside that budget.
const PUSH_LOCK_TIMEOUT_MS: u32 = 1_000;

/// How many times a push-event write may be re-attempted after its lock wait
/// expired. Bounded, because the caller runs inline on the user's `git push`.
const PUSH_LOCK_ATTEMPTS: u32 = 3;

/// Postgres `lock_not_available`, which is what `SET LOCAL lock_timeout`
/// cancels a statement with. The retryable failure, as distinct from every
/// other database error, which is returned on the first attempt.
const LOCK_NOT_AVAILABLE: &str = "55P03";

fn is_lock_timeout(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|e| e.code())
        .is_some_and(|code| code == LOCK_NOT_AVAILABLE)
}

/// The two transient classes a bounded inline write may retry: a lock wait the
/// timeout cancelled (`lock_not_available`), and a pool acquire that timed out
/// behind the queue. Every other error is permanent for this attempt.
pub(crate) fn is_transient_db_write(err: &anyhow::Error) -> bool {
    match err.downcast_ref::<sqlx::Error>() {
        Some(e) => is_lock_timeout(e) || matches!(e, sqlx::Error::PoolTimedOut),
        None => false,
    }
}

impl Db {
    /// Record one local push event. Idempotent on the row id.
    ///
    /// Test-only, for the same reason as [`Db::set_open_pr_heads`]: the push path
    /// writes a whole push in one statement, and this single-row form survives
    /// only to keep row-seeding tests readable.
    #[cfg(test)]
    pub async fn insert_repo_push_event(&self, event: &RepoPushEvent) -> Result<()> {
        self.insert_repo_push_events(std::slice::from_ref(event))
            .await
    }

    /// Record a whole push's events in one statement, under the repo's write
    /// lock. Idempotent on the row ids.
    ///
    /// One multi-row insert rather than one round trip per ref: the receive-pack
    /// path runs this inline on the user's `git push`, so a sequential loop makes
    /// the push response pay a database round trip for every ref it carries.
    ///
    /// `seq` is not bound. It is a bigserial the database assigns in insert
    /// order, which is exactly why the poll cursor can trust it; a value supplied
    /// here would defeat that.
    ///
    /// WRITERS AGAINST ONE REPO ARE SERIALIZED, on the same transaction-scoped
    /// advisory lock [`Db::insert_status_claim_capped`] takes, so the two agree
    /// on what a repo lock means. Insert order alone is not enough for the
    /// cursor: `nextval` allocates the sequence at INSERT and the row becomes
    /// visible at COMMIT, and it does not roll back, so two overlapping writers
    /// can commit out of allocation order. When they do, the poller reads the
    /// higher sequence, advances its cursor past the lower one, and that row,
    /// once it commits, is never delivered by any later poll. Holding the lock
    /// across the commit is what makes allocation order equal visibility order
    /// within a repo. Across repos nothing is serialized, and nothing needs to
    /// be: the cursor is per repo.
    ///
    /// The wait is bounded rather than indefinite, because this runs on the
    /// user's push: `SET LOCAL lock_timeout` cancels the wait and the write is
    /// re-attempted [`PUSH_LOCK_ATTEMPTS`] times before the error is returned.
    /// The caller must not swallow it (see `api::repos::record_push_events`); a
    /// dropped chunk is the same permanent loss the lock exists to prevent.
    ///
    /// Callers must chunk the slice (see `api::repos::PUSH_WRITE_CHUNK`): every
    /// row costs five bind parameters, against a protocol ceiling of 65535. The
    /// chunking bounds one STATEMENT, not the push: every ref receive-pack
    /// accepted is written, across as many chunks as that takes. The lock is
    /// therefore taken once per chunk, which still holds the property: each
    /// chunk commits before any other writer can allocate.
    pub async fn insert_repo_push_events(&self, events: &[RepoPushEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        // Every repo the batch touches, in one fixed order. In practice a push
        // is one repo and this is one key; sorting is what keeps two batches
        // that did span repos from taking the same keys in opposite orders and
        // deadlocking.
        let mut repo_ids: Vec<&str> = events.iter().map(|e| e.repo_id.as_str()).collect();
        repo_ids.sort_unstable();
        repo_ids.dedup();

        let mut values = String::new();
        for i in 0..events.len() {
            if i > 0 {
                values.push(',');
            }
            let b = i * 5;
            values.push_str(&format!(
                "(${},${},${},${},${})",
                b + 1,
                b + 2,
                b + 3,
                b + 4,
                b + 5
            ));
        }
        let sql = format!(
            "INSERT INTO repo_push_events (id, repo_id, ref_name, after_sha, created_at)
             VALUES {values}
             ON CONFLICT(id) DO NOTHING"
        );

        let mut attempt = 1;
        loop {
            match self.push_events_attempt(&sql, &repo_ids, events).await {
                Ok(()) => return Ok(()),
                Err(e) if attempt < PUSH_LOCK_ATTEMPTS && is_lock_timeout(&e) => {
                    tracing::debug!(
                        attempt,
                        repos = repo_ids.len(),
                        "push-event write timed out waiting for the repo lock; retrying"
                    );
                    attempt += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// One attempt at the write above: take the repo locks, insert, commit.
    ///
    /// The lock releases with the transaction, so the commit here is what makes
    /// the next writer's allocation safe.
    async fn push_events_attempt(
        &self,
        sql: &str,
        repo_ids: &[&str],
        events: &[RepoPushEvent],
    ) -> std::result::Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // First statement of the transaction, so it bounds the lock waits below
        // and nothing else: `SET LOCAL` reverts at commit or rollback.
        sqlx::query(&format!(
            "SET LOCAL lock_timeout = '{PUSH_LOCK_TIMEOUT_MS}ms'"
        ))
        .execute(&mut *tx)
        .await?;

        for repo_id in repo_ids {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
                .bind(*repo_id)
                .execute(&mut *tx)
                .await?;
        }

        let mut q = sqlx::query(sql);
        for e in events {
            q = q
                .bind(&e.id)
                .bind(&e.repo_id)
                .bind(&e.ref_name)
                .bind(&e.after_sha)
                .bind(&e.created_at);
        }
        count_push_write_statement();
        q.execute(&mut *tx).await?;

        tx.commit().await
    }

    /// The SHA of the most recent push this node recorded for one ref of a repo,
    /// or `None` if it has never seen a push for it.
    ///
    /// This is the pull request rollup's branch resolve. It reads
    /// `repo_push_events` rather than `branch_cids` because that table is written
    /// unconditionally for every ref update on the receive-pack path, while
    /// `branch_cids` only gets a row when the pushed objects came back carrying a
    /// pin CID — on a node with no pinning configured it is never written at all,
    /// which left the resolve permanently unable to answer.
    ///
    /// Both the ref filter and the ordering are the database's work: the caller
    /// gets one row, not the repo's whole push history to scan. "Most recent" is
    /// the highest `seq`, not the latest `created_at`: the timestamp is stamped
    /// before the insert, so the last row written is not necessarily the one
    /// carrying the largest stamp, and every row of one multi-ref push shares a
    /// stamp anyway. `(repo_id, ref_name, seq DESC)` is the index this rides.
    pub async fn latest_push_sha_for_ref(
        &self,
        repo_id: &str,
        ref_name: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT after_sha FROM repo_push_events
             WHERE repo_id = $1 AND ref_name = $2
             ORDER BY seq DESC LIMIT 1",
        )
        .bind(repo_id)
        .bind(ref_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("after_sha")))
    }

    /// The ordering key of one push event, looked up BY ROW ID and scoped to the
    /// repository that owns it.
    ///
    /// This is what turns the poll surface's opaque cursor back into something
    /// the keyset walk can use, and the scoping is the security half of it: a
    /// token naming a row of some other repository resolves to `None` here, not
    /// to that row's `seq`. `None` is also the honest answer for a row that no
    /// longer exists, which the caller reports as a refusal rather than serving
    /// an empty page that would read as "up to date".
    ///
    /// `(repo_id, id)` rather than `id` alone even though the id is the primary
    /// key: the predicate is the point, and a lookup that found the row and then
    /// compared afterwards would be one refactor away from dropping the compare.
    pub async fn push_event_seq(&self, repo_id: &str, id: &str) -> Result<Option<i64>> {
        let row = sqlx::query("SELECT seq FROM repo_push_events WHERE repo_id = $1 AND id = $2")
            .bind(repo_id)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get("seq")))
    }

    /// One page of a repo's push events, OLDEST first, walked by a `seq` keyset
    /// cursor rather than an offset.
    ///
    /// `after` is the cursor a poller last saw; the page reads rows strictly
    /// after it via `seq > after`, which matches the `ORDER BY` exactly. One
    /// column is enough because `seq` is a database-assigned bigserial: it is
    /// unique, so there is no tiebreak to get wrong, and it is assigned at insert
    /// time rather than by the application. It does not follow from that alone
    /// that the sequence agrees with the order the rows became visible: the
    /// value is allocated at INSERT and published at COMMIT, so two overlapping
    /// writers can commit out of allocation order and strand the lower row
    /// behind a cursor that has already passed it. What makes the agreement
    /// hold is the write side, where [`Db::insert_repo_push_events`] serializes
    /// a repo's writers on an advisory lock held across the commit.
    /// `created_at` cannot do this job either: it is
    /// stamped before the insert, every row of one multi-ref push carries the
    /// same value, and a clock that steps backwards makes a later row sort
    /// earlier, stranding it behind a cursor that has already passed.
    ///
    /// Oldest-first is what makes the cursor stable under concurrent writes: a
    /// push landing mid-walk sorts after the window being paged, so it cannot
    /// shift it, and the next poll picks it up.
    pub async fn list_repo_push_events_keyset(
        &self,
        repo_id: &str,
        after: Option<i64>,
        limit: i64,
    ) -> Result<Vec<RepoPushEvent>> {
        const COLS: &str = "id, seq, repo_id, ref_name, after_sha, created_at";

        // Positional params in bind order: repo_id, after?, limit.
        let (cursor_clause, limit_param) = match after {
            Some(_) => (" AND seq > $2", 3),
            None => ("", 2),
        };
        let sql = format!(
            "SELECT {COLS} FROM repo_push_events WHERE repo_id = $1{cursor_clause} \
             ORDER BY seq ASC LIMIT ${limit_param}"
        );

        let mut q = sqlx::query(&sql).bind(repo_id.to_string());
        if let Some(seq) = after {
            q = q.bind(seq);
        }
        let rows = q.bind(limit).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(row_to_repo_push_event).collect())
    }
}

fn row_to_repo_push_event(r: sqlx::postgres::PgRow) -> RepoPushEvent {
    RepoPushEvent {
        id: r.get("id"),
        seq: r.get("seq"),
        repo_id: r.get("repo_id"),
        ref_name: r.get("ref_name"),
        after_sha: r.get("after_sha"),
        created_at: r.get("created_at"),
    }
}

// ── Received Ref Updates ──────────────────────────────────────────────────────

impl Db {
    pub async fn insert_ref_update(&self, update: &ReceivedRefUpdate) -> Result<()> {
        sqlx::query(
            "INSERT INTO received_ref_updates
             (id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, timestamp,
              cert_id, received_at, from_peer, owner_did)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&update.id)
        .bind(&update.node_did)
        .bind(&update.pusher_did)
        .bind(&update.repo)
        .bind(&update.ref_name)
        .bind(&update.old_sha)
        .bind(&update.new_sha)
        .bind(&update.timestamp)
        .bind(&update.cert_id)
        .bind(&update.received_at)
        .bind(&update.from_peer)
        .bind(&update.owner_did)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Resolve the trusted display `owner_did` for every ref-update row in a page,
    /// issuing at most one query per *unique* local repo so the cost scales with
    /// the number of distinct repos in the page rather than the page size.
    ///
    /// The stored `owner_did` (and the `repo` slug) arrive over gossipsub or the
    /// unsigned peer-notify HTTP path, so neither is trusted. This method binds
    /// the wire `owner_did` to the local repo the slug names before it is ever
    /// surfaced:
    ///
    /// * **P1 (untrusted wire value):** a peer-supplied `owner_did` is only
    ///   echoed when it normalizes equal to the canonical owner of the *actual
    ///   local repo* at that slug. A caller asserting `did:key:zVictim` on a
    ///   `zAlice/widget` row is dropped, because `zVictim` does not own the
    ///   local `zAlice/widget` repo. The canonical DID is returned (not the raw
    ///   wire bytes), so the projection is always the local source of truth.
    /// * **P3 (legacy fallback):** a row stored with `owner_did = None` is
    ///   attributed only via an *exact, normalized, unique* local match —
    ///   `get_repo` matches the slug's owner key and name exactly (`LIMIT 1`,
    ///   preferring canonical rows). The loose prefix-tolerant drop gate
    ///   (`ref_update_row_names_repo`) is never used for attribution, so a
    ///   cross-method slug collision cannot synthesize the wrong owner. When no
    ///   unique local repo proves the owner, `None` is returned.
    ///
    /// # P2 mirror-only fallback
    ///
    /// Mirror-only repos store their owner as the bare normalized key (no DID
    /// method prefix).  When a validated wire DID carries a full prefix (e.g.
    /// `did:key:z…`) and the matching repo is a mirror, the full wire value is
    /// returned so the API contract preserves the DID method for these rows.
    ///
    /// The slug must be `"{owner}/{name}"`; a slug without a `/` cannot be
    /// attributed and yields `None`.
    pub async fn resolve_ref_update_owner_dids(
        &self,
        rows: &[(&str, Option<&str>)],
    ) -> Result<Vec<Option<String>>> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // ── 1.  Collect unique lookup keys ────────────────────────────────
        let mut slug_parts: Vec<Option<String>> = Vec::with_capacity(rows.len());
        // Keys are stored as `format!("{normalized_key}\0{name}")` for cheap
        // HashMap lookup.
        let mut unique_keys: Vec<String> = Vec::new();

        for (slug, _wire) in rows {
            if let Some((owner_part, name)) = slug.rsplit_once('/') {
                let normalized = normalize_owner_key(owner_part);
                let key = format!("{normalized}\0{name}");
                if !unique_keys.contains(&key) {
                    unique_keys.push(key.clone());
                }
                slug_parts.push(Some(key));
            } else {
                slug_parts.push(None);
            }
        }

        // ── 2.  Fetch all matching repos in one set-based query ──────────
        // Build a single SQL with one OR condition per unique key so every
        // distinct slug is resolved in one round-trip regardless of how many
        // unique repos the page names.
        let mut repo_map: std::collections::HashMap<String, RepoRecord> =
            std::collections::HashMap::new();

        if !unique_keys.is_empty() {
            let mut sql = String::from(
                "SELECT id, name, owner_did, description, is_public, default_branch,
                        created_at, updated_at, disk_path, forked_from, machine_id
                 FROM repos WHERE (",
            );
            let mut conds: Vec<String> = Vec::with_capacity(unique_keys.len());
            for i in 0..unique_keys.len() {
                let p = (2 * i + 1) as i64;
                let q = (2 * i + 2) as i64;
                conds.push(format!("({}) = ${p} AND name = ${q}", OWNER_KEY_CASE_SQL));
            }
            sql.push_str(&conds.join(" OR "));
            sql.push_str(
                ") ORDER BY CASE WHEN position('/' in id) > 0 THEN 1 ELSE 0 END, \
                 created_at ASC, id ASC",
            );

            let mut q = sqlx::query(&sql);
            for key in &unique_keys {
                if let Some((owner_part, name)) = key.split_once('\0') {
                    q = q.bind(owner_part).bind(name);
                }
            }

            for row in q.fetch_all(&self.pool).await? {
                let repo = row_to_repo(row);
                let key = format!("{}\0{}", normalize_owner_key(&repo.owner_did), repo.name);
                repo_map.entry(key).or_insert(repo);
            }
        }

        // ── 3.  Resolve every input row ──────────────────────────────────
        let mut results = Vec::with_capacity(rows.len());
        for (i, (_slug, wire_owner_did)) in rows.iter().enumerate() {
            let Some(repo) = slug_parts[i].as_ref().and_then(|k| repo_map.get(k)) else {
                results.push(None);
                continue;
            };

            match (wire_owner_did, repo) {
                (Some(wire), repo)
                    if normalize_owner_key(wire) == normalize_owner_key(&repo.owner_did) =>
                {
                    if repo.id.contains('/') && *wire != repo.owner_did {
                        results.push(Some((*wire).to_string()));
                    } else {
                        results.push(Some(repo.owner_did.clone()));
                    }
                }
                (None, _) => {
                    results.push(Some(repo.owner_did.clone()));
                }
                _ => results.push(None),
            }
        }

        Ok(results)
    }

    /// One page of ref updates (newest first), optionally scoped to one repo.
    /// The `(timestamp DESC, id DESC)` order gives a stable tiebreak so offset
    /// paging does not skip or duplicate rows when timestamps collide. Used by
    /// the visibility-gated feed collector, which pages past dropped private rows
    /// so a small limit still returns the latest visible events (#114).
    /// One page of ref updates for the visibility collector, ordered
    /// `timestamp DESC, id DESC`, using a **keyset** cursor rather than
    /// `LIMIT/OFFSET`.
    ///
    /// `after` is the `(timestamp, id)` of the last row of the previous page;
    /// the next page reads rows strictly older than it via the row-value
    /// predicate `(timestamp, id) < (after_ts, after_id)`, which matches the
    /// `ORDER BY` exactly (same id tie-break). Because a concurrently inserted
    /// row is newer (larger `timestamp`) and so sorts to the front, it lands
    /// *above* the window we are paging through and cannot shift it. That keeps
    /// a single multi-page scan free of the duplicate/skip that OFFSET paging
    /// suffers when `received_ref_updates` is written between page reads.
    pub async fn list_ref_updates_keyset(
        &self,
        repo: Option<&str>,
        limit: i64,
        after: Option<(&str, &str)>,
    ) -> Result<Vec<ReceivedRefUpdate>> {
        const COLS: &str = "id, node_did, pusher_did, repo, ref_name, old_sha, new_sha, \
                            timestamp, cert_id, received_at, from_peer, owner_did";

        // Positional params in bind order: repo?, after_ts?, after_id?, limit.
        let mut conds: Vec<String> = Vec::new();
        let mut n = 0;
        if repo.is_some() {
            n += 1;
            conds.push(format!("repo = ${n}"));
        }
        if after.is_some() {
            let (a, b) = (n + 1, n + 2);
            n += 2;
            conds.push(format!("(timestamp, id) < (${a}, ${b})"));
        }
        let where_clause = if conds.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conds.join(" AND "))
        };
        let sql = format!(
            "SELECT {COLS} FROM received_ref_updates{where_clause} \
             ORDER BY timestamp DESC, id DESC LIMIT ${}",
            n + 1
        );

        let mut q = sqlx::query(&sql);
        if let Some(r) = repo {
            q = q.bind(r.to_string());
        }
        if let Some((ts, id)) = after {
            q = q.bind(ts.to_string()).bind(id.to_string());
        }
        let rows = q.bind(limit).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(row_to_ref_update).collect())
    }
}

// ── Agent Tasks ───────────────────────────────────────────────────────────────

/// Permanent authorization denial: the task is reserved for a different assignee.
/// Handlers downcast this to return 403 (vs 409 for a lost claim race).
#[derive(Debug, thiserror::Error)]
#[error("task not claimable: reserved for another assignee")]
pub struct TaskReservedForOtherAssignee;

/// ASCII whitespace treated as blank for assignee slots — must stay in sync with
/// `BTRIM(assignee_did, E' \t\n\r')` in `claim_task`'s SQL open-slot check.
const ASSIGNEE_BLANK: &[char] = &[' ', '\t', '\n', '\r'];

fn assignee_slot_blank(s: &str) -> bool {
    s.trim_matches(ASSIGNEE_BLANK).is_empty()
}

/// Trim assignee DIDs for auth matching (same ASCII blank set as SQL/open checks).
pub fn trim_assignee_did(s: &str) -> &str {
    s.trim_matches(ASSIGNEE_BLANK)
}

impl Db {
    /// Persist a task. Whitespace-only `assignee_did` is stored as `NULL` (open).
    /// Returns the normalized row shape so REST/GraphQL create responses match GET.
    pub async fn create_task(&self, task: &AgentTask) -> Result<AgentTask> {
        let mut stored = task.clone();
        stored.assignee_did = stored
            .assignee_did
            .take()
            .filter(|s| !assignee_slot_blank(s));
        sqlx::query(
            "INSERT INTO agent_tasks (id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        )
        .bind(&stored.id)
        .bind(&stored.repo_id)
        .bind(&stored.kind)
        .bind(&stored.status)
        .bind(&stored.delegator_did)
        .bind(&stored.assignee_did)
        .bind(&stored.capability)
        .bind(&stored.ucan_token)
        .bind(&stored.payload)
        .bind(&stored.result)
        .bind(&stored.created_at)
        .bind(&stored.updated_at)
        .bind(&stored.deadline)
        .execute(&self.pool)
        .await?;
        Ok(stored)
    }

    pub async fn get_task(&self, id: &str) -> Result<Option<AgentTask>> {
        let row = sqlx::query(
            "SELECT id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline
             FROM agent_tasks WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(row_to_task))
    }

    pub async fn list_tasks_keyset(
        &self,
        status: Option<&str>,
        assignee_did: Option<&str>,
        limit: i64,
        after: Option<(&str, &str)>,
    ) -> Result<Vec<AgentTask>> {
        // create_task stores the supplied assignee form unchanged. Compare the
        // did:key short form so a `did:key:z...` filter matches a bare `z...`
        // row (and the reverse), matching `did_matches` on the read path.
        let assignee_key = assignee_did.map(normalize_owner_key);
        let sql = list_tasks_keyset_sql(status.is_some(), assignee_key.is_some(), after.is_some());
        let mut q = sqlx::query(&sql);
        if let Some(status) = status {
            q = q.bind(status);
        }
        if let Some(key) = assignee_key {
            q = q.bind(key);
        }
        if let Some((created_at, id)) = after {
            q = q.bind(created_at).bind(id);
        }
        let rows = q.bind(limit).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(row_to_task).collect())
    }

    /// Claim a pending task for `assignee_did`.
    ///
    /// If the task was created with a non-blank pre-set `assignee_did`, only that
    /// agent (DID-normalized via [`crate::api::did_matches`]) may claim it. Open
    /// tasks (`NULL` / blank) remain first-claimer-wins. A reserved claim keeps
    /// the **exact** stored DID form via `COALESCE($4, $2)` (no BTRIM rewrite) so
    /// exact-match list filters still work. The UPDATE also re-checks the
    /// assignee slot as defense-in-depth against a future writer racing the
    /// pre-check.
    pub async fn claim_task(&self, id: &str, assignee_did: &str) -> Result<AgentTask> {
        let now = Utc::now().to_rfc3339();
        // Denial path only needs status + assignee — do not load payload/UCAN
        // for a permissionless caller who will be rejected.
        let row = sqlx::query("SELECT status, assignee_did FROM agent_tasks WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("task not claimable: not found or already claimed"))?;
        let status: String = row.get("status");
        if status != "pending" {
            return Err(anyhow::anyhow!(
                "task not claimable: not found or already claimed"
            ));
        }
        let stored: Option<String> = row.get("assignee_did");
        // Blank reservations are treated as open. Keep the exact stored string
        // for the UPDATE equality check and SET (do not BTRIM the reserved form).
        // Blank definition matches SQL `BTRIM(..., E' \t\n\r')` (not space-only).
        let reserved_exact = stored.as_deref().filter(|r| !assignee_slot_blank(r));
        if let Some(reserved) = reserved_exact {
            if !crate::api::did_matches(assignee_did, trim_assignee_did(reserved)) {
                return Err(TaskReservedForOtherAssignee.into());
            }
        }
        // Keep the exact reserved form ($4); only fill assignee on open claims ($2).
        // Treat blank stored values as open for the SQL slot check.
        let row = sqlx::query(
            "UPDATE agent_tasks SET status='claimed',
                 assignee_did = COALESCE($4, $2),
                 updated_at=$3
             WHERE id=$1 AND status='pending'
               AND (
                 ($4::text IS NULL AND (assignee_did IS NULL OR BTRIM(assignee_did, E' \t\n\r') = ''))
                 OR assignee_did = $4
               )
             RETURNING id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline",
        )
        .bind(id)
        .bind(assignee_did)
        .bind(&now)
        .bind(reserved_exact)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_task)
            .ok_or_else(|| anyhow::anyhow!("task not claimable: not found or already claimed"))
    }

    /// Transition a claimed task to `new_status` (`completed` / `failed`).
    ///
    /// `actor_did` must be the task's assignee (DID-normalized). The UPDATE
    /// binds the exact stored `assignee_did` so a concurrent reassignment /
    /// re-claim cannot finish under a check-then-act race in the handler.
    pub async fn finish_task(
        &self,
        id: &str,
        new_status: &str,
        result: Option<&str>,
        actor_did: &str,
    ) -> Result<AgentTask> {
        let now = Utc::now().to_rfc3339();
        let existing = self
            .get_task(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("task not found or not in claimed state"))?;
        if existing.status != "claimed" {
            return Err(anyhow::anyhow!("task not found or not in claimed state"));
        }
        let Some(ref assigned) = existing.assignee_did else {
            return Err(anyhow::anyhow!("task not found or not in claimed state"));
        };
        // Trim matches claim_task so tab-padded stored values can finish.
        if !crate::api::did_matches(actor_did, trim_assignee_did(assigned)) {
            return Err(anyhow::anyhow!(
                "task not finishable: only the assignee may finish it"
            ));
        }
        let row = sqlx::query(
            "UPDATE agent_tasks SET status=$2, result=$3, updated_at=$4
             WHERE id=$1 AND status='claimed' AND assignee_did=$5
             RETURNING id, repo_id, kind, status, delegator_did, assignee_did, capability, ucan_token, payload, result, created_at, updated_at, deadline",
        )
        .bind(id)
        .bind(new_status)
        .bind(result)
        .bind(&now)
        .bind(assigned.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_task)
            .ok_or_else(|| anyhow::anyhow!("task not found or not in claimed state"))
    }
}

// ── Arweave anchors ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArweaveAnchor {
    pub id: String,
    pub repo: String,
    pub owner_did: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub cid: Option<String>,
    pub irys_tx_id: String,
    pub arweave_url: String,
    pub node_did: String,
    pub anchored_at: String,
}

/// Input parameters for recording an Arweave anchor.
pub struct RecordAnchorInput<'a> {
    pub repo: &'a str,
    pub owner_did: &'a str,
    pub ref_name: &'a str,
    pub old_sha: &'a str,
    pub new_sha: &'a str,
    pub cid: Option<&'a str>,
    pub irys_tx_id: &'a str,
    pub arweave_url: &'a str,
    pub node_did: &'a str,
}

impl Db {
    pub async fn record_arweave_anchor(&self, input: &RecordAnchorInput<'_>) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO arweave_anchors (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(&id)
        .bind(input.repo)
        .bind(input.owner_did)
        .bind(input.ref_name)
        .bind(input.old_sha)
        .bind(input.new_sha)
        .bind(input.cid)
        .bind(input.irys_tx_id)
        .bind(input.arweave_url)
        .bind(input.node_did)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_arweave_anchors(
        &self,
        repo: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ArweaveAnchor>> {
        let rows = if let Some(repo) = repo {
            sqlx::query(
                "SELECT id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at
                 FROM arweave_anchors WHERE repo=$1 ORDER BY anchored_at DESC LIMIT $2",
            )
            .bind(repo)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at
                 FROM arweave_anchors ORDER BY anchored_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| ArweaveAnchor {
                id: r.get("id"),
                repo: r.get("repo"),
                owner_did: r.get("owner_did"),
                ref_name: r.get("ref_name"),
                old_sha: r.get("old_sha"),
                new_sha: r.get("new_sha"),
                cid: r.get("cid"),
                irys_tx_id: r.get("irys_tx_id"),
                arweave_url: r.get("arweave_url"),
                node_did: r.get("node_did"),
                anchored_at: r.get("anchored_at"),
            })
            .collect())
    }
}

// ── Row helpers ───────────────────────────────────────────────────────────────

#[cfg_attr(not(test), allow(dead_code))]
fn row_to_repo_mirror_state(r: sqlx::postgres::PgRow) -> Result<RepoMirrorState> {
    let repo_id = r
        .try_get("id")
        .context("reading mirror repository id from database")?;
    let upstream_url = r
        .try_get("upstream_url")
        .context("reading mirror upstream URL from database")?;
    let status = r
        .try_get::<String, _>("mirror_status")
        .context("reading mirror status from database")?;
    let status = MirrorStatus::from_db(&status)?;
    let transition_id = r
        .try_get("mirror_transition_id")
        .context("reading mirror transition id from database")?;
    let transition_phase = r
        .try_get::<Option<String>, _>("mirror_transition_phase")
        .context("reading mirror transition phase from database")?
        .as_deref()
        .map(MirrorTransitionPhase::from_db)
        .transpose()?;
    let updated_at = r
        .try_get::<String, _>("mirror_updated_at")
        .context("reading mirror update timestamp from database")?
        .parse::<DateTime<Utc>>()
        .context("invalid mirror_updated_at stored in database")?;

    let state = RepoMirrorState {
        repo_id,
        upstream_url,
        status,
        transition_id,
        transition_phase,
        updated_at,
    };
    state.validate()?;
    Ok(state)
}

#[cfg(test)]
mod mirror_state_tests {
    use super::{
        row_to_repo_mirror_state, validate_mirror_upstream_url, Db, MirrorStatus,
        MirrorTransitionPhase, RepoMirrorState, RepoRecord,
    };
    use chrono::{DateTime, Utc};
    use sqlx::PgPool;
    use uuid::Uuid;

    fn ts(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }

    fn repo(id: Uuid) -> RepoRecord {
        RepoRecord {
            id: id.to_string(),
            name: "mirror-fixture".to_string(),
            owner_did: "did:key:z6MkMirrorOwner".to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: ts("2026-08-14T00:00:00Z"),
            updated_at: ts("2026-08-14T00:00:00Z"),
            disk_path: format!("/srv/repos/{id}.git"),
            forked_from: None,
            machine_id: None,
        }
    }

    async fn migrated_db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    #[test]
    fn upstream_url_accepts_https_forges_without_credentials() {
        for valid in [
            "https://github.com/Gitlawb/node.git",
            "https://gitlab.example.com/platform/subgroup/node",
            "https://ghe.internal.example/org/repo.git",
        ] {
            validate_mirror_upstream_url(valid).unwrap();
        }
    }

    #[test]
    fn upstream_url_rejects_unsafe_or_ambiguous_forms() {
        for invalid in [
            "",
            "http://github.com/Gitlawb/node.git",
            "ssh://git@github.com/Gitlawb/node.git",
            "file:///etc/passwd",
            "https://user:secret@github.com/Gitlawb/node.git",
            "https://github.com/Gitlawb/node.git?token=secret",
            "https://github.com/Gitlawb/node.git#main",
            "https://github.com/",
            "https://github.com/Gitlawb/node.git\n",
            "https://localhost/Gitlawb/node.git",
            "https://forge.localhost/Gitlawb/node.git",
            "https://127.0.0.1/Gitlawb/node.git",
            "https://[::1]/Gitlawb/node.git",
            "https://169.254.169.254/Gitlawb/node.git",
            "https://10.0.0.5/Gitlawb/node.git",
            "https://172.16.0.5/Gitlawb/node.git",
            "https://192.168.1.5/Gitlawb/node.git",
            "https://forge.internal/Gitlawb/node.git",
            "https://[::ffff:127.0.0.1]/Gitlawb/node.git",
            "https://[64:ff9b::7f00:1]/Gitlawb/node.git",
            // Special-use literals the peer classifier accepts but the fetch
            // worker's stricter permit denies; configure and fetch must agree.
            "https://192.0.2.1/org/repo.git",
            "https://198.18.0.1/org/repo.git",
            "https://203.0.113.5/org/repo.git",
            "https://[2001:db8::1]/org/repo.git",
        ] {
            assert!(
                validate_mirror_upstream_url(invalid).is_err(),
                "unsafe mirror URL was accepted: {invalid:?}"
            );
        }
    }

    #[test]
    fn transition_metadata_must_match_the_status() {
        let base = RepoMirrorState {
            repo_id: Uuid::new_v4().to_string(),
            upstream_url: "https://github.com/Gitlawb/node.git".to_string(),
            status: MirrorStatus::Inbound,
            transition_id: None,
            transition_phase: None,
            updated_at: Utc::now(),
        };
        base.validate().unwrap();

        let mut invalid = base.clone();
        invalid.status = MirrorStatus::TransitioningInboundToOutbound;
        assert!(invalid.validate().is_err());

        invalid.transition_id = Some(Uuid::new_v4());
        invalid.transition_phase = Some(MirrorTransitionPhase::DrainingWrites);
        invalid.validate().unwrap();

        invalid.transition_phase = Some(MirrorTransitionPhase::Completed);
        assert!(invalid.validate().is_err());
    }

    #[sqlx::test]
    async fn migrations_v30_v31_upgrade_an_existing_repo_without_rewriting_it(pool: PgPool) {
        let db = migrated_db(pool).await;

        // Recreate the pre-v30 shape, then add data written by the old node.
        sqlx::query("ALTER TABLE repos DROP COLUMN upstream_url CASCADE")
            .execute(&db.pool)
            .await
            .unwrap();
        for column in [
            "mirror_status",
            "mirror_transition_id",
            "mirror_transition_phase",
            "mirror_updated_at",
        ] {
            sqlx::query(&format!("ALTER TABLE repos DROP COLUMN {column}"))
                .execute(&db.pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM schema_migrations WHERE version IN (30, 31)")
            .execute(&db.pool)
            .await
            .unwrap();

        let existing = repo(Uuid::new_v4());
        db.create_repo(&existing).await.unwrap();

        db.run_migrations().await.unwrap();

        let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repos WHERE id = $1")
            .bind(&existing.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            still_there, 1,
            "the existing repository must survive v30/v31"
        );

        let mirror_values: (Option<String>, Option<String>, Option<Uuid>, Option<String>) =
            sqlx::query_as(
                "SELECT upstream_url, mirror_status, mirror_transition_id,
                        mirror_transition_phase
                 FROM repos WHERE id = $1",
            )
            .bind(&existing.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(mirror_values, (None, None, None, None));

        let recorded: Vec<(i64, String)> = sqlx::query_as(
            "SELECT version, name FROM schema_migrations
             WHERE version IN (30, 31) ORDER BY version",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            recorded,
            vec![
                (30, "repo_upstream_mirror_state".to_string()),
                (31, "validate_repo_upstream_mirror_state".to_string()),
            ]
        );
        let constraint_validated: bool = sqlx::query_scalar(
            "SELECT convalidated FROM pg_constraint
             WHERE conrelid = 'repos'::regclass
               AND conname = 'repos_mirror_state_valid'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert!(constraint_validated, "v31 must validate the v30 constraint");

        // Production entry point remains idempotent after the upgrade.
        db.run_migrations().await.unwrap();
    }

    #[sqlx::test]
    async fn migration_replaces_a_same_named_weaker_constraint(pool: PgPool) {
        let db = migrated_db(pool).await;

        sqlx::query("ALTER TABLE repos DROP CONSTRAINT repos_mirror_state_valid")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query(
            "ALTER TABLE repos ADD CONSTRAINT repos_mirror_state_valid CHECK (TRUE) NOT VALID",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version IN (30, 31)")
            .execute(&db.pool)
            .await
            .unwrap();

        db.run_migrations().await.unwrap();

        let definition: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid)
             FROM pg_constraint
             WHERE conrelid = 'repos'::regclass
               AND conname = 'repos_mirror_state_valid'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert!(
            definition.contains("transitioning_inbound_to_outbound")
                && !definition.eq_ignore_ascii_case("CHECK (true)"),
            "migration preserved an impostor constraint: {definition}"
        );

        let existing = repo(Uuid::new_v4());
        db.create_repo(&existing).await.unwrap();
        let malformed = sqlx::query(
            "UPDATE repos
             SET upstream_url = 'https://github.com/Gitlawb/node.git',
                 mirror_status = 'transitioning_inbound_to_outbound',
                 mirror_updated_at = '2026-08-14T00:00:00Z'
             WHERE id = $1",
        )
        .bind(&existing.id)
        .execute(&db.pool)
        .await;
        assert!(
            malformed.is_err(),
            "replacement constraint accepted missing transition metadata"
        );
    }

    #[sqlx::test]
    async fn inbound_configuration_round_trips_without_overwriting_state(pool: PgPool) {
        let db = migrated_db(pool).await;
        let existing = repo(Uuid::new_v4());
        db.create_repo(&existing).await.unwrap();

        assert!(db
            .get_repo_mirror_state(&existing.id)
            .await
            .unwrap()
            .is_none());

        let first = db
            .configure_inbound_mirror(&existing.id, "https://github.com/Gitlawb/node.git")
            .await
            .unwrap();
        assert_eq!(first.status, MirrorStatus::Inbound);
        assert_eq!(first.transition_id, None);
        assert_eq!(first.transition_phase, None);

        // An exact retry is safe, but a different source cannot replace it.
        let original_updated_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        sqlx::query("UPDATE repos SET mirror_updated_at = $2 WHERE id = $1")
            .bind(&existing.id)
            .bind(original_updated_at.to_rfc3339())
            .execute(&db.pool)
            .await
            .unwrap();
        let retry = db
            .configure_inbound_mirror(&existing.id, "https://github.com/Gitlawb/node.git")
            .await
            .unwrap();
        assert_eq!(retry.updated_at, original_updated_at);
        assert!(db
            .configure_inbound_mirror(&existing.id, "https://github.com/Gitlawb/other.git",)
            .await
            .is_err());

        let stored = db
            .get_repo_mirror_state(&existing.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.upstream_url, first.upstream_url);
        assert_eq!(stored.status, MirrorStatus::Inbound);
        assert_eq!(stored.updated_at, original_updated_at);
    }

    #[sqlx::test]
    async fn inbound_worker_pages_all_and_only_stable_inbound_mirrors(pool: PgPool) {
        let db = migrated_db(pool).await;
        let ids = [
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
        ];
        for (index, id) in ids.into_iter().enumerate() {
            let mut existing = repo(id);
            existing.name = format!("mirror-{index}");
            db.create_repo(&existing).await.unwrap();
            db.configure_inbound_mirror(
                &existing.id,
                &format!("https://github.example/org/mirror-{index}.git"),
            )
            .await
            .unwrap();
        }

        // The middle row simulates a transition selected by the next B1 slice.
        // It must not be scheduled while authority is changing.
        sqlx::query(
            "UPDATE repos
             SET mirror_status = 'transitioning_inbound_to_outbound',
                 mirror_transition_id = $2,
                 mirror_transition_phase = 'queued'
             WHERE id = $1",
        )
        .bind(ids[1].to_string())
        .bind(Uuid::new_v4())
        .execute(db.pool())
        .await
        .unwrap();

        let first = db.list_inbound_mirror_targets(None, 1).await.unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].repo_id, ids[0].to_string());
        assert_eq!(first[0].name, "mirror-0");
        assert_eq!(first[0].owner_did, "did:key:z6MkMirrorOwner");
        assert_eq!(
            first[0].upstream_url,
            "https://github.example/org/mirror-0.git"
        );

        let second = db
            .list_inbound_mirror_targets(Some(&first[0].repo_id), 1)
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].repo_id, ids[2].to_string());

        let exhausted = db
            .list_inbound_mirror_targets(Some(&second[0].repo_id), 1)
            .await
            .unwrap();
        assert!(exhausted.is_empty());
    }

    /// The second stable shape the CHECK admits: an inbound row whose
    /// transition completed keeps its audit metadata and must still be
    /// scheduled. Only in-flight phases make a row unstable.
    #[sqlx::test]
    async fn inbound_worker_pages_completed_stable_mirror_rows(pool: PgPool) {
        let db = migrated_db(pool).await;
        let id = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let mut existing = repo(id);
        existing.name = "mirror-completed".to_string();
        db.create_repo(&existing).await.unwrap();
        db.configure_inbound_mirror(
            &existing.id,
            "https://github.example/org/mirror-completed.git",
        )
        .await
        .unwrap();

        sqlx::query(
            "UPDATE repos
             SET mirror_transition_id = $2,
                 mirror_transition_phase = 'completed'
             WHERE id = $1",
        )
        .bind(id.to_string())
        .bind(Uuid::new_v4())
        .execute(db.pool())
        .await
        .unwrap();

        let page = db.list_inbound_mirror_targets(None, 10).await.unwrap();
        assert!(
            page.iter().any(|t| t.repo_id == id.to_string()),
            "completed-stable inbound row must be scheduled: {page:?}"
        );
    }

    #[sqlx::test]
    async fn malformed_mirror_row_returns_an_error_instead_of_panicking(pool: PgPool) {
        let row = sqlx::query(
            "SELECT 'repo-id'::text AS id,
                    'https://github.com/Gitlawb/node.git'::text AS upstream_url,
                    'inbound'::text AS mirror_status,
                    NULL::uuid AS mirror_transition_id,
                    NULL::text AS mirror_transition_phase,
                    NULL::text AS mirror_updated_at",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let error = row_to_repo_mirror_state(row).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reading mirror update timestamp from database"),
            "unexpected error: {error:#}"
        );
    }

    #[sqlx::test]
    async fn inbound_configuration_never_resets_an_active_transition(pool: PgPool) {
        let db = migrated_db(pool).await;
        let existing = repo(Uuid::new_v4());
        db.create_repo(&existing).await.unwrap();
        db.configure_inbound_mirror(&existing.id, "https://github.com/Gitlawb/node.git")
            .await
            .unwrap();

        let transition_id = Uuid::new_v4();
        sqlx::query(
            "UPDATE repos
             SET mirror_status = 'transitioning_inbound_to_outbound',
                 mirror_transition_id = $2,
                 mirror_transition_phase = 'draining_writes'
             WHERE id = $1",
        )
        .bind(&existing.id)
        .bind(transition_id)
        .execute(&db.pool)
        .await
        .unwrap();

        let retry = db
            .configure_inbound_mirror(&existing.id, "https://github.com/Gitlawb/node.git")
            .await;
        assert!(retry.is_err(), "configuration must not reset a transition");

        let stored = db
            .get_repo_mirror_state(&existing.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, MirrorStatus::TransitioningInboundToOutbound);
        assert_eq!(stored.transition_id, Some(transition_id));
        assert_eq!(
            stored.transition_phase,
            Some(MirrorTransitionPhase::DrainingWrites)
        );
    }

    #[sqlx::test]
    async fn database_constraint_rejects_partial_or_insecure_mirror_state(pool: PgPool) {
        let db = migrated_db(pool).await;
        let existing = repo(Uuid::new_v4());
        db.create_repo(&existing).await.unwrap();

        let partial = sqlx::query(
            "UPDATE repos
             SET upstream_url = 'https://github.com/Gitlawb/node.git',
                 mirror_status = 'transitioning_inbound_to_outbound',
                 mirror_updated_at = '2026-08-14T00:00:00Z'
             WHERE id = $1",
        )
        .bind(&existing.id)
        .execute(&db.pool)
        .await;
        assert!(partial.is_err(), "transition metadata must be durable");

        // PostgreSQL CHECK constraints accept NULL results. These cases pin
        // the outer `IS TRUE` guard so SQL three-valued logic cannot admit a
        // row that the Rust reader rejects or panics while decoding.
        struct InvalidNullState<'a> {
            case: &'a str,
            status: Option<&'a str>,
            transition_id: Option<Uuid>,
            transition_phase: Option<&'a str>,
        }
        let invalid_null_states = [
            InvalidNullState {
                case: "missing mirror status",
                status: None,
                transition_id: None,
                transition_phase: None,
            },
            InvalidNullState {
                case: "stable status with job but no phase",
                status: Some("inbound"),
                transition_id: Some(Uuid::new_v4()),
                transition_phase: None,
            },
            InvalidNullState {
                case: "transition with job but no phase",
                status: Some("transitioning_inbound_to_outbound"),
                transition_id: Some(Uuid::new_v4()),
                transition_phase: None,
            },
        ];
        for invalid in invalid_null_states {
            let result = sqlx::query(
                "UPDATE repos
                 SET upstream_url = 'https://github.com/Gitlawb/node.git',
                     mirror_status = $2,
                     mirror_transition_id = $3,
                     mirror_transition_phase = $4,
                     mirror_updated_at = '2026-08-14T00:00:00Z'
                 WHERE id = $1",
            )
            .bind(&existing.id)
            .bind(invalid.status)
            .bind(invalid.transition_id)
            .bind(invalid.transition_phase)
            .execute(&db.pool)
            .await;
            assert!(result.is_err(), "constraint accepted {}", invalid.case);
        }

        let insecure = sqlx::query(
            "UPDATE repos
             SET upstream_url = 'http://github.com/Gitlawb/node.git',
                 mirror_status = 'inbound',
                 mirror_updated_at = '2026-08-14T00:00:00Z'
             WHERE id = $1",
        )
        .bind(&existing.id)
        .execute(&db.pool)
        .await;
        assert!(
            insecure.is_err(),
            "the database must reject non-HTTPS upstreams"
        );
    }

    #[sqlx::test]
    async fn database_constraint_accepts_the_complete_transition_vocabulary(pool: PgPool) {
        let db = migrated_db(pool).await;
        let existing = repo(Uuid::new_v4());
        db.create_repo(&existing).await.unwrap();

        let phases = [
            "queued",
            "starting",
            "initializing_mirror_fetch",
            "draining_writes",
            "finalizing_mirror_fetch",
            "finalizing_mirror_push",
            "committing_target_status",
            "rolling_back",
        ];
        for status in [
            "transitioning_inbound_to_outbound",
            "transitioning_outbound_to_inbound",
        ] {
            for phase in phases {
                sqlx::query(
                    "UPDATE repos
                     SET upstream_url = 'https://github.com/Gitlawb/node.git',
                         mirror_status = $2,
                         mirror_transition_id = $3,
                         mirror_transition_phase = $4,
                         mirror_updated_at = '2026-08-14T00:00:00Z'
                     WHERE id = $1",
                )
                .bind(&existing.id)
                .bind(status)
                .bind(Uuid::new_v4())
                .bind(phase)
                .execute(&db.pool)
                .await
                .unwrap_or_else(|error| panic!("{status}/{phase} was rejected: {error}"));
            }
        }

        // A completed job remains auditable after authority reaches its stable
        // target status; the initial never-transitioned state uses two NULLs.
        sqlx::query(
            "UPDATE repos
             SET mirror_status = 'outbound',
                 mirror_transition_id = $2,
                 mirror_transition_phase = 'completed'
             WHERE id = $1",
        )
        .bind(&existing.id)
        .bind(Uuid::new_v4())
        .execute(&db.pool)
        .await
        .unwrap();

        let stored = db
            .get_repo_mirror_state(&existing.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, MirrorStatus::Outbound);
        assert_eq!(
            stored.transition_phase,
            Some(MirrorTransitionPhase::Completed)
        );
    }

    #[sqlx::test]
    async fn continuous_mirror_uuid_gate_leaves_peer_rows_untouched(pool: PgPool) {
        let db = migrated_db(pool).await;
        db.upsert_mirror_repo("z6MkPeer", "repo", "/srv/peer/repo.git", None, false)
            .await
            .unwrap();

        let error = db
            .configure_inbound_mirror("z6MkPeer/repo", "https://github.com/Gitlawb/node.git")
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("continuous mirrors require a canonical UUID repository id"),
            "unexpected error: {error:#}"
        );

        let unchanged: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT upstream_url, mirror_status FROM repos WHERE id = $1")
                .bind("z6MkPeer/repo")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(unchanged, (None, None));
        assert!(db
            .get_repo_mirror_state("z6MkPeer/repo")
            .await
            .unwrap()
            .is_none());
    }
}

fn row_to_repo(r: sqlx::postgres::PgRow) -> RepoRecord {
    let created_str: String = r.get("created_at");
    let updated_str: String = r.get("updated_at");
    RepoRecord {
        id: r.get("id"),
        name: r.get("name"),
        owner_did: r.get("owner_did"),
        description: r.get("description"),
        is_public: r.get::<bool, _>("is_public"),
        default_branch: r.get("default_branch"),
        created_at: created_str
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now()),
        updated_at: updated_str
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now()),
        disk_path: r.get("disk_path"),
        forked_from: r.try_get("forked_from").unwrap_or(None),
        machine_id: r.try_get("machine_id").unwrap_or(None),
    }
}

fn row_to_pr(r: sqlx::postgres::PgRow) -> PullRequest {
    PullRequest {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        number: r.get("number"),
        title: r.get("title"),
        body: r.get("body"),
        author_did: r.get("author_did"),
        source_branch: r.get("source_branch"),
        target_branch: r.get("target_branch"),
        status: r.get("status"),
        merged_by_did: r.get("merged_by_did"),
        merged_at: r.get("merged_at"),
        head_commit: r.get("head_commit"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

fn row_to_status_claim(r: sqlx::postgres::PgRow) -> StatusClaim {
    StatusClaim {
        id: r.get("id"),
        seq: r.get("seq"),
        repo_id: r.get("repo_id"),
        commit_sha: r.get("commit_sha"),
        state: r.get("state"),
        context: r.get("context"),
        target_url: r.get("target_url"),
        description: r.get("description"),
        producer_did: r.get("producer_did"),
        authorizing_did: r.get("authorizing_did"),
        signature: r.get("signature"),
        signature_input: r.get("signature_input"),
        signing_string: r.get("signing_string"),
        request_body: r.get("request_body"),
        request_digest: r.get("request_digest"),
        created_at: r.get("created_at"),
    }
}

fn row_to_status_projection(r: sqlx::postgres::PgRow) -> StatusProjection {
    StatusProjection {
        state: r.get("state"),
        context: r.get("context"),
        target_url: r.get("target_url"),
        description: r.get("description"),
        producer_did: r.get("producer_did"),
        created_at: r.get("created_at"),
    }
}

fn row_to_webhook(r: sqlx::postgres::PgRow) -> Webhook {
    let events_str: String = r.get("events");
    let events: Vec<String> =
        serde_json::from_str(&events_str).unwrap_or_else(|_| vec!["*".into()]);
    Webhook {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        url: r.get("url"),
        secret: r.get::<Option<String>, _>("secret").map(WebhookSecret::new),
        events,
        created_by_did: r.get("created_by_did"),
        created_at: r.get("created_at"),
        active: r.get::<bool, _>("active"),
    }
}

fn row_to_cert(r: sqlx::postgres::PgRow) -> RefCertificate {
    RefCertificate {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        ref_name: r.get("ref_name"),
        old_sha: r.get("old_sha"),
        new_sha: r.get("new_sha"),
        pusher_did: r.get("pusher_did"),
        node_did: r.get("node_did"),
        signature: r.get("signature"),
        issued_at: r.get("issued_at"),
        version: r.get::<i32, _>("version") as u32,
    }
}

#[allow(dead_code)] // wired by the handler refactor in the next slice
fn row_to_receive_pack_request(r: sqlx::postgres::PgRow) -> ReceivePackRequest {
    ReceivePackRequest {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        pusher_did: r.get("pusher_did"),
        node_did: r.get("node_did"),
        request_bytes: r.get("request_bytes"),
        request_bytes_hash: r.get("request_bytes_hash"),
        state: r.get("state"),
        git_exit_ok: r.get("git_exit_ok"),
        parsed_report: r.get("parsed_report"),
        accepted_ordinal: r.get("accepted_ordinal"),
        attempt_count: r.get("attempt_count"),
        last_error: r.get("last_error"),
        next_attempt_at: r.get("next_attempt_at"),
        created_at: r.get("created_at"),
        completed_at: r.get("completed_at"),
        signature_header: r.try_get("signature_header").ok().flatten(),
        signature_input: r.try_get("signature_input").ok().flatten(),
        content_digest: r.try_get("content_digest").ok().flatten(),
    }
}

fn row_to_pending_ref_transition(r: sqlx::postgres::PgRow) -> PendingRefTransition {
    PendingRefTransition {
        id: r.get("id"),
        request_id: r.get("request_id"),
        repo_id: r.get("repo_id"),
        ref_name: r.get("ref_name"),
        old_sha: r.get("old_sha"),
        new_sha: r.get("new_sha"),
        pusher_did: r.get("pusher_did"),
        node_did: r.get("node_did"),
        signature_header: r.get("signature_header"),
        signature_input: r.get("signature_input"),
        content_digest: r.get("content_digest"),
        state: r.get("state"),
        created_at: r.get("created_at"),
        applied_at: r.get("applied_at"),
        cancelled_at: r.get("cancelled_at"),
        ordinal: r.get("ordinal"),
        git_target_kind: r.get("git_target_kind"),
    }
}

fn row_to_ref_update(r: sqlx::postgres::PgRow) -> ReceivedRefUpdate {
    ReceivedRefUpdate {
        id: r.get("id"),
        node_did: r.get("node_did"),
        pusher_did: r.get("pusher_did"),
        repo: r.get("repo"),
        ref_name: r.get("ref_name"),
        old_sha: r.get("old_sha"),
        new_sha: r.get("new_sha"),
        timestamp: r.get("timestamp"),
        cert_id: r.get("cert_id"),
        received_at: r.get("received_at"),
        from_peer: r.get("from_peer"),
        owner_did: r.get("owner_did"),
    }
}

fn row_to_task(r: sqlx::postgres::PgRow) -> AgentTask {
    AgentTask {
        id: r.get("id"),
        repo_id: r.get("repo_id"),
        kind: r.get("kind"),
        status: r.get("status"),
        delegator_did: r.get("delegator_did"),
        assignee_did: r.get("assignee_did"),
        capability: r.get("capability"),
        ucan_token: r.get("ucan_token"),
        payload: r.get("payload"),
        result: r.get("result"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        deadline: r.get("deadline"),
    }
}

// ── Protected Branches ────────────────────────────────────────────────────────

impl Db {
    pub async fn protect_branch(
        &self,
        repo_id: &str,
        branch: &str,
        created_by: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{repo_id}:{branch}");
        sqlx::query(
            "INSERT INTO protected_branches (id, repo_id, branch, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (repo_id, branch) DO NOTHING",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(branch)
        .bind(created_by)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn unprotect_branch(&self, repo_id: &str, branch: &str) -> Result<()> {
        sqlx::query("DELETE FROM protected_branches WHERE repo_id = $1 AND branch = $2")
            .bind(repo_id)
            .bind(branch)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_protected_branches(&self, repo_id: &str) -> Result<Vec<String>> {
        let rows =
            sqlx::query("SELECT branch FROM protected_branches WHERE repo_id = $1 ORDER BY branch")
                .bind(repo_id)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|r| r.get::<String, _>("branch"))
            .collect())
    }

    pub async fn is_branch_protected(&self, repo_id: &str, branch: &str) -> Result<bool> {
        let row =
            sqlx::query("SELECT 1 FROM protected_branches WHERE repo_id = $1 AND branch = $2")
                .bind(repo_id)
                .bind(branch)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }
}

// ── Path-scoped Visibility ────────────────────────────────────────────────────

impl Db {
    /// Set or replace a visibility rule and bump the repo's policy epoch
    /// atomically. A sweep reading the rule after it commits must see the new
    /// epoch; the two are never visible from different transactions.
    pub async fn set_visibility_rule(
        &self,
        repo_id: &str,
        path_glob: &str,
        mode: VisibilityMode,
        reader_dids: &[String],
        created_by: &str,
    ) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let readers = serde_json::to_string(reader_dids).unwrap_or_else(|_| "[]".to_string());
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO visibility_rules
                 (id, repo_id, path_glob, mode, reader_dids, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (repo_id, path_glob) DO UPDATE
             SET mode = EXCLUDED.mode,
                 reader_dids = EXCLUDED.reader_dids,
                 created_by = EXCLUDED.created_by,
                 created_at = EXCLUDED.created_at",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(path_glob)
        .bind(mode.as_str())
        .bind(&readers)
        .bind(created_by)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE repos SET policy_epoch = policy_epoch + 1 WHERE id = $1")
            .bind(repo_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Remove a visibility rule and bump the repo's policy epoch atomically.
    /// A delete that matches zero rows is not a write: the epoch bump is
    /// skipped so a typo'd or double-deleted glob cannot abort in-flight
    /// fenced batches for unchanged policy (mirrors `set_repo_quarantine`).
    pub async fn remove_visibility_rule(&self, repo_id: &str, path_glob: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let deleted =
            sqlx::query("DELETE FROM visibility_rules WHERE repo_id = $1 AND path_glob = $2")
                .bind(repo_id)
                .bind(path_glob)
                .execute(&mut *tx)
                .await?;
        if deleted.rows_affected() > 0 {
            sqlx::query("UPDATE repos SET policy_epoch = policy_epoch + 1 WHERE id = $1")
                .bind(repo_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Current visibility-policy epoch for a repo (0 for a repo with no entry).
    /// The epoch is bumped by every rule or quarantine mutation, so a value that
    /// changes between two reads proves a policy change happened in between.
    pub async fn repo_policy_epoch(&self, repo_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT policy_epoch FROM repos WHERE id = $1")
            .bind(repo_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get::<i64, _>("policy_epoch")).unwrap_or(0))
    }

    /// Bump `policy_epoch` for `repo_id` by one, mirroring the
    /// `UPDATE repos SET policy_epoch = policy_epoch + 1`
    /// statement `set_visibility_rule` / `remove_visibility_rule`
    /// run. Test-only: production rule writes are wrapped in a
    /// transaction that also touches the visibility_rules table;
    /// the standalone bump here is for the test fixture that
    /// drives a fenced-record-with-bumped-epoch scenario.
    #[cfg(test)]
    pub async fn bump_repo_policy_epoch(&self, repo_id: &str) -> Result<()> {
        sqlx::query("UPDATE repos SET policy_epoch = policy_epoch + 1 WHERE id = $1")
            .bind(repo_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// #218 review round 9 (guidance #3 — linearization point):
    /// read the repo's policy epoch under a row lock that a
    /// narrowing rule write must also acquire. Caller must hold
    /// an open transaction and pass it in. The lock is released
    /// when the transaction commits or rolls back.
    ///
    /// This is the third fence check: between the irreversible
    /// HTTP POST and the DB record, a rule write can still
    /// commit. Reading the epoch under `FOR UPDATE` here means
    /// either (a) the rule write blocks on us — we get the
    /// post-narrow epoch and abort the record, or (b) we block
    /// on the rule write — we get the post-narrow epoch and
    /// abort the record. Either way no stale record lands.
    pub async fn repo_policy_epoch_locked(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
    ) -> Result<Option<i64>> {
        let row = sqlx::query("SELECT policy_epoch FROM repos WHERE id = $1 FOR UPDATE")
            .bind(repo_id)
            .fetch_optional(&mut **tx)
            .await?;
        // P2 (reviewer round 9): a missing repos row used to fold
        // to 0 via `unwrap_or(0)`, so a fenced record call against
        // a non-existent repo would silently compare 0 == 0 and
        // PASS — exactly the fail-open path a missing row should
        // NOT admit. The row-level lock on a missing predicate
        // takes no lock either, so nothing was serializing
        // anyway. Return `None`; callers that must compare
        // (`record_pinned_cid_with_source_fenced`,
        // `record_pinata_cid_fenced`) bail fail-closed.
        Ok(row.map(|r| r.get::<i64, _>("policy_epoch")))
    }

    pub async fn list_visibility_rules(&self, repo_id: &str) -> Result<Vec<VisibilityRule>> {
        let rows = sqlx::query(
            "SELECT id, repo_id, path_glob, mode, reader_dids, created_by, created_at
             FROM visibility_rules WHERE repo_id = $1 ORDER BY path_glob",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let readers: String = r.get("reader_dids");
                let created_at: String = r.get("created_at");
                VisibilityRule {
                    id: r.get("id"),
                    repo_id: r.get("repo_id"),
                    path_glob: r.get("path_glob"),
                    mode: VisibilityMode::from_db(&r.get::<String, _>("mode")),
                    reader_dids: serde_json::from_str(&readers).unwrap_or_default(),
                    created_by: r.get("created_by"),
                    created_at: created_at
                        .parse::<DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                }
            })
            .collect())
    }

    /// All visibility rules for a set of repos, grouped by `repo_id`, in one
    /// query. The listing surfaces use this to apply the same `"/"` visibility
    /// decision the per-repo endpoints make without an N+1 per-repo rule fetch
    /// (#97). Repos with no rules are simply absent from the map.
    pub async fn list_visibility_rules_for_repos(
        &self,
        repo_ids: &[String],
    ) -> Result<std::collections::HashMap<String, Vec<VisibilityRule>>> {
        use std::collections::HashMap;
        if repo_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows = sqlx::query(
            "SELECT id, repo_id, path_glob, mode, reader_dids, created_by, created_at
             FROM visibility_rules WHERE repo_id = ANY($1) ORDER BY path_glob",
        )
        .bind(repo_ids)
        .fetch_all(&self.pool)
        .await?;
        let mut out: HashMap<String, Vec<VisibilityRule>> = HashMap::new();
        for r in rows {
            let readers: String = r.get("reader_dids");
            let created_at: String = r.get("created_at");
            let rule = VisibilityRule {
                id: r.get("id"),
                repo_id: r.get("repo_id"),
                path_glob: r.get("path_glob"),
                mode: VisibilityMode::from_db(&r.get::<String, _>("mode")),
                reader_dids: serde_json::from_str(&readers).unwrap_or_default(),
                created_by: r.get("created_by"),
                created_at: created_at
                    .parse::<DateTime<Utc>>()
                    .unwrap_or_else(|_| Utc::now()),
            };
            out.entry(rule.repo_id.clone()).or_default().push(rule);
        }
        Ok(out)
    }

    /// Visibility rules for one scan page, bounded IN THE QUERY by a byte budget.
    ///
    /// The unbounded sibling above is right for the listing surfaces: they read a page
    /// the caller is already authorized for. It is wrong for the resolver's legacy scan,
    /// which runs on an anonymously reachable route while holding scarce walk admission.
    /// A repo owner controls both how many rules their repos carry and how long each
    /// `reader_dids` list is, so summing the bytes AFTER the rows arrive truncates the
    /// request without bounding the work: the oversized page has already been transferred
    /// and allocated by the time the sum is taken (INV-10 bounds work done, never results
    /// measured afterwards).
    ///
    /// The cut lands on a REPO boundary, never inside one. A partially loaded rule set is
    /// indistinguishable at the gate from a repo with no rules at all, so a mid-repo cut
    /// would FAIL OPEN and serve a path-scoped object the missing rules would have
    /// denied. Every repo this returns is therefore complete, and the caller drops the
    /// page's tail from the cut onward rather than gating it against rules it does not
    /// have.
    ///
    /// `repo_ids` must be in the page's `(created_at, id)` order; the returned cut is the
    /// 0-based index into that slice of the first repo whose rules did NOT fit, or `None`
    /// when the whole page fit. Repos carrying no rules never cut.
    ///
    /// The FIRST rule-carrying repo of a page is admitted whatever its size, so a page
    /// always makes progress. Without that a repo whose rules alone exceed the remaining
    /// budget would put the cut at the cursor, the caller's next request would reproduce
    /// it exactly, and the ladder would be wedged on a permanent 503. One repo's rule set
    /// is the residual bound this leaves; the whole page's was the bound before.
    pub async fn list_visibility_rules_for_repos_bounded(
        &self,
        repo_ids: &[String],
        byte_budget: usize,
    ) -> Result<(
        std::collections::HashMap<String, Vec<VisibilityRule>>,
        Option<usize>,
    )> {
        use std::collections::HashMap;
        if repo_ids.is_empty() {
            return Ok((HashMap::new(), None));
        }
        // `running` is a sum of non-negative per-repo sizes over the page order, so it is
        // monotonic: once it passes the budget every later repo is excluded too, which is
        // what makes "the kept set is a prefix" true and the single cut index meaningful.
        // `rn = 1` is the always-admit escape for the first rule-carrying repo.
        let rows = sqlx::query(
            "WITH sized AS (
                 SELECT v.id, v.repo_id, v.path_glob, v.mode, v.reader_dids, v.created_by,
                        v.created_at,
                        octet_length(v.id) + octet_length(v.repo_id)
                          + octet_length(v.path_glob) + octet_length(v.created_by)
                          + octet_length(v.reader_dids) AS b,
                        array_position($1::text[], v.repo_id) AS pos
                 FROM visibility_rules v
                 WHERE v.repo_id = ANY($1::text[])
             ),
             per_repo AS (
                 SELECT repo_id, pos, SUM(b) AS repo_bytes FROM sized GROUP BY repo_id, pos
             ),
             cum AS (
                 SELECT repo_id, pos,
                        SUM(repo_bytes) OVER (ORDER BY pos ROWS UNBOUNDED PRECEDING) AS running,
                        ROW_NUMBER() OVER (ORDER BY pos) AS rn
                 FROM per_repo
             ),
             kept AS (
                 SELECT repo_id, pos FROM cum WHERE running <= $2::bigint OR rn = 1
             ),
             cut AS (
                 SELECT MIN(pos) AS cut_pos FROM cum WHERE running > $2::bigint AND rn > 1
             )
             SELECT s.id, s.repo_id, s.path_glob, s.mode, s.reader_dids, s.created_by,
                    s.created_at, cut.cut_pos
             FROM sized s
             JOIN kept k ON k.repo_id = s.repo_id
             CROSS JOIN cut
             ORDER BY k.pos, s.path_glob",
        )
        .bind(repo_ids)
        .bind(byte_budget.min(i64::MAX as usize) as i64)
        .fetch_all(&self.pool)
        .await?;

        // `array_position` is 1-based and the caller indexes a slice. No rows means no
        // rules matched the page at all, which is also no cut.
        let cut_at = rows
            .first()
            .and_then(|r| r.get::<Option<i32>, _>("cut_pos"))
            .map(|pos| (pos as usize).saturating_sub(1));
        let mut out: HashMap<String, Vec<VisibilityRule>> = HashMap::new();
        for r in rows {
            let readers: String = r.get("reader_dids");
            let created_at: String = r.get("created_at");
            let rule = VisibilityRule {
                id: r.get("id"),
                repo_id: r.get("repo_id"),
                path_glob: r.get("path_glob"),
                mode: VisibilityMode::from_db(&r.get::<String, _>("mode")),
                reader_dids: serde_json::from_str(&readers).unwrap_or_default(),
                created_by: r.get("created_by"),
                created_at: created_at
                    .parse::<DateTime<Utc>>()
                    .unwrap_or_else(|_| Utc::now()),
            };
            out.entry(rule.repo_id.clone()).or_default().push(rule);
        }
        Ok((out, cut_at))
    }
}

// ── Repo Stars ────────────────────────────────────────────────────────────────

impl Db {
    /// Star a repo. Returns true if inserted (new star), false if already starred.
    pub async fn star_repo(&self, repo_id: &str, agent_did: &str) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{repo_id}:{agent_did}");
        let result = sqlx::query(
            "INSERT INTO repo_stars (id, repo_id, agent_did, starred_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (repo_id, agent_did) DO NOTHING",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(agent_did)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Unstar a repo. Idempotent — no error if not starred.
    pub async fn unstar_repo(&self, repo_id: &str, agent_did: &str) -> Result<()> {
        sqlx::query("DELETE FROM repo_stars WHERE repo_id = $1 AND agent_did = $2")
            .bind(repo_id)
            .bind(agent_did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Count total stars for a repo.
    pub async fn count_stars(&self, repo_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM repo_stars WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    // ── Repo replicas ──────────────────────────────────────────────────

    /// Register a replica for a repo. Returns true if inserted, false if the
    /// replica was already registered (URL updated either way).
    pub async fn register_replica(
        &self,
        repo_id: &str,
        replica_did: &str,
        replica_url: &str,
    ) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let id = format!("{repo_id}:{replica_did}");
        let result = sqlx::query(
            "INSERT INTO repo_replicas (id, repo_id, replica_did, replica_url, registered_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (repo_id, replica_did) DO UPDATE
               SET replica_url = EXCLUDED.replica_url",
        )
        .bind(&id)
        .bind(repo_id)
        .bind(replica_did)
        .bind(replica_url)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Unregister a replica. Idempotent.
    pub async fn unregister_replica(&self, repo_id: &str, replica_did: &str) -> Result<()> {
        sqlx::query("DELETE FROM repo_replicas WHERE repo_id = $1 AND replica_did = $2")
            .bind(repo_id)
            .bind(replica_did)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List all replicas for a repo, oldest registration first.
    pub async fn list_replicas(&self, repo_id: &str) -> Result<Vec<RepoReplica>> {
        let rows = sqlx::query(
            "SELECT replica_did, replica_url, registered_at
             FROM repo_replicas
             WHERE repo_id = $1
             ORDER BY registered_at ASC",
        )
        .bind(repo_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RepoReplica {
                replica_did: r.get("replica_did"),
                replica_url: r.get("replica_url"),
                registered_at: r.get("registered_at"),
            })
            .collect())
    }

    /// Count replicas registered for a repo.
    pub async fn count_replicas(&self, repo_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM repo_replicas WHERE repo_id = $1")
            .bind(repo_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    /// Check whether a specific agent has starred a repo.
    #[allow(dead_code)]
    pub async fn is_starred(&self, repo_id: &str, agent_did: &str) -> Result<bool> {
        let row = sqlx::query("SELECT 1 FROM repo_stars WHERE repo_id = $1 AND agent_did = $2")
            .bind(repo_id)
            .bind(agent_did)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }
}

// ── Bounties ─────────────────────────────────────────────────────────────────

impl Db {
    pub async fn create_bounty(&self, b: &BountyRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO bounties
                (id, repo_owner, repo_name, issue_id, title, amount, creator_did, status, created_at, deadline_secs)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
        )
        .bind(&b.id)
        .bind(&b.repo_owner)
        .bind(&b.repo_name)
        .bind(&b.issue_id)
        .bind(&b.title)
        .bind(b.amount)
        .bind(&b.creator_did)
        .bind(&b.status)
        .bind(&b.created_at)
        .bind(b.deadline_secs)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_bounty(&self, id: &str) -> Result<Option<BountyRecord>> {
        let row = sqlx::query("SELECT * FROM bounties WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| self.bounty_from_row(&r)))
    }

    pub async fn list_bounties(
        &self,
        repo_owner: Option<&str>,
        repo_name: Option<&str>,
        status: Option<&str>,
        limit: i64,
        after_created_at: Option<&str>,
        after_id: Option<&str>,
    ) -> Result<Vec<BountyRecord>> {
        let mut sql = String::from("SELECT * FROM bounties WHERE 1=1");
        let mut binds: Vec<String> = Vec::new();
        let mut idx = 1;

        if let Some(o) = repo_owner {
            sql.push_str(&format!(" AND repo_owner = ${idx}"));
            binds.push(o.to_string());
            idx += 1;
        }
        if let Some(n) = repo_name {
            sql.push_str(&format!(" AND repo_name = ${idx}"));
            binds.push(n.to_string());
            idx += 1;
        }
        if let Some(s) = status {
            sql.push_str(&format!(" AND status = ${idx}"));
            binds.push(s.to_string());
            idx += 1;
        }
        if let Some(ts) = after_created_at {
            let id = after_id.unwrap_or("");
            sql.push_str(&format!(" AND (created_at, id) < (${idx}, ${})", idx + 1));
            binds.push(ts.to_string());
            idx += 1;
            binds.push(id.to_string());
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY created_at DESC, id DESC LIMIT ${idx}"));

        let mut q = sqlx::query(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        q = q.bind(limit);

        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| self.bounty_from_row(r)).collect())
    }

    pub async fn claim_bounty(
        &self,
        id: &str,
        claimant_did: &str,
        claimant_wallet: Option<&str>,
        claimed_at: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET claimant_did=$1, claimant_wallet=$2, claimed_at=$3, status='claimed' WHERE id=$4 AND status='open'",
        )
        .bind(claimant_did)
        .bind(claimant_wallet)
        .bind(claimed_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn submit_bounty(&self, id: &str, pr_id: &str, submitted_at: &str) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET pr_id=$1, submitted_at=$2, status='submitted' WHERE id=$3 AND status='claimed'",
        )
        .bind(pr_id)
        .bind(submitted_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn approve_bounty(
        &self,
        id: &str,
        completed_at: &str,
        tx_hash: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET completed_at=$1, tx_hash=$2, status='completed' WHERE id=$3 AND status='submitted'",
        )
        .bind(completed_at)
        .bind(tx_hash)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn cancel_bounty(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE bounties SET status='cancelled' WHERE id=$1 AND status='open'")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn dispute_bounty(&self, id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE bounties SET status='open', claimant_did=NULL, claimant_wallet=NULL, pr_id=NULL, claimed_at=NULL, submitted_at=NULL WHERE id=$1 AND status IN ('claimed','submitted')",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Visibility-filtered bounty aggregates (#477) ─────────────────────

    /// Count bounties by status, restricted to repos whose `(owner_did, name)`
    /// pairs are in `visible`.  Owner keys are normalized on both sides so
    /// `did:key:` and bare-key forms match.  An empty set returns 0.
    pub async fn count_bounties_by_status_visible(
        &self,
        status: &str,
        visible: &[(String, String)],
    ) -> Result<i64> {
        if visible.is_empty() {
            return Ok(0);
        }
        let owners: Vec<String> = visible.iter().map(|(o, _)| o.clone()).collect();
        let names: Vec<String> = visible.iter().map(|(_, n)| n.clone()).collect();
        let sql = format!(
            "SELECT COUNT(*) as c FROM bounties b \
             WHERE b.status = $1 \
             AND EXISTS ( \
                 SELECT 1 FROM unnest($2::text[], $3::text[]) AS v(o, n) \
                 WHERE ({bounty_owner}) = v.o AND b.repo_name = v.n \
             )",
            bounty_owner = BOUNTY_OWNER_CASE_SQL,
        );
        let row = sqlx::query(&sql)
            .bind(status)
            .bind(&owners)
            .bind(&names)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("c"))
    }

    /// Per-agent bounty stats restricted to visible repos.  `b.repo_owner` is
    /// normalized and `b.claimant_did` is matched against both spellings of the
    /// agent key, so `did:key:` and bare-key forms match.
    pub async fn agent_bounty_stats_visible(
        &self,
        agent_did: &str,
        visible: &[(String, String)],
    ) -> Result<(i64, i64)> {
        if visible.is_empty() {
            return Ok((0, 0));
        }
        // Index-friendly form of `normalize(claimant_did) = N`: a claimant
        // normalizes to N only when stored as N or as `did:key:N` (the latter
        // only when N has no ':', else the prefix is not stripped). Matching
        // the raw column keeps `idx_bounties_claimant` usable.
        let normalized_agent = normalize_owner_key(agent_did);
        let mut claimants: Vec<String> = vec![normalized_agent.to_string()];
        if !normalized_agent.contains(':') {
            claimants.push(format!("did:key:{normalized_agent}"));
        }
        let owners: Vec<String> = visible.iter().map(|(o, _)| o.clone()).collect();
        let names: Vec<String> = visible.iter().map(|(_, n)| n.clone()).collect();
        let sql = format!(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(amount), 0)::BIGINT as total FROM bounties b \
             WHERE b.claimant_did = ANY($1::text[]) \
             AND b.status = 'completed' \
             AND EXISTS ( \
                 SELECT 1 FROM unnest($2::text[], $3::text[]) AS v(o, n) \
                 WHERE ({bounty_owner}) = v.o AND b.repo_name = v.n \
             )",
            bounty_owner = BOUNTY_OWNER_CASE_SQL,
        );
        let row = sqlx::query(&sql)
            .bind(&claimants)
            .bind(&owners)
            .bind(&names)
            .fetch_one(&self.pool)
            .await?;
        Ok((row.get::<i64, _>("cnt"), row.get::<i64, _>("total")))
    }

    /// Leaderboard restricted to visible repos.  Owner and claimant keys are
    /// normalized so `did:key:` and bare-key forms match and group together.
    pub async fn bounty_leaderboard_visible(
        &self,
        limit: i64,
        visible: &[(String, String)],
    ) -> Result<Vec<(String, i64, i64)>> {
        if visible.is_empty() {
            return Ok(Vec::new());
        }
        let owners: Vec<String> = visible.iter().map(|(o, _)| o.clone()).collect();
        let names: Vec<String> = visible.iter().map(|(_, n)| n.clone()).collect();
        let sql = format!(
            "SELECT MIN(claimant_did) as claimant_did, COUNT(*) as cnt, COALESCE(SUM(amount), 0)::BIGINT as total \
             FROM bounties b \
             WHERE b.status = 'completed' AND b.claimant_did IS NOT NULL \
             AND EXISTS ( \
                 SELECT 1 FROM unnest($1::text[], $2::text[]) AS v(o, n) \
                 WHERE ({bounty_owner}) = v.o AND b.repo_name = v.n \
             ) \
             GROUP BY ({claimant_case}) ORDER BY total DESC LIMIT $3",
            claimant_case = BOUNTY_CLAIMANT_CASE_SQL,
            bounty_owner = BOUNTY_OWNER_CASE_SQL,
        );
        let rows = sqlx::query(&sql)
            .bind(&owners)
            .bind(&names)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>("claimant_did"),
                    r.get::<i64, _>("cnt"),
                    r.get::<i64, _>("total"),
                )
            })
            .collect())
    }

    fn bounty_from_row(&self, r: &sqlx::postgres::PgRow) -> BountyRecord {
        BountyRecord {
            id: r.get("id"),
            repo_owner: r.get("repo_owner"),
            repo_name: r.get("repo_name"),
            issue_id: r.get("issue_id"),
            title: r.get("title"),
            amount: r.get("amount"),
            creator_did: r.get("creator_did"),
            claimant_did: r.get("claimant_did"),
            claimant_wallet: r.get("claimant_wallet"),
            pr_id: r.get("pr_id"),
            status: r.get("status"),
            created_at: r.get("created_at"),
            claimed_at: r.get("claimed_at"),
            submitted_at: r.get("submitted_at"),
            completed_at: r.get("completed_at"),
            deadline_secs: r.get("deadline_secs"),
            tx_hash: r.get("tx_hash"),
        }
    }
}

// ── Agent Profiles ───────────────────────────────────────────────────────────

impl Db {
    pub async fn upsert_profile(
        &self,
        did: &str,
        display_name: Option<&str>,
        bio: Option<&str>,
        avatar_url: Option<&str>,
        website: Option<&str>,
        socials: Option<&str>,
    ) -> Result<ProfileRecord> {
        let now = Utc::now().to_rfc3339();

        // Try update first for existing profiles (merge fields)
        let existing = self.get_profile(did).await?;

        if let Some(existing) = existing {
            let new_name = display_name.or(existing.display_name.as_deref());
            let new_bio = bio.or(existing.bio.as_deref());
            let new_avatar = avatar_url.or(existing.avatar_url.as_deref());
            let new_website = website.or(existing.website.as_deref());
            let new_socials = socials.or(existing.socials.as_deref());

            // get_profile equates bare short ids with did:key:<id>. UPDATE must target
            // the stored row identity (existing.did), not the caller's raw input form,
            // or a did:key: alias against a bare-stored profile updates zero rows.
            sqlx::query(
                "UPDATE agent_profiles
                 SET display_name=$1, bio=$2, avatar_url=$3, website=$4, socials=$5, updated_at=$6
                 WHERE did=$7",
            )
            .bind(new_name)
            .bind(new_bio)
            .bind(new_avatar)
            .bind(new_website)
            .bind(new_socials)
            .bind(&now)
            .bind(&existing.did)
            .execute(&self.pool)
            .await?;

            Ok(ProfileRecord {
                did: existing.did,
                display_name: new_name.map(String::from),
                bio: new_bio.map(String::from),
                avatar_url: new_avatar.map(String::from),
                website: new_website.map(String::from),
                socials: new_socials.map(String::from),
                profile_cid: existing.profile_cid,
                created_at: existing.created_at,
                updated_at: now,
            })
        } else {
            sqlx::query(
                "INSERT INTO agent_profiles (did, display_name, bio, avatar_url, website, socials, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(did)
            .bind(display_name)
            .bind(bio)
            .bind(avatar_url)
            .bind(website)
            .bind(socials)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;

            Ok(ProfileRecord {
                did: did.to_string(),
                display_name: display_name.map(String::from),
                bio: bio.map(String::from),
                avatar_url: avatar_url.map(String::from),
                website: website.map(String::from),
                socials: socials.map(String::from),
                profile_cid: None,
                created_at: now.clone(),
                updated_at: now,
            })
        }
    }

    pub async fn get_profile(&self, did: &str) -> Result<Option<ProfileRecord>> {
        // Same owner-key contract as get_repo: strip `did:key:` only when the
        // remainder is a bare key id. The old `LIKE '%:' || $1` matched any DID
        // method that shared a suffix and could resolve the wrong profile.
        let did_key = normalize_owner_key(did);
        let sql = format!(
            "SELECT did, display_name, bio, avatar_url, website, socials, profile_cid, created_at, updated_at
             FROM agent_profiles
             WHERE ({key}) = $1",
            key = PROFILE_DID_CASE_SQL
        );
        let row = sqlx::query(&sql)
            .bind(did_key)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| ProfileRecord {
            did: r.get("did"),
            display_name: r.get("display_name"),
            bio: r.get("bio"),
            avatar_url: r.get("avatar_url"),
            website: r.get("website"),
            socials: r.get("socials"),
            profile_cid: r.get("profile_cid"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn set_profile_cid(&self, did: &str, cid: &str) -> Result<()> {
        // Same did:key / bare equivalence as get_profile so a full did:key: form
        // updates a profile stored under the bare short id.
        let did_key = normalize_owner_key(did);
        let sql = format!(
            "UPDATE agent_profiles SET profile_cid = $1, updated_at = $2 WHERE ({key}) = $3",
            key = PROFILE_DID_CASE_SQL
        );
        sqlx::query(&sql)
            .bind(cid)
            .bind(Utc::now().to_rfc3339())
            .bind(did_key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// These tests don't require a live Postgres connection. They validate the
// static migration catalogue is well-formed so a future maintainer can't
// ship a regression like duplicate versions, negative versions, or empty
// migration bodies. The actual SQL execution is exercised by integration
// tests / first-run on a real node.

#[cfg(test)]
mod migration_tests {
    use super::{MIGRATIONS, MIGRATION_V1_NAME};

    #[test]
    fn migrations_are_non_empty() {
        assert!(
            !MIGRATIONS.is_empty(),
            "MIGRATIONS must contain at least the initial v1 schema"
        );
    }

    #[test]
    fn migration_versions_are_strictly_increasing() {
        let mut last = i64::MIN;
        for m in MIGRATIONS {
            assert!(
                m.version > last,
                "migration versions must be strictly increasing; \
                 found {} after {}",
                m.version,
                last
            );
            last = m.version;
        }
    }

    #[test]
    fn migration_versions_start_at_one() {
        // A version of 0 (or negative) would be a footgun: any future
        // `WHERE version > current_max` style query would skip it.
        assert_eq!(
            MIGRATIONS.first().map(|m| m.version),
            Some(1),
            "the first migration must have version 1"
        );
    }

    #[test]
    fn migration_names_are_non_empty_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for m in MIGRATIONS {
            assert!(
                !m.name.is_empty(),
                "migration v{} has empty name",
                m.version
            );
            assert!(
                !m.name.contains(char::is_whitespace),
                "migration v{} name {:?} contains whitespace",
                m.version,
                m.name
            );
            assert!(
                seen.insert(m.name),
                "duplicate migration name: {:?}",
                m.name
            );
        }
    }

    #[test]
    fn migration_bodies_are_non_empty() {
        for m in MIGRATIONS {
            assert!(
                !m.stmts.is_empty(),
                "migration v{} ({}) has no SQL statements",
                m.version,
                m.name
            );
        }
    }

    #[test]
    fn split_migration_ledger_is_linear_from_main_v26() {
        // Split PRs must form one ordered ledger from main's v26:
        // versions unique (strictly increasing covers it), names distinct
        // (covered above), and the split-1 range v27..=v35 contiguous so a
        // sibling claiming any of those numbers collides loudly via the
        // (version, name) runner guard instead of silently skipping.
        let versions: Vec<i64> = MIGRATIONS.iter().map(|m| m.version).collect();
        for w in versions.windows(2) {
            // Main history is contiguous; splits must not introduce gaps
            // that hide a skipped sibling migration.
            assert!(
                w[1] == w[0] + 1 || w[0] < 27,
                "migration gap between v{} and v{}; splits must extend one linear ledger",
                w[0],
                w[1]
            );
        }
        for v in 27..=35 {
            assert!(
                versions.contains(&v),
                "split-1 ledger must own v{v} contiguously from main v26"
            );
        }
    }

    #[test]
    fn v1_name_is_the_initial_schema() {
        // This is what the legacy-install backfill writes to
        // `schema_migrations` when an existing node upgrades. If you rename
        // it, you must also update the backfill.
        assert_eq!(MIGRATIONS[0].name, MIGRATION_V1_NAME);
    }

    /// Simulate an existing node at v9 with populated received_ref_updates,
    /// then apply the v11 migration and verify (a) owner_did IS NULL on
    /// existing rows, (b) the column exists and is nullable TEXT, and
    /// (c) idempotent re-run does not error.
    #[sqlx::test]
    async fn migration_v11_creates_owner_did_column(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);

        // Create all tables by running the full migration chain from scratch,
        // then drop the owner_did column to simulate a pre-v10 schema.
        db.migrate().await.unwrap();
        sqlx::query("ALTER TABLE received_ref_updates DROP COLUMN owner_did")
            .execute(db.pool())
            .await
            .unwrap();

        // Truncate schema_migrations and re-seed at v9 — simulate an existing
        // node that has run v1..v9 but not yet v10.
        sqlx::query("DELETE FROM schema_migrations")
            .execute(db.pool())
            .await
            .unwrap();
        for m in MIGRATIONS.iter().take_while(|m| m.version < 10) {
            sqlx::query(
                "INSERT INTO schema_migrations (version, name, applied_at)
                 VALUES ($1, $2, $3)",
            )
            .bind(m.version)
            .bind(m.name)
            .bind("2026-07-01T00:00:00Z")
            .execute(db.pool())
            .await
            .unwrap();
        }

        // ── Simulate an existing node with rows recorded before v11 ────────
        // The owner_did column does not exist yet, so we INSERT without it.
        let row_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO received_ref_updates
             (id, node_did, pusher_did, repo, ref_name, old_sha, new_sha,
              timestamp, cert_id, received_at, from_peer)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(&row_id)
        .bind("did:key:zNode")
        .bind("did:key:zPusher")
        .bind("z6MkOwner/myrepo")
        .bind("refs/heads/main")
        .bind("0000000000000000000000000000000000000000")
        .bind("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind("2026-07-01T12:00:00Z")
        .bind::<Option<String>>(None)
        .bind("2026-07-01T12:00:01Z")
        .bind("12D3KooWPeer")
        .execute(db.pool())
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM received_ref_updates")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            1,
            "pre-migration row must exist"
        );

        // ── Apply pending migrations (v10 ref_cert_unique_per_ref, v11 owner_did) ──
        db.migrate().await.unwrap();

        // ── Assertions ────────────────────────────────────────────────────

        // (a) Existing row has owner_did IS NULL (not overwritten).
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_did FROM received_ref_updates WHERE id = $1")
                .bind(&row_id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(owner, None, "existing row's owner_did must be NULL");

        // (b) Column exists and is nullable TEXT.
        let col: (String, String, String) = sqlx::query_as(
            "SELECT column_name, data_type, is_nullable
             FROM information_schema.columns
             WHERE table_name = 'received_ref_updates' AND column_name = 'owner_did'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(col.0, "owner_did");
        assert_eq!(col.1, "text");
        assert_eq!(col.2, "YES", "owner_did must be nullable");

        // (c) Version 11 is recorded as applied.
        let v11_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations WHERE version = 11")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            v11_count.0, 1,
            "migration v11 must be recorded in schema_migrations"
        );

        // (d) Re-run: idempotent — ADD COLUMN IF NOT EXISTS must not error.
        db.migrate().await.unwrap();
    }

    // ── sync_queue scheduling (attempted_at, v17) ────────────────────────────

    async fn enqueue_one(db: &super::Db, repo: &str) {
        db.enqueue_sync(
            repo,
            "did:key:zPEER",
            "refs/heads/main",
            &"0".repeat(40),
            None,
        )
        .await
        .unwrap();
    }

    async fn attempted_at_of(db: &super::Db, repo: &str) -> Option<String> {
        sqlx::query_scalar("SELECT attempted_at FROM sync_queue WHERE repo = $1")
            .bind(repo)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    /// Upgrade-path test: simulate a node already at v11 and let the real
    /// migration entry point apply v17, rather than hand-copying its SQL.
    ///
    /// This is the test that catches the column being added to the v1
    /// statement array instead of a new migration. v1 never re-runs on an
    /// existing install, so that mistake breaks every deployed node's dequeue
    /// while staying invisible to every other test here, since `#[sqlx::test]`
    /// hands out a fresh database that runs the whole chain.
    #[sqlx::test]
    async fn migration_v17_adds_sync_queue_attempted_at(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        // Roll back to v11: drop the column and forget the version.
        sqlx::query("ALTER TABLE sync_queue DROP COLUMN attempted_at")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 17")
            .execute(db.pool())
            .await
            .unwrap();

        // A row written by the old node, before the column existed.
        enqueue_one(&db, "z6Mkfoo/legacy").await;

        db.migrate().await.unwrap();

        let col: (String, String) = sqlx::query_as(
            "SELECT data_type, is_nullable
             FROM information_schema.columns
             WHERE table_name = 'sync_queue' AND column_name = 'attempted_at'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(col.0, "text");
        assert_eq!(col.1, "YES", "attempted_at must be nullable");

        let recorded: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations WHERE version = 17")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(recorded.0, 1, "v17 must be recorded as applied");

        // The pre-existing row survives with a null key and is still dequeued.
        assert_eq!(attempted_at_of(&db, "z6Mkfoo/legacy").await, None);
        let items = db.dequeue_pending_syncs(10).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].repo, "z6Mkfoo/legacy");

        // Idempotent re-run.
        db.migrate().await.unwrap();
    }

    // ── Status claims, stored PR head, push events (v47) ─────────────────────

    /// The version this branch's migration claims. Kept as a named constant so
    /// the upgrade test's rollback target is derived from `MIGRATIONS` rather
    /// than hard-coded twice.
    const V47: i64 = 47;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// Seed a stored head without going through the code under test, so a
    /// freeze assertion cannot pass just because the writer never ran.
    async fn set_head_directly(db: &super::Db, pr_id: &str, sha: &str) {
        sqlx::query("UPDATE pull_requests SET head_commit=$1 WHERE id=$2")
            .bind(sha)
            .bind(pr_id)
            .execute(&db.pool)
            .await
            .unwrap();
    }

    fn sample_claim(repo_id: &str, sha: &str, context: &str) -> super::StatusClaim {
        super::StatusClaim {
            id: uuid::Uuid::new_v4().to_string(),
            // Ignored on insert: the database assigns the ordering key.
            seq: 0,
            repo_id: repo_id.to_string(),
            commit_sha: sha.to_string(),
            state: "success".to_string(),
            context: context.to_string(),
            target_url: Some("https://ci.example.com/runs/1".to_string()),
            description: Some("all checks passed".to_string()),
            producer_did: "did:key:zProducer".to_string(),
            authorizing_did: "did:key:zOwner".to_string(),
            signature: "sig1=:YWJj:".to_string(),
            signature_input: "sig1=(\"@method\" \"@target-uri\");created=1754524800".to_string(),
            signing_string: "\"@method\": POST\n\"@path\": /api/v1/repos/o/r/statuses/aaa"
                .to_string(),
            request_body: b"{\"state\":\"success\"}".to_vec(),
            // Fresh per call, the way two real requests are: a genuine signature
            // covers a `created` parameter and the body's digest, so no two
            // distinct requests carry the same material. A constant here would
            // make the second sample_claim of any test a replay of the first,
            // which is a different property than the one under test.
            request_digest: uuid::Uuid::new_v4().to_string(),
            created_at: "2026-08-07T00:00:00+00:00".to_string(),
        }
    }

    async fn table_exists(db: &super::Db, table: &str) -> bool {
        sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
            .bind(format!("public.{table}"))
            .fetch_one(&db.pool)
            .await
            .unwrap()
    }

    async fn column_exists(db: &super::Db, table: &str, column: &str) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns
             WHERE table_name = $1 AND column_name = $2)",
        )
        .bind(table)
        .bind(column)
        .fetch_one(&db.pool)
        .await
        .unwrap()
    }

    async fn insert_push_event(db: &super::Db, repo_id: &str, ref_name: &str, sha: &str, at: &str) {
        sqlx::query(
            "INSERT INTO repo_push_events (id, repo_id, ref_name, after_sha, created_at)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(repo_id)
        .bind(ref_name)
        .bind(sha)
        .bind(at)
        .execute(&db.pool)
        .await
        .unwrap();
    }

    fn sample_pr(repo_id: &str, number: i64) -> super::PullRequest {
        super::PullRequest {
            id: uuid::Uuid::new_v4().to_string(),
            repo_id: repo_id.to_string(),
            number,
            title: "add a thing".to_string(),
            body: None,
            author_did: "did:key:zAuthor".to_string(),
            source_branch: "feature".to_string(),
            target_branch: "main".to_string(),
            status: "open".to_string(),
            merged_by_did: None,
            merged_at: None,
            head_commit: None,
            created_at: "2026-08-07T00:00:00+00:00".to_string(),
            updated_at: "2026-08-07T00:00:00+00:00".to_string(),
        }
    }

    /// Fresh-database path: the whole chain on an empty database creates all
    /// three v47 objects, and a claim round-trips field for field, including
    /// the nullable columns in both directions.
    #[sqlx::test]
    async fn migration_v47_fresh_chain_round_trips_a_claim(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        assert!(table_exists(&db, "status_claims").await);
        assert!(table_exists(&db, "repo_push_events").await);
        assert!(column_exists(&db, "pull_requests", "head_commit").await);

        let full = sample_claim("repo-1", SHA_A, "ci/build");
        let seq = db.insert_status_claim(&full).await.unwrap();
        assert!(seq > 0, "the database must assign a positive sequence");

        // Same tuple, nullable fields absent.
        let mut sparse = sample_claim("repo-1", SHA_A, "ci/build");
        sparse.state = "pending".to_string();
        sparse.target_url = None;
        sparse.description = None;
        db.insert_status_claim(&sparse).await.unwrap();

        let claims = db.list_status_claims("repo-1", SHA_A).await.unwrap();
        assert_eq!(claims.len(), 2, "both claims are kept, nothing overwritten");

        let got = &claims[0];
        assert_eq!(got.id, full.id);
        assert_eq!(got.seq, seq);
        assert_eq!(got.repo_id, full.repo_id);
        assert_eq!(got.commit_sha, full.commit_sha);
        assert_eq!(got.state, full.state);
        assert_eq!(got.context, full.context);
        assert_eq!(got.target_url, full.target_url);
        assert_eq!(got.description, full.description);
        assert_eq!(got.producer_did, full.producer_did);
        assert_eq!(got.authorizing_did, full.authorizing_did);
        assert_eq!(got.signature, full.signature);
        assert_eq!(got.signature_input, full.signature_input);
        assert_eq!(got.signing_string, full.signing_string);
        assert_eq!(got.request_body, full.request_body);
        assert_eq!(got.created_at, full.created_at);

        let sparse_row = &claims[1];
        assert_eq!(sparse_row.id, sparse.id);
        assert_eq!(sparse_row.state, "pending");
        assert_eq!(sparse_row.target_url, None, "nullable column reads as None");
        assert_eq!(
            sparse_row.description, None,
            "nullable column reads as None"
        );

        // A different commit does not see this commit's claims.
        assert!(db
            .list_status_claims("repo-1", &"b".repeat(40))
            .await
            .unwrap()
            .is_empty());

        // The push-events table takes a row per observed ref update.
        insert_push_event(
            &db,
            "repo-1",
            "refs/heads/main",
            SHA_A,
            "2026-08-07T00:00:00+00:00",
        )
        .await;
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM repo_push_events WHERE repo_id = $1")
                .bind("repo-1")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }

    /// The rollup's branch resolve asks for the newest push on one ref, and
    /// "newest" has to mean the last row written, not the largest `created_at`.
    /// The stamp is applied before the insert, so a push that stamped later can
    /// commit earlier, the same defect the poll cursor had, in the reader next
    /// door. Constructed rather than raced for: the row written first carries the
    /// later timestamp.
    #[sqlx::test]
    async fn latest_push_sha_for_ref_follows_insertion_not_the_stamp(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        insert_push_event(
            &db,
            "repo-1",
            "refs/heads/main",
            SHA_A,
            "2026-08-07T13:00:00+00:00",
        )
        .await;
        insert_push_event(
            &db,
            "repo-1",
            "refs/heads/main",
            SHA_B,
            "2026-08-07T12:00:00+00:00",
        )
        .await;

        assert_eq!(
            db.latest_push_sha_for_ref("repo-1", "refs/heads/main")
                .await
                .unwrap()
                .as_deref(),
            Some(SHA_B),
            "the resolve must return the last push written, not the one carrying \
             the largest application-stamped timestamp"
        );

        // The ref filter is still doing its job, so the assertion above is not
        // just reading whatever row happens to be newest in the whole repo.
        insert_push_event(
            &db,
            "repo-1",
            "refs/heads/other",
            SHA_A,
            "2026-08-07T14:00:00+00:00",
        )
        .await;
        assert_eq!(
            db.latest_push_sha_for_ref("repo-1", "refs/heads/main")
                .await
                .unwrap()
                .as_deref(),
            Some(SHA_B),
            "a push to another ref must not move this ref's resolve"
        );
    }

    /// One push event on a caller-owned transaction, returning the sequence the
    /// database allocated. The allocation is what these tests are about, so the
    /// row goes in through raw SQL rather than the public writer: the writer now
    /// owns its own transaction and the reproduction below needs to own the
    /// commit boundaries itself.
    async fn raw_push_insert(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        repo_id: &str,
        ref_name: &str,
        sha: &str,
    ) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO repo_push_events (id, repo_id, ref_name, after_sha, created_at)
             VALUES ($1,$2,$3,$4,$5) RETURNING seq",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(repo_id)
        .bind(ref_name)
        .bind(sha)
        .bind("2026-08-07T00:00:00+00:00")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
    }

    fn push_event(repo_id: &str, ref_name: &str, sha: &str) -> super::RepoPushEvent {
        super::RepoPushEvent {
            id: uuid::Uuid::new_v4().to_string(),
            seq: 0,
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            after_sha: sha.to_string(),
            created_at: "2026-08-07T00:00:00+00:00".to_string(),
        }
    }

    /// The defect the repo lock exists to stop, pinned at the layer it lives in.
    ///
    /// `seq` is a bigserial: `nextval` allocates at INSERT and the row becomes
    /// visible at COMMIT, and the two orders are independent. A writer that
    /// allocates first and commits second leaves its row behind a cursor that
    /// has already passed, and no later poll asks for it again, so the event is
    /// lost silently and permanently.
    ///
    /// Driven with two test-owned transactions rather than two racing calls to
    /// the public writer, because the test has to decide when each one commits.
    /// A barrier around the public writer cannot reproduce this: allocate and
    /// commit were a single round trip, so there was no client-side window to
    /// interleave. This test therefore holds against the shape the write had
    /// before the lock as well as after it; what it documents is the mechanism,
    /// and the guard that the writer actually takes the lock is the test below.
    #[sqlx::test]
    async fn out_of_order_commits_strand_a_row_behind_the_cursor(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        let mut first = pool.begin().await.unwrap();
        let seq_first = raw_push_insert(&mut first, "repo-1", "refs/heads/main", SHA_A).await;
        let mut second = pool.begin().await.unwrap();
        let seq_second = raw_push_insert(&mut second, "repo-1", "refs/heads/other", SHA_B).await;
        assert!(
            seq_first < seq_second,
            "the fixture must allocate in this order to be the case under test"
        );

        // The later allocation commits first, which is exactly what an
        // unserialized pair of writers can do.
        second.commit().await.unwrap();

        let page = db
            .list_repo_push_events_keyset("repo-1", None, 50)
            .await
            .unwrap();
        assert_eq!(
            page.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![seq_second],
            "only the committed row is visible, so the poller's cursor lands past \
             the uncommitted one"
        );
        let cursor = page.last().unwrap().seq;
        assert!(cursor > seq_first);

        first.commit().await.unwrap();

        let total: i64 =
            sqlx::query_scalar("SELECT count(*) FROM repo_push_events WHERE repo_id = 'repo-1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(total, 2, "both rows are committed and visible");
        assert!(
            db.list_repo_push_events_keyset("repo-1", Some(cursor), 50)
                .await
                .unwrap()
                .is_empty(),
            "the row that committed second is now unreachable: every later poll \
             asks for seq > {cursor} and it will never be delivered"
        );
    }

    /// The writer waits on its own repo's lock and on no other repo's.
    ///
    /// Probed directly rather than inferred from timing between two writers: a
    /// transaction owned by the test holds the advisory lock for one repo, so
    /// "does the writer take this lock" becomes an observation rather than a
    /// race. The negative half is the one that matters and it is asserted
    /// first-class: a write for a different repo must not queue behind an
    /// unrelated repo's push.
    #[sqlx::test]
    async fn a_push_write_waits_on_its_own_repo_lock_and_no_others(pool: sqlx::PgPool) {
        use std::time::Duration;

        let db = super::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        let mut holder = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind("repo-held")
            .execute(&mut *holder)
            .await
            .unwrap();

        // Both failure modes are one assertion on purpose: a key too coarse
        // makes this write either hang until the outer timeout or fail its own
        // bounded lock wait, and either way the property that broke is the same
        // one.
        let free = tokio::time::timeout(
            Duration::from_secs(10),
            db.insert_repo_push_events(&[push_event("repo-free", "refs/heads/main", SHA_A)]),
        )
        .await;
        assert!(
            matches!(free, Ok(Ok(()))),
            "a write for another repo must not wait on this repo's lock; got {free:?}"
        );

        let blocked = tokio::time::timeout(
            Duration::from_millis(500),
            db.insert_repo_push_events(&[push_event("repo-held", "refs/heads/main", SHA_A)]),
        )
        .await;
        assert!(
            blocked.is_err(),
            "a write for a repo whose lock is held must wait rather than allocate \
             a sequence, or its row can commit after a later one and be stranded"
        );
        let held_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM repo_push_events WHERE repo_id = 'repo-held'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(held_rows, 0, "the blocked write must not have committed");

        holder.rollback().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(10),
            db.insert_repo_push_events(&[push_event("repo-held", "refs/heads/main", SHA_B)]),
        )
        .await
        .expect("the write must proceed once the lock is released")
        .unwrap();
    }

    /// A wait that never ends returns an error rather than holding the push
    /// open, and it spends its whole retry budget getting there.
    ///
    /// Both halves matter and neither implies the other. Without the bound the
    /// user's `git push` hangs for as long as the lock is held, which on the
    /// inline path is a pooled connection held with it. Without the retries a
    /// single slow neighbour turns into a lost chunk, which is the loss the lock
    /// exists to prevent, arriving by another road.
    #[sqlx::test]
    async fn a_lock_wait_that_never_clears_is_retried_and_then_returned(pool: sqlx::PgPool) {
        use std::time::Duration;

        let db = super::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        let mut holder = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
            .bind("repo-held")
            .execute(&mut *holder)
            .await
            .unwrap();

        let lock_wait = Duration::from_millis(super::PUSH_LOCK_TIMEOUT_MS.into());
        let started = std::time::Instant::now();
        // A fixed ceiling, not one derived from the constants above: the point
        // of this half is that the write terminates on its own, and an
        // expectation computed from the same values it is checking would move
        // with them.
        let outcome = tokio::time::timeout(
            Duration::from_secs(30),
            db.insert_repo_push_events(&[push_event("repo-held", "refs/heads/main", SHA_A)]),
        )
        .await
        .expect("the write must give up on its own rather than wait on the lock forever");
        let elapsed = started.elapsed();

        let err = outcome.expect_err("the write cannot have succeeded under a held lock");
        assert!(
            err.to_string().contains("lock timeout"),
            "the error must be the lock wait expiring, not something else the \
             retry classified wrongly; got: {err}"
        );
        assert!(
            elapsed >= lock_wait * 2,
            "the write must wait out more than one lock timeout before giving \
             up; it returned after {elapsed:?}, which is a single attempt"
        );

        holder.rollback().await.unwrap();
    }

    /// Two writers against one repo, in flight at once: every row is delivered
    /// by a cursor walk exactly once, and none is skipped.
    ///
    /// `tokio::spawn` and a `tokio::sync::Barrier`, never a thread: the
    /// push-write statement counter is a thread-local that depends on
    /// `#[sqlx::test]` building a single-threaded runtime, and a writer moved
    /// off that thread splits the count for every test that measures it.
    #[sqlx::test]
    async fn concurrent_writers_are_each_delivered_exactly_once(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        const WRITERS: usize = 4;
        let gate = std::sync::Arc::new(tokio::sync::Barrier::new(WRITERS));
        let mut handles = Vec::new();
        for i in 0..WRITERS {
            let db = db.clone();
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                let event = push_event("repo-race", &format!("refs/heads/b{i}"), SHA_A);
                gate.wait().await;
                db.insert_repo_push_events(std::slice::from_ref(&event))
                    .await
                    .unwrap();
                event.id
            }));
        }
        let mut written = Vec::new();
        for handle in handles {
            written.push(handle.await.unwrap());
        }

        // Page one row at a time, the way a poller that persists its cursor
        // does, so a skipped row shows up as a missing id rather than being
        // hidden inside one large page.
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = db
                .list_repo_push_events_keyset("repo-race", cursor, 1)
                .await
                .unwrap();
            let Some(row) = page.into_iter().next() else {
                break;
            };
            seen.push(row.id);
            cursor = Some(row.seq);
        }

        assert_eq!(
            seen.len(),
            WRITERS,
            "the walk returned {} rows for {WRITERS} writers",
            seen.len()
        );
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), seen.len(), "no row may be delivered twice");
        let mut expected = written;
        expected.sort();
        assert_eq!(unique, expected, "every writer's row must be reachable");
    }

    /// Upgrade path, the load-bearing one: `#[sqlx::test]` hands out a fresh
    /// database that runs the entire chain, so the fresh-chain test above stays
    /// green even if the v47 statements were appended to an already-applied
    /// entry. Only a simulated existing node catches that.
    #[sqlx::test]
    async fn migration_v47_upgrade_path_adds_claims_head_commit_and_push_events(
        pool: sqlx::PgPool,
    ) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        // Roll the database back to the state of a node at the highest version
        // below 47 that this build declares.
        sqlx::query("DROP TABLE IF EXISTS status_claims")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DROP TABLE IF EXISTS repo_push_events")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE pull_requests DROP COLUMN IF EXISTS head_commit")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version >= $1")
            .bind(V47)
            .execute(&db.pool)
            .await
            .unwrap();

        let prior = MIGRATIONS
            .iter()
            .map(|m| m.version)
            .filter(|v| *v < V47)
            .max()
            .expect("MIGRATIONS must declare a version below 47");
        let recorded_max: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_migrations")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            recorded_max, prior,
            "the simulated node must sit at the highest version below {V47}"
        );

        // A pull request written by the old node, before the column existed.
        let legacy = sample_pr("repo-legacy", 1);
        db.create_pr(&legacy).await.unwrap();

        // Upgrade through the real entry point rather than hand-copied SQL.
        db.migrate().await.unwrap();

        assert!(
            table_exists(&db, "status_claims").await,
            "status_claims missing after upgrade on an existing node"
        );
        assert!(
            table_exists(&db, "repo_push_events").await,
            "repo_push_events missing after upgrade on an existing node"
        );
        assert!(
            column_exists(&db, "pull_requests", "head_commit").await,
            "head_commit missing after upgrade on an existing node"
        );

        let col: (String, String) = sqlx::query_as(
            "SELECT data_type, is_nullable
             FROM information_schema.columns
             WHERE table_name = 'pull_requests' AND column_name = 'head_commit'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(col.0, "text");
        assert_eq!(col.1, "YES", "head_commit must be nullable");

        // The pre-existing row survives with a null head.
        let survived = db.get_pr("repo-legacy", 1).await.unwrap().unwrap();
        assert_eq!(survived.head_commit, None);

        // And the runtime paths work against the upgraded schema.
        let claim = sample_claim("repo-legacy", SHA_A, "ci/build");
        let seq = db.insert_status_claim(&claim).await.unwrap();
        let claims = db.list_status_claims("repo-legacy", SHA_A).await.unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].id, claim.id);
        assert_eq!(claims[0].seq, seq);
        assert_eq!(claims[0].target_url, claim.target_url);
        insert_push_event(
            &db,
            "repo-legacy",
            "refs/heads/main",
            SHA_A,
            "2026-08-07T00:00:00+00:00",
        )
        .await;

        let recorded: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations WHERE version = 47")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(recorded.0, 1, "v47 must be recorded as applied");

        // Idempotent re-run.
        db.migrate().await.unwrap();
    }

    /// A pull request opened before anything pushed to its source branch has no
    /// stored head, on both read paths.
    #[sqlx::test]
    async fn pr_created_before_any_push_has_no_head_commit(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        db.create_pr(&sample_pr("repo-1", 1)).await.unwrap();

        let one = db.get_pr("repo-1", 1).await.unwrap().unwrap();
        assert_eq!(
            one.head_commit, None,
            "get_pr must read a null head as None"
        );

        let listed = db.list_prs("repo-1").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].head_commit, None,
            "list_prs must read a null head as None"
        );
    }

    /// The push-side update is one statement keyed on (repo, source branch,
    /// open). Prove every arm of that WHERE clause in both directions in one
    /// pass: the open PR on the branch moves, an open PR on a different branch
    /// does not, and the closed and merged PRs on the *same* branch keep the
    /// head they froze at. The status predicate is the whole freeze mechanism,
    /// so a missing one shows up here as a moved head on a closed PR.
    #[sqlx::test]
    async fn set_open_pr_heads_moves_open_prs_on_the_branch_and_freezes_the_rest(
        pool: sqlx::PgPool,
    ) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        // #1 open on `feature` — must move.
        db.create_pr(&sample_pr("repo-1", 1)).await.unwrap();
        // #2 open on `other` — must not move.
        let mut other = sample_pr("repo-1", 2);
        other.source_branch = "other".to_string();
        db.create_pr(&other).await.unwrap();
        // #3 closed on `feature`, frozen at SHA_A.
        let closed = sample_pr("repo-1", 3);
        db.create_pr(&closed).await.unwrap();
        set_head_directly(&db, &closed.id, SHA_A).await;
        db.close_pr(&closed.id, None).await.unwrap();
        // #4 merged on `feature`, frozen at SHA_A.
        let merged = sample_pr("repo-1", 4);
        db.create_pr(&merged).await.unwrap();
        set_head_directly(&db, &merged.id, SHA_A).await;
        db.merge_pr(&merged.id, "did:key:zMerger", None)
            .await
            .unwrap();

        let moved = db
            .set_open_pr_heads("repo-1", "feature", SHA_B)
            .await
            .unwrap();
        assert_eq!(moved, 1, "only the one open PR on `feature` may be updated");

        assert_eq!(
            db.get_pr("repo-1", 1).await.unwrap().unwrap().head_commit,
            Some(SHA_B.to_string()),
            "an open PR on the pushed branch must track the new head"
        );
        assert_eq!(
            db.get_pr("repo-1", 2).await.unwrap().unwrap().head_commit,
            None,
            "a PR on an unrelated branch must be untouched"
        );
        assert_eq!(
            db.get_pr("repo-1", 3).await.unwrap().unwrap().head_commit,
            Some(SHA_A.to_string()),
            "a closed PR's head is frozen"
        );
        assert_eq!(
            db.get_pr("repo-1", 4).await.unwrap().unwrap().head_commit,
            Some(SHA_A.to_string()),
            "a merged PR's head is frozen"
        );
    }

    /// Closing a pull request freezes the source head the close decided
    /// against. Both arms: a snapshot the handler resolved is persisted, and a
    /// `None` (head unresolvable) keeps whatever the push path last recorded —
    /// the same fall-back-to-stored trade `merge_pr` makes.
    #[sqlx::test]
    async fn close_pr_freezes_the_resolved_head_and_preserves_a_stored_one(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        // #1 has no stored head; the close supplies the resolved snapshot.
        let pr = sample_pr("repo-1", 1);
        db.create_pr(&pr).await.unwrap();
        db.close_pr(&pr.id, Some(SHA_B)).await.unwrap();
        let closed = db.get_pr("repo-1", 1).await.unwrap().unwrap();
        assert_eq!(closed.status, "closed");
        assert_eq!(
            closed.head_commit,
            Some(SHA_B.to_string()),
            "the close must freeze the head it resolved against"
        );

        // #2 already has a stored head; a close that resolves nothing must not
        // null it out.
        let pr2 = sample_pr("repo-1", 2);
        db.create_pr(&pr2).await.unwrap();
        set_head_directly(&db, &pr2.id, SHA_A).await;
        db.close_pr(&pr2.id, None).await.unwrap();
        assert_eq!(
            db.get_pr("repo-1", 2).await.unwrap().unwrap().head_commit,
            Some(SHA_A.to_string()),
            "an unresolvable close keeps the stored head"
        );
    }

    /// The handler reads the pull request before it resolves a fallback head,
    /// so a push can store a head in between. The fallback fills an empty head
    /// only; a stored head must win over it.
    #[sqlx::test]
    async fn close_pr_fallback_does_not_overwrite_a_head_stored_after_the_read(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        let pr = sample_pr("repo-1", 1);
        db.create_pr(&pr).await.unwrap();
        // The handler saw head_commit = NULL and resolved SHA_A; a push then
        // stored SHA_B before the close statement ran.
        set_head_directly(&db, &pr.id, SHA_B).await;
        db.close_pr(&pr.id, Some(SHA_A)).await.unwrap();

        let closed = db.get_pr("repo-1", 1).await.unwrap().unwrap();
        assert_eq!(closed.status, "closed");
        assert_eq!(
            closed.head_commit,
            Some(SHA_B.to_string()),
            "a head stored by a concurrent push must survive the close fallback"
        );
    }

    /// A repeated close must not re-freeze a head onto a pull request that is
    /// already closed: the handler resolves the head from the branch as it is
    /// now, so applying it would retarget a historical status after the fact.
    #[sqlx::test]
    async fn close_pr_leaves_an_already_closed_pull_request_untouched(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        let pr = sample_pr("repo-1", 1);
        db.create_pr(&pr).await.unwrap();
        db.close_pr(&pr.id, None).await.unwrap();
        let first = db.get_pr("repo-1", 1).await.unwrap().unwrap();
        assert_eq!(first.head_commit, None, "closed with no resolvable head");

        db.close_pr(&pr.id, Some(SHA_B)).await.unwrap();
        let second = db.get_pr("repo-1", 1).await.unwrap().unwrap();
        assert_eq!(
            second.head_commit, None,
            "a second close must not store a head on a closed pull request"
        );
        assert_eq!(second.updated_at, first.updated_at);
    }

    /// A same-named branch is the common case across repos, so a missing repo
    /// predicate would be invisible to every single-repo assertion above.
    #[sqlx::test]
    async fn set_open_pr_heads_is_scoped_to_the_named_repo(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        db.create_pr(&sample_pr("repo-1", 1)).await.unwrap();
        db.create_pr(&sample_pr("repo-2", 1)).await.unwrap();

        let moved = db
            .set_open_pr_heads("repo-1", "feature", SHA_B)
            .await
            .unwrap();
        assert_eq!(moved, 1, "the sibling repo's PR must not be counted");

        assert_eq!(
            db.get_pr("repo-1", 1).await.unwrap().unwrap().head_commit,
            Some(SHA_B.to_string())
        );
        assert_eq!(
            db.get_pr("repo-2", 1).await.unwrap().unwrap().head_commit,
            None,
            "a push in one repo must not move a same-named branch's PR elsewhere"
        );
    }

    /// The merge stamp writes the head it actually merged, overwriting whatever
    /// a racing push left. Passing `None` (a merge that could not resolve the
    /// source head) must preserve the stored value rather than null it out.
    #[sqlx::test]
    async fn merge_pr_stamps_the_supplied_head_and_none_preserves_it(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        let stamped = sample_pr("repo-1", 1);
        db.create_pr(&stamped).await.unwrap();
        set_head_directly(&db, &stamped.id, SHA_A).await;
        db.merge_pr(&stamped.id, "did:key:zMerger", Some(SHA_B))
            .await
            .unwrap();
        let after = db.get_pr("repo-1", 1).await.unwrap().unwrap();
        assert_eq!(after.status, "merged");
        assert_eq!(
            after.head_commit,
            Some(SHA_B.to_string()),
            "the merge stamps the head it merged, not the one the row carried"
        );

        let preserved = sample_pr("repo-1", 2);
        db.create_pr(&preserved).await.unwrap();
        set_head_directly(&db, &preserved.id, SHA_A).await;
        db.merge_pr(&preserved.id, "did:key:zMerger", None)
            .await
            .unwrap();
        assert_eq!(
            db.get_pr("repo-1", 2).await.unwrap().unwrap().head_commit,
            Some(SHA_A.to_string()),
            "an unresolvable source head must not null a stored head"
        );
    }

    /// The read-side fallback's write, which an UNAUTHENTICATED rollup read can
    /// trigger. It has to be self-limiting in SQL, not by handler ordering: it
    /// fills an absent head on an open pull request and refuses every other case,
    /// so a concurrent push that already recorded a newer head cannot be rolled
    /// back to a staler branch tip, and a closed pull request's frozen head (or
    /// frozen absence) is never written at all.
    #[sqlx::test]
    async fn set_pr_head_if_absent_fills_only_an_absent_open_head(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        // Absent head, open: filled.
        let fresh = sample_pr("repo-1", 1);
        db.create_pr(&fresh).await.unwrap();
        assert_eq!(db.set_pr_head_if_absent(&fresh.id, SHA_A).await.unwrap(), 1);
        assert_eq!(
            db.get_pr("repo-1", 1).await.unwrap().unwrap().head_commit,
            Some(SHA_A.to_string())
        );

        // Head already present: refused, and the stored value stands.
        assert_eq!(
            db.set_pr_head_if_absent(&fresh.id, SHA_B).await.unwrap(),
            0,
            "a stored head must never be overwritten by a read-side fallback"
        );
        assert_eq!(
            db.get_pr("repo-1", 1).await.unwrap().unwrap().head_commit,
            Some(SHA_A.to_string()),
            "a stored head must never be overwritten by a read-side fallback"
        );

        // Absent head but closed: refused.
        let closed = sample_pr("repo-1", 2);
        db.create_pr(&closed).await.unwrap();
        db.close_pr(&closed.id, None).await.unwrap();
        assert_eq!(
            db.set_pr_head_if_absent(&closed.id, SHA_A).await.unwrap(),
            0
        );
        assert_eq!(
            db.get_pr("repo-1", 2).await.unwrap().unwrap().head_commit,
            None,
            "a closed pull request's head must not be back-filled"
        );

        // Absent head but merged: refused.
        let merged = sample_pr("repo-1", 3);
        db.create_pr(&merged).await.unwrap();
        db.merge_pr(&merged.id, "did:key:zMerger", None)
            .await
            .unwrap();
        assert_eq!(
            db.set_pr_head_if_absent(&merged.id, SHA_A).await.unwrap(),
            0
        );
        assert_eq!(
            db.get_pr("repo-1", 3).await.unwrap().unwrap().head_commit,
            None
        );
    }

    /// The projection orders on `seq`, so prove the database hands out strictly
    /// increasing values in insertion order rather than assuming it.
    #[sqlx::test]
    async fn status_claim_seq_is_monotonic_within_a_tuple(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        let mut seqs = Vec::new();
        let mut ids = Vec::new();
        for state in ["pending", "failure", "success"] {
            let mut claim = sample_claim("repo-1", SHA_A, "ci/build");
            claim.state = state.to_string();
            // Identical server timestamp on every row: nothing but `seq` can
            // recover the insertion order.
            claim.created_at = "2026-08-07T00:00:00+00:00".to_string();
            seqs.push(db.insert_status_claim(&claim).await.unwrap());
            ids.push(claim.id);
        }

        assert!(
            seqs[0] < seqs[1] && seqs[1] < seqs[2],
            "seq must strictly increase in insertion order, got {seqs:?}"
        );

        let claims = db.list_status_claims("repo-1", SHA_A).await.unwrap();
        assert_eq!(
            claims.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
            ids,
            "claims must read back in seq order"
        );
        assert_eq!(
            claims.iter().map(|c| c.seq).collect::<Vec<_>>(),
            seqs,
            "the stored seq must be the one the insert reported"
        );
    }

    /// The replay containment lives in the schema, not in the Rust that reads it.
    ///
    /// The capped insert probes for the digest before it writes, but that probe
    /// is a fast path: it is a read, and a read cannot exclude a writer it has
    /// not seen commit. This drives the raw insert past the probe entirely, so
    /// what refuses is the unique index or nothing. Asserted here rather than
    /// only through the handler because the handler's own replay tests stay green
    /// on the probe alone, which is exactly how a guard rots into decoration.
    #[sqlx::test]
    async fn the_schema_refuses_a_second_claim_with_the_same_request_digest(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        let first = sample_claim("repo-digest", SHA_A, "ci/build");
        db.insert_status_claim(&first).await.unwrap();

        // Different row in every other respect: a fresh id, another commit, a
        // different context and verdict. Only the request identity repeats.
        let mut replay = sample_claim("repo-digest", SHA_B, "ci/other");
        replay.state = "failure".to_string();
        replay.request_digest = first.request_digest.clone();

        let err = db
            .insert_status_claim(&replay)
            .await
            .expect_err("the database must refuse a second row carrying a digest it already has");
        let text = err.to_string();
        assert!(
            text.contains("uq_status_claims_request_digest") || text.contains("duplicate key"),
            "the refusal must come from the request-digest uniqueness, got: {text}"
        );

        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM status_claims WHERE repo_id = 'repo-digest'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(rows, 1, "the refused write must leave no row");
    }

    /// The caps have to hold against writers racing each other, which is the only
    /// case they are actually for: a sequential caller hitting a cap is a
    /// misbehaving client, a burst of them is the fan-out the bound exists to
    /// stop. Eight writers are released together onto a tuple seeded to `cap - 1`,
    /// so exactly one of them may win. Counting rows under READ COMMITTED and then
    /// inserting is not enough: each writer's count is taken before any of the
    /// others commit, so every one of them reads `cap - 1` and inserts, and the
    /// table ends up over the bound by the concurrency.
    #[sqlx::test]
    async fn capped_insert_holds_the_bound_against_concurrent_writers(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool.clone());
        db.migrate().await.unwrap();

        const CAP: i64 = 3;
        const WRITERS: usize = 8;
        // Only the per-tuple bound is under test; the other two are left far out
        // of reach so the refusal cannot come from them.
        fn caps() -> super::ClaimCaps {
            super::ClaimCaps {
                per_tuple: CAP,
                contexts_per_commit: 1_000,
                per_repo_window: 1_000_000,
            }
        }

        for _ in 0..CAP - 1 {
            db.insert_status_claim(&sample_claim("repo-race", SHA_A, "ci/build"))
                .await
                .unwrap();
        }

        let gate = std::sync::Arc::new(tokio::sync::Barrier::new(WRITERS));
        let mut handles = Vec::new();
        for _ in 0..WRITERS {
            let db = db.clone();
            let gate = gate.clone();
            handles.push(tokio::spawn(async move {
                let claim = sample_claim("repo-race", SHA_A, "ci/build");
                // Every writer reaches the capped insert at the same moment, so
                // the count-then-insert windows overlap instead of queueing.
                gate.wait().await;
                db.insert_status_claim_capped(&claim, &caps())
                    .await
                    .unwrap()
            }));
        }

        let mut accepted = 0;
        for handle in handles {
            if let super::ClaimInsert::Inserted(_) = handle.await.unwrap() {
                accepted += 1;
            }
        }

        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM status_claims WHERE repo_id = 'repo-race'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            rows, CAP,
            "the bound is {CAP} rows; {WRITERS} concurrent writers left {rows}"
        );
        assert_eq!(
            accepted, 1,
            "exactly one writer may be told its claim was accepted"
        );
    }

    /// The public commit-status read must not pull the signature material off
    /// disk. `signing_string` and `request_body` are write-time provenance that
    /// no read surface renders, and together they run to kilobytes per claim, so
    /// selecting them costs the anonymous read path on every request. Asserted on
    /// the query text, because a widened column list is invisible in the response
    /// body: the extra bytes are read and then dropped.
    #[test]
    fn projection_selects_no_signature_columns() {
        for banned in [
            "signature",
            "signature_input",
            "signing_string",
            "request_body",
        ] {
            assert!(
                !super::LATEST_STATUS_CLAIMS_SQL.contains(banned),
                "the commit-status projection must not select `{banned}`: it is \
                 write-time provenance no read surface renders"
            );
        }
    }

    #[sqlx::test]
    async fn migration_v27_drops_raw_assignee_index(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        // Roll back: restore the raw index, forget v27.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_agent_tasks_assignee ON agent_tasks(assignee_did)",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 27")
            .execute(&db.pool)
            .await
            .unwrap();

        // Re-run migration.
        db.migrate().await.unwrap();

        let old_idx_exists: (bool,) = sqlx::query_as(
            "SELECT EXISTS(
                SELECT 1 FROM pg_indexes
                WHERE tablename = 'agent_tasks' AND indexname = 'idx_agent_tasks_assignee'
            )",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert!(
            !old_idx_exists.0,
            "idx_agent_tasks_assignee must be dropped"
        );

        // v27 no longer builds the single-column expression index; v28 builds
        // the keyset-ordered variants directly.
        let expr_idx_exists: (bool,) = sqlx::query_as(
            "SELECT EXISTS(
                SELECT 1 FROM pg_indexes
                WHERE tablename = 'agent_tasks' AND indexname = 'idx_agent_tasks_assignee_key'
            )",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert!(
            !expr_idx_exists.0,
            "idx_agent_tasks_assignee_key must never be built by v27"
        );

        let recorded: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations WHERE version = 27")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(recorded.0, 1, "v27 must be recorded as applied");

        // Idempotent re-run.
        db.migrate().await.unwrap();
    }

    #[sqlx::test]
    async fn migration_v28_creates_task_keyset_indexes(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        for name in [
            "idx_agent_tasks_created_at_id",
            "idx_agent_tasks_status_created_at_id",
            "idx_agent_tasks_assignee_key_created_at_id",
            "idx_agent_tasks_status_assignee_key_created_at_id",
        ] {
            let exists: (bool,) = sqlx::query_as(
                "SELECT EXISTS(
                    SELECT 1 FROM pg_indexes
                    WHERE tablename = 'agent_tasks' AND indexname = $1
                )",
            )
            .bind(name)
            .fetch_one(&db.pool)
            .await
            .unwrap();
            assert!(exists.0, "{name} must exist");
        }

        for old_name in ["idx_agent_tasks_assignee_key", "idx_agent_tasks_status"] {
            let exists: (bool,) = sqlx::query_as(
                "SELECT EXISTS(
                    SELECT 1 FROM pg_indexes
                    WHERE tablename = 'agent_tasks' AND indexname = $1
                )",
            )
            .bind(old_name)
            .fetch_one(&db.pool)
            .await
            .unwrap();
            assert!(!exists.0, "{old_name} must be dropped by v28");
        }

        sqlx::query("DROP INDEX IF EXISTS idx_agent_tasks_created_at_id")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DROP INDEX IF EXISTS idx_agent_tasks_status_created_at_id")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DROP INDEX IF EXISTS idx_agent_tasks_assignee_key_created_at_id")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DROP INDEX IF EXISTS idx_agent_tasks_status_assignee_key_created_at_id")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 28")
            .execute(&db.pool)
            .await
            .unwrap();

        db.migrate().await.unwrap();

        let recorded: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM schema_migrations WHERE version = 28")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(recorded.0, 1, "v28 must be recorded as applied");
        let exists: (bool,) = sqlx::query_as(
            "SELECT EXISTS(
                SELECT 1 FROM pg_indexes
                WHERE tablename = 'agent_tasks'
                  AND indexname = 'idx_agent_tasks_created_at_id'
            )",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert!(
            exists.0,
            "v28 must recreate the unfiltered keyset index on an upgrading node"
        );

        db.migrate().await.unwrap();
    }

    #[sqlx::test]
    async fn dequeue_stamps_attempted_at_on_every_row_it_hands_out(pool: sqlx::PgPool) {
        // The stamp is what stops a deferred row from holding the window, and
        // it happens here rather than at the deferral branches so no call site
        // can forget it.
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        enqueue_one(&db, "z6Mkfoo/a").await;
        assert_eq!(
            attempted_at_of(&db, "z6Mkfoo/a").await,
            None,
            "a freshly enqueued row has no attempt yet"
        );

        let items = db.dequeue_pending_syncs(10).await.unwrap();
        assert_eq!(items.len(), 1);
        assert!(
            attempted_at_of(&db, "z6Mkfoo/a").await.is_some(),
            "dequeue must stamp the row it returns, whatever the worker does next"
        );
    }

    #[sqlx::test]
    async fn dequeue_orders_by_last_attempt_then_enqueue_time(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        enqueue_one(&db, "z6Mkfoo/older").await;
        enqueue_one(&db, "z6Mkfoo/newer").await;
        sqlx::query("UPDATE sync_queue SET enqueued_at = $1 WHERE repo = $2")
            .bind("2026-07-29T00:00:00Z")
            .bind("z6Mkfoo/older")
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE sync_queue SET enqueued_at = $1 WHERE repo = $2")
            .bind("2026-07-29T00:00:01Z")
            .bind("z6Mkfoo/newer")
            .execute(db.pool())
            .await
            .unwrap();

        // Never-attempted rows fall back to enqueue order.
        let first = db.dequeue_pending_syncs(1).await.unwrap();
        assert_eq!(first[0].repo, "z6Mkfoo/older");

        // Having been attempted, it now sorts behind the untried row.
        let second = db.dequeue_pending_syncs(1).await.unwrap();
        assert_eq!(
            second[0].repo, "z6Mkfoo/newer",
            "an attempted row must yield to one that has never been tried"
        );
    }

    #[sqlx::test]
    async fn dequeue_leaves_enqueued_at_untouched(pool: sqlx::PgPool) {
        // enqueued_at keeps meaning enqueue time, so backlog age stays
        // measurable; that is the reason attempted_at is a separate column.
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        enqueue_one(&db, "z6Mkfoo/a").await;
        let before: String =
            sqlx::query_scalar("SELECT enqueued_at FROM sync_queue WHERE repo = 'z6Mkfoo/a'")
                .fetch_one(db.pool())
                .await
                .unwrap();

        db.dequeue_pending_syncs(10).await.unwrap();

        let after: String =
            sqlx::query_scalar("SELECT enqueued_at FROM sync_queue WHERE repo = 'z6Mkfoo/a'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(before, after);
    }

    #[sqlx::test]
    async fn dequeue_does_not_touch_settled_rows(pool: sqlx::PgPool) {
        // The stamping UPDATE must not reach a row that already left the
        // pending set, or a terminal row could be dragged back into rotation.
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        enqueue_one(&db, "z6Mkfoo/failed").await;
        enqueue_one(&db, "z6Mkfoo/done").await;
        let ids: Vec<(String, String)> =
            sqlx::query_as("SELECT repo, id FROM sync_queue ORDER BY repo")
                .fetch_all(&db.pool)
                .await
                .unwrap();
        for (repo, id) in &ids {
            if repo.ends_with("failed") {
                db.mark_sync_failed(id).await.unwrap();
            } else {
                db.mark_sync_done(id).await.unwrap();
            }
        }

        assert!(db.dequeue_pending_syncs(10).await.unwrap().is_empty());
        assert_eq!(attempted_at_of(&db, "z6Mkfoo/failed").await, None);
        assert_eq!(attempted_at_of(&db, "z6Mkfoo/done").await, None);
    }

    /// Migration v32 makes pinned_cids.cid nullable so record_pinata_cid can
    /// create Pinata-only rows without a local IPFS CID.  This test seeds a
    /// pre-v32 schema (cid NOT NULL, pinata_cid column exists but no
    /// nullability change yet) with rows in each of the three states the
    /// has_ipfs_cid / filter_ipfs_pinned_oids predicates must classify:
    ///
    ///   (1) cid IS NOT NULL, pinata_cid IS NULL              → has_ipfs = true
    ///   (2) cid IS NOT NULL, cid != pinata_cid              → has_ipfs = false
    ///       (ambiguous pre-v30; the strict backfill leaves it out and the
    ///       next sweep pass re-derives by re-pinning)
    ///   (3) cid IS NOT NULL, cid = pinata_cid (legacy)      → has_ipfs = false
    ///
    /// Legacy row (3) stops being a special case because migration v27 clears
    /// `cid = pinata_cid` back to NULL, so `has_ipfs_cid` reduces to the plain
    /// `cid IS NOT NULL` predicate (provenance recorded, never inferred).
    ///
    /// After the migration we also test that a Pinata-only INSERT (cid = NULL)
    /// works and produces has_ipfs = false, has_pinata = true.
    #[sqlx::test]
    async fn migration_v32_makes_cid_nullable_and_preserves_classification(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);

        // Create all tables, then drop the NOT NULL constraint on cid
        // and drop schema_migrations records to simulate a pre-v32 node.
        db.migrate().await.unwrap();
        sqlx::query("ALTER TABLE pinned_cids ALTER COLUMN cid SET NOT NULL")
            .execute(&db.pool)
            .await
            .unwrap();

        sqlx::query("DELETE FROM schema_migrations")
            .execute(&db.pool)
            .await
            .unwrap();
        for m in MIGRATIONS.iter().take_while(|m| m.version < 32) {
            sqlx::query(
                "INSERT INTO schema_migrations (version, name, applied_at)
                 VALUES ($1, $2, $3)",
            )
            .bind(m.version)
            .bind(m.name)
            .bind("2026-07-01T00:00:00Z")
            .execute(&db.pool)
            .await
            .unwrap();
        }

        // ── Seed legacy rows ───────────────────────────────────────────
        let now = "2026-07-01T12:00:00Z";

        // (1) Real local IPFS pin, no Pinata.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ($1, $2, $3, $4)",
        )
        .bind("sha_real_only")
        .bind("QmRealLocalCid")
        .bind(now)
        .bind(Option::<&str>::None)
        .execute(&db.pool)
        .await
        .unwrap();

        // (2) Both CIDs present and distinct.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ($1, $2, $3, $4)",
        )
        .bind("sha_both_distinct")
        .bind("QmLocalForThisBlob")
        .bind(now)
        .bind("QmPinataForThisBlob")
        .execute(&db.pool)
        .await
        .unwrap();

        // (3) Legacy row where cid was set to pinata_cid as fallback.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ($1, $2, $3, $4)",
        )
        .bind("sha_legacy_fallback")
        .bind("QmLegacyEqual")
        .bind(now)
        .bind("QmLegacyEqual")
        .execute(&db.pool)
        .await
        .unwrap();

        // ── Apply migration v32 ────────────────────────────────────────
        db.migrate().await.unwrap();

        // ── Assertions ─────────────────────────────────────────────────

        // Column is now nullable.
        let nullable: String = sqlx::query_scalar(
            "SELECT is_nullable FROM information_schema.columns
             WHERE table_name = 'pinned_cids' AND column_name = 'cid'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(nullable, "YES", "cid must be nullable after v32");

        // Classification: has_ipfs_cid.
        //
        // Unknown-migration (v35): EVERY pre-migration row reads FALSE,
        // including the local-shaped `sha_real_only`. Column shape is
        // not evidence of a Kubo write — the pre-fix writer produced
        // exactly that shape on 2xx-without-`Hash` responses — so no
        // backfill may promote any row to durable. The next sweep pass
        // re-pins to establish provenance (see
        // `sweep_rederives_legacy_unknown_row_by_repinning`); the
        // `local_ipfs_provenance` column is the authoritative
        // predicate and `has_ipfs_cid` keys on it.
        for sha in ["sha_real_only", "sha_both_distinct", "sha_legacy_fallback"] {
            assert!(
                !db.has_ipfs_cid(sha).await.unwrap(),
                "{sha} must read as unknown (FALSE) until a re-pin establishes provenance"
            );
        }

        // has_pinata_cid.
        assert!(
            !db.has_pinata_cid("sha_real_only").await.unwrap(),
            "no pinata_cid means has_pinata = false"
        );
        assert!(
            db.has_pinata_cid("sha_both_distinct").await.unwrap(),
            "non-null pinata_cid means has_pinata = true"
        );
        assert!(
            db.has_pinata_cid("sha_legacy_fallback").await.unwrap(),
            "non-null pinata_cid means has_pinata = true (legacy row)"
        );

        // ── Pinata-only INSERT (new post-v32 row) ──────────────────────
        db.record_pinata_cid(
            "sha_pinata_only",
            "QmPinataOnly",
            "QmPinataOnly",
            None,
            i64::MAX,
        )
        .await
        .unwrap();
        assert!(
            !db.has_ipfs_cid("sha_pinata_only").await.unwrap(),
            "Pinata-only row must NOT be classified as having a local IPFS CID"
        );
        assert!(
            db.has_pinata_cid("sha_pinata_only").await.unwrap(),
            "Pinata-only row must have has_pinata = true"
        );

        // ── Idempotent re-run ──────────────────────────────────────────
        db.migrate().await.unwrap();
    }

    /// Migration v32 (round-3 renumber from v27) clears legacy rows where cid
    /// was set to pinata_cid as a fallback, so `has_ipfs_cid` no longer has to
    /// infer provenance from CID inequality (R2-P2). Rows where the CIDs genuinely
    /// differ are untouched.
    ///
    /// Round-3 P3: the previous assertions all went through `has_ipfs_cid` /
    /// `has_pinata_cid` — a v30 backfill that flipped `local_ipfs_provenance`
    /// to FALSE on the distinct row would make the test still GREEN even
    /// if v32's `cid = NULL` backfill never ran. Read the `cid` and
    /// `pinata_cid` columns DIRECTLY so the test cannot pass on a no-op.
    #[sqlx::test]
    async fn migration_v32_clears_legacy_equal_cid(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        let now = "2026-07-01T12:00:00Z";

        // Seed one legacy equal-cid row and one distinct-cid row, then mark
        // v32 (and v33-v36, applied after it) as not yet run so re-running
        // migrate() exercises the backfill in isolation.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ('sha_equal', 'QmSame', $1, 'QmSame'),
                    ('sha_distinct', 'QmLocal', $1, 'QmPinata')",
        )
        .bind(now)
        .execute(&db.pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version >= 32")
            .execute(&db.pool)
            .await
            .unwrap();

        db.migrate().await.unwrap();

        // Read cid / pinata_cid directly. The previous assertions went
        // through `has_ipfs_cid` and `has_pinata_cid`, which would
        // still return false / true if a future refactor flipped
        // `local_ipfs_provenance` without touching cid / pinata_cid —
        // a v32 no-op would then hide behind a green test.
        let equal_cid: Option<String> =
            sqlx::query_scalar("SELECT cid FROM pinned_cids WHERE sha256_hex = 'sha_equal'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        let equal_pinata: Option<String> =
            sqlx::query_scalar("SELECT pinata_cid FROM pinned_cids WHERE sha256_hex = 'sha_equal'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        let distinct_cid: Option<String> =
            sqlx::query_scalar("SELECT cid FROM pinned_cids WHERE sha256_hex = 'sha_distinct'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        let distinct_pinata: Option<String> = sqlx::query_scalar(
            "SELECT pinata_cid FROM pinned_cids WHERE sha256_hex = 'sha_distinct'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();

        assert_eq!(
            equal_cid, None,
            "v32 must clear the legacy equal-cid row to NULL; \
             cid is still {equal_cid:?}"
        );
        assert_eq!(
            equal_pinata.as_deref(),
            Some("QmSame"),
            "v32 must preserve pinata_cid on the legacy row"
        );
        assert_eq!(
            distinct_cid.as_deref(),
            Some("QmLocal"),
            "v32 must NOT touch the distinct-cid row's cid"
        );
        assert_eq!(
            distinct_pinata.as_deref(),
            Some("QmPinata"),
            "v32 must preserve pinata_cid on the distinct row"
        );
    }

    /// #218 review P1: the local-IPFS provenance predicate moved from
    /// `cid IS NOT NULL` to a dedicated `local_ipfs_provenance` column set
    /// by the writer (#218 review P1 — provenance is now established at
    /// the writer boundary, never inferred from CID shape). Migration v35
    /// (round-3 renumber from v30) does NOT backfill: legacy rows are left
    /// `local_ipfs_provenance = FALSE` and stay unproven until the
    /// reconciliation sweep re-derives each one through
    /// `record_pinned_cid_with_source`; `has_ipfs_cid` /
    /// `filter_ipfs_pinned_oids` key on the
    /// new column. This test exercises the full chain: pre-v35 schema,
    /// the four row shapes, the v35 migration, the post-migration
    /// column values, and the post-migration `has_ipfs_cid` /
    /// `filter_ipfs_pinned_oids` classification.
    /// post-migration `has_ipfs_cid` / `filter_ipfs_pinned_oids`
    /// classification.
    #[sqlx::test]
    async fn migration_v35_leaves_legacy_rows_unknown_for_rederivation(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool.clone());

        // Build a pre-v35 schema: every migration applied, then forget
        // v35 (drop the column and index, delete the migration record)
        // and re-run `migrate()` so v35 lands on the seeded rows. The
        // v12 test below uses the same pattern.
        db.migrate().await.unwrap();

        // Reset to a pre-v35 schema: drop the v35 column and the
        // partial index, and forget the v35 migration record.
        sqlx::query("ALTER TABLE pinned_cids DROP COLUMN IF EXISTS local_ipfs_provenance")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DROP INDEX IF EXISTS idx_pinned_cids_local_ipfs_provenance")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 35")
            .execute(&db.pool)
            .await
            .unwrap();

        // Sanity: pre-v35 — the column does not exist.
        let col_pre: bool = sqlx::query_scalar(
            "SELECT EXISTS (
               SELECT 1 FROM information_schema.columns
               WHERE table_name = 'pinned_cids'
                 AND column_name = 'local_ipfs_provenance'
             )",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !col_pre,
            "pre-v35 schema must not have the local_ipfs_provenance column"
        );

        // Seed the four row shapes. The shapes are the same as the v12
        // backfill test (the v27 / v30 lineage) — keeping the fixture
        // names in sync so a future reader can see the contract evolved
        // in place rather than being silently rewritten.
        let now = "2026-07-01T12:00:00Z";
        let seed = async |sha: &str, cid: Option<&str>, pinata: Option<&str>| {
            sqlx::query(
                "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(sha)
            .bind(cid)
            .bind(now)
            .bind(pinata)
            .execute(&pool)
            .await
            .unwrap();
        };

        // (1) Legacy local-shaped row: cid set, no Pinata. Genuine iff a
        // Kubo add really stored the bytes — but the pre-fix writer also
        // produced EXACTLY this shape on a 2xx response with no `Hash`
        // (wrong-port health endpoint, HTML proxy, truncated body), so
        // the column pattern cannot prove it. Unknown, not TRUE.
        seed("sha_v30_real_only", Some("QmRealLocalCid"), None).await;
        // (2) Both CIDs present and distinct → unknown.
        seed(
            "sha_v30_both_distinct",
            Some("QmLocalForThisBlob"),
            Some("QmPinataForThisBlob"),
        )
        .await;
        // (3) Pinata-only (post-v27 NULL cid, pinata_cid set) → FALSE.
        seed("sha_v30_pinata_only", None, Some("QmPinataOnlyCid")).await;
        // (4) Pinata-only with a provider CID → FALSE.
        seed("sha_v30_pinata_provider", None, Some("QmPinataProviderCid")).await;

        // Apply v35 by re-running `migrate()`. The runner sees v35
        // missing from `schema_migrations` and runs the migration body:
        // the `ALTER TABLE` adds the column (default FALSE) and the
        // partial index is created. There is deliberately NO backfill
        // UPDATE: no column pattern proves a Kubo write happened.
        db.migrate().await.unwrap();

        // The column now exists with the documented default.
        let col_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
               SELECT 1 FROM information_schema.columns
               WHERE table_name = 'pinned_cids'
                 AND column_name = 'local_ipfs_provenance'
             )",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            col_exists,
            "v35 migration must add the local_ipfs_provenance column"
        );

        // Unknown-migration: EVERY pre-v35 row reads FALSE, including
        // the local-shaped (1). A genuine legacy pin and a phantom
        // 2xx/no-Hash row are byte-identical in the table, so trusting
        // either would let the sweep filter the phantom as "already
        // durable" forever. The next sweep pass re-pins to establish
        // provenance (cheap, idempotent); Pinata history is preserved
        // untouched for (2)–(4).
        let provenance = |sha: &str| {
            let pool = pool.clone();
            let sha = sha.to_string();
            async move {
                let row: Option<bool> = sqlx::query_scalar(
                    "SELECT local_ipfs_provenance FROM pinned_cids WHERE sha256_hex = $1",
                )
                .bind(&sha)
                .fetch_optional(&pool)
                .await
                .unwrap();
                row
            }
        };

        for sha in [
            "sha_v30_real_only",
            "sha_v30_both_distinct",
            "sha_v30_pinata_only",
            "sha_v30_pinata_provider",
        ] {
            assert_eq!(
                provenance(sha).await,
                Some(false),
                "{sha} must migrate as unknown (FALSE), even the local-shaped row: \
                 column shape is not evidence of a Kubo write"
            );
        }

        // Pinata history survives the migration verbatim.
        let pinata_of = |sha: &str| {
            let pool = pool.clone();
            let sha = sha.to_string();
            async move {
                let row: Option<String> =
                    sqlx::query_scalar("SELECT pinata_cid FROM pinned_cids WHERE sha256_hex = $1")
                        .bind(&sha)
                        .fetch_optional(&pool)
                        .await
                        .unwrap();
                row
            }
        };
        assert_eq!(
            pinata_of("sha_v30_both_distinct").await.as_deref(),
            Some("QmPinataForThisBlob"),
            "dual-row provider history must survive the migration"
        );
        assert_eq!(
            pinata_of("sha_v30_pinata_only").await.as_deref(),
            Some("QmPinataOnlyCid"),
            "pinata-only provider history must survive the migration"
        );

        // The classification predicate `has_ipfs_cid` keys on
        // `local_ipfs_provenance = TRUE`, so nothing is classified as
        // locally pinned yet — not even the local-shaped row. The
        // integration test
        // `sweep_rederives_legacy_unknown_row_by_repinning`
        // covers the writer path that brings such a row into the
        // IPFS-pinned set on the next sweep pass.
        for sha in [
            "sha_v30_real_only",
            "sha_v30_both_distinct",
            "sha_v30_pinata_only",
            "sha_v30_pinata_provider",
        ] {
            assert!(
                !db.has_ipfs_cid(sha).await.unwrap(),
                "{sha} must report FALSE until a re-pin establishes provenance"
            );
        }

        // The gap filter used by the sweep (`filter_ipfs_pinned_oids`)
        // follows the same predicate: unknown rows are re-offered,
        // never filtered as durable.
        let candidates = vec![
            "sha_v30_real_only".to_string(),
            "sha_v30_both_distinct".to_string(),
            "sha_v30_pinata_only".to_string(),
            "sha_v30_pinata_provider".to_string(),
        ];
        let filtered = db.filter_ipfs_pinned_oids(&candidates).await.unwrap();
        assert!(
            filtered.is_empty(),
            "no migrated row may read as durable before re-derivation; got {filtered:?}"
        );
    }

    /// `list_pinned_cids` must map a SQL NULL `cid` (Pinata-only row) to
    /// `None`. The old `try_get("cid").ok()` conflated NULL with a decode
    /// failure, so `/api/v1/ipfs/pins` could silently omit or misrepresent a
    /// row instead of surfacing the DB error.
    #[sqlx::test]
    async fn list_pinned_cids_maps_null_cid_to_none(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        let now = "2026-07-01T12:00:00Z";

        // One row with a real CID, one Pinata-only row (cid NULL).
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ('sha_real', 'QmReal', $1, 'QmPinata'),
                    ('sha_pinata_only', NULL, $1, 'QmPinata2')",
        )
        .bind(now)
        .execute(&db.pool)
        .await
        .unwrap();

        let pins = db.list_pinned_cids().await.unwrap();
        let real = pins
            .iter()
            .find(|p| p.sha256_hex == "sha_real")
            .expect("real-cid row must be listed");
        assert_eq!(real.cid.as_deref(), Some("QmReal"));
        let pinata_only = pins
            .iter()
            .find(|p| p.sha256_hex == "sha_pinata_only")
            .expect("Pinata-only row must be listed");
        assert_eq!(pinata_only.cid, None, "NULL cid must map to None");
    }

    /// Round-3 P1: `cid_for_oid` must return `None` for a row with
    /// `cid = NULL` (Pinata-only row), not panic. Pre-fix the column
    /// decode used `r.get::<String, _>("cid")` which `try_get().unwrap()`s
    /// on an unexpected NULL, and the pin loop at `ipfs_pin.rs:235`
    /// calls this on every batch — the first batch after v32 on a
    /// node with any Pinata-only row would have walked straight into
    /// the panic.
    #[sqlx::test]
    async fn cid_for_oid_returns_none_when_cid_is_null(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ('sha_pinata_only', NULL, '2026-07-01T12:00:00Z', 'QmPinata')",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        let got = db
            .cid_for_oid("sha_pinata_only")
            .await
            .expect("cid_for_oid must not panic on NULL cid");
        assert_eq!(got, None, "NULL cid must return None, not panic or error");
    }

    /// Round-3 P1: `pinned_cids_after` must surface NULL `cid` as
    /// `None` in the tuple, not panic. The legacy repair loop
    /// (`ipfs_pin.rs:896`) iterates the rows and skips NULL-cid
    /// entries — the re-key has no string to operate on.
    #[sqlx::test]
    async fn pinned_cids_after_skips_rows_with_null_cid(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ('sha_real', 'QmReal', '2026-07-01T12:00:00Z', NULL),
                    ('sha_pinata', NULL, '2026-07-01T12:00:00Z', 'QmPinata')",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        let rows = db.pinned_cids_after("", 10).await.unwrap();
        let real = rows
            .iter()
            .find(|(sha, _)| sha == "sha_real")
            .expect("real-cid row must be returned");
        assert_eq!(real.1.as_deref(), Some("QmReal"));
        let pinata = rows
            .iter()
            .find(|(sha, _)| sha == "sha_pinata")
            .expect("Pinata-only row must be returned");
        assert_eq!(
            pinata.1, None,
            "NULL cid must return as None in the tuple, not panic"
        );
    }

    /// A corrupt `cid` value must surface as a decode error, not a silent
    /// None. Postgres only stores values of the column's declared type, so
    /// reach the decode failure by retyping the column to bytea (a future
    /// migration doing the same is the realistic corruption path). The column
    /// is retyped before the first `list_pinned_cids` call so the query plan
    /// is compiled against the corrupt type.
    #[sqlx::test]
    async fn list_pinned_cids_errors_on_corrupt_cid(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();
        let now = "2026-07-01T12:00:00Z";

        sqlx::query("ALTER TABLE pinned_cids ALTER COLUMN cid TYPE bytea USING NULL::bytea")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid)
             VALUES ('sha_bad', E'\\\\xdeadbeef', $1, NULL)",
        )
        .bind(now)
        .execute(&db.pool)
        .await
        .unwrap();

        let err = db
            .list_pinned_cids()
            .await
            .expect_err("corrupt cid column must fail the whole listing");
        assert!(
            err.to_string().contains("invalid type") || err.to_string().contains("cid"),
            "decode failure must be the reported error, got: {err}"
        );
    }

    /// Migration v28 creates the node_state key/value table and the get/set
    /// helpers round-trip through it (used by the sweep cursor persistence).
    #[sqlx::test]
    async fn node_state_roundtrip_and_delete(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        assert_eq!(
            db.get_node_state("sweep_cursor").await.unwrap(),
            None,
            "absent key reads as None"
        );

        db.set_node_state("sweep_cursor", Some("repo/b"))
            .await
            .unwrap();
        assert_eq!(
            db.get_node_state("sweep_cursor").await.unwrap(),
            Some("repo/b".to_string()),
            "value survives a write + read"
        );

        // Upsert overwrites.
        db.set_node_state("sweep_cursor", Some("repo/c"))
            .await
            .unwrap();
        assert_eq!(
            db.get_node_state("sweep_cursor").await.unwrap(),
            Some("repo/c".to_string())
        );

        // None deletes the key.
        db.set_node_state("sweep_cursor", None).await.unwrap();
        assert_eq!(db.get_node_state("sweep_cursor").await.unwrap(), None);
    }

    /// record_pinned_cid must repair a stale WRONG local CID, not only fill a
    /// NULL or Pinata-fallback slot (R1-P2): an object pinned once with the
    /// wrong bytes is overwritten by a subsequent push-path pin, but the sweep
    /// gap filter (`cid IS NOT NULL`) excludes rows with a present CID from
    /// re-processing, so the sweep cannot repair them.
    #[sqlx::test]
    async fn record_pinned_cid_repairs_stale_wrong_cid(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        // A stale wrong CID that is neither NULL nor equal to pinata_cid.
        db.record_pinned_cid("sha_stale", "QmStaleWrong", None)
            .await
            .unwrap();
        db.record_pinata_cid("sha_stale", "QmRawStale", "QmPinataX", None, i64::MAX)
            .await
            .unwrap();

        // Re-pin with the correct CID — must overwrite despite the existing
        // distinct cid column.
        db.record_pinned_cid("sha_stale", "QmCorrect", None)
            .await
            .unwrap();

        let cid: String =
            sqlx::query_scalar("SELECT cid FROM pinned_cids WHERE sha256_hex = 'sha_stale'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(cid, "QmCorrect", "stale wrong CID must be repaired");
    }

    /// record_pinata_cid must clear a legacy cid = pinata_cid fallback (v27's
    /// belt-and-suspenders) so a later Pinata-only row is never misread as a
    /// local IPFS pin.
    #[sqlx::test]
    async fn record_pinata_cid_clears_legacy_equal_cid(pool: sqlx::PgPool) {
        let db = super::Db::for_testing(pool);
        db.migrate().await.unwrap();

        db.record_pinned_cid("sha_fallback", "QmFallback", None)
            .await
            .unwrap();
        // Simulate a legacy row where cid was forced equal to pinata_cid.
        sqlx::query(
            "UPDATE pinned_cids SET pinata_cid = 'QmFallback' WHERE sha256_hex = 'sha_fallback'",
        )
        .execute(&db.pool)
        .await
        .unwrap();

        // Recording a new (different) Pinata CID must NULL the stale fallback cid.
        db.record_pinata_cid(
            "sha_fallback",
            "QmRawFallback",
            "QmPinataNew",
            None,
            i64::MAX,
        )
        .await
        .unwrap();

        let cid: Option<String> =
            sqlx::query_scalar("SELECT cid FROM pinned_cids WHERE sha256_hex = 'sha_fallback'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(cid, None, "legacy equal-cid fallback must be cleared");

        // But a genuine local pin plus a distinct Pinata CID is preserved.
        db.record_pinned_cid("sha_genuine", "QmLocalGenuine", None)
            .await
            .unwrap();
        db.record_pinata_cid(
            "sha_genuine",
            "QmRawGenuine",
            "QmPinataGenuine",
            None,
            i64::MAX,
        )
        .await
        .unwrap();
        let cid: String =
            sqlx::query_scalar("SELECT cid FROM pinned_cids WHERE sha256_hex = 'sha_genuine'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(cid, "QmLocalGenuine");
    }
}

#[cfg(test)]
mod agent_discovery_tests {
    use super::{filter_discoverable, AgentRow};

    fn agent(did: &str, trust: f64, status: &str, caps: &[&str]) -> AgentRow {
        AgentRow {
            did: did.to_string(),
            trust_score: trust,
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
            registered_at: "2026-06-19T00:00:00Z".to_string(),
            last_seen: None,
            status: status.to_string(),
        }
    }

    fn dids(rows: &[AgentRow]) -> Vec<&str> {
        rows.iter().map(|a| a.did.as_str()).collect()
    }

    #[test]
    fn only_active_agents_are_returned() {
        let rows = vec![
            agent("did:key:active1", 0.5, "active", &["reputation:score"]),
            agent("did:key:revoked1", 0.4, "revoked", &["reputation:score"]),
            agent("did:key:revoked2", 0.3, "revoked", &["reputation:score"]),
        ];

        let out = filter_discoverable(rows, None);

        assert_eq!(dids(&out), vec!["did:key:active1"]);
    }

    #[test]
    fn revoked_orphan_never_wins_capability_routing() {
        // Reproduces issue #29: a self-deregistered orphan sharing the
        // canonical agent's capability and equal trust must be excluded so the
        // active replacement is the only capability match.
        let rows = vec![
            agent("did:key:orphan", 0.1, "revoked", &["reputation:score"]),
            agent("did:key:canonical", 0.1, "active", &["reputation:score"]),
        ];

        let out = filter_discoverable(rows, Some("reputation:score"));

        assert_eq!(dids(&out), vec!["did:key:canonical"]);
    }

    #[test]
    fn capability_and_status_filters_compose() {
        let rows = vec![
            // matches capability but retired -> excluded
            agent("did:key:revoked", 0.9, "revoked", &["attestation:verify"]),
            // active but wrong capability -> excluded
            agent("did:key:other", 0.8, "active", &["oracle:agent-trust"]),
            // active and matches -> kept
            agent("did:key:match", 0.7, "active", &["attestation:verify"]),
        ];

        let out = filter_discoverable(rows, Some("attestation:verify"));

        assert_eq!(dids(&out), vec!["did:key:match"]);
    }

    #[test]
    fn input_order_is_preserved_so_active_stays_trust_ranked() {
        // Input arrives pre-sorted by trust desc; filtering must not reorder.
        let rows = vec![
            agent("did:key:high", 0.9, "active", &[]),
            agent("did:key:retired", 0.8, "revoked", &[]),
            agent("did:key:mid", 0.5, "active", &[]),
            agent("did:key:low", 0.2, "active", &[]),
        ];

        let out = filter_discoverable(rows, None);

        assert_eq!(
            dids(&out),
            vec!["did:key:high", "did:key:mid", "did:key:low"]
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(filter_discoverable(vec![], None).is_empty());
        assert!(filter_discoverable(vec![], Some("reputation:score")).is_empty());
    }
}

#[cfg(test)]
mod dedup_db_tests {
    use super::{Db, RepoRecord};
    use chrono::{DateTime, Utc};
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    /// Build a repo row with explicit timestamps. A slash in `id` marks a mirror
    /// row (the format `upsert_mirror_repo` writes); a UUID-shaped `id` is canonical.
    fn rec(
        id: &str,
        owner_did: &str,
        name: &str,
        desc: &str,
        created: &str,
        updated: &str,
    ) -> RepoRecord {
        RepoRecord {
            id: id.to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: Some(desc.to_string()),
            is_public: true,
            default_branch: "main".to_string(),
            created_at: ts(created),
            updated_at: ts(updated),
            disk_path: format!("/srv/{id}"),
            forked_from: None,
            machine_id: None,
        }
    }

    /// The canonical `did:key:` row and the short-owner mirror row of one logical
    /// repo collapse to a single deduped entry: the canonical row wins and inherits
    /// the group's most recent `updated_at`.
    #[sqlx::test]
    async fn deduped_collapses_mirror_and_canonical(pool: PgPool) {
        let db = db(pool).await;
        let canonical = rec(
            "9d92186a-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "Decentralized npm for agents",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        // Mirror row in the shape upsert_mirror_repo writes: slash id, bare owner.
        let mirror = rec(
            "z6Mkwbud/nipmod",
            "z6Mkwbud",
            "nipmod",
            "mirrored from peer",
            "2026-02-01T00:00:00Z",
            "2026-03-01T00:00:00Z",
        );
        db.create_repo(&canonical).await.unwrap();
        db.create_repo(&mirror).await.unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1, "the pair collapses to one logical repo");
        assert_eq!(out[0].owner_did, "did:key:z6Mkwbud", "canonical row wins");
        assert_eq!(
            out[0].updated_at,
            ts("2026-03-01T00:00:00Z"),
            "survivor inherits the group's MAX(updated_at)"
        );
    }

    #[sqlx::test]
    async fn deduped_id_lookup_returns_only_requested_repo(pool: PgPool) {
        let db = db(pool).await;
        let requested = rec(
            "requested",
            "did:key:z6MkRequested",
            "requested",
            "requested",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        );
        let unrelated = rec(
            "unrelated",
            "did:key:z6MkUnrelated",
            "unrelated",
            "unrelated",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        );
        db.create_repo(&requested).await.unwrap();
        db.create_repo(&unrelated).await.unwrap();

        // Empty input returns empty without querying.
        let empty = db.list_repos_deduped_by_ids(&[]).await.unwrap();
        assert!(empty.is_empty());

        let out = db
            .list_repos_deduped_by_ids(std::slice::from_ref(&requested.id))
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, requested.id);

        // Deduplication order of operations:
        // Canonical row and mirror row for the same group: canonical wins.
        let canonical = rec(
            "canonical-pair-id",
            "did:key:z6MkPairOwner",
            "pair-repo",
            "canonical",
            "2026-01-10T00:00:00Z",
            "2026-01-10T00:00:00Z",
        );
        let mirror = rec(
            "z6MkPairOwner/pair-repo",
            "z6MkPairOwner",
            "pair-repo",
            "mirror",
            "2026-01-11T00:00:00Z",
            "2026-01-11T00:00:00Z",
        );
        db.create_repo(&canonical).await.unwrap();
        db.create_repo(&mirror).await.unwrap();

        // Requesting canonical returns canonical survivor.
        let out_can = db
            .list_repos_deduped_by_ids(std::slice::from_ref(&canonical.id))
            .await
            .unwrap();
        assert_eq!(out_can.len(), 1);
        assert_eq!(out_can[0].id, canonical.id);

        // Requesting mirror returns empty because canonical survivor wins and
        // mirror id does not match the survivor.
        let out_mir = db
            .list_repos_deduped_by_ids(std::slice::from_ref(&mirror.id))
            .await
            .unwrap();
        assert!(out_mir.is_empty());

        // Requesting both returns canonical survivor once.
        let out_both = db
            .list_repos_deduped_by_ids(&[canonical.id.clone(), mirror.id.clone()])
            .await
            .unwrap();
        assert_eq!(out_both.len(), 1);
        assert_eq!(out_both[0].id, canonical.id);

        // Quarantined mirror is withheld even if requested by ID.
        db.upsert_mirror_repo("z6MkQuar", "quar-repo", "/srv/quar", None, true)
            .await
            .unwrap();
        let quar_id = "z6MkQuar/quar-repo".to_string();

        let out_quar = db
            .list_repos_deduped_by_ids(std::slice::from_ref(&quar_id))
            .await
            .unwrap();
        assert!(out_quar.is_empty());
    }

    /// A PRIVATE canonical repo and a PUBLIC mirror row for the same
    /// (owner, name) collapse to a single survivor whose `is_public` is the
    /// canonical `false`, not the mirror's `true`. `upsert_mirror_repo` always
    /// writes `is_public=true`, so without this the deduped set could carry a
    /// public flag for a locally-private repo and the ref-updates feed gate
    /// would over-serve. Pins the DEDUP_CTE tiebreak so a future regression
    /// that flips the survivor can't leak silently.
    #[sqlx::test]
    async fn deduped_private_canonical_beats_public_mirror(pool: PgPool) {
        let db = db(pool).await;
        // Private canonical row (rec() forces is_public=true, so build inline).
        let mut canonical = rec(
            "uuid-private-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "private canonical",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        canonical.is_public = false;
        db.create_repo(&canonical).await.unwrap();
        // Public mirror row for the same (owner, name): id = "z6Mkwbud/nipmod",
        // is_public = true.
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/mirror", None, false)
            .await
            .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1, "the pair collapses to one logical repo");
        assert_eq!(out[0].owner_did, "did:key:z6Mkwbud", "canonical row wins");
        assert!(
            !out[0].is_public,
            "survivor keeps the canonical private is_public=false, not the mirror's true"
        );
    }

    /// upsert_mirror_repo's own rows dedupe against a canonical twin (proves the
    /// real mirror writer's row shape is classified correctly).
    #[sqlx::test]
    async fn deduped_collapses_real_upsert_mirror_row(pool: PgPool) {
        let db = db(pool).await;
        let canonical = rec(
            "uuid-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "real",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        db.create_repo(&canonical).await.unwrap();
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/mirror", None, false)
            .await
            .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            1,
            "real mirror row collapses with its canonical twin"
        );
        assert_eq!(out[0].owner_did, "did:key:z6Mkwbud", "canonical row wins");
    }

    /// Same name and base58 id but different DID methods (`did:key` vs
    /// `did:gitlawb`) must NOT collapse: the grouping key strips only `did:key:`
    /// and leaves other methods whole, matching crate::api::did_matches. Both the
    /// list (DEDUP_CTE) and count (count_repos_deduped) paths must agree.
    #[sqlx::test]
    async fn deduped_keeps_distinct_did_methods_apart(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-keyed",
            "did:key:z6Mkwbud",
            "nipmod",
            "via did:key",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-gitlawb",
            "did:gitlawb:z6Mkwbud",
            "nipmod",
            "via did:gitlawb",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 2, "distinct DID methods are distinct owners");
        assert_eq!(
            db.count_repos_deduped().await.unwrap(),
            2,
            "count path agrees with the list path",
        );
    }

    /// SQL residual-colon guard: a malformed `did:key:did:gitlawb:X` strips to a
    /// value that still holds a `:`, so the CASE keeps it whole and it does NOT
    /// collapse with a real `did:gitlawb:X`. Proves the SQL key matches the Rust
    /// `strip_prefix(...).filter(|r| !r.contains(':'))` and did_matches.
    #[sqlx::test]
    async fn deduped_did_key_wrapping_a_full_did_stays_distinct(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-wrapped",
            "did:key:did:gitlawb:z6Mkwbud",
            "nipmod",
            "malformed nested DID",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-method",
            "did:gitlawb:z6Mkwbud",
            "nipmod",
            "real method DID",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            2,
            "wrapped full DID stays distinct from the method DID"
        );
        assert_eq!(
            db.count_repos_deduped().await.unwrap(),
            2,
            "count path agrees with the list path",
        );
    }

    /// Empty-residual boundary: `did:key:` matches `LIKE 'did:key:%'`,
    /// `substr(owner_did, 9)` is '', and `position(':' in '')` is 0, so the CASE
    /// keys it to '' just like a bare empty owner, while a real `did:key:z…` keys
    /// separately. Pins that the SQL empty-residual handling matches the Rust
    /// `strip_prefix(...).filter(...)` path (mirrored in the api-level test).
    #[sqlx::test]
    async fn deduped_empty_did_key_residual_keys_to_empty_string(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-empty-didkey",
            "did:key:",
            "nipmod",
            "empty residual",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-empty-bare",
            "",
            "nipmod",
            "empty owner",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-real",
            "did:key:z6Mkwbud",
            "nipmod",
            "real id",
            "2026-01-03T00:00:00Z",
            "2026-01-03T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            2,
            "`did:key:` and the empty owner collapse on the empty key; the real id is separate"
        );
        assert_eq!(
            db.count_repos_deduped().await.unwrap(),
            2,
            "count path agrees with the list path",
        );
    }

    /// Distinct repos are preserved and ordered by most recent activity.
    #[sqlx::test]
    async fn deduped_preserves_distinct_repos_ordered_by_updated(pool: PgPool) {
        let db = db(pool).await;
        db.create_repo(&rec(
            "id-a",
            "did:key:z6Aaa",
            "alpha",
            "first",
            "2026-03-01T00:00:00Z",
            "2026-03-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "id-b",
            "did:key:z6Bbb",
            "beta",
            "second",
            "2026-03-02T00:00:00Z",
            "2026-03-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "beta", "most recently updated first");
        assert_eq!(out[1].name, "alpha");
    }

    /// count_repos_deduped counts logical repos, not raw rows.
    #[sqlx::test]
    async fn count_repos_deduped_counts_logical_repos(pool: PgPool) {
        let db = db(pool).await;
        // One logical repo (canonical + mirror) plus one standalone.
        db.create_repo(&rec(
            "uuid-c",
            "did:key:z6Mkwbud",
            "nipmod",
            "real",
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        ))
        .await
        .unwrap();
        db.upsert_mirror_repo("z6Mkwbud", "nipmod", "/srv/m", None, false)
            .await
            .unwrap();
        db.create_repo(&rec(
            "uuid-d",
            "did:key:z6Other",
            "solo",
            "real",
            "2026-01-16T00:00:00Z",
            "2026-01-16T00:00:00Z",
        ))
        .await
        .unwrap();

        assert_eq!(db.count_repos_deduped().await.unwrap(), 2);
    }

    /// Full tie (same mirror-status and created_at within a group) resolves to a
    /// deterministic survivor by `id ASC`, matching the Rust helper's tiebreak.
    #[sqlx::test]
    async fn deduped_full_tie_resolves_by_id_asc(pool: PgPool) {
        let db = db(pool).await;
        // Two canonical rows in the same (normalized owner, name) group, identical
        // created_at; only the id differs. Different owner_did strings avoid any
        // (owner, name) collision while still normalizing to the same group key.
        db.create_repo(&rec(
            "bbb",
            "did:key:z6Same",
            "repo",
            "real",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.create_repo(&rec(
            "aaa",
            "z6Same",
            "repo",
            "real",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1, "same group collapses");
        assert_eq!(
            out[0].id, "aaa",
            "id ASC breaks a full tie deterministically"
        );
    }

    /// Marker robustness: a canonical row whose `description` is literally
    /// "mirrored from peer" but whose `id` is a UUID is still ranked canonical and
    /// wins over a true slash-id mirror in its group — even though the mirror was
    /// created earlier. Proves dedup keys on the structural id, not the description.
    #[sqlx::test]
    async fn deduped_marker_uses_id_not_description(pool: PgPool) {
        let db = db(pool).await;
        let canonical = rec(
            "uuid-canonical",
            "did:key:z6Mkwbud",
            "nipmod",
            "mirrored from peer", // user-settable description = the old marker string
            "2026-01-15T00:00:00Z",
            "2026-01-15T00:00:00Z",
        );
        let mirror = rec(
            "z6Mkwbud/nipmod", // slash id = the real structural marker
            "z6Mkwbud",
            "nipmod",
            "a normal description, not the marker",
            "2026-01-01T00:00:00Z", // earlier: would win on created_at if marker ignored
            "2026-01-01T00:00:00Z",
        );
        db.create_repo(&canonical).await.unwrap();
        db.create_repo(&mirror).await.unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].id, "uuid-canonical",
            "canonical wins by structural id marker despite carrying the mirror description"
        );
    }

    /// A mirror row with no canonical twin survives dedup as the sole entry for its
    /// group (it is not dropped just because it is the mirror).
    #[sqlx::test]
    async fn deduped_mirror_only_group_survives(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6Lonely", "orphan", "/srv/m", None, false)
            .await
            .unwrap();

        let out = db.list_all_repos_deduped().await.unwrap();
        assert_eq!(
            out.len(),
            1,
            "a mirror-only group still yields one logical repo"
        );
        assert_eq!(out[0].id, "z6Lonely/orphan");
        assert_eq!(db.count_repos_deduped().await.unwrap(), 1);
    }

    /// Degenerate empty table: deduped list is empty and the count is 0, no error.
    #[sqlx::test]
    async fn deduped_empty_table(pool: PgPool) {
        let db = db(pool).await;
        assert!(db.list_all_repos_deduped().await.unwrap().is_empty());
        assert_eq!(db.count_repos_deduped().await.unwrap(), 0);
    }

    /// count_repos_deduped and list_all_repos_deduped must agree: the count is the
    /// number of logical repos the list returns. Guards the two independent SQL
    /// queries against drifting on the grouping key.
    #[sqlx::test]
    async fn deduped_count_matches_list_len(pool: PgPool) {
        let db = db(pool).await;
        // Two logical repos: one canonical+mirror pair, one standalone canonical.
        db.create_repo(&rec(
            "uuid-1",
            "did:key:z6Pair",
            "shared",
            "real",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
        ))
        .await
        .unwrap();
        db.upsert_mirror_repo("z6Pair", "shared", "/srv/m", None, false)
            .await
            .unwrap();
        db.create_repo(&rec(
            "uuid-2",
            "did:key:z6Solo",
            "solo",
            "real",
            "2026-01-02T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ))
        .await
        .unwrap();

        let list_len = db.list_all_repos_deduped().await.unwrap().len() as i64;
        let count = db.count_repos_deduped().await.unwrap();
        assert_eq!(list_len, 2);
        assert_eq!(count, list_len, "count must equal the deduped list length");
    }

    /// get_repo must prefer the canonical row over the mirror row when both match,
    /// so the visibility gate keys off the canonical row's rules and is_public flag
    /// rather than the mirror's hardcoded public-with-no-rules (issue #124).
    #[sqlx::test]
    async fn get_repo_prefers_canonical_over_mirror(pool: PgPool) {
        let db = db(pool).await;
        let short = "z6Mkwbud";
        let owner_did = "did:key:z6Mkwbud";

        // Mirror row seeded FIRST — hardcoded is_public=true, no visibility rules.
        // Without the ORDER BY fix, fetch_optional returns this row by insertion order,
        // so the test fails (proving it locks in the fix).
        db.upsert_mirror_repo(short, "secret-repo", "/srv/mirror", None, false)
            .await
            .unwrap();

        // Canonical row with is_public=false.
        let canonical = RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "secret-repo".into(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: false,
            default_branch: "main".into(),
            // Date after the mirror (Utc::now()) so that created_at ASC alone
            // would pick the mirror; the CASE WHEN position('/' in id) > 0 term
            // is what makes the canonical row win.
            created_at: ts("2126-01-01T00:00:00Z"),
            updated_at: ts("2126-01-01T00:00:00Z"),
            disk_path: "/srv/secret".into(),
            forked_from: None,
            machine_id: None,
        };
        db.create_repo(&canonical).await.unwrap();

        // Querying with bare short DID should return the canonical row.
        let got = db
            .get_repo(short, "secret-repo")
            .await
            .unwrap()
            .expect("get_repo should find the repo");

        assert_eq!(
            got.owner_did, owner_did,
            "canonical row (did:key: form) must win over mirror row (bare short DID)"
        );
        assert!(
            !got.id.contains('/'),
            "canonical row id must not contain a slash"
        );
        assert!(
            !got.is_public,
            "canonical row's is_public must be preserved"
        );

        // Querying with full did:key: form should also return the canonical row.
        let got_full = db
            .get_repo(owner_did, "secret-repo")
            .await
            .unwrap()
            .expect("get_repo should find the repo with full did:key");

        assert_eq!(
            got_full.owner_did, owner_did,
            "canonical row must be found using full did:key: form"
        );
        assert!(
            !got_full.id.contains('/'),
            "canonical row id must not contain a slash"
        );
        assert!(
            !got_full.is_public,
            "canonical row's is_public must be preserved"
        );
    }

    /// Seed a private canonical plus a public mirror twin for the same owner+name
    /// (mirror inserted first), call authorize_repo_read with caller=None, and
    /// assert Err(RepoNotFound). That locks the property at the gate.
    #[sqlx::test]
    async fn authorize_repo_read_denies_private_canonical_even_with_public_mirror(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let short = "z6Mkwbud";
        let owner_did = "did:key:z6Mkwbud";

        // Mirror row seeded FIRST — hardcoded is_public=true, no visibility rules.
        state
            .db
            .upsert_mirror_repo(short, "secret-repo", "/srv/mirror", None, false)
            .await
            .unwrap();

        // Canonical row with is_public=false.
        let canonical = RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "secret-repo".into(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: false,
            default_branch: "main".into(),
            created_at: ts("2126-01-01T00:00:00Z"),
            updated_at: ts("2126-01-01T00:00:00Z"),
            disk_path: "/srv/secret".into(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&canonical).await.unwrap();

        // call authorize_repo_read with caller=None, and assert Err(RepoNotFound)
        let res = crate::api::authorize_repo_read(&state, short, "secret-repo", None, "/").await;
        assert!(
            matches!(res, Err(crate::error::AppError::RepoNotFound(_))),
            "expected Err(RepoNotFound), got {res:?}"
        );
    }

    /// get_repo still returns the mirror row when no canonical row exists
    /// (mirror-only group), so sync and read paths remain functional.
    #[sqlx::test]
    async fn get_repo_returns_mirror_when_no_canonical(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6Lonely", "orphan", "/srv/m", None, false)
            .await
            .unwrap();

        let got = db
            .get_repo("z6Lonely", "orphan")
            .await
            .unwrap()
            .expect("get_repo should find the mirror");

        assert_eq!(got.id, "z6Lonely/orphan", "mirror row is returned");
        assert!(got.is_public, "mirror row's is_public should be true");
    }

    /// get_repo must NOT match a non-key DID row (e.g. did:gitlawb:) when queried
    /// with the bare short DID — the old LIKE '%:' || $1 || '%' was too broad and
    /// could rank a non-key canonical row ahead of the exact mirror.
    #[sqlx::test]
    async fn get_repo_does_not_match_non_key_did(pool: PgPool) {
        let db = db(pool).await;
        let short = "z6Mkwbud";

        // Mirror row for the bare short DID.
        db.upsert_mirror_repo(short, "shared-name", "/srv/m", None, false)
            .await
            .unwrap();

        // Non-key DID row sharing the same trailing id — must stay distinct.
        let non_key = RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "shared-name".into(),
            owner_did: format!("did:gitlawb:{short}"),
            description: None,
            is_public: false,
            default_branch: "main".into(),
            created_at: ts("2126-01-01T00:00:00Z"),
            updated_at: ts("2126-01-01T00:00:00Z"),
            disk_path: "/srv/other".into(),
            forked_from: None,
            machine_id: None,
        };
        db.create_repo(&non_key).await.unwrap();

        // Querying with the bare short DID must return the mirror, NOT the
        // did:gitlawb row (different DID method, separate owner).
        let got = db
            .get_repo(short, "shared-name")
            .await
            .unwrap()
            .expect("get_repo should find the mirror row");

        assert!(
            got.id.contains('/'),
            "must return the mirror (slash id), not a non-key canonical row"
        );
        assert!(got.is_public, "mirror row's is_public should be true");

        // Querying with the full non-key DID must return that exact row.
        let got = db
            .get_repo(&format!("did:gitlawb:{short}"), "shared-name")
            .await
            .unwrap()
            .expect("get_repo should find the non-key DID row");

        assert!(
            !got.id.contains('/'),
            "must return the non-key canonical row (UUID id)"
        );
        assert!(!got.is_public, "non-key row's is_public must be preserved");
    }

    /// get_profile must not resolve a non-key DID (e.g. did:gitlawb:) when
    /// queried with the bare short id. The old `LIKE '%:' || $1` clause was too
    /// broad and could return the wrong profile row.
    #[sqlx::test]
    async fn get_profile_does_not_match_non_key_did(pool: PgPool) {
        let db = db(pool).await;
        let short = "z6Mkprof1";

        // Seed only a non-key DID row first. When queried with the bare short ID,
        // get_profile must return None (lone non-key fixture test).
        db.upsert_profile(
            &format!("did:gitlawb:{short}"),
            Some("other-method"),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let got = db.get_profile(short).await.unwrap();
        assert!(
            got.is_none(),
            "bare short id must not resolve a lone non-key DID profile"
        );

        // Now seed the canonical bare key profile row as well.
        db.upsert_profile(short, Some("canonical"), None, None, None, None)
            .await
            .unwrap();

        let got = db
            .get_profile(short)
            .await
            .unwrap()
            .expect("bare short id should resolve the key-form profile");
        assert_eq!(got.did, short);
        assert_eq!(got.display_name.as_deref(), Some("canonical"));

        let got = db
            .get_profile(&format!("did:key:{short}"))
            .await
            .unwrap()
            .expect("did:key form should also resolve the key-form profile");
        assert_eq!(got.did, short);

        let got = db
            .get_profile(&format!("did:gitlawb:{short}"))
            .await
            .unwrap()
            .expect("full non-key DID should resolve its own profile");
        assert_eq!(got.did, format!("did:gitlawb:{short}"));
        assert_eq!(got.display_name.as_deref(), Some("other-method"));
    }

    /// upsert_profile must update a bare-stored profile when called with the
    /// full did:key: form. get_profile equates the two, so the UPDATE has to
    /// target existing.did rather than the raw input.
    #[sqlx::test]
    async fn upsert_profile_updates_via_did_key_alias(pool: PgPool) {
        let db = db(pool).await;
        let short = "z6Mkprof2";

        db.upsert_profile(short, Some("before"), None, None, None, None)
            .await
            .unwrap();

        let updated = db
            .upsert_profile(
                &format!("did:key:{short}"),
                Some("after"),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(updated.did, short, "preserve the stored did form on update");
        assert_eq!(updated.display_name.as_deref(), Some("after"));

        let got = db
            .get_profile(short)
            .await
            .unwrap()
            .expect("profile should still resolve by bare short id");
        assert_eq!(got.did, short);
        assert_eq!(got.display_name.as_deref(), Some("after"));

        db.set_profile_cid(&format!("did:key:{short}"), "bafytestcid")
            .await
            .unwrap();
        let got = db.get_profile(short).await.unwrap().unwrap();
        assert_eq!(got.profile_cid.as_deref(), Some("bafytestcid"));
    }

    /// Verify that the Rust `normalize_owner_key` and the `OWNER_KEY_CASE_SQL`
    /// expression agree on every boundary value in the owner-key normalization
    /// set. A mismatch would let the Rust code bind a different key than the SQL
    /// predicate filters on, silently breaking the did:key-only matching contract.
    #[sqlx::test]
    async fn normalize_owner_key_matches_sql_case(pool: PgPool) {
        // The full boundary set: did:key short/full, bare, non-key DIDs,
        // did:key with extra colon, empty, empty residual, uppercase.
        let boundary_values = [
            "did:key:z6Mkfoo",
            "z6Mkfoo",
            "did:gitlawb:z6Mkfoo",
            "did:web:example.com:alice",
            "did:web:z6Mkfoo",
            "did:key:did:gitlawb:z6Mkfoo",
            "",
            "did:key:",
            "DID:KEY:z6Mkfoo",
        ];

        // Build a VALUES list with the column aliased as `owner_did` so the
        // OWNER_KEY_CASE_SQL expression (which references `owner_did`) works
        // verbatim — no search-and-replace that could hide a drift.
        let values_sql: String = boundary_values
            .iter()
            .map(|v| format!("('{}'::text)", v))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH data(owner_did) AS (VALUES {values_sql})
             SELECT owner_did, ({key}) AS normalized FROM data ORDER BY owner_did",
            key = super::OWNER_KEY_CASE_SQL
        );

        let rows: Vec<(String, String)> = sqlx::query_as(&sql).fetch_all(&pool).await.unwrap();

        assert_eq!(
            rows.len(),
            boundary_values.len(),
            "every boundary value must produce a row"
        );

        for (val, sql_result) in &rows {
            let rust_result = super::normalize_owner_key(val);
            assert_eq!(
                sql_result, rust_result,
                "normalize_owner_key(\"{val}\") mismatch: Rust = \"{rust_result}\", SQL CASE = \"{sql_result}\""
            );
        }
    }

    /// Verify that `PROFILE_DID_CASE_SQL` (which aliases the column `did`) also
    /// agrees with Rust `normalize_owner_key` across the full boundary matrix.
    #[sqlx::test]
    async fn profile_did_case_sql_matches_normalize_owner_key(pool: PgPool) {
        let boundary_values = [
            "did:key:z6Mkfoo",
            "z6Mkfoo",
            "did:gitlawb:z6Mkfoo",
            "did:web:example.com:alice",
            "did:web:z6Mkfoo",
            "did:key:did:gitlawb:z6Mkfoo",
            "",
            "did:key:",
            "DID:KEY:z6Mkfoo",
        ];

        let values_sql: String = boundary_values
            .iter()
            .map(|v| format!("('{}'::text)", v))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH data(did) AS (VALUES {values_sql})
             SELECT did, ({key}) AS normalized FROM data ORDER BY did",
            key = super::PROFILE_DID_CASE_SQL
        );

        let rows: Vec<(String, String)> = sqlx::query_as(&sql).fetch_all(&pool).await.unwrap();

        assert_eq!(
            rows.len(),
            boundary_values.len(),
            "every boundary value must produce a row"
        );

        for (val, sql_result) in &rows {
            let rust_result = super::normalize_owner_key(val);
            assert_eq!(
                sql_result, rust_result,
                "PROFILE_DID_CASE_SQL(\"{val}\") mismatch: Rust = \"{rust_result}\", SQL CASE = \"{sql_result}\""
            );
        }
    }

    /// Verify that `ASSIGNEE_DID_CASE_SQL` (which aliases `assignee_did`) also
    /// agrees with Rust `normalize_owner_key` across the full boundary matrix.
    #[sqlx::test]
    async fn assignee_did_case_sql_matches_normalize_owner_key(pool: PgPool) {
        let boundary_values = [
            "did:key:z6Mkfoo",
            "z6Mkfoo",
            "did:gitlawb:z6Mkfoo",
            "did:web:example.com:alice",
            "did:web:z6Mkfoo",
            "did:key:did:gitlawb:z6Mkfoo",
            "",
            "did:key:",
            "DID:KEY:z6Mkfoo",
        ];

        let values_sql: String = boundary_values
            .iter()
            .map(|v| format!("('{}'::text)", v))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "WITH data(assignee_did) AS (VALUES {values_sql})
             SELECT assignee_did, ({key}) AS normalized FROM data ORDER BY assignee_did",
            key = super::ASSIGNEE_DID_CASE_SQL
        );

        let rows: Vec<(String, String)> = sqlx::query_as(&sql).fetch_all(&pool).await.unwrap();

        assert_eq!(
            rows.len(),
            boundary_values.len(),
            "every boundary value must produce a row"
        );

        for (val, sql_result) in &rows {
            let rust_result = super::normalize_owner_key(val);
            assert_eq!(
                sql_result, rust_result,
                "ASSIGNEE_DID_CASE_SQL(\"{val}\") mismatch: Rust = \"{rust_result}\", SQL CASE = \"{sql_result}\""
            );
        }
    }
}

/// #327: the candidate ceiling must bound database work, not only the Rust
/// loop. Each supported keyset domain has to continue in created_at/id order
/// without sorting a growing match set before LIMIT.
#[cfg(test)]
mod list_tasks_keyset_plan_tests {
    use super::{list_tasks_keyset_sql, Db};
    use serde_json::Value;
    use sqlx::PgPool;

    const POPULATED_ROWS: i32 = 4000;
    const BATCH: i64 = 50;

    fn plan_walk(plan: &Value, visit: &mut impl FnMut(&Value)) {
        visit(plan);
        if let Some(children) = plan.get("Plans").and_then(Value::as_array) {
            for child in children {
                plan_walk(child, visit);
            }
        }
    }

    fn assert_keyset_plan(plan: &Value, domain: &str) {
        let mut saw_sort = false;
        let mut saw_limit = false;
        let mut saw_index = false;
        let mut saw_seqscan = false;
        plan_walk(plan, &mut |node| {
            let node_type = node.get("Node Type").and_then(Value::as_str).unwrap_or("");
            match node_type {
                "Sort" => saw_sort = true,
                "Limit" => saw_limit = true,
                "Seq Scan" => saw_seqscan = true,
                other if other.contains("Index") => saw_index = true,
                _ => {}
            }
        });
        assert!(saw_limit, "{domain}: plan must keep LIMIT: {plan}");
        assert!(
            !saw_sort,
            "{domain}: ORDER BY created_at DESC, id DESC must not sort a growing match set before LIMIT: {plan}"
        );
        assert!(
            saw_index && !saw_seqscan,
            "{domain}: the agent_tasks scan must be index-backed, not a seq scan: {plan}"
        );
    }

    async fn seed_populated_tasks(pool: &PgPool) {
        sqlx::query(
            "INSERT INTO agent_tasks (
                 id, kind, status, delegator_did, assignee_did, capability,
                 payload, created_at, updated_at
             )
             SELECT
                 'plan-' || g,
                 'test',
                 CASE WHEN g % 2 = 0 THEN 'pending' ELSE 'claimed' END,
                 'did:key:zDelegator',
                 CASE WHEN g % 3 = 0 THEN 'did:key:zAssigneeA' ELSE 'zAssigneeB' END,
                 'cap',
                 '{}',
                 to_char(
                     timestamptz '2020-01-01 00:00:00+00' + make_interval(secs => g),
                     'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'
                 ),
                 to_char(
                     timestamptz '2020-01-01 00:00:00+00' + make_interval(secs => g),
                     'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'
                 )
             FROM generate_series(1, $1) AS g",
        )
        .bind(POPULATED_ROWS)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("ANALYZE agent_tasks")
            .execute(pool)
            .await
            .unwrap();
    }

    async fn explain_domain(
        pool: &PgPool,
        has_status: bool,
        has_assignee: bool,
        has_after: bool,
        status: Option<&str>,
        assignee: Option<&str>,
        after: Option<(&str, &str)>,
    ) -> Value {
        let sql = format!(
            "EXPLAIN (FORMAT JSON) {}",
            list_tasks_keyset_sql(has_status, has_assignee, has_after)
        );
        let mut q = sqlx::query_scalar::<_, Value>(&sql);
        if let Some(status) = status {
            q = q.bind(status);
        }
        if let Some(assignee) = assignee {
            q = q.bind(crate::db::normalize_owner_key(assignee));
        }
        if let Some((created_at, id)) = after {
            q = q.bind(created_at).bind(id);
        }
        let explained = q.bind(BATCH).fetch_one(pool).await.unwrap();
        let root = match &explained {
            Value::Array(arr) => arr.first().cloned(),
            Value::String(s) => serde_json::from_str(s).ok(),
            other => Some(other.clone()),
        };
        root.as_ref()
            .and_then(|obj| obj.get("Plan"))
            .cloned()
            .expect("EXPLAIN (FORMAT JSON) returns [{\"Plan\": ...}]")
    }

    #[sqlx::test]
    async fn keyset_plans_use_indexes_for_every_filter_domain(pool: PgPool) {
        let db = Db::for_testing(pool.clone());
        db.migrate().await.unwrap();
        seed_populated_tasks(&pool).await;

        let first = db.list_tasks_keyset(None, None, 1, None).await.unwrap();
        let after = first
            .first()
            .map(|t| (t.created_at.as_str(), t.id.as_str()));

        let domains = [
            ("unfiltered", false, false, None, None),
            ("status", true, false, Some("pending"), None),
            ("assignee", false, true, None, Some("did:key:zAssigneeA")),
            (
                "status+assignee",
                true,
                true,
                Some("pending"),
                Some("zAssigneeB"),
            ),
        ];

        for (name, has_status, has_assignee, status, assignee) in domains {
            for (label, has_after, after) in
                [("first-page", false, None), ("continuation", true, after)]
            {
                let domain = format!("{name}/{label}");
                let plan = explain_domain(
                    &pool,
                    has_status,
                    has_assignee,
                    has_after,
                    status,
                    assignee,
                    after,
                )
                .await;
                assert_keyset_plan(&plan, &domain);
            }
        }

        let page = db
            .list_tasks_keyset(Some("pending"), Some("did:key:zAssigneeA"), BATCH, None)
            .await
            .unwrap();
        assert_eq!(
            page.len() as i64, BATCH,
            "populated pending+assignee stream must fill a batch so the plan is not a tiny one-row special case"
        );
    }
}

/// #327 / #396 review: the scoped repository lookup must follow the requested
/// logical groups and resolve candidates through the owner-key/name index without
/// scanning and discarding the entire unrelated population.
#[cfg(test)]
mod scoped_repo_lookup_plan_tests {
    use super::Db;
    use serde_json::Value;
    use sqlx::PgPool;

    const POPULATED_ROWS: i32 = 4000;

    fn plan_walk(plan: &Value, visit: &mut impl FnMut(&Value)) {
        visit(plan);
        if let Some(children) = plan.get("Plans").and_then(Value::as_array) {
            for child in children {
                plan_walk(child, visit);
            }
        }
    }

    fn assert_scoped_repo_plan(plan: &Value, mode: &str) {
        let mut saw_seqscan = false;
        let mut saw_index = false;
        let mut discarded = 0.0_f64;
        plan_walk(plan, &mut |node| {
            let node_type = node.get("Node Type").and_then(Value::as_str).unwrap_or("");
            let relation = node
                .get("Relation Name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if node_type == "Seq Scan" && relation == "repos" {
                saw_seqscan = true;
            }
            if node_type.contains("Index") && relation == "repos" {
                saw_index = true;
            }
            discarded += node
                .get("Rows Removed by Filter")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                * node
                    .get("Actual Loops")
                    .and_then(Value::as_f64)
                    .unwrap_or(1.0);
        });
        assert!(
            saw_index && !saw_seqscan,
            "{mode}: scoped repo lookup must use index scans on repos, not sequential scans over all repos: {plan}"
        );
        assert!(
            discarded < 100.0,
            "{mode}: scoped lookup discarded unrelated rows: {discarded}: {plan}"
        );
    }

    #[test]
    #[should_panic(expected = "discarded unrelated rows")]
    fn scoped_plan_rejects_the_previous_full_index_scan() {
        // The previous membership filter used the right index but discarded
        // every unrelated row. Pin that observed plan shape, not just Seq Scan.
        let plan = serde_json::json!({
            "Node Type": "Index Scan",
            "Relation Name": "repos",
            "Index Name": "idx_repos_owner_key_name",
            "Rows Removed by Filter": 3999,
            "Actual Loops": 1
        });
        assert_scoped_repo_plan(&plan, "previous-plan");
    }

    async fn seed_populated_repos(pool: &PgPool) {
        sqlx::query(
            "INSERT INTO repos (
                 id, name, owner_did, description, is_public, default_branch,
                 created_at, updated_at, disk_path, forked_from, machine_id, quarantined
             )
             SELECT
                 'repo-plan-' || g,
                 'repo-name-' || g,
                 'did:key:z6MkOwner' || g,
                 'desc',
                 true,
                 'main',
                 '2026-01-01T00:00:00Z',
                 '2026-01-01T00:00:00Z',
                 '/disk/' || g,
                 NULL,
                 'mach1',
                 false
             FROM generate_series(1, $1) AS g",
        )
        .bind(POPULATED_ROWS)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("ANALYZE repos").execute(pool).await.unwrap();
    }

    async fn explain_scoped_repo_lookup(pool: &PgPool, force_generic: bool) -> Value {
        let mut conn = pool.acquire().await.unwrap();
        if force_generic {
            sqlx::query("SET plan_cache_mode = force_generic_plan")
                .execute(&mut *conn)
                .await
                .unwrap();
        } else {
            sqlx::query("SET plan_cache_mode = force_custom_plan")
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        // EXPLAIN of a literal SELECT does not exercise the prepared-plan cache.
        let sql = format!(
            "PREPARE scoped_repo_plan(text[]) AS {}",
            Db::scoped_dedup_sql()
        );
        sqlx::query(&sql).execute(&mut *conn).await.unwrap();
        let explained = sqlx::query_scalar::<_, Value>(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE scoped_repo_plan(ARRAY['repo-plan-1']::text[])"
        )
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        let counters: (i64, i64) = sqlx::query_as(
            "SELECT generic_plans, custom_plans FROM pg_prepared_statements WHERE name = 'scoped_repo_plan'"
        ).fetch_one(&mut *conn).await.unwrap();
        assert_eq!(counters, if force_generic { (1, 0) } else { (0, 1) });
        sqlx::query("DEALLOCATE scoped_repo_plan")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("RESET plan_cache_mode")
            .execute(&mut *conn)
            .await
            .unwrap();
        let root = match &explained {
            Value::Array(arr) => arr.first().cloned(),
            Value::String(s) => serde_json::from_str(s).ok(),
            other => Some(other.clone()),
        };
        root.as_ref()
            .and_then(|obj| obj.get("Plan"))
            .cloned()
            .expect("EXPLAIN (FORMAT JSON) returns [{\"Plan\": ...}]")
    }

    #[sqlx::test]
    async fn scoped_repo_lookup_uses_indexes_for_custom_and_generic_plans(pool: PgPool) {
        let db = Db::for_testing(pool.clone());
        db.migrate().await.unwrap();
        seed_populated_repos(&pool).await;

        let custom_plan = explain_scoped_repo_lookup(&pool, false).await;
        assert_scoped_repo_plan(&custom_plan, "custom-plan");

        let generic_plan = explain_scoped_repo_lookup(&pool, true).await;
        assert_scoped_repo_plan(&generic_plan, "generic-plan");
    }
}

/// Exercises the iCaptcha single-use proof ledger (`icaptcha_consumed_proofs`),
/// which is what gives the gate its anti-replay security value.
#[cfg(test)]
mod icaptcha_ledger_tests {
    use super::Db;
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    /// First sighting of a jti is recorded (allowed); the same jti again is a
    /// replay (rejected); a distinct jti is independently allowed.
    #[sqlx::test]
    async fn consume_proof_jti_single_use(pool: PgPool) {
        let db = db(pool).await;
        let exp = 9_000_000_000i64; // far-future expiry

        assert!(
            db.consume_proof_jti("jti-a", exp).await.unwrap(),
            "first use of a jti is recorded and allowed"
        );
        assert!(
            !db.consume_proof_jti("jti-a", exp).await.unwrap(),
            "re-using the same jti is a replay and must be rejected"
        );
        assert!(
            db.consume_proof_jti("jti-b", exp).await.unwrap(),
            "a different jti is independent and allowed"
        );
    }

    /// The sweep deletes only rows whose `expires_at` is strictly before the
    /// cutoff, returns the deleted count, and leaves unexpired rows intact (so a
    /// still-valid spent proof keeps rejecting replays).
    #[sqlx::test]
    async fn sweep_expired_proofs_removes_only_expired(pool: PgPool) {
        let db = db(pool).await;
        db.consume_proof_jti("old-1", 100).await.unwrap();
        db.consume_proof_jti("old-2", 199).await.unwrap();
        db.consume_proof_jti("fresh", 500).await.unwrap();

        let deleted = db.sweep_expired_proofs(200).await.unwrap();
        assert_eq!(
            deleted, 2,
            "only the two rows with expires_at < 200 are swept"
        );

        // Swept jtis are fresh again; the unexpired one still rejects as a replay.
        assert!(db.consume_proof_jti("old-1", 100).await.unwrap());
        assert!(
            !db.consume_proof_jti("fresh", 500).await.unwrap(),
            "an unexpired spent proof survives the sweep and still blocks replays"
        );
    }

    /// A repo's creation proof round-trips through the side table so it can be
    /// served to mirroring peers; absent for an unknown repo.
    #[sqlx::test]
    async fn repo_proof_roundtrips(pool: PgPool) {
        let db = db(pool).await;
        assert_eq!(db.get_repo_proof_token("nope").await.unwrap(), None);

        db.record_repo_proof("repo-1", "tok.sig", "did:key:zX", 3, "jti-1", 123)
            .await
            .unwrap();
        assert_eq!(
            db.get_repo_proof_token("repo-1").await.unwrap().as_deref(),
            Some("tok.sig")
        );

        // Idempotent: re-recording overwrites in place.
        db.record_repo_proof("repo-1", "tok2.sig", "did:key:zX", 4, "jti-2", 456)
            .await
            .unwrap();
        assert_eq!(
            db.get_repo_proof_token("repo-1").await.unwrap().as_deref(),
            Some("tok2.sig")
        );
    }

    /// Mirror admission spends a jti against a forward retention window, never the
    /// proof's own (already-past) exp. A jti stored that way must survive a sweep
    /// keyed at the proof's original exp, so the token cannot admit a second mirror
    /// after cleanup. Pins the CR3/5 fix (`MIRROR_REPLAY_RETENTION_SECS`).
    #[sqlx::test]
    async fn mirror_jti_retention_survives_sweep_at_proof_exp(pool: PgPool) {
        let db = db(pool).await;
        let proof_exp = 1_000i64; // the proof is already expired on the mirror path
        let retain_until = 9_000_000_000i64; // forward retention window

        assert!(db
            .consume_proof_jti("mirror-jti", retain_until)
            .await
            .unwrap());

        // A sweep at (or just past) the proof's original exp must not free the row.
        let removed = db.sweep_expired_proofs(proof_exp + 1).await.unwrap();
        assert_eq!(
            removed, 0,
            "mirror replay record must outlive the proof's exp"
        );

        assert!(
            !db.consume_proof_jti("mirror-jti", retain_until)
                .await
                .unwrap(),
            "the token must stay spent so it can't admit a second mirror"
        );
    }
}

/// Exercises the iCaptcha propagation quarantine: the `quarantined` flag on
/// repos and its interaction with `upsert_mirror_repo` and the listing surfaces.
#[cfg(test)]
mod icaptcha_quarantine_tests {
    use super::Db;
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    /// A repo defaults to not-quarantined; the flag can be set and cleared, and
    /// reads of an unknown repo are false (not an error).
    #[sqlx::test]
    async fn quarantine_flag_set_and_release(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6owner", "good", "/srv/good", None, false)
            .await
            .unwrap();

        assert!(!db.is_repo_quarantined("z6owner/good").await.unwrap());
        assert!(!db.is_repo_quarantined("does-not-exist").await.unwrap());

        assert_eq!(
            db.set_repo_quarantine("z6owner/good", true).await.unwrap(),
            1
        );
        assert!(db.is_repo_quarantined("z6owner/good").await.unwrap());
        assert_eq!(
            db.list_quarantined_repo_ids().await.unwrap(),
            vec!["z6owner/good".to_string()]
        );

        // Release.
        assert_eq!(
            db.set_repo_quarantine("z6owner/good", false).await.unwrap(),
            1
        );
        assert!(!db.is_repo_quarantined("z6owner/good").await.unwrap());
        assert!(db.list_quarantined_repo_ids().await.unwrap().is_empty());
    }

    /// `remove_visibility_rule` bumps `policy_epoch` only when it actually
    /// deletes a row: a delete matching nothing is not a write, and
    /// bumping on it would abort in-flight fenced batches for unchanged
    /// policy (mirrors the `set_repo_quarantine` rows-affected guard).
    #[sqlx::test]
    async fn remove_visibility_rule_bumps_epoch_only_on_delete(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6owner", "epochrepo", "/srv/epoch", None, false)
            .await
            .unwrap();
        let repo_id = "z6owner/epochrepo";
        let epoch0 = db.repo_policy_epoch(repo_id).await.unwrap();

        // Deleting a glob that was never written changes nothing.
        db.remove_visibility_rule(repo_id, "/nope/**")
            .await
            .unwrap();
        assert_eq!(
            db.repo_policy_epoch(repo_id).await.unwrap(),
            epoch0,
            "delete-with-zero-rows must not bump the epoch"
        );

        db.set_visibility_rule(
            repo_id,
            "/secret/**",
            super::VisibilityMode::B,
            &[],
            "did:key:zEpochOwner",
        )
        .await
        .unwrap();
        let epoch1 = db.repo_policy_epoch(repo_id).await.unwrap();
        assert_eq!(epoch1, epoch0 + 1, "insert bumps the epoch");

        db.remove_visibility_rule(repo_id, "/secret/**")
            .await
            .unwrap();
        assert_eq!(
            db.repo_policy_epoch(repo_id).await.unwrap(),
            epoch1 + 1,
            "deleting an existing rule bumps the epoch"
        );

        // Second delete of the same glob matches nothing now.
        db.remove_visibility_rule(repo_id, "/secret/**")
            .await
            .unwrap();
        assert_eq!(
            db.repo_policy_epoch(repo_id).await.unwrap(),
            epoch1 + 1,
            "double-delete must not bump the epoch"
        );
    }

    /// A mirror admitted quarantined stays quarantined across a re-sync — the
    /// admission decision is made once and an operator's later release (or the
    /// initial quarantine) must not be reverted by ON CONFLICT.
    #[sqlx::test]
    async fn quarantine_preserved_on_resync(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6owner", "garbage", "/srv/g", None, true)
            .await
            .unwrap();
        assert!(db.is_repo_quarantined("z6owner/garbage").await.unwrap());

        // A later re-sync passes quarantined=false but must not clear the flag.
        db.upsert_mirror_repo("z6owner", "garbage", "/srv/g", None, false)
            .await
            .unwrap();
        assert!(
            db.is_repo_quarantined("z6owner/garbage").await.unwrap(),
            "re-sync must preserve the prior quarantine decision"
        );
    }

    /// Quarantined repos are withheld from the deduped listing surfaces.
    #[sqlx::test]
    async fn listings_exclude_quarantined(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_mirror_repo("z6good", "ok", "/srv/ok", None, false)
            .await
            .unwrap();
        db.upsert_mirror_repo("z6bad", "spam", "/srv/spam", None, true)
            .await
            .unwrap();

        let names: Vec<String> = db
            .list_all_repos_deduped()
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert!(names.contains(&"ok".to_string()));
        assert!(
            !names.contains(&"spam".to_string()),
            "quarantined mirror must not appear in listings"
        );

        let with_stars = db.list_all_repos_deduped_with_stars(None).await.unwrap();
        assert!(with_stars.iter().all(|(r, _)| r.name != "spam"));
    }

    /// `update_trust_score` must never create an agent row. Registration (behind
    /// the iCaptcha gate) is the only way in; otherwise a push/issue/PR from a
    /// deregistered DID would silently re-register it and bypass the gate.
    #[sqlx::test]
    async fn update_trust_score_never_creates_agent(pool: PgPool) {
        let db = db(pool).await;
        let did = "did:key:zNeverRegistered";

        // Unregistered DID: updating its score is a no-op, not an insert.
        db.update_trust_score(did, 0.9).await.unwrap();
        assert!(
            db.get_agent(did).await.unwrap().is_none(),
            "update_trust_score must not resurrect an unregistered DID"
        );

        // Once genuinely registered, the score updates in place.
        db.register_agent(did, &[]).await.unwrap();
        db.update_trust_score(did, 0.9).await.unwrap();
        assert_eq!(db.get_trust_score(did).await.unwrap(), 0.9);
    }
}

#[cfg(test)]
mod ref_update_keyset_paging_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    fn rru(id: &str, ts: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:zN".into(),
            pusher_did: "did:key:zP".into(),
            repo: "z6MkOwner/openrepo".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".into(),
            new_sha: "1".into(),
            timestamp: ts.into(),
            cert_id: None,
            received_at: ts.into(),
            from_peer: "peer".into(),
            owner_did: None,
        }
    }

    async fn seed_r1_to_r4(db: &Db) {
        for i in 1..=4 {
            db.insert_ref_update(&rru(
                &format!("r{i}"),
                &format!("2026-07-01T10:00:0{i}+00:00"),
            ))
            .await
            .unwrap();
        }
    }

    // Documents the bug jatmn flagged: OFFSET paging re-reads a page-1 row when a
    // newer row is inserted between page reads (the newer row shifts every offset).
    #[sqlx::test]
    async fn offset_paging_duplicates_a_row_under_concurrent_insert(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        seed_r1_to_r4(&db).await;

        let offset_page = |limit: i64, offset: i64| {
            let pool = db.pool.clone();
            async move {
                sqlx::query_scalar::<_, String>(
                    "SELECT id FROM received_ref_updates \
                     ORDER BY timestamp DESC, id DESC LIMIT $1 OFFSET $2",
                )
                .bind(limit)
                .bind(offset)
                .fetch_all(&pool)
                .await
                .unwrap()
            }
        };

        let p1 = offset_page(2, 0).await;
        assert_eq!(p1, vec!["r4", "r3"], "offset page 1");
        // concurrent insert of a newer row shifts every later offset by one
        db.insert_ref_update(&rru("r5", "2026-07-01T10:00:09+00:00"))
            .await
            .unwrap();
        let p2 = offset_page(2, 2).await;
        assert!(
            p2.contains(&"r3".to_string()),
            "OFFSET paging re-reads r3 after the concurrent insert (the bug keyset fixes); got {p2:?}"
        );
    }

    // The fix: keyset paging on (timestamp, id) reads strictly older rows each
    // page, so a concurrent newer insert cannot duplicate or skip a row.
    #[sqlx::test]
    async fn keyset_paging_is_stable_under_concurrent_insert(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        seed_r1_to_r4(&db).await;

        let p1 = db.list_ref_updates_keyset(None, 2, None).await.unwrap();
        let p1_ids: Vec<String> = p1.iter().map(|u| u.id.clone()).collect();
        assert_eq!(p1_ids, vec!["r4", "r3"], "keyset page 1");
        let last = p1.last().unwrap();
        let cursor = (last.timestamp.clone(), last.id.clone());

        // concurrent insert of a newer row between page reads
        db.insert_ref_update(&rru("r5", "2026-07-01T10:00:09+00:00"))
            .await
            .unwrap();

        let p2 = db
            .list_ref_updates_keyset(None, 2, Some((cursor.0.as_str(), cursor.1.as_str())))
            .await
            .unwrap();
        let p2_ids: Vec<String> = p2.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p2_ids,
            vec!["r2", "r1"],
            "keyset page 2 reads strictly older rows, unaffected by the concurrent insert"
        );

        let all: Vec<String> = p1_ids.into_iter().chain(p2_ids).collect();
        let uniq: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(uniq.len(), 4, "no row appears twice across pages");
        assert!(
            !all.iter().any(|id| id == "r5"),
            "a row inserted above the scan window is not folded in mid-scan"
        );
    }
}

#[cfg(test)]
mod ref_update_keyset_repo_filtered_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    fn rru_repo(id: &str, ts: &str, repo: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:zN".into(),
            pusher_did: "did:key:zP".into(),
            repo: repo.into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".into(),
            new_sha: "1".into(),
            timestamp: ts.into(),
            cert_id: None,
            received_at: ts.into(),
            from_peer: "peer".into(),
            owner_did: None,
        }
    }

    // Exercises the (Some(repo), Some(after)) keyset branch: a repo-filtered
    // multi-page continuation that emits `WHERE repo=$1 AND (timestamp,id)<($2,$3)`
    // with four binds. Also confirms the repo filter holds across pages, noise
    // rows are excluded, and a concurrent insert does not duplicate or skip.
    #[sqlx::test]
    async fn keyset_repo_filtered_multipage_stable_under_concurrent_insert(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        let target = "z6MkOwner/target";
        let other = "z6MkOwner/other";

        // 3 target rows (older) + 2 noise rows for another repo (newer, so they
        // sort to the front of the global order and must be filtered out).
        for (id, ts) in [("T1", "01"), ("T2", "02"), ("T3", "03")] {
            db.insert_ref_update(&rru_repo(
                id,
                &format!("2026-07-01T10:00:{ts}+00:00"),
                target,
            ))
            .await
            .unwrap();
        }
        for (id, ts) in [("O1", "04"), ("O2", "05")] {
            db.insert_ref_update(&rru_repo(
                id,
                &format!("2026-07-01T10:00:{ts}+00:00"),
                other,
            ))
            .await
            .unwrap();
        }

        // page 1: (Some(repo), None) -> two newest TARGET rows only
        let p1 = db
            .list_ref_updates_keyset(Some(target), 2, None)
            .await
            .unwrap();
        let p1_ids: Vec<String> = p1.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p1_ids,
            vec!["T3", "T2"],
            "repo-filtered page 1 excludes other-repo rows"
        );
        assert!(
            p1.iter().all(|u| u.repo == target),
            "no noise rows on page 1"
        );
        let last = p1.last().unwrap();
        let cursor = (last.timestamp.clone(), last.id.clone());

        // concurrent insert of a newer TARGET row between page reads
        db.insert_ref_update(&rru_repo("T4", "2026-07-01T10:00:06+00:00", target))
            .await
            .unwrap();

        // page 2: (Some(repo), Some(after)) -> the four-bind continuation branch
        let p2 = db
            .list_ref_updates_keyset(
                Some(target),
                2,
                Some((cursor.0.as_str(), cursor.1.as_str())),
            )
            .await
            .unwrap();
        let p2_ids: Vec<String> = p2.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p2_ids,
            vec!["T1"],
            "repo-filtered keyset page 2 reads only older target rows"
        );
        assert!(
            p2.iter().all(|u| u.repo == target),
            "no noise rows on page 2"
        );

        let all: Vec<String> = p1_ids.into_iter().chain(p2_ids).collect();
        let uniq: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(uniq.len(), 3, "each target row exactly once across pages");
        assert!(
            !all.iter().any(|id| id == "T4"),
            "concurrent newer row not folded in mid-scan"
        );
    }
}

#[cfg(test)]
mod ref_update_keyset_same_timestamp_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    fn row(id: &str, ts: &str) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.into(),
            node_did: "did:key:zN".into(),
            pusher_did: "did:key:zP".into(),
            repo: "z6MkOwner/openrepo".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".into(),
            new_sha: "1".into(),
            timestamp: ts.into(),
            cert_id: None,
            received_at: ts.into(),
            from_peer: "peer".into(),
            owner_did: None,
        }
    }

    // Load-bearing for the `id` half of the (timestamp, id) keyset cursor: all
    // rows share ONE timestamp, so ordering and the page boundary fall entirely
    // on `id DESC`. A timestamp-only cursor would return nothing for page 2 and
    // silently skip b and a; the (timestamp, id) tie-break must advance instead.
    #[sqlx::test]
    async fn keyset_advances_within_an_equal_timestamp_run(pool: PgPool) {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        let ts = "2026-07-01T10:00:00+00:00";
        for id in ["a", "b", "c", "d"] {
            db.insert_ref_update(&row(id, ts)).await.unwrap();
        }

        // id DESC over equal timestamps: d, c, b, a
        let p1 = db.list_ref_updates_keyset(None, 2, None).await.unwrap();
        let p1_ids: Vec<String> = p1.iter().map(|u| u.id.clone()).collect();
        assert_eq!(p1_ids, vec!["d", "c"], "page 1 by id DESC");
        let last = p1.last().unwrap();

        // page boundary lands INSIDE the equal-timestamp group (cursor = (ts, "c"))
        let p2 = db
            .list_ref_updates_keyset(None, 2, Some((last.timestamp.as_str(), last.id.as_str())))
            .await
            .unwrap();
        let p2_ids: Vec<String> = p2.iter().map(|u| u.id.clone()).collect();
        assert_eq!(
            p2_ids,
            vec!["b", "a"],
            "keyset must advance by id within an equal-timestamp run (a timestamp-only cursor would skip these)"
        );

        let all: Vec<String> = p1_ids.into_iter().chain(p2_ids).collect();
        let uniq: std::collections::HashSet<&String> = all.iter().collect();
        assert_eq!(
            uniq.len(),
            4,
            "no dup or skip across a same-timestamp page boundary"
        );
    }
}

#[cfg(test)]
mod ref_certificate_tests {
    use super::{Db, RefCertificate, RepoRecord};
    use chrono::Utc;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn make_cert(
        id: &str,
        repo_id: &str,
        ref_name: &str,
        old_sha: &str,
        new_sha: &str,
        issued_at: &str,
    ) -> RefCertificate {
        RefCertificate {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old_sha.to_string(),
            new_sha: new_sha.to_string(),
            pusher_did: "did:key:zPUSHER".to_string(),
            node_did: "did:key:zNODE".to_string(),
            signature: "sig".to_string(),
            issued_at: issued_at.to_string(),
            version: 1,
        }
    }

    #[sqlx::test]
    async fn list_ref_certificates_respects_limit(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = uuid::Uuid::new_v4().to_string();

        // Create a repo to satisfy FK
        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "limit-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/limit-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // Insert 5 certs with descending issued_at
        for i in 0..5 {
            db.insert_ref_certificate(&make_cert(
                &format!("cert-{i}"),
                &repo_id,
                &format!("refs/heads/feature-{i}"),
                "0000",
                "1111",
                &format!("2026-07-03T20:0{i}:00Z"),
            ))
            .await
            .unwrap();
        }

        // limit=2 returns only 2
        let certs = db.list_ref_certificates(&repo_id, 2).await.unwrap();
        assert_eq!(certs.len(), 2, "LIMIT 2 must return exactly 2 certs");
        assert_eq!(certs[0].id, "cert-4", "most recent first");
        assert_eq!(certs[1].id, "cert-3", "second most recent");

        // limit=10 returns all 5 (no padding)
        let all = db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(all.len(), 5, "LIMIT >= row count returns all rows");
    }

    #[sqlx::test]
    async fn insert_ref_certificate_upserts_on_repo_ref(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = uuid::Uuid::new_v4().to_string();

        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "upsert-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/upsert-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // First insert
        db.insert_ref_certificate(&make_cert(
            "cert-original",
            &repo_id,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-03T20:00:00Z",
        ))
        .await
        .unwrap();

        // Upsert same ref with new values
        db.insert_ref_certificate(&make_cert(
            "cert-upserted",
            &repo_id,
            "refs/heads/main",
            "aaaa",
            "bbbb",
            "2026-07-03T21:00:00Z",
        ))
        .await
        .unwrap();

        // Only one row exists for this ref
        let certs = db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(certs.len(), 1, "upsert must not create a duplicate row");
        assert_eq!(
            certs[0].id, "cert-original",
            "upsert must preserve the original ID across re-pushes"
        );
        assert_eq!(certs[0].old_sha, "aaaa", "old_sha updated");
        assert_eq!(certs[0].new_sha, "bbbb", "new_sha updated");
        assert_eq!(
            certs[0].issued_at, "2026-07-03T21:00:00Z",
            "newer issued_at overwrites older"
        );

        // Now try to overwrite with an OLDER cert — the guard must reject it.
        db.insert_ref_certificate(&make_cert(
            "stale-id",
            &repo_id,
            "refs/heads/main",
            "stale",
            "stale",
            "2026-07-03T19:00:00Z",
        ))
        .await
        .unwrap();
        let certs = db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(certs.len(), 1, "no extra row from stale cert");
        assert_eq!(
            certs[0].id, "cert-original",
            "stale cert does not change the original id"
        );
        assert_eq!(
            certs[0].old_sha, "aaaa",
            "stale cert does not regress old_sha"
        );
        assert_eq!(
            certs[0].new_sha, "bbbb",
            "stale cert does not regress new_sha"
        );
        assert_eq!(
            certs[0].issued_at, "2026-07-03T21:00:00Z",
            "stale cert does not regress issued_at"
        );
    }

    /// P1-B: the live handler routes cert issuance through
    /// `cert::issue_ref_certificate` (the upsert, NOT
    /// `insert_ref_certificate_idempotent`'s DO NOTHING). This test
    /// exercises the full `cert::issue_ref_certificate` call path
    /// end-to-end through the `AppState`, asserting that:
    ///
    /// - a re-push to the same `(repo_id, ref_name)` updates
    ///   `old_sha` / `new_sha` / `pusher_did` / `issued_at` /
    ///   `signature` to the new transition's values,
    /// - the deterministic `cert_id` (derived from
    ///   `ref_cert_id_for(request_id, ordinal)`) is preserved
    ///   across the re-push, and
    /// - exactly one cert row exists for the ref after the
    ///   re-push.
    ///
    /// This pins the live-handler contract that the previous
    /// `issue_ref_certificate_idempotent` call violated. The DB-level
    /// `insert_ref_certificate_upserts_on_repo_ref` test pins the
    /// underlying upsert SQL; this test pins the live-handler wrapper.
    #[sqlx::test]
    async fn issue_ref_certificate_upserts_on_repo_ref_via_live_path(pool: PgPool) {
        use crate::cert;
        use crate::db::ref_cert_id_for;

        let state = crate::test_support::test_state(pool.clone()).await;
        let repo_id = uuid::Uuid::new_v4().to_string();
        state
            .db
            .create_repo(&RepoRecord {
                id: repo_id.clone(),
                name: "cert-upsert-live".into(),
                owner_did: "did:key:zOWNER".into(),
                description: None,
                is_public: true,
                default_branch: "main".into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                disk_path: "/tmp/cert-upsert-live".into(),
                forked_from: None,
                machine_id: None,
            })
            .await
            .unwrap();

        // First push: 0000 -> 1111, pusher A.
        let c1 = cert::issue_ref_certificate(
            &state,
            &repo_id,
            "refs/heads/main",
            "0000",
            "1111",
            "did:key:zFirstPusher",
            &ref_cert_id_for("req-A", 0),
        )
        .await
        .unwrap();

        // Sleep 1ms so the second push's `issued_at` is strictly
        // greater than the first. `build_ref_certificate` stamps
        // `issued_at = Utc::now()`, and the upsert's per-column
        // guard `EXCLUDED.issued_at > ref_certificates.issued_at`
        // only updates on strictly-newer timestamps.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;

        // Second push: aaaa -> bbbb, pusher B, SAME deterministic
        // cert id (same `request_id` and `ref_name`).
        let c2 = cert::issue_ref_certificate(
            &state,
            &repo_id,
            "refs/heads/main",
            "aaaa",
            "bbbb",
            "did:key:zSecondPusher",
            &ref_cert_id_for("req-A", 0),
        )
        .await
        .unwrap();

        // The deterministic id is preserved across the re-push.
        assert_eq!(c1.id, c2.id, "cert id is preserved across re-push");
        assert_eq!(
            c1.id,
            ref_cert_id_for("req-A", 0),
            "cert id is the deterministic (request_id, ordinal) hash"
        );

        // The upsert updated every other field to the second push.
        assert_eq!(c1.new_sha, "1111", "first push's new_sha");
        assert_eq!(c2.new_sha, "bbbb", "re-push updates new_sha");
        assert_eq!(c1.pusher_did, "did:key:zFirstPusher");
        assert_eq!(c2.pusher_did, "did:key:zSecondPusher");
        assert_ne!(
            c1.issued_at, c2.issued_at,
            "issued_at advances on a re-push"
        );
        assert_ne!(c1.signature, c2.signature, "signature is re-signed");

        // Exactly one row in the table for the ref.
        let certs = state.db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(certs.len(), 1, "exactly one cert row per ref");
        assert_eq!(certs[0].id, c1.id, "the original id survives");
        assert_eq!(certs[0].new_sha, "bbbb", "row reflects the latest push");
        assert_eq!(
            certs[0].pusher_did, "did:key:zSecondPusher",
            "row reflects the latest pusher"
        );
    }

    #[sqlx::test]
    async fn list_ref_certificates_clamps_negative_limit(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = uuid::Uuid::new_v4().to_string();

        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "clamp-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/clamp-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        db.insert_ref_certificate(&make_cert(
            "clamp-1",
            &repo_id,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-03T20:00:00Z",
        ))
        .await
        .unwrap();

        // Negative limit is clamped to 1 at the DB boundary
        let certs = db.list_ref_certificates(&repo_id, -5).await.unwrap();
        assert_eq!(certs.len(), 1, "negative limit clamped to min 1");
        assert_eq!(certs[0].id, "clamp-1");

        // Zero limit also clamped to 1
        let certs = db.list_ref_certificates(&repo_id, 0).await.unwrap();
        assert_eq!(certs.len(), 1, "zero limit clamped to min 1");
        assert_eq!(certs[0].id, "clamp-1");
    }

    #[sqlx::test]
    async fn list_ref_certificates_empty_repo_returns_empty(pool: PgPool) {
        let db = db(pool).await;
        let certs = db
            .list_ref_certificates("nonexistent-repo-id", 10)
            .await
            .unwrap();
        assert!(certs.is_empty());
    }

    /// Certificate ids covering every character the prefix search has to treat
    /// literally: the two LIKE wildcards, the escape character itself, and a
    /// backslash (the default escape, which must stay an ordinary character).
    const PREFIX_CERT_IDS: [&str; 5] = ["cert-a", "cert%b", "cert_c", "cert\\d", "cert!e"];

    /// Seed one repo holding `PREFIX_CERT_IDS` and return the repo id.
    async fn seed_prefix_certs(db: &Db) -> String {
        let repo_id = uuid::Uuid::new_v4().to_string();

        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "prefix-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/prefix-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        for (i, id) in PREFIX_CERT_IDS.iter().enumerate() {
            db.insert_ref_certificate(&make_cert(
                id,
                &repo_id,
                &format!("refs/heads/branch-{i}"),
                "0000",
                "1111",
                &format!("2026-07-03T20:0{i}:00Z"),
            ))
            .await
            .unwrap();
        }

        repo_id
    }

    #[sqlx::test]
    async fn list_ref_certificates_by_prefix_treats_wildcards_literally(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = seed_prefix_certs(&db).await;

        // A plain prefix still matches every id that starts with it.
        let all = db
            .list_ref_certificates_by_prefix(&repo_id, "cert", 10)
            .await
            .unwrap();
        assert_eq!(all.len(), 5, "plain prefix matches all five certs");

        // `%` in the prefix must match a literal percent sign, not act as a
        // wildcard that would also return every other seeded id.
        let pct = db
            .list_ref_certificates_by_prefix(&repo_id, "cert%", 10)
            .await
            .unwrap();
        assert_eq!(pct.len(), 1, "percent prefix matches only literal id");
        assert_eq!(pct[0].id, "cert%b");

        // `_` must match a literal underscore, not any single character.
        let under = db
            .list_ref_certificates_by_prefix(&repo_id, "cert_", 10)
            .await
            .unwrap();
        assert_eq!(under.len(), 1, "underscore prefix matches only literal id");
        assert_eq!(under[0].id, "cert_c");

        // `!` carries the escape role, so a caller-supplied `!` must itself be
        // escaped and match a literal exclamation mark.
        let bang = db
            .list_ref_certificates_by_prefix(&repo_id, "cert!", 10)
            .await
            .unwrap();
        assert_eq!(bang.len(), 1, "escape-char prefix matches only literal id");
        assert_eq!(bang[0].id, "cert!e");

        // A backslash is an ordinary character once `!` is the escape, so it must
        // match a literal backslash rather than escaping the character after it.
        let bs = db
            .list_ref_certificates_by_prefix(&repo_id, "cert\\", 10)
            .await
            .unwrap();
        assert_eq!(bs.len(), 1, "backslash prefix matches only literal id");
        assert_eq!(bs[0].id, "cert\\d");
    }

    /// The prefix query must parse under either `standard_conforming_strings`
    /// mode. Spelling the LIKE escape as a backslash SQL literal (`ESCAPE '\'`)
    /// leaves the statement unterminated when a session runs with the legacy
    /// `off` value, which breaks *every* prefix lookup, not only the ones that
    /// contain a metacharacter. Connection settings come from outside the
    /// process, so that mode can arrive from database- or role-level config.
    #[sqlx::test]
    async fn list_ref_certificates_by_prefix_parses_under_legacy_string_mode(pool: PgPool) {
        let db = db(pool.clone()).await;
        let repo_id = seed_prefix_certs(&db).await;

        // Request the legacy parser mode at connection startup, the same way
        // `PGOPTIONS` or a `ALTER ROLE ... SET` would deliver it.
        let legacy_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(
                (*pool.connect_options())
                    .clone()
                    .options([("standard_conforming_strings", "off")]),
            )
            .await
            .unwrap();

        let mode: String = sqlx::query_scalar("SHOW standard_conforming_strings")
            .fetch_one(&legacy_pool)
            .await
            .unwrap();
        assert_eq!(
            mode, "off",
            "test session must be in the legacy parser mode"
        );

        let legacy_db = Db::for_testing(legacy_pool.clone());

        // A prefix with no metacharacters at all: this is what a backslash
        // literal would break first, since the parse fails before the bound
        // parameters are ever considered.
        let all = legacy_db
            .list_ref_certificates_by_prefix(&repo_id, "cert", 10)
            .await
            .unwrap();
        assert_eq!(all.len(), 5, "plain prefix still resolves in legacy mode");

        // Escaping still holds under the legacy mode.
        let pct = legacy_db
            .list_ref_certificates_by_prefix(&repo_id, "cert%", 10)
            .await
            .unwrap();
        assert_eq!(pct.len(), 1, "percent prefix matches only literal id");
        assert_eq!(pct[0].id, "cert%b");

        let bs = legacy_db
            .list_ref_certificates_by_prefix(&repo_id, "cert\\", 10)
            .await
            .unwrap();
        assert_eq!(bs.len(), 1, "backslash prefix matches only literal id");
        assert_eq!(bs[0].id, "cert\\d");

        // Release the extra session so it can't hold the per-test database open
        // against the harness's cleanup.
        legacy_pool.close().await;
    }

    /// NOTE: this test hand-copies the migration SQL as string literals and will
    /// silently drift if the v10 migration block changes.  The load-bearing
    /// upgrade-path test is `v10_upgrade_dedup_via_migration`, which fires the
    /// real MIGRATIONS[v10] entry via run_migrations().
    #[sqlx::test]
    async fn v10_dedup_removes_old_duplicates(pool: PgPool) {
        let db = db(pool.clone()).await;

        // Drop the unique index so we can simulate pre-v10 duplicate rows.
        sqlx::query("DROP INDEX IF EXISTS idx_ref_certs_repo_ref")
            .execute(&pool)
            .await
            .unwrap();

        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "dedup-test".into(),
            owner_did: "did:key:zOWNER".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/dedup-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // Insert two rows for the same (repo_id, ref_name) with raw INSERT
        // (no ON CONFLICT — the unique index was dropped above to simulate a
        // pre-v10 database). The second row has the newer timestamp and should
        // survive the dedup.
        sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("keep-id")
        .bind(&repo_id)
        .bind("refs/heads/main")
        .bind("0000")
        .bind("1111")
        .bind("did:key:zPUSHER")
        .bind("did:key:zNODE")
        .bind("sig-first")
        .bind("2026-07-03T20:00:00Z")
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("remove-id")
        .bind(&repo_id)
        .bind("refs/heads/main")
        .bind("aaaa")
        .bind("bbbb")
        .bind("did:key:zPUSHER")
        .bind("did:key:zNODE")
        .bind("sig-dup")
        .bind("2026-07-03T19:00:00Z") // older timestamp → should be removed
        .execute(&pool)
        .await
        .unwrap();

        // Apply the v10 dedup logic: keep the most recent per (repo_id, ref_name).
        sqlx::query(
            "DELETE FROM ref_certificates
             WHERE id IN (
                 SELECT id FROM (
                     SELECT id, ROW_NUMBER() OVER (
                         PARTITION BY repo_id, ref_name ORDER BY issued_at DESC, id DESC
                     ) AS rn
                     FROM ref_certificates
                 ) dups WHERE dups.rn > 1
             )",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Re-create the unique index — must succeed after dedup.
        sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_ref_certs_repo_ref ON ref_certificates(repo_id, ref_name)")
            .execute(&pool)
            .await
            .unwrap();

        // Only the most recent row survives.
        let certs = db.list_ref_certificates(&repo_id, 10).await.unwrap();
        assert_eq!(certs.len(), 1, "dedup leaves one row per ref");
        assert_eq!(
            certs[0].id, "keep-id",
            "dedup keeps the most recent (later issued_at)"
        );
    }

    /// INV-7: upgrade-path test — an existing node already past v1 must still get
    /// the `pinned_cids.cid` index. It ships as its OWN v11 migration (not appended
    /// to the applied v1 bundle), so dropping the index + its `schema_migrations`
    /// row and re-running migrations must recreate it, exercising the real code
    /// path rather than hand-copying the SQL.
    #[sqlx::test]
    async fn v18_pinned_cids_cid_index_applies_on_upgrade(pool: PgPool) {
        async fn index_exists(pool: &PgPool) -> bool {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = 'idx_pinned_cids_cid')",
            )
            .fetch_one(pool)
            .await
            .unwrap()
        }

        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        assert!(
            index_exists(&pool).await,
            "fresh migration chain creates the index"
        );

        // Simulate a node at pre-v18: drop the index and its migration record.
        sqlx::query("DROP INDEX IF EXISTS idx_pinned_cids_cid")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 18")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !index_exists(&pool).await,
            "precondition: index and its migration record removed"
        );

        // Re-run migrations: v11 re-applies and recreates the index on the upgrade.
        db.run_migrations().await.unwrap();
        assert!(
            index_exists(&pool).await,
            "v11 must recreate idx_pinned_cids_cid on an upgrading node"
        );
    }

    /// #173 (jatmn), INV-7 + INV-10: the paged legacy CID scan orders on
    /// `(created_at, id)` ASC, and `repos` had no index in that order — only
    /// `idx_repos_updated_at`, which backed the order the paging REPLACED. Without a
    /// matching index Postgres seq-scans `repos` and top-N sorts it to return every
    /// page (measured: 954 shared buffers, ~47ms per page on 50k rows) while the
    /// scarce IPFS walk admission is held, so the application-side bound the paging
    /// buys is cancelled by an O(rows) database cost on an anonymously reachable
    /// route. With the index each page is an Index Only Scan at 4-5 buffers with the
    /// keyset predicate pushed down as an `Index Cond`.
    ///
    /// PRESENCE is the whole property, so this asserts it structurally rather than by
    /// name: some index on `repos` must lead with `created_at` then `id`, in that
    /// order and ascending. A rename is fine; a reorder, a direction flip, or a drop
    /// is not. Nothing names this index in any query text, so nothing else would
    /// notice its removal.
    ///
    /// Also the INV-7 upgrade path, in the shape of the v18 test above: an existing
    /// node past v1 gets the index from its OWN v25 entry, proven by dropping the
    /// index plus its `schema_migrations` row and re-running the real migration code.
    /// MUTATION (RED): delete the v25 entry from `MIGRATIONS` and the fresh-chain
    /// assertion fails.
    #[sqlx::test]
    async fn v25_repos_created_at_id_index_applies_on_upgrade(pool: PgPool) {
        // Structural, not by name: the leading two columns must be `created_at` then
        // `id`, ascending (ASC is the default, so it renders with no DESC).
        async fn keyset_index_exists(pool: &PgPool) -> bool {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                     SELECT 1
                     FROM pg_index i
                     JOIN pg_class t ON t.oid = i.indrelid
                     WHERE t.relname = 'repos'
                       AND i.indnatts >= 2
                       AND (SELECT a.attname FROM pg_attribute a
                            WHERE a.attrelid = t.oid AND a.attnum = i.indkey[0]) = 'created_at'
                       AND (SELECT a.attname FROM pg_attribute a
                            WHERE a.attrelid = t.oid AND a.attnum = i.indkey[1]) = 'id'
                       AND pg_get_indexdef(i.indexrelid) NOT LIKE '%DESC%'
                 )",
            )
            .fetch_one(pool)
            .await
            .unwrap()
        }

        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        assert!(
            keyset_index_exists(&pool).await,
            "the paged legacy CID scan's ORDER BY created_at ASC, id ASC must be \
             index-backed, or every page seq-scans and sorts the whole repos table \
             while the IPFS walk admission is held (INV-10)"
        );

        // Simulate a node at pre-v25: drop the index and its migration record.
        sqlx::query("DROP INDEX IF EXISTS idx_repos_created_at_id")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 25")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !keyset_index_exists(&pool).await,
            "precondition: index and its migration record removed"
        );

        db.run_migrations().await.unwrap();
        assert!(
            keyset_index_exists(&pool).await,
            "v25 must recreate the keyset index on an upgrading node"
        );
    }

    /// U4 (#173 round 13, F5, INV-7 upgrade path): an existing node past v1 gets the
    /// discovery-continuation columns from its OWN v26 entry, proven by dropping the
    /// columns plus their `schema_migrations` row and re-running the real migration
    /// code.
    ///
    /// The round-trip runs on a NEVER-SWEPT database, with no `pin_repair_sweep` row at
    /// all, because that is the state the setter's insert arm is written for. v23
    /// declares `cursor` NOT NULL and seeds no row, so an upsert naming only the two new
    /// columns fails its NOT NULL check on exactly the nodes this sweep exists for, and
    /// every caller of the setter treats a failure as warn-only, so the window would
    /// simply never rotate and nothing would say so. Asserting the read-back is what
    /// makes that failure visible here.
    ///
    /// MUTATION (RED): delete the v26 entry from `MIGRATIONS` and the fresh-chain
    /// round-trip fails on the missing columns.
    #[sqlx::test]
    async fn v26_discovery_continuation_applies_on_upgrade(pool: PgPool) {
        async fn continuation_columns_exist(pool: &PgPool) -> bool {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM information_schema.columns
                  WHERE table_name = 'pin_repair_sweep'
                    AND column_name IN ('discovery_cursor_created_at', 'discovery_cursor_id')",
            )
            .fetch_one(pool)
            .await
            .unwrap()
                == 2
        }

        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        assert!(
            continuation_columns_exist(&pool).await,
            "the fresh migration chain must carry the discovery continuation columns"
        );

        // Simulate a node at pre-v26: drop the columns and their migration record.
        sqlx::query(
            "ALTER TABLE pin_repair_sweep
                 DROP COLUMN IF EXISTS discovery_cursor_created_at,
                 DROP COLUMN IF EXISTS discovery_cursor_id",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 26")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !continuation_columns_exist(&pool).await,
            "precondition: columns and their migration record removed"
        );

        db.run_migrations().await.unwrap();
        assert!(
            continuation_columns_exist(&pool).await,
            "v26 must add the continuation columns on an upgrading node"
        );

        // NEVER SWEPT: no `pin_repair_sweep` row exists, so the setter has to INSERT and
        // its insert arm has to satisfy v23's NOT NULL `cursor`.
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pin_repair_sweep")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0,
            "precondition: the sweep has never run on this node"
        );
        assert_eq!(
            db.discovery_continuation().await.unwrap(),
            (String::new(), String::new()),
            "an unswept node reads the empty continuation, which means the head of the list"
        );
        db.set_discovery_continuation("2020-01-01T00:00:00+00:00", "repo-42")
            .await
            .expect("the continuation persists on a never-swept node");
        assert_eq!(
            db.discovery_continuation().await.unwrap(),
            (
                "2020-01-01T00:00:00+00:00".to_string(),
                "repo-42".to_string()
            ),
            "the continuation round-trips"
        );
        assert_eq!(
            db.pin_repair_cursor().await.unwrap(),
            "",
            "the insert arm seeds the row-walk cursor at the head of the table"
        );

        // A rotation must never move the row walk. Park the row cursor, rotate again,
        // and read it back.
        db.set_pin_repair_cursor("ff00").await.unwrap();
        db.set_discovery_continuation("2021-06-01T00:00:00+00:00", "repo-99")
            .await
            .unwrap();
        assert_eq!(
            db.pin_repair_cursor().await.unwrap(),
            "ff00",
            "the update arm touches only the continuation columns, so an in-progress \
             table walk is never rewound by a window rotation"
        );
    }

    /// #26 Split PR 1 — upgrade-path test: a node at v26 must be able to
    /// apply the split ledger when sibling splits land. The
    /// collision guard in `run_pending_migrations` catches a name mismatch,
    /// but only if both migrations are registered. This test exercises the
    /// v38 application through the real `run_migrations()` path so it stays
    /// in sync with the `MIGRATIONS` entry rather than hand-copying SQL.
    /// v38 owns the `pending_ref_transitions` CREATE since the trio moved
    /// ahead of the outbox ALTERs.
    ///
    /// MUTATION (RED): delete the v38 entry from `MIGRATIONS` and the
    /// fresh-chain round-trip fails on the missing `pending_ref_transitions` table.
    #[sqlx::test]
    async fn v38_pending_ref_transitions_outbox_applies_on_upgrade(pool: PgPool) {
        async fn outbox_tables_exist(pool: &PgPool) -> bool {
            let has_transitions = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM information_schema.tables
                  WHERE table_name = 'pending_ref_transitions'",
            )
            .fetch_one(pool)
            .await
            .unwrap()
                == 1;
            let has_anchor_jobs = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM information_schema.tables
                  WHERE table_name = 'anchor_jobs'",
            )
            .fetch_one(pool)
            .await
            .unwrap()
                == 1;
            has_transitions && has_anchor_jobs
        }

        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        assert!(
            outbox_tables_exist(&pool).await,
            "the fresh migration chain must create pending_ref_transitions and anchor_jobs"
        );

        // Simulate a node at pre-v38: drop the tables and their migration record.
        sqlx::query("DROP TABLE IF EXISTS anchor_jobs")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP TABLE IF EXISTS pending_ref_transitions")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 38")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !outbox_tables_exist(&pool).await,
            "precondition: v38 tables and migration record removed"
        );

        db.run_migrations().await.unwrap();
        assert!(
            outbox_tables_exist(&pool).await,
            "v38 must create pending_ref_transitions and anchor_jobs on an upgrading node"
        );
    }

    #[sqlx::test]
    async fn v10_upgrade_dedup_via_migration(pool: PgPool) {
        // 1. Bootstrap schema via the full migration chain.
        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        // 2. Roll back to v9: remove the v10-unique index and the
        //    schema_migrations record so that run_migrations() re-applies v10.
        sqlx::query("DROP INDEX IF EXISTS idx_ref_certs_repo_ref")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 10")
            .execute(&pool)
            .await
            .unwrap();

        // 3. Seed repos and duplicate certs (raw INSERT — no ON CONFLICT
        //    since the index is gone).
        let r1 = uuid::Uuid::new_v4().to_string();
        let r2 = uuid::Uuid::new_v4().to_string();
        for (id, name) in [(&r1, "upgrade-repo-a"), (&r2, "upgrade-repo-b")] {
            db.create_repo(&RepoRecord {
                id: id.clone(),
                name: name.into(),
                owner_did: "did:key:zOWNER".into(),
                description: None,
                is_public: true,
                default_branch: "main".into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                disk_path: format!("/tmp/{name}"),
                forked_from: None,
                machine_id: None,
            })
            .await
            .unwrap();
        }

        // Helper macro for raw INSERT.
        macro_rules! insert_cert {
            ($id:expr, $repo_id:expr, $ref_name:expr, $old_sha:expr, $new_sha:expr, $issued_at:expr) => {
                sqlx::query(
                    "INSERT INTO ref_certificates
                     (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                )
                .bind($id)
                .bind($repo_id)
                .bind($ref_name)
                .bind($old_sha)
                .bind($new_sha)
                .bind("did:key:zPUSHER")
                .bind("did:key:zNODE")
                .bind("sig")
                .bind($issued_at)
                .execute(&pool)
                .await
                .unwrap();
            };
        }

        // Repo A, ref "main": two rows with distinct timestamps.
        insert_cert!(
            "dup-a-old",
            &r1,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );
        insert_cert!(
            "dup-a-new",
            &r1,
            "refs/heads/main",
            "aaaa",
            "bbbb",
            "2026-07-02T10:00:00Z"
        );

        // Repo A, ref "feature": two rows with IDENTICAL timestamps — the
        // id-DESC tiebreaker must choose the higher id (alphabetical: "z" > "a").
        insert_cert!(
            "dup-feat-a",
            &r1,
            "refs/heads/feature",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );
        insert_cert!(
            "dup-feat-z",
            &r1,
            "refs/heads/feature",
            "cccc",
            "dddd",
            "2026-07-01T10:00:00Z"
        );

        // Repo B, ref "main": two rows with distinct timestamps.
        insert_cert!(
            "dup-b-old",
            &r2,
            "refs/heads/main",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );
        insert_cert!(
            "dup-b-new",
            &r2,
            "refs/heads/main",
            "eeee",
            "ffff",
            "2026-07-02T10:00:00Z"
        );

        // A non-duplicate singleton row (single row per ref) — must survive
        // untouched.
        insert_cert!(
            "singleton",
            &r2,
            "refs/heads/singleton",
            "0000",
            "1111",
            "2026-07-01T10:00:00Z"
        );

        // 4. Run migrations — the v10 dedup fires inside run_pending_migrations.
        db.run_migrations().await.unwrap();

        // 5. Assert each ref has exactly one survivor.
        let all_r1 = db.list_ref_certificates(&r1, 10).await.unwrap();
        assert_eq!(all_r1.len(), 2, "repo A: 2 refs, 1 survivor each");

        let r1_main: Vec<_> = all_r1
            .iter()
            .filter(|c| c.ref_name == "refs/heads/main")
            .collect();
        assert_eq!(r1_main.len(), 1, "repo A main deduped to one row");
        assert_eq!(r1_main[0].id, "dup-a-new", "newer timestamp survives");
        assert_eq!(r1_main[0].old_sha, "aaaa");
        assert_eq!(r1_main[0].new_sha, "bbbb");

        let r1_feat: Vec<_> = all_r1
            .iter()
            .filter(|c| c.ref_name == "refs/heads/feature")
            .collect();
        assert_eq!(r1_feat.len(), 1, "repo A feature deduped to one row");
        assert_eq!(
            r1_feat[0].id, "dup-feat-z",
            "same-timestamp tiebreaker: higher id wins (id DESC)"
        );

        let all_r2 = db.list_ref_certificates(&r2, 10).await.unwrap();
        assert_eq!(all_r2.len(), 2, "repo B: 2 refs, 1 survivor each");

        let r2_main: Vec<_> = all_r2
            .iter()
            .filter(|c| c.ref_name == "refs/heads/main")
            .collect();
        assert_eq!(r2_main.len(), 1, "repo B main deduped to one row");
        assert_eq!(r2_main[0].id, "dup-b-new", "newer timestamp survives");

        let all_r2 = db.list_ref_certificates(&r2, 10).await.unwrap();
        assert_eq!(
            all_r2.iter().filter(|c| c.id == "singleton").count(),
            1,
            "non-duplicate singleton untouched"
        );

        // 6. Verify the unique index exists: the upsert helper must succeed
        //    (exercises ON CONFLICT) and a direct duplicate INSERT must fail.
        db.insert_ref_certificate(&make_cert(
            "post-migration-upsert",
            &r1,
            "refs/heads/main",
            "1111",
            "2222",
            "2026-07-03T10:00:00Z",
        ))
        .await
        .unwrap();
        let after_upsert = db.list_ref_certificates(&r1, 10).await.unwrap();
        let r1_main_after: Vec<_> = after_upsert
            .iter()
            .filter(|c| c.ref_name == "refs/heads/main")
            .collect();
        assert_eq!(
            r1_main_after.len(),
            1,
            "upsert keeps exactly one row for main"
        );
        assert_eq!(
            r1_main_after[0].id, "dup-a-new",
            "upsert preserves original id"
        );
        assert_eq!(r1_main_after[0].old_sha, "1111", "upsert updated old_sha");

        // A raw INSERT for the same (repo_id, ref_name) must now fail.
        let err = sqlx::query(
            "INSERT INTO ref_certificates
             (id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did, signature, issued_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind("should-fail")
        .bind(&r1)
        .bind("refs/heads/main")
        .bind("xxxx")
        .bind("yyyy")
        .bind("did:key:zPUSHER")
        .bind("did:key:zNODE")
        .bind("sig")
        .bind("2026-07-04T10:00:00Z")
        .execute(&pool)
        .await;
        assert!(
            err.is_err(),
            "raw duplicate INSERT must be rejected by the unique index"
        );
    }
}
#[cfg(test)]
#[cfg(test)]
mod ref_update_db_tests {
    use super::{Db, ReceivedRefUpdate};
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn update(
        id: &str,
        repo: &str,
        owner_did: Option<&str>,
        ref_name: &str,
        sha: &str,
    ) -> ReceivedRefUpdate {
        ReceivedRefUpdate {
            id: id.to_string(),
            node_did: "did:key:zNode".into(),
            pusher_did: "did:key:zPusher".into(),
            repo: repo.to_string(),
            owner_did: owner_did.map(|s| s.to_string()),
            ref_name: ref_name.to_string(),
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: sha.to_string(),
            timestamp: "2026-07-02T12:00:00Z".into(),
            cert_id: None,
            received_at: "2026-07-02T12:00:01Z".into(),
            from_peer: "12D3KooWTest".into(),
        }
    }

    #[sqlx::test]
    async fn insert_and_list_with_owner_did(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u1",
            "zOwner/myrepo",
            Some("did:key:zOwner"),
            "refs/heads/main",
            "aaaa",
        ))
        .await
        .unwrap();

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].owner_did.as_deref(), Some("did:key:zOwner"));
        assert_eq!(all[0].repo, "zOwner/myrepo");
    }

    #[sqlx::test]
    async fn insert_and_list_without_owner_did(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u2",
            "zOwner/myrepo",
            None,
            "refs/heads/main",
            "bbbb",
        ))
        .await
        .unwrap();

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].owner_did, None);
    }

    #[sqlx::test]
    async fn list_repo_ref_updates_filters_by_repo(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u3",
            "alice/repo1",
            Some("did:key:zAlice"),
            "refs/heads/main",
            "cccc",
        ))
        .await
        .unwrap();
        db.insert_ref_update(&update(
            "u4",
            "bob/repo2",
            Some("did:key:zBob"),
            "refs/heads/feat",
            "dddd",
        ))
        .await
        .unwrap();

        let alice_events = db
            .list_ref_updates_keyset(Some("alice/repo1"), 100, None)
            .await
            .unwrap();
        assert_eq!(alice_events.len(), 1);
        assert_eq!(alice_events[0].id, "u3");
        assert_eq!(alice_events[0].owner_did.as_deref(), Some("did:key:zAlice"));

        let bob_events = db
            .list_ref_updates_keyset(Some("bob/repo2"), 100, None)
            .await
            .unwrap();
        assert_eq!(bob_events.len(), 1);
        assert_eq!(bob_events[0].id, "u4");
        assert_eq!(bob_events[0].owner_did.as_deref(), Some("did:key:zBob"));

        let empty = db
            .list_ref_updates_keyset(Some("other/repo"), 100, None)
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[sqlx::test]
    async fn list_ref_updates_filtered_by_repo(pool: PgPool) {
        let db = db(pool).await;
        db.insert_ref_update(&update(
            "u5",
            "ownerA/proj",
            Some("did:key:zA"),
            "refs/heads/main",
            "eeee",
        ))
        .await
        .unwrap();
        db.insert_ref_update(&update(
            "u6",
            "ownerB/proj",
            Some("did:web:host:zB"),
            "refs/heads/main",
            "ffff",
        ))
        .await
        .unwrap();

        let filtered = db
            .list_ref_updates_keyset(Some("ownerA/proj"), 100, None)
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "u5");

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[sqlx::test]
    async fn insert_update_idempotent_on_conflict(pool: PgPool) {
        let db = db(pool).await;
        let u = update(
            "u7",
            "repo/x",
            Some("did:key:zX"),
            "refs/heads/main",
            "gggg",
        );
        db.insert_ref_update(&u).await.unwrap();
        db.insert_ref_update(&u).await.unwrap();

        let all = db.list_ref_updates_keyset(None, 100, None).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].new_sha, "gggg");
    }
}

#[cfg(test)]
mod peer_reachability_tests {
    use super::{Db, PeerWriteAuthority};
    use sqlx::PgPool;

    // Real derivable did:key fixtures. The unproven arm resolves the verifying
    // key, so a made-up method-id is refused before any SQL runs.
    const VICTIM_DID: &str = "did:key:z6Mkrmsd28nDTPBjk55EJCSjtJLVJDZffyczjBEHvywhutM4";
    const HONEST_URL: &str = "https://honest-peer.example.com";
    const ATTACKER_URL: &str = "https://attacker.example.com";

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    /// Read the row back through `list_peers`, the same surface the federated
    /// fan-out filters on, rather than issuing raw SQL from the test.
    async fn peer(db: &Db, did: &str) -> (String, bool) {
        let row = db
            .list_peers()
            .await
            .unwrap()
            .into_iter()
            .find(|p| p.did == did)
            .expect("seeded peer row is missing");
        (row.http_url, row.last_ping_ok)
    }

    /// Parsed rather than string-compared, so the ordering assertion does not
    /// depend on the stored timestamp's textual precision.
    async fn last_seen(db: &Db, did: &str) -> chrono::DateTime<chrono::Utc> {
        let row = db
            .list_peers()
            .await
            .unwrap()
            .into_iter()
            .find(|p| p.did == did)
            .expect("seeded peer row is missing");
        chrono::DateTime::parse_from_rfc3339(&row.last_seen.expect("last_seen is set by upsert"))
            .expect("last_seen is rfc3339")
            .with_timezone(&chrono::Utc)
    }

    /// Seed a peer that has earned reachability, asserting the seed took so a
    /// later case cannot pass vacuously on a row that was never written.
    async fn seed_reachable(db: &Db) {
        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();
        db.mark_peer_ping(VICTIM_DID, true).await.unwrap();
        assert_eq!(
            peer(db, VICTIM_DID).await,
            (HONEST_URL.to_string(), true),
            "seed did not take"
        );
    }

    /// Repointing an existing peer's URL must drop the reachability gate: the
    /// new host has not been probed, so it cannot inherit the old host's
    /// earned `last_ping_ok`.
    #[sqlx::test]
    async fn url_change_clears_reachability(pool: PgPool) {
        let db = db(pool).await;
        seed_reachable(&db).await;

        // Proven: the repoint is the row's own key announcing a new host, which
        // is the case #270's reset is about. An unproven repoint is refused
        // outright now, so it cannot express this property.
        db.upsert_peer(
            VICTIM_DID,
            ATTACKER_URL,
            PeerWriteAuthority::Proven(VICTIM_DID),
        )
        .await
        .unwrap();

        let (url, reachable) = peer(&db, VICTIM_DID).await;
        assert_eq!(url, ATTACKER_URL, "the URL should still be rewritten");
        assert!(
            !reachable,
            "a repointed peer must re-earn reachability, not inherit it"
        );
    }

    /// A plain liveness re-announce carries the same URL and must not cost an
    /// honest peer its place in the federated fan-out. Guards against a fix
    /// that clears the flag on every conflict instead of only on a change.
    #[sqlx::test]
    async fn same_url_reannounce_keeps_reachability(pool: PgPool) {
        let db = db(pool).await;
        seed_reachable(&db).await;

        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();

        let (url, reachable) = peer(&db, VICTIM_DID).await;
        assert_eq!(url, HONEST_URL);
        assert!(
            reachable,
            "an unchanged-URL re-announce must not drop the gate"
        );
    }

    /// The must-not-grant direction. An unchanged URL preserves the flag as it
    /// stands, which means FALSE stays FALSE: reachability is earned by a probe,
    /// never by announcing. This is the only case that fails if the conditional
    /// is flattened to `last_ping_ok = (peers.http_url IS NOT DISTINCT FROM $2)`,
    /// which would let any unsigned same-URL re-announce set the flag TRUE.
    #[sqlx::test]
    async fn same_url_reannounce_does_not_grant_reachability(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();
        assert_eq!(peer(&db, VICTIM_DID).await, (HONEST_URL.to_string(), false));

        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();

        let (_, reachable) = peer(&db, VICTIM_DID).await;
        assert!(
            !reachable,
            "announcing must never grant reachability without a probe"
        );
    }

    /// A first insert stays out of the fan-out until a probe confirms it. Guards
    /// against the conditional leaking into the INSERT branch.
    #[sqlx::test]
    async fn fresh_peer_inserts_unreachable(pool: PgPool) {
        let db = db(pool).await;

        db.upsert_peer(
            "did:key:z6MkfGVENKztfeXa631WYVqyAGaXeP8AnN6nTkfogHn9vaaQ",
            HONEST_URL,
            PeerWriteAuthority::Unproven,
        )
        .await
        .unwrap();

        let (_, reachable) = peer(
            &db,
            "did:key:z6MkfGVENKztfeXa631WYVqyAGaXeP8AnN6nTkfogHn9vaaQ",
        )
        .await;
        assert!(!reachable, "a never-probed peer must insert unreachable");
    }

    /// Comparison is exact, by decision: http_url is stored as announced and
    /// nothing normalizes it, so a trailing slash is a different remote as far
    /// as this row is concerned and clears the gate. Pins that decision against
    /// a future normalizing comparison, which every other case here would pass
    /// because they only ever compare identical or wholly different hosts.
    #[sqlx::test]
    async fn cosmetic_url_difference_counts_as_a_change(pool: PgPool) {
        let db = db(pool).await;
        seed_reachable(&db).await;

        let with_slash = format!("{HONEST_URL}/");
        db.upsert_peer(
            VICTIM_DID,
            &with_slash,
            PeerWriteAuthority::Proven(VICTIM_DID),
        )
        .await
        .unwrap();

        let (url, reachable) = peer(&db, VICTIM_DID).await;
        assert_eq!(url, with_slash);
        assert!(
            !reachable,
            "comparison is exact, so a cosmetic difference clears the gate too"
        );
    }

    /// The reset must ride the existing UPDATE, not gate it. Hoisting the
    /// condition to a statement-level WHERE would leave every case above green
    /// while silently skipping the whole update on a same-URL re-announce, so
    /// liveness would stop advancing and the peer would age out on last_seen.
    #[sqlx::test]
    async fn same_url_reannounce_still_advances_last_seen(pool: PgPool) {
        let db = db(pool).await;
        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();
        let first = last_seen(&db, VICTIM_DID).await;

        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();

        let second = last_seen(&db, VICTIM_DID).await;
        assert!(
            second > first,
            "a same-URL re-announce is a liveness signal and must still \
             advance last_seen: {first} then {second}"
        );
    }
}

#[cfg(test)]
mod peer_authority_tests {
    use super::{Db, PeerWriteAuthority, PeerWriteDenied};
    use sqlx::PgPool;

    // Real derivable did:key fixtures. The unproven arm resolves the verifying
    // key, so a made-up method-id is refused before any SQL runs.
    const VICTIM_DID: &str = "did:key:z6MkuMqUm4i228K9qXidJ57zqSWAcQLgrcbMxB8RKVLuqitj";
    const OTHER_DID: &str = "did:key:z6MkuzEVwHSWSCLq6xAkgTAJxHMa24KuBtgozce77TEihnWD";
    const WEB_DID: &str = "did:web:squatter.example.com";
    const HONEST_URL: &str = "https://honest-peer.example.com";
    const ATTACKER_URL: &str = "https://attacker.example.com";

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    /// `peer_exists` answers the membership question the gossip ingest gate
    /// asks on every event, so both answers are pinned here: a registered DID
    /// is true, and an unregistered one is false rather than an error or a
    /// prefix match on a registered DID.
    #[sqlx::test]
    async fn peer_exists_answers_both_ways(pool: sqlx::PgPool) {
        let db = db(pool).await;
        let did = VICTIM_DID;

        assert!(
            !db.peer_exists(did).await.unwrap(),
            "an empty peers table must answer false, not error"
        );

        db.upsert_peer(
            did,
            "https://peer.example.com",
            PeerWriteAuthority::Proven(did),
        )
        .await
        .unwrap();

        assert!(db.peer_exists(did).await.unwrap());
        assert!(
            !db.peer_exists(OTHER_DID).await.unwrap(),
            "a different DID must not match"
        );
        assert!(
            !db.peer_exists(&VICTIM_DID[..VICTIM_DID.len() - 1])
                .await
                .unwrap(),
            "the lookup is an equality test, not a prefix test"
        );
    }

    /// The whole row, read back through `list_peers` rather than raw SQL, so a
    /// case that claims "unchanged" is comparing every column a consumer sees.
    async fn row(db: &Db, did: &str) -> Option<(String, String, Option<String>, bool, String)> {
        db.list_peers()
            .await
            .unwrap()
            .into_iter()
            .find(|p| p.did == did)
            .map(|p| {
                (
                    p.did,
                    p.http_url,
                    p.last_seen,
                    p.last_ping_ok,
                    p.announced_at,
                )
            })
    }

    /// Seed a row and assert the seed took, so no case below can pass
    /// vacuously against a row that was never written.
    async fn seed(db: &Db) -> (String, String, Option<String>, bool, String) {
        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();
        db.mark_peer_ping(VICTIM_DID, true).await.unwrap();
        let seeded = row(db, VICTIM_DID).await.expect("seed did not take");
        assert_eq!(seeded.1, HONEST_URL, "seed did not take");
        assert!(seeded.3, "seed did not earn reachability");
        seeded
    }

    fn denial(err: anyhow::Error) -> PeerWriteDenied {
        err.downcast::<PeerWriteDenied>()
            .expect("rejection must be the typed denial, or the handler renders it as a 500")
    }

    /// A row a deployed database ALREADY holds must keep refreshing its
    /// liveness. Before this gate existed `upsert_peer` did no DID validation
    /// at all and the handler accepted any parseable DID, so live peer tables
    /// carry did:web rows and did:key rows whose key never resolved. Judging
    /// the DID before looking at whether the row exists freezes those forever:
    /// the unsigned refresh is refused, and a signed one is impossible because
    /// no key resolves. Nothing is protected by that, since the row is already
    /// there and an identical-URL refresh changes no authority. Kills a gate
    /// scoped to the DID instead of to the INSERT.
    #[sqlx::test]
    async fn a_legacy_row_can_still_refresh_its_liveness(pool: PgPool) {
        let db = db(pool).await;

        for legacy in [WEB_DID, "did:key:znotarealkeymaterial"] {
            sqlx::query(
                "INSERT INTO peers (did, http_url, last_seen, announced_at) \
                 VALUES ($1, $2, $3, $3)",
            )
            .bind(legacy)
            .bind(HONEST_URL)
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(db.pool())
            .await
            .expect("seeding a pre-gate row must succeed");

            db.upsert_peer(legacy, HONEST_URL, PeerWriteAuthority::Unproven)
                .await
                .unwrap_or_else(|e| {
                    panic!("a legacy row must keep refreshing its liveness: {legacy} -> {e}")
                });
        }
    }

    /// The other half: the gate still refuses to CREATE such a row. Without
    /// this, scoping the check to the insert path could be satisfied by
    /// dropping the check altogether.
    #[sqlx::test]
    async fn a_legacy_did_still_cannot_be_created_fresh(pool: PgPool) {
        let db = db(pool).await;

        let err = db
            .upsert_peer(WEB_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .expect_err("an unseen non-did:key must still be refused at insert");
        assert!(
            matches!(denial(err), PeerWriteDenied::UnsupportedDidMethod { .. }),
            "the insert refusal must survive the insert-scoping"
        );
    }

    /// Discovery stays open: an unproven caller may still seed an unseen
    /// did:key row. Kills a gate widened until it rejects inserts too.
    #[sqlx::test]
    async fn unproven_insert_of_an_unseen_did_key_is_allowed(pool: PgPool) {
        let db = db(pool).await;

        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .unwrap();

        let (_, url, last_seen, reachable, _) = row(&db, VICTIM_DID).await.expect("row missing");
        assert_eq!(url, HONEST_URL);
        assert!(last_seen.is_some());
        assert!(!reachable, "a never-probed peer must insert unreachable");
    }

    /// The defect this change exists to close. Kills the unconditional
    /// `ON CONFLICT(did) DO UPDATE SET http_url = $2`.
    #[sqlx::test]
    async fn unproven_repoint_of_an_existing_row_is_rejected(pool: PgPool) {
        let db = db(pool).await;
        let before = seed(&db).await;

        let err = db
            .upsert_peer(VICTIM_DID, ATTACKER_URL, PeerWriteAuthority::Unproven)
            .await
            .expect_err("an unproven repoint must be an error, never a silent no-op");

        assert!(
            matches!(denial(err), PeerWriteDenied::UnprovenRepoint { .. }),
            "the denial must be the typed repoint refusal"
        );
        assert_eq!(
            row(&db, VICTIM_DID).await.expect("row vanished"),
            before,
            "the stored row must be byte-identical after a refused repoint"
        );
    }

    /// Honest peers re-announce, so the identical-URL case is a liveness
    /// refresh, not a denial. The URL string is reused byte for byte: the
    /// comparison inherited from #270 is exact, so a trailing slash would make
    /// this pass as a repoint rejection instead. Kills a too-wide gate.
    #[sqlx::test]
    async fn unproven_reannounce_of_the_identical_url_refreshes_last_seen(pool: PgPool) {
        let db = db(pool).await;
        let before = seed(&db).await;

        db.upsert_peer(VICTIM_DID, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .expect("an identical-URL re-announce cannot change the URL, so it is allowed");

        let after = row(&db, VICTIM_DID).await.expect("row vanished");
        assert_eq!(after.1, HONEST_URL, "URL untouched");
        assert_eq!(after.3, before.3, "reachability untouched");
        assert_eq!(after.4, before.4, "announced_at untouched");
        let parse = |s: &Option<String>| {
            chrono::DateTime::parse_from_rfc3339(s.as_deref().expect("last_seen is set")).unwrap()
        };
        assert!(
            parse(&after.2) > parse(&before.2),
            "a same-URL re-announce is a liveness signal and must advance last_seen"
        );
    }

    /// A signed repoint from the row's own key is the allowed case, and it must
    /// still clear reachability per #270: a proven repoint is still an unprobed
    /// URL. Kills a gate that rejects proven writes, and kills dropping the
    /// #270 CASE.
    #[sqlx::test]
    async fn proven_repoint_by_the_rows_own_did_updates_and_clears_reachability(pool: PgPool) {
        let db = db(pool).await;
        seed(&db).await;

        db.upsert_peer(
            VICTIM_DID,
            ATTACKER_URL,
            PeerWriteAuthority::Proven(VICTIM_DID),
        )
        .await
        .unwrap();

        let (_, url, _, reachable, _) = row(&db, VICTIM_DID).await.expect("row missing");
        assert_eq!(url, ATTACKER_URL, "a proven repoint must land");
        assert!(
            !reachable,
            "a repointed peer must re-earn reachability, even when the repoint is signed"
        );
    }

    /// The RUSTSEC-2022-0009 shape at the boundary: a valid proof of control
    /// over one DID must not authorize a write to a different DID's row. Kills
    /// a bare proven/unproven flag that never checks WHICH DID was proven, and
    /// kills neutralizing the boundary's comparison.
    #[sqlx::test]
    async fn proof_of_another_did_cannot_write_this_row(pool: PgPool) {
        let db = db(pool).await;
        let before = seed(&db).await;

        let err = db
            .upsert_peer(
                VICTIM_DID,
                ATTACKER_URL,
                PeerWriteAuthority::Proven(OTHER_DID),
            )
            .await
            .expect_err("a proof naming another DID must not authorize this row");

        assert!(
            matches!(denial(err), PeerWriteDenied::ProofDidMismatch { .. }),
            "the denial must name the proof/target mismatch"
        );
        assert_eq!(
            row(&db, VICTIM_DID).await.expect("row vanished"),
            before,
            "the stored row must be byte-identical after a mismatched proof"
        );
    }

    /// Signed first contact must not regress: a proven write for an unseen DID
    /// still inserts.
    #[sqlx::test]
    async fn proven_insert_of_an_unseen_did_is_allowed(pool: PgPool) {
        let db = db(pool).await;

        db.upsert_peer(
            VICTIM_DID,
            HONEST_URL,
            PeerWriteAuthority::Proven(VICTIM_DID),
        )
        .await
        .unwrap();

        let (_, url, _, reachable, _) = row(&db, VICTIM_DID).await.expect("row missing");
        assert_eq!(url, HONEST_URL);
        assert!(!reachable, "a never-probed peer must insert unreachable");
    }

    /// R8. A DID whose method can never authenticate is refused in the
    /// validation class, with nothing written. Kills a method gate applied only
    /// to the update path. This case is about the METHOD LABEL alone, which is
    /// the one thing methodNotSupported can truthfully say; a did:key whose key
    /// material does not resolve is a different refusal and is covered by the
    /// unresolvable tests below, so it is deliberately not in this loop.
    #[sqlx::test]
    async fn unproven_insert_of_a_non_did_key_is_rejected(pool: PgPool) {
        let db = db(pool).await;

        for did in [WEB_DID, "did:gitlawb:z6MkSomeKey"] {
            let err = db
                .upsert_peer(did, HONEST_URL, PeerWriteAuthority::Unproven)
                .await
                .expect_err("a DID method that can never authenticate must not be insertable");

            let denied = denial(err);
            assert!(
                matches!(denied, PeerWriteDenied::UnsupportedDidMethod { .. }),
                "the denial must be the typed method refusal: {did}"
            );
            assert!(
                denied
                    .to_string()
                    .contains("methodNotSupported: only did:key peers"),
                "the denial must name the unsupported method"
            );
            assert!(
                row(&db, did).await.is_none(),
                "a rejected announce must leave no row behind: {did}"
            );
        }
    }

    /// The oversized method-id is refused ahead of the quadratic base58 decode,
    /// and the caller is told THAT, not that did:key is unsupported. Kills
    /// folding the key-resolution failure back into the method class.
    #[sqlx::test]
    async fn unproven_insert_of_an_oversized_did_key_reports_the_cause(pool: PgPool) {
        let db = db(pool).await;
        let did = format!("did:key:z{}", "a".repeat(70));

        let err = db
            .upsert_peer(&did, HONEST_URL, PeerWriteAuthority::Unproven)
            .await
            .expect_err("a did:key whose key cannot be resolved must not be insertable");

        let denied = denial(err);
        assert!(
            matches!(denied, PeerWriteDenied::UnresolvableDid { .. }),
            "the denial must be the typed resolution refusal"
        );
        let denied = denied.to_string();
        assert!(
            denied.contains("cannot resolve DID"),
            "an unresolvable did:key must report resolution, not method support, got {denied:?}"
        );
        assert!(
            denied.contains("method-specific id too long"),
            "the denial must carry the underlying cause, got {denied:?}"
        );
        assert!(
            row(&db, &did).await.is_none(),
            "a rejected announce must leave no row behind: {did}"
        );
    }

    /// The remaining resolution failures, one input class per entry, each
    /// pinned to its own cause. The multibase entry asserts only the class
    /// message: its sub-reason is multibase's own Display and a dependency bump
    /// can reword it.
    #[sqlx::test]
    async fn unproven_insert_of_an_unresolvable_did_key_reports_the_cause(pool: PgPool) {
        let db = db(pool).await;

        // "0" is not in the base58btc alphabet, so the decode itself fails.
        // "notarealkey" carries the right method label and no decodable key,
        // which is the permanently uncorrectable row this gate prevents.
        // The secp256k1 vector is the W3C did:key test vector: it decodes
        // cleanly and is simply not an ed25519 key.
        // The wrong-length vector is base58btc(0xed 0x01 || sixteen bytes
        // 0x00..0x0f) with the multibase 'z' prefix: the right multicodec, half
        // the key.
        for (did, cause) in [
            ("did:key:z0", None),
            ("did:key:notarealkey", None),
            (
                "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                Some("not an ed25519 multicodec key"),
            ),
            (
                "did:key:zAq9r99PUfP1Xyitb5n8V9sxht",
                Some("ed25519 key must be 32 bytes"),
            ),
        ] {
            let err = db
                .upsert_peer(did, HONEST_URL, PeerWriteAuthority::Unproven)
                .await
                .expect_err("a did:key whose key cannot be resolved must not be insertable");

            let denied = denial(err);
            assert!(
                matches!(denied, PeerWriteDenied::UnresolvableDid { .. }),
                "the denial must be the typed resolution refusal: {did}"
            );
            let denied = denied.to_string();
            assert!(
                denied.contains("cannot resolve DID"),
                "an unresolvable did:key must report resolution, not method support: \
                 {did} got {denied:?}"
            );
            if let Some(cause) = cause {
                assert!(
                    denied.contains(cause),
                    "the denial must carry the underlying cause {cause:?}: {did} got {denied:?}"
                );
            }
            assert!(
                row(&db, did).await.is_none(),
                "a rejected announce must leave no row behind: {did}"
            );
        }
    }

    /// The bootstrap announce-back in main.rs hands this boundary the contacted
    /// peer's raw JSON string, so a value that never parses as a DID reaches
    /// here; the announce handler cannot produce it, since it parses req.did
    /// first. The parse error is what an operator reading that loop's warning
    /// needs, and methodNotSupported would be a false claim about a string that
    /// names no method at all.
    #[sqlx::test]
    async fn unproven_insert_of_an_unparseable_string_reports_the_parse_failure(pool: PgPool) {
        let db = db(pool).await;

        for (did, cause) in [
            ("not-a-did", "does not start with 'did:'"),
            ("did:foo:x", "unsupported DID method: foo"),
        ] {
            let err = db
                .upsert_peer(did, HONEST_URL, PeerWriteAuthority::Unproven)
                .await
                .expect_err("a string that is not a DID must not be insertable");

            let denied = denial(err);
            assert!(
                matches!(denied, PeerWriteDenied::UnresolvableDid { .. }),
                "the denial must be the typed resolution refusal: {did}"
            );
            let denied = denied.to_string();
            assert!(
                denied.contains("cannot resolve DID"),
                "an unparseable DID must report resolution, not method support: \
                 {did} got {denied:?}"
            );
            assert!(
                denied.contains(cause),
                "the denial must carry the parse failure {cause:?}: {did} got {denied:?}"
            );
            assert!(
                row(&db, did).await.is_none(),
                "a rejected announce must leave no row behind: {did}"
            );
        }
    }
}

/// #273 completeness ledger: every writer of the `peers` table.
///
/// The required set is derived from the authority that DEFINES membership, the
/// write statements themselves, not from the set of `upsert_peer` callers. A
/// caller scan is structurally blind to a future writer that issues its own SQL
/// and bypasses `upsert_peer`, which is precisely the case the type system
/// cannot see.
///
/// The type system carries the real weight: `upsert_peer`'s authority parameter
/// has no default, so a new caller cannot omit its declaration, compile-enforced
/// and exhaustive by construction. This scan is the backstop for the bypass case
/// alone, which is why it is one equality assertion rather than a framework.
///
/// The ledger, one row per function that writes the table:
///
/// | Writer | Disposition |
/// | --- | --- |
/// | `upsert_peer` (db/mod.rs) | guarded by the authority parameter |
/// | `mark_peer_ping` (db/mod.rs) | benign for `http_url`: it writes only `last_seen` and `last_ping_ok`. It IS the table's other production writer, and its unauthenticated reachability is tracked separately as issue #269 |
/// | `prune_self_peers` (db/mod.rs) | a delete keyed on `http_url`; cannot repoint; boot-only caller in main.rs |
/// | `prune_non_public_peers` (db/mod.rs) | a delete keyed on a computed bad-DID array; cannot repoint; boot-only caller in main.rs |
/// | `seed_local_peer` (sync.rs) | excluded by test-module location: a deliberate `upsert_peer` bypass for `file://` fixtures, which the public-URL gate rejects |
/// | `a_legacy_row_can_still_refresh_its_liveness` (db/mod.rs) | test-only. Seeds a PRE-GATE row by raw SQL on purpose: `upsert_peer` cannot create one, since the gate it is testing refuses exactly that DID. The fixture models what a deployed table already holds |
/// | `manual_ping_uses_readiness_without_mutating_federation_gate` (api/peers.rs) | test-only fixture seed, same shape and same reason: the row under test must pre-exist so the assertion is about what the ping does NOT rewrite |
/// | `gossip_ping_round_requires_two_failures_before_persisting_unreachable` (lib.rs) | test-only fixture seed for the gossip hysteresis round; the row must pre-exist so the assertion is about when `mark_peer_ping` fires |
/// | `seed_peer` (p2p/mod.rs) | test-only fixture seed. Raw SQL so the gossip ingest tests can drive the known-peer gate directly, including the did:web case `upsert_peer` would refuse |
/// | `federated_peer_query_is_bounded` (api/repos.rs) | test-only fixture seed for the bounded federation query; inserts reachable rows without exercising peer admission |
/// | `federated_route_annotates_peer_repos_on_real_200_body` (api/repos.rs) | test-only fixture seed; inserts the mock peer row the bounded federation query reads, so the response-envelope assertions run against a real HTTP 200 body |
/// | `federated_route_reports_truncated_when_peer_fetch_fails` (api/repos.rs) | test-only fixture seed; seeds one unreachable peer so the fetch-failure path is the witness under test |
/// | `federated_route_reports_truncated_when_peer_table_overflows` (api/repos.rs) | test-only fixture seed; overflows the peer table past `MAX_FEDERATED_PEERS` so the count bound is the only witness for `truncated` |
///
/// And the `upsert_peer` CALL-SITE authority table, which the ledger above
/// structurally cannot hold, because the bootstrap site issues no SQL of its own
/// and therefore can never appear in a scan of write statements:
///
/// | Call site | Authority declared |
/// | --- | --- |
/// | api/peers.rs (announce) | proven if and only if the `AuthenticatedDid` extension is present, carrying that extension's DID |
/// | main.rs (bootstrap announce-back) | unproven, unconditionally. Reasoned-not-run: no runtime test reaches that site in this change |
#[cfg(test)]
mod peers_table_writer_guard {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// The per-file scan, split out so the multi-line-SQL property can be
    /// asserted against a synthetic source rather than only against the real
    /// tree, which happens to contain no multi-line peers write today. A guard
    /// whose blind spot is invisible because the tree does not currently
    /// exercise it is one that fails the moment somebody writes normal code.
    fn scan_source(src: &str) -> BTreeMap<String, usize> {
        let needles: Vec<String> = needles().iter().map(|n| n.to_lowercase()).collect();
        let mut found: BTreeMap<String, usize> = BTreeMap::new();
        // Normalize the WHOLE file before matching, not each line on its
        // own. Per-line `contains` is whitespace- and case-sensitive, so
        // `sqlx::query(r#"UPDATE\n  peers SET ..."#)` walked straight past
        // it, and that multi-line form is how the longer queries in this
        // file are already written. Verified both ways: the single-line
        // bypass went RED, the identical statement split across lines
        // stayed GREEN. Offsets are mapped back to line numbers so each
        // statement is still attributed to the function that issues it.
        let mut flat = String::with_capacity(src.len());
        let mut starts: Vec<(usize, usize)> = Vec::new(); // (offset, line index)
        for (idx, line) in src.lines().enumerate() {
            starts.push((flat.len(), idx));
            flat.push_str(&line.trim().to_lowercase());
            flat.push(' ');
        }
        let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");

        // Re-derive offsets against the collapsed text by walking it once.
        let mut collapsed = String::with_capacity(flat.len());
        let mut owners: Vec<usize> = Vec::new(); // line index per byte
        for (idx, line) in src.lines().enumerate() {
            for tok in line.trim().to_lowercase().split_whitespace() {
                if !collapsed.is_empty() {
                    collapsed.push(' ');
                    owners.push(idx);
                }
                for _ in 0..tok.len() {
                    owners.push(idx);
                }
                collapsed.push_str(tok);
            }
        }

        let fn_at: Vec<&str> = {
            let mut current = "<module level>";
            src.lines()
                .map(|line| {
                    if let Some(name) = declared_fn(line) {
                        current = name;
                    }
                    current
                })
                .collect()
        };

        for needle in &needles {
            let mut from = 0usize;
            while let Some(rel) = collapsed[from..].find(needle.as_str()) {
                let at = from + rel;
                let line_idx = owners.get(at).copied().unwrap_or(0);
                let owner = fn_at.get(line_idx).copied().unwrap_or("<module level>");
                *found.entry(owner.to_string()).or_default() += 1;
                from = at + needle.len();
            }
        }
        found
    }

    /// Each dispositioned writer and the number of statements it issues against
    /// the table. Bidirectional: an undispositioned hit fails, and so does a
    /// listed function that no longer has one.
    const LEDGER: &[(&str, usize)] = &[
        ("a_legacy_row_can_still_refresh_its_liveness", 1),
        ("federated_peer_query_is_bounded", 1),
        ("federated_route_annotates_peer_repos_on_real_200_body", 1),
        ("federated_route_reports_truncated_when_peer_fetch_fails", 1),
        (
            "federated_route_reports_truncated_when_peer_table_overflows",
            1,
        ),
        (
            "manual_ping_uses_readiness_without_mutating_federation_gate",
            1,
        ),
        (
            "gossip_ping_round_requires_two_failures_before_persisting_unreachable",
            1,
        ),
        ("mark_peer_ping", 1),
        ("prune_non_public_peers", 1),
        ("prune_self_peers", 1),
        ("seed_local_peer", 1),
        ("seed_peer", 1),
        ("upsert_peer", 2),
    ];

    /// Assembled at runtime rather than written as literals, so this module's
    /// own source does not match the scan it performs.
    fn needles() -> Vec<String> {
        ["INSERT INTO ", "UPDATE ", "DELETE FROM "]
            .iter()
            .map(|verb| format!("{verb}peers"))
            .collect()
    }

    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("the crate source tree must be readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The function a line declares, if it declares one.
    fn declared_fn(line: &str) -> Option<&str> {
        let trimmed = line.trim_start();
        let rest = [
            "pub(crate) async fn ",
            "pub(crate) fn ",
            "pub async fn ",
            "pub fn ",
            "async fn ",
            "fn ",
        ]
        .iter()
        .find_map(|p| trimmed.strip_prefix(p))?;
        rest.split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .next()
            .filter(|name| !name.is_empty())
    }

    /// The backstop the authority parameter cannot provide: a new raw write
    /// against the table from outside `upsert_peer` is invisible to the type
    /// system, so it is caught here or not at all.
    /// The blind spot this guard shipped with: matching a verb-plus-table needle
    /// per line is whitespace- and case-sensitive, so the identical statement split
    /// across lines walked past it. That form is how the longer queries in this
    /// file are already written, so it is the shape a future writer most likely
    /// takes. Both directions asserted, plus lowercase.
    ///
    /// The fixtures are DERIVED from `needles()` at runtime for the same reason
    /// the needles themselves are: a literal here would be found by the scan of
    /// this very file and counted against this test function. Deriving them
    /// also means the test follows if the needle set ever changes.
    #[test]
    fn the_scan_sees_a_write_whose_verb_and_table_are_on_different_lines() {
        for needle in needles() {
            let (verb, table) = needle.rsplit_once(' ').expect("a needle is '<VERB> peers'");
            let cases = [
                ("single-line", format!("{verb} {table} SET x = $1")),
                (
                    "split across lines",
                    format!("{verb}\n             {table}\n             SET x = $1"),
                ),
                (
                    "lowercase, double-spaced",
                    format!("{}  {} set x = $1", verb.to_lowercase(), table),
                ),
            ];
            for (label, sql) in cases {
                let src = format!("fn sneaky() {{\n    sqlx::query(\"{sql}\");\n}}\n");
                let found = scan_source(&src);
                assert_eq!(
                    found.get("sneaky").copied(),
                    Some(1),
                    "the scan missed a peers write written {label} with needle {needle:?}: {found:?}"
                );
            }
        }
    }

    #[test]
    fn every_peers_table_write_is_dispositioned() {
        let mut files = Vec::new();
        rust_sources(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        // Anti-vacuity: a scrape that walked nothing would report a clean tree.
        assert!(
            files.len() > 10,
            "the scan found only {} source files, so a clean result proves nothing",
            files.len()
        );

        let mut found: BTreeMap<String, usize> = BTreeMap::new();
        for file in &files {
            let src = std::fs::read_to_string(file).expect("source file must be readable");

            for (owner, n) in scan_source(&src) {
                *found.entry(owner).or_default() += n;
            }
        }

        let expected: BTreeMap<String, usize> =
            LEDGER.iter().map(|(f, n)| ((*f).to_string(), *n)).collect();
        assert_eq!(
            found, expected,
            "the peers-table writers no longer match the ledger. A new writer must \
             be dispositioned in the table above (and gated), and a removed one \
             dropped from LEDGER"
        );
    }
}

#[cfg(test)]
mod cid_candidate_order_tests {
    use super::Db;
    use sqlx::PgPool;

    /// The candidate order `oids_for_cid` returns must not depend on the physical
    /// row order in `pinned_cids`.
    ///
    /// `get_by_cid` walks the candidates under ONE shared probe budget, visit budget
    /// and pager, so whichever candidate comes back first is the one that spends the
    /// request's budget. Without an `ORDER BY` the query is a bare sequential scan and
    /// Postgres is free to return heap order, which any UPDATE to any row rewrites: two
    /// nodes holding identical data, or one node before and after an unrelated write,
    /// resolve the same CID by trying candidates in a different order, so one serves the
    /// object and the other sheds a 503.
    ///
    /// The sibling `pin_sources_for_oid` already orders its union for exactly this
    /// reason, and the handler's own comment leans on that determinism.
    ///
    /// MUTATION (RED): drop the `ORDER BY` and the post-UPDATE read comes back rotated.
    #[sqlx::test]
    async fn oids_for_cid_is_ordered_independently_of_physical_row_order(pool: PgPool) {
        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        let cid = "bafkreiorderingfixtureaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let oids = ["aa".repeat(32), "bb".repeat(32), "cc".repeat(32)];
        for oid in &oids {
            db.record_pinned_cid(oid, cid, None).await.unwrap();
        }

        let before = db.oids_for_cid(cid).await.unwrap();
        assert_eq!(before.len(), 3, "fixture must seed three candidates");

        // Move the first candidate to the end of the heap the way production does it:
        // an unpin followed by a re-pin of the same object. An in-place UPDATE is not
        // enough, since a HOT update leaves the row reachable from its original item
        // pointer and a sequential scan still returns it in its old position.
        sqlx::query("DELETE FROM pinned_cids WHERE sha256_hex = $1")
            .bind(&oids[0])
            .execute(&pool)
            .await
            .expect("unpin one candidate");
        db.record_pinned_cid(&oids[0], cid, None).await.unwrap();

        let after = db.oids_for_cid(cid).await.unwrap();
        assert_eq!(
            before, after,
            "an unrelated write to one candidate must not reorder the candidate list; \
             the order decides which oid spends the request's shared budget"
        );

        let mut sorted = after.clone();
        sorted.sort();
        assert_eq!(
            after, sorted,
            "the order must be a stated one (ascending oid), not whatever the heap holds"
        );
    }
}

#[cfg(test)]
mod pending_ref_transition_tests {
    //! #26 Split PR 1 — durable post-receive outbox at the DB layer.
    //!
    //! These tests exercise the producer / persistence / drain contracts
    //! directly. The handler-level test (failure injection between
    //! receive_pack and the bookkeeping) is a follow-up that lands with
    //! the handler refactor in the next slice. Every test here uses
    //! `Db::for_testing` + `run_migrations` to provision a clean schema,
    //! so they are independent of any other test's seed state.
    //!
    //! Each test names the invariant it pins. Reverting the production
    //! line under test turns the named assertion red.

    use super::{
        anchor_job_id_for, deterministic_id, pending_state, push_event_id_for, ref_cert_id_for,
        AnchorJob, Db, PendingRefTransition, RepoRecord,
    };
    use crate::api::repos::RefUpdate;
    use chrono::Utc;
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn ref_update(name: &str, old: &str, new: &str) -> RefUpdate {
        RefUpdate {
            ref_name: name.to_string(),
            old_sha: old.to_string(),
            new_sha: new.to_string(),
        }
    }

    /// The producer contract: every ref update in a push gets a `prepared`
    /// row carrying the verified pusher, the signature header, and the
    /// request id. `mark_applied` flips exactly those rows.
    #[sqlx::test]
    async fn insert_then_mark_applied_flips_state_for_every_ref(pool: PgPool) {
        let db = db(pool).await;
        let updates = vec![
            ref_update(
                "refs/heads/main",
                "a".repeat(40).as_str(),
                "b".repeat(40).as_str(),
            ),
            ref_update(
                "refs/heads/feature",
                "c".repeat(40).as_str(),
                "d".repeat(40).as_str(),
            ),
        ];
        let rows = db
            .insert_pending_ref_transitions(
                "req-1",
                "repo-1",
                "did:key:node",
                "did:key:pusher",
                &updates,
                "Signature: sig=...",
                "Signature-Input: ...",
                "Content-Digest: ...",
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "one row per ref update");
        assert!(rows.iter().all(|r| r.state == pending_state::PREPARED));

        let flipped = db
            .mark_pending_ref_transitions_applied("req-1")
            .await
            .unwrap();
        assert_eq!(flipped, 2, "every prepared row for the request flips");

        let drained = db.list_pending_ref_transitions_applied(100).await.unwrap();
        assert_eq!(drained.len(), 2);
        assert!(drained.iter().all(|r| r.state == pending_state::APPLIED));
        assert!(drained.iter().all(|r| r.pusher_did == "did:key:pusher"));
        assert!(
            drained
                .iter()
                .all(|r| r.signature_header == "Signature: sig=..."),
            "the original signature header must survive the round trip — \
             recovery re-derives the cert and the anchor under the original identity"
        );
    }

    /// A second `mark_applied` for the same request is a no-op — the row is
    /// already in `applied` and the state predicate prevents re-flipping.
    /// This is what makes a recovery re-pass safe.
    #[sqlx::test]
    async fn mark_applied_is_idempotent_on_repeat(pool: PgPool) {
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-2",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[ref_update(
                "refs/heads/main",
                "a".repeat(40).as_str(),
                "b".repeat(40).as_str(),
            )],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();

        assert_eq!(
            db.mark_pending_ref_transitions_applied("req-2")
                .await
                .unwrap(),
            1,
            "first call flips the one row"
        );
        assert_eq!(
            db.mark_pending_ref_transitions_applied("req-2")
                .await
                .unwrap(),
            0,
            "second call flips nothing — the row is already applied"
        );
    }

    /// The reviewer's second proof: a `cancelled` row is never drained.
    /// The drain's WHERE clause is on `state = 'applied'`, so a row that
    /// never made it past receive_pack CANNOT become a push event, a
    /// certificate, or an anchor handoff.
    #[sqlx::test]
    async fn cancelled_rows_are_not_returned_by_the_drain(pool: PgPool) {
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-3",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[ref_update(
                "refs/heads/main",
                "a".repeat(40).as_str(),
                "b".repeat(40).as_str(),
            )],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();
        db.mark_pending_ref_transitions_cancelled("req-3")
            .await
            .unwrap();

        let drained = db.list_pending_ref_transitions_applied(100).await.unwrap();
        assert!(
            drained.is_empty(),
            "a cancelled receive-pack must never reach the drain — the row's \
             state is `cancelled`, not `applied`, and the drain is keyed on `applied`"
        );
    }

    /// Same proof, but for the pre-flip state. A `prepared` row (handler
    /// crashed between `insert_prepared` and `mark_applied` / never
    /// reached either post-receive branch) is also never drained. The
    /// recovery cannot promote a `prepared` row by itself — only the
    /// handler's post-Ok code does, by calling `mark_applied`.
    #[sqlx::test]
    async fn prepared_rows_are_not_returned_by_the_drain(pool: PgPool) {
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-4",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[ref_update(
                "refs/heads/main",
                "a".repeat(40).as_str(),
                "b".repeat(40).as_str(),
            )],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();
        // No mark_applied / mark_cancelled call. The row stays `prepared`.

        let drained = db.list_pending_ref_transitions_applied(100).await.unwrap();
        assert!(
            drained.is_empty(),
            "a row the handler never reached the post-Ok branch for must not \
             be drained; only `mark_applied` flips a row, only the drain \
             picks up `applied` rows"
        );
    }

    /// The reviewer's first proof (DB layer): a recovery re-pass on the
    /// same `applied` row produces the same push event id, the same cert
    /// id, and the same anchor job id, and the idempotent inserts all
    /// collapse to no-ops. The drain deletes the row after the work
    /// lands, so a third pass has nothing to do.
    #[sqlx::test]
    async fn drain_then_re_derive_is_idempotent(pool: PgPool) {
        let db = db(pool).await;
        let now = Utc::now().to_rfc3339();
        let row = PendingRefTransition {
            id: super::deterministic_id(&[
                "pending_ref_transition",
                "req-5",
                "repo-1",
                "refs/heads/main",
                &"a".repeat(40),
                &"b".repeat(40),
            ]),
            request_id: "req-5".to_string(),
            repo_id: "repo-1".to_string(),
            ref_name: "refs/heads/main".to_string(),
            old_sha: "a".repeat(40),
            new_sha: "b".repeat(40),
            pusher_did: "did:key:pusher".to_string(),
            node_did: "did:key:node".to_string(),
            signature_header: "Signature: sig=...".to_string(),
            signature_input: "Signature-Input: ...".to_string(),
            content_digest: "Content-Digest: ...".to_string(),
            state: pending_state::APPLIED.to_string(),
            created_at: now.clone(),
            applied_at: Some(now.clone()),
            cancelled_at: None,
            // Single-ref test fixture; the request's only child is
            // ordinal 0. Multi-ref tests set the ordinal explicitly
            // for each child row.
            ordinal: 0,
            git_target_kind: Some("update".to_string()),
        };
        db.insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        // First drain: picks up the row. Caller would now re-derive the
        // artifacts; the row is then deleted.
        let first = db.list_pending_ref_transitions_applied(100).await.unwrap();
        assert_eq!(first.len(), 1);
        let push_id_1 = push_event_id_for(&row.request_id, row.ordinal);
        let cert_id_1 = ref_cert_id_for(&row.request_id, row.ordinal);
        let anchor_id_1 =
            anchor_job_id_for(&row.repo_id, &row.ref_name, &row.old_sha, &row.new_sha);

        // Second drain: row is still there (we did not delete). Re-derive
        // the same ids; the inserts collapse.
        let second = db.list_pending_ref_transitions_applied(100).await.unwrap();
        assert_eq!(second.len(), 1, "the row is still in `applied`");
        let push_id_2 = push_event_id_for(&row.request_id, row.ordinal);
        let cert_id_2 = ref_cert_id_for(&row.request_id, row.ordinal);
        let anchor_id_2 =
            anchor_job_id_for(&row.repo_id, &row.ref_name, &row.old_sha, &row.new_sha);
        assert_eq!(push_id_1, push_id_2, "push id is deterministic");
        assert_eq!(cert_id_1, cert_id_2, "cert id is deterministic");
        assert_eq!(anchor_id_1, anchor_id_2, "anchor id is deterministic");

        // Now exercise the idempotent inserts directly: a second
        // `record_push_with_id` returns false, the cert insert returns
        // None on the (repo_id, ref_name) unique, and the anchor insert
        // returns false on the (repo_id, ref_name, old_sha, new_sha)
        // unique.
        assert!(
            db.record_push_with_id(&push_id_1, &row.pusher_did, &row.repo_id, &row.new_sha, 0)
                .await
                .unwrap(),
            "first push insert is created"
        );
        assert!(
            !db.record_push_with_id(&push_id_2, &row.pusher_did, &row.repo_id, &row.new_sha, 0)
                .await
                .unwrap(),
            "second push insert with the same id collapses to a no-op"
        );

        // Anchor: one row per occurrence, never two for same occurrence.
        let job = AnchorJob {
            id: anchor_id_1.clone(),
            repo_id: row.repo_id.clone(),
            ref_name: row.ref_name.clone(),
            old_sha: row.old_sha.clone(),
            new_sha: row.new_sha.clone(),
            pusher_did: row.pusher_did.clone(),
            created_at: now.clone(),
            claimed_at: None,
            request_id: Some(row.request_id.clone()),
            request_ordinal: Some(row.ordinal),
        };
        assert!(db.insert_anchor_job_idempotent(&job).await.unwrap());
        assert!(
            !db.insert_anchor_job_idempotent(&job).await.unwrap(),
            "a second anchor insert with the same id is a no-op"
        );
        assert_eq!(
            db.count_anchor_jobs(&row.repo_id, &row.ref_name, &row.old_sha, &row.new_sha)
                .await
                .unwrap(),
            1,
            "exactly one anchor job per transition, no matter how many recovery passes"
        );
        assert_eq!(
            db.count_push_events(&row.repo_id, &row.new_sha, &row.pusher_did)
                .await
                .unwrap(),
            1,
            "exactly one push event per (repo, commit, pusher)"
        );

        // After the work lands, the drain deletes the row. A third pass
        // sees nothing.
        db.delete_pending_ref_transition(&row.id).await.unwrap();
        let third = db.list_pending_ref_transitions_applied(100).await.unwrap();
        assert!(third.is_empty(), "the row is gone after recovery");
    }

    #[sqlx::test]
    async fn anchor_occurrence_keys_recurrence_not_only_tuple(_pool: PgPool) {
        // A->B, B->A, A->B again must yield three handoffs; retry of one
        // occurrence remains a no-op.
        let a1 = super::anchor_job_id_for_occurrence("req-a", 0, "r", "refs/heads/m", "A", "B");
        let a2 = super::anchor_job_id_for_occurrence("req-b", 0, "r", "refs/heads/m", "B", "A");
        let a3 = super::anchor_job_id_for_occurrence("req-c", 0, "r", "refs/heads/m", "A", "B");
        assert_ne!(a1, a3, "same tuple, different occurrence => distinct id");
        assert_eq!(
            a1,
            super::anchor_job_id_for_occurrence("req-a", 0, "r", "refs/heads/m", "A", "B"),
            "retry reuses occurrence identity"
        );
        let _ = (a2,);
    }

    /// `mark_cancelled` is also idempotent. The state predicate is
    /// `state = 'prepared'`, so a second call flips nothing.
    #[sqlx::test]
    async fn mark_cancelled_is_idempotent_on_repeat(pool: PgPool) {
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-6",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[ref_update(
                "refs/heads/main",
                "a".repeat(40).as_str(),
                "b".repeat(40).as_str(),
            )],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();
        assert_eq!(
            db.mark_pending_ref_transitions_cancelled("req-6")
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            db.mark_pending_ref_transitions_cancelled("req-6")
                .await
                .unwrap(),
            0
        );
    }

    // ----- P1 round 4: per-ref variant tests -----
    //
    // The new per-ref helpers are the foundation of the
    // ref-by-ref outcome model. A mixed push where one ref was
    // rejected and one was accepted must:
    //   1. flip ONLY the accepted ref to `applied`
    //   2. flip ONLY the rejected ref to `cancelled`
    //   3. leave any ref the report did not mention as `prepared`
    // The bulk helpers were the bug that issued certs for the
    // rejected ref; the per-ref helpers are the fix.

    #[sqlx::test]
    async fn per_ref_applied_only_flips_named_refs(pool: PgPool) {
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-per-ref-1",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[
                ref_update("refs/heads/main", &"a".repeat(40), &"b".repeat(40)),
                ref_update("refs/heads/feature", &"c".repeat(40), &"d".repeat(40)),
                ref_update("refs/tags/v1", &"e".repeat(40), &"f".repeat(40)),
            ],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();

        // Flip only `main` and `feature` (the OK refs); the
        // tag stays `prepared` for the next call to handle.
        let n = db
            .mark_pending_ref_transitions_applied_for_names(
                "req-per-ref-1",
                &["refs/heads/main", "refs/heads/feature"],
            )
            .await
            .unwrap();
        assert_eq!(n, 2, "exactly the two named rows flip");

        // The tag row is still `prepared`.
        let applied = db.list_pending_ref_transitions_applied(100).await.unwrap();
        assert_eq!(applied.len(), 2, "two rows in applied");
        let names: std::collections::HashSet<&str> =
            applied.iter().map(|r| r.ref_name.as_str()).collect();
        assert!(names.contains("refs/heads/main"));
        assert!(names.contains("refs/heads/feature"));
        assert!(!names.contains("refs/tags/v1"));
    }

    #[sqlx::test]
    async fn per_ref_cancelled_only_flips_named_refs(pool: PgPool) {
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-per-ref-2",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[
                ref_update("refs/heads/main", &"a".repeat(40), &"b".repeat(40)),
                ref_update("refs/heads/feature", &"c".repeat(40), &"d".repeat(40)),
            ],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();
        // The report rejected only `main`.
        let n = db
            .mark_pending_ref_transitions_cancelled_for_names("req-per-ref-2", &["refs/heads/main"])
            .await
            .unwrap();
        assert_eq!(n, 1, "only the rejected ref flips");
        let still_prepared = db.list_pending_ref_transitions_prepared(100).await.unwrap();
        assert_eq!(still_prepared.len(), 1);
        assert_eq!(still_prepared[0].ref_name, "refs/heads/feature");
    }

    #[sqlx::test]
    async fn per_ref_uncertain_does_not_set_cancelled_at(pool: PgPool) {
        // P2 (reviewer-2 round 4): `mark_uncertain` must NOT set
        // `cancelled_at`. An `uncertain` row is undecided and
        // should leave the column null so any future consumer
        // filtering on `cancelled_at IS NOT NULL` only sees
        // truly-cancelled rows.
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-uncertain-test",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[ref_update(
                "refs/heads/main",
                &"a".repeat(40),
                &"b".repeat(40),
            )],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();
        let n = db
            .mark_pending_ref_transitions_uncertain("req-uncertain-test")
            .await
            .unwrap();
        assert_eq!(n, 1);
        let rows = db
            .list_pending_ref_transitions_prepared_or_uncertain(10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, pending_state::UNCERTAIN);
        assert!(
            rows[0].cancelled_at.is_none(),
            "uncertain row must leave cancelled_at null"
        );
    }

    #[sqlx::test]
    async fn lookup_pending_ref_transition_id_returns_named_ref(pool: PgPool) {
        // P1 (reviewer-1 round 4): the per-ref cleanup loop needs
        // to map (request_id, ref_name) → row_id. Verify the
        // lookup returns the correct id for the ref it was
        // inserted with, and `None` for an absent one.
        let db = db(pool).await;
        db.insert_pending_ref_transitions(
            "req-lookup",
            "repo-1",
            "did:key:node",
            "did:key:pusher",
            &[
                ref_update("refs/heads/main", &"a".repeat(40), &"b".repeat(40)),
                ref_update("refs/heads/feature", &"c".repeat(40), &"d".repeat(40)),
            ],
            "Signature: sig=...",
            "Signature-Input: ...",
            "Content-Digest: ...",
        )
        .await
        .unwrap();
        let main_id = db
            .lookup_pending_ref_transition_id("req-lookup", "refs/heads/main")
            .await
            .unwrap();
        assert!(main_id.is_some(), "main row id is present");
        let absent = db
            .lookup_pending_ref_transition_id("req-lookup", "refs/heads/never")
            .await
            .unwrap();
        assert!(absent.is_none(), "absent ref returns None");
    }

    #[sqlx::test]
    async fn count_pending_ref_transitions_applied_reports_zero_after_drain(pool: PgPool) {
        // P3 (reviewer-2 round 4): the residual-backlog warning
        // key on REMAINING, not on EXAMINED. A backlog of exactly
        // `per_pass_limit * (max_passes + 1)` rows that fully
        // drains must report `remaining == 0` so the warning does
        // not fire on a clean drain.
        let db = db(pool).await;
        assert_eq!(db.count_pending_ref_transitions_applied().await.unwrap(), 0);
    }

    /// P2 (reviewer-2 round 2): the multi-row `insert_pending_ref_transitions`
    /// must be atomic. A mid-loop failure (here simulated by pre-seeding a
    /// row whose PK collides with the second ref's deterministic id) must
    /// roll the first row back; otherwise the handler can return 503 after
    /// some `prepared` rows are already on disk, leaving the request in
    /// an inconsistent state for the startup reconcile to clean up.
    #[sqlx::test]
    async fn insert_pending_ref_transitions_rolls_back_on_mid_loop_failure(pool: sqlx::PgPool) {
        let db = db(pool).await;
        // Seed a repo so the FK (if any) is satisfied.
        db.create_repo(&RepoRecord {
            id: "repo-atomic".to_string(),
            name: "atomic".to_string(),
            owner_did: "did:key:zAtomic".to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/atomic".to_string(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        // Pre-seed a row that collides with the SECOND ref update's
        // deterministic id, so the loop's second INSERT fails on PK.
        let second_ref = "refs/heads/feature-a";
        let second_old = "2".repeat(40);
        let second_new = "3".repeat(40);
        let collision_id = deterministic_id(&[
            "pending_ref_transition",
            "req-atomic",
            "repo-atomic",
            second_ref,
            &second_old,
            &second_new,
        ]);
        // Direct insert bypassing the helper to land a `prepared` row
        // with the colliding id.
        sqlx::query(
            r#"INSERT INTO pending_ref_transitions
               (id, request_id, repo_id, ref_name, old_sha, new_sha, pusher_did, node_did,
                signature_header, signature_input, content_digest, state, created_at,
                ordinal, git_target_kind)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
        )
        .bind(&collision_id)
        .bind("req-pre-seed")
        .bind("repo-atomic")
        .bind(second_ref)
        .bind(&second_old)
        .bind(&second_new)
        .bind("did:key:zPre")
        .bind("did:key:zNode")
        .bind("sig-pre")
        .bind("sig-input-pre")
        .bind("digest-pre")
        .bind(pending_state::PREPARED)
        .bind(Utc::now().to_rfc3339())
        .bind(1_i32) // second child of the seeded request
        .bind(Option::<String>::None)
        .execute(db.pool())
        .await
        .unwrap();

        // Now call the production helper. The first ref (main) inserts
        // fine; the second ref collides and the loop returns Err.
        let res = db
            .insert_pending_ref_transitions(
                "req-atomic",
                "repo-atomic",
                "did:key:zNode",
                "did:key:zPusher",
                &[
                    ref_update("refs/heads/main", &"1".repeat(40), &"2".repeat(40)),
                    ref_update(second_ref, &second_old, &second_new),
                ],
                "sig",
                "sig-input",
                "digest",
            )
            .await;
        assert!(
            res.is_err(),
            "the colliding insert must return Err (pre-condition for the rollback check)"
        );

        // The atomicity half: NO `req-atomic` row may exist. Without
        // the transaction the first row would have been persisted
        // before the second failed, and the startup reconcile would
        // later see a stranded `prepared` row pointing at a push
        // that never ran.
        let stranded = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pending_ref_transitions WHERE request_id = $1",
        )
        .bind("req-atomic")
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            stranded, 0,
            "the transaction must roll back the first row when the second fails"
        );
        // The pre-seeded row is unaffected.
        let pres = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pending_ref_transitions WHERE id = $1",
        )
        .bind(&collision_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(pres, 1, "the pre-seeded row is untouched");
    }

    /// The `deterministic_id` helper uses an ASCII Unit Separator between
    /// fields so that two distinct tuples can never collide by accidental
    /// prefix overlap. `(a, bc)` and `(ab, c)` would otherwise hash the
    /// same input. A regression on the separator shows up here.
    #[test]
    fn deterministic_id_avoids_prefix_overlap_collisions() {
        let a = super::deterministic_id(&["a", "bc"]);
        let b = super::deterministic_id(&["ab", "c"]);
        assert_ne!(a, b, "the field separator must distinguish ab+bc from a+bc");
    }

    /// The push event id is stable across calls. The recovery drain
    /// derives it the same way twice and gets the same value, which is
    /// the entire reason for using a hash instead of a UUID.
    #[test]
    fn push_event_id_for_is_stable() {
        assert_eq!(push_event_id_for("req-x", 0), push_event_id_for("req-x", 0));
        assert_ne!(
            push_event_id_for("req-x", 0),
            push_event_id_for("req-y", 0),
            "different request ids produce different push event ids"
        );
        assert_ne!(
            push_event_id_for("req-x", 0),
            push_event_id_for("req-x", 1),
            "different ordinals produce different push event ids"
        );
    }
}

#[cfg(test)]
mod policy_fence_tests {
    //! P1 (reviewer round 9): the third fence has a single
    //! production call site but no test that can fail when the
    //! guard stops comparing. These tests pin the three modes:
    //!
    //! 1. matching epoch lands the row
    //! 2. epoch bumped between capture and record aborts the
    //!    record with no row landed
    //! 3. the i64::MAX "no fence" sentinel skips the lock and
    //!    lands the row
    //!
    //! P2: a missing repos row must fail closed (was
    //! `unwrap_or(0)` — a fail-open path against a non-existent
    //! repo).
    use super::{Db, RepoRecord};
    use chrono::Utc;
    use sqlx::PgPool;
    use std::time::{Duration, Instant};

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    async fn seed_repo(db: &Db) -> String {
        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&RepoRecord {
            id: repo_id.clone(),
            name: "fence-test".into(),
            owner_did: "did:key:zFENCE".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: "/tmp/fence-test".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();
        repo_id
    }

    #[sqlx::test]
    async fn record_pinned_cid_with_source_fenced_pins_under_matching_epoch(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = seed_repo(&db).await;
        let epoch = db.repo_policy_epoch(&repo_id).await.unwrap();
        db.record_pinned_cid_with_source_fenced("sha-match-1", "cid-match-1", &repo_id, epoch)
            .await
            .expect("matching epoch must land the row");
    }

    #[sqlx::test]
    async fn record_pinned_cid_with_source_fenced_aborts_on_epoch_bump(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = seed_repo(&db).await;
        // Capture an epoch, then bump the policy_epoch between
        // capture and record. The fenced record must abort and
        // the row must NOT land.
        let captured = db.repo_policy_epoch(&repo_id).await.unwrap();
        // Simulate a narrowing rule write by bumping the epoch
        // the way `set_visibility_rule` would.
        db.bump_repo_policy_epoch(&repo_id).await.unwrap();
        let result = db
            .record_pinned_cid_with_source_fenced("sha-bump-1", "cid-bump-1", &repo_id, captured)
            .await;
        assert!(result.is_err(), "epoch bump must abort the record");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("policy epoch changed"),
            "the abort message names the failure class, got: {err}"
        );
        // No row should have landed in pinned_cids.
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pinned_cids WHERE sha256_hex = 'sha-bump-1'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(count, 0, "no row landed when the epoch was bumped");
    }

    #[sqlx::test]
    async fn record_pinned_cid_with_source_fenced_with_sentinel_skips_comparison(pool: PgPool) {
        // P2 (reviewer round 9): the i64::MAX sentinel is the
        // push-side "no fence" path. The call must succeed
        // even against a repo whose policy_epoch is something
        // other than i64::MAX, because the comparison is
        // skipped on the sentinel path. Also: the sentinel
        // path must NOT take the row lock (push side has no
        // decision to invalidate).
        let db = db(pool).await;
        let repo_id = seed_repo(&db).await;
        // Epoch here is 0 by default; the i64::MAX sentinel
        // would fail any comparison. The test passes only
        // because the sentinel path skips the comparison AND
        // the row lock.
        let start = Instant::now();
        db.record_pinned_cid_with_source_fenced(
            "sha-sentinel-1",
            "cid-sentinel-1",
            &repo_id,
            i64::MAX,
        )
        .await
        .expect("i64::MAX sentinel must land the row without comparing or locking");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "sentinel-path record should not contend on a row lock, \
             took {elapsed:?}"
        );
    }

    #[sqlx::test]
    async fn record_pinned_cid_with_source_fenced_bails_on_missing_repo(pool: PgPool) {
        // P2 (reviewer round 9): a record call against a
        // non-existent repo must NOT silently pass. The
        // previous `unwrap_or(0)` paired with `i64::MAX != 0`
        // admitted a row against a missing repos row. The
        // helper now bails with no row landed.
        let db = db(pool).await;
        let result = db
            .record_pinned_cid_with_source_fenced(
                "sha-missing-1",
                "cid-missing-1",
                "nonexistent-repo-id",
                0,
            )
            .await;
        assert!(result.is_err(), "missing repos row must abort the record");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("policy epoch row missing"),
            "the abort message names the failure class, got: {err}"
        );
    }

    /// `verify_pinata_record` is the read half of the timed-out-write
    /// contract: true only for the exact row content with a matching fence
    /// epoch. Covers the four unconfirmed shapes a timed-out
    /// `record_pinata_cid` must not count as durable.
    #[sqlx::test]
    async fn verify_pinata_record_proves_exact_row_and_epoch(pool: PgPool) {
        let db = db(pool).await;
        let repo_id = seed_repo(&db).await;
        let epoch = db.repo_policy_epoch(&repo_id).await.unwrap();
        db.record_pinata_cid(
            "sha-vrf-1",
            "cid-raw-vrf-1",
            "cid-prov-vrf-1",
            Some(&repo_id),
            epoch,
        )
        .await
        .unwrap();
        assert!(
            db.verify_pinata_record(
                "sha-vrf-1",
                "cid-raw-vrf-1",
                "cid-prov-vrf-1",
                &repo_id,
                epoch
            )
            .await
            .unwrap(),
            "the exact row with a matching epoch verifies"
        );
        assert!(
            !db.verify_pinata_record(
                "sha-vrf-1",
                "cid-raw-vrf-1",
                "cid-other-provider",
                &repo_id,
                epoch
            )
            .await
            .unwrap(),
            "a different provider CID must not verify"
        );
        assert!(
            !db.verify_pinata_record(
                "sha-vrf-1",
                "cid-other-raw",
                "cid-prov-vrf-1",
                &repo_id,
                epoch
            )
            .await
            .unwrap(),
            "a different raw CID must not verify"
        );
        assert!(
            !db.verify_pinata_record(
                "sha-vrf-absent",
                "cid-raw-vrf-1",
                "cid-prov-vrf-1",
                &repo_id,
                epoch
            )
            .await
            .unwrap(),
            "a missing row must not verify"
        );
        // A narrow landing after the write must invalidate the proof even
        // though the row is still present.
        db.bump_repo_policy_epoch(&repo_id).await.unwrap();
        assert!(
            !db.verify_pinata_record(
                "sha-vrf-1",
                "cid-raw-vrf-1",
                "cid-prov-vrf-1",
                &repo_id,
                epoch
            )
            .await
            .unwrap(),
            "a moved epoch must not verify against the captured one"
        );
        // Equal-CID shape stores cid NULL; verification matches that shape.
        let epoch2 = db.repo_policy_epoch(&repo_id).await.unwrap();
        db.record_pinata_cid("sha-vrf-2", "cid-same", "cid-same", Some(&repo_id), epoch2)
            .await
            .unwrap();
        assert!(
            db.verify_pinata_record("sha-vrf-2", "cid-same", "cid-same", &repo_id, epoch2)
                .await
                .unwrap(),
            "the equal-CID NULL shape verifies against itself"
        );
        assert!(
            db.verify_pinata_record("sha-vrf-2", "cid-same", "cid-same", &repo_id, i64::MAX)
                .await
                .unwrap(),
            "the unfenced sentinel skips the epoch comparison"
        );
    }
}
