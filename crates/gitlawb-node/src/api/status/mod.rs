//! Commit status claims: the write path and the combined read.
//!
//! POST /api/v1/repos/:owner/:repo/statuses/:sha — append one claim (owner only)
//! GET  /api/v1/repos/:owner/:repo/commits/:sha/status — the combined projection
//!
//! Claims are append-only: a producer reporting twice for the same context
//! leaves both rows and the visible status is a projection over the history.
//! Reporting twice means two REQUESTS, though. An exact repeat of one already
//! accepted is answered with 200 and the row it wrote, not a second row: the
//! projection elects the highest `seq`, so a replayed claim would not duplicate
//! a verdict but overturn the one that superseded it.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::StatusClaim;
use crate::error::{AppError, Result};
use crate::state::AppState;

/// Claims for one (repo, commit, producer, context). Generous for a real
/// producer; a producer past it is misbehaving.
const MAX_CLAIMS_PER_TUPLE: i64 = 100;
/// Distinct contexts for one (repo, commit). The context string is caller-chosen
/// and free-form, so the tuple cap alone bounds nothing.
const MAX_CONTEXTS_PER_COMMIT: i64 = 50;
/// Claim rows for one repo within the trailing window the db layer counts over.
/// The commit SHA is caller-chosen and never existence-checked, so a writer at
/// the two caps above can still fan out over fresh 40-hex strings without this
/// one. It bounds the RATE of that fan-out rather than a lifetime total, because
/// nothing prunes the table: a lifetime bound would close the surface on a repo
/// permanently while answering with a status every client retries.
const MAX_CLAIMS_PER_REPO_PER_WINDOW: i64 = 10_000;

#[derive(Deserialize)]
pub struct CreateStatusRequest {
    pub state: String,
    pub context: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
}

/// The wire state set (KTD-1): GitHub's four commit-status states, so absence
/// stays distinguishable without a fifth value no client understands.
const CLAIM_STATES: [&str; 4] = ["error", "failure", "pending", "success"];

/// Bounds on the signature material this write path persists verbatim. Every one
/// of the four is caller-influenced: the headers come off the request, the
/// signing string grows with the component list the caller's Signature-Input
/// chose, and the body is the caller's. Without a bound the claim log's row size
/// is set by whoever writes to it, so these are explicit and generous rather than
/// implicit and absent. A conforming `sign_request` produces roughly 100, 200 and
/// 400 bytes for the first three.
const MAX_SIGNATURE_CHARS: usize = 512;
const MAX_SIGNATURE_INPUT_CHARS: usize = 1024;
const MAX_SIGNING_STRING_CHARS: usize = 4096;
/// The body is a `CreateStatusRequest`, whose own fields are already capped at
/// roughly 3.3 KB in total by the three limits below; this leaves room for JSON
/// framing and nothing more.
const MAX_REQUEST_BODY_BYTES: usize = 8192;

const MAX_CONTEXT_CHARS: usize = 255;
const MAX_TARGET_URL_CHARS: usize = 2048;
const MAX_DESCRIPTION_CHARS: usize = 1024;

/// The 201 body for an accepted claim: what the client needs to identify the row
/// it just wrote, and nothing else.
///
/// Deliberately not the stored [`StatusClaim`]. That struct carries the signature
/// material, and serializing it echoed the signature, the signing string and the
/// whole request body back on every write — the body as a JSON array of integers.
/// Write-time provenance belongs in the row, not on the wire, which is the same
/// line [`StatusEntry`] draws on the read side.
#[derive(Serialize)]
pub struct CreatedStatus {
    pub id: String,
    /// The database-assigned ordering key, so the client can name its own row.
    pub seq: i64,
    pub repo_id: String,
    pub commit_sha: String,
    pub state: String,
    pub context: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub producer_did: String,
    pub created_at: String,
}

impl CreatedStatus {
    fn from_claim(claim: StatusClaim, seq: i64) -> Self {
        Self {
            id: claim.id,
            seq,
            repo_id: claim.repo_id,
            commit_sha: claim.commit_sha,
            state: claim.state,
            context: claim.context,
            target_url: claim.target_url,
            description: claim.description,
            producer_did: claim.producer_did,
            created_at: claim.created_at,
        }
    }
}

/// POST /api/v1/repos/:owner/:repo/statuses/:sha
pub async fn create_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, sha)): Path<(String, String, String)>,
    material: Option<Extension<crate::auth::SignatureMaterial>>,
    Json(req): Json<CreateStatusRequest>,
) -> Result<(StatusCode, Json<CreatedStatus>)> {
    // Read-visibility first, then owner, and the order is the security property.
    // authorize_repo_read denies a quarantined repo before the visibility gate and
    // answers with the repo's own not-found, byte-identical to a missing repo, so
    // a caller who cannot read the repo cannot learn it exists. Loading the repo
    // and comparing the owner would answer 403 there, turning this endpoint into
    // an existence oracle. require_repo_owner then 403s a non-owner of a repo the
    // caller can read, where existence is not secret.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(&auth.0), "/").await?;
    crate::api::require_repo_owner(&record, &auth.0)?;

    let commit_sha = normalize_sha(&sha)?;
    let claim_state = validate_state(&req.state)?;
    let context = validate_context(&req.context)?;
    let target_url = validate_target_url(req.target_url.as_deref())?;
    let description = validate_description(req.description.as_deref())?;

    // KTD-5: the signature material is captured here because the request carries
    // the only copy, and `signing_string` is the exact byte sequence the
    // middleware verified. Its absence means this handler was reached without
    // `require_signature` — a server misconfiguration (a route group that lost
    // its auth layer, a handler mounted somewhere new), not anything the client
    // did, so it is a 500 and no row is written. Storing an empty payload instead
    // would leave every claim from that moment on unverifiable with nothing going
    // red, which is exactly the absence-renders-as-success shape.
    let Some(Extension(material)) = material else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "status claim write reached without verified signature material — \
             the route is not behind require_signature"
        )));
    };
    // Bounded before anything is written. The material is verified, which says
    // the caller holds the key, not that what they signed is a reasonable size.
    bound("signature", material.signature.len(), MAX_SIGNATURE_CHARS)?;
    bound(
        "signature_input",
        material.signature_input.len(),
        MAX_SIGNATURE_INPUT_CHARS,
    )?;
    bound(
        "signing_string",
        material.signing_string.len(),
        MAX_SIGNING_STRING_CHARS,
    )?;
    bound("request body", material.body.len(), MAX_REQUEST_BODY_BYTES)?;

    let digest = request_digest(&material);
    let (signature, signature_input, signing_string, request_body) = (
        material.signature,
        material.signature_input,
        material.signing_string,
        material.body.to_vec(),
    );

    let claim = StatusClaim {
        id: Uuid::new_v4().to_string(),
        // Ignored on insert: the database assigns the ordering key (KTD-3).
        seq: 0,
        repo_id: record.id.clone(),
        commit_sha,
        state: claim_state,
        context,
        target_url,
        description,
        // Both are the owner identity today (KTD-5); they split when delegated
        // capabilities land.
        producer_did: auth.0.clone(),
        authorizing_did: auth.0,
        signature,
        signature_input,
        signing_string,
        request_body,
        request_digest: digest,
        created_at: Utc::now().to_rfc3339(),
    };

    let caps = crate::db::ClaimCaps {
        per_tuple: MAX_CLAIMS_PER_TUPLE,
        contexts_per_commit: MAX_CONTEXTS_PER_COMMIT,
        per_repo_window: MAX_CLAIMS_PER_REPO_PER_WINDOW,
    };
    match state.db.insert_status_claim_capped(&claim, &caps).await? {
        crate::db::ClaimInsert::Inserted(seq) => Ok((
            StatusCode::CREATED,
            Json(CreatedStatus::from_claim(claim, seq)),
        )),
        // Already recorded, so 200 and the original row rather than 201 and a
        // second one. The claim the caller gets back is the stored one, id and
        // seq included, which is what makes a retry safe to treat as success.
        crate::db::ClaimInsert::AlreadyRecorded(existing) => {
            let seq = existing.seq;
            Ok((
                StatusCode::OK,
                Json(CreatedStatus::from_claim(*existing, seq)),
            ))
        }
        crate::db::ClaimInsert::CapExceeded(which) => Err(AppError::TooManyRequests(format!(
            "claim limit reached for {which}"
        ))),
    }
}

/// The identity of one signed write, as a hex sha-256.
///
/// All four inputs together, because a replay is the same bytes arriving twice:
/// the signature, the input that names what it covers, the canonical string it
/// was verified over, and the body that string covers through a content-digest.
/// The signature alone would nearly do (it covers the other three transitively),
/// but hashing what is actually stored means the digest describes the row rather
/// than a claim about it.
///
/// Each field is length-prefixed so no two different requests can concatenate to
/// the same bytes: without it, a signature ending in some prefix of the next
/// field would collide with the shorter signature that absorbed it.
///
/// This is not a nonce, and deliberately so. A nonce table needs pruning and a
/// pruning window is a second replay window; the claim row IS the record of what
/// was accepted, so uniqueness on it is self-maintaining.
fn request_digest(material: &crate::auth::SignatureMaterial) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in [
        material.signature.as_bytes(),
        material.signature_input.as_bytes(),
        material.signing_string.as_bytes(),
        &material.body,
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    format!("{:x}", h.finalize())
}

/// One reported context in the combined response. Signature material is
/// deliberately absent: it is write-time provenance, not read-surface data.
#[derive(Serialize)]
pub struct StatusEntry {
    pub state: String,
    pub context: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub producer_did: String,
    pub created_at: String,
}

/// The combined commit status. `state` never leaves the four-value set (KTD-1),
/// so absence is carried by `total_count` 0 with the pending state rather than a
/// fifth value, and `reported_only` (R19) says out loud that the state covers the
/// contexts that reported, not every check a caller expected.
#[derive(Serialize)]
pub struct CombinedStatus {
    pub state: String,
    pub sha: String,
    pub total_count: usize,
    pub statuses: Vec<StatusEntry>,
    pub reported_only: bool,
}

/// GET /api/v1/repos/:owner/:repo/commits/:sha/status
///
/// The auth extension is optional and MUST be last in the extractor list: the
/// route group carries `optional_signature`, so an unsigned caller reaches here
/// with no `AuthenticatedDid` at all and a public repo still answers.
pub async fn commit_status(
    State(state): State<AppState>,
    Path((owner, name, sha)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<CombinedStatus>> {
    let caller = auth.as_ref().map(|Extension(a)| a.0.as_str());
    // The gate runs first and on the requested path, before any claim data is
    // touched. Its deny is the repo's own not-found, byte-identical to a missing
    // repo, so the status surface cannot answer "does this repo exist".
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let commit_sha = normalize_sha(&sha)?;
    let statuses = project_claims(&state, &record, &commit_sha).await?;

    Ok(Json(CombinedStatus {
        state: combined_state(&statuses).to_string(),
        sha: commit_sha,
        total_count: statuses.len(),
        statuses,
        reported_only: true,
    }))
}

/// The projection, in one place. Both read surfaces call it, so R3's "the rollup
/// is derived by the same projection as the commit read" holds by construction
/// rather than by two implementations happening to agree.
///
/// KTD-5: current authorization, not write-time authorization. An ownership
/// transfer drops the prior owner's claims from the projection while the
/// append-only history keeps them.
async fn project_claims(
    state: &AppState,
    record: &crate::db::RepoRecord,
    commit_sha: &str,
) -> Result<Vec<StatusEntry>> {
    let claims = state
        .db
        .latest_status_claims(&record.id, commit_sha, &record.owner_did)
        .await?;
    Ok(claims
        .into_iter()
        .map(|c| StatusEntry {
            state: c.state,
            context: c.context,
            target_url: c.target_url,
            description: c.description,
            producer_did: c.producer_did,
            created_at: c.created_at,
        })
        .collect())
}

/// The pull request head rollup (R11). `state` stays inside the four wire values
/// whatever happened to the head (KTD-1): an unresolvable head is carried by
/// `head_resolved`, alongside the pull request's own state, so a client can tell
/// "the head could not be resolved" from "the head resolved and nothing reported"
/// without a fifth state value no client understands.
#[derive(Serialize)]
pub struct PullRequestStatus {
    pub number: i64,
    /// The pull request's own state: open, closed, or merged.
    pub pull_request_state: String,
    pub head_resolved: bool,
    /// The target commit, absent exactly when `head_resolved` is false.
    pub sha: Option<String>,
    pub state: String,
    pub total_count: usize,
    pub statuses: Vec<StatusEntry>,
    pub reported_only: bool,
}

/// GET /api/v1/repos/:owner/:repo/pulls/:number/status
///
/// Same optional-auth shape as the commit read, and the auth extension MUST stay
/// last in the extractor list.
pub async fn pull_request_status(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<PullRequestStatus>> {
    let caller = auth.as_ref().map(|Extension(a)| a.0.as_str());
    // The gate runs first, on the requested path, before the pull request row is
    // loaded. Its deny is the repo's own not-found, byte-identical to a missing
    // repo. Once it passes, a missing pull request number is the plain not-found:
    // existence is no longer secret.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let head = rollup_head(&state, &record, &pr).await?;

    let statuses = match &head {
        Some(sha) => project_claims(&state, &record, sha).await?,
        None => Vec::new(),
    };

    Ok(Json(PullRequestStatus {
        number: pr.number,
        pull_request_state: pr.status,
        head_resolved: head.is_some(),
        sha: head,
        state: combined_state(&statuses).to_string(),
        total_count: statuses.len(),
        statuses,
        reported_only: true,
    }))
}

/// Branch-head lookups performed by the rollup fallback, counted so a test can
/// assert WORK DONE rather than only the answer returned. A fallback that
/// re-resolved on every read and then discarded the answer would be invisible in
/// the response and visible here.
#[cfg(test)]
pub(crate) static BRANCH_RESOLVES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The rollup's target commit (KTD-4).
///
/// The stored head wins whenever it is set. It is frozen at close or merge, so a
/// closed or merged pull request keeps the commit the decision was made against,
/// and only an OPEN pull request with no stored head falls back to the branch.
///
/// The fallback is one database read: the latest push this node recorded for the
/// pull request's source branch, from `repo_push_events`. It deliberately does
/// NOT go through `git::store` ref listing, which needs an acquired repository
/// path — on a cold node that downloads the whole repository from object storage,
/// and this read group carries no rate limiter, so an anonymous caller could
/// drive repeated downloads with a URL.
///
/// `repo_push_events` is the source rather than `branch_cids` because
/// `record_push_events` writes it for every ref update unconditionally, whereas
/// the sole writer of `branch_cids` sits behind a pin CID. A node with no object
/// pinning configured never writes that table, so a resolve keyed on it could
/// never answer there and every open pull request without a stored head reported
/// `head_resolved: false` forever. The residual limit is that only pushes taken
/// after this shipped have rows, so a branch last pushed before then still does
/// not resolve.
///
/// The resolved head is persisted, which makes an unauthenticated GET write. That
/// is only acceptable because the write is self-limiting: it fires exactly when
/// `head_commit` is absent and it fills it, and the fill is conditioned on that
/// same absence in SQL, so the PERSIST happens at most once per pull request.
/// The resolve attempt itself is not once-only — a pull request whose branch does
/// not resolve stores nothing, so there is nothing to short-circuit on and the
/// lookup runs again on every read until it succeeds.
async fn rollup_head(
    state: &AppState,
    record: &crate::db::RepoRecord,
    pr: &crate::db::PullRequest,
) -> Result<Option<String>> {
    if let Some(stored) = pr.head_commit.clone() {
        return Ok(Some(stored));
    }
    if pr.status != "open" {
        return Ok(None);
    }

    // The push path records the full ref while a pull request stores the bare
    // branch name, the same mismatch `crate::api::repos::branch_from_ref`
    // reconciles on the write side; this is that mapping run backwards. The empty
    // branch is excluded for the same reason it is there: `refs/heads/` is not a
    // branch and nothing can have written it.
    if pr.source_branch.is_empty() {
        return Ok(None);
    }
    let ref_name = format!("refs/heads/{}", pr.source_branch);
    #[cfg(test)]
    BRANCH_RESOLVES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let resolved = state
        .db
        .latest_push_sha_for_ref(&record.id, &ref_name)
        .await?
        // A recorded head that is not a commit SHA is no target at all, and
        // storing it would leave the rollup pointing at nothing forever.
        .and_then(|sha| normalize_sha(&sha).ok());

    let Some(sha) = resolved else {
        return Ok(None);
    };
    // Best effort, and deliberately not `?`. The head is already resolved and the
    // response does not depend on this write landing, so a transient database
    // failure here must not turn a served read into a 500; the next read resolves
    // again and re-attempts the fill. Same catch-and-log the sibling writes on the
    // push path use (`update_open_pr_heads`, `record_push_events`).
    if let Err(e) = state.db.set_pr_head_if_absent(&pr.id, &sha).await {
        tracing::warn!(
            err = %e,
            pr_id = %pr.id,
            "failed to persist a resolved pull request head; serving the resolved head anyway"
        );
    }
    Ok(Some(sha))
}

/// KTD-1's fold: any error or failure yields failure, else any pending yields
/// pending, else success. An empty set is pending, never success — total absence
/// of a verdict is its own state and must not read as a pass (R10).
fn combined_state(statuses: &[StatusEntry]) -> &'static str {
    if statuses.is_empty() {
        return "pending";
    }
    if statuses
        .iter()
        .any(|s| s.state == "error" || s.state == "failure")
    {
        "failure"
    } else if statuses.iter().any(|s| s.state == "pending") {
        "pending"
    } else {
        "success"
    }
}

/// 40 hex characters, lowercased. The SHA is never existence-checked (KTD-7):
/// a claim describes a commit object, and the object may not have arrived yet.
fn normalize_sha(sha: &str) -> Result<String> {
    if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(sha.to_ascii_lowercase())
    } else {
        Err(AppError::BadRequest(
            "commit sha must be exactly 40 hexadecimal characters".into(),
        ))
    }
}

/// One size bound on persisted signature material, measured in bytes.
fn bound(what: &str, len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(AppError::BadRequest(format!(
            "{what} must be at most {max} bytes"
        )));
    }
    Ok(())
}

fn validate_state(state: &str) -> Result<String> {
    if CLAIM_STATES.contains(&state) {
        Ok(state.to_string())
    } else {
        Err(AppError::BadRequest(format!(
            "state must be one of {}",
            CLAIM_STATES.join(", ")
        )))
    }
}

/// The context is the projection key, so it is trimmed, bounded, and required to
/// be free of control characters.
fn validate_context(context: &str) -> Result<String> {
    let trimmed = context.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_CONTEXT_CHARS {
        return Err(AppError::BadRequest(format!(
            "context must be 1 to {MAX_CONTEXT_CHARS} characters"
        )));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "context must not contain control characters".into(),
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_target_url(url: Option<&str>) -> Result<Option<String>> {
    let Some(url) = url else { return Ok(None) };
    if url.chars().count() > MAX_TARGET_URL_CHARS {
        return Err(AppError::BadRequest(format!(
            "target_url must be at most {MAX_TARGET_URL_CHARS} characters"
        )));
    }
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(Some(url.to_string()))
    } else {
        Err(AppError::BadRequest(
            "target_url must be an http or https URL".into(),
        ))
    }
}

fn validate_description(description: Option<&str>) -> Result<Option<String>> {
    match description {
        Some(d) if d.chars().count() > MAX_DESCRIPTION_CHARS => Err(AppError::BadRequest(format!(
            "description must be at most {MAX_DESCRIPTION_CHARS} characters"
        ))),
        other => Ok(other.map(str::to_string)),
    }
}

#[cfg(test)]
mod tests;
