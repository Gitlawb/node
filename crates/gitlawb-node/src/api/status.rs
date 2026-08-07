//! Commit status claims: the write path and the combined read.
//!
//! POST /api/v1/repos/:owner/:repo/statuses/:sha — append one claim (owner only)
//! GET  /api/v1/repos/:owner/:repo/commits/:sha/status — the combined projection
//!
//! Claims are append-only: a producer reporting twice for the same context
//! leaves both rows and the visible status is a projection over the history.

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
/// Total claim rows for one repo. The commit SHA is caller-chosen and never
/// existence-checked, so a writer at the two caps above can still fan out over
/// fresh 40-hex strings without this one.
const MAX_CLAIMS_PER_REPO: i64 = 10_000;

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

const MAX_CONTEXT_CHARS: usize = 255;
const MAX_TARGET_URL_CHARS: usize = 2048;
const MAX_DESCRIPTION_CHARS: usize = 1024;

/// POST /api/v1/repos/:owner/:repo/statuses/:sha
pub async fn create_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, sha)): Path<(String, String, String)>,
    material: Option<Extension<crate::auth::SignatureMaterial>>,
    Json(req): Json<CreateStatusRequest>,
) -> Result<(StatusCode, Json<StatusClaim>)> {
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
    let (signature, signature_input, signed_payload) = (
        material.signature,
        material.signature_input,
        material.signing_string.into_bytes(),
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
        signed_payload,
        created_at: Utc::now().to_rfc3339(),
    };

    let caps = crate::db::ClaimCaps {
        per_tuple: MAX_CLAIMS_PER_TUPLE,
        contexts_per_commit: MAX_CONTEXTS_PER_COMMIT,
        per_repo: MAX_CLAIMS_PER_REPO,
    };
    match state.db.insert_status_claim_capped(&claim, &caps).await? {
        crate::db::ClaimInsert::Inserted(seq) => {
            Ok((StatusCode::CREATED, Json(StatusClaim { seq, ..claim })))
        }
        crate::db::ClaimInsert::CapExceeded(which) => Err(AppError::TooManyRequests(format!(
            "claim limit reached for {which}"
        ))),
    }
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
    let authorizing = authorizing_did_variants(&record.owner_did);
    let claims = state
        .db
        .latest_status_claims(&record.id, commit_sha, &authorizing)
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

/// The set of stored `authorizing_did` values that count as the current owner,
/// reproducing [`crate::api::did_matches`] as a set so the filter can be a
/// membership test inside the projection query. `did:key` collapses its full and
/// bare forms; every other method matches exactly, because a bare base58 id must
/// never match across methods.
fn authorizing_did_variants(owner_did: &str) -> Vec<String> {
    let key_id = owner_did.strip_prefix("did:key:").unwrap_or(owner_did);
    if key_id.contains(':') {
        return vec![owner_did.to_string()];
    }
    let full = format!("did:key:{key_id}");
    if full == owner_did {
        vec![owner_did.to_string(), key_id.to_string()]
    } else {
        vec![owner_did.to_string(), full]
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
mod tests {
    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use sqlx::PgPool;
    use tower::ServiceExt;

    use crate::db::RepoRecord;
    use crate::test_support::{signed_request_as, test_state};

    const OWNER: &str = "did:key:zSTATUSOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const STRANGER: &str = "did:key:zSTATUSSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBB";
    const SHA_A: &str = "1111111111111111111111111111111111111111";
    const SHA_B: &str = "2222222222222222222222222222222222222222";
    const SHA_C: &str = "3333333333333333333333333333333333333333";

    fn seed_repo(owner_did: &str, name: &str, is_public: bool) -> RepoRecord {
        let now = chrono::Utc::now();
        RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{name}"),
            forked_from: None,
            machine_id: None,
        }
    }

    fn router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/statuses/{sha}",
                post(super::create_status),
            )
            .with_state(state)
    }

    fn body_of(state: &str, context: &str) -> Body {
        Body::from(format!(r#"{{"state":"{state}","context":"{context}"}}"#))
    }

    fn uri(owner: &str, repo: &str, sha: &str) -> String {
        format!("/api/v1/repos/{owner}/{repo}/statuses/{sha}")
    }

    /// `signed_request_as` plus the verified RFC 9421 material the signature
    /// middleware injects in production, so a handler mounted bare still runs the
    /// real path instead of a missing-material branch.
    fn signed_with_material(did: &str, uri: &str, body: Body) -> axum::http::Request<Body> {
        let mut req = signed_request_as(did, Method::POST, uri, body);
        req.extensions_mut().insert(crate::auth::SignatureMaterial {
            signature: "sig1=:dGVzdA==:".to_string(),
            signature_input: "sig1=(\"@method\" \"@path\" \"content-digest\");alg=\"ed25519\""
                .to_string(),
            signing_string: "\"@method\": POST".to_string(),
        });
        req
    }

    async fn post_as(
        state: &crate::state::AppState,
        did: &str,
        uri: &str,
        body: Body,
    ) -> axum::response::Response {
        router(state.clone())
            .oneshot(signed_with_material(did, uri, body))
            .await
            .unwrap()
    }

    /// Status plus the full response body, for the byte-identical deny comparison.
    async fn status_and_bytes(resp: axum::response::Response) -> (StatusCode, Vec<u8>) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, bytes)
    }

    /// The owner's claim is recorded with both DIDs and a server timestamp. The
    /// repo is seeded with the BARE owner key while the caller presents the full
    /// `did:key:` form, so the owner gate has to normalize (did_matches), not
    /// compare raw strings.
    #[sqlx::test]
    async fn owner_writes_a_claim_recording_both_dids(pool: PgPool) {
        let state = test_state(pool).await;
        let bare = OWNER.strip_prefix("did:key:").unwrap();
        let repo = seed_repo(bare, "status-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "status-repo", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].state, "success");
        assert_eq!(claims[0].context, "ci/build");
        assert_eq!(claims[0].producer_did, OWNER);
        assert_eq!(claims[0].authorizing_did, OWNER);
        assert!(
            chrono::DateTime::parse_from_rfc3339(&claims[0].created_at).is_ok(),
            "created_at must be a server-assigned rfc3339 timestamp, got {:?}",
            claims[0].created_at
        );
        assert!(claims[0].seq > 0, "seq is assigned by the database");
        // The verified RFC 9421 material is persisted with the row: a claim that
        // cannot be re-verified after the request is gone is not history.
        assert_eq!(claims[0].signature, "sig1=:dGVzdA==:");
        assert!(claims[0].signature_input.starts_with("sig1=("));
        assert_eq!(claims[0].signed_payload, b"\"@method\": POST");
    }

    /// Covers AE1. Two claims for one context both survive: the history is
    /// append-only and the later claim never overwrites the earlier row.
    #[sqlx::test]
    async fn ae1_pending_then_success_keeps_both_rows(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "history-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        for st in ["pending", "success"] {
            let resp = post_as(
                &state,
                OWNER,
                &uri(OWNER, "history-repo", SHA_A),
                body_of(st, "ci/build"),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
        }

        let claims = state.db.list_status_claims(&repo_id, SHA_A).await.unwrap();
        let states: Vec<&str> = claims.iter().map(|c| c.state.as_str()).collect();
        assert_eq!(
            states,
            vec!["pending", "success"],
            "both claims must remain, ordered by seq"
        );
    }

    /// Covers AE5. A signed non-owner writing to a repo it CAN read is refused
    /// with exactly 403 (existence is not secret on a public repo) and writes
    /// nothing.
    #[sqlx::test]
    async fn ae5_non_owner_on_public_repo_is_forbidden(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "public-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        let resp = post_as(
            &state,
            STRANGER,
            &uri(OWNER, "public-repo", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            state
                .db
                .list_status_claims(&repo_id, SHA_A)
                .await
                .unwrap()
                .is_empty(),
            "a refused write must leave no row"
        );
    }

    /// A non-owner writing to a private repo gets the response a MISSING repo
    /// returns, byte for byte. The same URI is driven twice — once before the
    /// repo exists, once after it is seeded private — so the two bodies are
    /// comparable and the deny cannot pass vacuously on an absent row.
    #[sqlx::test]
    async fn non_owner_on_private_repo_is_indistinguishable_from_missing(pool: PgPool) {
        let state = test_state(pool).await;
        let target = uri(OWNER, "hidden-repo", SHA_A);

        let missing = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
        let missing = status_and_bytes(missing).await;

        let repo = seed_repo(OWNER, "hidden-repo", false);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        let denied = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
        let denied = status_and_bytes(denied).await;

        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(
            denied, missing,
            "a private-repo deny must be byte-identical to the missing-repo response"
        );
        assert!(
            state
                .db
                .list_status_claims(&repo_id, SHA_A)
                .await
                .unwrap()
                .is_empty(),
            "a refused write must leave no row"
        );
    }

    /// A quarantined repo denies before the visibility gate, so even a PUBLIC
    /// quarantined repo answers with the missing-repo response. A plain repo load
    /// plus owner comparison would answer 403 here, which is what makes this the
    /// case that separates the two implementations.
    #[sqlx::test]
    async fn non_owner_on_quarantined_repo_is_indistinguishable_from_missing(pool: PgPool) {
        let state = test_state(pool).await;
        let target = uri(OWNER, "quarantined-repo", SHA_A);

        let missing = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
        let missing = status_and_bytes(missing).await;

        // Public on purpose: quarantine must deny independently of visibility.
        let repo = seed_repo(OWNER, "quarantined-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();
        state.db.set_repo_quarantine(&repo_id, true).await.unwrap();

        let denied = post_as(&state, STRANGER, &target, body_of("success", "ci/build")).await;
        let denied = status_and_bytes(denied).await;

        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(
            denied, missing,
            "a quarantined-repo deny must be byte-identical to the missing-repo response"
        );
        assert!(
            state
                .db
                .list_status_claims(&repo_id, SHA_A)
                .await
                .unwrap()
                .is_empty(),
            "a refused write must leave no row"
        );
    }

    /// Every malformed field is exactly 400 and writes nothing. The two SHA cases
    /// ride in the path, the rest in the body.
    #[sqlx::test]
    async fn malformed_claims_are_rejected_with_400(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "valid-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        let long_description = "d".repeat(1025);
        let cases: Vec<(&str, String, String)> = vec![
            (
                "state outside the four-value set",
                uri(OWNER, "valid-repo", SHA_A),
                r#"{"state":"passed","context":"ci"}"#.into(),
            ),
            (
                "sha of 39 characters",
                uri(OWNER, "valid-repo", &"1".repeat(39)),
                r#"{"state":"success","context":"ci"}"#.into(),
            ),
            (
                "sha with a non-hex character",
                uri(OWNER, "valid-repo", &format!("{}z", "1".repeat(39))),
                r#"{"state":"success","context":"ci"}"#.into(),
            ),
            (
                "empty context",
                uri(OWNER, "valid-repo", SHA_A),
                r#"{"state":"success","context":"   "}"#.into(),
            ),
            (
                "control characters in context",
                uri(OWNER, "valid-repo", SHA_A),
                r#"{"state":"success","context":"ci\u0007build"}"#.into(),
            ),
            (
                "oversized description",
                uri(OWNER, "valid-repo", SHA_A),
                format!(
                    r#"{{"state":"success","context":"ci","description":"{long_description}"}}"#
                ),
            ),
            (
                "javascript: target url",
                uri(OWNER, "valid-repo", SHA_A),
                r#"{"state":"success","context":"ci","target_url":"javascript:alert(1)"}"#.into(),
            ),
        ];

        for (label, target, body) in cases {
            let resp = post_as(&state, OWNER, &target, Body::from(body)).await;
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{label} must be rejected with 400"
            );
        }

        for sha in [SHA_A, &"1".repeat(39), &format!("{}z", "1".repeat(39))] {
            assert!(
                state
                    .db
                    .list_status_claims(&repo_id, sha)
                    .await
                    .unwrap()
                    .is_empty(),
                "a rejected claim must leave no row"
            );
        }
    }

    /// Seed one (repo, commit, producer, context) tuple to its cap; the next claim
    /// on that tuple is exactly 429, while a fresh context on the same commit
    /// still writes — proving the refusal came from the tuple cap and not from a
    /// broader bound.
    #[sqlx::test]
    async fn per_tuple_cap_refuses_the_next_claim(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "tuple-cap-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        seed_claims(
            &pool,
            &repo_id,
            SHA_A,
            OWNER,
            "ci/build",
            super::MAX_CLAIMS_PER_TUPLE,
        )
        .await;

        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "tuple-cap-repo", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "tuple-cap-repo", SHA_A),
            body_of("success", "ci/lint"),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a different context on the same commit is under its own tuple cap"
        );
    }

    /// Seed the per-(repo, commit) context limit under distinct contexts; a claim
    /// carrying a fresh context is exactly 429 even though its own tuple is empty.
    #[sqlx::test]
    async fn context_fanout_cap_refuses_a_fresh_context(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "context-cap-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        for i in 0..super::MAX_CONTEXTS_PER_COMMIT {
            seed_claims(&pool, &repo_id, SHA_A, OWNER, &format!("ci/{i}"), 1).await;
        }

        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "context-cap-repo", SHA_A),
            body_of("success", "ci/fresh"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "context-cap-repo", SHA_A),
            body_of("success", "ci/0"),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "a context already present does not widen the fanout, so it still writes"
        );
    }

    /// Seed the per-repo row limit across distinct well-formed SHAs; a claim
    /// against a fresh SHA is exactly 429, which is the bound the caller-chosen
    /// (never existence-checked) SHA would otherwise escape.
    #[sqlx::test]
    async fn repo_row_cap_refuses_a_fresh_sha(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "repo-cap-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        seed_claims_across_shas(&pool, &repo_id, OWNER, super::MAX_CLAIMS_PER_REPO).await;

        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "repo-cap-repo", SHA_B),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// A handler reached without the verified signature material writes NOTHING
    /// and answers 500. The material is a server-side invariant (`require_signature`
    /// always injects it), so its absence is a misconfiguration, not a client
    /// error — and a claim stored without it is unverifiable history, which the
    /// substrate cannot adopt. Failing open here would be silent: the row looks
    /// fine and nothing goes red.
    #[sqlx::test]
    async fn missing_signature_material_fails_closed(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "material-repo", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        // Deliberately NOT signed_with_material: only the identity is injected.
        let resp = router(state.clone())
            .oneshot(signed_request_as(
                OWNER,
                Method::POST,
                &uri(OWNER, "material-repo", SHA_A),
                body_of("success", "ci/build"),
            ))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            state
                .db
                .list_status_claims(&repo_id, SHA_A)
                .await
                .unwrap()
                .is_empty(),
            "an unverifiable claim must never be stored"
        );
    }

    /// The route is registered on the production router AND its group reached the
    /// merge chain: an unsigned request is refused by the signature layer with 401,
    /// which a path axum never learned about would answer 404 instead.
    #[sqlx::test]
    async fn route_is_registered_behind_the_signature_layer(pool: PgPool) {
        let state = test_state(pool).await;
        let router = crate::server::build_router(state);
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri(uri(OWNER, "any-repo", SHA_A))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(body_of("success", "ci/build"))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the status write route must exist and sit behind require_signature"
        );
    }

    // ── Read path (U4) ────────────────────────────────────────────────────

    const NEW_OWNER: &str = "did:key:zSTATUSNEWOWNERCCCCCCCCCCCCCCCCCCCCCC";

    fn read_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/commits/{sha}/status",
                axum::routing::get(super::commit_status),
            )
            .with_state(state)
    }

    fn status_uri(owner: &str, repo: &str, sha: &str) -> String {
        format!("/api/v1/repos/{owner}/{repo}/commits/{sha}/status")
    }

    /// GET the read surface as `did`, or anonymously when it is `None` (no
    /// `AuthenticatedDid` extension at all, which is what an unsigned caller
    /// looks like once `optional_signature` has passed it through).
    async fn get_status(
        state: &crate::state::AppState,
        did: Option<&str>,
        uri: &str,
    ) -> axum::response::Response {
        let req = match did {
            Some(d) => signed_request_as(d, Method::GET, uri, Body::empty()),
            None => axum::http::Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        };
        read_router(state.clone()).oneshot(req).await.unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).expect("response body must be json")
    }

    /// One claim row with every field chosen by the caller, including the
    /// authorizing DID and the display timestamp, so the projection's ordering
    /// key and its current-authorization filter can both be driven directly.
    #[allow(clippy::too_many_arguments)]
    async fn seed_claim(
        pool: &PgPool,
        id: &str,
        repo_id: &str,
        sha: &str,
        producer: &str,
        authorizing: &str,
        context: &str,
        claim_state: &str,
        created_at: &str,
    ) {
        sqlx::query(
            "INSERT INTO status_claims
             (id, repo_id, commit_sha, state, context, producer_did, authorizing_did,
              signature, signature_input, signed_payload, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'','',''::bytea,$8)",
        )
        .bind(id)
        .bind(repo_id)
        .bind(sha)
        .bind(claim_state)
        .bind(context)
        .bind(producer)
        .bind(authorizing)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("seed claim");
    }

    /// Covers AE1. A context reported pending then success reads as success with
    /// exactly one entry: the projection takes the LATEST claim per (producer,
    /// context), not every row in the history.
    #[sqlx::test]
    async fn ae1_latest_claim_per_context_reads_as_success(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "read-ae1", true);
        state.db.create_repo(&repo).await.unwrap();

        for st in ["pending", "success"] {
            let resp = post_as(
                &state,
                OWNER,
                &uri(OWNER, "read-ae1", SHA_A),
                body_of(st, "ci/build"),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
        }

        let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-ae1", SHA_A)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["state"], "success");
        assert_eq!(body["total_count"], 1);
        assert_eq!(body["statuses"].as_array().unwrap().len(), 1);
        assert_eq!(body["statuses"][0]["state"], "success");
        assert_eq!(body["statuses"][0]["context"], "ci/build");
        assert_eq!(body["statuses"][0]["producer_did"], OWNER);
        assert_eq!(
            body["reported_only"], true,
            "R19: the response marks that the state covers reported contexts only"
        );
    }

    /// The latest claim for a context is the highest server-assigned `seq`
    /// (KTD-3), never the newest timestamp and never the largest row id. The two
    /// rows are seeded so every other candidate key picks the LOSING row: the
    /// earlier claim carries a far-future `created_at` and a lexically larger
    /// uuid than the later one.
    #[sqlx::test]
    async fn latest_claim_is_highest_seq_not_newest_timestamp_or_id(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "read-order", true);
        state.db.create_repo(&repo).await.unwrap();

        seed_claim(
            &pool,
            "zzzzzzzz-0000-0000-0000-000000000001",
            &repo.id,
            SHA_A,
            OWNER,
            OWNER,
            "ci/build",
            "pending",
            "2099-01-01T00:00:00Z",
        )
        .await;
        seed_claim(
            &pool,
            "aaaaaaaa-0000-0000-0000-000000000002",
            &repo.id,
            SHA_A,
            OWNER,
            OWNER,
            "ci/build",
            "success",
            "2000-01-01T00:00:00Z",
        )
        .await;

        let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-order", SHA_A)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(
            body["state"], "success",
            "the highest-seq claim wins; ordering on created_at or on the row id \
             would elect the stale pending claim"
        );
        assert_eq!(body["total_count"], 1);
    }

    /// Covers AE2. Two producers, two contexts, one success and one failure: the
    /// combined state is failure and BOTH entries are present.
    #[sqlx::test]
    async fn ae2_two_producers_one_failure_reads_as_failure(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "read-ae2", true);
        state.db.create_repo(&repo).await.unwrap();

        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-ae2", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        // A second producer, authorized by the same owner key.
        seed_claim(
            &pool,
            "11111111-0000-0000-0000-000000000001",
            &repo.id,
            SHA_A,
            STRANGER,
            OWNER,
            "ci/test",
            "failure",
            "2026-01-01T00:00:00Z",
        )
        .await;

        let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-ae2", SHA_A)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["state"], "failure");
        assert_eq!(body["total_count"], 2);
        let contexts: Vec<&str> = body["statuses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["context"].as_str().unwrap())
            .collect();
        assert!(contexts.contains(&"ci/build"), "contexts: {contexts:?}");
        assert!(contexts.contains(&"ci/test"), "contexts: {contexts:?}");
    }

    /// An error-state claim folds to the combined failure state (the error arm of
    /// KTD-1, distinct from the failure arm the AE2 case covers).
    #[sqlx::test]
    async fn error_claim_folds_to_combined_failure(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "read-error", true);
        state.db.create_repo(&repo).await.unwrap();

        for (st, ctx) in [("success", "ci/build"), ("error", "ci/test")] {
            let resp = post_as(
                &state,
                OWNER,
                &uri(OWNER, "read-error", SHA_A),
                body_of(st, ctx),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
        }

        let body = body_json(
            get_status(&state, Some(OWNER), &status_uri(OWNER, "read-error", SHA_A)).await,
        )
        .await;
        assert_eq!(
            body["state"], "failure",
            "an error claim must fold to failure, never to success or pending"
        );
    }

    /// A pending claim alongside a success yields the combined pending state (the
    /// middle arm of KTD-1).
    #[sqlx::test]
    async fn pending_alongside_success_reads_as_pending(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "read-pending", true);
        state.db.create_repo(&repo).await.unwrap();

        for (st, ctx) in [("success", "ci/build"), ("pending", "ci/test")] {
            let resp = post_as(
                &state,
                OWNER,
                &uri(OWNER, "read-pending", SHA_A),
                body_of(st, ctx),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED, "{st} claim");
        }

        let body = body_json(
            get_status(
                &state,
                Some(OWNER),
                &status_uri(OWNER, "read-pending", SHA_A),
            )
            .await,
        )
        .await;
        assert_eq!(body["state"], "pending");
        assert_eq!(body["total_count"], 2);
    }

    /// Covers AE3. A commit nobody reported on is exactly 200 with the pending
    /// zero-count body. The WHOLE body is asserted, not just the status: a client
    /// that renders this must not be able to arrive at green through a missing
    /// field, an empty object, or a success state with an empty array.
    #[sqlx::test]
    async fn ae3_commit_with_no_claims_is_pending_zero(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "read-ae3", true);
        state.db.create_repo(&repo).await.unwrap();

        let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-ae3", SHA_A)).await;
        let (status, bytes) = status_and_bytes(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                r#"{{"state":"pending","sha":"{SHA_A}","total_count":0,"statuses":[],"reported_only":true}}"#
            ),
            "absence must serialize as the explicit pending zero-count body"
        );
    }

    /// Covers AE4. An anonymous read of a PRIVATE repo that HAS a claim answers
    /// byte for byte what the same caller gets for a repo that does not exist.
    /// The claim is seeded first, so the deny cannot pass vacuously on an empty
    /// projection.
    #[sqlx::test]
    async fn ae4_anon_private_repo_read_is_indistinguishable_from_missing(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let target = status_uri(OWNER, "read-ae4", SHA_A);

        let missing = status_and_bytes(get_status(&state, None, &target).await).await;

        let repo = seed_repo(OWNER, "read-ae4", false);
        state.db.create_repo(&repo).await.unwrap();
        seed_claim(
            &pool,
            "22222222-0000-0000-0000-000000000001",
            &repo.id,
            SHA_A,
            OWNER,
            OWNER,
            "ci/build",
            "success",
            "2026-01-01T00:00:00Z",
        )
        .await;

        let denied = status_and_bytes(get_status(&state, None, &target).await).await;

        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(
            denied, missing,
            "a private-repo deny must be byte-identical to the missing-repo response"
        );
        assert!(
            !String::from_utf8_lossy(&denied.1).contains("ci/build"),
            "the deny must carry no trace of the claim"
        );
    }

    /// The other half of the visibility pair: a PUBLIC repo's status is served to
    /// an anonymous caller, so the gate above is a gate and not a blanket refusal.
    #[sqlx::test]
    async fn public_repo_status_served_to_anon(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "read-public", true);
        state.db.create_repo(&repo).await.unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-public", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = get_status(&state, None, &status_uri(OWNER, "read-public", SHA_A)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["state"], "success");
        assert_eq!(body["statuses"][0]["context"], "ci/build");
    }

    /// KTD-2 regression: the projection is computed per read, so tightening
    /// visibility AFTER a claim was written retroactively hides it. A write-time
    /// gated derived index kept serving a repo made private afterwards
    /// (docs/solutions/security-issues/write-time-visibility-gate-leaves-derived-index-stale.md);
    /// this is that shape on the status surface.
    #[sqlx::test]
    async fn tightening_visibility_hides_existing_claims_from_anon(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "read-tighten", true);
        state.db.create_repo(&repo).await.unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-tighten", SHA_A),
            body_of("success", "ci/secret-build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let target = status_uri(OWNER, "read-tighten", SHA_A);
        let served = get_status(&state, None, &target).await;
        assert_eq!(
            served.status(),
            StatusCode::OK,
            "the claim is anonymously readable while the repo is public"
        );

        // Tighten: a root rule with an empty reader list denies everyone but the
        // owner, even though the repo row is still is_public.
        state
            .db
            .set_visibility_rule(&repo.id, "/", crate::db::VisibilityMode::B, &[], OWNER)
            .await
            .unwrap();

        let (status, bytes) = status_and_bytes(get_status(&state, None, &target).await).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a claim written while public must stop being served once visibility tightens"
        );
        assert!(
            !String::from_utf8_lossy(&bytes).contains("ci/secret-build"),
            "the deny must carry no trace of the claim"
        );
    }

    /// KTD-5: the projection filters on CURRENT authorization. After the repo
    /// changes hands, the previous owner's claims drop out of the read, while the
    /// append-only history keeps every row.
    #[sqlx::test]
    async fn claims_authorized_by_a_former_owner_leave_the_projection(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "read-transfer", true);
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-transfer", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        sqlx::query("UPDATE repos SET owner_did = $1 WHERE id = $2")
            .bind(NEW_OWNER)
            .bind(&repo_id)
            .execute(&pool)
            .await
            .expect("transfer the repo");

        let resp = get_status(
            &state,
            Some(NEW_OWNER),
            &status_uri(NEW_OWNER, "read-transfer", SHA_A),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(
            body["state"], "pending",
            "a claim the current owner never authorized must not decide the state"
        );
        assert_eq!(body["total_count"], 0);
        assert!(body["statuses"].as_array().unwrap().is_empty());

        assert_eq!(
            state
                .db
                .list_status_claims(&repo_id, SHA_A)
                .await
                .unwrap()
                .len(),
            1,
            "the history row survives the transfer; only the projection drops it"
        );
    }

    /// The current-authorization filter accepts the owner DID in either
    /// representation, matching `did_matches`: a repo whose stored owner is the
    /// BARE key still projects claims authorized under the full `did:key:` form.
    #[sqlx::test]
    async fn projection_matches_the_owner_in_either_did_form(pool: PgPool) {
        let state = test_state(pool).await;
        let bare = OWNER.strip_prefix("did:key:").unwrap();
        let repo = seed_repo(bare, "read-didform", true);
        state.db.create_repo(&repo).await.unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-didform", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body = body_json(
            get_status(
                &state,
                Some(OWNER),
                &status_uri(OWNER, "read-didform", SHA_A),
            )
            .await,
        )
        .await;
        assert_eq!(body["state"], "success");
        assert_eq!(body["total_count"], 1);
    }

    /// The lookup-failure path. With the claims table gone, the read is exactly
    /// 500 carrying the stable `db_error` code — never a 200, and never an empty
    /// statuses array. The message is the sqlx text and is not asserted; a
    /// connectivity failure would take the separate 503 arm instead.
    #[sqlx::test]
    async fn claim_lookup_failure_is_500_never_empty_success(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "read-dberr", true);
        state.db.create_repo(&repo).await.unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "read-dberr", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        sqlx::query("DROP TABLE status_claims")
            .execute(&pool)
            .await
            .expect("drop the claims table");

        let resp = get_status(&state, Some(OWNER), &status_uri(OWNER, "read-dberr", SHA_A)).await;
        let (status, bytes) = status_and_bytes(resp).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a failed projection query must not render as a served status"
        );
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "db_error");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("statuses"),
            "an error must not carry an empty statuses array: {text}"
        );
    }

    /// The read route is registered on the production router AND its group kept
    /// the `optional_signature` layer. A path axum never learned about answers
    /// 404 for the anonymous case; a group missing the layer would ignore the
    /// signature headers in the second case and serve 200 instead of 401.
    #[sqlx::test]
    async fn read_route_is_registered_with_optional_signature(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "read-wired", true);
        state.db.create_repo(&repo).await.unwrap();
        let target = status_uri(OWNER, "read-wired", SHA_A);

        let resp = crate::server::build_router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(&target)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the read route must exist on the production router and serve a public repo to anon"
        );

        let resp = crate::server::build_router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(&target)
                    .header("signature", "sig1=:bm90YXNpZw==:")
                    .header("signature-input", "sig1=(\"@method\");alg=\"ed25519\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, bytes) = status_and_bytes(resp).await;
        // A presented signature is verified, and this one is unusable (no keyid,
        // required components missing), so the signature layer refuses it. Only
        // the layer can produce this: the same request against a group without it
        // is treated as anonymous and served 200 by the handler above.
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a presented signature must be verified, which only happens if the \
             read group still carries optional_signature"
        );
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["error"], "invalid_signature",
            "the refusal must come from the signature layer, not the handler"
        );
    }

    /// The set the projection filters on reproduces `did_matches` exactly, in both
    /// directions and across the cross-method cases: the filter has to live inside
    /// the query, so it cannot call the helper itself.
    #[test]
    fn authorizing_variants_agree_with_did_matches() {
        let cases = [
            ("did:key:zABC", "did:key:zABC"),
            ("did:key:zABC", "zABC"),
            ("zABC", "did:key:zABC"),
            ("zABC", "zABC"),
            ("did:key:zABC", "did:key:zXYZ"),
            ("did:key:zABC", "did:gitlawb:zABC"),
            ("did:gitlawb:zABC", "did:key:zABC"),
            ("did:web:example.com", "did:web:example.com"),
            ("did:web:example.com", "example.com"),
            ("", ""),
        ];
        for (owner, candidate) in cases {
            let in_set = super::authorizing_did_variants(owner)
                .iter()
                .any(|v| v == candidate);
            assert_eq!(
                in_set,
                crate::api::did_matches(candidate, owner),
                "variant set for owner {owner:?} disagrees with did_matches on {candidate:?}"
            );
        }
    }

    /// `n` claims on one (repo, commit, producer, context) tuple, inserted in one
    /// statement so the cap tests stay fast.
    async fn seed_claims(
        pool: &PgPool,
        repo_id: &str,
        sha: &str,
        producer: &str,
        context: &str,
        n: i64,
    ) {
        sqlx::query(
            "INSERT INTO status_claims
             (id, repo_id, commit_sha, state, context, producer_did, authorizing_did,
              signature, signature_input, signed_payload, created_at)
             SELECT md5(random()::text || g::text), $1, $2, 'success', $3, $4, $4,
                    '', '', ''::bytea, '2026-01-01T00:00:00Z'
             FROM generate_series(1, $5) g",
        )
        .bind(repo_id)
        .bind(sha)
        .bind(context)
        .bind(producer)
        .bind(n)
        .execute(pool)
        .await
        .expect("seed claims");
    }

    /// `n` claims on one repo spread across `n` distinct 40-hex SHAs, one claim
    /// each, so no tuple or context cap is reached before the per-repo one.
    async fn seed_claims_across_shas(pool: &PgPool, repo_id: &str, producer: &str, n: i64) {
        sqlx::query(
            "INSERT INTO status_claims
             (id, repo_id, commit_sha, state, context, producer_did, authorizing_did,
              signature, signature_input, signed_payload, created_at)
             SELECT md5(random()::text || g::text), $1,
                    substr(md5(g::text) || md5((g + 1)::text), 1, 40),
                    'success', 'ci/build', $2, $2,
                    '', '', ''::bytea, '2026-01-01T00:00:00Z'
             FROM generate_series(1, $3) g",
        )
        .bind(repo_id)
        .bind(producer)
        .bind(n)
        .execute(pool)
        .await
        .expect("seed claims across shas");
    }

    // ── Pull request rollup (U5) ──────────────────────────────────────────

    fn rollup_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/pulls/{number}/status",
                axum::routing::get(super::pull_request_status),
            )
            .with_state(state)
    }

    fn rollup_uri(owner: &str, repo: &str, number: i64) -> String {
        format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/status")
    }

    async fn get_rollup(
        state: &crate::state::AppState,
        did: Option<&str>,
        uri: &str,
    ) -> axum::response::Response {
        let req = match did {
            Some(d) => signed_request_as(d, Method::GET, uri, Body::empty()),
            None => axum::http::Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        };
        rollup_router(state.clone()).oneshot(req).await.unwrap()
    }

    fn seed_pr(repo_id: &str, number: i64, source_branch: &str) -> crate::db::PullRequest {
        let now = chrono::Utc::now().to_rfc3339();
        crate::db::PullRequest {
            id: uuid::Uuid::new_v4().to_string(),
            repo_id: repo_id.to_string(),
            number,
            title: format!("PR {number}"),
            body: None,
            author_did: OWNER.to_string(),
            source_branch: source_branch.to_string(),
            target_branch: "main".to_string(),
            status: "open".to_string(),
            merged_by_did: None,
            merged_at: None,
            head_commit: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Point a branch at a SHA the way the receive-pack path does: one
    /// `repo_push_events` row, which is what the rollup's fallback resolves
    /// through. Each call takes a strictly later timestamp than the last, so a
    /// second call to the same branch reads as a later push rather than tying
    /// with the first.
    async fn seed_branch_head(
        state: &crate::state::AppState,
        repo: &RepoRecord,
        branch: &str,
        sha: &str,
    ) {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let created_at = format!("2026-01-01T00:00:00.{n:06}Z");
        seed_push_event(state, repo, branch, sha, &created_at).await;
    }

    /// One `repo_push_events` row, exactly the shape `record_push_events` writes
    /// on the receive-pack path: a FULL ref name and the post-push SHA. The
    /// timestamp is explicit because the fallback picks the most recent row for
    /// the ref and `created_at` is the ordering key; letting two seeds share a
    /// wall clock would leave which one wins to the uuid tiebreak.
    async fn seed_push_event(
        state: &crate::state::AppState,
        repo: &RepoRecord,
        branch: &str,
        sha: &str,
        created_at: &str,
    ) {
        state
            .db
            .insert_repo_push_event(&crate::db::RepoPushEvent {
                id: uuid::Uuid::new_v4().to_string(),
                repo_id: repo.id.clone(),
                ref_name: format!("refs/heads/{branch}"),
                after_sha: sha.to_string(),
                created_at: created_at.to_string(),
            })
            .await
            .expect("seed push event");
    }

    const PUSH_T1: &str = "2026-01-01T00:00:00.000000Z";
    const PUSH_T2: &str = "2026-01-02T00:00:00.000000Z";

    /// Serializes the tests that read [`super::BRANCH_RESOLVES`] and zeroes it, so
    /// the counter measures one test's requests rather than whatever else the
    /// harness is running in the same process. Held for the test's lifetime.
    ///
    /// Every test that TRIGGERS a resolve takes it too, not only the ones that
    /// read the count. The counter is process-global while the databases are
    /// per-test, so an unguarded resolver running concurrently inflates a
    /// guarded test's count and the failure looks like a bug in the fallback.
    /// Async-aware on purpose: the guard is held across the test's awaits, which a
    /// blocking `std` mutex must not be.
    async fn resolve_count_guard() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let guard = LOCK.lock().await;
        super::BRANCH_RESOLVES.store(0, std::sync::atomic::Ordering::SeqCst);
        guard
    }

    fn resolve_count() -> usize {
        super::BRANCH_RESOLVES.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The four wire states (KTD-1). The rollup never adds a fifth value, whatever
    /// happened to the head.
    fn assert_wire_state(body: &serde_json::Value) {
        let state = body["state"].as_str().expect("state must be a string");
        assert!(
            ["error", "failure", "pending", "success"].contains(&state),
            "rollup state {state:?} is outside the four-value wire set"
        );
    }

    /// R3/R11: the rollup is the SAME projection as the commit read. Asserted by
    /// comparing the two responses on the head SHA, so the two surfaces cannot
    /// drift into two answers.
    #[sqlx::test]
    async fn rollup_matches_the_commit_read_for_the_stored_head(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-same", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        state
            .db
            .set_open_pr_heads(&repo.id, "feature", SHA_A)
            .await
            .unwrap();

        for (st, ctx) in [("success", "ci/build"), ("pending", "ci/test")] {
            let resp = post_as(
                &state,
                OWNER,
                &uri(OWNER, "rollup-same", SHA_A),
                body_of(st, ctx),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let commit =
            body_json(get_status(&state, None, &status_uri(OWNER, "rollup-same", SHA_A)).await)
                .await;
        let rollup =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-same", 1)).await).await;

        assert_eq!(rollup["sha"], SHA_A);
        assert_eq!(rollup["head_resolved"], true);
        assert_eq!(rollup["pull_request_state"], "open");
        assert_eq!(rollup["reported_only"], true);
        assert_eq!(rollup["state"], commit["state"]);
        assert_eq!(rollup["total_count"], commit["total_count"]);
        assert_eq!(
            rollup["statuses"], commit["statuses"],
            "the rollup must serve the commit read's projection unchanged"
        );
    }

    /// Covers AE2 (rollup half). Two contexts on the head, one failing: the
    /// rollup must not read as success.
    #[sqlx::test]
    async fn ae2_rollup_with_a_failing_context_does_not_read_as_success(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-ae2", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        state
            .db
            .set_open_pr_heads(&repo.id, "feature", SHA_A)
            .await
            .unwrap();

        for (st, ctx) in [("success", "ci/build"), ("failure", "ci/test")] {
            let resp = post_as(
                &state,
                OWNER,
                &uri(OWNER, "rollup-ae2", SHA_A),
                body_of(st, ctx),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-ae2", 1)).await).await;
        assert_eq!(body["state"], "failure");
        assert_ne!(body["state"], "success");
        assert_eq!(body["total_count"], 2);
    }

    /// R12's first arm: a resolved head with nothing reported is pending-zero with
    /// `head_resolved` TRUE. Pairs with the unresolvable case below, which differs
    /// on that boolean alone.
    #[sqlx::test]
    async fn resolved_head_with_no_claims_is_pending_zero_and_head_resolved(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-silent", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        state
            .db
            .set_open_pr_heads(&repo.id, "feature", SHA_A)
            .await
            .unwrap();

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-silent", 1)).await).await;
        assert_wire_state(&body);
        assert_eq!(body["state"], "pending");
        assert_eq!(body["total_count"], 0);
        assert_eq!(body["statuses"].as_array().unwrap().len(), 0);
        assert_eq!(body["head_resolved"], true);
        assert_eq!(body["sha"], SHA_A);
    }

    /// R17: an open pull request whose source branch is gone has no resolvable
    /// head. The answer is pending with zero contexts and `head_resolved` FALSE,
    /// which is the ONLY field separating it from the reported-nothing case above.
    #[sqlx::test]
    async fn unresolvable_head_differs_from_silent_head_on_head_resolved_alone(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-gone", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "deleted-branch");
        state.db.create_pr(&pr).await.unwrap();

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-gone", 1)).await).await;
        assert_wire_state(&body);
        assert_eq!(body["state"], "pending");
        assert_eq!(body["total_count"], 0);
        assert_eq!(body["statuses"].as_array().unwrap().len(), 0);
        assert_eq!(
            body["head_resolved"], false,
            "an unresolvable head must report head_resolved false, which is the \
             only field separating it from a resolved head nobody reported on"
        );
        assert!(
            body["sha"].is_null(),
            "an unresolved head must carry no target sha, got {:?}",
            body["sha"]
        );
        assert_eq!(body["pull_request_state"], "open");
        // Nothing was resolvable, so nothing was persisted either.
        assert_eq!(
            state
                .db
                .get_pr(&repo.id, 1)
                .await
                .unwrap()
                .unwrap()
                .head_commit,
            None
        );
    }

    /// R17's closed arm: a closed pull request with no stored head answers
    /// unresolved and does NOT fall back to the branch, even when the branch still
    /// has a head. Resolving there would hand a reader a commit the pull request
    /// was never decided against.
    #[sqlx::test]
    async fn closed_pr_with_no_stored_head_does_not_resolve_the_branch(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-closed", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        state.db.close_pr(&pr.id).await.unwrap();
        // The branch is alive and would resolve if the fallback ran.
        seed_branch_head(&state, &repo, "feature", SHA_B).await;

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-closed", 1)).await).await;
        assert_wire_state(&body);
        assert_eq!(body["pull_request_state"], "closed");
        assert_eq!(
            body["head_resolved"], false,
            "a closed pull request with no stored head is unresolved, not back-filled"
        );
        assert!(body["sha"].is_null(), "no branch resolve on a closed PR");
        assert_eq!(body["total_count"], 0);
        assert_eq!(
            state
                .db
                .get_pr(&repo.id, 1)
                .await
                .unwrap()
                .unwrap()
                .head_commit,
            None,
            "a closed PR's head must not be back-filled from the live branch"
        );
        assert_eq!(
            resolve_count(),
            0,
            "a closed pull request must not trigger a branch resolve at all"
        );
    }

    /// R17's merged arm: the stored head is frozen at merge and its claims are
    /// still served, with the pull request state named.
    #[sqlx::test]
    async fn merged_pr_serves_its_frozen_head(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-merged", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "rollup-merged", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        state.db.merge_pr(&pr.id, OWNER, Some(SHA_A)).await.unwrap();
        // The branch moved on after the merge; the frozen head must win.
        seed_branch_head(&state, &repo, "feature", SHA_B).await;

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-merged", 1)).await).await;
        assert_eq!(body["pull_request_state"], "merged");
        assert_eq!(body["head_resolved"], true);
        assert_eq!(body["sha"], SHA_A);
        assert_eq!(body["state"], "success");
        assert_eq!(body["total_count"], 1);
    }

    /// The force-push flow: a re-pointed head is a fresh target, so the rollup
    /// goes back to pending-zero until something reports on the new SHA. A rollup
    /// keyed to the OLD sha would keep showing a green that describes code nobody
    /// is looking at any more.
    #[sqlx::test]
    async fn moving_the_stored_head_repoints_the_rollup(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-force", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        state
            .db
            .set_open_pr_heads(&repo.id, "feature", SHA_A)
            .await
            .unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "rollup-force", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let before =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-force", 1)).await).await;
        assert_eq!(before["state"], "success");

        state
            .db
            .set_open_pr_heads(&repo.id, "feature", SHA_B)
            .await
            .unwrap();

        let after =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-force", 1)).await).await;
        assert_eq!(after["sha"], SHA_B);
        assert_eq!(after["state"], "pending");
        assert_eq!(after["total_count"], 0);
    }

    /// The open-PR fallback: no stored head, a live source branch, so the branch
    /// head is resolved from the database, served, AND persisted as the stored
    /// head for the next read.
    #[sqlx::test]
    async fn open_pr_without_a_stored_head_resolves_and_persists_the_branch_head(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-fallback", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        seed_branch_head(&state, &repo, "feature", SHA_A).await;

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-fallback", 1)).await)
                .await;
        assert_eq!(body["head_resolved"], true);
        assert_eq!(body["sha"], SHA_A);
        assert_eq!(body["state"], "pending");
        assert_eq!(
            state
                .db
                .get_pr(&repo.id, 1)
                .await
                .unwrap()
                .unwrap()
                .head_commit,
            Some(SHA_A.to_string()),
            "the resolved head must be persisted as the stored head"
        );
    }

    /// The fallback must resolve on a node with no object-storage pinning at all.
    ///
    /// `branch_cids` has exactly one production writer, and it only fires for a
    /// ref whose objects came back with a pin CID, so on a node with no Pinata JWT
    /// the table stays empty forever. `repo_push_events` is written unconditionally
    /// for every ref update on the receive-pack path, which is why it is the
    /// fallback's source. Nothing here seeds `branch_cids`: if the resolve still
    /// went through it, this open pull request would answer `head_resolved: false`
    /// permanently.
    #[sqlx::test]
    async fn fallback_resolves_from_push_events_with_no_pin_recorded(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "rollup-nopin", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        seed_push_event(&state, &repo, "feature", SHA_A, PUSH_T1).await;

        let pinned: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM branch_cids")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(pinned, 0, "the unpinned node premise must hold");

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-nopin", 1)).await).await;
        assert_eq!(
            body["head_resolved"], true,
            "a pushed branch must resolve on a node that pins nothing"
        );
        assert_eq!(body["sha"], SHA_A);
        assert_eq!(
            state
                .db
                .get_pr(&repo.id, 1)
                .await
                .unwrap()
                .unwrap()
                .head_commit,
            Some(SHA_A.to_string()),
            "the resolved head must still be persisted"
        );
    }

    /// The fallback takes the LATEST push for the branch, not any push, and it
    /// takes it for the right ref: a tag sharing the branch's name and a push to a
    /// different branch are both seeded ahead of the real one, so a query missing
    /// either predicate returns the wrong SHA rather than passing vacuously.
    #[sqlx::test]
    async fn fallback_takes_the_latest_push_for_that_exact_branch(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-latest", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();

        seed_push_event(&state, &repo, "feature", SHA_A, PUSH_T1).await;
        seed_push_event(&state, &repo, "other", SHA_C, PUSH_T2).await;
        // A tag named like the branch, written the way the push path would.
        state
            .db
            .insert_repo_push_event(&crate::db::RepoPushEvent {
                id: uuid::Uuid::new_v4().to_string(),
                repo_id: repo.id.clone(),
                ref_name: "refs/tags/feature".to_string(),
                after_sha: SHA_C.to_string(),
                created_at: PUSH_T2.to_string(),
            })
            .await
            .unwrap();
        seed_push_event(&state, &repo, "feature", SHA_B, PUSH_T2).await;

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-latest", 1)).await).await;
        assert_eq!(
            body["sha"], SHA_B,
            "the newest push to refs/heads/feature is the head"
        );
    }

    /// A push recorded for a DIFFERENT repository must never resolve this one's
    /// branch. Same branch name, same timestamp, no row for this repo.
    #[sqlx::test]
    async fn fallback_does_not_cross_repositories(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let mine = seed_repo(OWNER, "rollup-mine", true);
        let theirs = seed_repo(OWNER, "rollup-theirs", true);
        state.db.create_repo(&mine).await.unwrap();
        state.db.create_repo(&theirs).await.unwrap();
        let pr = seed_pr(&mine.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        seed_push_event(&state, &theirs, "feature", SHA_A, PUSH_T1).await;

        let body =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-mine", 1)).await).await;
        assert_eq!(
            body["head_resolved"], false,
            "another repository's push must not resolve this pull request's head"
        );
    }

    /// The comment on `rollup_head` claims the PERSIST is once-per-pull-request,
    /// not the resolve. This is what keeps that claim honest: an open pull request
    /// whose branch never resolves runs the lookup again on every read, forever,
    /// because there is nothing to store and therefore nothing to short-circuit on.
    #[sqlx::test]
    async fn an_unresolvable_head_re_runs_the_resolve_on_every_read(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-retry", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "never-pushed");
        state.db.create_pr(&pr).await.unwrap();

        let first =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-retry", 1)).await).await;
        assert_eq!(first["head_resolved"], false);
        assert_eq!(resolve_count(), 1, "the first read attempts the resolve");

        let second =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-retry", 1)).await).await;
        assert_eq!(second["head_resolved"], false);
        assert_eq!(
            resolve_count(),
            2,
            "with nothing stored there is nothing to short-circuit on, so the \
             second read attempts the resolve again"
        );
    }

    /// The fallback writes on an UNAUTHENTICATED read, so it has to be
    /// self-limiting: it fires only while `head_commit` is absent, and it sets it.
    ///
    /// Proven two ways, because the output alone would not show it. The response
    /// says the second read returned the STORED sha after the branch moved
    /// underneath it, which it could not do if it had re-resolved; and the resolve
    /// counter says the branch lookup RAN once across two reads, which is the
    /// work-done bound rather than the results-emitted one — a fallback that
    /// re-read the branch on every call and then discarded the answer would leave
    /// the response identical and the cost doubled.
    #[sqlx::test]
    async fn head_fallback_resolves_once_and_later_reads_use_the_stored_head(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-once", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        seed_branch_head(&state, &repo, "feature", SHA_A).await;

        let first =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-once", 1)).await).await;
        assert_eq!(first["sha"], SHA_A, "the first read resolves the branch");
        assert_eq!(
            resolve_count(),
            1,
            "the first read must perform exactly one branch-head lookup"
        );
        assert_eq!(
            state
                .db
                .get_pr(&repo.id, 1)
                .await
                .unwrap()
                .unwrap()
                .head_commit,
            Some(SHA_A.to_string()),
            "the first read persists what it resolved"
        );

        // Move the branch WITHOUT going through the push path, so nothing updates
        // the stored head. A second read that resolved again would return SHA_B.
        seed_branch_head(&state, &repo, "feature", SHA_B).await;

        let second =
            body_json(get_rollup(&state, None, &rollup_uri(OWNER, "rollup-once", 1)).await).await;
        assert_eq!(
            second["sha"], SHA_A,
            "the second read must be served from the stored head, not a fresh branch resolve"
        );
        assert_eq!(
            state
                .db
                .get_pr(&repo.id, 1)
                .await
                .unwrap()
                .unwrap()
                .head_commit,
            Some(SHA_A.to_string()),
            "the stored head must not be rewritten by a later read"
        );
        assert_eq!(
            resolve_count(),
            1,
            "the branch resolve must not run again once a head is stored"
        );
    }

    /// The write-back is a cache fill, so its failure must not destroy an answer
    /// the read already has. The head is resolved BEFORE the persist is attempted,
    /// and the persist is the only thing that fails here.
    ///
    /// The failure is induced with a CHECK constraint that rejects any non-null
    /// `head_commit`: the UPDATE errors while every read in the request path
    /// (`repos`, `pull_requests`, `repo_push_events`) still works, which is what
    /// isolates the write. Dropping a table would take the read down with it and
    /// the test would pass for the wrong reason.
    #[sqlx::test]
    async fn a_failed_head_write_back_still_serves_the_resolved_head(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool.clone()).await;
        let repo = seed_repo(OWNER, "rollup-wbfail", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        seed_push_event(&state, &repo, "feature", SHA_A, PUSH_T1).await;

        sqlx::query(
            "ALTER TABLE pull_requests
             ADD CONSTRAINT no_head_commit_writes CHECK (head_commit IS NULL)",
        )
        .execute(&pool)
        .await
        .expect("install the write-blocking constraint");
        // The premise: this exact call is the one the rollup makes, and it errors.
        state
            .db
            .set_pr_head_if_absent(&pr.id, SHA_A)
            .await
            .expect_err("the persist must fail for this test to mean anything");

        let resp = get_rollup(&state, None, &rollup_uri(OWNER, "rollup-wbfail", 1)).await;
        let (status, bytes) = status_and_bytes(resp).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a failed best-effort cache fill must not turn a resolved read into an \
             error: {}",
            String::from_utf8_lossy(&bytes)
        );
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["head_resolved"], true);
        assert_eq!(body["sha"], SHA_A);
        assert_eq!(body["state"], "pending");
        assert_eq!(
            resolve_count(),
            1,
            "the read resolved the branch itself rather than reading a stored head"
        );
        assert_eq!(
            state
                .db
                .get_pr(&repo.id, 1)
                .await
                .unwrap()
                .unwrap()
                .head_commit,
            None,
            "nothing was persisted, which is the point: the answer was served anyway"
        );
    }

    /// The rollup's deny is the repo's own not-found, byte for byte what a caller
    /// gets for a repo that does not exist. The pull request and its claims are
    /// seeded first, so the deny cannot pass vacuously.
    #[sqlx::test]
    async fn anon_rollup_on_private_repo_is_indistinguishable_from_missing(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let target = rollup_uri(OWNER, "rollup-private", 1);

        let missing = status_and_bytes(get_rollup(&state, None, &target).await).await;

        let repo = seed_repo(OWNER, "rollup-private", false);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        state
            .db
            .set_open_pr_heads(&repo.id, "feature", SHA_A)
            .await
            .unwrap();
        seed_claim(
            &pool,
            "33333333-0000-0000-0000-000000000001",
            &repo.id,
            SHA_A,
            OWNER,
            OWNER,
            "ci/build",
            "success",
            "2026-01-01T00:00:00Z",
        )
        .await;

        let denied = status_and_bytes(get_rollup(&state, None, &target).await).await;

        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(
            denied, missing,
            "a private-repo deny must be byte-identical to the missing-repo response"
        );
        assert!(
            !String::from_utf8_lossy(&denied.1).contains("ci/build"),
            "the deny must carry no trace of the claim"
        );
    }

    /// A pull request number that does not exist on a repo the caller CAN read is
    /// the plain not-found: existence is not secret once the read gate passed.
    #[sqlx::test]
    async fn unknown_pr_number_on_a_visible_repo_is_404(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-missing-pr", true);
        state.db.create_repo(&repo).await.unwrap();

        let resp = get_rollup(&state, None, &rollup_uri(OWNER, "rollup-missing-pr", 99)).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// R18's endpoint boundary: the rollup lives ONLY on the per-pull-request
    /// endpoint. The list response must gain no rollup field and do no status
    /// work, or one list call becomes N projections.
    ///
    /// Asserted on the ABSENCE of the named rollup fields, never on the full field
    /// set: `head_commit` already surfaces on this response through the pull
    /// request's own Serialize, and `status` is the pull request's own open/closed
    /// state, so neither is evidence either way.
    #[sqlx::test]
    async fn pr_list_response_carries_no_rollup_fields(pool: PgPool) {
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-boundary", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        state
            .db
            .set_open_pr_heads(&repo.id, "feature", SHA_A)
            .await
            .unwrap();
        let resp = post_as(
            &state,
            OWNER,
            &uri(OWNER, "rollup-boundary", SHA_A),
            body_of("success", "ci/build"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let router = Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/pulls",
                axum::routing::get(crate::api::pulls::list_prs),
            )
            .with_state(state.clone());
        let resp = router
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/repos/{OWNER}/rollup-boundary/pulls"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let entry = &body["pulls"][0];
        assert_eq!(
            entry["number"], 1,
            "the list must still serve the pull request"
        );
        for field in [
            "combined_state",
            "head_resolved",
            "reported_only",
            "rollup",
            "statuses",
            "total_count",
        ] {
            assert!(
                entry.get(field).is_none(),
                "the pull request list response must not carry `{field}`"
            );
            assert!(
                body.get(field).is_none(),
                "the pull request list envelope must not carry `{field}`"
            );
        }
    }

    /// R18's cost bound, by source read: no path in this module acquires the
    /// repository. `repo_store.acquire` downloads the whole repository from object
    /// storage on a cold node, and this read group carries no rate limiter, so an
    /// anonymous caller could drive repeated downloads. The ref helper that needs
    /// an acquired path is named here too, since reaching for it is how the
    /// acquire gets reintroduced.
    #[test]
    fn status_module_never_acquires_the_repo_or_lists_refs_from_disk() {
        let src = include_str!("status.rs");
        // Split on the tests module itself, not on any `#[cfg(test)]` attribute:
        // the production half carries test-only instrumentation of its own, and
        // stopping at the first attribute would leave most of the module unscanned.
        let (body_of_module, rest) = src
            .split_once("\n#[cfg(test)]\nmod tests {")
            .expect("module has a tests module");
        assert!(
            !rest.is_empty() && body_of_module.contains("pull_request_status"),
            "the scan must cover the whole production half of the module"
        );
        for banned in ["repo_store.acquire", "store::list_refs"] {
            assert!(
                !body_of_module.contains(banned),
                "the status module must not call `{banned}` — the rollup's branch \
                 resolve is a database read, not a repository acquire"
            );
        }
        assert!(
            body_of_module.contains("latest_push_sha_for_ref("),
            "the fallback's branch lookup must be the database-backed \
             latest_push_sha_for_ref over repo_push_events"
        );
        assert!(
            !body_of_module.contains("list_branch_cids("),
            "the fallback must not read branch_cids — that table has one writer \
             and it only fires when the pushed objects came back with a pin CID, \
             so on a node with no pinning configured it is never written"
        );
    }

    /// The rollup route exists on the production router and its group kept
    /// `optional_signature`: a group that is never merged is not a route, and a
    /// group without the layer reads every caller as anonymous.
    #[sqlx::test]
    async fn rollup_route_is_registered_with_optional_signature(pool: PgPool) {
        let _counting = resolve_count_guard().await;
        let state = test_state(pool).await;
        let repo = seed_repo(OWNER, "rollup-wired", true);
        state.db.create_repo(&repo).await.unwrap();
        let pr = seed_pr(&repo.id, 1, "feature");
        state.db.create_pr(&pr).await.unwrap();
        let target = rollup_uri(OWNER, "rollup-wired", 1);

        let resp = crate::server::build_router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(&target)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the rollup route must exist on the production router and serve a public repo to anon"
        );

        let resp = crate::server::build_router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method(Method::GET)
                    .uri(&target)
                    .header("signature", "sig1=:bm90YXNpZw==:")
                    .header("signature-input", "sig1=(\"@method\");alg=\"ed25519\"")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, bytes) = status_and_bytes(resp).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a presented signature must be verified, which only happens if the \
             rollup's group still carries optional_signature"
        );
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "invalid_signature");
    }
}
