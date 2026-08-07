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
    // KTD-5: current authorization, not write-time authorization. An ownership
    // transfer drops the prior owner's claims from the projection while the
    // append-only history keeps them.
    let authorizing = authorizing_did_variants(&record.owner_did);
    let claims = state
        .db
        .latest_status_claims(&record.id, &commit_sha, &authorizing)
        .await?;

    let statuses: Vec<StatusEntry> = claims
        .into_iter()
        .map(|c| StatusEntry {
            state: c.state,
            context: c.context,
            target_url: c.target_url,
            description: c.description,
            producer_did: c.producer_did,
            created_at: c.created_at,
        })
        .collect();

    Ok(Json(CombinedStatus {
        state: combined_state(&statuses).to_string(),
        sha: commit_sha,
        total_count: statuses.len(),
        statuses,
        reported_only: true,
    }))
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
}
