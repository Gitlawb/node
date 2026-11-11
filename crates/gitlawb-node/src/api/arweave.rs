//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Extension, Query, State},
    Json,
};
use serde::Deserialize;

use crate::db::normalize_owner_key;
use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ListAnchorsQuery {
    pub repo: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// GET /api/v1/arweave/anchors
///
/// `?repo=<owner>/<name>` returns anchors for one repository and binds the
/// request to the canonical read-authorization path used by every other
/// repo-scoped read: the same `authorize_repo_read` helper, with the caller
/// identity attached. Missing repositories, quarantined mirrors, and signed
/// non-readers all collapse to the standard `404` (no existence oracle). The
/// unscoped listing is auth-only — the #121 contract — and does not admit
/// visibility filtering, which is the #136 stale-index class and explicitly
/// out of scope for this auth slice.
pub async fn list_anchors(
    State(state): State<AppState>,
    Query(q): Query<ListAnchorsQuery>,
    auth: Option<Extension<crate::auth::AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    // The route's `optional_signature` layer is permissive (it admits unsigned
    // legacy callers) so this in-handler check is the actual gate. A signed
    // non-reader still passes this check and proceeds to the authz step below.
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    if caller.is_none() {
        return Err(AppError::Unauthorized(
            "authentication required for anchor listing".into(),
        ));
    }

    // Clamp before the SQL query. A negative or non-numeric limit must not
    // reach Postgres as `LIMIT -1` (which it rejects as a db error / 500) — the
    // contract is the same default ceiling as the listing page itself.
    let limit = q.limit.clamp(0, 200);

    let anchors = if let Some(repo_slug) = q.repo.as_deref() {
        // Parse the user-supplied "owner/name" through the same slug validator
        // the sync path uses, so a malformed query is a 400, not a 500.
        let (owner, name) = match crate::git::repo_store::validate_repo_slug(repo_slug) {
            Ok(parts) => parts,
            Err(e) => return Err(AppError::BadRequest(format!("invalid ?repo: {e}"))),
        };
        // Read gate. Returns `RepoNotFound` (→ 404) indistinguishably for
        // missing repos, quarantined mirrors, and signed non-readers.
        let (record, _rules) =
            crate::api::authorize_repo_read(&state, owner, name, caller, "/").await?;
        // Build the SQL filter from the canonical stored slug, NOT from the
        // user-supplied `?repo=` string. Anchor rows are written as
        // `{normalize_owner_key(owner_did)}/{name}` (the short form), so a
        // request that passes authz with the full `did:key:…/name` form would
        // match zero rows and return a false empty page. The gate already
        // verified the repo is readable; `record.owner_did` is the canonical
        // identity and `record.name` is the stored name.
        let stored_slug = format!("{}/{}", normalize_owner_key(&record.owner_did), record.name);
        state
            .db
            .list_arweave_anchors(Some(&stored_slug), limit)
            .await?
    } else {
        // No scope → no repo-read decision. Auth-only.
        state.db.list_arweave_anchors(None, limit).await?
    };

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}

#[cfg(test)]
mod closed_pool_tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use serde_json::Value;
    use sqlx::PgPool;
    use tower::ServiceExt;

    /// #251: a closed pool on /api/v1/arweave/anchors must be 503 db_unavailable.
    #[sqlx::test]
    async fn list_anchors_closed_pool_returns_503_db_unavailable(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        pool.close().await;

        let resp = Router::new()
            .route("/api/v1/arweave/anchors", axum::routing::get(list_anchors))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/arweave/anchors")
                    .extension(crate::auth::AuthenticatedDid("did:key:test".into()))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "closed-pool outage must be retryable 503, not 500"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v,
            serde_json::json!({
                "error": crate::error::DB_UNAVAILABLE_CODE,
                "message": crate::error::DB_UNAVAILABLE_MESSAGE,
            })
        );
    }
}
