//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
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
/// Returns Arweave ref-update anchors. When `?repo=<owner>/<name>` is provided,
/// the response is gated on the caller's read visibility for that repo (deny ->
/// 404). Without a `?repo=` filter, authentication is required to prevent
/// anonymous node-wide anchor enumeration (#121).
pub async fn list_anchors(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Query(q): Query<ListAnchorsQuery>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());

    if let Some(ref repo) = q.repo {
        // Gate on per-repo visibility.
        let parts: Vec<&str> = repo.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(AppError::NotFound("repo not found".into()));
        }
        let (owner, name) = (parts[0], parts[1]);
        crate::api::authorize_repo_read(&state, owner, name, caller, "/").await?;
    } else {
        // Global listing (no ?repo=) requires authentication.
        if caller.is_none() {
            return Err(AppError::Unauthorized("authentication required".into()));
        }
    }

    let limit = q.limit.min(200);
    let anchors = state
        .db
        .list_arweave_anchors(q.repo.as_deref(), limit)
        .await
        .map_err(AppError::Internal)?;

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}
