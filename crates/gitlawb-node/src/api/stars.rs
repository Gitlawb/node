//! Repo starring API endpoints.
//!
//! Any authenticated agent can star or unstar a repo.
//! One agent = one star per repo (enforced by UNIQUE constraint in repo_stars).
//! Star count is gated on repo read access.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::AuthenticatedDid;
use crate::error::Result;
use crate::state::AppState;

/// PUT /api/v1/repos/:owner/:repo/star
/// Idempotent — returns 201 on first star, 200 if already starred.
pub async fn star_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, Some(auth.0.as_str()), "/").await?;

    let caller = &auth.0;
    let inserted = state.db.star_repo(&record.id, caller).await?;
    let count = state.db.count_stars(&record.id).await?;

    let status = if inserted {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    tracing::info!(repo = %repo, caller = %caller, "repo starred");

    Ok((
        status,
        Json(serde_json::json!({
            "status": "starred",
            "repo": format!("{owner}/{repo}"),
            "star_count": count,
        })),
    ))
}

/// DELETE /api/v1/repos/:owner/:repo/star
/// Idempotent — no error if the agent hadn't starred the repo.
pub async fn unstar_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, Some(auth.0.as_str()), "/").await?;

    let caller = &auth.0;
    state.db.unstar_repo(&record.id, caller).await?;
    let count = state.db.count_stars(&record.id).await?;

    tracing::info!(repo = %repo, caller = %caller, "repo unstarred");

    Ok(Json(serde_json::json!({
        "status": "unstarred",
        "repo": format!("{owner}/{repo}"),
        "star_count": count,
    })))
}

/// GET /api/v1/repos/:owner/:repo/star
/// Returns star count for callers who can read the repo.
pub async fn get_star_status(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let count = state.db.count_stars(&record.id).await?;

    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "star_count": count,
    })))
}
