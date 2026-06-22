//! Branch protection API endpoints.
//!
//! Only the repo owner can protect or unprotect branches.
//! Protected branches reject pushes from any DID that is not the repo owner.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::{is_repo_owner, AuthenticatedDid};
use crate::error::{AppError, Result};
use crate::state::AppState;

/// POST /api/v1/repos/:owner/:repo/branches/:branch/protect
pub async fn protect_branch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    // Only the repo owner can protect branches
    let caller = &auth.0;
    if !is_repo_owner(&record, caller) {
        return Err(AppError::Forbidden(
            "only the repo owner can protect branches".into(),
        ));
    }

    state.db.protect_branch(&record.id, &branch, caller).await?;

    tracing::info!(repo = %repo, branch = %branch, caller = %caller, "branch protected");

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "protected",
            "repo": format!("{owner}/{repo}"),
            "branch": branch,
        })),
    ))
}

/// DELETE /api/v1/repos/:owner/:repo/branches/:branch/protect
pub async fn unprotect_branch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    let caller = &auth.0;
    if !is_repo_owner(&record, caller) {
        return Err(AppError::Forbidden(
            "only the repo owner can unprotect branches".into(),
        ));
    }

    state.db.unprotect_branch(&record.id, &branch).await?;

    tracing::info!(repo = %repo, branch = %branch, caller = %caller, "branch unprotected");

    Ok(Json(serde_json::json!({
        "status": "unprotected",
        "repo": format!("{owner}/{repo}"),
        "branch": branch,
    })))
}

/// GET /api/v1/repos/:owner/:repo/branches/protected
pub async fn list_protected_branches(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    let branches = state.db.list_protected_branches(&record.id).await?;

    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "protected_branches": branches,
        "count": branches.len(),
    })))
}
