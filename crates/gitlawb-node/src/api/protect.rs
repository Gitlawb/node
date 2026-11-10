//! Branch protection API endpoints.
//!
//! Only the repo owner can protect or unprotect branches.
//! Protected branches reject pushes from any DID that is not the repo owner.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::AuthenticatedDid;
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

    // Only the repo owner can protect branches (DID-safe match, shared idiom).
    let caller = &auth.0;
    if !crate::api::did_matches(caller, &record.owner_did) {
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
    if !crate::api::did_matches(caller, &record.owner_did) {
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
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    // Read-visibility-gated (INV-2 root listing): a public repo's protected
    // branches stay anonymously listable; a private repo's branch names are
    // hidden (404) from anyone who cannot read it at the root.
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let branches = state.db.list_protected_branches(&record.id).await?;

    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "protected_branches": branches,
        "count": branches.len(),
    })))
}
