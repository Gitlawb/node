//! Repo label management endpoints.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LabelRequest {
    pub label: String,
}

/// POST /api/v1/repos/:owner/:repo/labels
pub async fn add_label(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<LabelRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let label = req.label.trim().to_lowercase();
    if label.is_empty() || label.len() > 50 {
        return Err(AppError::BadRequest("label must be 1–50 characters".into()));
    }
    if !label
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == ':')
    {
        return Err(AppError::BadRequest(
            "label must contain only alphanumeric characters, hyphens, and colons".into(),
        ));
    }

    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;
    crate::api::require_repo_owner(&record, &auth.0)?;

    let added = state.db.add_label(&record.id, &label).await?;
    let status = if added {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(serde_json::json!({ "label": label, "added": added })),
    ))
}

/// DELETE /api/v1/repos/:owner/:repo/labels/:label
pub async fn remove_label(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, label)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;
    crate::api::require_repo_owner(&record, &auth.0)?;

    state.db.remove_label(&record.id, &label).await?;
    Ok(Json(serde_json::json!({ "label": label, "removed": true })))
}

/// GET /api/v1/repos/:owner/:repo/labels
pub async fn list_labels(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let labels = state.db.list_labels(&record.id).await?;
    Ok(Json(serde_json::json!({ "labels": labels })))
}
