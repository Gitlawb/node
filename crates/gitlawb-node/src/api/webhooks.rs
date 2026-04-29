//! Webhook CRUD API.
//!
//! POST   /api/v1/repos/:owner/:repo/hooks        — create (auth required)
//! GET    /api/v1/repos/:owner/:repo/hooks        — list
//! DELETE /api/v1/repos/:owner/:repo/hooks/:id   — delete (auth required)

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::Webhook;
use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub secret: Option<String>,
    /// Event patterns to subscribe to. Use ["*"] for all events.
    /// Valid values: "pull_request.opened", "pull_request.reviewed",
    ///               "pull_request.merged", "pull_request.closed", "push", "*"
    pub events: Option<Vec<String>>,
}

/// POST /api/v1/repos/:owner/:repo/hooks
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<Webhook>)> {
    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    // Validate URL is http/https
    if !req.url.starts_with("http://") && !req.url.starts_with("https://") {
        return Err(AppError::BadRequest(
            "webhook URL must be http:// or https://".into(),
        ));
    }

    let events = req.events.unwrap_or_else(|| vec!["*".into()]);
    let created_by_did = auth.0;

    let hook = Webhook {
        id: Uuid::new_v4().to_string(),
        repo_id: record.id,
        url: req.url,
        secret: req.secret,
        events,
        created_by_did,
        created_at: Utc::now().to_rfc3339(),
        active: true,
    };

    state.db.create_webhook(&hook).await?;
    Ok((StatusCode::CREATED, Json(hook)))
}

/// GET /api/v1/repos/:owner/:repo/hooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let hooks = state.db.list_webhooks(&record.id).await?;
    // Redact secrets in list response
    let redacted: Vec<_> = hooks
        .into_iter()
        .map(|mut h| {
            if h.secret.is_some() {
                h.secret = Some("***".into());
            }
            h
        })
        .collect();

    Ok(Json(
        serde_json::json!({ "webhooks": redacted, "count": redacted.len() }),
    ))
}

/// DELETE /api/v1/repos/:owner/:repo/hooks/:id
pub async fn delete_webhook(
    State(state): State<AppState>,
    Path((owner, name, id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    // Verify the webhook belongs to this repo
    let hook = state
        .db
        .get_webhook(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("webhook {id} not found")))?;

    if hook.repo_id != record.id {
        return Err(AppError::NotFound(format!("webhook {id} not found")));
    }

    state.db.delete_webhook(&id).await?;
    Ok(Json(serde_json::json!({ "deleted": true, "id": id })))
}
