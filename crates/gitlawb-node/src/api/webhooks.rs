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
    crate::api::require_repo_owner(&record, &auth.0)?;

    // Gate the target through the same hardened public-host validator the peer
    // announce path uses, so an authenticated owner cannot register a webhook
    // that makes the node POST to loopback/private/link-local/metadata
    // endpoints (SSRF). Delivery runs on the shared no-redirect client
    // (main.rs), which closes the 3xx-to-internal bounce.
    if !crate::api::peers::is_public_http_url(&req.url) {
        return Err(AppError::BadRequest(
            "webhook URL must be a public http(s) URL (no loopback, private, or .internal/.local hosts)".into(),
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
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    // This route sits on `optional_signature`, so the DID is optional. Webhook
    // callback URLs are owner-secret config and there is no anonymous form, so a
    // headerless caller is rejected before any lookup (401, which fires for an
    // existing-private and an absent repo alike, so it leaks no existence).
    let Some(Extension(AuthenticatedDid(caller))) = auth else {
        return Err(AppError::Unauthorized(
            "listing webhooks requires authentication".into(),
        ));
    };

    // Read-visibility first, then owner. authorize_repo_read returns 404 on a
    // visibility deny, so a non-reader of a private repo cannot tell it exists
    // (uniform with the sibling read surfaces); require_repo_owner then yields
    // 403 only for a non-owner of a public/readable repo, where existence is not
    // secret.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(&caller), "/").await?;
    crate::api::require_repo_owner(&record, &caller)?;

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
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;
    crate::api::require_repo_owner(&record, &auth.0)?;

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

#[cfg(test)]
mod tests {
    use crate::api::peers::is_public_http_url;

    // create_webhook gates req.url through is_public_http_url. Pin the exact
    // SSRF targets from issue #81 so the webhook path can never regress to the
    // old scheme-only check, independent of the validator's own peer tests.
    #[test]
    fn webhook_url_gate_rejects_ssrf_targets() {
        for bad in [
            "http://127.0.0.1:5432/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/",
            "http://10.0.0.5/",
            "http://[::1]/",
            // IPv6 transition encodings smuggling loopback v4 (6to4 / NAT64).
            "http://[2002:7f00:1::]/",
            "http://[64:ff9b::7f00:1]/",
            "ftp://example.com/",
            "not-a-url",
        ] {
            assert!(!is_public_http_url(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn webhook_url_gate_allows_public_targets() {
        assert!(is_public_http_url("https://hooks.example.com/gitlawb"));
        assert!(is_public_http_url("http://203.0.113.10:7545/"));
    }
}
