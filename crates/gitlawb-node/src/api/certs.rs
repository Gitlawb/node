//! API handlers for ref certificates.

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, State};
use axum::Json;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;

/// GET /api/v1/repos/{owner}/{repo}/certs?limit=50
pub async fn list_certs(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .map(|v| v.max(1))
        .unwrap_or(50)
        .min(200);

    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    // When a prefix is given (short-ID resolution from the CLI) use a
    // generous limit and delegate to the prefix-matched query so the
    // caller can resolve IDs regardless of how many certs exist.
    let prefix = params.get("prefix").filter(|p| !p.is_empty());
    let certs = if let Some(prefix) = prefix {
        state
            .db
            .list_ref_certificates_by_prefix(&record.id, prefix, 200)
            .await?
    } else {
        state.db.list_ref_certificates(&record.id, limit).await?
    };
    let certs_json: Vec<serde_json::Value> = certs
        .iter()
        .map(|c| {
            serde_json::json!({
                "id":         c.id,
                "repo_id":    c.repo_id,
                "ref_name":   c.ref_name,
                "old_sha":    c.old_sha,
                "new_sha":    c.new_sha,
                "pusher_did": c.pusher_did,
                "node_did":   c.node_did,
                "signature":  c.signature,
                "issued_at":  c.issued_at,
            })
        })
        .collect();

    let count = certs_json.len();
    Ok(Json(
        serde_json::json!({ "certificates": certs_json, "count": count }),
    ))
}

/// GET /api/v1/repos/{owner}/{repo}/certs/{id}
pub async fn get_cert(
    State(state): State<AppState>,
    Path((owner, name, id)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let cert = state
        .db
        .get_ref_certificate(&id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("certificate {id}")))?;

    if cert.repo_id != record.id {
        return Err(AppError::NotFound(format!("certificate {id}")));
    }

    Ok(Json(serde_json::json!({
        "id":         cert.id,
        "repo_id":    cert.repo_id,
        "ref_name":   cert.ref_name,
        "old_sha":    cert.old_sha,
        "new_sha":    cert.new_sha,
        "pusher_did": cert.pusher_did,
        "node_did":   cert.node_did,
        "signature":  cert.signature,
        "issued_at":  cert.issued_at,
    })))
}
