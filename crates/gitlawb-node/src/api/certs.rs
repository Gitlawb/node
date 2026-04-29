//! API handlers for ref certificates.

use axum::extract::{Path, State};
use axum::Json;

use crate::error::{AppError, Result};
use crate::state::AppState;

/// GET /api/v1/repos/{owner}/{repo}/certs
pub async fn list_certs(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let certs = state.db.list_ref_certificates(&record.id).await?;
    let certs_json: Vec<serde_json::Value> = certs.iter().map(|c| serde_json::json!({
        "id":         c.id,
        "repo_id":    c.repo_id,
        "ref_name":   c.ref_name,
        "old_sha":    c.old_sha,
        "new_sha":    c.new_sha,
        "pusher_did": c.pusher_did,
        "node_did":   c.node_did,
        "signature":  c.signature,
        "issued_at":  c.issued_at,
    })).collect();

    Ok(Json(serde_json::json!({ "certificates": certs_json })))
}

/// GET /api/v1/repos/{owner}/{repo}/certs/{id}
pub async fn get_cert(
    State(state): State<AppState>,
    Path((owner, name, id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    // Verify the repo exists
    let _record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let cert = state.db.get_ref_certificate(&id).await?
        .ok_or_else(|| AppError::NotFound(format!("certificate {id}")))?;

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
