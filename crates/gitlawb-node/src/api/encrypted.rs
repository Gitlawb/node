//! Authenticated discovery + fetch for encrypted withheld blobs (Option B1).

use axum::extract::{Extension, Path, State};
use axum::Json;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;

/// GET /api/v1/repos/{owner}/{repo}/encrypted-blobs
/// Returns [{oid, cid}] for encrypted blobs the caller may decrypt.
pub async fn list_encrypted_blobs(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str()).unwrap_or("");
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    let rows = state
        .db
        .list_encrypted_blobs_for(&record.id, caller)
        .await?;
    let blobs: Vec<_> = rows
        .into_iter()
        .map(|(oid, cid)| serde_json::json!({ "oid": oid, "cid": cid }))
        .collect();
    Ok(Json(serde_json::json!({ "blobs": blobs })))
}

/// GET /api/v1/repos/{owner}/{repo}/encrypted-blob/{oid}
/// Returns raw envelope bytes if the caller is a recipient.
pub async fn get_encrypted_blob(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
) -> Result<Vec<u8>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str()).unwrap_or("");
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    let cid = state
        .db
        .encrypted_blob_cid(&record.id, &oid, caller)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}/{oid}")))?;
    let bytes = crate::ipfs_pin::cat(&state.config.ipfs_api, &cid)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    Ok(bytes)
}

/// GET /api/v1/repos/{owner}/{repo}/encrypted-blobs/replicate
/// Returns [{oid, cid, recipients}] for every encrypted blob in the repo, for
/// peer-mirror replication (Option B2). Not recipient-scoped: recipient DIDs are
/// already public via the IPFS-pinned envelopes, so this exposes only ciphertext
/// metadata (content-addressed OIDs/CIDs and recipient DIDs), never plaintext.
pub async fn replicate_encrypted_blobs(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    let rows = state.db.list_all_encrypted_blobs(&record.id).await?;
    let blobs: Vec<_> = rows
        .into_iter()
        .map(|(oid, cid, recipients)| {
            serde_json::json!({ "oid": oid, "cid": cid, "recipients": recipients })
        })
        .collect();
    Ok(Json(serde_json::json!({ "blobs": blobs })))
}
