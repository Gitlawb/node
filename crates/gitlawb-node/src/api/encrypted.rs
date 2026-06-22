//! Authenticated discovery + fetch for encrypted withheld blobs (Option B1).

use axum::extract::{Extension, Path, State};
use axum::Json;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

/// GET /api/v1/repos/{owner}/{repo}/encrypted-blobs
/// Returns [{oid, cid}] for every encrypted blob in the repo, to any caller who
/// can read the repo. Not recipient-scoped: recipient identities are not stored,
/// so access control here is repo readability and decryption is gated by the
/// envelope crypto (only a real recipient can open an envelope).
pub async fn list_encrypted_blobs(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let rules = state.db.list_visibility_rules(&record.id).await?;
    if visibility_check(&rules, record.is_public, &record.owner_did, caller, "/") == Decision::Deny
    {
        return Err(AppError::RepoNotFound(format!("{owner}/{repo}")));
    }
    let rows = state.db.list_all_encrypted_blobs(&record.id).await?;
    let blobs: Vec<_> = rows
        .into_iter()
        .map(|(oid, cid)| serde_json::json!({ "oid": oid, "cid": cid }))
        .collect();
    Ok(Json(serde_json::json!({ "blobs": blobs })))
}

/// GET /api/v1/repos/{owner}/{repo}/encrypted-blob/{oid}
/// Returns raw envelope bytes to callers who can read the repo; the envelope
/// crypto still ensures only true recipients can decrypt.
pub async fn get_encrypted_blob(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
) -> Result<Vec<u8>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let rules = state.db.list_visibility_rules(&record.id).await?;
    if visibility_check(&rules, record.is_public, &record.owner_did, caller, "/") == Decision::Deny
    {
        return Err(AppError::RepoNotFound(format!("{owner}/{repo}/{oid}")));
    }
    let cid = state
        .db
        .encrypted_blob_cid(&record.id, &oid)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}/{oid}")))?;
    let bytes = crate::ipfs_pin::cat(&state.config.ipfs_api, &cid)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    Ok(bytes)
}

/// GET /api/v1/repos/{owner}/{repo}/encrypted-blobs/replicate
/// Returns [{oid, cid}] for every encrypted blob in the repo, for peer-mirror
/// replication (Option B2). Gated by repo readability, like discovery, so a
/// non-readable repo does not expose its blob index; for the intended case (a
/// public repo with withheld subtrees) the public root keeps this open to peers.
/// Recipient identities are deliberately withheld: the v2 envelopes no longer
/// carry recipient public keys, so peers must not learn the reader set either. A
/// mirror detects a re-seal by the CID changing (the OID is stable across
/// re-seals). Ciphertext metadata only, never plaintext.
pub async fn replicate_encrypted_blobs(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let rules = state.db.list_visibility_rules(&record.id).await?;
    if visibility_check(&rules, record.is_public, &record.owner_did, caller, "/") == Decision::Deny
    {
        return Err(AppError::RepoNotFound(format!("{owner}/{repo}")));
    }
    let rows = state.db.list_all_encrypted_blobs(&record.id).await?;
    let blobs: Vec<_> = rows
        .into_iter()
        .map(|(oid, cid)| replicate_blob_json(oid, cid))
        .collect();
    Ok(Json(serde_json::json!({ "blobs": blobs })))
}

/// Serialize one blob for the replication wire. Recipient identities are
/// intentionally absent so a mirror never learns the reader set.
fn replicate_blob_json(oid: String, cid: String) -> serde_json::Value {
    serde_json::json!({ "oid": oid, "cid": cid })
}

#[cfg(test)]
mod tests {
    use super::replicate_blob_json;

    #[test]
    fn replicate_blob_json_omits_recipients() {
        let v = replicate_blob_json("oid1".into(), "cidA".into());
        assert_eq!(v["oid"], "oid1");
        assert_eq!(v["cid"], "cidA");
        assert!(
            v.get("recipients").is_none(),
            "replication wire must not carry recipient identities"
        );
    }
}
