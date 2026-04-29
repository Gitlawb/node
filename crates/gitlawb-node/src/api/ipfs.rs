//! GET /ipfs/{cid} — content-addressed retrieval of git objects by CIDv1.
//!
//! Every git object stored on this node is addressable by its IPFS CIDv1.
//! The CID is computed as:
//!
//!   CIDv1(codec=raw, multihash=sha2-256(content_bytes))
//!
//! where `content_bytes` is the raw object content as returned by
//! `git cat-file <type> <sha256>` (i.e. without the git framing header).
//! This is consistent with how `gitlawb_core::cid::Cid::from_git_object_bytes`
//! computes CIDs when objects are pushed.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cid::CidGeneric;
use std::str::FromStr;

use crate::error::{AppError, Result};
use crate::git::store;
use crate::state::AppState;

/// GET /ipfs/{cid}
///
/// Search all repos on the node for a git object whose SHA-256 hash matches
/// the given CIDv1. Returns the raw object content bytes with appropriate
/// headers if found, or 404 if not found.
pub async fn get_by_cid(
    Path(cid_str): Path<String>,
    State(state): State<AppState>,
) -> Result<Response> {
    // 1. Decode the CID and extract the SHA-256 digest
    let cid = CidGeneric::<64>::from_str(&cid_str)
        .map_err(|e| AppError::BadRequest(format!("invalid CID: {e}")))?;

    let mh = cid.hash();
    // multihash code 0x12 = sha2-256
    const SHA2_256_CODE: u64 = 0x12;
    if mh.code() != SHA2_256_CODE {
        return Err(AppError::BadRequest(
            "only sha2-256 CIDs are supported".to_string(),
        ));
    }

    let sha256_hex = hex::encode(mh.digest());

    // 2. Search all repos for an object with this SHA-256
    let repos = state
        .db
        .list_all_repos()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    for repo in &repos {
        let repo_path = match state.repo_store.acquire(&repo.owner_did, &repo.name).await {
            Ok(p) => p,
            Err(_) => continue,
        };

        match store::read_object(&repo_path, &sha256_hex) {
            Ok(Some((_obj_type, content))) => {
                // 3. Return the content with IPFS-style headers
                let mut headers = HeaderMap::new();
                headers.insert(
                    HeaderName::from_static("content-type"),
                    HeaderValue::from_static("application/octet-stream"),
                );
                headers.insert(
                    HeaderName::from_static("x-content-cid"),
                    HeaderValue::from_str(&cid_str)
                        .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
                );
                headers.insert(
                    HeaderName::from_static("x-git-hash"),
                    HeaderValue::from_str(&sha256_hex)
                        .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
                );

                return Ok((StatusCode::OK, headers, content).into_response());
            }
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(repo = %repo.name, err = %e, "error reading git object");
                continue;
            }
        }
    }

    // Not found in any repo
    Err(AppError::RepoNotFound(format!(
        "no git object found for CID {cid_str}"
    )))
}

/// GET /api/v1/ipfs/pins
///
/// Returns all CIDs that have been pinned to the local IPFS node from git
/// objects received via push. Each entry includes the git SHA-256 hex, the
/// CIDv1 string, and the timestamp when it was pinned.
pub async fn list_pins(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let pins = state
        .db
        .list_pinned_cids()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;

    Ok(Json(serde_json::json!({
        "pins": pins,
        "count": pins.len(),
    })))
}
