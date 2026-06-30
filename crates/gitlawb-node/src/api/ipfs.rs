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
//!
//! Serving is access-controlled: an object is returned only from a repo row the
//! requesting caller is permitted to read (per-caller path-scoped visibility,
//! see `get_by_cid`).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use cid::CidGeneric;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::git::store;
use crate::git::visibility_pack::{has_path_scoped_rule, withheld_blob_oids};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

/// GET /ipfs/{cid}
///
/// Search all repos on the node for a git object whose SHA-256 hash matches
/// the given CIDv1, returning its raw content if the caller may read it.
///
/// Visibility (#110): the object is served only from a repo row the caller
/// passes. For each iterated row we gate against that row's OWN rules
/// (`visibility_check` at `"/"`), never re-resolving via `authorize_repo_read`
/// — `get_repo`'s fuzzy match could otherwise authorize a different physical
/// row than the one read (KTD2a). When the row carries path-scoped rules, a
/// blob withheld from the caller (`withheld_blob_oids`) is skipped. Denial and
/// genuine not-found both fall through to an opaque 404.
///
/// Scope: this closes the direct unauthenticated scan. A stale-public mirror
/// row still serves withheld content (tracked separately, #124).
pub async fn get_by_cid(
    Path(cid_str): Path<String>,
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
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
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let caller_owned = caller.map(|c| c.to_string());

    // 2. Search all repos for an object with this SHA-256
    let repos = state
        .db
        .list_all_repos()
        .await
        .map_err(AppError::Internal)?;

    // Fetch every repo's visibility rules in one query rather than one per row
    // (the gate runs each row against its OWN rules — KTD2a). A row absent from
    // the map has no rules.
    let repo_ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
    let rules_by_repo = state
        .db
        .list_visibility_rules_for_repos(&repo_ids)
        .await
        .map_err(AppError::Internal)?;

    // Request-scoped memo of the per-repo withheld set (KTD1). The caller is
    // constant for one request, so `repo.id` alone is a safe, sufficient key —
    // never a coarse caller "class", which `visibility_check`'s exact full-DID
    // reader match would make unsafe.
    let mut withheld_memo: HashMap<String, HashSet<String>> = HashMap::new();

    for repo in &repos {
        // Repo-level read gate against THIS row's own rules (KTD2a).
        let rules: &[crate::db::VisibilityRule] = rules_by_repo
            .get(&repo.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if visibility_check(rules, repo.is_public, &repo.owner_did, caller, "/") == Decision::Deny {
            continue;
        }

        let repo_path = match state.repo_store.acquire(&repo.owner_did, &repo.name).await {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Per-blob withholding only applies when a path-scoped rule exists (KTD4).
        if has_path_scoped_rule(rules) {
            if !withheld_memo.contains_key(&repo.id) {
                let rp = repo_path.clone();
                let r = rules.to_vec();
                let is_public = repo.is_public;
                let owner = repo.owner_did.clone();
                let caller_for_walk = caller_owned.clone();
                // Full-history walk shells out to git — keep it off the async runtime.
                let walk = tokio::task::spawn_blocking(move || {
                    withheld_blob_oids(&rp, &r, is_public, &owner, caller_for_walk.as_deref())
                })
                .await;
                // Fail closed on EITHER a task panic (JoinError) or a walk error:
                // we cannot prove the caller may read here, so skip this repo and
                // let a public copy (if any) serve. Never serve on an unproven gate.
                let set = match walk {
                    Ok(Ok(set)) => set,
                    Ok(Err(e)) => {
                        tracing::warn!(repo = %repo.name, err = %e, "withheld walk failed; skipping repo");
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(repo = %repo.name, err = %e, "withheld walk task panicked; skipping repo");
                        continue;
                    }
                };
                withheld_memo.insert(repo.id.clone(), set);
            }
            if withheld_memo
                .get(&repo.id)
                .is_some_and(|set| set.contains(&sha256_hex))
            {
                continue;
            }
        }

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
        .map_err(AppError::Internal)?;

    Ok(Json(serde_json::json!({
        "pins": pins,
        "count": pins.len(),
    })))
}
