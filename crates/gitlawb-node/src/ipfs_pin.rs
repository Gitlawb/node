//! IPFS pinning integration for gitlawb-node.
//!
//! After a git push lands, each new git object is pinned to a local Kubo node
//! via its HTTP API (`/api/v0/add`). Objects already recorded in the
//! `pinned_cids` DB table are skipped to avoid duplicate work.
//!
//! If `ipfs_api` is empty the functions are no-ops, so the node works fine
//! without a local IPFS daemon.

use anyhow::Result;
use gitlawb_core::cid::Cid;

/// Pin a single git object to the local IPFS/Kubo node.
///
/// - `ipfs_api`: base URL of the Kubo HTTP API, e.g. `http://127.0.0.1:5001`.
///   If empty the function returns `Ok("")` immediately.
/// - `sha256_hex`: the git SHA-256 hex object ID (used only for logging).
/// - `data`: raw git object content bytes (same bytes used for CID computation).
///
/// Returns the CID string on success, or `""` when IPFS is not configured.
pub async fn pin_git_object(ipfs_api: &str, sha256_hex: &str, data: &[u8]) -> Result<String> {
    if ipfs_api.is_empty() {
        return Ok(String::new());
    }

    // Compute the expected CIDv1 from the content bytes
    let expected_cid = Cid::from_git_object_bytes(data).to_string();

    let url = format!(
        "{}/api/v0/add?cid-version=1&raw-leaves=true&pin=true",
        ipfs_api.trim_end_matches('/')
    );

    // Build multipart form with the object data
    let part = reqwest::multipart::Part::bytes(data.to_vec())
        .file_name("object")
        .mime_str("application/octet-stream")?;
    let form = reqwest::multipart::Form::new().part("file", part);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .multipart(form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("IPFS add request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "IPFS /api/v0/add returned {status}: {body}"
        ));
    }

    // Kubo returns newline-delimited JSON; we only care about the last object
    // (there's typically just one for a single-file add).
    let body = resp.text().await?;
    let cid = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            v["Hash"].as_str().map(|s| s.to_string())
        })
        .next_back()
        .unwrap_or(expected_cid.clone());

    tracing::debug!(sha256 = %sha256_hex, %cid, "pinned git object to IPFS");
    Ok(cid)
}

/// Fetch raw bytes for a CID from the local Kubo node (`/api/v0/cat`).
pub async fn cat(ipfs_api: &str, cid: &str) -> Result<Vec<u8>> {
    if ipfs_api.is_empty() {
        return Err(anyhow::anyhow!("IPFS not configured"));
    }
    let url = format!("{}/api/v0/cat?arg={}", ipfs_api.trim_end_matches('/'), cid);
    let resp = reqwest::Client::new().post(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("ipfs cat {cid}: {}", resp.status()));
    }
    Ok(resp.bytes().await?.to_vec())
}

/// Pin any of the given candidate git objects that are not yet recorded in
/// `pinned_cids`.
///
/// `object_list` is the already-withheld-filtered OID set to pin: the caller
/// applies `visibility_pack::replicable_objects` on the delta path or the
/// `..._fail_closed` filter on the full-scan path before calling, so this
/// function never sees a withheld blob. `repo_path` is still needed to read each
/// object's bytes. The twin in `pinata.rs` mirrors this shape — change both in
/// lockstep.
///
/// Returns a list of `(sha256_hex, cid)` pairs for objects pinned this call.
pub async fn pin_new_objects(
    ipfs_api: &str,
    repo_path: &std::path::Path,
    object_list: Vec<String>,
    db: &crate::db::Db,
) -> Vec<(String, String)> {
    if ipfs_api.is_empty() {
        return vec![];
    }

    let mut pinned = Vec::new();

    for sha in object_list {
        // Skip if already pinned
        match db.is_pinned(&sha).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "DB error checking pinned status");
                continue;
            }
        }

        // Read raw object content
        let data = match crate::git::store::read_object(repo_path, &sha) {
            Ok(Some((_obj_type, bytes))) => bytes,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "failed to read git object for pinning");
                continue;
            }
        };

        // Pin to IPFS
        match pin_git_object(ipfs_api, &sha, &data).await {
            Ok(cid) if !cid.is_empty() => {
                if let Err(e) = db.record_pinned_cid(&sha, &cid).await {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pinned CID in DB");
                }
                pinned.push((sha, cid));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "failed to pin git object to IPFS");
            }
        }
    }

    pinned
}
