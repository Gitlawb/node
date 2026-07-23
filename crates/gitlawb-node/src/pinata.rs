//! Pinata IPFS pinning integration for Filecoin-backed warm storage.
//!
//! After git objects land on the node, this module uploads them to Pinata
//! so they are pinned off-node and available via the public IPFS gateway.
//!
//! Set `GITLAWB_PINATA_JWT` to enable. Leave empty and every call is a
//! no-op, so nodes without Pinata backing work fine.

use anyhow::Result;

/// Pin a single git object's raw bytes on Pinata (v3 API).
///
/// - `client`:     shared reqwest client
/// - `upload_url`: Pinata v3 upload URL (configured via `GITLAWB_PINATA_UPLOAD_URL`)
/// - `jwt`:        Pinata bearer JWT; returns `Ok("")` immediately if empty
/// - `sha`:        git object hash hex (used as the pin name)
/// - `data`:       raw git object bytes
///
/// Returns the IPFS CID assigned by Pinata on success.
pub async fn pin_object(
    client: &reqwest::Client,
    upload_url: &str,
    jwt: &str,
    sha: &str,
    data: &[u8],
) -> Result<String> {
    if jwt.is_empty() {
        return Ok(String::new());
    }

    let filename = format!("git-{}.bin", &sha[..sha.len().min(8)]);
    let part = reqwest::multipart::Part::bytes(data.to_vec())
        .file_name(filename)
        .mime_str("application/octet-stream")?;
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("network", "public")
        .text("name", format!("git-{sha}"));

    let resp = client
        .post(upload_url)
        .bearer_auth(jwt)
        .multipart(form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Pinata request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Pinata returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Pinata response: {e}"))?;

    // v3 response: {"data": {"cid": "...", "name": "...", ...}}
    let cid = json["data"]["cid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'data.cid' in Pinata response: {json}"))?
        .to_string();

    tracing::debug!(sha = %sha, %cid, "pinned git object to Pinata");
    Ok(cid)
}

/// Pin any of the given candidate git objects that haven't yet been sent to
/// Pinata.
///
/// `object_list` is the already-withheld-filtered OID set to pin: the caller
/// applies `visibility_pack::replicable_objects` on the delta path or the
/// `..._fail_closed` filter on the full-scan path before calling. `repo_path` is
/// still needed to read each object's bytes. The twin in `ipfs_pin.rs` mirrors
/// this shape — change both in lockstep. Objects already recorded with a
/// `pinata_cid` are skipped. Returns `(sha_hex, cid)` pairs for each newly
/// pinned object.
pub async fn pin_new_objects(
    client: &reqwest::Client,
    upload_url: &str,
    jwt: &str,
    repo_path: &std::path::Path,
    object_list: Vec<String>,
    db: &crate::db::Db,
) -> Vec<(String, String)> {
    if jwt.is_empty() {
        return vec![];
    }

    let mut pinned = Vec::new();

    for sha in object_list {
        match db.has_pinata_cid(&sha).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "DB error checking pinata_cid");
                continue;
            }
        }

        let data = match crate::git::store::read_object(repo_path, &sha) {
            Ok(Some((_kind, bytes))) => bytes,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "failed to read git object for Pinata");
                continue;
            }
        };

        match pin_object(client, upload_url, jwt, &sha, &data).await {
            Ok(cid) if !cid.is_empty() => {
                if let Err(e) = db.record_pinata_cid(&sha, &cid).await {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pinata_cid in DB");
                }
                pinned.push((sha, cid));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "Pinata pin failed — continuing");
            }
        }
    }

    pinned
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pin_skipped_when_jwt_empty() {
        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            "https://uploads.pinata.cloud/v3/files",
            "",
            "deadbeef",
            b"data",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "", "empty JWT must return empty CID");
    }

    #[tokio::test]
    async fn test_pin_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","name":"git-deadbeef.bin","size":20}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "test-jwt",
            "deadbeef00000000",
            b"raw git object bytes",
        )
        .await;

        assert!(result.is_ok(), "pin should succeed: {result:?}");
        assert_eq!(
            result.unwrap(),
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        );
        _mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_pin_auth_failure_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(401)
            .with_body(r#"{"error":"UNAUTHORIZED"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "bad-jwt",
            "deadbeef00000000",
            b"data",
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[tokio::test]
    async fn test_pin_server_error_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(&client, &server.url(), "jwt", "deadbeef00000000", b"data").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    #[tokio::test]
    async fn test_pin_missing_cid_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"name":"git-deadbeef.bin"}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(&client, &server.url(), "jwt", "deadbeef00000000", b"data").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no 'data.cid'"));
    }

    #[tokio::test]
    async fn test_pin_uses_bearer_auth() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer my-pinata-jwt")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"cid":"QmTest","name":"git-deadbeef.bin","size":4}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "my-pinata-jwt",
            "deadbeef00000000",
            b"data",
        )
        .await;

        assert!(result.is_ok());
        _mock.assert_async().await;
    }
}
