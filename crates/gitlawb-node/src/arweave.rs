//! Arweave permanent anchoring via Irys.
//!
//! Every ref-update event (push) is anchored to Arweave through the Irys
//! network. The anchor payload is a small JSON object containing:
//!
//!   { repo, owner_did, ref_name, old_sha, new_sha, cid, timestamp, node_did }
//!
//! Irys allows free uploads for data < 100 KiB on both devnet and mainnet
//! (via Turbo). No wallet is required for payloads under the free threshold.
//!
//! Set `GITLAWB_IRYS_URL` to override the default endpoint:
//!   - devnet (free, no cost): https://devnet.irys.xyz
//!   - mainnet:                https://node2.irys.xyz
//!
//! Each anchor returns an Irys transaction ID (43-char base58 string).
//! The permanent Arweave URL is: https://arweave.net/<tx_id>
//!
//! Anchors are stored in the `arweave_anchors` table for auditability.

use anyhow::Result;
use serde_json::json;

/// Data describing a ref-update event to be anchored.
#[derive(Debug, Clone)]
pub struct RefAnchor {
    pub repo: String,
    pub owner_did: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    /// IPFS CIDv1 of the commit object, if available
    pub cid: Option<String>,
    pub timestamp: String,
    pub node_did: String,
}

/// Anchor a ref-update to Arweave via Irys.
///
/// Returns the Irys/Arweave transaction ID on success.
/// Returns `Ok("")` if `irys_url` is empty (anchoring disabled).
pub async fn anchor_ref_update(
    client: &reqwest::Client,
    irys_url: &str,
    anchor: &RefAnchor,
) -> Result<String> {
    if irys_url.is_empty() {
        return Ok(String::new());
    }

    let payload = json!({
        "schema": "gitlawb/ref-update/v1",
        "repo": anchor.repo,
        "owner_did": anchor.owner_did,
        "ref_name": anchor.ref_name,
        "old_sha": anchor.old_sha,
        "new_sha": anchor.new_sha,
        "cid": anchor.cid,
        "timestamp": anchor.timestamp,
        "node_did": anchor.node_did,
        "network": "alpha",
    });

    let body = serde_json::to_vec(&payload)?;

    // Irys upload endpoint
    let url = format!("{}/upload", irys_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        // Irys tags allow indexing on Arweave gateway
        .header("x-irys-tags", build_tags_header(anchor))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Irys upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Irys returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Irys response: {e}"))?;

    // Irys response: {"id": "<tx_id>", "timestamp": ..., "version": ...}
    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Irys response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %anchor.repo,
        ref_name = %anchor.ref_name,
        new_sha = %anchor.new_sha,
        tx_id = %tx_id,
        "anchored ref update to Arweave"
    );

    Ok(tx_id)
}

/// Arweave permanent URL for a given Irys transaction ID.
pub fn arweave_url(tx_id: &str) -> String {
    format!("https://arweave.net/{tx_id}")
}

/// Build the Irys tag header value for Arweave indexing.
/// Format: comma-separated "name:value" pairs.
fn build_tags_header(anchor: &RefAnchor) -> String {
    vec![
        format!("App-Name:gitlawb"),
        format!("Schema:gitlawb/ref-update/v1"),
        format!("Repo:{}", sanitize_tag(&anchor.repo)),
        format!("Ref:{}", sanitize_tag(&anchor.ref_name)),
        format!("SHA:{}", &anchor.new_sha[..anchor.new_sha.len().min(16)]),
        format!("Node-DID:{}", sanitize_tag(&anchor.node_did)),
    ]
    .join(",")
}

/// Strip characters that are invalid in Irys/Arweave tag values.
fn sanitize_tag(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
        .take(128)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anchor_noop_when_url_empty() {
        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            new_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            cid: Some("bafyreib5...".into()),
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6MknndwexV9...".into(),
        };
        let result = anchor_ref_update(&client, "", &anchor).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[tokio::test]
    async fn test_anchor_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/upload")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(64),
            new_sha: "a1b2c3d4".repeat(8),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
        };

        let result = anchor_ref_update(&client, &server.url(), &anchor).await;
        assert!(result.is_ok(), "anchor should succeed: {result:?}");
        assert_eq!(
            result.unwrap(),
            "7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
        _mock.assert_async().await;
    }

    #[test]
    fn test_arweave_url() {
        let url = arweave_url("7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk");
        assert_eq!(
            url,
            "https://arweave.net/7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
    }

    #[test]
    fn test_sanitize_tag() {
        assert_eq!(sanitize_tag("alice/myrepo"), "alice/myrepo");
        assert_eq!(sanitize_tag("hello world!"), "helloworld");
    }
}
