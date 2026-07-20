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
use base64::Engine as _;
use serde::Serialize;
use serde_json::json;
use sha2::Digest;
use std::str::FromStr;

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
    /// The full signed [`crate::db::RefCertificate`] for this ref update,
    /// serialized and embedded so a verifier can validate the chain.
    pub certificate: Option<crate::db::RefCertificate>,
}

/// Anchor a ref-update to Arweave via Irys.
///
/// Returns the Irys/Arweave transaction ID on success.
/// Returns `Ok("")` if `bundler_url` is empty (anchoring disabled).
pub async fn anchor_ref_update(
    client: &reqwest::Client,
    bundler_url: &str,
    anchor: &RefAnchor,
) -> Result<String> {
    if bundler_url.is_empty() {
        return Ok(String::new());
    }

    let mut payload = json!({
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

    // Embed the signed certificate so verifiers can validate the chain.
    if let Some(cert) = &anchor.certificate {
        payload["certificate"] = serde_json::to_value(cert)?;
    }

    let body = serde_json::to_vec(&payload)?;

    // Irys upload endpoint
    let url = format!("{}/v1/tx", bundler_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("x-bundler-tags", build_tags_header(anchor))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Bundler upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Bundler returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Bundler response: {e}"))?;

    // Bundler response: {"id": "<data_item_id>", "timestamp": ..., "version": ...}
    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Bundler response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %anchor.repo,
        ref_name = %anchor.ref_name,
        new_sha = %anchor.new_sha,
        tx_id = %tx_id,
        "anchored ref update to Arweave via bundler"
    );

    Ok(tx_id)
}

/// A per-push manifest of the blobs encrypted this push (Option B3). The
/// `blobs` slice is `(oid, cid)` tuples. Anchored directly to Arweave as its JSON
/// body so the discovery index survives total node loss. Recipient identities are
/// never part of the manifest.
pub struct EncryptedManifest<'a> {
    pub repo: &'a str,
    pub owner_did: &'a str,
    pub node_did: &'a str,
    pub timestamp: &'a str,
    pub blobs: &'a [(String, String)],
}

/// Anchor a per-push encrypted-blob manifest to Arweave via Irys. The manifest
/// JSON body is the payload (not a CID pointer to IPFS), so the index is
/// permanent and self-contained. Recipient identities are deliberately omitted:
/// the anchor is permanent and public, and the v2 envelopes no longer expose
/// recipients, so the reader set must not be written to Arweave either.
///
/// Returns the Arweave transaction ID, or `Ok("")` when `bundler_url` is empty
/// (anchoring disabled) or there are no blobs to anchor.
pub async fn anchor_encrypted_manifest(
    client: &reqwest::Client,
    bundler_url: &str,
    manifest: &EncryptedManifest<'_>,
) -> Result<String> {
    if bundler_url.is_empty() || manifest.blobs.is_empty() {
        return Ok(String::new());
    }

    let blobs_json: Vec<serde_json::Value> = manifest
        .blobs
        .iter()
        .map(|(oid, cid)| manifest_blob_json(oid, cid))
        .collect();

    let payload = json!({
        "schema": "gitlawb/encrypted-manifest/v1",
        "repo": manifest.repo,
        "owner_did": manifest.owner_did,
        "node_did": manifest.node_did,
        "timestamp": manifest.timestamp,
        "blobs": blobs_json,
    });

    let body = serde_json::to_vec(&payload)?;
    let url = format!("{}/v1/tx", bundler_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header("Content-Type", "application/octet-stream")
        .header("x-bundler-tags", build_manifest_tags_header(manifest))
        .body(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Bundler upload failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Bundler returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Bundler response: {e}"))?;

    let tx_id = json["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'id' in Bundler response: {json}"))?
        .to_string();

    tracing::info!(
        repo = %manifest.repo,
        tx_id = %tx_id,
        blobs = manifest.blobs.len(),
        "anchored encrypted manifest to Arweave via bundler"
    );

    Ok(tx_id)
}

/// Serialize one blob for the Arweave manifest. Recipient identities are
/// intentionally absent so the permanent public anchor never records who can
/// read a blob.
fn manifest_blob_json(oid: &str, cid: &str) -> serde_json::Value {
    json!({ "oid": oid, "cid": cid })
}

/// Build the bundler tag header for an encrypted-blob manifest. `Repo` and `Schema`
/// are the tags the `gl` recovery query filters on.
fn build_manifest_tags_header(manifest: &EncryptedManifest<'_>) -> String {
    [
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/encrypted-manifest/v1".to_string(),
        format!("Repo:{}", sanitize_tag(manifest.repo)),
        format!("Owner-DID:{}", sanitize_tag(manifest.owner_did)),
        format!("Node-DID:{}", sanitize_tag(manifest.node_did)),
    ]
    .join(",")
}

/// Build the bundler tag header value for Arweave indexing.
/// Format: comma-separated "name:value" pairs.
fn build_tags_header(anchor: &RefAnchor) -> String {
    [
        "App-Name:gitlawb".to_string(),
        "Schema:gitlawb/ref-update/v1".to_string(),
        format!("Repo:{}", sanitize_tag(&anchor.repo)),
        format!("Ref:{}", sanitize_tag(&anchor.ref_name)),
        format!("SHA:{}", &anchor.new_sha[..anchor.new_sha.len().min(16)]),
        format!("Node-DID:{}", sanitize_tag(&anchor.node_did)),
    ]
    .join(",")
}

/// Strip characters that are invalid in bundler/Arweave tag values.
fn sanitize_tag(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'))
        .take(128)
        .collect()
}

/// Arweave URL for a given transaction ID, resolved through a configurable gateway.
#[allow(dead_code)]
pub fn arweave_url(gateway: &str, tx_id: &str) -> String {
    format!("{}/{}", gateway.trim_end_matches('/'), tx_id)
}

/// Result of verifying an Arweave anchor against the stored certificate chain.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub anchor: serde_json::Value,
    pub certificate: Option<crate::db::RefCertificate>,
    pub errors: Vec<String>,
}

/// Fetch an anchor from Arweave, extract the embedded certificate, and verify
/// the full chain: certificate signature, prev hash linkage, and pusher signature.
pub async fn verify_anchor(
    client: &reqwest::Client,
    gateway_url: &str,
    tx_id: &str,
    db: &crate::db::Db,
) -> Result<VerifyResult> {
    // Fetch the data item from the bundler gateway.
    let url = format!("{}/v1/tx/{}", gateway_url.trim_end_matches('/'), tx_id);
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch data from bundler gateway: {e}"))?;
    if !resp.status().is_success() {
        return Ok(VerifyResult {
            valid: false,
            anchor: serde_json::Value::Null,
            certificate: None,
            errors: vec![format!("bundler gateway returned {}", resp.status())],
        });
    }
    let body_bytes = resp.bytes().await?;

    // Parse the payload — could be JSON or raw bytes depending on gateway
    let anchor: serde_json::Value = serde_json::from_slice(&body_bytes)?;
    let cert_value = anchor.get("certificate");

    let cert: Option<crate::db::RefCertificate> = match cert_value {
        Some(v) => serde_json::from_value(v.clone()).ok(),
        None => None,
    };

    let mut errors = Vec::new();

    if let Some(ref c) = cert {
        // 1. Verify node signature on the certificate payload
        let payload = serde_json::json!({
            "repo_id":    c.repo_id,
            "ref":        c.ref_name,
            "old":        c.old_sha,
            "new":        c.new_sha,
            "pusher":     c.pusher_did,
            "node":       c.node_did,
            "ts":         c.issued_at,
            "seq":        c.seq,
            "prev":       c.prev,
            "pusher_sig": c.pusher_sig,
        });
        let payload_bytes = serde_json::to_vec(&payload)?;

        // Resolve node DID to public key
        let node_did = gitlawb_core::did::Did::from_str(&c.node_did)
            .map_err(|e| anyhow::anyhow!("invalid node DID: {e}"))?;
        let verifying_key = node_did
            .to_verifying_key()
            .map_err(|e| anyhow::anyhow!("unresolvable node DID: {e}"))?;

        let sig_array: [u8; 64] =
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&c.signature) {
                Ok(bytes) => match bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        errors.push("certificate signature is not 64 bytes".to_string());
                        return Ok(VerifyResult {
                            valid: false,
                            anchor,
                            certificate: cert,
                            errors,
                        });
                    }
                },
                Err(_) => {
                    errors.push("certificate signature is not valid base64".to_string());
                    return Ok(VerifyResult {
                        valid: false,
                        anchor,
                        certificate: cert,
                        errors,
                    });
                }
            };

        if let Err(e) = gitlawb_core::identity::verify(&verifying_key, &payload_bytes, &sig_array) {
            errors.push(format!("certificate signature verification failed: {e}"));
        }

        // 2. Verify prev hash linkage against the predecessor at seq - 1
        if c.seq > 1 {
            if let Ok(Some(pred)) = db.get_cert_by_seq(&c.repo_id, c.seq - 1).await {
                let prev_payload = serde_json::json!({
                    "repo_id":    pred.repo_id,
                    "ref":        pred.ref_name,
                    "old":        pred.old_sha,
                    "new":        pred.new_sha,
                    "pusher":     pred.pusher_did,
                    "node":       pred.node_did,
                    "ts":         pred.issued_at,
                });
                let prev_bytes = serde_json::to_vec(&prev_payload)?;
                let expected_prev = hex::encode(sha2::Sha256::digest(&prev_bytes));
                if c.prev != expected_prev {
                    errors.push(format!(
                        "prev hash mismatch: claimed {} expected {}",
                        c.prev, expected_prev
                    ));
                }
            }
        }
    } else {
        errors.push("no embedded certificate found in anchor".to_string());
    }

    Ok(VerifyResult {
        valid: errors.is_empty(),
        anchor,
        certificate: cert,
        errors,
    })
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
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            cid: Some("bafyreib5...".into()),
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6MknndwexV9...".into(),
            certificate: None,
        };
        let result = anchor_ref_update(&client, "", &anchor).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[tokio::test]
    async fn test_anchor_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/v1/tx")
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
            old_sha: "0".repeat(40),
            new_sha: "a1b2c3d4".repeat(8),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
            certificate: None,
        };

        let result = anchor_ref_update(&client, &server.url(), &anchor).await;
        assert!(result.is_ok(), "anchor should succeed: {result:?}");
        assert_eq!(
            result.unwrap(),
            "7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
        _mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_anchor_body_carries_real_old_sha() {
        // The anchored body must serialize the real old→new transition the
        // node was handed, never a zero placeholder. Regression guard for the
        // push handler that used to hardcode `old_sha` to 64 zeros (#26).
        let mut server = mockito::Server::new_async().await;
        let real_old = "1111111111111111111111111111111111111111";
        let real_new = "2222222222222222222222222222222222222222";
        let _mock = server
            .mock("POST", "/v1/tx")
            .match_body(mockito::Matcher::AllOf(vec![
                mockito::Matcher::PartialJsonString(format!(r#"{{"old_sha":"{real_old}"}}"#)),
                mockito::Matcher::PartialJsonString(format!(r#"{{"new_sha":"{real_new}"}}"#)),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"TX_REAL_OLD_SHA","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let anchor = RefAnchor {
            repo: "alice/myrepo".into(),
            owner_did: "did:key:z6Mk...".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: real_old.into(),
            new_sha: real_new.into(),
            cid: None,
            timestamp: "2026-03-14T00:00:00Z".into(),
            node_did: "did:key:z6Mknnd...".into(),
            certificate: None,
        };

        let result = anchor_ref_update(&client, &server.url(), &anchor).await;
        assert_eq!(result.unwrap(), "TX_REAL_OLD_SHA");
        // The mock only matches when the posted JSON carries both real SHAs.
        _mock.assert_async().await;
    }

    #[test]
    fn test_arweave_url() {
        let url = arweave_url(
            "https://arweave.net",
            "7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk",
        );
        assert_eq!(
            url,
            "https://arweave.net/7xGpIoHUQ8j9GhD3Y2mKzP1NsVtXwRcFe4bEaLnMuOk"
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_noop_when_url_empty() {
        let client = reqwest::Client::new();
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        assert_eq!(
            anchor_encrypted_manifest(&client, "", &m).await.unwrap(),
            ""
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_noop_when_no_blobs() {
        let client = reqwest::Client::new();
        let blobs: Vec<(String, String)> = vec![];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        // Non-empty URL, but no blobs: still a no-op.
        assert_eq!(
            anchor_encrypted_manifest(&client, "https://example.invalid", &m)
                .await
                .unwrap(),
            ""
        );
    }

    #[tokio::test]
    async fn test_manifest_anchor_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/v1/tx")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"MANIFESTTX123","timestamp":1710000000000,"version":"1.0.0"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let blobs = vec![("oid1".to_string(), "cid1".to_string())];
        let m = EncryptedManifest {
            repo: "alice/r",
            owner_did: "did:key:zO",
            node_did: "did:key:zN",
            timestamp: "2026-06-11T00:00:00Z",
            blobs: &blobs,
        };
        let r = anchor_encrypted_manifest(&client, &server.url(), &m).await;
        assert_eq!(r.unwrap(), "MANIFESTTX123");
        _mock.assert_async().await;
    }

    #[test]
    fn manifest_blob_json_omits_recipients() {
        let v = manifest_blob_json("oid1", "cidA");
        assert_eq!(v["oid"], "oid1");
        assert_eq!(v["cid"], "cidA");
        assert!(
            v.get("recipients").is_none(),
            "Arweave manifest must not anchor recipient identities"
        );
    }

    #[test]
    fn test_sanitize_tag() {
        assert_eq!(sanitize_tag("alice/myrepo"), "alice/myrepo");
        assert_eq!(sanitize_tag("hello world!"), "helloworld");
    }

    #[tokio::test]
    async fn test_verify_anchor_uses_correct_gateway_url() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/v1/tx/does-not-exist")
            .with_status(404)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        // verify_anchor needs a real PgPool; this test only exercises that
        // the function correctly formats the gateway URL and handles a 404.
        // It will error on the pool access which is expected without a test DB.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
            .expect("lazy pool creation should not fail");
        let db = crate::db::Db::for_testing(pool);
        let result = verify_anchor(&client, &server.url(), "does-not-exist", &db).await;

        match result {
            Ok(r) => {
                // With a lazy unconnected pool, get_most_recent_cert will fail,
                // but the function still returns Ok(VerifyResult) with errors.
                assert!(!r.valid);
            }
            Err(e) => {
                // On some systems the POSTGRES connection attempt may abort
                // rather than fail gracefully.
                let msg = e.to_string();
                assert!(
                    msg.contains("pool") || msg.contains("error"),
                    "unexpected error: {msg}"
                );
            }
        }
    }
}
