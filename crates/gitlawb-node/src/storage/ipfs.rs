//! IPFS (content-addressed) blob backend over a Kubo node's Mutable File System.
//!
//! Kubo's MFS (`/api/v0/files/*`) provides a path-addressed, mutable namespace
//! backed by content-addressed IPFS objects — a natural fit for a key→blob store.
//! Each object's etag is its IPFS CID (from `files/stat`), giving true
//! content-addressing for the skip-redundant-download optimization.
//!
//! Requires a reachable Kubo HTTP API (`GITLAWB_IPFS_API`, e.g.
//! `http://127.0.0.1:5001`). Objects written here are also retrievable by CID
//! from the wider IPFS network once pinned/announced by the node.

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;

use super::{validate_key, BlobStore, ObjectMeta};

#[derive(Clone)]
pub struct IpfsBlobStore {
    api: String,
    client: reqwest::Client,
}

impl IpfsBlobStore {
    pub fn new(api: &str) -> Result<Self> {
        // Bound requests so an unresponsive Kubo API can't hang push/write flows
        // indefinitely. connect_timeout guards the dial; the generous total
        // timeout still allows large repo-archive transfers.
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .context("building IPFS HTTP client")?;
        Ok(Self {
            api: api.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// MFS path for a key: `/gitlawb/<key>` (namespaced to avoid clobbering
    /// other MFS users on a shared node).
    fn mfs_path(key: &str) -> String {
        format!("/gitlawb/{key}")
    }
}

#[async_trait]
impl BlobStore for IpfsBlobStore {
    fn backend_name(&self) -> &'static str {
        "ipfs"
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        validate_key(key)?;
        let url = format!("{}/api/v0/files/read", self.api);
        let resp = self
            .client
            .post(&url)
            .query(&[("arg", Self::mfs_path(key).as_str())])
            .send()
            .await
            .context("IPFS files/read")?;
        if resp.status().is_success() {
            Ok(Some(resp.bytes().await.context("reading IPFS body")?))
        } else {
            // Kubo returns 500 with a JSON message when the path is absent.
            let body = resp.text().await.unwrap_or_default();
            if body.contains("does not exist") || body.contains("no link named") {
                Ok(None)
            } else {
                anyhow::bail!("IPFS files/read {key}: {body}")
            }
        }
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<ObjectMeta> {
        validate_key(key)?;
        let size = body.len() as u64;
        let url = format!("{}/api/v0/files/write", self.api);
        // Stream the body instead of copying it via to_vec — avoids doubling
        // peak memory for large archives. Length is known, so set it explicitly.
        let part = reqwest::multipart::Part::stream_with_length(reqwest::Body::from(body), size)
            .file_name("blob");
        let form = reqwest::multipart::Form::new().part("data", part);
        let resp = self
            .client
            .post(&url)
            .query(&[
                ("arg", Self::mfs_path(key).as_str()),
                ("create", "true"),
                ("parents", "true"),
                ("truncate", "true"),
            ])
            .multipart(form)
            .send()
            .await
            .context("IPFS files/write")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let b = resp.text().await.unwrap_or_default();
            anyhow::bail!("IPFS files/write {key} returned {status}: {b}");
        }
        // etag = CID from stat
        let etag = self.head(key).await?.and_then(|m| m.etag);
        Ok(ObjectMeta { size, etag })
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        validate_key(key)?;
        let url = format!("{}/api/v0/files/stat", self.api);
        let resp = self
            .client
            .post(&url)
            .query(&[("arg", Self::mfs_path(key).as_str())])
            .send()
            .await
            .context("IPFS files/stat")?;
        if resp.status().is_success() {
            let v: serde_json::Value = resp.json().await.context("parsing files/stat")?;
            Ok(Some(ObjectMeta {
                size: v.get("Size").and_then(|s| s.as_u64()).unwrap_or(0),
                etag: v
                    .get("Hash")
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string()),
            }))
        } else {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("does not exist") || body.contains("no link named") {
                Ok(None)
            } else {
                anyhow::bail!("IPFS files/stat {key}: {body}")
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        let url = format!("{}/api/v0/files/rm", self.api);
        let resp = self
            .client
            .post(&url)
            .query(&[("arg", Self::mfs_path(key).as_str()), ("force", "true")])
            .send()
            .await
            .context("IPFS files/rm")?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("does not exist") || body.contains("no link named") {
                Ok(())
            } else {
                anyhow::bail!("IPFS files/rm {key}: {body}")
            }
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        // Best-effort recursive walk of the MFS subtree under `prefix`.
        let mut keys = Vec::new();
        let mut stack = vec![prefix.trim_end_matches('/').to_string()];
        while let Some(rel) = stack.pop() {
            let url = format!("{}/api/v0/files/ls", self.api);
            let mfs = if rel.is_empty() {
                "/gitlawb".to_string()
            } else {
                Self::mfs_path(&rel)
            };
            let resp = self
                .client
                .post(&url)
                .query(&[("arg", mfs.as_str()), ("long", "true")])
                .send()
                .await
                .context("IPFS files/ls")?;
            if !resp.status().is_success() {
                // Distinguish "this subtree doesn't exist" (fine — nothing to
                // list) from real auth/network/server errors, which must surface
                // rather than masquerade as an empty listing.
                let body = resp.text().await.unwrap_or_default();
                if body.contains("does not exist") || body.contains("no link named") {
                    continue;
                }
                anyhow::bail!("IPFS files/ls {mfs}: {body}");
            }
            let v: serde_json::Value = resp.json().await.context("parsing files/ls")?;
            if let Some(entries) = v.get("Entries").and_then(|e| e.as_array()) {
                for entry in entries {
                    let name = entry.get("Name").and_then(|n| n.as_str()).unwrap_or("");
                    if name.is_empty() {
                        continue;
                    }
                    let child = if rel.is_empty() {
                        name.to_string()
                    } else {
                        format!("{rel}/{name}")
                    };
                    // Type 1 = directory in Kubo's MFS ls.
                    if entry.get("Type").and_then(|t| t.as_u64()) == Some(1) {
                        stack.push(child);
                    } else {
                        keys.push(child);
                    }
                }
            }
        }
        Ok(keys)
    }
}
