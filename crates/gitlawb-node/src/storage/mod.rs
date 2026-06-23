//! Storage-agnostic blob layer.
//!
//! Repos are persisted to a pluggable object store behind the [`BlobStore`]
//! trait. Backends:
//!   - [`s3::S3BlobStore`]  — any S3-compatible service (Tigris, Cloudflare R2,
//!     AWS S3, MinIO, Backblaze B2). Selected by default when a bucket is set.
//!   - [`fs::FsBlobStore`]  — a local/mounted directory; for self-hosters & tests.
//!   - [`ipfs::IpfsBlobStore`] — content-addressed storage over a Kubo (IPFS) node
//!     using its Mutable File System (MFS) for a key→blob namespace.
//!
//! Higher layers ([`archive::RepoArchive`]) compose a bare repo into a single
//! `repos/v1/{slug}/{repo}.tar.zst` object on top of whichever backend is active,
//! so the repo-storage semantics are identical regardless of backend.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use tracing::info;

use crate::config::Config;

pub mod archive;
pub mod fs;
pub mod ipfs;
pub mod s3;

/// Metadata about a stored object. `etag` is an opaque change-detection token
/// (S3 ETag, IPFS CID, or a size/mtime fingerprint for the filesystem backend).
#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub size: u64,
    pub etag: Option<String>,
}

/// A backend-agnostic key→bytes object store.
///
/// Keys are forward-slash-delimited paths (e.g. `repos/v1/slug/repo.tar.zst`).
/// Implementations must reject `..` traversal in keys.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Short backend name, for logs.
    fn backend_name(&self) -> &'static str;

    /// Fetch an object. Returns `None` if the key does not exist.
    async fn get(&self, key: &str) -> Result<Option<Bytes>>;

    /// Store an object, returning its metadata (including the new etag).
    async fn put(&self, key: &str, body: Bytes) -> Result<ObjectMeta>;

    /// Fetch object metadata without the body. Returns `None` if absent.
    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>>;

    /// Delete an object. Succeeds (no-op) if the key does not exist.
    async fn delete(&self, key: &str) -> Result<()>;

    /// List object keys under a prefix. Part of the backend interface (and
    /// implemented by every backend) for future admin/GC/migration use; not yet
    /// wired to a caller, hence the allow.
    #[allow(dead_code)]
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// Build the configured blob store.
///
/// Returns `Ok(None)` only when no backend is configured at all (local-only
/// passthrough mode). A misconfigured backend (missing required setting, or a
/// client that fails to construct) returns `Err`: we fail closed rather than
/// silently degrading to local-only, which would accept writes without the
/// intended durable backend and risk cross-node persistence drift.
///
/// Note: this validates configuration and client construction, not live
/// connectivity — e.g. the S3 client builds successfully against an unreachable
/// or wrong bucket, and that surfaces as an error on the first real request.
///
/// Selection order:
///   1. Explicit `GITLAWB_STORAGE_BACKEND` (`s3` | `fs` | `ipfs`).
///   2. Auto: `s3` if a bucket is configured (incl. legacy `GITLAWB_TIGRIS_BUCKET`),
///      else `fs` if `GITLAWB_STORAGE_FS_DIR` is set,
///      else `ipfs` if `GITLAWB_IPFS_API` is set,
///      else local-only.
pub async fn build(config: &Config) -> Result<Option<Arc<dyn BlobStore>>> {
    let bucket = if !config.s3_bucket.is_empty() {
        config.s3_bucket.clone()
    } else {
        config.tigris_bucket.clone()
    };

    let backend = if !config.storage_backend.is_empty() {
        config.storage_backend.to_ascii_lowercase()
    } else if !bucket.is_empty() {
        "s3".to_string()
    } else if !config.storage_fs_dir.is_empty() {
        "fs".to_string()
    } else if !config.ipfs_api.is_empty() {
        "ipfs".to_string()
    } else {
        info!("object storage disabled (no backend configured) — local-only mode");
        return Ok(None);
    };

    // A backend was selected (explicitly or by auto-detection); fail closed from
    // here — a missing required setting or an init failure is a hard error.
    match backend.as_str() {
        "s3" => {
            if bucket.is_empty() {
                anyhow::bail!(
                    "storage backend=s3 but no bucket configured (set GITLAWB_S3_BUCKET)"
                );
            }
            let endpoint = (!config.s3_endpoint.is_empty()).then(|| config.s3_endpoint.clone());
            let s = s3::S3BlobStore::new(&bucket, endpoint, config.s3_force_path_style)
                .await
                .context("initializing S3 storage")?;
            info!(bucket = %bucket, backend = "s3", "object storage enabled");
            Ok(Some(Arc::new(s) as Arc<dyn BlobStore>))
        }
        "fs" => {
            if config.storage_fs_dir.is_empty() {
                anyhow::bail!("storage backend=fs but GITLAWB_STORAGE_FS_DIR is empty");
            }
            let s = fs::FsBlobStore::new(&config.storage_fs_dir)
                .context("initializing filesystem storage")?;
            info!(dir = %config.storage_fs_dir, backend = "fs", "object storage enabled");
            Ok(Some(Arc::new(s) as Arc<dyn BlobStore>))
        }
        "ipfs" => {
            if config.ipfs_api.is_empty() {
                anyhow::bail!("storage backend=ipfs but GITLAWB_IPFS_API is empty");
            }
            let s =
                ipfs::IpfsBlobStore::new(&config.ipfs_api).context("initializing IPFS storage")?;
            info!(api = %config.ipfs_api, backend = "ipfs", "object storage enabled");
            Ok(Some(Arc::new(s) as Arc<dyn BlobStore>))
        }
        other => {
            anyhow::bail!("unknown GITLAWB_STORAGE_BACKEND: {other}");
        }
    }
}

/// Reject keys that could escape the namespace (`..`) or are absolute.
pub(crate) fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        anyhow::bail!("blob key is empty");
    }
    if key.split('/').any(|seg| seg == ".." || seg == ".") {
        anyhow::bail!("blob key contains traversal segment: {key}");
    }
    if key.starts_with('/') || key.contains('\0') {
        anyhow::bail!("blob key is absolute or contains null byte: {key}");
    }
    Ok(())
}
