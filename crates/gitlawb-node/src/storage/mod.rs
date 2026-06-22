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

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use tracing::{info, warn};

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

/// Build the configured blob store, or `None` for local-only (passthrough) mode.
///
/// Selection order:
///   1. Explicit `GITLAWB_STORAGE_BACKEND` (`s3` | `fs` | `ipfs`).
///   2. Auto: `s3` if a bucket is configured (incl. legacy `GITLAWB_TIGRIS_BUCKET`),
///      else `fs` if a storage dir is set, else local-only.
pub async fn build(config: &Config) -> Option<Arc<dyn BlobStore>> {
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
        return None;
    };

    match backend.as_str() {
        "s3" => {
            if bucket.is_empty() {
                warn!("storage backend=s3 but no bucket configured — local-only mode");
                return None;
            }
            let endpoint = (!config.s3_endpoint.is_empty()).then(|| config.s3_endpoint.clone());
            match s3::S3BlobStore::new(&bucket, endpoint, config.s3_force_path_style).await {
                Ok(s) => {
                    info!(bucket = %bucket, backend = "s3", "object storage enabled");
                    Some(Arc::new(s) as Arc<dyn BlobStore>)
                }
                Err(e) => {
                    warn!(err = %e, "failed to init S3 storage — local-only mode");
                    None
                }
            }
        }
        "fs" => {
            if config.storage_fs_dir.is_empty() {
                warn!("storage backend=fs but GITLAWB_STORAGE_FS_DIR is empty — local-only mode");
                return None;
            }
            match fs::FsBlobStore::new(&config.storage_fs_dir) {
                Ok(s) => {
                    info!(dir = %config.storage_fs_dir, backend = "fs", "object storage enabled");
                    Some(Arc::new(s) as Arc<dyn BlobStore>)
                }
                Err(e) => {
                    warn!(err = %e, "failed to init filesystem storage — local-only mode");
                    None
                }
            }
        }
        "ipfs" => {
            if config.ipfs_api.is_empty() {
                warn!("storage backend=ipfs but GITLAWB_IPFS_API is empty — local-only mode");
                return None;
            }
            match ipfs::IpfsBlobStore::new(&config.ipfs_api) {
                Ok(s) => {
                    info!(api = %config.ipfs_api, backend = "ipfs", "object storage enabled");
                    Some(Arc::new(s) as Arc<dyn BlobStore>)
                }
                Err(e) => {
                    warn!(err = %e, "failed to init IPFS storage — local-only mode");
                    None
                }
            }
        }
        other => {
            warn!(backend = %other, "unknown GITLAWB_STORAGE_BACKEND — local-only mode");
            None
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
