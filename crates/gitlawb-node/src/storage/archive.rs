//! Repo-archive layer: stores a bare git repo as a single
//! `repos/v1/{owner_slug}/{repo_name}.tar.zst` object on top of any
//! [`BlobStore`] backend. Backend-agnostic replacement for the old
//! single-backend (Tigris-only) client.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result};
use bytes::Bytes;
use tracing::{debug, info};

use super::BlobStore;

#[derive(Clone)]
pub struct RepoArchive {
    store: Arc<dyn BlobStore>,
}

impl RepoArchive {
    pub fn new(store: Arc<dyn BlobStore>) -> Self {
        Self { store }
    }

    /// Object key for a repo archive.
    fn key(owner_slug: &str, repo_name: &str) -> String {
        format!("repos/v1/{owner_slug}/{repo_name}.tar.zst")
    }

    /// Current archive etag, or `None` if the repo isn't in storage yet.
    pub async fn head_etag(&self, owner_slug: &str, repo_name: &str) -> Result<Option<String>> {
        let key = Self::key(owner_slug, repo_name);
        Ok(self
            .store
            .head(&key)
            .await?
            .map(|m| m.etag.unwrap_or_else(|| format!("size:{}", m.size))))
    }

    /// Whether the repo archive exists in storage.
    pub async fn exists(&self, owner_slug: &str, repo_name: &str) -> Result<bool> {
        Ok(self
            .store
            .head(&Self::key(owner_slug, repo_name))
            .await?
            .is_some())
    }

    /// Compress the bare repo and upload it. Returns the new etag (for the
    /// skip-redundant-download cache).
    pub async fn upload(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
    ) -> Result<Option<String>> {
        let key = Self::key(owner_slug, repo_name);
        let archive_bytes = tokio::task::spawn_blocking({
            let local_path = local_path.to_path_buf();
            move || compress_repo(&local_path)
        })
        .await
        .context("tar task panicked")?
        .context("compressing repo")?;

        let meta = self
            .store
            .put(&key, Bytes::from(archive_bytes))
            .await
            .context("uploading repo archive")?;
        info!(key = %key, backend = self.store.backend_name(), "uploaded repo archive");
        Ok(meta.etag.or_else(|| Some(format!("size:{}", meta.size))))
    }

    /// Download the repo archive and extract it to `local_path` (atomic swap).
    pub async fn download(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
    ) -> Result<()> {
        let key = Self::key(owner_slug, repo_name);
        debug!(key = %key, "downloading repo archive");
        let data = self
            .store
            .get(&key)
            .await
            .context("fetching repo archive")?
            .ok_or_else(|| anyhow::anyhow!("repo archive missing: {key}"))?;

        tokio::task::spawn_blocking({
            let local_path = local_path.to_path_buf();
            move || decompress_repo(&data, &local_path)
        })
        .await
        .context("extract task panicked")?
        .context("extracting repo")?;
        info!(key = %key, path = %local_path.display(), "downloaded repo archive");
        Ok(())
    }

    /// Delete a repo archive.
    #[allow(dead_code)]
    pub async fn delete(&self, owner_slug: &str, repo_name: &str) -> Result<()> {
        self.store.delete(&Self::key(owner_slug, repo_name)).await
    }
}

/// Compress a bare repo directory into a tar.zst byte vector.
fn compress_repo(repo_path: &Path) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let encoder = zstd::stream::Encoder::new(buf, 3)?; // level 3 = fast + decent ratio
    let mut tar = tar::Builder::new(encoder);
    tar.append_dir_all(".", repo_path)
        .context("building tar archive")?;
    let encoder = tar.into_inner().context("finishing tar")?;
    let compressed = encoder.finish().context("finishing zstd")?;
    Ok(compressed)
}

/// Per-repo-path lock serializing the publish (swap-into-place) step of
/// `decompress_repo`. Concurrent extractions unpack into isolated temp dirs in
/// parallel, but the final `remove_dir_all` + `rename` must not interleave for
/// the same `local_path`, or they race to a nondeterministic overwrite/failure.
fn publish_lock(local_path: &Path) -> Arc<Mutex<()>> {
    // KNOWN LIMITATION: this map is never evicted — one (PathBuf, Arc<Mutex>)
    // entry accrues per distinct repo path for the process lifetime. Bounded by
    // the number of repos a node hosts, so it's negligible for normal use, but
    // high-volume/churning deployments may want LRU or weak-ref eviction here.
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = locks.lock().expect("publish lock map poisoned");
    map.entry(local_path.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Decompress a tar.zst byte vector into a local directory.
///
/// Extraction is atomic with respect to `local_path`: the archive is unpacked
/// into a sibling temp directory first, and only swapped into place once it
/// fully succeeds. A corrupt or truncated archive therefore can never clobber a
/// good existing copy at `local_path` — on failure we discard the temp dir and
/// leave `local_path` exactly as it was.
fn decompress_repo(data: &[u8], local_path: &Path) -> Result<()> {
    let parent = local_path.parent().context("repo path has no parent")?;
    std::fs::create_dir_all(parent).context("creating parent dir")?;

    let file_name = local_path
        .file_name()
        .context("repo path has no file name")?
        .to_string_lossy();
    // Unique per-extraction temp dir: a fixed name would let two concurrent
    // extractions of the same repo share one dir and clobber each other's
    // in-progress unpack. A fresh UUID also means it can't collide with a
    // leftover dir from a previously-interrupted run.
    let tmp_dir = parent.join(format!(".{file_name}.tmp-extract.{}", uuid::Uuid::new_v4()));

    std::fs::create_dir_all(&tmp_dir).context("creating temp extract dir")?;

    let unpack = (|| -> Result<()> {
        let decoder = zstd::stream::Decoder::new(data)?;
        let mut archive = tar::Archive::new(decoder);
        archive.unpack(&tmp_dir).context("unpacking tar.zst")?;
        Ok(())
    })();
    if let Err(e) = unpack {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(e);
    }

    // Swap the freshly-extracted repo into place. rename within the same parent
    // is effectively atomic, but most platforms refuse to rename onto a
    // non-empty dir, so remove the old copy first. Serialize this per repo path:
    // concurrent extractions unpack into isolated temp dirs, but their swaps
    // must not interleave or they race to a nondeterministic overwrite/failure.
    let lock = publish_lock(local_path);
    let _publish = lock.lock().expect("publish lock poisoned");
    let swap = (|| -> Result<()> {
        if local_path.exists() {
            std::fs::remove_dir_all(local_path).context("removing stale repo dir")?;
        }
        std::fs::rename(&tmp_dir, local_path).context("swapping extracted repo into place")?;
        Ok(())
    })();
    if swap.is_err() {
        // Don't leak the extracted temp dir if the swap failed.
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
    swap
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn seed_repo(dir: &std::path::Path) {
        fs::create_dir_all(dir.join("refs/heads")).unwrap();
        fs::write(dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(dir.join("refs/heads/main"), b"abc123\n").unwrap();
        fs::write(dir.join("config"), b"[core]\n\tbare = true\n").unwrap();
    }

    #[test]
    fn compress_decompress_round_trip_preserves_files() {
        let src = tempfile::tempdir().unwrap();
        seed_repo(src.path());

        let bytes = compress_repo(src.path()).unwrap();
        assert!(!bytes.is_empty());

        let out_parent = tempfile::tempdir().unwrap();
        let out = out_parent.path().join("restored.git");
        decompress_repo(&bytes, &out).unwrap();

        assert_eq!(
            fs::read(out.join("HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
        assert_eq!(fs::read(out.join("refs/heads/main")).unwrap(), b"abc123\n");
        assert_eq!(
            fs::read(out.join("config")).unwrap(),
            b"[core]\n\tbare = true\n"
        );
    }

    #[test]
    fn decompress_swap_replaces_existing_dir_atomically() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("HEAD"), b"new\n").unwrap();
        let bytes = compress_repo(src.path()).unwrap();

        // Pre-existing copy with stale junk that the swap must fully replace.
        let out_parent = tempfile::tempdir().unwrap();
        let out = out_parent.path().join("repo.git");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("STALE"), b"old\n").unwrap();

        decompress_repo(&bytes, &out).unwrap();
        assert_eq!(fs::read(out.join("HEAD")).unwrap(), b"new\n");
        assert!(
            !out.join("STALE").exists(),
            "stale content must be gone after the swap"
        );
    }

    #[test]
    fn decompress_corrupt_archive_leaves_existing_copy_untouched() {
        let out_parent = tempfile::tempdir().unwrap();
        let out = out_parent.path().join("repo.git");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("HEAD"), b"good\n").unwrap();

        // Garbage is not a valid tar.zst: unpack fails before the swap, so the
        // existing copy is preserved (atomicity claim).
        assert!(decompress_repo(b"not a real archive", &out).is_err());
        assert_eq!(fs::read(out.join("HEAD")).unwrap(), b"good\n");
    }

    #[tokio::test]
    async fn upload_download_round_trip_over_fs_backend() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn BlobStore> =
            Arc::new(crate::storage::fs::FsBlobStore::new(store_dir.path()).unwrap());
        let archive = RepoArchive::new(store);

        let src = tempfile::tempdir().unwrap();
        seed_repo(src.path());

        assert!(!archive.exists("owner", "repo").await.unwrap());
        let etag = archive.upload("owner", "repo", src.path()).await.unwrap();
        assert!(etag.is_some());
        assert!(archive.exists("owner", "repo").await.unwrap());

        let out_parent = tempfile::tempdir().unwrap();
        let out = out_parent.path().join("repo.git");
        archive.download("owner", "repo", &out).await.unwrap();
        assert_eq!(
            fs::read(out.join("HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
        assert_eq!(fs::read(out.join("refs/heads/main")).unwrap(), b"abc123\n");
    }
}
