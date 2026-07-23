//! Local filesystem blob backend.
//!
//! Stores each object as a file under a configured root directory, using the
//! object key as a relative path. For self-hosters without S3 and for tests of
//! the storage abstraction. The etag is a fresh UUID persisted in a `.etag`
//! sidecar on every write, so the skip-redundant-download optimization can rely
//! on "etag unchanged ⇒ content unchanged" even on filesystems with coarse
//! timestamps (objects predating the sidecar fall back to size-mtime).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;

use super::{validate_key, BlobStore, ObjectMeta};

#[derive(Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating storage dir {}", root.display()))?;
        Ok(Self { root })
    }

    fn path_for(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        let path = self.root.join(key);
        // Defence in depth: the resolved path must stay under root.
        if !path.starts_with(&self.root) {
            anyhow::bail!("blob key escaped storage root: {key}");
        }
        Ok(path)
    }

    /// Sidecar file persisting the object's etag: a fresh UUID per `put`.
    /// RepoStore treats etag equality as proof the local copy is current, so
    /// the token must change on EVERY write. A `size-mtime` fingerprint cannot
    /// guarantee that on mounted filesystems with coarse timestamp precision
    /// (two same-size writes in one tick collide); a per-write UUID can.
    fn sidecar_of(path: &Path) -> PathBuf {
        let mut os = path.as_os_str().to_owned();
        os.push(".etag");
        PathBuf::from(os)
    }

    /// Fallback fingerprint for objects written before the sidecar existed.
    fn legacy_etag(md: &std::fs::Metadata) -> String {
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}-{}", md.len(), mtime)
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    fn backend_name(&self) -> &'static str {
        "fs"
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>> {
        let path = self.path_for(key)?;
        match tokio::fs::read(&path).await {
            Ok(data) => Ok(Some(Bytes::from(data))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context(format!("reading {}", path.display())),
        }
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<ObjectMeta> {
        let path = self.path_for(key)?;
        let parent = path
            .parent()
            .context("blob path has no parent")?
            .to_path_buf();
        // Unique temp name per write: a fixed suffix would let concurrent puts
        // to the same key overwrite each other's temp file and corrupt the blob.
        let tmp = path.with_extension(format!("{}.tmp-put", uuid::Uuid::new_v4()));
        let path2 = path.clone();
        // Atomic write: temp file in the same dir, then rename into place. On any
        // failure, remove the temp file so a failed write can't leak it. The
        // trailing stat + etag-sidecar write run inside the same blocking task —
        // no synchronous fs call ever touches the async runtime.
        tokio::task::spawn_blocking(move || -> Result<ObjectMeta> {
            std::fs::create_dir_all(&parent).context("creating blob parent dir")?;
            let write_and_swap = (|| -> Result<()> {
                std::fs::write(&tmp, &body).context("writing temp blob")?;
                std::fs::rename(&tmp, &path2).context("renaming blob into place")?;
                Ok(())
            })();
            if let Err(e) = write_and_swap {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
            let md = std::fs::metadata(&path2).context("stat blob after write")?;
            // Persist a fresh per-write etag; see `sidecar_of` for why
            // size-mtime is not collision-resistant enough here.
            let etag = uuid::Uuid::new_v4().to_string();
            std::fs::write(Self::sidecar_of(&path2), &etag).context("writing etag sidecar")?;
            Ok(ObjectMeta {
                size: md.len(),
                etag: Some(etag),
            })
        })
        .await
        .context("fs put task panicked")?
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let path = self.path_for(key)?;
        // Probe existence by io error kind, not path.exists(): a permission/IO
        // error must surface, not be silently reported as "not found".
        let md = match tokio::fs::metadata(&path).await {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context(format!("stat {}", path.display())),
        };
        let etag = match tokio::fs::read_to_string(Self::sidecar_of(&path)).await {
            Ok(tag) => tag.trim().to_string(),
            // Object written before the sidecar existed — legacy fingerprint.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::legacy_etag(&md),
            Err(e) => {
                return Err(e).context(format!("reading etag sidecar for {}", path.display()))
            }
        };
        Ok(Some(ObjectMeta {
            size: md.len(),
            etag: Some(etag),
        }))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context(format!("deleting {}", path.display())),
        }
        match tokio::fs::remove_file(Self::sidecar_of(&path)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context(format!("deleting etag sidecar for {}", path.display())),
        }
    }
}

/// Test-only helper: enumerate stored keys. `list` was dropped from the
/// `BlobStore` trait until a production consumer (GC/admin/migration) exists;
/// the tests here still need it to assert on stored state.
#[cfg(test)]
impl FsBlobStore {
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let root = self.root.clone();
        let prefix = prefix.to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut keys = Vec::new();
            let mut stack = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                // Propagate read errors rather than skipping: a partial listing
                // reported as success would mislead GC/admin/migration callers.
                let rd = std::fs::read_dir(&dir)
                    .with_context(|| format!("listing {}", dir.display()))?;
                for entry in rd {
                    // Propagate per-entry errors rather than dropping them via
                    // flatten(): a partial listing must not look like success.
                    let entry =
                        entry.with_context(|| format!("reading entry under {}", dir.display()))?;
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if let Ok(rel) = path.strip_prefix(&root) {
                        let key = rel.to_string_lossy().replace('\\', "/");
                        // Etag sidecars are backend metadata, not objects.
                        if key.starts_with(&prefix) && !key.ends_with(".etag") {
                            keys.push(key);
                        }
                    }
                }
            }
            Ok(keys)
        })
        .await
        .context("fs list task panicked")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_get_head_delete_list_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::new(dir.path()).unwrap();

        // Absent key
        assert!(store.get("repos/v1/a/x.tar.zst").await.unwrap().is_none());
        assert!(store.head("repos/v1/a/x.tar.zst").await.unwrap().is_none());

        // Put then get
        let body = Bytes::from_static(b"hello blob");
        let meta = store
            .put("repos/v1/a/x.tar.zst", body.clone())
            .await
            .unwrap();
        assert_eq!(meta.size, body.len() as u64);
        assert!(meta.etag.is_some());
        let got = store.get("repos/v1/a/x.tar.zst").await.unwrap().unwrap();
        assert_eq!(got, body);

        // Head returns matching etag (stable across reads)
        let h = store.head("repos/v1/a/x.tar.zst").await.unwrap().unwrap();
        assert_eq!(h.etag, meta.etag);

        // List by prefix
        store
            .put("repos/v1/b/y.tar.zst", Bytes::from_static(b"y"))
            .await
            .unwrap();
        let mut keys = store.list("repos/v1/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["repos/v1/a/x.tar.zst", "repos/v1/b/y.tar.zst"]);

        // Delete is idempotent
        store.delete("repos/v1/a/x.tar.zst").await.unwrap();
        store.delete("repos/v1/a/x.tar.zst").await.unwrap();
        assert!(store.get("repos/v1/a/x.tar.zst").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rewrite_always_changes_etag_even_for_identical_content() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::new(dir.path()).unwrap();
        let key = "repos/v1/a/x.tar.zst";
        let body = Bytes::from_static(b"same bytes");

        // Two writes of identical content back-to-back: a size-mtime
        // fingerprint can collide inside one timestamp tick on coarse
        // filesystems; the persisted per-write etag must always differ.
        let m1 = store.put(key, body.clone()).await.unwrap();
        let m2 = store.put(key, body).await.unwrap();
        assert_ne!(m1.etag, m2.etag, "every put must produce a new etag");

        // head() reports the latest persisted etag.
        let h = store.head(key).await.unwrap().unwrap();
        assert_eq!(h.etag, m2.etag);

        // delete() removes the sidecar with the object.
        store.delete(key).await.unwrap();
        assert!(store.head(key).await.unwrap().is_none());
        assert!(store.list("repos/v1/").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejects_key_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::new(dir.path()).unwrap();
        assert!(store.get("../escape").await.is_err());
        assert!(store.put("a/../../etc/passwd", Bytes::new()).await.is_err());
        // Backslashes are separators on Windows — must be rejected as keys.
        assert!(store.get("a\\..\\escape").await.is_err());
        assert!(store.put("repos\\v1\\x", Bytes::new()).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_puts_same_key_do_not_corrupt_or_leak_temps() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::new(dir.path()).unwrap();
        let key = "repos/v1/a/x.tar.zst";
        let body = Bytes::from_static(b"the-one-true-blob");

        // Many concurrent writers of the same key: with a fixed temp name they
        // would clobber each other's temp file mid-write and corrupt the result.
        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            let body = body.clone();
            handles.push(tokio::spawn(async move { store.put(key, body).await }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }

        // Final content is intact...
        assert_eq!(store.get(key).await.unwrap().unwrap(), body);
        // ...and no unique-suffixed temp files were left behind.
        let leftovers: Vec<String> = store
            .list("repos/v1/")
            .await
            .unwrap()
            .into_iter()
            .filter(|k| k.contains("tmp-put"))
            .collect();
        assert!(leftovers.is_empty(), "leaked temp files: {leftovers:?}");
    }
}
