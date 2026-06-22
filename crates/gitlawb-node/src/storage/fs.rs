//! Local filesystem blob backend.
//!
//! Stores each object as a file under a configured root directory, using the
//! object key as a relative path. For self-hosters without S3 and for tests of
//! the storage abstraction. The etag is a `size-mtime` fingerprint so the
//! skip-redundant-download optimization works against it.

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

    fn meta_of(path: &Path) -> Result<ObjectMeta> {
        let md = std::fs::metadata(path).context("stat blob")?;
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Ok(ObjectMeta {
            size: md.len(),
            etag: Some(format!("{}-{}", md.len(), mtime)),
        })
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
        let tmp = path.with_extension("tmp-put");
        let path2 = path.clone();
        // Atomic write: temp file in the same dir, then rename into place.
        tokio::task::spawn_blocking(move || -> Result<()> {
            std::fs::create_dir_all(&parent).context("creating blob parent dir")?;
            std::fs::write(&tmp, &body).context("writing temp blob")?;
            std::fs::rename(&tmp, &path2).context("renaming blob into place")?;
            Ok(())
        })
        .await
        .context("fs put task panicked")??;
        Self::meta_of(&path)
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let path = self.path_for(key)?;
        match Self::meta_of(&path) {
            Ok(m) => Ok(Some(m)),
            Err(_) if !path.exists() => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context(format!("deleting {}", path.display())),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let root = self.root.clone();
        let prefix = prefix.to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let mut keys = Vec::new();
            let mut stack = vec![root.clone()];
            while let Some(dir) = stack.pop() {
                let rd = match std::fs::read_dir(&dir) {
                    Ok(rd) => rd,
                    Err(_) => continue,
                };
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if let Ok(rel) = path.strip_prefix(&root) {
                        let key = rel.to_string_lossy().replace('\\', "/");
                        if key.starts_with(&prefix) {
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
    async fn rejects_key_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsBlobStore::new(dir.path()).unwrap();
        assert!(store.get("../escape").await.is_err());
        assert!(store.put("a/../../etc/passwd", Bytes::new()).await.is_err());
    }
}
