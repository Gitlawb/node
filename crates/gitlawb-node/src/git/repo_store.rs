//! Centralized repo storage layer — local disk cache backed by a pluggable
//! object store (S3-compatible / filesystem / IPFS) via [`RepoArchive`].
//!
//! Every handler that needs access to a git repo on disk goes through `RepoStore`:
//!
//! - `acquire()` — ensures the repo is on local disk (downloads on cache miss).
//! - `acquire_write()` — write lock + ensures local matches storage (skips the
//!   download when the cached etag already matches — the push-latency win).
//! - `release()` / `release_after_write()` — upload the updated repo to storage.
//! - `init()` — creates a new bare repo locally and uploads to storage.
//!
//! When no backend is configured, this is a simple passthrough to local disk.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::store;
use crate::storage::archive::RepoArchive;

/// Centralized repo storage: local disk cache + optional object-storage backend
/// (S3-compatible / filesystem / IPFS) behind the [`RepoArchive`] layer.
#[derive(Clone)]
pub struct RepoStore {
    repos_dir: PathBuf,
    archive: Option<RepoArchive>,
    /// Shared Postgres pool for advisory locks.
    pool: PgPool,
    /// Tracks repos already confirmed to exist in storage — avoids redundant
    /// HEAD checks and background uploads for repos we've already migrated.
    migrated: Arc<Mutex<HashSet<String>>>,
    /// Last-known archive etag per `owner_slug/repo` key. Lets a write skip the
    /// pre-write download when our local copy already matches storage (the
    /// common case under sticky routing) — the main push-latency win.
    versions: Arc<Mutex<HashMap<String, String>>>,
}

impl RepoStore {
    #[cfg(test)]
    pub fn for_testing(repos_dir: PathBuf, pool: PgPool) -> Self {
        Self {
            repos_dir,
            archive: None,
            pool,
            migrated: Arc::new(Mutex::new(HashSet::new())),
            versions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn new(repos_dir: PathBuf, archive: Option<RepoArchive>, pool: PgPool) -> Self {
        Self {
            repos_dir,
            archive,
            pool,
            migrated: Arc::new(Mutex::new(HashSet::new())),
            versions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Ensure the local copy matches storage, skipping the download when our
    /// cached etag already equals the current archive etag.
    ///
    /// `require_fresh` selects the failure policy:
    /// - `false` (read path, `acquire_fresh`): self-heal — if a storage HEAD or
    ///   download fails but a valid local copy exists, use it; a later upload
    ///   re-syncs storage.
    /// - `true` (write path, `acquire_write`): fail closed — never fall back to
    ///   a possibly-stale local copy. The remote etag differs (remote is newer),
    ///   so uploading our stale copy after the write would clobber it (lost
    ///   update). Propagate the error so the write is rejected instead.
    async fn sync_down_if_stale(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
        require_fresh: bool,
    ) -> Result<()> {
        let Some(ref archive) = self.archive else {
            return Ok(());
        };
        let key = format!("{owner_slug}/{repo_name}");

        let remote_etag = match archive.head_etag(owner_slug, repo_name).await {
            Ok(Some(etag)) => etag,
            Ok(None) => return Ok(()), // not in storage yet — local is authoritative
            Err(e) => {
                // HEAD failed. Read path: fall back to a valid local copy if we
                // have one. Write path: fail closed (see `require_fresh`).
                if !require_fresh && local_path.exists() {
                    warn!(repo = %repo_name, err = %e, "storage head failed — using local copy");
                    return Ok(());
                }
                return Err(e).context("storage head before access");
            }
        };

        if local_path.exists() {
            let known = self.versions.lock().await.get(&key).cloned();
            if known.as_deref() == Some(remote_etag.as_str()) {
                debug!(repo = %repo_name, "local copy current (etag match) — skipping download");
                return Ok(());
            }
        }

        match archive.download(owner_slug, repo_name, local_path).await {
            Ok(()) => {
                self.versions.lock().await.insert(key, remote_etag);
                Ok(())
            }
            Err(e) => {
                // Read path self-heal only: a corrupt/unreadable archive must not
                // block access when a valid local copy exists. On the write path
                // the remote etag differs (remote is newer), so falling back and
                // later uploading our stale copy would clobber it — fail closed.
                if !require_fresh && local_path.exists() {
                    warn!(repo = %repo_name, err = %e,
                        "archive download failed — falling back to local copy");
                    Ok(())
                } else {
                    Err(e).context("downloading repo archive")
                }
            }
        }
    }

    /// Ensure a repo is available on local disk, downloading from storage if needed.
    /// If the repo exists locally but not yet in storage, a background upload is
    /// spawned to lazily migrate it (on-demand migration for pre-storage repos).
    /// Returns the local path to the bare repo.
    pub async fn acquire(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        // Fast path: repo exists locally
        if local_path.exists() {
            // Lazy migration: if storage is enabled and we haven't confirmed this
            // repo is in storage yet, check and upload in the background.
            if let Some(ref archive) = self.archive {
                let key = format!("{owner_slug}/{repo_name}");
                let already_migrated = self.migrated.lock().await.contains(&key);
                if !already_migrated {
                    let archive = archive.clone();
                    let slug = owner_slug.clone();
                    let name = repo_name.to_string();
                    let path = local_path.clone();
                    let migrated = Arc::clone(&self.migrated);
                    let versions = Arc::clone(&self.versions);
                    tokio::spawn(async move {
                        // Check if already in storage before uploading
                        match archive.exists(&slug, &name).await {
                            Ok(true) => {
                                debug!(repo = %name, "repo already in storage — skipping migration");
                            }
                            Ok(false) => {
                                info!(repo = %name, "migrating local repo to storage");
                                match archive.upload(&slug, &name, &path).await {
                                    Ok(etag) => {
                                        if let Some(etag) = etag {
                                            versions
                                                .lock()
                                                .await
                                                .insert(format!("{slug}/{name}"), etag);
                                        }
                                        info!(repo = %name, "lazy migration to storage complete");
                                    }
                                    Err(e) => {
                                        warn!(repo = %name, err = %e, "lazy migration to storage failed");
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(repo = %name, err = %e, "storage existence check failed");
                                return;
                            }
                        }
                        migrated.lock().await.insert(format!("{slug}/{name}"));
                    });
                }
            }
            return Ok(local_path);
        }

        // Try downloading from storage
        if let Some(ref archive) = self.archive {
            if let Some(remote_etag) = archive
                .head_etag(&owner_slug, repo_name)
                .await
                .context("checking storage for repo")?
            {
                debug!(repo = %repo_name, "cache miss — downloading from storage");
                archive
                    .download(&owner_slug, repo_name, &local_path)
                    .await
                    .context("downloading repo from storage")?;
                let key = format!("{owner_slug}/{repo_name}");
                self.migrated.lock().await.insert(key.clone());
                self.versions.lock().await.insert(key, remote_etag);
                return Ok(local_path);
            }
        }

        // Not found anywhere — return path anyway; caller will get a meaningful
        // error from git when the path doesn't exist.
        Ok(local_path)
    }

    /// Ensure a repo is available on local disk with the **latest** storage state.
    /// Use this for operations that precede a write (e.g. `info/refs` for
    /// `git-receive-pack`) so the client sees the same refs that `acquire_write()`
    /// will operate on.
    pub async fn acquire_fresh(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;
        self.sync_down_if_stale(&owner_slug, repo_name, &local_path, false)
            .await?;
        Ok(local_path)
    }

    /// Take a write lock (Postgres advisory lock), ensure repo is local, return guard.
    /// The lock prevents concurrent writes to the same repo across machines.
    pub async fn acquire_write(&self, owner_did: &str, repo_name: &str) -> Result<RepoWriteGuard> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;
        let lock_key = advisory_lock_key(&owner_slug, repo_name);

        // Postgres advisory locks are SESSION-scoped: they bind to one backend
        // connection and only release on that same connection. With a pool,
        // acquiring and releasing on different checked-out connections means the
        // unlock silently no-ops while the lock lingers on the original. So we
        // pin ONE connection for the whole lock lifetime — acquire, release on
        // sync error, and the final release in the guard all run on it.
        let mut conn = self
            .pool
            .acquire()
            .await
            .context("acquiring db connection for advisory lock")?;

        // Acquire with retry using pg_try_advisory_lock to avoid blocking
        // indefinitely on stale locks from crashed connections.
        let mut acquired = false;
        for attempt in 0..60 {
            let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *conn)
                .await
                .context("trying advisory lock")?;
            if row.0 {
                acquired = true;
                break;
            }
            if attempt < 59 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        if !acquired {
            anyhow::bail!("could not acquire advisory lock after 60s — possible stale lock for {owner_slug}/{repo_name}");
        }

        // Ensure local matches the latest in storage before writing. The etag
        // cache skips the full download when our copy is already current (the
        // common single-machine case under sticky routing); a stale copy (another
        // machine pushed since) still triggers a download. The advisory lock above
        // serializes this so the post-write upload can't race a concurrent writer.
        if let Err(e) = self
            .sync_down_if_stale(&owner_slug, repo_name, &local_path, true)
            .await
        {
            // Release the lock on the SAME connection before bailing.
            if let Err(unlock_err) = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(lock_key)
                .execute(&mut *conn)
                .await
            {
                warn!(repo = %repo_name, err = %unlock_err,
                    "failed to release advisory lock after sync error");
            }
            return Err(e);
        }

        Ok(RepoWriteGuard {
            owner_slug,
            repo_name: repo_name.to_string(),
            local_path,
            lock_key,
            conn,
            archive: self.archive.clone(),
            versions: Arc::clone(&self.versions),
        })
    }

    /// Initialize a new bare repo on local disk and upload to storage.
    pub async fn init(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        store::init_bare(&local_path).context("initializing bare repo")?;

        // Upload to storage in background
        if let Some(ref archive) = self.archive {
            let archive = archive.clone();
            let owner_slug = owner_slug.clone();
            let repo_name = repo_name.to_string();
            let path = local_path.clone();
            let versions = Arc::clone(&self.versions);
            tokio::spawn(async move {
                match archive.upload(&owner_slug, &repo_name, &path).await {
                    Ok(Some(etag)) => {
                        versions
                            .lock()
                            .await
                            .insert(format!("{owner_slug}/{repo_name}"), etag);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(repo = %repo_name, err = %e, "failed to upload new repo to storage");
                    }
                }
            });
        }

        Ok(local_path)
    }

    /// Upload a repo to storage after a write operation (merge, fork, etc.).
    /// Call this after any operation that modifies the git repo on disk.
    pub async fn release_after_write(&self, owner_did: &str, repo_name: &str) {
        if let Some(ref archive) = self.archive {
            let (owner_slug, local_path) = match self.local_path(owner_did, repo_name) {
                Ok(p) => p,
                Err(e) => {
                    warn!(repo = %repo_name, err = %e, "rejected unsafe path in release_after_write");
                    return;
                }
            };
            match archive.upload(&owner_slug, repo_name, &local_path).await {
                Ok(Some(etag)) => {
                    self.versions
                        .lock()
                        .await
                        .insert(format!("{owner_slug}/{repo_name}"), etag);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(repo = %repo_name, err = %e, "failed to upload repo to storage after write");
                }
            }
        }
    }

    /// Compute the local disk path and owner slug for a repo.
    ///
    /// Three-layer defence against path traversal:
    ///   1. Strict allowlist on `owner_did` and `repo_name` (no `..`, slashes,
    ///      null bytes, leading dots; length-bounded).
    ///   2. The joined path must remain rooted at `repos_dir`.
    ///   3. Every component of the joined path must be `Component::Normal`
    ///      (or the prefix/root from `repos_dir`); any `ParentDir`/`CurDir`
    ///      segment is rejected. This is the CodeQL-recognised barrier
    ///      pattern for `rust/path-injection`.
    fn local_path(&self, owner_did: &str, repo_name: &str) -> Result<(String, PathBuf)> {
        validate_path_components(owner_did, repo_name)?;

        let owner_slug = owner_did.replace([':', '/'], "_");
        let local_path = self
            .repos_dir
            .join(&owner_slug)
            .join(format!("{repo_name}.git"));

        if !local_path.starts_with(&self.repos_dir) {
            anyhow::bail!(
                "computed repo path escaped repos_dir: {}",
                local_path.display()
            );
        }

        // Explicit component walk — sanitisation barrier that static analysers
        // (CodeQL `rust/path-injection`) recognise. The path must be composed
        // entirely of Normal segments after the root prefix; any ParentDir or
        // CurDir component is a traversal attempt.
        for component in local_path.components() {
            use std::path::Component;
            match component {
                Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {}
                Component::ParentDir => {
                    anyhow::bail!("path contains parent-directory component");
                }
                Component::CurDir => {
                    anyhow::bail!("path contains current-directory component");
                }
            }
        }

        Ok((owner_slug, local_path))
    }
}

/// Strict allowlist validator for `owner_did` and `repo_name`.
///
/// Rejects any character that isn't explicitly safe, plus length and
/// special-sequence checks (`..`, leading `.`, leading `-`).
fn validate_path_components(owner_did: &str, repo_name: &str) -> Result<()> {
    validate_owner_did(owner_did)?;
    validate_repo_name(repo_name)?;
    Ok(())
}

fn validate_owner_did(owner_did: &str) -> Result<()> {
    if owner_did.is_empty() {
        anyhow::bail!("owner_did is empty");
    }
    if owner_did.len() > 256 {
        anyhow::bail!("owner_did exceeds 256 chars");
    }
    // DIDs are `did:method:identifier` — `did:key:z6Mk...`, `did:web:host:user`, etc.
    // Allow alnum + `:`, `.`, `_`, `-`. Reject `..` substring and any `/` or `\`.
    if owner_did.contains("..") {
        anyhow::bail!("owner_did contains '..' sequence");
    }
    for ch in owner_did.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, ':' | '.' | '_' | '-');
        if !ok {
            anyhow::bail!("owner_did contains disallowed character: {ch:?}");
        }
    }
    Ok(())
}

fn validate_repo_name(repo_name: &str) -> Result<()> {
    if repo_name.is_empty() {
        anyhow::bail!("repo_name is empty");
    }
    if repo_name.len() > 100 {
        anyhow::bail!("repo_name exceeds 100 chars");
    }
    // Repo names are `[A-Za-z0-9._-]+` minus path-traversal traps.
    if repo_name.contains("..") {
        anyhow::bail!("repo_name contains '..' sequence");
    }
    if repo_name.starts_with('.') || repo_name.starts_with('-') {
        anyhow::bail!("repo_name must not start with '.' or '-'");
    }
    for ch in repo_name.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-');
        if !ok {
            anyhow::bail!("repo_name contains disallowed character: {ch:?}");
        }
    }
    Ok(())
}

/// Guard returned by `acquire_write()`. Holds the Postgres advisory lock and
/// uploads to storage + releases the lock on `release()`.
pub struct RepoWriteGuard {
    owner_slug: String,
    repo_name: String,
    pub local_path: PathBuf,
    lock_key: i64,
    /// The connection the session-scoped advisory lock was taken on. The lock
    /// must be released on this same connection, so it's held for the guard's
    /// lifetime and dropped (returned to the pool) only after `release()`.
    conn: PoolConnection<Postgres>,
    archive: Option<RepoArchive>,
    versions: Arc<Mutex<HashMap<String, String>>>,
}

impl RepoWriteGuard {
    /// Path to the bare repo on local disk.
    pub fn path(&self) -> &Path {
        &self.local_path
    }

    /// Upload to storage (only when the write succeeded) and release the advisory
    /// lock. Pass `success = false` when the write operation failed — uploading a
    /// half-applied or otherwise inconsistent repo would propagate corruption to
    /// storage (and to every node that later downloads it). The lock is always
    /// released regardless, to avoid stale locks blocking future writes.
    ///
    /// IMPORTANT: the advisory lock is held until the upload finishes, so a
    /// concurrent writer on another machine cannot read a stale archive. When
    /// callers want a fast client ack, they spawn this future as a background
    /// task (write-back) — the lock + etag-cache update still complete in order.
    pub async fn release(mut self, success: bool) {
        // Upload to storage only on success.
        if success {
            if let Some(ref archive) = self.archive {
                match archive
                    .upload(&self.owner_slug, &self.repo_name, &self.local_path)
                    .await
                {
                    Ok(Some(etag)) => {
                        self.versions
                            .lock()
                            .await
                            .insert(format!("{}/{}", self.owner_slug, self.repo_name), etag);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(repo = %self.repo_name, err = %e, "failed to upload repo to storage after write");
                    }
                }
            }
        } else {
            warn!(repo = %self.repo_name, "write failed — skipping storage upload to avoid propagating an inconsistent repo");
        }

        // Release the advisory lock on the same connection it was taken on, then
        // drop the connection (returns it to the pool).
        if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.lock_key)
            .execute(&mut *self.conn)
            .await
        {
            warn!(repo = %self.repo_name, err = %e, "failed to release advisory lock");
        }
    }
}

/// Compute a stable i64 hash for a Postgres advisory lock key.
fn advisory_lock_key(owner_slug: &str, repo_name: &str) -> i64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    owner_slug.hash(&mut hasher);
    repo_name.hash(&mut hasher);
    hasher.finish() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── repo_name validation ───────────────────────────────────────────────

    #[test]
    fn repo_name_accepts_normal_names() {
        for name in [
            "hello",
            "hello-world",
            "hello_world",
            "hello.world",
            "Repo123",
            "a",
        ] {
            validate_repo_name(name).unwrap_or_else(|e| panic!("{name} should be valid: {e}"));
        }
    }

    #[test]
    fn repo_name_rejects_empty() {
        assert!(validate_repo_name("").is_err());
    }

    #[test]
    fn repo_name_rejects_path_traversal_dotdot() {
        for name in ["..", "../etc", "../../passwd", "foo/../bar", "a..b"] {
            assert!(
                validate_repo_name(name).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    #[test]
    fn repo_name_rejects_slashes() {
        for name in ["foo/bar", "foo\\bar", "/abs", "a/b/c"] {
            assert!(
                validate_repo_name(name).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    #[test]
    fn repo_name_rejects_leading_dot_or_dash() {
        for name in [".hidden", ".", "-foo"] {
            assert!(
                validate_repo_name(name).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    #[test]
    fn repo_name_rejects_null_byte() {
        assert!(validate_repo_name("foo\0bar").is_err());
    }

    #[test]
    fn repo_name_rejects_overlong() {
        let long = "a".repeat(101);
        assert!(validate_repo_name(&long).is_err());
    }

    // ── owner_did validation ───────────────────────────────────────────────

    #[test]
    fn owner_did_accepts_did_key() {
        validate_owner_did("did:key:z6MkqDnb7Siv3Cwj7pGJq4T5EsUisECqR8KpnDLwcaZq5TPr").unwrap();
    }

    #[test]
    fn owner_did_accepts_did_web_with_dots() {
        validate_owner_did("did:web:example.com:user").unwrap();
    }

    #[test]
    fn owner_did_rejects_empty() {
        assert!(validate_owner_did("").is_err());
    }

    #[test]
    fn owner_did_rejects_path_traversal() {
        for did in [
            "did:key:..",
            "did:key:../../etc",
            "..",
            "did:key:foo/../bar",
        ] {
            assert!(validate_owner_did(did).is_err(), "{did:?} must be rejected");
        }
    }

    #[test]
    fn owner_did_rejects_slashes_and_backslashes() {
        for did in ["did:key:foo/bar", "did:key:foo\\bar", "did/key/foo"] {
            assert!(validate_owner_did(did).is_err(), "{did:?} must be rejected");
        }
    }

    #[test]
    fn owner_did_rejects_null_byte() {
        assert!(validate_owner_did("did:key:z6Mk\0evil").is_err());
    }

    #[test]
    fn owner_did_rejects_overlong() {
        let long = format!("did:key:{}", "z".repeat(260));
        assert!(validate_owner_did(&long).is_err());
    }

    // ── end-to-end local_path ──────────────────────────────────────────────

    fn make_store() -> RepoStore {
        // We only exercise the path-construction code, which doesn't touch
        // the pool or the network. Fabricate a pool reference via PgPool::connect_lazy
        // so we don't need a live DB.
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid").unwrap();
        RepoStore::new(PathBuf::from("/var/lib/gitlawb/repos"), None, pool)
    }

    #[tokio::test]
    async fn local_path_resolves_safe_inputs() {
        let store = make_store();
        let (slug, path) = store
            .local_path(
                "did:key:z6MkqDnb7Siv3Cwj7pGJq4T5EsUisECqR8KpnDLwcaZq5TPr",
                "hello",
            )
            .unwrap();
        assert_eq!(
            slug,
            "did_key_z6MkqDnb7Siv3Cwj7pGJq4T5EsUisECqR8KpnDLwcaZq5TPr"
        );
        assert!(path.starts_with("/var/lib/gitlawb/repos"));
        assert!(path.ends_with("hello.git"));
    }

    #[tokio::test]
    async fn local_path_rejects_traversal_in_repo_name() {
        let store = make_store();
        for bad in ["../etc/passwd", "..", "../../shadow"] {
            assert!(
                store.local_path("did:key:z6MkAlice", bad).is_err(),
                "repo_name={bad:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn local_path_rejects_traversal_in_owner_did() {
        let store = make_store();
        for bad in ["did:key:..", "..", "did/key/foo"] {
            assert!(
                store.local_path(bad, "hello").is_err(),
                "owner_did={bad:?} must be rejected"
            );
        }
    }

    // ── sync_down_if_stale (fs-backed archive, lazy pool) ──────────────────

    /// A RepoStore over an fs-backed archive. `sync_down_if_stale` never touches
    /// the pool, so a lazy (never-connected) pool is fine.
    fn store_with_fs_archive(repos_dir: PathBuf, store_root: &Path) -> RepoStore {
        let blob: Arc<dyn crate::storage::BlobStore> =
            Arc::new(crate::storage::fs::FsBlobStore::new(store_root).unwrap());
        let archive = crate::storage::archive::RepoArchive::new(blob);
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid").unwrap();
        RepoStore::new(repos_dir, Some(archive), pool)
    }

    #[tokio::test]
    async fn sync_down_if_stale_downloads_then_skips_on_etag_match() {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let store = store_with_fs_archive(repos_dir.path().to_path_buf(), store_root.path());

        // Seed the archive with a repo.
        let seed = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("HEAD"), b"v1\n").unwrap();
        store
            .archive
            .as_ref()
            .unwrap()
            .upload("owner", "repo", seed.path())
            .await
            .unwrap();

        let local = repos_dir.path().join("owner").join("repo.git");

        // First call downloads.
        store
            .sync_down_if_stale("owner", "repo", &local, false)
            .await
            .unwrap();
        assert_eq!(std::fs::read(local.join("HEAD")).unwrap(), b"v1\n");

        // Locally mutate, then sync again: the cached etag still matches the
        // remote, so the download is skipped and our local edit survives.
        std::fs::write(local.join("HEAD"), b"LOCAL-EDIT\n").unwrap();
        store
            .sync_down_if_stale("owner", "repo", &local, false)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(local.join("HEAD")).unwrap(),
            b"LOCAL-EDIT\n",
            "etag match must skip the download (local copy preserved)"
        );
    }

    #[tokio::test]
    async fn sync_down_if_stale_require_fresh_fails_closed_on_bad_remote() {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let store = store_with_fs_archive(repos_dir.path().to_path_buf(), store_root.path());

        let seed = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("HEAD"), b"v1\n").unwrap();
        store
            .archive
            .as_ref()
            .unwrap()
            .upload("owner", "repo", seed.path())
            .await
            .unwrap();

        let local = repos_dir.path().join("owner").join("repo.git");
        store
            .sync_down_if_stale("owner", "repo", &local, false)
            .await
            .unwrap();

        // Corrupt the stored archive: HEAD now succeeds with a *new* etag (so the
        // cache no longer matches and a download is forced), but the download
        // decompresses garbage and fails.
        let blob_path = store_root.path().join("repos/v1/owner/repo.tar.zst");
        std::fs::write(&blob_path, b"corrupted not-a-tar-zst").unwrap();

        // Write path: must fail closed rather than fall back to the stale local
        // copy (which a later upload would use to clobber the newer remote).
        assert!(
            store
                .sync_down_if_stale("owner", "repo", &local, true)
                .await
                .is_err(),
            "require_fresh=true must propagate the download error"
        );

        // Read path: self-heals — falls back to the valid local copy.
        store
            .sync_down_if_stale("owner", "repo", &local, false)
            .await
            .expect("require_fresh=false must fall back to the local copy");
        assert_eq!(std::fs::read(local.join("HEAD")).unwrap(), b"v1\n");
    }
}
