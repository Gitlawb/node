//! Centralized repo storage layer — local disk cache backed by Tigris (S3).
//!
//! Every handler that needs access to a git repo on disk goes through `RepoStore`:
//!
//! - `acquire()` — ensures the repo is on local disk (downloads from Tigris on cache miss).
//! - `release_after_write()` — uploads the updated repo to Tigris after a write operation.
//! - `init()` — creates a new bare repo locally and uploads to Tigris.
//!
//! When Tigris is disabled (bucket empty), this is a simple passthrough to local disk.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::PgPool;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::store;
use super::tigris::ObjectStore;

/// Centralized repo storage: local disk cache + optional object-store backend.
#[derive(Clone)]
pub struct RepoStore {
    repos_dir: PathBuf,
    object_store: Option<Arc<dyn ObjectStore>>,
    /// Shared Postgres pool for advisory locks.
    pool: PgPool,
    /// Tracks repos already confirmed to exist in the object store — avoids
    /// redundant HEAD checks and background uploads for repos we've migrated.
    migrated: Arc<Mutex<HashSet<String>>>,
}

impl RepoStore {
    #[cfg(test)]
    pub fn for_testing(repos_dir: PathBuf, pool: PgPool) -> Self {
        Self {
            repos_dir,
            object_store: None,
            pool,
            migrated: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    pub fn new(
        repos_dir: PathBuf,
        object_store: Option<Arc<dyn ObjectStore>>,
        pool: PgPool,
    ) -> Self {
        Self {
            repos_dir,
            object_store,
            pool,
            migrated: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Ensure a repo is available on local disk, downloading from Tigris if needed.
    /// If the repo exists locally but not yet in Tigris, a background upload is
    /// spawned to lazily migrate it (on-demand migration for pre-Tigris repos).
    /// Returns the local path to the bare repo.
    pub async fn acquire(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        // Fast path: repo exists locally
        if local_path.exists() {
            // Lazy migration: if Tigris is enabled and we haven't confirmed this
            // repo is in Tigris yet, check and upload in the background.
            if let Some(ref tigris) = self.object_store {
                let key = format!("{owner_slug}/{repo_name}");
                let already_migrated = self.migrated.lock().await.contains(&key);
                if !already_migrated {
                    let tigris = tigris.clone();
                    let slug = owner_slug.clone();
                    let name = repo_name.to_string();
                    let path = local_path.clone();
                    let migrated = Arc::clone(&self.migrated);
                    tokio::spawn(async move {
                        // Check if already in Tigris before uploading
                        match tigris.exists(&slug, &name).await {
                            Ok(true) => {
                                debug!(repo = %name, "repo already in tigris — skipping migration");
                            }
                            Ok(false) => {
                                info!(repo = %name, "migrating local repo to tigris");
                                if let Err(e) = tigris.upload(&slug, &name, &path).await {
                                    warn!(repo = %name, err = %e, "lazy migration to tigris failed");
                                    return;
                                }
                                info!(repo = %name, "lazy migration to tigris complete");
                            }
                            Err(e) => {
                                warn!(repo = %name, err = %e, "tigris existence check failed");
                                return;
                            }
                        }
                        migrated.lock().await.insert(format!("{slug}/{name}"));
                    });
                }
            }
            return Ok(local_path);
        }

        // Try downloading from Tigris
        if let Some(ref tigris) = self.object_store {
            if tigris.exists(&owner_slug, repo_name).await.unwrap_or(false) {
                debug!(repo = %repo_name, "cache miss — downloading from tigris");
                tigris
                    .download(&owner_slug, repo_name, &local_path)
                    .await
                    .context("downloading repo from tigris")?;
                // Mark as migrated since we just downloaded it
                self.migrated
                    .lock()
                    .await
                    .insert(format!("{owner_slug}/{repo_name}"));
                return Ok(local_path);
            }
        }

        // Not found anywhere — return path anyway; caller will get a meaningful
        // error from git when the path doesn't exist.
        Ok(local_path)
    }

    /// Ensure a repo is available on local disk with the **latest** Tigris state.
    /// Use this for operations that precede a write (e.g. `info/refs` for
    /// `git-receive-pack`) so the client sees the same refs that `acquire_write()`
    /// will operate on.
    pub async fn acquire_fresh(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        if let Some(ref tigris) = self.object_store {
            if tigris.exists(&owner_slug, repo_name).await.unwrap_or(false) {
                debug!(repo = %repo_name, "acquire_fresh: downloading latest from tigris");
                if let Err(e) = tigris.download(&owner_slug, repo_name, &local_path).await {
                    // The Tigris archive is present (HEAD ok) but unreadable — a
                    // corrupt/partial upload, or a transient GET failure. If we have a
                    // valid local copy, proceed with it rather than blocking the write;
                    // the post-write upload re-syncs (self-heals) Tigris. Only hard-fail
                    // when there is no local copy to fall back to.
                    if local_path.exists() {
                        warn!(repo = %repo_name, err = %e,
                            "acquire_fresh: tigris download failed — falling back to local copy");
                        return Ok(local_path);
                    }
                    return Err(e).context("downloading repo from tigris (fresh)");
                }
                return Ok(local_path);
            }
        }

        // Tigris disabled or repo not in Tigris — fall back to local
        Ok(local_path)
    }

    /// Take a write lock (Postgres advisory lock), ensure repo is local, return guard.
    /// The lock prevents concurrent writes to the same repo across machines.
    pub async fn acquire_write(&self, owner_did: &str, repo_name: &str) -> Result<RepoWriteGuard> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;
        let lock_key = advisory_lock_key(&owner_slug, repo_name);

        // Acquire the advisory lock on a DEDICATED connection, held for the
        // guard's whole lifetime so the session-scoped lock lives on ONE
        // connection and `release` unlocks it on that SAME connection, and so a
        // concurrent `try_lock_repo`'s `pool.acquire()` cannot be handed the
        // lock-owning connection and reentrantly re-grab it. Mirrors
        // `RepoLockGuard`. Use pg_try_advisory_lock with retry to avoid blocking
        // indefinitely on a stale lock from a crashed connection.
        //
        // Between FAILED attempts the connection is returned to the pool (the
        // `drop` below) so a writer spinning on a contended repo does NOT hold a
        // pool connection through the retry backoff — holding one per spinner
        // would starve the shared pool under a same-repo write burst. Only the
        // WINNING attempt keeps its connection (the lock lives on it).
        let mut conn = {
            let mut acquired = None;
            for attempt in 0..60 {
                let mut c = self
                    .pool
                    .acquire()
                    .await
                    .context("acquiring write-lock connection")?;
                let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                    .bind(lock_key)
                    .fetch_one(&mut *c)
                    .await
                    .context("trying advisory lock")?;
                if row.0 {
                    acquired = Some(c);
                    break;
                }
                drop(c);
                if attempt < 59 {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            match acquired {
                Some(c) => c,
                None => anyhow::bail!(
                    "could not acquire advisory lock after 60s — possible stale lock for {owner_slug}/{repo_name}"
                ),
            }
        };

        // Always download the latest from the object store before writing.
        // Local disk may be stale if another machine pushed since our last access.
        if let Some(ref store) = self.object_store {
            if store.exists(&owner_slug, repo_name).await.unwrap_or(false) {
                debug!(repo = %repo_name, "write acquire: downloading latest from object store");
                if let Err(e) = store.download(&owner_slug, repo_name, &local_path).await {
                    // Same self-healing fallback as acquire_fresh: a corrupt/unreadable
                    // archive must not block a write when a valid local copy
                    // exists — release(success) will re-upload a good archive.
                    if local_path.exists() {
                        warn!(repo = %repo_name, err = %e,
                            "write acquire: object-store download failed — falling back to local copy");
                    } else {
                        // Unlock on the pinned connection before bailing, else the
                        // advisory lock orphans on it: the guard is not constructed
                        // yet (so its release never runs), and sqlx does not release
                        // session locks when a connection returns to the pool — the
                        // lock would block every future write to this repo until the
                        // pool reaps the connection.
                        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                            .bind(lock_key)
                            .execute(&mut *conn)
                            .await;
                        return Err(e).context("downloading repo from object store for write");
                    }
                }
            }
        }

        Ok(RepoWriteGuard {
            owner_slug,
            repo_name: repo_name.to_string(),
            local_path,
            lock_key,
            conn,
            object_store: self.object_store.clone(),
        })
    }

    /// Try to acquire ONLY the per-repo advisory lock, non-blocking, with no
    /// Tigris I/O — the lightweight counterpart to [`acquire_write`](Self::acquire_write)
    /// for out-of-band admin ops (purge-spam) that must mutually exclude a live
    /// push during a destructive delete but never download/re-upload the repo.
    ///
    /// Returns `Some(guard)` if the lock was free, `None` if another writer holds
    /// it (so the caller can skip rather than block). The guard holds a dedicated
    /// pooled connection for its whole lifetime, so the lock lives on that one
    /// connection and `release()` unlocks it on the SAME connection — a plain
    /// pool query could unlock on a different connection and silently fail.
    pub async fn try_lock_repo(
        &self,
        owner_did: &str,
        repo_name: &str,
    ) -> Result<Option<RepoLockGuard>> {
        let (owner_slug, _local) = self.local_path(owner_did, repo_name)?;
        let lock_key = advisory_lock_key(&owner_slug, repo_name);
        let mut conn = self
            .pool
            .acquire()
            .await
            .context("acquiring lock connection")?;
        let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(lock_key)
            .fetch_one(&mut *conn)
            .await
            .context("try advisory lock")?;
        if !row.0 {
            return Ok(None);
        }
        Ok(Some(RepoLockGuard { conn, lock_key }))
    }

    /// Initialize a new bare repo on local disk and upload to Tigris.
    pub async fn init(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        store::init_bare(&local_path).context("initializing bare repo")?;

        // Upload to Tigris in background
        if let Some(ref tigris) = self.object_store {
            let tigris = tigris.clone();
            let owner_slug = owner_slug.clone();
            let repo_name = repo_name.to_string();
            let path = local_path.clone();
            tokio::spawn(async move {
                if let Err(e) = tigris.upload(&owner_slug, &repo_name, &path).await {
                    warn!(repo = %repo_name, err = %e, "failed to upload new repo to tigris");
                }
            });
        }

        Ok(local_path)
    }

    /// Upload a repo to Tigris after a write operation (push, merge, fork, etc.).
    /// Call this after any operation that modifies the git repo on disk.
    pub async fn release_after_write(&self, owner_did: &str, repo_name: &str) {
        if let Some(ref tigris) = self.object_store {
            let (owner_slug, local_path) = match self.local_path(owner_did, repo_name) {
                Ok(p) => p,
                Err(e) => {
                    warn!(repo = %repo_name, err = %e, "rejected unsafe path in release_after_write");
                    return;
                }
            };
            if let Err(e) = tigris.upload(&owner_slug, repo_name, &local_path).await {
                warn!(repo = %repo_name, err = %e, "failed to upload repo to tigris after write");
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

    /// Refresh the local copy from the authoritative object-store archive so an
    /// emptiness recheck reflects remote state (used by purge-spam on a Tigris
    /// deployment, where the admin node's local disk can be stale). Downloads
    /// the archive over the local path when it exists; a no-op when no object
    /// store is configured (single-machine). Errors propagate so the caller can
    /// fail closed rather than delete on a stale-local view.
    pub async fn refresh_from_archive(&self, owner_did: &str, repo_name: &str) -> Result<()> {
        let Some(ref store) = self.object_store else {
            return Ok(());
        };
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;
        if store.exists(&owner_slug, repo_name).await? {
            store.download(&owner_slug, repo_name, &local_path).await?;
        }
        Ok(())
    }

    /// Delete the object-store archive for a repo. A no-op when no object store
    /// is configured. Used by purge-spam so a deleted repo's archive cannot be
    /// downloaded into a later repo created with the same owner/name.
    pub async fn delete_archive(&self, owner_did: &str, repo_name: &str) -> Result<()> {
        let Some(ref store) = self.object_store else {
            return Ok(());
        };
        let (owner_slug, _local_path) = self.local_path(owner_did, repo_name)?;
        store.delete(&owner_slug, repo_name).await
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

pub(crate) fn validate_repo_name(repo_name: &str) -> Result<()> {
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
/// uploads to Tigris + releases the lock on `release()`.
pub struct RepoWriteGuard {
    owner_slug: String,
    repo_name: String,
    pub local_path: PathBuf,
    lock_key: i64,
    /// Dedicated pooled connection the advisory lock lives on. Held for the
    /// guard's lifetime so `release` unlocks on the SAME session that locked,
    /// and so a concurrent `try_lock_repo` cannot be handed this connection and
    /// reentrantly re-grab the lock.
    conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
    object_store: Option<Arc<dyn ObjectStore>>,
}

impl RepoWriteGuard {
    /// Path to the bare repo on local disk.
    pub fn path(&self) -> &Path {
        &self.local_path
    }

    /// Upload to Tigris (only when the write succeeded) and release the advisory
    /// lock. Pass `success = false` when the write operation failed — uploading a
    /// half-applied or otherwise inconsistent repo would propagate corruption to
    /// Tigris (and to every node that later downloads it). The lock is always
    /// released regardless, to avoid stale locks blocking future writes.
    pub async fn release(mut self, success: bool) {
        // Upload to Tigris only on success.
        if success {
            if let Some(ref tigris) = self.object_store {
                if let Err(e) = tigris
                    .upload(&self.owner_slug, &self.repo_name, &self.local_path)
                    .await
                {
                    warn!(repo = %self.repo_name, err = %e, "failed to upload repo to tigris after write");
                }
            }
        } else {
            warn!(repo = %self.repo_name, "write failed — skipping tigris upload to avoid propagating an inconsistent repo");
        }

        // Release the advisory lock on the SAME connection that took it, then
        // the connection returns to the pool on drop.
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.lock_key)
            .execute(&mut *self.conn)
            .await;
    }
}

/// Lock-only guard from [`RepoStore::try_lock_repo`]. Holds the Postgres advisory
/// lock (and the dedicated connection it lives on) until `release()`. No Tigris
/// I/O — unlike [`RepoWriteGuard`], releasing does NOT upload anything.
pub struct RepoLockGuard {
    conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
    lock_key: i64,
}

impl RepoLockGuard {
    /// Release the advisory lock on the same connection that took it, then return
    /// the connection to the pool.
    pub async fn release(mut self) {
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.lock_key)
            .execute(&mut *self.conn)
            .await;
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

    // ── advisory-lock mutual exclusion (P1a) ────────────────────────────────

    // A live `acquire_write` guard must exclude a concurrent `try_lock_repo`
    // (the purge path) on the same repo. This is load-bearing for the purge
    // tool's M4 mutual exclusion.
    //
    // The pool MUST be single-connection. `try_lock_repo`'s own return is the
    // only observable that exposes the bug (it acquires through the pool), and
    // it is only deterministic when the writer's connection is the ONLY one, so
    // `try_lock_repo`'s `pool.acquire()` is forced onto it:
    //   * Pre-fix, `acquire_write` locks via `.fetch_one(&self.pool)` and returns
    //     the lock-owning connection to the pool. `try_lock_repo` re-acquires
    //     that same connection and `pg_try_advisory_lock` re-locks it
    //     reentrantly -> Ok(Some) (RED). (On a multi-connection pool the reentrant
    //     grab is non-deterministic: `acquire` may hand back a different idle
    //     connection, so the bug hides — verified by execution.)
    //   * Post-fix, `acquire_write` pins the connection, so `try_lock_repo`'s
    //     `pool.acquire()` cannot get one and times out -> Err. Either way the
    //     fix guarantees try_lock does NOT reentrantly grab the held lock.
    #[sqlx::test]
    async fn acquire_write_guard_blocks_try_lock(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        let pool = pool_opts
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect_with(connect_opts)
            .await
            .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let store = RepoStore::for_testing(tmp.path().to_path_buf(), pool);
        let owner = "did:key:z6MkWriterLockOwnerAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "locktest";

        // A live writer holds the per-repo advisory lock.
        let guard = store.acquire_write(owner, name).await.unwrap();

        // The purge path must NOT reentrantly acquire the same lock while held.
        // Pre-fix: Ok(Some) (reentrant grab). Post-fix: Err (connection pinned).
        // The invariant is "not Ok(Some)".
        let contended = store.try_lock_repo(owner, name).await;
        assert!(
            !matches!(contended, Ok(Some(_))),
            "try_lock_repo must not reentrantly acquire a lock a live acquire_write \
             guard holds (got Ok(Some) — the reentrant-grab bug)"
        );

        // After the writer releases (on its pinned connection), the lock is free
        // and the single connection is back in the pool.
        guard.release(true).await;
        let after = store.try_lock_repo(owner, name).await.unwrap();
        assert!(
            after.is_some(),
            "lock must be free once the writer releases it"
        );
        after.unwrap().release().await;
    }

    // The exclusion is real ACROSS sessions, not just the reentrant
    // same-connection case: on a multi-connection pool the writer pins its
    // connection, so `try_lock_repo`'s `pool.acquire()` gets a DIFFERENT
    // connection whose `pg_try_advisory_lock` correctly observes the lock held
    // -> Ok(None). This is the actual production topology (writer and purge on
    // different sessions), and it also catches a pin-but-don't-actually-lock
    // regression that the single-connection test (which passes via a
    // pool-exhaustion Err) cannot distinguish from a real held lock.
    #[sqlx::test]
    async fn acquire_write_guard_excludes_try_lock_across_connections(pool: PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = RepoStore::for_testing(tmp.path().to_path_buf(), pool);
        let owner = "did:key:z6MkCrossConnExclusionAAAAAAAAAAAAAAAAAAAAA";
        let name = "xconn";

        let guard = store.acquire_write(owner, name).await.unwrap();

        // A second, distinct pooled connection must see the lock held.
        let contended = store.try_lock_repo(owner, name).await.unwrap();
        assert!(
            contended.is_none(),
            "a live acquire_write guard must exclude try_lock_repo on a different \
             connection (Ok(None)); Ok(Some) would mean the lock is not held"
        );

        guard.release(true).await;
        let after = store.try_lock_repo(owner, name).await.unwrap();
        assert!(after.is_some(), "lock is free after release");
        after.unwrap().release().await;
    }
}
