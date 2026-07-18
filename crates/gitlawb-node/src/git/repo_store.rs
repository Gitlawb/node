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
use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::store;
use super::tigris::TigrisClient;

/// Centralized repo storage: local disk cache + optional Tigris backend.
#[derive(Clone)]
pub struct RepoStore {
    repos_dir: PathBuf,
    tigris: Option<TigrisClient>,
    /// Shared Postgres pool for advisory locks.
    pool: PgPool,
    /// Tracks repos already confirmed to exist in Tigris — avoids redundant
    /// HEAD checks and background uploads for repos we've already migrated.
    migrated: Arc<Mutex<HashSet<String>>>,
}

impl RepoStore {
    #[cfg(test)]
    pub fn for_testing(repos_dir: PathBuf, pool: PgPool) -> Self {
        Self {
            repos_dir,
            tigris: None,
            pool,
            migrated: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    pub fn new(repos_dir: PathBuf, tigris: Option<TigrisClient>, pool: PgPool) -> Self {
        Self {
            repos_dir,
            tigris,
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
            if let Some(ref tigris) = self.tigris {
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
        if let Some(ref tigris) = self.tigris {
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

        if let Some(ref tigris) = self.tigris {
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

        // Pin a dedicated pooled connection and build the guard holding it BEFORE
        // issuing the lock query. Session-level pg advisory locks are
        // connection-affine (they can only be released on the session that took
        // them), so the guard must own the locking connection; and building the
        // guard first means any cancellation after the lock is taken — a
        // `tokio::time::timeout` firing during the Tigris download below — drops a
        // guard that CAN release, closing the leak the outer timeout otherwise
        // opened (#174 F1).
        let conn = self
            .pool
            .acquire()
            .await
            .context("acquiring db connection for the write advisory lock")?;
        let mut guard = RepoWriteGuard {
            owner_slug: owner_slug.clone(),
            repo_name: repo_name.to_string(),
            local_path: local_path.clone(),
            lock_key,
            conn: Some(conn),
            locked: false,
            released: false,
            tigris: self.tigris.clone(),
        };

        // Acquire the advisory lock with retry, through the guard's OWN connection,
        // so the matching unlock (in release, or the Drop backstop) runs on the same
        // session — pg_advisory_unlock on a different pooled connection is a no-op.
        let mut acquired = false;
        for attempt in 0..60 {
            let c = guard
                .conn
                .as_deref_mut()
                .expect("write guard holds its connection during acquisition");
            let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *c)
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
        guard.locked = true;

        // Always download the latest from Tigris before writing. Local disk may be
        // stale if another machine pushed since our last access. The guard already
        // owns the lock + its connection, so a cancellation here drops through Drop.
        if let Some(ref tigris) = self.tigris {
            if tigris.exists(&owner_slug, repo_name).await.unwrap_or(false) {
                debug!(repo = %repo_name, "write acquire: downloading latest from tigris");
                if let Err(e) = tigris.download(&owner_slug, repo_name, &local_path).await {
                    // Same self-healing fallback as acquire_fresh: a corrupt/unreadable
                    // Tigris archive must not block a write when a valid local copy
                    // exists — release(success) will re-upload a good archive.
                    if local_path.exists() {
                        warn!(repo = %repo_name, err = %e,
                            "write acquire: tigris download failed — falling back to local copy");
                    } else {
                        return Err(e).context("downloading repo from tigris for write");
                    }
                }
            }
        }

        Ok(guard)
    }

    /// Initialize a new bare repo on local disk and upload to Tigris.
    pub async fn init(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        store::init_bare(&local_path).context("initializing bare repo")?;

        // Upload to Tigris in background
        if let Some(ref tigris) = self.tigris {
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
        if let Some(ref tigris) = self.tigris {
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
/// uploads to Tigris + releases the lock on `release()`.
pub struct RepoWriteGuard {
    owner_slug: String,
    repo_name: String,
    pub local_path: PathBuf,
    lock_key: i64,
    /// The pooled connection that took the advisory lock. Session-level pg
    /// advisory locks are connection-affine, so the guard pins that connection
    /// for its whole lifetime and unlocks on it (in `release`, or the `Drop`
    /// backstop). `None` only after the connection has been taken to unlock.
    conn: Option<PoolConnection<Postgres>>,
    /// Set once the advisory lock has actually been taken. A guard dropped
    /// before the lock is held (or after `release`) performs no unlock.
    locked: bool,
    /// Set once `release` has run its unlock, making the `Drop` backstop inert.
    released: bool,
    tigris: Option<TigrisClient>,
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
            if let Some(ref tigris) = self.tigris {
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

        // Release the advisory lock on the SAME connection that took it (session
        // advisory locks are connection-affine). Taking the connection here makes
        // the Drop backstop inert.
        if self.locked {
            if let Some(mut conn) = self.conn.take() {
                let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(self.lock_key)
                    .execute(&mut *conn)
                    .await;
            }
        }
        self.released = true;
    }
}

impl Drop for RepoWriteGuard {
    /// Cancellation-safe backstop: if the guard is dropped while still holding the
    /// advisory lock (a `tokio::time::timeout` cancelled `acquire_write`, or a
    /// handler future was dropped before `release`), unlock on the pinned
    /// connection. `Drop` cannot await, so spawn a detached unlock — it runs on the
    /// same session (connection-affine). An off-runtime drop falls back to a log;
    /// the ~60s stale-lock retry loop in `acquire_write` reclaims it.
    fn drop(&mut self) {
        if self.released || !self.locked {
            return;
        }
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        let lock_key = self.lock_key;
        let repo_name = self.repo_name.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
                        .bind(lock_key)
                        .execute(&mut *conn)
                        .await
                    {
                        warn!(repo = %repo_name, err = %e, "detached advisory-unlock on write-guard drop failed");
                    }
                });
            }
            Err(_) => {
                warn!(
                    repo = %repo_name,
                    "RepoWriteGuard dropped off a Tokio runtime; advisory lock not released \
                     synchronously — the stale-lock retry loop will reclaim it"
                );
            }
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

    // ── advisory-lock cancellation-safety (#174 F1, RED-before/GREEN-after) ──

    /// F1 (P1): dropping a `RepoWriteGuard` WITHOUT calling `release()` — the
    /// state a `tokio::time::timeout` cancellation leaves `acquire_write` in when
    /// it fires during the Tigris await — must still release the session advisory
    /// lock. A checker connection is held OUT of the pool first, so `acquire_write`
    /// is forced onto a distinct session; the checker (a different session) then
    /// probes the lock, so advisory-lock re-entrancy cannot mask a leak.
    ///
    /// Load-bearing: RED today (no `Drop` releases the lock → held by
    /// `acquire_write`'s session → checker's `pg_try_advisory_lock` returns
    /// false). GREEN after the connection-affine `Drop` backstop.
    #[sqlx::test]
    async fn write_guard_drop_without_release_frees_the_lock(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = RepoStore::for_testing(dir.path().to_path_buf(), pool.clone());
        let owner = "did:key:z6MkDropBackstopProofAAAAAAAAAAAAAAAAAAAAAA";
        let name = "leaktest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        // Distinct session for the probe: hold it out of the pool BEFORE acquiring,
        // so acquire_write cannot use it and a re-entrant probe cannot falsely read free.
        let mut checker = pool.acquire().await.expect("checker connection");

        let guard = store.acquire_write(owner, name).await.expect("acquire");
        // The cancellation shape: drop without release().
        drop(guard);
        // Let the detached unlock task run.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let (free,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *checker)
            .await
            .unwrap();
        assert!(
            free,
            "advisory lock must be released when the guard is dropped without release()"
        );
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
    }

    /// F1 (latent non-affine release): `release()` must unlock on the SAME
    /// session that locked, so the lock is freed regardless of which pooled
    /// connection would service a fresh query. Observed from a distinct session.
    #[sqlx::test]
    async fn write_guard_release_frees_the_lock_from_a_distinct_session(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = RepoStore::for_testing(dir.path().to_path_buf(), pool.clone());
        let owner = "did:key:z6MkAffineReleaseProofBBBBBBBBBBBBBBBBBBBB";
        let name = "affinetest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        let mut checker = pool.acquire().await.expect("checker connection");
        let guard = store.acquire_write(owner, name).await.expect("acquire");
        guard.release(false).await;

        let (free,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *checker)
            .await
            .unwrap();
        assert!(
            free,
            "release() must free the advisory lock via connection-affine unlock"
        );
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
    }
}
