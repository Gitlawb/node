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
    /// Test-only seam: armed here, copied into every `RepoWriteGuard` this store
    /// hands out, so a test that only holds the `AppState` (not the guard) can
    /// still park `release` at its pre-unlock point. See
    /// `RepoWriteGuard::test_pre_unlock_gate`. Never set outside tests.
    #[cfg(test)]
    pre_unlock_gate: Option<Arc<tokio::sync::Notify>>,
}

impl RepoStore {
    #[cfg(test)]
    pub fn for_testing(repos_dir: PathBuf, pool: PgPool) -> Self {
        Self {
            repos_dir,
            tigris: None,
            pool,
            migrated: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            pre_unlock_gate: None,
        }
    }

    /// Test-only: every guard from this store parks in `release` right before the
    /// `pg_advisory_unlock` await, until `gate` is notified. Dropping the future
    /// while it is parked reproduces a client disconnect inside `release`.
    #[cfg(test)]
    pub fn with_pre_unlock_gate(mut self, gate: Arc<tokio::sync::Notify>) -> Self {
        self.pre_unlock_gate = Some(gate);
        self
    }

    pub fn new(repos_dir: PathBuf, tigris: Option<TigrisClient>, pool: PgPool) -> Self {
        Self {
            repos_dir,
            tigris,
            pool,
            migrated: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(test)]
            pre_unlock_gate: None,
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
            #[cfg(test)]
            test_pre_unlock_gate: self.pre_unlock_gate.clone(),
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
    /// backstop). `None` only after the connection has been taken, either to run
    /// the detached unlock in `Drop` or to be closed when `release`'s unlock
    /// errored (#174 F3b).
    conn: Option<PoolConnection<Postgres>>,
    /// Set once the advisory lock has actually been taken. A guard dropped
    /// before the lock is held (or after `release`) performs no unlock.
    locked: bool,
    /// Set once `release` has run its unlock, making the `Drop` backstop inert.
    released: bool,
    tigris: Option<TigrisClient>,
    /// Test-only seam: when set, `release` parks on this gate at the exact point
    /// it is about to await `pg_advisory_unlock` (connection still owned, not yet
    /// released). Dropping the `release` future while it is parked reproduces a
    /// mid-unlock cancellation, so a test can assert the `Drop` backstop still
    /// frees the session lock. Never set outside tests.
    #[cfg(test)]
    test_pre_unlock_gate: Option<Arc<tokio::sync::Notify>>,
}

/// Deadline for tearing down the connection that saw a failing `pg_advisory_unlock`.
/// Long enough that a healthy socket always finishes well inside it, short enough that
/// a blackholed one does not pin admission resources for a TCP timeout.
const UNLOCK_ERROR_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Await `close` under a deadline (#174 F3c).
///
/// `release` awaits this INLINE while the global write permit, the per-source permit
/// and the write lease are all still held, and sqlx puts no deadline on `close()`:
/// it writes Terminate and then tears the socket down. The branch that reaches here is
/// by definition a connection whose last statement errored, and a blackholed TCP path
/// to Postgres (a cloud failover that drops packets without an RST) is a plausible
/// cause, so an unbounded await here parks every later push to the repo behind three
/// pinned admission resources until the steal bound.
///
/// On elapsed the future is simply dropped, which drops the `PoolConnection` it owns.
/// Dropping it closes the socket, and closing the socket is what actually ends the
/// session and makes Postgres release the lock, so the deadline costs nothing the
/// graceful path was buying.
async fn close_conn_bounded(
    repo_name: &str,
    close: impl std::future::Future<Output = Result<(), sqlx::Error>>,
) {
    match tokio::time::timeout(UNLOCK_ERROR_CLOSE_TIMEOUT, close).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(repo = %repo_name, err = %e,
                "closing the write-lock connection failed, the session teardown still frees the lock server-side");
        }
        Err(_) => {
            warn!(repo = %repo_name, timeout_secs = UNLOCK_ERROR_CLOSE_TIMEOUT.as_secs(),
                "closing the write-lock connection timed out, dropping it instead; the socket goes down either way, which is what frees the lock server-side");
        }
    }
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
        // advisory locks are connection-affine). Unlock through the connection
        // while it is STILL owned by `self` — do not `take()` it first. If this
        // future is cancelled during the unlock await, `self` is dropped with
        // `conn == Some(..)` and `released == false`, so the `Drop` backstop still
        // runs the detached unlock. `released` is set only AFTER the await
        // resolves, so a cancellation cannot make the backstop inert (#174 F4).
        if self.locked {
            #[cfg(test)]
            let pre_unlock_gate = self.test_pre_unlock_gate.clone();
            let unlock = if let Some(conn) = self.conn.as_deref_mut() {
                // Test-only: park right before the unlock await so a test can drop
                // this future mid-unlock (connection owned, not yet released).
                #[cfg(test)]
                if let Some(gate) = pre_unlock_gate {
                    gate.notified().await;
                }
                Some(
                    sqlx::query("SELECT pg_advisory_unlock($1)")
                        .bind(self.lock_key)
                        .execute(&mut *conn)
                        .await,
                )
            } else {
                None
            };
            // An unlock that ERRORS is a different failure from a cancellation: the
            // await resolved, so `Drop` is about to be made inert by `released`
            // below, but the session is still alive and still holds the lock
            // (statement timeout, admin cancel, aborted transaction). Returning that
            // `PoolConnection` to the pool would hand the next caller a connection
            // holding a lock nobody tracks (#174 F3b). Connection disposal is the
            // single mechanism here, and it is why we do not instead try to keep the
            // `Drop` backstop armed: disposal needs `conn.take()`, and `Drop`
            // early-returns on `conn == None`. Ending the session is what frees the
            // lock, so `released = true` still holds.
            if let Some(Err(e)) = unlock {
                warn!(repo = %self.repo_name, err = %e,
                    "advisory unlock failed, closing the connection so the session ends and postgres drops the lock");
                if let Some(conn) = self.conn.take() {
                    // `close()` over `detach()`: both consume the `PoolConnection` by
                    // value in sqlx 0.8.6, but we are in an async fn, so `close()`
                    // sends Terminate and waits for the socket to go down before
                    // `release` returns. `detach()` would only end the session
                    // whenever the returned `PgConnection` is dropped and its
                    // background close completes. If this future is cancelled during
                    // `close()`, the connection is dropped mid-close, which still
                    // tears the session down. That last point is also why the await is
                    // safe to bound: see `close_conn_bounded`, which gives it the
                    // deadline sqlx does not.
                    close_conn_bounded(&self.repo_name, conn.close()).await;
                }
            }
        }
        self.released = true;
    }
}

impl Drop for RepoWriteGuard {
    /// Cancellation-safe backstop: if the guard is dropped while still holding the
    /// advisory lock (a `tokio::time::timeout` cancelled `acquire_write`, or a
    /// handler future was dropped before `release`), unlock on the pinned
    /// connection. This is NOT the backstop for an unlock that ran and returned an
    /// error: that case is closed inside `release` by disposing of the connection,
    /// because `Drop` early-returns on `conn == None` and the two mechanisms cannot
    /// both apply (#174 F3b). `Drop` cannot await, so spawn a detached unlock — it runs on the
    /// same session (connection-affine). An off-runtime drop falls back to a log;
    /// the ~60s stale-lock retry loop in `acquire_write` reclaims it. On runtime
    /// SHUTDOWN the spawned unlock task may be dropped before it polls, so the unlock
    /// may not run — but shutdown tears down the pool, and closing the connection
    /// releases the session-level advisory lock server-side, so this too is bounded.
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

    // ── cancellation-safe unlock (#174 F4, RED-before/GREEN-after) ──────────

    /// F4 (P1): a cancellation DURING the unlock await must still free the session
    /// advisory lock. `release` unlocks through the connection while `self` still
    /// owns it, so if the future is dropped mid-unlock, `Drop` sees `conn == Some`
    /// + `locked && !released` and runs its detached-unlock backstop. A test-only
    /// gate parks `release` at the exact pre-unlock point; dropping the future
    /// there reproduces the cancellation.
    ///
    /// Load-bearing: RED on the original ordering (`self.conn.take()` before the
    /// await → at cancellation `self.conn == None` → `Drop` skips → the local
    /// connection returns to the pool with the session lock still held → the
    /// checker's `pg_try_advisory_lock` returns false). GREEN after the reorder.
    #[sqlx::test]
    async fn write_guard_release_cancelled_mid_unlock_frees_the_lock(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = RepoStore::for_testing(dir.path().to_path_buf(), pool.clone());
        let owner = "did:key:z6MkCancelMidUnlockProofCCCCCCCCCCCCCCCCCC";
        let name = "canceltest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        // Distinct session for the probe, held out of the pool before acquiring.
        let mut checker = pool.acquire().await.expect("checker connection");

        let mut guard = store.acquire_write(owner, name).await.expect("acquire");
        // Arm the pre-unlock gate; it is never notified, so `release` parks on it
        // with the connection still owned and `released` still false.
        let gate = Arc::new(tokio::sync::Notify::new());
        guard.test_pre_unlock_gate = Some(gate);

        // Box the future so we can drop it ourselves (tokio::pin! keeps it alive to
        // end of scope, which would defer the guard's Drop past the assertions).
        let mut fut = Box::pin(guard.release(false));
        let parked =
            tokio::time::timeout(std::time::Duration::from_millis(300), fut.as_mut()).await;
        assert!(
            parked.is_err(),
            "release should park on the pre-unlock gate, not complete"
        );
        // Cancel mid-unlock: dropping the boxed future runs RepoWriteGuard::drop.
        drop(fut);

        // Let the Drop backstop's detached unlock task run.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let (free,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *checker)
            .await
            .unwrap();
        assert!(
            free,
            "advisory lock must be freed when release is cancelled mid-unlock — the \
             connection must stay owned by the guard so Drop's backstop can run"
        );
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
    }

    /// F4: the ordinary success path still frees the lock, and a second write
    /// acquire on the same repo returns promptly (no stale-lock retry loop).
    #[sqlx::test]
    async fn write_guard_release_true_frees_lock_and_second_acquire_succeeds(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = RepoStore::for_testing(dir.path().to_path_buf(), pool.clone());
        let owner = "did:key:z6MkReleaseTrueProofDDDDDDDDDDDDDDDDDDDDDD";
        let name = "reltruetest";

        let guard = store
            .acquire_write(owner, name)
            .await
            .expect("first acquire");
        guard.release(true).await;

        let again = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            store.acquire_write(owner, name),
        )
        .await
        .expect("second acquire_write must not hit the ~60s stale-lock retry loop")
        .expect("second acquire");
        again.release(true).await;
    }

    // ── unlock error disposes the connection (#174 F3b, RED-before/GREEN-after) ─

    /// Put the guard's pinned connection into a failed-transaction state, so the
    /// next statement on it errors while the SESSION stays alive and keeps holding
    /// the session-level advisory lock (those survive a transaction abort; only
    /// `pg_advisory_xact_lock` would not). This is the smallest injection that
    /// reproduces F3b's shape: `pg_advisory_unlock` returning `Err` on a live,
    /// still-locking session. No production seam is needed because the tests live
    /// in this module and can reach `conn` directly.
    async fn poison_guard_connection(guard: &mut RepoWriteGuard) {
        let conn = guard
            .conn
            .as_deref_mut()
            .expect("guard holds its connection before release");
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .expect("open a transaction on the guard connection");
        let poisoned = sqlx::query("SELECT 1 / 0").execute(&mut *conn).await;
        assert!(
            poisoned.is_err(),
            "the poison statement must fail so the transaction is aborted"
        );
    }

    /// How long the polls below may wait for an asynchronous server-side effect.
    /// Postgres frees a session advisory lock when the backend exits, which happens
    /// asynchronously to our socket close, so these are polled to a generous deadline
    /// rather than slept for a fixed interval: a constant sleep is a flake under load,
    /// and one that is long enough to be safe is dead time on every run.
    const RELEASE_POLL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

    /// Poll `cond` until it holds, failing at the deadline so a regression fails the
    /// test rather than hanging the suite.
    async fn wait_until(mut cond: impl FnMut() -> bool, what: &str) {
        let deadline = std::time::Instant::now() + RELEASE_POLL_DEADLINE;
        while !cond() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// Poll the advisory lock from `checker` until it is free. `pg_try_advisory_lock`
    /// ACQUIRES on success, so a true result both answers the question and leaves the
    /// checker session holding the lock; the caller unlocks it.
    async fn wait_until_lock_free(checker: &mut sqlx::PgConnection, key: i64, what: &str) {
        let deadline = std::time::Instant::now() + RELEASE_POLL_DEADLINE;
        loop {
            let (free,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(key)
                .fetch_one(&mut *checker)
                .await
                .unwrap();
            if free {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// A second pool over the same test database with the idle reaper DISABLED.
    ///
    /// `#[sqlx::test]`'s own pool sets `idle_timeout(1s)`, so a connection returned to
    /// it is closed by the reaper about a second later, which ends the session and
    /// frees the advisory lock all on its own. The old fixed 400ms sleep landed inside
    /// that window by luck; polling to a deadline long enough to be flake-proof would
    /// land outside it and go green whether or not `release` disposed of the
    /// connection, so the tests below would stop testing anything (measured: with the
    /// reaper in play, the disposal shows up at ~2s even with the fix reverted). With
    /// no reaper, `release` is the only thing that can end that session, so the poll
    /// measures exactly the property these two tests exist for.
    async fn pool_without_idle_reaper(pool: &sqlx::PgPool) -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .expect("a second pool over the test database")
    }

    /// F3c (P2): the connection teardown on the failing-unlock path must be BOUNDED.
    /// `release` awaits it inline while the global write permit, the per-source permit
    /// and the write lease are all still held, and sqlx's `close()` carries no deadline
    /// of its own, so a blackholed socket would park every later push to that repo
    /// behind three pinned admission resources.
    ///
    /// What this covers: the deadline itself. A close that never resolves still lets
    /// `close_conn_bounded` return, which is the property `release` depends on. What it
    /// does NOT cover, and is reasoned rather than run: that sqlx's own `close()` is
    /// what stalls in production. Making a real `PgConnection::close` hang needs a
    /// blackholed TCP path to Postgres, and the flip has to land after the unlock
    /// statement round-trips but before the Terminate write, which is not a seam this
    /// module exposes. A never-resolving future is the faithful stand-in for that
    /// close, and the F3b tests above already cover that `release` really routes its
    /// close through here.
    ///
    /// Time is paused, so nothing here depends on wall clock: the runtime auto-advances
    /// to the next timer, and the assertion is on which timer fired, not on elapsed
    /// time. The outer bound is what turns a removed deadline into a failure rather
    /// than a hung suite.
    ///
    /// Load-bearing: drop the `tokio::time::timeout` in `close_conn_bounded` and the
    /// inner future never resolves, so the outer bound fires and this fails.
    #[tokio::test(start_paused = true)]
    async fn unlock_error_connection_close_is_bounded() {
        let hanging = std::future::pending::<Result<(), sqlx::Error>>();
        let outcome = tokio::time::timeout(
            UNLOCK_ERROR_CLOSE_TIMEOUT * 4,
            close_conn_bounded("boundedclosetest", hanging),
        )
        .await;
        assert!(
            outcome.is_ok(),
            "a connection close that never completes must not hold the write lease and \
             both admission permits open-endedly: close_conn_bounded must give up and \
             drop the connection"
        );
    }

    /// F3b (P1): when `pg_advisory_unlock` ERRORS while the session is still alive
    /// (statement timeout, admin cancel, aborted transaction), the lock must not
    /// survive `release`. The old code discarded the error with `let _ =` and set
    /// `released = true` anyway, so `Drop` early-returned and the `PoolConnection`
    /// went back to the pool still holding the session lock.
    ///
    /// Observed from a SEPARATE connection held out of the pool before acquiring:
    /// session advisory locks are re-entrant and counted, so probing from the
    /// holding session (or via a fresh `acquire_write` that may be handed the same
    /// connection) would report free whether or not the fix is present.
    ///
    /// Load-bearing: RED before the fix (lock still held → `pg_try_advisory_lock`
    /// returns false), GREEN after (the errored connection is closed, so the
    /// session ends and Postgres drops the lock).
    #[sqlx::test]
    async fn write_guard_release_with_failing_unlock_frees_the_lock(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let store_pool = pool_without_idle_reaper(&pool).await;
        let store = RepoStore::for_testing(dir.path().to_path_buf(), store_pool.clone());
        let owner = "did:key:z6MkUnlockErrorProofFFFFFFFFFFFFFFFFFFFFFF";
        let name = "unlockerrtest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        // Distinct session for the probe, held out of the pool before acquiring.
        let mut checker = pool.acquire().await.expect("checker connection");

        let mut guard = store.acquire_write(owner, name).await.expect("acquire");
        poison_guard_connection(&mut guard).await;

        // Sanity: the poisoned session is still alive and still holds the lock, so
        // the assertion below measures the release path and not a dead session.
        let (free_before,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *checker)
            .await
            .unwrap();
        assert!(
            !free_before,
            "the poisoned session must still hold the lock before release"
        );

        guard.release(false).await;

        // Postgres drops the lock when the disposed session's backend exits, which is
        // asynchronous to our socket close: poll for it rather than sleeping a
        // constant. The deadline is what keeps this load-bearing: a release that
        // leaves the lock held never satisfies the probe and fails here.
        wait_until_lock_free(
            &mut checker,
            key,
            "an errored pg_advisory_unlock must not leave the lock held: release must \
             dispose of the connection so the session ends",
        )
        .await;
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
    }

    /// F3b: the connection that saw the unlock error must leave the pool entirely,
    /// rather than being handed to the next caller while still holding the lock.
    /// `PgPool::size()` counts the connections the pool owns, so closing the
    /// errored one is observable as a drop in that count.
    #[sqlx::test]
    async fn write_guard_release_with_failing_unlock_does_not_return_the_connection(
        pool: sqlx::PgPool,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let store_pool = pool_without_idle_reaper(&pool).await;
        let store = RepoStore::for_testing(dir.path().to_path_buf(), store_pool.clone());
        let owner = "did:key:z6MkUnlockErrorPoolProofGGGGGGGGGGGGGGGGGG";
        let name = "unlockerrpooltest";

        let mut guard = store.acquire_write(owner, name).await.expect("acquire");
        poison_guard_connection(&mut guard).await;
        let size_before = store_pool.size();
        assert!(size_before > 0, "the pool owns the guard's connection");

        guard.release(false).await;

        // The pool's size drops when the closed connection's slot is given up, which
        // is not synchronous with `release` returning: poll rather than sleep.
        wait_until(
            || store_pool.size() == size_before - 1,
            "the connection that saw the unlock error to be closed rather than returned \
             to the pool still holding the session lock",
        )
        .await;
    }

    /// F3b regression guard on the success path: a normal unlock keeps the
    /// connection in the pool and marks the guard released, so the disposal branch
    /// is confined to the error case.
    #[sqlx::test]
    async fn write_guard_release_success_keeps_the_connection_and_frees_the_lock(
        pool: sqlx::PgPool,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = RepoStore::for_testing(dir.path().to_path_buf(), pool.clone());
        let owner = "did:key:z6MkUnlockOkProofHHHHHHHHHHHHHHHHHHHHHHHH";
        let name = "unlockoktest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        let mut checker = pool.acquire().await.expect("checker connection");
        let guard = store.acquire_write(owner, name).await.expect("acquire");
        let size_before = pool.size();

        guard.release(false).await;
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        assert_eq!(
            pool.size(),
            size_before,
            "a successful unlock must leave the connection in the pool"
        );
        let (free,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *checker)
            .await
            .unwrap();
        assert!(free, "the success path must still free the lock");
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
    }

    /// F4: releasing a guard that never took the lock (`locked == false`, the state
    /// acquire_write leaves after a failed acquisition) must not unlock or panic.
    #[sqlx::test]
    async fn write_guard_release_when_not_locked_does_not_unlock_or_panic(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let owner = "did:key:z6MkNotLockedProofEEEEEEEEEEEEEEEEEEEEEE";
        let name = "notlockedtest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        let guard = RepoWriteGuard {
            owner_slug: slug,
            repo_name: name.to_string(),
            local_path: dir.path().to_path_buf(),
            lock_key: key,
            conn: Some(pool.acquire().await.expect("conn")),
            locked: false,
            released: false,
            tigris: None,
            test_pre_unlock_gate: None,
        };
        // Must complete without panic and issue no unlock.
        guard.release(false).await;

        let mut checker = pool.acquire().await.expect("checker");
        let (free,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *checker)
            .await
            .unwrap();
        assert!(free, "release on an unlocked guard must not touch the key");
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
    }
}
