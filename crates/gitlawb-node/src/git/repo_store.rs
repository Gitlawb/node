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
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgPoolOptions;
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
    /// Dedicated Postgres pool for repo write advisory locks, built by
    /// `build_lock_pool` (see there for why it is separate and why it carries an
    /// `after_release` hook). Never use this for ordinary queries.
    lock_pool: PgPool,
    /// Tracks repos already confirmed to exist in Tigris — avoids redundant
    /// HEAD checks and background uploads for repos we've already migrated.
    migrated: Arc<Mutex<HashSet<String>>>,
    /// Test-only stall injected at the head of `acquire_write`'s Tigris phase,
    /// i.e. AFTER the advisory lock is taken and BEFORE the guard exists. That
    /// window is exactly where the outer `tokio::time::timeout` in
    /// `api/repos.rs` can drop the future (#173). `TigrisClient` takes its
    /// endpoint from process-wide AWS env vars and has no injectable seam, so
    /// this flag is the smallest way to hold a real `acquire_write` open in that
    /// window and cancel it there.
    #[cfg(test)]
    tigris_stall: Option<std::time::Duration>,
}

impl RepoStore {
    /// Derives its own lock pool from `pool`, so callers that only have the main
    /// pool (tests, `for_testing` sites in other modules) still get the
    /// `after_release` semantics `acquire_write` depends on.
    #[cfg(test)]
    pub fn for_testing(repos_dir: PathBuf, pool: PgPool) -> Self {
        Self::new(
            repos_dir,
            None,
            build_lock_pool(&pool, 8, Duration::from_secs(5)),
        )
    }

    /// Test-only: see `tigris_stall`.
    #[cfg(test)]
    pub fn with_tigris_stall(mut self, stall: Duration) -> Self {
        self.tigris_stall = Some(stall);
        self
    }

    /// `lock_pool` must come from `build_lock_pool`; a plain pool leaks advisory
    /// locks on cancellation.
    pub fn new(repos_dir: PathBuf, tigris: Option<TigrisClient>, lock_pool: PgPool) -> Self {
        Self {
            repos_dir,
            tigris,
            lock_pool,
            migrated: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(test)]
            tigris_stall: None,
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

        // Check out ONE connection from the lock pool and keep it for the whole
        // lock lifetime. Two reasons, both bugs we hit with `fetch_one(&pool)`:
        //
        //   * A session-level advisory lock belongs to the CONNECTION that took
        //     it. Running the lock and the unlock through the pool lets them land
        //     on different connections, so `pg_advisory_unlock` silently returns
        //     false and the lock leaks, while a competing acquire that happens to
        //     draw the holding connection re-enters the lock and pushes to the
        //     same repo run concurrently.
        //   * Cancellation. `api/repos.rs` bounds this call with
        //     `tokio::time::timeout`; when it fires during the Tigris phase below
        //     the future is dropped after the lock was taken and before
        //     `RepoWriteGuard` (the only caller of `pg_advisory_unlock`) exists.
        //     Dropping this connection instead runs the pool's `after_release`
        //     hook, which clears the lock (#173).
        let mut lock_conn = self
            .lock_pool
            .acquire()
            .await
            .context("checking out a lock-pool connection")?;

        // Acquire Postgres advisory lock with retry using pg_try_advisory_lock
        // to avoid blocking indefinitely on stale locks from crashed connections.
        let mut acquired = false;
        for attempt in 0..60 {
            let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *lock_conn)
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

        #[cfg(test)]
        if let Some(stall) = self.tigris_stall {
            tokio::time::sleep(stall).await;
        }

        // Always download the latest from Tigris before writing.
        // Local disk may be stale if another machine pushed since our last access.
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

        Ok(RepoWriteGuard {
            owner_slug,
            repo_name: repo_name.to_string(),
            local_path,
            lock_key,
            lock_conn,
            tigris: self.tigris.clone(),
        })
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
    /// The lock-pool connection that TOOK the advisory lock. It must be the one
    /// that releases it (session locks are owned by their connection), and
    /// holding it here is also what makes a guard dropped without `release`
    /// safe: the drop returns the connection through `after_release`, which
    /// clears the lock.
    lock_conn: PoolConnection<Postgres>,
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

        // Release the advisory lock on the connection that took it. Anything else
        // (a fresh `&pool` checkout) is a no-op that returns false: Postgres
        // scopes a session lock to its owning connection.
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.lock_key)
            .execute(&mut *self.lock_conn)
            .await;
        // Dropping `self` returns the connection to the lock pool, where
        // `after_release` sweeps anything the unlock above missed.
    }
}

/// Build the dedicated advisory-lock pool a `RepoStore` runs its write locks on.
/// Connect options are cloned off an existing pool so callers need not re-parse
/// the database URL; the pool is lazy, so no connection is opened here.
///
/// Two properties, both load-bearing:
///
///   * The `after_release` hook runs `pg_advisory_unlock_all()` before a
///     connection goes back into the pool. sqlx's `PoolConnection::drop` spawns
///     `return_to_pool()`, which invokes this hook, so a connection dropped by
///     CANCELLATION still clears its locks. That is what keeps an `acquire_write`
///     killed mid-Tigris by the caller's `tokio::time::timeout` from leaking a
///     lock and wedging every later push to that repo (#173). Note the hook runs
///     from that spawned task, so the unlock is asynchronous with respect to the
///     drop: the lock clears shortly after the connection goes away, not
///     synchronously with it.
///   * It is a SEPARATE pool from the main query pool, not a slice of it. A push
///     holds its lock connection for the whole receive-pack, and
///     `db_max_connections` (default 20) is well below
///     `max_concurrent_git_pushes` (default 32), so drawing these from the main
///     pool would starve every other query during a push burst.
///
/// `acquire_timeout` bounds the wait when every lock-pool connection is busy, so
/// exhaustion surfaces as a clean error rather than an unbounded hang.
pub fn build_lock_pool(source: &PgPool, max_connections: u32, acquire_timeout: Duration) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(acquire_timeout)
        .after_release(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SELECT pg_advisory_unlock_all()")
                    .execute(&mut *conn)
                    .await?;
                Ok(true)
            })
        })
        .connect_lazy_with((*source.connect_options()).clone())
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
    use std::time::Duration;

    // ── advisory-lock test helpers (#173 U1) ───────────────────────────────

    /// Postgres advisory locks live in a CLUSTER-wide space, not a per-database
    /// one, so two `#[sqlx::test]` cases running against their own temporary
    /// databases still share the key space. Every lock test therefore mints its
    /// own key instead of reusing a fixed constant.
    fn unique_lock_key() -> i64 {
        use std::sync::atomic::{AtomicI64, Ordering};
        static NEXT: AtomicI64 = AtomicI64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        ((std::process::id() as i64) << 24) | (n & 0xff_ffff)
    }

    /// A plain pool (no `after_release` hook, no idle timeout) at the same
    /// database as the `#[sqlx::test]` pool. Two separate reasons these tests
    /// cannot just use the pool the harness hands them:
    ///
    /// 1. Observing lock state has to happen from a session that is definitely
    ///    not the one under test. Session advisory locks are re-entrant, so
    ///    `pg_try_advisory_lock` on the very connection that already holds the key
    ///    returns true, and a same-pool probe silently reports a leaked lock free.
    /// 2. The harness pool sets `idle_timeout(1s)`, so a connection returned to it
    ///    is closed about a second later and Postgres drops every lock that
    ///    session held. That would mask exactly the leak these tests exist to
    ///    catch, so the store under test runs on one of these too.
    fn sibling_pool(pool: &PgPool, max_connections: u32) -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_lazy_with((*pool.connect_options()).clone())
    }

    /// Probe the lock from a connection that is NOT the one under test. Session
    /// advisory locks are re-entrant within their own session, so a check from the
    /// holding connection would pass vacuously and prove nothing.
    async fn lock_is_free_elsewhere(pool: &PgPool, key: i64) -> bool {
        let mut probe = pool.acquire().await.expect("probe connection");
        let taken: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *probe)
            .await
            .expect("probe try-lock");
        if taken.0 {
            sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(key)
                .execute(&mut *probe)
                .await
                .expect("probe unlock");
        }
        taken.0
    }

    /// `after_release` runs from the task sqlx spawns in `PoolConnection::drop`,
    /// so the unlock is ASYNCHRONOUS with respect to the drop. Callers must poll
    /// rather than assume the lock is gone the instant the connection goes away.
    async fn wait_until_free(pool: &PgPool, key: i64, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        loop {
            if lock_is_free_elsewhere(pool, key).await {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    // ── DESIGN GATE ────────────────────────────────────────────────────────
    // The whole cancellation-safety design rests on one sqlx behaviour:
    // `PoolConnection::drop` spawns `return_to_pool()`, which invokes the pool's
    // `after_release` hook before the connection is reused. If that holds, a
    // connection dropped by cancellation still runs `pg_advisory_unlock_all()`
    // and the lock cannot leak. This test proves it by execution, through the
    // production `build_lock_pool` so that stripping the hook there turns it red.

    #[sqlx::test]
    async fn dropped_pool_connection_runs_after_release_and_clears_locks(pool: PgPool) {
        let key = unique_lock_key();
        let lock_pool = build_lock_pool(&pool, 4, Duration::from_secs(5));

        {
            let mut conn = lock_pool.acquire().await.expect("lock-pool connection");
            let taken: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(key)
                .fetch_one(&mut *conn)
                .await
                .expect("try-lock");
            assert!(taken.0, "first try-lock must succeed");
            assert!(
                !lock_is_free_elsewhere(&pool, key).await,
                "lock must be observably HELD from another session while the connection lives"
            );
            // Drop WITHOUT calling pg_advisory_unlock: this models cancellation.
        }

        assert!(
            wait_until_free(&pool, key, Duration::from_secs(5)).await,
            "after_release must clear the advisory lock of a dropped connection"
        );
    }

    // ── acquire_write cancellation safety (#173 U1) ────────────────────────

    /// The reviewer's named regression. `api/repos.rs` wraps `acquire_write` in a
    /// `tokio::time::timeout`; when that fires during the Tigris phase the future
    /// is dropped after the advisory lock was taken and before `RepoWriteGuard`
    /// (the only thing that unlocks) exists. The lock then leaks and every later
    /// push to the same repo spins the 60-attempt / 60s ceiling and fails.
    #[sqlx::test]
    async fn cancelled_acquire_write_mid_tigris_does_not_leak_the_lock(pool: PgPool) {
        let repos_dir = PathBuf::from("/tmp/gitlawb-test-repos");
        let owner = "did:key:z6MkCancelMidTigris";
        let repo = "cancel-mid-tigris";

        let store_pool = sibling_pool(&pool, 8);
        let stalling = RepoStore::for_testing(repos_dir.clone(), store_pool.clone())
            .with_tigris_stall(Duration::from_secs(30));
        let cancelled = tokio::time::timeout(
            Duration::from_millis(500),
            stalling.acquire_write(owner, repo),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the acquire must still be inside the Tigris phase when the timeout fires"
        );

        // Observed from an independent session, so the check cannot be satisfied
        // by re-entrancy on whichever pooled connection happens to be handed back.
        let probe = sibling_pool(&pool, 2);
        let key = advisory_lock_key(&owner.replace([':', '/'], "_"), repo);
        assert!(
            wait_until_free(&probe, key, Duration::from_secs(5)).await,
            "a cancelled acquire_write must leave no advisory lock held"
        );

        // A subsequent acquire for the SAME repo must succeed promptly. Before the
        // fix it blocks on the leaked lock until the 60-attempt ceiling.
        let store = RepoStore::for_testing(repos_dir, store_pool);
        let guard = tokio::time::timeout(Duration::from_secs(5), store.acquire_write(owner, repo))
            .await
            .expect("second acquire_write must not block on a leaked lock")
            .expect("second acquire_write must succeed");
        guard.release(false).await;
    }

    /// Cancellation BEFORE the lock is taken must leave nothing behind: no lock,
    /// and no lock-pool connection stranded. The lock pool here holds exactly one
    /// connection, so a stranded one would make the follow-up acquire time out
    /// waiting for a checkout.
    #[sqlx::test]
    async fn cancelled_acquire_write_before_the_lock_leaves_nothing_held(pool: PgPool) {
        let probe = sibling_pool(&pool, 2);
        let owner = "did:key:z6MkCancelEarly";
        let repo = "cancel-early";
        let key = advisory_lock_key(&owner.replace([':', '/'], "_"), repo);

        let store = RepoStore::new(
            PathBuf::from("/tmp/gitlawb-test-repos"),
            None,
            build_lock_pool(&pool, 1, Duration::from_secs(3)),
        );

        // A zero deadline polls the future once, which gets it no further than the
        // first await (the pool checkout / the first try-lock round trip), so it is
        // cancelled before any lock can be taken.
        let cancelled =
            tokio::time::timeout(Duration::ZERO, store.acquire_write(owner, repo)).await;
        assert!(cancelled.is_err(), "the acquire must be cancelled");

        assert!(
            lock_is_free_elsewhere(&probe, key).await,
            "no lock may be held when the acquire never got that far"
        );

        // The single lock-pool connection must be back: if cancellation stranded
        // it, this checkout blocks until the 3s acquire timeout and fails.
        let guard = tokio::time::timeout(Duration::from_secs(2), store.acquire_write(owner, repo))
            .await
            .expect("the lock-pool connection must have been returned")
            .expect("acquire after cancellation");
        guard.release(false).await;
    }

    /// Lock-pool exhaustion is a bounded wait and a clean error, never a panic and
    /// never an unbounded hang.
    #[sqlx::test]
    async fn lock_pool_exhaustion_is_a_bounded_error(pool: PgPool) {
        let owner = "did:key:z6MkExhaustion";
        let store = RepoStore::new(
            PathBuf::from("/tmp/gitlawb-test-repos"),
            None,
            build_lock_pool(&pool, 1, Duration::from_secs(2)),
        );

        let held = store
            .acquire_write(owner, "exhaust-a")
            .await
            .expect("first acquire");

        // Different repo, so this is not the advisory lock queueing: the only
        // connection in the lock pool is checked out by `held`.
        let started = std::time::Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            store.acquire_write(owner, "exhaust-b"),
        )
        .await
        .expect("the wait must be bounded by the pool acquire timeout");
        let err = match err {
            Ok(_) => panic!("an exhausted lock pool must surface an error, not a guard"),
            Err(e) => e,
        };
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "the error must arrive on the acquire timeout, not after a long hang"
        );
        assert!(
            err.to_string().contains("lock-pool connection"),
            "the error must name the lock-pool checkout, got: {err}"
        );

        held.release(false).await;
    }

    /// Round trip: the lock is observably HELD between acquire and release, and
    /// observably FREE after. Both checks run from an independent session; from
    /// the holding session they would pass vacuously (session locks are
    /// re-entrant) and would not notice an unlock that landed on the wrong
    /// connection.
    #[sqlx::test]
    async fn acquire_write_holds_the_lock_until_release(pool: PgPool) {
        let probe = sibling_pool(&pool, 2);
        let owner = "did:key:z6MkRoundTrip";
        let repo = "round-trip";
        let key = advisory_lock_key(&owner.replace([':', '/'], "_"), repo);

        let store = RepoStore::for_testing(PathBuf::from("/tmp/gitlawb-test-repos"), pool.clone());
        let guard = store.acquire_write(owner, repo).await.expect("acquire");
        assert!(
            !lock_is_free_elsewhere(&probe, key).await,
            "the lock must be held while the guard is alive"
        );

        // No polling here, deliberately. `release` must free the lock SYNCHRONOUSLY,
        // which it can only do by unlocking on the connection that took it; a
        // `pg_advisory_unlock` sent through the pool would land on some other
        // session and return false. The `after_release` hook is a net for the
        // cancellation path and fires from a spawned task well after this point, so
        // it must not be what makes this assertion pass.
        guard.release(true).await;
        assert!(
            lock_is_free_elsewhere(&probe, key).await,
            "release must free the lock as seen from another session"
        );
    }

    /// `release(false)` skips the Tigris upload but must still free the lock; a
    /// failed write that kept the lock would wedge the repo.
    #[sqlx::test]
    async fn release_after_failed_write_still_frees_the_lock(pool: PgPool) {
        let probe = sibling_pool(&pool, 2);
        let owner = "did:key:z6MkFailedWrite";
        let repo = "failed-write";
        let key = advisory_lock_key(&owner.replace([':', '/'], "_"), repo);

        let store = RepoStore::for_testing(PathBuf::from("/tmp/gitlawb-test-repos"), pool.clone());
        let guard = store.acquire_write(owner, repo).await.expect("acquire");
        guard.release(false).await;

        assert!(
            wait_until_free(&probe, key, Duration::from_secs(5)).await,
            "release(success = false) must still free the lock"
        );
    }

    /// The lock is per repo: a second acquire for the SAME repo waits for the
    /// first to release, while a different repo proceeds straight through.
    #[sqlx::test]
    async fn same_repo_acquires_serialize_and_different_repos_do_not(pool: PgPool) {
        let repos_dir = PathBuf::from("/tmp/gitlawb-test-repos");
        let owner = "did:key:z6MkSerialize";
        let store = RepoStore::for_testing(repos_dir, pool.clone());

        let first = store
            .acquire_write(owner, "serialize-a")
            .await
            .expect("first acquire");

        // Different repo: unaffected by the held lock.
        let other = tokio::time::timeout(
            Duration::from_secs(2),
            store.acquire_write(owner, "serialize-b"),
        )
        .await
        .expect("a different repo must not wait on this lock")
        .expect("acquire other repo");
        other.release(false).await;

        // Same repo: must not acquire while `first` is alive.
        let contender = tokio::spawn({
            let store = store.clone();
            async move { store.acquire_write(owner, "serialize-a").await }
        });
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !contender.is_finished(),
            "a second acquire for the same repo must block while the first guard lives"
        );

        first.release(false).await;
        let second = tokio::time::timeout(Duration::from_secs(10), contender)
            .await
            .expect("contender must finish once the lock is free")
            .expect("contender task")
            .expect("contender acquire");
        second.release(false).await;
    }

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
}
