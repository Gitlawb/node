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

/// Default bound on `release()`'s post-write archive upload (INV-22). Generous
/// for a large-repo PUT while still guaranteeing the guard's pinned advisory-
/// lock connection returns to the pool within a fixed window even if the upload
/// stalls indefinitely.
const DEFAULT_RELEASE_UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Centralized repo storage: local disk cache + optional object-store backend.
#[derive(Clone)]
pub struct RepoStore {
    repos_dir: PathBuf,
    object_store: Option<Arc<dyn ObjectStore>>,
    /// Dedicated Postgres pool for advisory-lock guard connections, separate
    /// from the app pool that serves normal request handlers. Each write guard
    /// pins one connection from here for its whole lifetime, so a concurrent-
    /// push burst pins connections from this pool rather than starving the app
    /// pool. Sized by GITLAWB_DB_LOCK_POOL_MAX_CONNECTIONS to peak writers.
    lock_pool: PgPool,
    /// Upper bound on the post-write archive upload in `release()`, so a stalled
    /// upload cannot pin the guard's lock connection indefinitely.
    release_upload_timeout: std::time::Duration,
    /// Tracks repos already confirmed to exist in the object store — avoids
    /// redundant HEAD checks and background uploads for repos we've migrated.
    migrated: Arc<Mutex<HashSet<String>>>,
}

impl RepoStore {
    #[cfg(test)]
    pub fn for_testing(repos_dir: PathBuf, lock_pool: PgPool) -> Self {
        Self {
            repos_dir,
            object_store: None,
            lock_pool,
            release_upload_timeout: DEFAULT_RELEASE_UPLOAD_TIMEOUT,
            migrated: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    pub fn new(
        repos_dir: PathBuf,
        object_store: Option<Arc<dyn ObjectStore>>,
        lock_pool: PgPool,
    ) -> Self {
        Self {
            repos_dir,
            object_store,
            lock_pool,
            release_upload_timeout: DEFAULT_RELEASE_UPLOAD_TIMEOUT,
            migrated: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Shrink the `release()` upload timeout — test-only, so a stall test can
    /// assert the lock connection is freed within a short bound.
    #[cfg(test)]
    pub fn with_release_upload_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.release_upload_timeout = timeout;
        self
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
                    let store = self.clone();
                    let tigris = tigris.clone();
                    let did = owner_did.to_string();
                    let slug = owner_slug.clone();
                    let name = repo_name.to_string();
                    let migrated = Arc::clone(&self.migrated);
                    tokio::spawn(async move {
                        // Check if already in Tigris before uploading
                        match tigris.exists(&slug, &name).await {
                            Ok(true) => {
                                debug!(repo = %name, "repo already in tigris — skipping migration");
                            }
                            Ok(false) => {
                                info!(repo = %name, "migrating local repo to tigris");
                                // Upload under the per-repo lock so it can't race
                                // a purge. If it skipped (lock contended or dir
                                // gone), do NOT mark migrated — retry next acquire.
                                if !store.upload_locked(&did, &name, false).await {
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
        // lock-pool connection through the retry backoff — holding one per
        // spinner would starve the lock pool under a same-repo write burst. Only
        // the WINNING attempt keeps its connection (the lock lives on it).
        let conn = {
            let mut acquired = None;
            for attempt in 0..60 {
                let mut c = self
                    .lock_pool
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

        // Wrap the winning connection in the guard IMMEDIATELY, before any
        // further await. The download below can be cancelled (the caller's
        // future dropped mid-op) or fail; once the connection lives inside the
        // guard, its `Drop` frees the advisory lock on every such exit. Before
        // this ordering the lock orphaned on a bare connection returned to the
        // pool holding it. (KTD-2.)
        let guard = RepoWriteGuard {
            owner_slug,
            repo_name: repo_name.to_string(),
            local_path,
            lock_key,
            conn: Some(conn),
            object_store: self.object_store.clone(),
            release_upload_timeout: self.release_upload_timeout,
        };

        // Always download the latest from the object store before writing.
        // Local disk may be stale if another machine pushed since our last access.
        if let Some(ref store) = self.object_store {
            if store
                .exists(&guard.owner_slug, &guard.repo_name)
                .await
                .unwrap_or(false)
            {
                debug!(repo = %guard.repo_name, "write acquire: downloading latest from object store");
                if let Err(e) = store
                    .download(&guard.owner_slug, &guard.repo_name, &guard.local_path)
                    .await
                {
                    // Same self-healing fallback as acquire_fresh: a corrupt/unreadable
                    // archive must not block a write when a valid local copy
                    // exists — release(success) will re-upload a good archive.
                    if guard.local_path.exists() {
                        warn!(repo = %guard.repo_name, err = %e,
                            "write acquire: object-store download failed — falling back to local copy");
                    } else {
                        // Dropping the guard frees the advisory lock (its `Drop`
                        // closes the connection). No Tigris upload on a bail,
                        // unlike release(true).
                        return Err(e).context("downloading repo from object store for write");
                    }
                }
            }
        }

        Ok(guard)
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
        self.try_lock_repo_on(&self.lock_pool, owner_did, repo_name)
            .await
    }

    /// [`try_lock_repo`](Self::try_lock_repo) against a caller-chosen pool. The
    /// Postgres advisory lock is DATABASE-global, so the lock still mutually
    /// excludes holders of the same key from any other pool — only the connection
    /// the guard pins comes from `pool`. `create_repo` uses this with the app pool
    /// so its transient lock never draws from the write `lock_pool`.
    async fn try_lock_repo_on(
        &self,
        pool: &PgPool,
        owner_did: &str,
        repo_name: &str,
    ) -> Result<Option<RepoLockGuard>> {
        let (owner_slug, _local) = self.local_path(owner_did, repo_name)?;
        let lock_key = advisory_lock_key(&owner_slug, repo_name);
        let mut conn = pool.acquire().await.context("acquiring lock connection")?;
        let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(lock_key)
            .fetch_one(&mut *conn)
            .await
            .context("try advisory lock")?;
        if !row.0 {
            return Ok(None);
        }
        Ok(Some(RepoLockGuard {
            conn: Some(conn),
            lock_key,
            repo_name: repo_name.to_string(),
        }))
    }

    /// Initialize a new bare repo on local disk and upload to Tigris.
    pub async fn init(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (_owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        store::init_bare(&local_path).context("initializing bare repo")?;

        // Upload to the object store in the background, UNDER the per-repo lock
        // so the PUT can't race a purge. Skips on contention; a skipped init
        // upload self-heals — the first write's release re-uploads the state.
        if self.object_store.is_some() {
            let store = self.clone();
            let did = owner_did.to_string();
            let name = repo_name.to_string();
            tokio::spawn(async move {
                store.upload_locked(&did, &name, false).await;
            });
        }

        Ok(local_path)
    }

    /// Upload a repo to Tigris after a write operation (fork, etc.). Call this
    /// after any operation that modifies the git repo on disk. Uploads UNDER the
    /// per-repo advisory lock so the PUT cannot race a concurrent purge (which
    /// deletes the repo under the same lock) and resurrect a deleted archive.
    /// Waits (bounded) for the lock — a skipped fork upload would have no later
    /// retry; in practice the fork target's lock is uncontended (its DB row is
    /// created after this upload).
    pub async fn release_after_write(&self, owner_did: &str, repo_name: &str) {
        self.upload_locked(owner_did, repo_name, true).await;
    }

    /// Whether an object store is configured. Used by purge-spam to decide
    /// whether a repo with no local copy can be a remote-unverified candidate
    /// (its emptiness verified under the lock after a refresh) versus fail-closed.
    pub fn has_object_store(&self) -> bool {
        self.object_store.is_some()
    }

    /// Upload the local repo to the object store while holding the per-repo
    /// advisory lock, then release. The lock serializes the PUT against a
    /// concurrent `purge-spam` that deletes the repo (row + dir + archive) under
    /// the same lock, so an in-flight upload cannot resurrect a just-deleted
    /// archive. Re-checks the local dir exists UNDER the lock — a purge removes
    /// the dir under its lock, so a post-purge uploader finds it gone and skips.
    /// Returns true iff a PUT was performed. A no-op when no store is configured.
    ///
    /// `wait`: fork's foreground upload waits (bounded) for the lock; the
    /// background migration/init uploads pass `false` and skip on contention —
    /// they self-heal (lazy migration retries on the next `acquire`, init's
    /// state is re-uploaded by the first write's release).
    async fn upload_locked(&self, owner_did: &str, repo_name: &str, wait: bool) -> bool {
        let Some(ref store) = self.object_store else {
            return false;
        };
        let (owner_slug, local_path) = match self.local_path(owner_did, repo_name) {
            Ok(p) => p,
            Err(e) => {
                warn!(repo = %repo_name, err = %e, "rejected unsafe path before object-store upload");
                return false;
            }
        };
        let guard = if wait {
            match self.lock_repo_blocking(owner_did, repo_name).await {
                Ok(Some(g)) => g,
                Ok(None) => {
                    warn!(repo = %repo_name, "object-store upload skipped — repo lock still held after retry");
                    return false;
                }
                Err(e) => {
                    warn!(repo = %repo_name, err = %e, "object-store upload skipped — could not acquire repo lock");
                    return false;
                }
            }
        } else {
            match self.try_lock_repo(owner_did, repo_name).await {
                Ok(Some(g)) => g,
                Ok(None) => {
                    debug!(repo = %repo_name, "object-store upload skipped — repo locked by a live writer");
                    return false;
                }
                Err(e) => {
                    warn!(repo = %repo_name, err = %e, "object-store upload skipped — could not acquire repo lock");
                    return false;
                }
            }
        };
        // Re-check under the lock: a purge removes the on-disk dir under its lock,
        // so a post-purge uploader must find it gone and NOT recreate the archive.
        if !local_path.exists() {
            warn!(repo = %repo_name, "object-store upload skipped — local repo dir gone under lock (purged?)");
            guard.release().await;
            return false;
        }
        let uploaded = match store.upload(&owner_slug, repo_name, &local_path).await {
            Ok(()) => true,
            Err(e) => {
                warn!(repo = %repo_name, err = %e, "failed to upload repo to object store");
                false
            }
        };
        guard.release().await;
        uploaded
    }

    /// Bounded-wait lock-only acquire — the fork foreground upload's counterpart
    /// to `acquire_write`'s spin, without any object-store I/O. Retries
    /// `try_lock_repo` with short backoff. In practice the fork target's lock is
    /// uncontended (its DB row is created after the upload), so this returns on
    /// the first attempt. Also used by `create_repo` to serialize its
    /// existence-check -> init -> insert against a concurrent same-key purge
    /// (which holds this same lock across delete-row + remove-dir).
    pub async fn lock_repo_blocking(
        &self,
        owner_did: &str,
        repo_name: &str,
    ) -> Result<Option<RepoLockGuard>> {
        self.lock_repo_blocking_on(&self.lock_pool, owner_did, repo_name)
            .await
    }

    /// [`lock_repo_blocking`](Self::lock_repo_blocking) against a caller-chosen
    /// pool. `create_repo` passes the app pool so its transient serialization lock
    /// (check-exists -> init -> insert) does not draw a connection from the write
    /// `lock_pool` — a receive-pack burst that pins every lock-pool connection
    /// must not starve repo creation. The advisory lock is DB-global, so this
    /// still serializes create against a same-key purge that holds the lock from
    /// the lock pool.
    pub async fn lock_repo_blocking_on(
        &self,
        pool: &PgPool,
        owner_did: &str,
        repo_name: &str,
    ) -> Result<Option<RepoLockGuard>> {
        for attempt in 0..30 {
            if let Some(g) = self.try_lock_repo_on(pool, owner_did, repo_name).await? {
                return Ok(Some(g));
            }
            if attempt < 29 {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
        Ok(None)
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
    /// reentrantly re-grab the lock. `Option` so `release` can take it (return
    /// it to the pool) while `Drop` closes it when release was never reached.
    conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
    object_store: Option<Arc<dyn ObjectStore>>,
    /// Upper bound on the `release()` archive upload — copied from the store so
    /// a stalled upload cannot pin this connection past the bound.
    release_upload_timeout: std::time::Duration,
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
    pub async fn release(mut self, success: bool) -> bool {
        // Whether the durable copy is safe. Stays `true` when there is nothing to
        // upload (no object store, or `success == false` where no upload is
        // attempted) — those are not upload failures. Only an upload that was
        // ATTEMPTED and then errored or timed out flips it `false`, which the
        // caller surfaces as a FAILED push so the client re-pushes rather than
        // trusting a commit that never reached durable storage. (P1 data-loss.)
        let mut upload_ok = true;

        // Upload to Tigris only on success. Bound the upload so a stalled PUT
        // cannot pin the guard's advisory-lock connection indefinitely — on
        // timeout we log and fall through to the unlock, returning the
        // connection to the pool within the bound. (INV-22.) The lock is freed on
        // EVERY arm below regardless of `upload_ok`; only the return value tells
        // the caller whether the durable write landed.
        if success {
            if let Some(ref tigris) = self.object_store {
                match tokio::time::timeout(
                    self.release_upload_timeout,
                    tigris.upload(&self.owner_slug, &self.repo_name, &self.local_path),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        upload_ok = false;
                        warn!(repo = %self.repo_name, err = %e, "failed to upload repo to tigris after write");
                    }
                    Err(_) => {
                        upload_ok = false;
                        warn!(repo = %self.repo_name, timeout_secs = self.release_upload_timeout.as_secs(),
                            "tigris upload timed out after write — releasing the advisory lock without a completed upload");
                    }
                }
            }
        } else {
            warn!(repo = %self.repo_name, "write failed — skipping tigris upload to avoid propagating an inconsistent repo");
        }

        // Unlock on the SAME connection that took the lock, then TAKE the
        // connection so it returns to the pool on drop and the guard's `Drop`
        // sees `None` (no close-on-drop). If this future is cancelled before the
        // take completes, the connection stays in `self.conn` and `Drop` frees
        // the lock by closing it instead.
        if let Some(mut conn) = self.conn.take() {
            let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.lock_key)
                .execute(&mut *conn)
                .await;
        }

        upload_ok
    }
}

impl Drop for RepoWriteGuard {
    fn drop(&mut self) {
        // If `release()` was never reached (an early `?`, a panic, or the
        // caller's future cancelled on client disconnect), the connection still
        // holds the session advisory lock. Close it so Postgres frees the lock
        // at session end, rather than returning a lock-holding connection to the
        // pool where it would block every future write to this repo. (R1.)
        if let Some(mut conn) = self.conn.take() {
            warn!(repo = %self.repo_name,
                "RepoWriteGuard dropped without release() — closing its connection to free the advisory lock");
            conn.close_on_drop();
        }
    }
}

/// Lock-only guard from [`RepoStore::try_lock_repo`]. Holds the Postgres advisory
/// lock (and the dedicated connection it lives on) until `release()`. No Tigris
/// I/O — unlike [`RepoWriteGuard`], releasing does NOT upload anything.
pub struct RepoLockGuard {
    conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
    lock_key: i64,
    repo_name: String,
}

impl RepoLockGuard {
    /// Release the advisory lock on the same connection that took it, then return
    /// the connection to the pool.
    pub async fn release(mut self) {
        if let Some(mut conn) = self.conn.take() {
            let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.lock_key)
                .execute(&mut *conn)
                .await;
        }
    }
}

impl Drop for RepoLockGuard {
    fn drop(&mut self) {
        // Same guarantee as RepoWriteGuard: a lock guard dropped without
        // release() closes its connection so Postgres frees the advisory lock,
        // rather than returning a lock-holding connection to the pool. (R1.)
        if let Some(mut conn) = self.conn.take() {
            warn!(repo = %self.repo_name,
                "RepoLockGuard dropped without release() — closing its connection to free the advisory lock");
            conn.close_on_drop();
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

    // ── Drop-safety of the advisory-lock guards (U1: R1, R2; AE2) ───────────

    // A minimal ObjectStore double: `exists()` is configurable, `download()` can
    // park on a gate until notified (to hold `acquire_write` inside its
    // post-lock await for the cancellation test), and `upload()` records its
    // calls. Serves U1's reorder test and U3's serialization tests.
    struct GatedStore {
        // `exists` is dynamic so a delete() flips it false and an upload() flips
        // it true — lets U3's resurrect test assert a deleted archive stays gone.
        exists: std::sync::Arc<std::sync::atomic::AtomicBool>,
        download_gate: Option<std::sync::Arc<tokio::sync::Notify>>,
        // When set, `upload()` parks on this gate before doing anything — models a
        // stalled PUT so the release-upload timeout can be observed (U2).
        upload_gate: Option<std::sync::Arc<tokio::sync::Notify>>,
        uploads: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
        deletes: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl GatedStore {
        fn new(exists: bool) -> Self {
            Self {
                exists: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(exists)),
                download_gate: None,
                upload_gate: None,
                uploads: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                deletes: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::git::tigris::ObjectStore for GatedStore {
        async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
            Ok(self.exists.load(std::sync::atomic::Ordering::SeqCst))
        }
        async fn upload(&self, o: &str, r: &str, _p: &std::path::Path) -> anyhow::Result<()> {
            if let Some(gate) = &self.upload_gate {
                // Park indefinitely — the caller's timeout must be what unblocks.
                gate.notified().await;
            }
            self.uploads
                .lock()
                .unwrap()
                .push((o.to_string(), r.to_string()));
            self.exists.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn download(&self, _o: &str, _r: &str, _p: &std::path::Path) -> anyhow::Result<()> {
            if let Some(gate) = &self.download_gate {
                gate.notified().await;
            }
            Ok(())
        }
        async fn delete(&self, o: &str, r: &str) -> anyhow::Result<()> {
            self.deletes
                .lock()
                .unwrap()
                .push((o.to_string(), r.to_string()));
            self.exists
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    // Non-perturbing probe: true iff advisory lock `key` is free (grabs it and
    // immediately releases it on the observer's own separate session).
    async fn advisory_lock_is_free(conn: &mut sqlx::PgConnection, key: i64) -> bool {
        let (got,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        if got {
            let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(key)
                .execute(&mut *conn)
                .await;
        }
        got
    }

    async fn poll_until_free(conn: &mut sqlx::PgConnection, key: i64) -> bool {
        for _ in 0..50 {
            if advisory_lock_is_free(conn, key).await {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    fn lock_key_for(owner: &str, name: &str) -> i64 {
        advisory_lock_key(&owner.replace([':', '/'], "_"), name)
    }

    // Build a pool whose idle/lifetime reaping is disabled, so a leaked
    // (dropped-without-release) connection is NOT reclaimed by ambient sqlx
    // maintenance during the poll window. Without this the default sqlx-test
    // pool reaps the connection ~1.8s after drop, freeing the lock on its own
    // and masking the leak — the test must observe ONLY the fix's own unlock.
    async fn no_reap_pool(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: &sqlx::postgres::PgConnectOptions,
    ) -> PgPool {
        pool_opts
            .max_connections(5)
            .min_connections(0)
            .idle_timeout(None)
            .max_lifetime(None)
            .test_before_acquire(false)
            .connect_with(connect_opts.clone())
            .await
            .unwrap()
    }

    // R1/AE2: a RepoWriteGuard dropped WITHOUT release() must free its advisory
    // lock — its connection is closed rather than returned to the pool still
    // holding the session lock. Pre-fix (no Drop impl) the lock leaks -> RED.
    #[sqlx::test]
    async fn write_guard_dropped_without_release_frees_lock(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use sqlx::ConnectOptions;
        let pool = no_reap_pool(pool_opts, &connect_opts).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let store = RepoStore::new(tmp.path().to_path_buf(), None, pool);
        let owner = "did:key:z6MkDropFreesLockAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "droptest";
        let key = lock_key_for(owner, name);
        let mut observer = connect_opts.connect().await.unwrap();

        let guard = store.acquire_write(owner, name).await.unwrap();
        assert!(
            !advisory_lock_is_free(&mut observer, key).await,
            "lock must be held while the guard is alive"
        );

        drop(guard); // NO release()

        assert!(
            poll_until_free(&mut observer, key).await,
            "advisory lock must be freed after a RepoWriteGuard is dropped without release()"
        );
    }

    // R1: same guarantee for the purge lock-only guard.
    #[sqlx::test]
    async fn repo_lock_guard_dropped_without_release_frees_lock(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use sqlx::ConnectOptions;
        let pool = no_reap_pool(pool_opts, &connect_opts).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let store = RepoStore::new(tmp.path().to_path_buf(), None, pool);
        let owner = "did:key:z6MkLockGuardDropFreesAAAAAAAAAAAAAAAAAAAAAA";
        let name = "lockdrop";
        let key = lock_key_for(owner, name);
        let mut observer = connect_opts.connect().await.unwrap();

        let guard = store.try_lock_repo(owner, name).await.unwrap().unwrap();
        assert!(
            !advisory_lock_is_free(&mut observer, key).await,
            "lock must be held while the lock guard is alive"
        );

        drop(guard); // NO release()

        assert!(
            poll_until_free(&mut observer, key).await,
            "advisory lock must be freed after a RepoLockGuard is dropped without release()"
        );
    }

    // R2/KTD-2: cancelling acquire_write DURING its post-lock freshness download
    // must free the lock. Pre-reorder the lock is won onto a bare connection
    // before the guard exists, so cancellation leaks it -> RED; post-reorder the
    // guard wraps the connection first and its Drop frees the lock.
    #[sqlx::test]
    async fn acquire_write_cancelled_during_download_frees_lock(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use sqlx::ConnectOptions;
        let pool = no_reap_pool(pool_opts, &connect_opts).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let mut ts = GatedStore::new(true);
        ts.download_gate = Some(std::sync::Arc::new(tokio::sync::Notify::new()));
        let store = RepoStore::new(
            tmp.path().to_path_buf(),
            Some(std::sync::Arc::new(ts)),
            pool,
        );
        let owner = "did:key:z6MkCancelDownloadFreesAAAAAAAAAAAAAAAAAAAA";
        let name = "canceldl";
        let key = lock_key_for(owner, name);
        let mut observer = connect_opts.connect().await.unwrap();

        {
            let fut = store.acquire_write(owner, name);
            tokio::pin!(fut);
            tokio::select! {
                _ = &mut fut => panic!("acquire_write should be parked in download, not complete"),
                _ = tokio::time::sleep(std::time::Duration::from_millis(400)) => {}
            }
            // `fut` is dropped here — cancels acquire_write mid-download.
        }

        assert!(
            poll_until_free(&mut observer, key).await,
            "advisory lock must be freed when acquire_write is cancelled mid-download"
        );
    }

    // R2 negative: the normal release() path must NOT close the connection — it
    // returns to the pool, so writes don't churn the pool. On a single-connection
    // pool a second acquire_write can only succeed if the first returned its
    // connection (unlocked, not closed).
    #[sqlx::test]
    async fn release_returns_connection_to_pool(
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
        let store = RepoStore::new(tmp.path().to_path_buf(), None, pool);
        let owner = "did:key:z6MkReleasePoolsConnAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "releasepool";

        for _ in 0..3 {
            let guard = store.acquire_write(owner, name).await.unwrap();
            guard.release(true).await;
        }
    }

    // OQ1: settle whether a guard abandoned inside a detached task when the
    // tokio runtime tears down panics in Drop. `PoolConnection::drop` spawns a
    // task (both the close_on_drop path and the normal return path), and
    // `rt::spawn` panics via `missing_rt` if no runtime handle is current. U2
    // makes receive-pack a detached task that graceful shutdown does not drain,
    // so at process exit such a task can be dropped mid-flight holding a guard.
    // This drops a real runtime with a parked guard-holding task and asserts the
    // process survives (a panic-in-Drop during unwind would abort the binary).
    #[test]
    fn guard_drop_during_runtime_shutdown_does_not_panic() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => return, // no DB configured — skip (mirrors sqlx::test gating)
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let ready = std::sync::Arc::new(tokio::sync::Notify::new());
        let ready2 = ready.clone();
        rt.block_on(async move {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .connect(&url)
                .await
                .unwrap();
            let tmp = tempfile::TempDir::new().unwrap();
            let store = RepoStore::new(tmp.path().to_path_buf(), None, pool);
            tokio::spawn(async move {
                let _guard = store
                    .acquire_write("did:key:z6MkOQ1ShutdownAAAAAAAAAAAAAAAAAAAAAAAAA", "oq1")
                    .await
                    .unwrap();
                ready2.notify_one();
                // Park forever holding the guard.
                std::future::pending::<()>().await;
            });
            ready.notified().await;
        });
        // Drop the runtime while the detached task is parked holding the guard:
        // the task is cancelled, dropping the guard during runtime teardown. Its
        // Drop must not panic. Reaching the end of the test proves it didn't.
        drop(rt);
    }

    // ── U3: archive uploads serialize under the per-repo lock (R7, R8, R9) ───

    fn repo_dir_of(repos_dir: &std::path::Path, owner: &str, name: &str) -> std::path::PathBuf {
        repos_dir
            .join(owner.replace([':', '/'], "_"))
            .join(format!("{name}.git"))
    }

    // R7/R8/AE6: init's background upload must SKIP while a live writer holds the
    // repo lock. Pre-fix (unlocked upload) it PUTs regardless -> RED.
    #[sqlx::test]
    async fn init_upload_skips_while_repo_locked(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        let pool = pool_opts
            .max_connections(5)
            .connect_with(connect_opts)
            .await
            .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let ts = GatedStore::new(false);
        let uploads = ts.uploads.clone();
        let store = RepoStore::new(
            tmp.path().to_path_buf(),
            Some(std::sync::Arc::new(ts)),
            pool,
        );
        let owner = "did:key:z6MkInitSkipAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "initskip";

        let held = store.try_lock_repo(owner, name).await.unwrap().unwrap();
        store.init(owner, name).await.unwrap();
        // Let the spawned upload attempt-and-skip.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            uploads.lock().unwrap().is_empty(),
            "init's background upload must skip while the repo is locked by a live writer"
        );
        held.release().await;
    }

    // R8/AE6: fork's foreground upload (release_after_write) WAITS for the lock
    // rather than skipping, then PUTs once after it frees. Pre-fix it PUTs
    // immediately while the lock is held -> RED on the "still empty" assert.
    #[sqlx::test]
    async fn release_after_write_waits_then_uploads_after_lock_frees(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        let pool = pool_opts
            .max_connections(5)
            .connect_with(connect_opts)
            .await
            .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let ts = GatedStore::new(false);
        let uploads = ts.uploads.clone();
        let store = RepoStore::new(
            tmp.path().to_path_buf(),
            Some(std::sync::Arc::new(ts)),
            pool,
        );
        let owner = "did:key:z6MkForkWaitAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "forkwait";
        let slug = owner.replace([':', '/'], "_");
        std::fs::create_dir_all(repo_dir_of(tmp.path(), owner, name)).unwrap();

        let held = store.try_lock_repo(owner, name).await.unwrap().unwrap();
        let store2 = store.clone();
        let owner2 = owner.to_string();
        let name2 = name.to_string();
        let h = tokio::spawn(async move { store2.release_after_write(&owner2, &name2).await });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            uploads.lock().unwrap().is_empty(),
            "fork upload must wait (not skip) while the repo lock is held"
        );

        held.release().await;
        h.await.unwrap();
        let ups = uploads.lock().unwrap();
        assert_eq!(
            ups.len(),
            1,
            "fork upload must PUT exactly once after the lock frees"
        );
        assert_eq!(ups[0], (slug, name.to_string()));
    }

    // R9/AE6: after a purge deletes the archive AND removes the on-disk dir under
    // the lock, a late upload (that lost the race) must NOT resurrect the archive
    // — it finds the dir gone under the lock and skips. Pre-fix (no dir recheck)
    // it re-PUTs and revives the archive -> RED.
    #[sqlx::test]
    async fn upload_does_not_resurrect_a_purged_archive(pool: sqlx::PgPool) {
        use std::sync::atomic::Ordering::SeqCst;
        let tmp = tempfile::TempDir::new().unwrap();
        let ts = GatedStore::new(false);
        let uploads = ts.uploads.clone();
        let deletes = ts.deletes.clone();
        let exists = ts.exists.clone();
        let store = RepoStore::new(
            tmp.path().to_path_buf(),
            Some(std::sync::Arc::new(ts)),
            pool,
        );
        let owner = "did:key:z6MkResurrectAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "resurrect";
        let dir = repo_dir_of(tmp.path(), owner, name);
        std::fs::create_dir_all(&dir).unwrap();

        store.release_after_write(owner, name).await;
        assert!(exists.load(SeqCst), "archive exists after the first upload");
        assert_eq!(uploads.lock().unwrap().len(), 1);

        // Simulate a purge: delete the archive and remove the on-disk dir.
        store.delete_archive(owner, name).await.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(deletes.lock().unwrap().len(), 1, "archive delete recorded");
        assert!(!exists.load(SeqCst), "archive is deleted by the purge");

        // A late upload attempt must find the dir gone and skip, not resurrect.
        store.release_after_write(owner, name).await;
        assert!(
            !exists.load(SeqCst),
            "a purged archive must stay deleted — the upload found no dir and skipped"
        );
        assert_eq!(
            uploads.lock().unwrap().len(),
            1,
            "no second PUT after the repo dir was purged"
        );
    }

    // Negative: an uncontended fork upload PUTs exactly once (the lock is free).
    #[sqlx::test]
    async fn uncontended_release_after_write_uploads_once(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let ts = GatedStore::new(false);
        let uploads = ts.uploads.clone();
        let store = RepoStore::new(
            tmp.path().to_path_buf(),
            Some(std::sync::Arc::new(ts)),
            pool,
        );
        let owner = "did:key:z6MkUncontendedAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let name = "uncontended";
        std::fs::create_dir_all(repo_dir_of(tmp.path(), owner, name)).unwrap();

        store.release_after_write(owner, name).await;
        assert_eq!(
            uploads.lock().unwrap().len(),
            1,
            "an uncontended fork upload must PUT exactly once"
        );
    }

    // ── U2: dedicated lock pool + bounded release upload (R2, KTD2) ──────────

    // A no-reap pool sized to `max_connections` with a short acquire timeout, so
    // a held guard's connection is not reclaimed mid-assertion (see
    // raw-advisory-lock-guard-must-free-on-drop-and-ambient-pool-reap-masks-the-leak.md)
    // and an exhausted pool fails fast instead of stalling the whole test.
    async fn sized_no_reap_pool(
        connect_opts: &sqlx::postgres::PgConnectOptions,
        max_connections: u32,
    ) -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .min_connections(0)
            .idle_timeout(None)
            .max_lifetime(None)
            .test_before_acquire(false)
            .connect_with(connect_opts.clone())
            .await
            .unwrap()
    }

    // R2/KTD2: advisory-lock guards pin connections from the DEDICATED lock pool,
    // so N concurrent distinct-repo write guards do NOT consume the app pool — an
    // unrelated app-pool handler query still gets a connection. On the pre-split
    // base (the store shared the app pool, RepoStore::new(_, _, db.pool())) those
    // N guards pinned every app-pool connection and the unrelated query 503'd on
    // acquire; the `shared_pool_starves_*` control below pins that RED behavior.
    #[sqlx::test]
    async fn write_guards_on_lock_pool_do_not_starve_the_app_pool(
        _pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        const N: u32 = 3;
        let lock_pool = sized_no_reap_pool(&connect_opts, N).await;
        let app_pool = sized_no_reap_pool(&connect_opts, N).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let store = RepoStore::new(tmp.path().to_path_buf(), None, lock_pool.clone());

        // Hold N distinct-repo write guards -> N lock-pool connections pinned.
        let mut guards = Vec::new();
        for i in 0..N {
            let owner = format!("did:key:z6MkStarveApp{i}AAAAAAAAAAAAAAAAAAAAAAAA");
            guards.push(store.acquire_write(&owner, "starve").await.unwrap());
        }

        // The lock pool is now exhausted: a further acquire on it times out —
        // proving the guards really pinned all N of its connections (so the app-
        // pool assertion below is load-bearing, not vacuously green on idle).
        assert!(
            lock_pool.acquire().await.is_err(),
            "the lock pool must be exhausted by N held write guards"
        );

        // ...but the app pool is a SEPARATE pool, so an unrelated handler query
        // still acquires a connection. This is the query that starved pre-split.
        assert!(
            app_pool.acquire().await.is_ok(),
            "the app pool must stay available while N write guards are held on the lock pool"
        );

        for g in guards {
            g.release(true).await;
        }
    }

    // The pre-split hazard, pinned as a characterization test: when the store
    // SHARES its guard pool with the app pool (the pre-U2 wiring), N held write
    // guards pin every connection and an unrelated query on that SAME pool
    // starves (acquire times out). This is the RED the dedicated lock pool
    // closes; keeping it green documents WHY the pools must be split.
    #[sqlx::test]
    async fn shared_pool_starves_the_app_pool_under_held_write_guards(
        _pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        const N: u32 = 3;
        let shared = sized_no_reap_pool(&connect_opts, N).await;
        let tmp = tempfile::TempDir::new().unwrap();
        // Pre-split topology: the store's guard pool IS the app pool.
        let store = RepoStore::new(tmp.path().to_path_buf(), None, shared.clone());

        let mut guards = Vec::new();
        for i in 0..N {
            let owner = format!("did:key:z6MkSharedStarve{i}AAAAAAAAAAAAAAAAAAAAAA");
            guards.push(store.acquire_write(&owner, "starve").await.unwrap());
        }

        // An unrelated query on the SAME pool now starves.
        assert!(
            shared.acquire().await.is_err(),
            "a shared pool must starve under N held write guards — the hazard the split closes"
        );

        for g in guards {
            g.release(true).await;
        }
    }

    // R2: the lock pool is sized to peak writers, so N = pool-size concurrent
    // distinct-repo writers all acquire and proceed (the starvation is not
    // merely relocated from the app pool onto pushers).
    #[sqlx::test]
    async fn lock_pool_admits_peak_writers_concurrently(
        _pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        const N: u32 = 4;
        let lock_pool = sized_no_reap_pool(&connect_opts, N).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let store = RepoStore::new(tmp.path().to_path_buf(), None, lock_pool);

        let mut guards = Vec::new();
        for i in 0..N {
            let owner = format!("did:key:z6MkPeakWriter{i}AAAAAAAAAAAAAAAAAAAAAAAA");
            guards.push(
                store
                    .acquire_write(&owner, "peak")
                    .await
                    .expect("every writer up to the lock-pool size must acquire and proceed"),
            );
        }
        assert_eq!(guards.len(), N as usize);
        for g in guards {
            g.release(true).await;
        }
    }

    // R2/INV-22: a stalled release() upload must not pin the guard's advisory-
    // lock connection indefinitely. With a short upload bound and an upload that
    // never completes, release() still returns and frees the lock within the
    // bound. Pre-fix (untimed upload) release() would hang on the stalled PUT
    // and never reach the unlock.
    #[sqlx::test]
    async fn release_upload_stall_is_bounded(
        pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        use sqlx::ConnectOptions;
        let pool = no_reap_pool(pool_opts, &connect_opts).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let mut ts = GatedStore::new(true);
        // The upload parks forever; the release timeout is what must unblock it.
        ts.upload_gate = Some(std::sync::Arc::new(tokio::sync::Notify::new()));
        let store = RepoStore::new(
            tmp.path().to_path_buf(),
            Some(std::sync::Arc::new(ts)),
            pool,
        )
        .with_release_upload_timeout(std::time::Duration::from_millis(300));
        let owner = "did:key:z6MkReleaseStallBoundAAAAAAAAAAAAAAAAAAAAAA";
        let name = "stall";
        let key = lock_key_for(owner, name);
        let mut observer = connect_opts.connect().await.unwrap();

        let guard = store.acquire_write(owner, name).await.unwrap();
        assert!(
            !advisory_lock_is_free(&mut observer, key).await,
            "the lock must be held while the guard is alive"
        );

        // release(success) -> the upload stalls, but the bound caps the hold.
        let start = std::time::Instant::now();
        guard.release(true).await;
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "release() must return within the upload bound, not hang on the stalled PUT"
        );
        assert!(
            poll_until_free(&mut observer, key).await,
            "the advisory lock must be freed after the bounded (timed-out) upload"
        );
    }
}
