//! Centralized repo storage layer — local disk cache backed by a pluggable
//! object store (S3-compatible / filesystem / IPFS) via [`RepoArchive`].
//!
//! Every handler that needs access to a git repo on disk goes through `RepoStore`:
//!
//! - `acquire()` — ensures the repo is on local disk (downloads on cache miss).
//! - `acquire_write()` — write lock + ensures local matches storage (skips the
//!   download when the cached etag already matches — the push-latency win).
//! - `release()` — upload the updated repo to storage and free the write lock.
//! - `init()` — creates a new bare repo locally and uploads to storage.
//!
//! When no backend is configured, this is a simple passthrough to local disk.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::store;
use crate::storage::archive::RepoArchive;

/// Centralized repo storage: local disk cache + optional object-storage backend
/// (S3-compatible / filesystem / IPFS) behind the [`RepoArchive`] layer.
#[derive(Clone)]
pub struct RepoStore {
    repos_dir: PathBuf,
    archive: Option<RepoArchive>,
    /// Bounded pool dedicated to advisory-lock connections, built by
    /// `build_lock_pool` (see there for the `after_release` cancellation
    /// backstop and why it is separate from the handler pool). A push pins one
    /// connection while it HOLDS the lock (across receive-pack and the
    /// upload); WAITING for a contended lock occupies nothing — see
    /// `LockedConn::acquire` (#173 F1). Never use this pool for ordinary
    /// queries.
    lock_pool: PgPool,
    /// Tracks repos already confirmed to exist in storage — avoids redundant
    /// HEAD checks and background uploads for repos we've already migrated.
    migrated: Arc<Mutex<HashSet<String>>>,
    /// Last-known archive etag per `owner_slug/repo` key. Lets a write skip the
    /// pre-write download when our local copy already matches storage (the
    /// common case under sticky routing) — the main push-latency win.
    versions: Arc<Mutex<HashMap<String, String>>>,
    /// Test-only stall injected at the head of `acquire_write`'s storage phase,
    /// i.e. AFTER the advisory lock is taken and BEFORE the guard exists. That
    /// window is exactly where the outer `tokio::time::timeout` in
    /// `api/repos.rs` can drop the future (#173). The S3 client takes its
    /// endpoint from process-wide AWS env vars, so this flag is the smallest
    /// way to hold a real `acquire_write` open in that window and cancel it
    /// there.
    #[cfg(test)]
    storage_stall: Option<std::time::Duration>,
    /// Test-only counter of how many times a write guard from this store REACHED
    /// the storage upload site in `release` (the decision point past the
    /// `success` check). It counts the decision, not a network call, so it moves
    /// even when the store has no backend configured; reaching the site at all
    /// is the property under test — an interrupted push must not publish a
    /// half-applied repo (#173 F2).
    ///
    /// Per store rather than a process global, so cases running in parallel do
    /// not see each other's uploads, and an `Arc` rather than a `thread_local`
    /// because the guard is released from a detached task on another worker
    /// thread. Same test-only counter idiom as `ipfs_pin::note_legacy_repair_read`.
    #[cfg(test)]
    upload_site_reached: Arc<std::sync::atomic::AtomicUsize>,
    /// Test-only seam: armed here, copied into every `RepoWriteGuard` this store
    /// hands out, so a test that only holds the `AppState` (not the guard) can
    /// still park `release` at its pre-unlock point. See
    /// `RepoWriteGuard::test_pre_unlock_gate`. Never set outside tests.
    #[cfg(test)]
    pre_unlock_gate: Option<Arc<tokio::sync::Notify>>,
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

    /// Test-only: every guard from this store parks in `release` right before the
    /// `pg_advisory_unlock` await, until `gate` is notified. Dropping the future
    /// while it is parked reproduces a client disconnect inside `release`.
    #[cfg(test)]
    pub fn with_pre_unlock_gate(mut self, gate: Arc<tokio::sync::Notify>) -> Self {
        self.pre_unlock_gate = Some(gate);
        self
    }

    /// Test-only: the dedicated advisory-lock pool this store runs its write locks
    /// on. `for_testing` DERIVES it from the pool it is handed (see `build_lock_pool`),
    /// so a test that wants to observe what happened to a guard's connection has to
    /// look here, not at the pool it passed in.
    #[cfg(test)]
    pub(crate) fn lock_pool(&self) -> &PgPool {
        &self.lock_pool
    }

    /// Test-only: see `storage_stall`.
    #[cfg(test)]
    pub fn with_storage_stall(mut self, stall: Duration) -> Self {
        self.storage_stall = Some(stall);
        self
    }

    /// Test-only: how many write guards from this store have reached the storage
    /// upload site. See [`RepoStore::upload_site_reached`].
    #[cfg(test)]
    pub fn storage_upload_site_reached(&self) -> usize {
        self.upload_site_reached
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `lock_pool` must come from `build_lock_pool`: its `after_release` hook is
    /// the cancellation backstop behind `LockedConn`'s connection-affinity
    /// discipline, and a plain pool would leak advisory locks on paths that
    /// repool a connection.
    pub fn new(repos_dir: PathBuf, archive: Option<RepoArchive>, lock_pool: PgPool) -> Self {
        Self {
            repos_dir,
            archive,
            lock_pool,
            migrated: Arc::new(Mutex::new(HashSet::new())),
            versions: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            storage_stall: None,
            #[cfg(test)]
            upload_site_reached: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            pre_unlock_gate: None,
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

        // The repo path arrived as a parameter, so re-establish the traversal
        // barrier here, where the filesystem work happens, rather than relying
        // on the caller having built it through `validated_repo_disk_path`. See
        // `validated_repo_path_in`.
        let local_path = &validated_repo_path_in(&self.repos_dir, local_path)?;

        let marker = pending_upload_marker(local_path)?;
        // try_exists, not exists(): a transient EACCES/EIO must not read as
        // "no marker" — that path downloads and can roll back a pending local
        // write. Fail the write path closed; treat as present on the read path.
        let marker_present = match marker.try_exists() {
            Ok(present) => present,
            Err(e) => {
                if require_fresh {
                    return Err(e).context("probing pending-upload marker");
                }
                warn!(repo = %repo_name, err = %e,
                    "pending-upload marker probe failed — treating as present");
                true
            }
        };
        if marker_present {
            if local_path.exists() {
                // The local copy has a write that storage never received (its
                // upload failed, or the node stopped first). The marker records
                // the storage etag that write was BASED on — and, if an upload
                // was in flight, the etag it was going to produce — so we can
                // tell "storage unchanged — local strictly ahead" and "that's
                // our own completed upload" apart from "another node advanced
                // storage — genuine divergence".
                let pm = read_pending_marker(local_path);
                let remote = match archive.head_etag(owner_slug, repo_name).await {
                    Ok(r) => r,
                    Err(e) => {
                        if require_fresh {
                            return Err(e).context("storage head while local pending upload");
                        }
                        warn!(repo = %repo_name, err = %e,
                            "storage head failed while pending upload — using local copy");
                        return Ok(());
                    }
                };
                match remote.as_deref() {
                    // Storage empty, or exactly the version our write built on:
                    // local is strictly ahead. Serve it; the next successful
                    // post-write upload re-syncs storage and clears the marker.
                    None => return Ok(()),
                    Some(r) if pm.matches_base(r) => {
                        warn!(repo = %repo_name,
                            "local copy ahead of storage (pending upload) — skipping download");
                        return Ok(());
                    }
                    Some(r) => {
                        // Unexplained remote: our own interrupted upload, or a
                        // genuine external writer. Validate by CONTENT — fetch
                        // the remote bytes and compare their MD5 to the
                        // marker's recorded in-flight hash. Never trust the
                        // backend etag for this: etag semantics vary (IPFS
                        // CIDs, SSE-KMS), and the fs backend can crash between
                        // publishing its etag and its bytes.
                        if self
                            .remote_matches_inflight(archive, owner_slug, repo_name, &pm)
                            .await
                        {
                            debug!(repo = %repo_name,
                                "storage content matches our own in-flight upload — marker cleared, synced");
                            self.versions
                                .lock()
                                .await
                                .insert(format!("{owner_slug}/{repo_name}"), r.to_string());
                            clear_pending_upload_after_success(local_path, Some(r));
                            return Ok(());
                        }
                        // Storage advanced past our base while this node held
                        // un-uploaded local changes: both sides have writes
                        // the other lacks. Overwriting either loses a push.
                        if require_fresh {
                            anyhow::bail!(
                                "storage for {owner_slug}/{repo_name} advanced while local \
                                 changes were pending upload — refusing to overwrite either \
                                 side; reconcile manually (fetch both, merge, remove the \
                                 pending-upload marker)"
                            );
                        }
                        warn!(repo = %repo_name,
                            "storage diverged from pending local copy — serving local for read");
                        return Ok(());
                    }
                }
            }
            // Marker without a local copy: the repo dir was removed out from
            // under us, so the storage copy is the best remaining state. Drop
            // the stale marker and fall through to the normal download.
            let _ = std::fs::remove_file(&marker);
        }
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

        // KNOWN LIMITATION (pre-dates this layer): read-path downloads and
        // their swap-into-place are not serialized against the advisory write
        // lock, so a slow in-flight download decided before a push began can
        // swap a stale tree under a running receive-pack on the same node.
        // Requires a cache-miss/stale read racing a same-repo write; the
        // follow-up is to serialize download+swap with writers.
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

    /// Validate a heal candidate by CONTENT: does storage hold exactly the
    /// bytes this node's interrupted upload was sending? Fetches the remote
    /// object and compares its MD5 to the marker's recorded in-flight hash.
    /// Deliberately never compares against the backend etag — etag semantics
    /// vary (IPFS CIDs, SSE-KMS etags are not content MD5s) and the fs
    /// backend can crash between publishing its etag and its bytes. A full
    /// GET on this recovery-only path is an acceptable price for a check
    /// that cannot false-positive on stale bytes.
    async fn remote_matches_inflight(
        &self,
        archive: &RepoArchive,
        owner_slug: &str,
        repo_name: &str,
        pm: &PendingMarker,
    ) -> bool {
        let Some(ref inflight) = pm.inflight else {
            return false;
        };
        match archive.fetch_raw(owner_slug, repo_name).await {
            Ok(Some(bytes)) => {
                norm_etag(&crate::storage::archive::content_md5_hex(&bytes)) == norm_etag(inflight)
            }
            _ => false,
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
            if self.archive.is_some() {
                let key = format!("{owner_slug}/{repo_name}");
                let already_migrated = self.migrated.lock().await.contains(&key);
                // A pending-upload marker means the marker machinery already
                // owns this repo's next upload (next write, or the startup
                // retry). Migration must not steal it: `upload_under_lock`
                // knows nothing about markers, so its upload would strand the
                // marker with a base that no longer matches storage, wedging
                // the repo's writes on a spurious divergence.
                // A path the barrier rejects cannot carry a marker we wrote, so
                // it reads as "not pending" and migration proceeds under the
                // lock exactly as it would for an unmarked repo.
                let marker_pending =
                    pending_upload_marker(&local_path).is_ok_and(|marker| marker.exists());
                if !already_migrated && !marker_pending {
                    let this = self.clone();
                    let slug = owner_slug.clone();
                    let name = repo_name.to_string();
                    let path = local_path.clone();
                    let key = key.clone();
                    tokio::spawn(async move {
                        // Upload under the advisory lock (skip if already present)
                        // so this opportunistic migration can't clobber a
                        // concurrent locked push by landing a stale snapshot.
                        match this.upload_under_lock(&slug, &name, &path, true).await {
                            Ok(()) => {
                                this.migrated.lock().await.insert(key);
                                debug!(repo = %name, "lazy migration to storage complete (or already present)");
                            }
                            Err(e) => {
                                warn!(repo = %name, err = %e, "lazy migration to storage failed");
                            }
                        }
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
                // The local copy didn't exist, so any pending-upload marker
                // here is stale litter — clear it or it would wrongly pin the
                // just-downloaded copy as "ahead of storage".
                clear_pending_upload(&local_path);
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
    ///
    /// # Cross-machine guarantee
    ///
    /// When multiple nodes share a single Postgres database (the shared-Postgres
    /// deployment model), this lock prevents concurrent writes to the same repo
    /// across machines. The lock has no effect across separate Postgres instances
    /// (federated per-node-DB topology).
    ///
    /// # Rolling upgrade caveat (SHA-256 re-keying)
    ///
    /// This function hashes `(owner_slug, repo_name)` with SHA-256 to produce a
    /// stable `i64` key. Earlier builds used `std::collections::DefaultHasher`,
    /// whose algorithm is not frozen by the Rust standard and has already
    /// shifted across toolchain versions. The SHA-256 swap re-keys *every*
    /// repo: an old-binary node holding the legacy `DefaultHasher` key and a
    /// new-binary node holding the SHA-256 key for the same repo compute
    /// *different* i64 keys, so PostgreSQL treats them as independent locks and
    /// the cross-machine write-exclusion this lock provides is lost for the
    /// duration of a rolling upgrade.
    ///
    /// The accepted remediation (see issue #210) is operational: during a
    /// shared-Postgres rolling upgrade, **drain in-flight writes or cut over
    /// through a single node** (e.g. stop receive-pack / issue / pull / archive
    /// writers on the old version) before bringing new-binary nodes online. The
    /// window is bounded by the operator's rollout cadence. A future
    /// transition release could acquire both legacy and new keys for one cycle
    /// and drop the legacy one a release later; that's optional given the
    /// accepted-window path.
    pub async fn acquire_write(&self, owner_did: &str, repo_name: &str) -> Result<RepoWriteGuard> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;
        let label = format!("{owner_slug}/{repo_name}");
        let lock = LockedConn::acquire(
            &self.lock_pool,
            advisory_lock_key(&owner_slug, repo_name),
            &label,
        )
        .await?;

        #[cfg(test)]
        if let Some(stall) = self.storage_stall {
            tokio::time::sleep(stall).await;
        }

        // Ensure local matches the latest in storage before writing. The etag
        // cache skips the full download when our copy is already current (the
        // common single-machine case under sticky routing); a stale copy (another
        // machine pushed since) still triggers a download. The advisory lock above
        // serializes this so the post-write upload can't race a concurrent writer.
        // A cancellation anywhere in here drops `lock`, whose backstop frees the
        // advisory lock (see `LockedConn`).
        if let Err(e) = self
            .sync_down_if_stale(&owner_slug, repo_name, &local_path, true)
            .await
        {
            lock.unlock().await;
            return Err(e);
        }

        Ok(RepoWriteGuard {
            owner_slug,
            repo_name: repo_name.to_string(),
            local_path,
            lock,
            archive: self.archive.clone(),
            versions: Arc::clone(&self.versions),
            #[cfg(test)]
            upload_site_reached: Arc::clone(&self.upload_site_reached),
            #[cfg(test)]
            test_pre_unlock_gate: self.pre_unlock_gate.clone(),
        })
    }

    /// Initialize a new bare repo on local disk and publish it to storage.
    pub async fn init(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        self.create_published(owner_did, repo_name, |path| {
            store::init_bare(path).context("initializing bare repo")
        })
        .await
    }

    /// Create a new repo's on-disk content via `build` and publish its archive
    /// to storage, holding the per-repo advisory lock for the WHOLE
    /// claim-to-publication lifecycle.
    ///
    /// Callers insert the DB row (the claim) BEFORE calling this. Because
    /// pushes serialize on the same advisory lock, no push can execute in the
    /// window between the row becoming visible and publication finishing — so
    /// a failure here, compensated by the caller deleting its own row, can
    /// never destroy a concurrently accepted push. On failure the created
    /// local dir is removed so a retry doesn't hit an existing destination.
    ///
    /// `build` runs inline while the lock is held (matching the pre-existing
    /// pattern of running git plumbing on the handler task).
    pub async fn create_published(
        &self,
        owner_did: &str,
        repo_name: &str,
        build: impl FnOnce(&Path) -> Result<()> + Send,
    ) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;
        let label = format!("{owner_slug}/{repo_name}");
        let lock = LockedConn::acquire(
            &self.lock_pool,
            advisory_lock_key(&owner_slug, repo_name),
            &label,
        )
        .await?;

        let outcome: Result<()> = async {
            build(&local_path)?;
            // A marker left by a previous same-name repo (failed creation,
            // deleted repo) describes THAT repo's history, not this fresh one
            // — once this repo's archive exists, a stale marker would read as
            // divergence and wedge its writes.
            clear_pending_upload(&local_path);
            if let Some(ref archive) = self.archive {
                // Fail closed: a silent upload failure would leave the repo
                // absent from storage while its row is live.
                let etag = archive
                    .upload(&owner_slug, repo_name, &local_path)
                    .await
                    .context("uploading new repo to storage")?;
                if let Some(etag) = etag {
                    self.versions.lock().await.insert(label.clone(), etag);
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = outcome {
            if local_path.exists() {
                if let Err(cleanup_err) = std::fs::remove_dir_all(&local_path) {
                    warn!(repo = %repo_name, err = %cleanup_err,
                        "failed to remove local repo dir after creation failure");
                }
            }
            clear_pending_upload(&local_path);
            lock.unlock().await;
            return Err(e);
        }
        lock.unlock().await;
        Ok(local_path)
    }

    /// Whether a pending-upload marker currently protects this repo's local
    /// copy. Handlers use this after a failed `release()` to decide whether an
    /// already-committed git mutation is recoverable (marker present: the next
    /// upload re-syncs storage) or must fail the request (no marker: nothing
    /// protects the mutation from a stale-archive rollback).
    pub fn pending_marker_exists(&self, owner_did: &str, repo_name: &str) -> bool {
        self.local_path(owner_did, repo_name)
            .and_then(|(_, local_path)| pending_upload_marker(&local_path))
            .map(|marker| marker.try_exists().unwrap_or(false))
            .unwrap_or(false)
    }

    /// Startup sweep re-attempting the durable upload for every repo whose
    /// pending-upload marker survived a crash or a failed upload. Without this,
    /// a repo that receives no further writes stays divergent from storage
    /// indefinitely, visible only as one log line at failure time.
    ///
    /// Applies the same base-etag rule as `sync_down_if_stale`: a repo whose
    /// storage advanced past the marker's base is left marked (its writes stay
    /// wedged pending manual reconciliation) and only logged. Returns
    /// `(reuploaded, still_pending)`.
    pub async fn retry_pending_uploads(&self) -> (usize, usize) {
        if self.archive.is_none() {
            return (0, 0);
        }
        let mut reuploaded = 0usize;
        let mut still_pending = 0usize;

        let mut markers: Vec<(String, String, PathBuf)> = Vec::new(); // (slug, repo, local)
                                                                      // Scan failures are logged loudly: a sweep that scanned nothing must
                                                                      // not look identical to a node with no pending markers — especially
                                                                      // since the gauge below is seeded from this same scan.
        let owners = match std::fs::read_dir(&self.repos_dir) {
            Ok(owners) => owners,
            Err(e) => {
                warn!(dir = %self.repos_dir.display(), err = %e,
                    "pending-upload sweep: cannot read repos dir — sweep skipped");
                return (0, 0);
            }
        };
        for owner in owners.flatten() {
            if !owner.path().is_dir() {
                continue;
            }
            let slug = owner.file_name().to_string_lossy().into_owned();
            let entries = match std::fs::read_dir(owner.path()) {
                Ok(entries) => entries,
                Err(e) => {
                    warn!(dir = %owner.path().display(), err = %e,
                        "pending-upload sweep: cannot read owner dir — skipped");
                    continue;
                }
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                // Marker-write temp litter (crash mid-rename): collect it.
                if name.starts_with(".pending-upload.tmp-") {
                    let _ = std::fs::remove_file(entry.path());
                    continue;
                }
                // Marker layout: `.{repo}.git.pending-upload`
                let Some(repo_dir) = name
                    .strip_prefix('.')
                    .and_then(|n| n.strip_suffix(".pending-upload"))
                else {
                    continue;
                };
                let Some(repo_name) = repo_dir.strip_suffix(".git") else {
                    continue;
                };
                // The repo dir name comes off the filesystem here rather than
                // from a request, but it is a name this node wrote from
                // user-provided data and the result is handed to the upload
                // path's fs calls, so it goes through the same barrier as every
                // other repo path. A sweep entry that fails it is litter no
                // legitimate write could have produced: skip it rather than
                // acting on it.
                let repo_path =
                    match validated_repo_path_in(&self.repos_dir, &owner.path().join(repo_dir)) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(dir = %owner.path().display(), err = %e,
                            "pending-upload sweep: rejecting an unsafe repo path — skipped");
                            continue;
                        }
                    };
                markers.push((slug.clone(), repo_name.to_string(), repo_path));
            }
        }

        // Seed the gauge with the surviving-marker count before processing;
        // the clears below (and all runtime marker churn) then keep it
        // current via deltas.
        crate::metrics::set_pending_upload_markers(markers.len() as i64);

        for (slug, repo_name, local_path) in markers {
            if !local_path.exists() {
                // Stale litter (repo dir gone) — storage is the best remaining
                // state; drop the marker.
                clear_pending_upload(&local_path);
                continue;
            }
            let pm = read_pending_marker(&local_path);
            // The marker-vs-remote decision and the upload both happen inside
            // `upload_locked_with_marker`, UNDER the advisory lock: an
            // unlocked pre-check here could pass, then block on a concurrent
            // push's lock for that push's whole duration, and the stale
            // decision would clobber the push's freshly-uploaded archive.
            match self
                .upload_locked_with_marker(&slug, &repo_name, &local_path, &pm)
                .await
            {
                Ok(PendingUploadOutcome::Uploaded) => {
                    debug!(repo = %repo_name, "pending-upload retry: re-synced storage");
                    reuploaded += 1;
                }
                Ok(PendingUploadOutcome::Diverged) => {
                    warn!(repo = %repo_name,
                        "pending-upload retry: storage diverged from marker base — \
                         leaving marked; writes stay blocked pending manual reconciliation");
                    still_pending += 1;
                }
                Err(e) => {
                    warn!(repo = %repo_name, err = %e,
                        "pending-upload retry: upload failed — will retry on next write");
                    still_pending += 1;
                }
            }
        }
        (reuploaded, still_pending)
    }

    /// Marker-protected upload: takes the per-repo advisory lock, re-checks
    /// that storage still matches `base` UNDER the lock, and only then uploads,
    /// updates the versions cache, and clears the marker — all before the lock
    /// is released.
    ///
    /// Both halves of that ordering are load-bearing:
    /// - The divergence check must run under the lock. An unlocked check can
    ///   pass just before a concurrent locked push advances storage (the check
    ///   then blocks on that push's lock), and blindly uploading afterwards
    ///   would clobber the acked push it lost the race to.
    /// - The marker must be cleared before the lock is released, or a writer
    ///   queued on the lock could observe marker + fresh etag and fail with a
    ///   spurious "diverged — reconcile manually" on a consistent repo.
    async fn upload_locked_with_marker(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
        marker: &PendingMarker,
    ) -> Result<PendingUploadOutcome> {
        let Some(ref archive) = self.archive else {
            anyhow::bail!("upload_locked_with_marker called without a storage backend");
        };
        let label = format!("{owner_slug}/{repo_name}");
        let lock = LockedConn::acquire(
            &self.lock_pool,
            advisory_lock_key(owner_slug, repo_name),
            &label,
        )
        .await?;

        let outcome: Result<PendingUploadOutcome> = async {
            let remote = archive
                .head_etag(owner_slug, repo_name)
                .await
                .context("storage head under lock before pending upload")?;
            match remote.as_deref() {
                Some(r) if !marker.matches_base(r) => {
                    // Unexplained remote: validate by content whether it is
                    // exactly what this node was uploading when it died —
                    // synced, no PUT needed. Otherwise: divergence.
                    if self
                        .remote_matches_inflight(archive, owner_slug, repo_name, marker)
                        .await
                    {
                        self.versions
                            .lock()
                            .await
                            .insert(label.clone(), r.to_string());
                        clear_pending_upload_after_success(local_path, Some(r));
                        return Ok(PendingUploadOutcome::Uploaded);
                    }
                    return Ok(PendingUploadOutcome::Diverged);
                }
                None if !marker.matches_base("") => {
                    return Ok(PendingUploadOutcome::Diverged);
                }
                _ => {}
            }
            // Record the intended etag in the marker before the PUT: a crash
            // after the PUT lands is then recognizable (above) as our own
            // completed upload instead of wedging on false divergence.
            let etag = archive
                .upload_with_intent(owner_slug, repo_name, local_path, |intended| {
                    record_inflight_upload(local_path, intended)
                })
                .await
                .context("uploading repo to storage under lock")?;
            if let Some(ref etag) = etag {
                self.versions
                    .lock()
                    .await
                    .insert(label.clone(), etag.clone());
            }
            clear_pending_upload_after_success(local_path, etag.as_deref());
            Ok(PendingUploadOutcome::Uploaded)
        }
        .await;

        lock.unlock().await;
        outcome
    }

    /// Upload `local_path` to storage while holding the per-repo advisory lock,
    /// so a background or init-time upload can't clobber a concurrent locked
    /// write by landing an older snapshot after it. With `skip_if_exists`, skips
    /// the upload when the archive is already present (used by lazy migration).
    async fn upload_under_lock(
        &self,
        owner_slug: &str,
        repo_name: &str,
        local_path: &Path,
        skip_if_exists: bool,
    ) -> Result<()> {
        let Some(ref archive) = self.archive else {
            return Ok(());
        };
        let label = format!("{owner_slug}/{repo_name}");
        let lock = LockedConn::acquire(
            &self.lock_pool,
            advisory_lock_key(owner_slug, repo_name),
            &label,
        )
        .await?;

        let outcome: Result<Option<String>> = async {
            if skip_if_exists {
                // Propagate a failed existence check instead of treating it as
                // "absent": HEAD failing transiently while PUT would succeed
                // must not let this node's cache overwrite a newer shared
                // archive. The lazy-migration caller just retries later.
                let exists = archive
                    .exists(owner_slug, repo_name)
                    .await
                    .context("checking storage before migration upload")?;
                if exists {
                    return Ok(None); // already present — nothing to upload
                }
            }
            archive.upload(owner_slug, repo_name, local_path).await
        }
        .await;

        // Release the lock on the same connection regardless of outcome.
        lock.unlock().await;

        match outcome {
            Ok(Some(etag)) => {
                self.versions
                    .lock()
                    .await
                    .insert(format!("{owner_slug}/{repo_name}"), etag);
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => Err(e).context("uploading repo to storage under lock"),
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
        let owner_slug = owner_did.replace([':', '/'], "_");
        let local_path = validated_repo_disk_path(&self.repos_dir, owner_did, repo_name)?;
        Ok((owner_slug, local_path))
    }
}

/// The three-layer validated form of `store::repo_disk_path`, with NO Tigris fetch and
/// no `RepoStore` (#173 round 11, F3). Extracted from `RepoStore::local_path` so a
/// second caller that must not pull a cold repo, the U4 legacy provider-CID sweep, gets
/// the same barrier instead of the raw join. `local_path` is now a thin wrapper over
/// this, so the two cannot drift.
///
/// Three-layer defence against path traversal:
///   1. Strict allowlist on `owner_did` and `repo_name` (no `..`, slashes,
///      null bytes, leading dots; length-bounded).
///   2. The joined path must remain rooted at `repos_dir`.
///   3. Every component of the joined path must be `Component::Normal`
///      (or the prefix/root from `repos_dir`); any `ParentDir`/`CurDir`
///      segment is rejected. This is the CodeQL-recognised barrier
///      pattern for `rust/path-injection`.
pub(crate) fn validated_repo_disk_path(
    repos_dir: &Path,
    owner_did: &str,
    repo_name: &str,
) -> Result<PathBuf> {
    validate_path_components(owner_did, repo_name)?;

    let owner_slug = owner_did.replace([':', '/'], "_");
    let local_path = repos_dir.join(&owner_slug).join(format!("{repo_name}.git"));

    if !local_path.starts_with(repos_dir) {
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

    Ok(local_path)
}

/// Re-establish the traversal barrier on a repo path this function did not
/// build itself, and return the checked value.
///
/// `sync_down_if_stale` and the sweep receive a `&Path` as a PARAMETER. The
/// caller derived it from [`validated_repo_disk_path`], but a barrier the
/// reader has to trace across a call boundary is not a barrier a static
/// analyser will honour: to CodeQL's `rust/path-injection` the parameter is
/// just a path with user-provided data in its history, and every `exists()`,
/// `read_dir` and `remove_file` reached from it is a sink. Re-running the
/// check where the filesystem work actually happens costs two string compares
/// on a path we already hold and makes the guarantee local to the code it
/// guards, so it survives future refactors that move a call site.
///
/// Same three layers as [`validated_repo_disk_path`], minus the name allowlist
/// (the components are no longer separable once joined): containment under
/// `repos_dir`, then the explicit `Component::Normal` walk.
pub(crate) fn validated_repo_path_in(repos_dir: &Path, candidate: &Path) -> Result<PathBuf> {
    if !candidate.starts_with(repos_dir) {
        anyhow::bail!("repo path escaped repos_dir: {}", candidate.display());
    }

    // Explicit component walk — sanitisation barrier that static analysers
    // (CodeQL `rust/path-injection`) recognise. The path must be composed
    // entirely of Normal segments after the root prefix; any ParentDir or
    // CurDir component is a traversal attempt.
    for component in candidate.components() {
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

    Ok(candidate.to_path_buf())
}

/// The sibling-path counterpart to [`validated_repo_disk_path`], for the files
/// this layer writes NEXT TO a repo directory rather than inside it: the
/// pending-upload marker, its rename-temp, and the swap phase's `.bak-` and
/// `.tmp-extract.` work dirs.
///
/// A validated repo path does not make its siblings validated. `with_file_name`
/// and `join` build a NEW path, and a new path is a new question: nothing in
/// the type system says the name handed in contributed no separator, no `..`,
/// and no absolute prefix (a `join` with an absolute component silently
/// DISCARDS everything accumulated before it). These names are assembled from
/// the repo's own file name, which carries user-provided data all the way from
/// the push URL, so each one is re-checked here before any filesystem call
/// touches it.
///
/// Three layers, mirroring the repo-path barrier: the name must be a single
/// ordinary path segment, the result must stay under the repo's parent
/// directory, and the joined path must walk as `Component::Normal` throughout.
/// The returned `PathBuf` is the only value callers hand to the filesystem.
pub(crate) fn validated_sibling_path(local_path: &Path, file_name: &str) -> Result<PathBuf> {
    let parent = local_path
        .parent()
        .context("repo path has no parent directory")?;

    if file_name.is_empty() {
        anyhow::bail!("sibling file name is empty");
    }
    if file_name.len() > 255 {
        anyhow::bail!("sibling file name exceeds the 255-byte filesystem name limit");
    }
    if file_name == "." || file_name == ".." || file_name.contains("..") {
        anyhow::bail!("sibling file name contains a parent-directory reference");
    }
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains('\0') {
        anyhow::bail!("sibling file name contains a path separator or null byte");
    }

    let candidate = parent.join(file_name);

    if !candidate.starts_with(parent) {
        anyhow::bail!("sibling path escaped the repo parent dir: {file_name}");
    }

    // Explicit component walk — sanitisation barrier that static analysers
    // (CodeQL `rust/path-injection`) recognise. The path must be composed
    // entirely of Normal segments after the root prefix; any ParentDir or
    // CurDir component is a traversal attempt.
    for component in candidate.components() {
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

    Ok(candidate)
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

/// Validate a peer-supplied `owner/name` sync slug and return its two halves.
///
/// The sync queue carries a single `repo` string that peers control, and the
/// worker turns it into a filesystem path. `PathBuf::join` does not normalize,
/// and an absolute second component replaces the accumulated path, so an
/// unvalidated `a//tmp/x` resolved to `/tmp/x.git` outside `repos_dir` (#272).
///
/// The halves are checked with the same validators that guard
/// `RepoStore::local_path`, so there is one owner rule and one name rule in the
/// crate. The one rule added here is the leading `.`/`-` check on the owner
/// half: `validate_owner_did` has no such rule (it also serves full DIDs, which
/// always start with `d`), and without it an owner half of `.` puts a
/// peer-controlled mirror at the `repos_dir` root, which canonicalizes back
/// inside the root and so passes containment.
pub(crate) fn validate_repo_slug(slug: &str) -> Result<(&str, &str)> {
    let mut parts = slug.split('/');
    let (Some(owner), Some(name)) = (parts.next(), parts.next()) else {
        anyhow::bail!("repo slug must be 'owner/name'");
    };
    if parts.next().is_some() {
        anyhow::bail!("repo slug must contain exactly one '/'");
    }
    if owner.is_empty() || name.is_empty() {
        anyhow::bail!("repo slug has an empty owner or name");
    }
    if owner.starts_with('.') || owner.starts_with('-') {
        anyhow::bail!("repo slug owner must not start with '.' or '-'");
    }
    // The owner half becomes one path component, so it is bounded by NAME_MAX
    // (255), not by the DID column's 256. The two differ by exactly one, and
    // that one length is the gap that matters: validate_owner_did accepts 256,
    // create_dir_all then fails with ENAMETOOLONG on every attempt, and the
    // worker leaves such a row pending, so it is re-picked forever. Rejecting
    // it here means an undeliverable slug never enters the queue at all.
    if owner.len() > 255 {
        anyhow::bail!("repo slug owner exceeds 255 chars");
    }
    validate_owner_did(owner)?;
    validate_repo_name(name)?;
    Ok((owner, name))
}

/// The answer from [`path_within_root`].
///
/// Three-valued rather than a bool because the two negative answers call for
/// opposite handling. `Outside` is a deterministic verdict about a hostile or
/// misconfigured path: the same input fails the same way forever, so the caller
/// can retire the work. `IoError` says the question could not be answered at
/// all (EACCES, an unmounted root), which is transient, so the caller must keep
/// the work and try again rather than permanently retire a legitimate repo.
#[derive(Debug)]
pub(crate) enum Containment {
    /// The candidate resolves inside the root.
    Contained,
    /// The candidate resolves outside the root.
    Outside,
    /// The filesystem could not answer the question.
    IoError(std::io::Error),
}

/// Does `candidate` canonically resolve inside `root`?
///
/// The third layer of path defence, after the character allowlist and the
/// component walk on `RepoStore::local_path`. Those two read the path as text
/// and cannot see a symlink standing between the root and the target (#272).
///
/// One contract covers both the clone and the fetch branch. `symlink_metadata`
/// decides which:
///
///   * The candidate exists (including as a symlink), so the candidate itself is
///     canonicalized. That resolves the link and catches a mirror path that is a
///     symlink to a bare repo outside the root, which a parent-only check misses
///     entirely: the parent canonicalizes clean, `exists()` follows the link, and
///     the fetch then writes through it.
///   * The candidate does not exist, so its parent is canonicalized instead.
///     This is the first-clone case. Canonicalizing the candidate unconditionally
///     would reject every first clone, since `canonicalize` errors on a path that
///     does not exist.
///
/// Pure: it reads the filesystem and never creates, moves, or removes anything.
/// Callers that need the parent directory to exist create it themselves before
/// asking, because a predicate that created a directory as a side effect of
/// being asked would be wrong for a caller asking about a path it is about to
/// delete.
pub(crate) fn path_within_root(candidate: &Path, root: &Path) -> Containment {
    let root = match root.canonicalize() {
        Ok(p) => p,
        // A root that cannot be resolved is an operator condition, never a
        // verdict on the candidate, so every error kind is retryable here.
        Err(e) => return Containment::IoError(e),
    };

    let resolved = match std::fs::symlink_metadata(candidate) {
        // The candidate exists as an entry: resolve it, links and all. A failure
        // now (a dangling symlink, a permission change mid-flight) is an I/O
        // answer, since the entry was there a moment ago.
        Ok(_) => match candidate.canonicalize() {
            Ok(p) => p,
            Err(e) => return Containment::IoError(e),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let Some(parent) = candidate.parent() else {
                return Containment::Outside;
            };
            match parent.canonicalize() {
                Ok(p) => p,
                // A parent that is not there is a real answer about where this
                // path sits; anything else is the filesystem failing to answer.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Containment::Outside;
                }
                Err(e) => return Containment::IoError(e),
            }
        }
        // Neither "it is there" nor "it is not there": we cannot tell.
        Err(e) => return Containment::IoError(e),
    };

    if resolved.starts_with(&root) {
        Containment::Contained
    } else {
        Containment::Outside
    }
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

/// Error marker for "no lock-pool connection was available in time".
///
/// Carried through the `anyhow` chain (like [`smart_http::GitServiceTimeout`]) so the
/// HTTP handler can `downcast_ref` it and shed a 503 + Retry-After instead of the
/// generic 500 a git error maps to: an exhausted lock pool is a CAPACITY signal, and
/// telling the client to retry shortly is the same shed semantics the surrounding
/// admission code already uses (#173 F1).
///
/// [`smart_http::GitServiceTimeout`]: crate::git::smart_http::GitServiceTimeout
#[derive(Debug, thiserror::Error)]
#[error("no lock-pool connection available")]
pub struct LockPoolBusy;

/// How long to retry acquiring the per-repo advisory lock before giving up.
/// Matches the storage backends' total operation timeout (300s in `s3.rs` and
/// `ipfs.rs`): the writer holding the lock may legitimately be mid-upload of a
/// large archive, so a concurrent push must be willing to outwait the longest
/// possible upload rather than failing while the lock holder is still healthy.
pub(crate) const LOCK_ACQUIRE_TIMEOUT_SECS: u64 = 300;

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

/// A pool connection pinned for the lifetime of a session-scoped advisory lock.
///
/// Postgres advisory locks bind to one backend connection and only release on
/// that same connection; with a pool, acquiring and releasing on different
/// checked-out connections means the unlock silently no-ops while the lock
/// lingers on the original. So the lock's whole HELD lifetime — the winning
/// try-lock, use, unlock — runs on this single pinned connection.
///
/// `unlock()` is the graceful path: it releases the lock and returns the
/// connection to the pool (closing it instead when the unlock errors, since a
/// session whose unlock failed may still hold the lock). If the holder is
/// *dropped* while the lock is held — a cancelled `acquire_write`, a detached
/// write-back task cancelled by runtime shutdown mid upload — `Drop` runs a
/// detached unlock on the same session, disposing of the connection if that
/// errors; off a Tokio runtime it detaches and closes the connection, which
/// ends the Postgres session and frees the lock server-side. The one thing
/// this type never does is knowingly return a still-locked connection to the
/// pool — and the lock pool's `after_release` hook (`pg_advisory_unlock_all`)
/// backstops even the paths it cannot see (#173).
struct LockedConn {
    /// The connection that TOOK the advisory lock, owned until the unlock await
    /// RESOLVES. `Option` because the unlock is not always the end of it: when
    /// `pg_advisory_unlock` errors on a live session, `after_release` fails
    /// identically on that same broken session (#174 F3b), so those paths
    /// `take()` the connection and close it instead — ending the session is what
    /// actually frees the lock. `None` only after such a disposal, or after
    /// `Drop` has moved it into the detached unlock.
    conn: Option<PoolConnection<Postgres>>,
    lock_key: i64,
    repo_label: String,
    /// Set once `unlock()`'s await has resolved, making the `Drop` backstop
    /// inert. A `LockedConn` only ever exists with the lock already held, so
    /// there is no "never locked" state to track alongside it.
    released: bool,
}

impl LockedConn {
    /// Acquire `lock_key` on a pinned connection, polling `pg_try_advisory_lock`
    /// once per second up to [`LOCK_ACQUIRE_TIMEOUT_SECS`]. Polling (rather than
    /// the blocking `pg_advisory_lock`) keeps a stale lock from a crashed
    /// session from wedging writers indefinitely.
    ///
    /// The connection is checked out INSIDE the loop and RETURNED before each
    /// sleep; only the connection that actually took the lock is retained. Two
    /// constraints pull in opposite directions here, and this is what satisfies
    /// both (#173 F1):
    ///
    ///   * Session ownership. A session-level advisory lock belongs to the
    ///     CONNECTION that took it, so the lock and its `pg_advisory_unlock`
    ///     must run on the same one. Hence: keep the connection that WON.
    ///   * Occupancy. Holding a connection across the ~300 one-second sleeps
    ///     would let one spinning acquire park a lock-pool connection for
    ///     minutes. `api/issues.rs` and `api/pulls.rs` reach `acquire_write`
    ///     holding no concurrency permit at all, so a caller could park the
    ///     whole pool and starve authenticated pushes on every repo. Hence:
    ///     return the connection when we LOSE, before sleeping.
    ///
    /// Returning a losing connection is safe with respect to the cancellation
    /// design: `after_release` runs `pg_advisory_unlock_all()`, a no-op on a
    /// connection that took nothing, so it cannot disturb a lock held by any
    /// other connection.
    ///
    /// Pool exhaustion (no connection free within the pool's acquire timeout)
    /// surfaces as a downcastable [`LockPoolBusy`] so the HTTP layer can shed a
    /// 503 + Retry-After instead of a generic 500.
    async fn acquire(pool: &PgPool, lock_key: i64, repo_label: &str) -> Result<Self> {
        for attempt in 0..LOCK_ACQUIRE_TIMEOUT_SECS {
            let mut conn = pool.acquire().await.map_err(|e| {
                anyhow::Error::new(LockPoolBusy)
                    .context(format!("checking out a lock-pool connection: {e}"))
            })?;
            match sqlx::query_as::<_, (bool,)>("SELECT pg_try_advisory_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *conn)
                .await
            {
                Ok((true,)) => {
                    return Ok(Self {
                        conn: Some(conn),
                        lock_key,
                        repo_label: repo_label.to_string(),
                        released: false,
                    });
                }
                Ok((false,)) => {
                    // Lost the race: give the connection back so a spinning
                    // acquire occupies nothing while it waits.
                    drop(conn);
                }
                Err(e) => {
                    // The poll itself failing leaves the lock's server-side
                    // state unknown: if the query executed but the response was
                    // lost, this session HOLDS the lock, and repooling the
                    // connection would strand it behind `after_release`'s best
                    // effort. Close it deliberately; ending the session frees
                    // anything it took.
                    drop(conn.detach());
                    return Err(e).context("trying advisory lock");
                }
            }
            if attempt < LOCK_ACQUIRE_TIMEOUT_SECS - 1 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        anyhow::bail!(
            "could not acquire advisory lock for {repo_label} after {LOCK_ACQUIRE_TIMEOUT_SECS}s — \
             possible stale lock or a long-running upload"
        );
    }

    /// Release the held lock on the pinned connection and return it to the
    /// pool. An unlock that ERRORS is a live session that may still hold the
    /// lock — `after_release` would fail identically on the same broken session
    /// (#174 F3b) — so the connection is closed instead (bounded, #174 F3c):
    /// ending the session is what actually frees the lock.
    async fn unlock(mut self) {
        // Unlock through the connection while it is STILL owned by `self`; do
        // NOT `take()` it first. A cancellation during this await then drops
        // `self` with the connection in place, so `Drop`'s detached backstop
        // runs and the pool's `after_release` hook clears whatever the
        // interrupted unlock did not (#174 F4). Taking it early would leave
        // `Drop` with `conn == None` and strand the session lock.
        let unlock = match self.conn.as_deref_mut() {
            Some(conn) => Some(
                sqlx::query("SELECT pg_advisory_unlock($1)")
                    .bind(self.lock_key)
                    .execute(&mut *conn)
                    .await,
            ),
            None => None,
        };
        // An unlock that ERRORS is a different failure from a cancellation: the
        // await resolved, so the session is alive and still holds the lock, and
        // returning that connection to the pool does not recover it because
        // `after_release` runs its `pg_advisory_unlock_all()` on the same broken
        // session and fails identically (#174 F3b). Close it: ending the session
        // is what frees the lock.
        if let Some(Err(e)) = unlock {
            warn!(repo = %self.repo_label, err = %e,
                "advisory unlock failed, closing the connection so the session ends and postgres drops the lock");
            if let Some(conn) = self.conn.take() {
                close_conn_bounded(&self.repo_label, conn.close()).await;
            }
        }
        // Only now that the await has resolved: mark released so the `Drop`
        // backstop below does not re-issue an unlock on a lock already freed.
        // On the clean path, dropping `self` returns the connection to the lock
        // pool, where `after_release` sweeps anything this missed.
        self.released = true;
    }
}

impl Drop for LockedConn {
    /// Backstop for a holder dropped WITHOUT `unlock` (a cancelled
    /// `acquire_write`, a handler future dropped before release, a cancelled
    /// write-back task). The pool's `after_release` hook covers the ordinary
    /// case on its own, but not one: if the detached unlock ERRORS on a live
    /// session, the hook's `pg_advisory_unlock_all()` fails the same way and
    /// the connection returns to the pool still holding the lock (#174 F3b).
    /// So the unlock runs here and disposes of the connection when it errors.
    ///
    /// `Drop` cannot await, so the unlock is spawned; it runs on the same
    /// session, which is what makes it effective. With no runtime to spawn onto
    /// there is nothing that can unlock, so the connection is detached and
    /// dropped instead: closing the socket ends the session, and that frees the
    /// lock server-side (and detaching first avoids sqlx's return-to-pool
    /// spawn, which panics off-runtime).
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let Some(mut conn) = self.conn.take() else {
            return;
        };
        let lock_key = self.lock_key;
        let repo_label = self.repo_label.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    let unlock = sqlx::query("SELECT pg_advisory_unlock($1)")
                        .bind(lock_key)
                        .execute(&mut *conn)
                        .await;
                    if let Err(e) = unlock {
                        warn!(repo = %repo_label, err = %e,
                            "detached advisory-unlock on lock-holder drop failed, closing the connection so the session ends and postgres drops the lock");
                        close_conn_bounded(&repo_label, conn.close()).await;
                    }
                });
            }
            Err(_) => {
                drop(conn.detach());
                warn!(
                    repo = %repo_label,
                    "advisory-lock holder dropped off a Tokio runtime; no detached unlock is \
                     possible, so the pinned connection is disposed of instead: ending the \
                     session is what releases the advisory lock"
                );
            }
        }
    }
}

/// Guard returned by `acquire_write()`. Holds the Postgres advisory lock and
/// uploads to storage + releases the lock on `release()`.
///
/// `#[must_use]`: dropping the guard without calling `release()` skips the
/// storage upload and force-closes the pinned lock connection to free the
/// advisory lock (see [`LockedConn`]) — safe, but never what a caller wants.
#[must_use = "call release() — dropping the guard skips the upload and force-closes the lock connection"]
pub struct RepoWriteGuard {
    owner_slug: String,
    repo_name: String,
    pub local_path: PathBuf,
    /// The pinned advisory-lock connection; freed on `release()`, or by
    /// `LockedConn::drop` if the guard (or a write-back task driving it) is
    /// dropped or cancelled mid-flight.
    lock: LockedConn,
    archive: Option<RepoArchive>,
    versions: Arc<Mutex<HashMap<String, String>>>,
    /// Shared with the store that handed this guard out; see
    /// [`RepoStore::upload_site_reached`].
    #[cfg(test)]
    upload_site_reached: Arc<std::sync::atomic::AtomicUsize>,
    /// Test-only seam: when set, `release` parks on this gate at the exact point it
    /// is about to await the advisory unlock (connection still owned by the guard's
    /// `LockedConn`). Dropping the `release` future while it is parked reproduces a
    /// mid-unlock cancellation; the guard then drops with the lock connection still
    /// pinned, and `LockedConn`'s backstop frees the lock. Never set outside tests.
    #[cfg(test)]
    test_pre_unlock_gate: Option<Arc<tokio::sync::Notify>>,
}

impl RepoWriteGuard {
    /// Path to the bare repo on local disk.
    pub fn path(&self) -> &Path {
        &self.local_path
    }

    /// Durably record intent-to-upload NOW, before the caller acks the client.
    /// Write-back callers must call this before spawning `release()` — the
    /// spawned task may never be polled if the process stops right after the
    /// ack, and without the marker already on disk a restart would treat the
    /// stale storage archive as newer and roll the acked write back. On `Err`
    /// the caller must NOT ack early; fall back to strict upload-before-ack.
    /// Idempotent with the marker `release()` writes itself. No-op without a
    /// storage backend (markers would be inert until a backend appears, then
    /// wedge repos whose archives predate them).
    pub async fn mark_pending(&self) -> Result<()> {
        if self.archive.is_none() {
            return Ok(());
        }
        let key = format!("{}/{}", self.owner_slug, self.repo_name);
        let base = self.versions.lock().await.get(&key).cloned();
        mark_pending_upload(&self.local_path, base.as_deref())
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
    pub async fn release(self, success: bool) -> Result<()> {
        let key = format!("{}/{}", self.owner_slug, self.repo_name);

        // Upload to storage only on success. Capture the outcome so we can both
        // release the lock unconditionally and propagate a durable-upload
        // failure to the caller (a synchronous caller turns it into a client
        // error; a write-back caller logs it).
        let upload_result: Result<()> = if success {
            // The upload site, recorded for tests before the backend is consulted: it
            // counts the DECISION to upload, so it moves even with no backend
            // configured, and reaching this point at all is what an interrupted push
            // must never do (#173 F2).
            #[cfg(test)]
            self.upload_site_reached
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(ref archive) = self.archive {
                let base = self.versions.lock().await.get(&key).cloned();
                if let Err(e) = mark_pending_upload(&self.local_path, base.as_deref()) {
                    // Proceed with the upload anyway: if it succeeds, no marker
                    // is needed; if both fail, the error below reaches the
                    // caller (double-failure corner, same exposure as
                    // pre-marker behavior).
                    warn!(repo = %self.repo_name, err = %e, "failed to write pending-upload marker");
                }
                match archive
                    .upload_with_intent(
                        &self.owner_slug,
                        &self.repo_name,
                        &self.local_path,
                        |intended| record_inflight_upload(&self.local_path, intended),
                    )
                    .await
                {
                    Ok(Some(etag)) => {
                        self.versions.lock().await.insert(key.clone(), etag.clone());
                        clear_pending_upload_after_success(&self.local_path, Some(&etag));
                        Ok(())
                    }
                    Ok(None) => {
                        clear_pending_upload(&self.local_path);
                        Ok(())
                    }
                    Err(e) => {
                        // Storage is now behind local (this holds even for an
                        // already-acked write-back push). Drop the cached etag,
                        // and leave the pending-upload marker so the next
                        // access serves the local copy instead of rolling it
                        // back to the stale archive; the next successful
                        // upload re-syncs storage and clears the marker.
                        self.versions.lock().await.remove(&key);
                        Err(e).context("uploading repo to storage after write")
                    }
                }
            } else {
                Ok(())
            }
        } else {
            // Write failed: skip the upload (a half-applied repo must not reach
            // storage) and invalidate the cached etag — the local copy may be
            // dirty, so the next write must re-download instead of skipping on a
            // now-misleading etag match.
            warn!(repo = %self.repo_name, "write failed — skipping storage upload and invalidating etag cache");
            self.versions.lock().await.remove(&key);
            Ok(())
        };

        // Test-only: park right before the unlock await so a test can drop this
        // future mid-unlock, with the connection still owned.
        #[cfg(test)]
        if let Some(gate) = self.test_pre_unlock_gate.clone() {
            gate.notified().await;
        }
        // Release the advisory lock on the same connection it was taken on
        // regardless of the upload outcome, then return it to the pool.
        self.lock.unlock().await;

        upload_result
    }
}

/// Sibling marker file recording that `local_path` holds writes storage has
/// not received yet ("local is ahead"). Written before every post-write upload
/// and removed only when the upload succeeds, so it survives process death and
/// lets `sync_down_if_stale` distinguish "storage is ahead of local" (download)
/// from "local is ahead of storage" (never download — that would roll back an
/// acked write). Lives next to the repo dir, not inside it, so it is never
/// packed into the archive.
/// Fallible because it goes through [`validated_sibling_path`]: the marker name
/// is built from the repo's own file name, which carries user-provided data, so
/// the path is re-checked here rather than trusted from the repo path's own
/// earlier validation. Callers that cannot propagate the error (the `Drop`-like
/// cleanup paths) treat a rejected path as "no marker", which is the same
/// conservative answer they already give for an unreadable one.
fn pending_upload_marker(local_path: &Path) -> Result<PathBuf> {
    let name = local_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    validated_sibling_path(local_path, &format!(".{name}.pending-upload"))
}

/// The marker's rename-temp sibling. Same barrier, same reason; the UUID is
/// ours but the prefix is not, and one helper means the two cannot drift.
fn pending_upload_marker_tmp(local_path: &Path) -> Result<PathBuf> {
    validated_sibling_path(
        local_path,
        &format!(".pending-upload.tmp-{}", uuid::Uuid::new_v4()),
    )
}

/// Persist the intent-to-upload marker. Fallible (write-back callers must NOT
/// ack the client if this fails) and atomic (tmp + rename, so a crash cannot
/// leave a torn marker).
///
/// `base_etag` is the storage etag the local write was built on (empty when
/// storage held nothing). `sync_down_if_stale` compares it against the current
/// remote etag to distinguish "local strictly ahead" from cross-node
/// divergence.
///
/// An existing marker is preserved untouched: its base is the last storage
/// etag this node confirmed, which stays correct for every further write
/// stacked on the same undiverged local copy. Re-marking would record the
/// CURRENT cache — emptied by the preceding upload failure — and a corrupted
/// (empty) base makes the next sync read unchanged storage as divergence,
/// wedging the repo's whole write surface after two consecutive upload
/// failures.
fn mark_pending_upload(local_path: &Path, base_etag: Option<&str>) -> Result<()> {
    let marker = pending_upload_marker(local_path)?;
    match marker.try_exists() {
        Ok(true) => return Ok(()), // keep the original base
        Ok(false) => {}
        Err(e) => return Err(e).context("probing pending-upload marker"),
    }
    let tmp = pending_upload_marker_tmp(local_path)?;
    std::fs::write(&tmp, base_etag.unwrap_or_default()).context("writing pending-upload marker")?;
    std::fs::rename(&tmp, &marker)
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
        .context("publishing pending-upload marker")?;
    crate::metrics::add_pending_upload_markers(1);
    Ok(())
}

pub(crate) fn clear_pending_upload(local_path: &Path) {
    // A path the barrier rejects is one we must never have written, so there is
    // nothing to clear and nothing to report: the same no-op this already
    // performs for a marker that is simply absent.
    let Ok(marker) = pending_upload_marker(local_path) else {
        return;
    };
    if std::fs::remove_file(marker).is_ok() {
        crate::metrics::add_pending_upload_markers(-1);
    }
}

/// Etags compared structurally: S3 returns them quoted, our recorded values
/// are bare, and whitespace can differ across the marker round-trip.
fn norm_etag(e: &str) -> &str {
    e.trim().trim_matches('"')
}

/// Parsed pending-upload marker. Line 1 is the storage etag the local write
/// was BASED on; optional line 2 is the etag the in-flight upload was going to
/// produce (the archive's content MD5, recorded just before the PUT).
struct PendingMarker {
    base: String,
    inflight: Option<String>,
}

impl PendingMarker {
    /// Storage still holds exactly what the local write was based on: local
    /// is strictly ahead.
    fn matches_base(&self, remote: &str) -> bool {
        norm_etag(remote) == norm_etag(&self.base)
    }
}

fn read_pending_marker(local_path: &Path) -> PendingMarker {
    // A rejected path reads as an empty marker, which is what an absent or
    // unreadable one already produces: an empty base matches only empty
    // storage, so recovery stays conservative rather than claiming a base it
    // never confirmed.
    let content = pending_upload_marker(local_path)
        .ok()
        .and_then(|marker| std::fs::read_to_string(marker).ok())
        .unwrap_or_default();
    let mut lines = content.lines();
    let base = lines.next().unwrap_or("").trim().to_string();
    let inflight = lines
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    PendingMarker { base, inflight }
}

/// Atomically rewrite the marker as `base\nintended` just before the PUT, so
/// a crash anywhere between the PUT landing and the post-upload clear leaves a
/// marker that names the uploaded content — recovery then recognizes storage
/// as this node's own completed upload instead of wedging on false divergence.
/// MUST be fallible: if the intent cannot be durably recorded, the PUT it
/// describes must not run (the caller aborts the upload), or a crash after
/// that PUT reads as external divergence.
fn record_inflight_upload(local_path: &Path, intended_etag: &str) -> Result<()> {
    let marker = pending_upload_marker(local_path)?;
    let base = read_pending_marker(local_path).base;
    let tmp = pending_upload_marker_tmp(local_path)?;
    std::fs::write(&tmp, format!("{base}\n{intended_etag}"))
        .context("writing in-flight upload intent")?;
    std::fs::rename(&tmp, &marker)
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
        .context("publishing in-flight upload intent")
}

/// Remove the marker after a *successful* upload, first atomically rewriting
/// its base to the just-uploaded etag. A crash between the rewrite and the
/// unlink then reads as "local ahead, base matches" — which self-heals on the
/// next write or startup retry — instead of "base predates storage", which
/// would wedge the repo behind a spurious permanent divergence even though
/// local and storage are identical.
fn clear_pending_upload_after_success(local_path: &Path, new_etag: Option<&str>) {
    // As in `clear_pending_upload`: a path the barrier rejects is one nothing
    // ever wrote, so there is no marker to rewrite and none to unlink.
    let Ok(marker) = pending_upload_marker(local_path) else {
        return;
    };
    if let Some(etag) = new_etag {
        if marker.exists() {
            if let Ok(tmp) = pending_upload_marker_tmp(local_path) {
                if std::fs::write(&tmp, etag).is_ok() {
                    let _ = std::fs::rename(&tmp, &marker);
                } else {
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }
    }
    if std::fs::remove_file(&marker).is_ok() {
        crate::metrics::add_pending_upload_markers(-1);
    }
}

/// Outcome of a marker-protected upload attempt.
enum PendingUploadOutcome {
    /// Uploaded, versions cache updated, marker cleared — all under the lock.
    Uploaded,
    /// Storage no longer matches the marker's base: another writer advanced it.
    /// Nothing was uploaded and the marker was left in place.
    Diverged,
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
///     holds its lock connection for the whole receive-pack, so drawing these
///     from the main pool would let a burst of `max_concurrent_git_pushes`
///     pushes park that many query connections for the length of their
///     receive-packs and starve every other query. That is true at any pool
///     size, so the separation does not rest on how the two knobs are set;
///     `Config::validate` separately requires `db_max_connections` to clear
///     `max_concurrent_git_pushes` by `DB_POOL_APP_HEADROOM`.
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
///
/// Uses SHA-256 (not `DefaultHasher`) so the same `(owner_slug, repo_name)`
/// produces the same `i64` key across every Rust toolchain version, operating
/// system, and machine — the algorithm is frozen by the SHA-2 standard rather
/// than by a std-internal implementation detail.
///
/// Domain separation is `owner_slug + ":" + repo_name` with no length prefix,
/// so the mapping is injective only while `owner_slug` contains no `:` (the
/// `did:key:`→`did_key_` slug form `local_path` produces). A raw DID would
/// collide: `("did:key:abc", "x")` and `("did", "key:abc:x")` hash the same.
pub(crate) fn advisory_lock_key(owner_slug: &str, repo_name: &str) -> i64 {
    debug_assert!(
        !owner_slug.contains(':'),
        "advisory_lock_key owner_slug must not contain ':' (domain-separation guarantee)"
    );
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(owner_slug.as_bytes());
    hasher.update(b":");
    hasher.update(repo_name.as_bytes());
    let digest = hasher.finalize();
    i64::from_le_bytes(digest[..8].try_into().expect("sha256 output is >= 8 bytes"))
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
    /// `tokio::time::timeout`; when that fires during the storage phase the future
    /// is dropped after the advisory lock was taken and before `RepoWriteGuard`
    /// (the only thing that unlocks) exists. The lock then leaks and every later
    /// push to the same repo spins the 60-attempt / 60s ceiling and fails.
    #[sqlx::test]
    async fn cancelled_acquire_write_mid_storage_does_not_leak_the_lock(pool: PgPool) {
        let repos_dir = PathBuf::from("/tmp/gitlawb-test-repos");
        let owner = "did:key:z6MkCancelMidTigris";
        let repo = "cancel-mid-tigris";

        let store_pool = sibling_pool(&pool, 8);
        let stalling = RepoStore::for_testing(repos_dir.clone(), store_pool.clone())
            .with_storage_stall(Duration::from_secs(30));
        let cancelled = tokio::time::timeout(
            Duration::from_millis(500),
            stalling.acquire_write(owner, repo),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the acquire must still be inside the storage phase when the timeout fires"
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
        guard.release(false).await.ok();
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
        guard.release(false).await.ok();
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

        held.release(false).await.ok();
    }

    /// #173 F1 (RED-before/GREEN-after). A contended `acquire_write` spins for up to
    /// 60 one-second attempts. It must not OCCUPY a lock-pool connection for that whole
    /// spin: `acquire_write` has non-push callers (`api/issues.rs`, `api/pulls.rs`) that
    /// hold no concurrency permit, so any self-minted did:key could otherwise park a
    /// connection per call and starve authenticated pushes on EVERY repo.
    ///
    /// Lock pool of exactly 2, two spinners. Pre-fix (checkout hoisted above the retry
    /// loop) they pin both connections for the full spin and an UNCONTENDED acquire on a
    /// third repo dies on the pool acquire timeout. Post-fix each spinner returns its
    /// connection before sleeping, so it occupies ~0 and the uncontended acquire sails
    /// through.
    #[sqlx::test]
    async fn a_spinning_acquire_write_does_not_occupy_a_lock_pool_connection(pool: PgPool) {
        let owner = "did:key:z6MkSpinOccupancy";
        let owner_slug = owner.replace([':', '/'], "_");
        let store = RepoStore::new(
            PathBuf::from("/tmp/gitlawb-test-repos"),
            None,
            build_lock_pool(&pool, 2, Duration::from_secs(2)),
        );

        // An independent session holds both contended keys, so the spinners' try-locks
        // return false on every iteration and they stay in the retry loop.
        let holder = sibling_pool(&pool, 2);
        let mut held_conn = holder.acquire().await.expect("holder connection");
        for repo in ["spin-a", "spin-b"] {
            let taken: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(advisory_lock_key(&owner_slug, repo))
                .fetch_one(&mut *held_conn)
                .await
                .expect("holder try-lock");
            assert!(taken.0, "the holder must own {repo}'s key");
        }

        let mut spinners = Vec::new();
        for repo in ["spin-a", "spin-b"] {
            let store = store.clone();
            spinners.push(tokio::spawn(async move {
                store.acquire_write(owner, repo).await
            }));
        }
        // Let both reach the spin (each has done at least one failed try-lock by now).
        tokio::time::sleep(Duration::from_millis(500)).await;

        let started = std::time::Instant::now();
        let uncontended = tokio::time::timeout(
            Duration::from_secs(10),
            store.acquire_write(owner, "spin-free"),
        )
        .await
        .expect("the uncontended acquire must return, not hang");
        let elapsed = started.elapsed();
        let free_guard = uncontended.unwrap_or_else(|e| {
            panic!(
                "an UNCONTENDED acquire_write on a DIFFERENT repo must not be starved by \
                 spinners holding the lock pool; got: {e}"
            )
        });
        assert!(
            elapsed < Duration::from_secs(2),
            "the uncontended acquire must not queue behind the spinners for the pool \
             acquire timeout; took {elapsed:?}"
        );
        free_guard.release(false).await.ok();

        // The drop-and-retake cycle must still END in a real, exclusive lock: free
        // spin-a's key and the spinner that was cycling connections must take it.
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(advisory_lock_key(&owner_slug, "spin-a"))
            .execute(&mut *held_conn)
            .await
            .expect("release spin-a");
        let winner = tokio::time::timeout(Duration::from_secs(15), spinners.remove(0))
            .await
            .expect("the spinner must finish once its key frees")
            .expect("spinner task")
            .expect("the spinner must acquire once the key frees");
        let probe = sibling_pool(&pool, 2);
        assert!(
            !lock_is_free_elsewhere(&probe, advisory_lock_key(&owner_slug, "spin-a")).await,
            "the lock a spinner finally took must be observably held from another session"
        );
        winner.release(false).await.ok();

        for s in spinners {
            s.abort();
        }
        sqlx::query("SELECT pg_advisory_unlock_all()")
            .execute(&mut *held_conn)
            .await
            .expect("release the remaining holder lock");
    }

    /// #173 F1, the property the fix rests on: returning a lock-pool connection that
    /// holds NOTHING runs `after_release`'s `pg_advisory_unlock_all()`, which is a no-op
    /// and must not disturb a lock held on a DIFFERENT connection of the same pool.
    /// Session advisory locks are per connection, so this is by construction, but the
    /// spin fix depends on it, so it is proven by execution rather than assumed.
    #[sqlx::test]
    async fn returning_an_unlocked_connection_does_not_clear_another_connections_lock(
        pool: PgPool,
    ) {
        let owner = "did:key:z6MkNoOpUnlockAll";
        let repo = "noop-unlock";
        let key = advisory_lock_key(&owner.replace([':', '/'], "_"), repo);
        let probe = sibling_pool(&pool, 2);
        let lock_pool = build_lock_pool(&pool, 4, Duration::from_secs(5));
        let store = RepoStore::new(
            PathBuf::from("/tmp/gitlawb-test-repos"),
            None,
            lock_pool.clone(),
        );

        let guard = store.acquire_write(owner, repo).await.expect("acquire");

        // Churn the pool: check out and drop connections that hold no lock, exactly what
        // a spinning acquire now does between attempts. Each return fires
        // pg_advisory_unlock_all() on that connection.
        for _ in 0..10 {
            let mut conn = lock_pool.acquire().await.expect("churn checkout");
            let _: (i32,) = sqlx::query_as("SELECT 1")
                .fetch_one(&mut *conn)
                .await
                .expect("churn query");
            drop(conn);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            !lock_is_free_elsewhere(&probe, key).await,
            "a held write lock must survive other lock-pool connections being returned"
        );
        guard.release(true).await.ok();
        assert!(
            lock_is_free_elsewhere(&probe, key).await,
            "release must still free the lock after the churn"
        );
    }

    /// #173 F1: lock-pool exhaustion is a DISTINCT error the handler can shed as a 503,
    /// not a generic git 500. Both directions: an exhausted pool downcasts to
    /// [`LockPoolBusy`], and an unrelated failure (a rejected repo name) does not.
    #[sqlx::test]
    async fn lock_pool_exhaustion_is_a_distinct_downcastable_error(pool: PgPool) {
        let owner = "did:key:z6MkBusyDowncast";
        let store = RepoStore::new(
            PathBuf::from("/tmp/gitlawb-test-repos"),
            None,
            build_lock_pool(&pool, 1, Duration::from_secs(1)),
        );
        let held = store
            .acquire_write(owner, "busy-a")
            .await
            .expect("first acquire");

        let err = match store.acquire_write(owner, "busy-b").await {
            Ok(_) => panic!("an exhausted lock pool must error, not hand back a guard"),
            Err(e) => e,
        };
        assert!(
            err.downcast_ref::<LockPoolBusy>().is_some(),
            "lock-pool exhaustion must be downcastable so the handler sheds 503, got: {err}"
        );

        // MUST-NOT: an ordinary rejection is not a capacity signal.
        let other = match store.acquire_write(owner, "../escape").await {
            Ok(_) => panic!("a traversal repo name must be rejected"),
            Err(e) => e,
        };
        assert!(
            other.downcast_ref::<LockPoolBusy>().is_none(),
            "a validation failure must not masquerade as lock-pool capacity, got: {other}"
        );

        held.release(false).await.ok();
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
        guard.release(true).await.ok();
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
        guard.release(false).await.ok();

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
        other.release(false).await.ok();

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

        first.release(false).await.ok();
        let second = tokio::time::timeout(Duration::from_secs(10), contender)
            .await
            .expect("contender must finish once the lock is free")
            .expect("contender task")
            .expect("contender acquire");
        second.release(false).await.ok();
    }

    // ── sync slug validation (#272) ────────────────────────────────────────

    #[test]
    fn slug_accepts_owner_and_name() {
        let (owner, name) = validate_repo_slug("z6Mkfoo/hello").expect("valid slug");
        assert_eq!(owner, "z6Mkfoo");
        assert_eq!(name, "hello");
    }

    #[test]
    fn slug_rejects_traversal_in_owner_half() {
        assert!(validate_repo_slug("../hello").is_err());
    }

    #[test]
    fn slug_rejects_owner_half_only_the_did_validator_catches() {
        // These are the cases that isolate the `validate_owner_did` delegation.
        // `../hello` does NOT: the leading-character rule above rejects it
        // first, so deleting the delegation leaves that case green. Each owner
        // half here has exactly one separator, a non-empty name, and a leading
        // character the slug rules allow, so only the delegation can reject it.
        for bad in [
            "a..b/hello",    // interior `..` sequence
            "a%2e%2e/hello", // percent-encoded, disallowed `%`
            "own\\er/hello", // backslash
        ] {
            assert!(validate_repo_slug(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn slug_rejects_extra_separator() {
        // The verified #272 escape: `a//tmp/x` joined to an absolute
        // `/tmp/x.git` outside repos_dir.
        assert!(validate_repo_slug("a//tmp/gitlawb-probe").is_err());
        assert!(validate_repo_slug("../../etc/evil").is_err());
        assert!(validate_repo_slug("a/../../x").is_err());
    }

    #[test]
    fn slug_rejects_trailing_segment_only_the_separator_count_catches() {
        // The case that isolates the separator-count rule. Every slug in
        // `slug_rejects_extra_separator` is caught by some earlier rule
        // instead: `a//tmp/...` has an empty name half, `../../etc/evil` trips
        // the leading-character rule, and `a/../../x` has `..` as its name. Here
        // both halves are individually valid, so only the count can reject it.
        // It matters because the worker would otherwise join
        // `repos_dir/z6Mkfoo/hello.git` while composing the remote URL from the
        // full three-segment slug, silently mirroring one repo under another's
        // path.
        assert!(validate_repo_slug("z6Mkfoo/hello/extra").is_err());
    }

    #[test]
    fn slug_rejects_missing_separator() {
        for bad in ["..", "demo", ""] {
            assert!(validate_repo_slug(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn slug_rejects_empty_half() {
        for bad in ["/hello", "z6Mkfoo/"] {
            assert!(validate_repo_slug(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn slug_rejects_leading_dot_or_dash_owner() {
        // `./hello` would otherwise resolve to a mirror at the repos_dir root,
        // which the containment check would approve.
        for bad in ["./hello", "-owner/hello"] {
            assert!(validate_repo_slug(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn slug_rejects_bad_name_half() {
        for bad in [
            "z6Mkfoo/he\0llo",
            "z6Mkfoo/.hidden",
            "z6Mkfoo/-dash",
            "z6Mkfoo/a..b",
        ] {
            assert!(validate_repo_slug(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn slug_rejects_overlong_halves() {
        let long_owner = format!("{}/hello", "z".repeat(257));
        let long_name = format!("z6Mkfoo/{}", "n".repeat(101));
        assert!(validate_repo_slug(&long_owner).is_err());
        assert!(validate_repo_slug(&long_name).is_err());
    }

    #[test]
    fn slug_rejects_owner_half_at_the_filesystem_name_limit() {
        // The owner half becomes a single path component, and Linux NAME_MAX is
        // 255, so 256 is accepted by validate_owner_did (which bails only above
        // 256) but can never be created on disk. That made the sync row
        // permanently un-runnable: create_dir_all failed with ENAMETOOLONG on
        // every pass and the worker left the row pending, so ten unsigned
        // requests could hold the whole oldest-first batch forever.
        assert!(validate_repo_slug(&format!("{}/hello", "z".repeat(256))).is_err());
        // 255 is the largest creatable component and must still be accepted, so
        // the bound is not quietly over-tightened.
        assert!(validate_repo_slug(&format!("{}/hello", "z".repeat(255))).is_ok());
    }

    // ── canonical containment (#272) ───────────────────────────────────────

    use tempfile::TempDir;

    #[test]
    fn containment_accepts_a_path_inside_the_root() {
        let root = TempDir::new().unwrap();
        let inside = root.path().join("z6Mkfoo");
        std::fs::create_dir_all(&inside).unwrap();
        assert!(matches!(
            path_within_root(&inside.join("hello.git"), root.path()),
            Containment::Contained
        ));
    }

    #[test]
    fn containment_rejects_a_sibling_outside_the_root() {
        let base = TempDir::new().unwrap();
        let root = base.path().join("root");
        let sibling = base.path().join("other");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        assert!(matches!(
            path_within_root(&sibling, &root),
            Containment::Outside
        ));
    }

    #[cfg(unix)]
    #[test]
    fn containment_rejects_a_symlinked_directory_inside_the_root() {
        use std::os::unix::fs::symlink;
        let base = TempDir::new().unwrap();
        let root = base.path().join("root");
        let outside = base.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let link = root.join("owner");
        symlink(&outside, &link).unwrap();
        assert!(matches!(
            path_within_root(&link, &root),
            Containment::Outside
        ));
    }

    #[cfg(unix)]
    #[test]
    fn containment_rejects_a_symlinked_file_inside_the_root() {
        use std::os::unix::fs::symlink;
        let base = TempDir::new().unwrap();
        let root = base.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let outside = base.path().join("secret.txt");
        std::fs::write(&outside, b"x").unwrap();
        let link = root.join("hello.git");
        symlink(&outside, &link).unwrap();
        assert!(matches!(
            path_within_root(&link, &root),
            Containment::Outside
        ));
    }

    #[test]
    fn containment_accepts_a_missing_candidate_whose_parent_is_inside() {
        // The first-clone case: the mirror path does not exist yet, so only the
        // parent can be canonicalized. Rejecting this is total loss of mirroring.
        let root = TempDir::new().unwrap();
        let owner = root.path().join("z6Mkfoo");
        std::fs::create_dir_all(&owner).unwrap();
        let candidate = owner.join("hello.git");
        assert!(!candidate.exists());
        assert!(matches!(
            path_within_root(&candidate, root.path()),
            Containment::Contained
        ));
    }

    #[cfg(unix)]
    #[test]
    fn containment_rejects_a_missing_candidate_under_a_symlinked_parent() {
        use std::os::unix::fs::symlink;
        let base = TempDir::new().unwrap();
        let root = base.path().join("root");
        let outside = base.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.join("z6Mkfoo")).unwrap();
        let candidate = root.join("z6Mkfoo").join("hello.git");
        assert!(matches!(
            path_within_root(&candidate, &root),
            Containment::Outside
        ));
    }

    #[cfg(unix)]
    #[test]
    fn containment_reports_io_error_for_a_dangling_symlink() {
        // The link entry exists, so the candidate is the thing to resolve, and
        // resolving it fails. That is an I/O answer, not a verdict of Outside:
        // the worker must retry rather than permanently retire the row.
        use std::os::unix::fs::symlink;
        let root = TempDir::new().unwrap();
        let link = root.path().join("hello.git");
        symlink(root.path().join("nothing-here"), &link).unwrap();
        assert!(matches!(
            path_within_root(&link, root.path()),
            Containment::IoError(_)
        ));
    }

    #[test]
    fn containment_reports_io_error_for_an_uncanonicalizable_root() {
        // A repos_dir that cannot be resolved is an operator condition (an
        // unmounted volume, a bad config), not a hostile path.
        let base = TempDir::new().unwrap();
        let root = base.path().join("not-mounted");
        let candidate = base.path().join("not-mounted").join("hello.git");
        assert!(matches!(
            path_within_root(&candidate, &root),
            Containment::IoError(_)
        ));
    }

    #[test]
    fn containment_creates_nothing_on_disk() {
        // The predicate is pure: the admin purge path asks it about directories
        // it is about to delete, so creating one as a side effect would be wrong.
        let root = TempDir::new().unwrap();
        let candidate = root.path().join("z6Mkfoo").join("hello.git");
        let _ = path_within_root(&candidate, root.path());
        assert!(!candidate.exists());
        assert!(!root.path().join("z6Mkfoo").exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
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

    // ── advisory_lock_key stability ─────────────────────────────────────────

    #[test]
    fn advisory_lock_key_is_stable() {
        // Golden value: SHA-256("did_key_...:<repo_name>")[..8] as i64 little-endian.
        // If this test fails, the hashing algorithm has changed — the new key
        // must be backward-compatible or the rollout planned accordingly.
        let key = advisory_lock_key(
            "did_key_z6MkqDnb7Siv3Cwj7pGJq4T5EsUisECqR8KpnDLwcaZq5TPr",
            "hello",
        );
        assert_eq!(key, -6680856138670956537_i64);
    }

    #[test]
    fn advisory_lock_key_differs_for_different_inputs() {
        // Vary one axis at a time so a regression that drops either parameter
        // from the hash is caught, not just one that drops both. The golden
        // test above backstops a total algorithm swap.
        let base = advisory_lock_key("owner_a", "repo_a");

        // Same owner, different repo: a regression that hashes only owner_slug
        // would make these collide.
        let same_owner_diff_repo = advisory_lock_key("owner_a", "repo_b");
        assert_ne!(
            base, same_owner_diff_repo,
            "key must depend on repo_name, not just owner_slug"
        );

        // Same repo, different owner: a regression that hashes only repo_name
        // would make these collide.
        let diff_owner_same_repo = advisory_lock_key("owner_b", "repo_a");
        assert_ne!(
            base, diff_owner_same_repo,
            "key must depend on owner_slug, not just repo_name"
        );

        // Sanity: both axes varying at once still differs (the original shape).
        let both_differ = advisory_lock_key("owner_b", "repo_b");
        assert_ne!(base, both_differ);
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
        guard.release(false).await.ok();

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
    /// advisory lock. The guard owns the lock-pool connection that took the lock, so
    /// dropping the parked `release` future returns that connection to the pool,
    /// where the `after_release` hook runs `pg_advisory_unlock_all()` and clears
    /// whatever the interrupted unlock did not. A test-only gate parks `release` at
    /// the exact pre-unlock point; dropping the future there reproduces the
    /// cancellation.
    ///
    /// Load-bearing: build the store's lock pool WITHOUT the `after_release` hook
    /// and this goes RED, since the connection then returns to the pool still
    /// holding the session lock and the checker's `pg_try_advisory_lock` returns
    /// false.
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
        guard.release(true).await.ok();

        let again = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            store.acquire_write(owner, name),
        )
        .await
        .expect("second acquire_write must not hit the ~60s stale-lock retry loop")
        .expect("second acquire");
        again.release(true).await.ok();
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
            .lock
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

    /// U8, the off-runtime arm: with no Tokio runtime there is nothing to spawn the
    /// unlock onto, and the connection has already been taken out of the guard, so
    /// dropping it with no unlock attempted returns it to the pool with the session
    /// lock still held. Dropping a `PoolConnection` off a runtime is worse than that:
    /// sqlx's return-to-pool path spawns, and its no-runtime fallback panics, so that
    /// arm also panics in a destructor.
    ///
    /// Reached by dropping the guard on a plain `std::thread`, where
    /// `Handle::try_current()` fails.
    ///
    /// Load-bearing: replace the `detach` arm with a plain `drop(conn)` and the join
    /// sees sqlx's "requires a Tokio context" panic; `detach` gives up the pool slot,
    /// so nothing is spawned and dropping the detached connection closes the socket,
    /// which ends the session and frees the lock.
    #[sqlx::test]
    async fn write_guard_dropped_off_runtime_disposes_the_connection(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let store_pool = pool_without_idle_reaper(&pool).await;
        let store = RepoStore::for_testing(dir.path().to_path_buf(), store_pool.clone());
        let owner = "did:key:z6MkDropOffRuntimeProofKKKKKKKKKKKKKKKKKK";
        let name = "dropoffruntimetest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        let mut checker = pool.acquire().await.expect("checker connection");
        let guard = store.acquire_write(owner, name).await.expect("acquire");
        // The guard's connection lives in the store's DERIVED lock pool, not the pool
        // handed to `for_testing`; see `RepoStore::lock_pool`.
        let lock_pool = store.lock_pool().clone();
        let size_before = lock_pool.size();
        assert!(size_before > 0, "the lock pool owns the guard's connection");

        let dropped = std::thread::spawn(move || drop(guard)).join();
        assert!(
            dropped.is_ok(),
            "dropping a write guard off a Tokio runtime must not panic"
        );

        wait_until(
            || lock_pool.size() == size_before - 1,
            "the connection of a guard dropped off a runtime to be disposed of rather \
             than returned to the pool with no unlock attempted",
        )
        .await;
        wait_until_lock_free(
            &mut checker,
            key,
            "a guard dropped off a runtime to end its session so postgres drops the lock",
        )
        .await;
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
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

        guard.release(false).await.ok();

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
        let lock_pool = store.lock_pool().clone();
        let size_before = lock_pool.size();
        assert!(size_before > 0, "the lock pool owns the guard's connection");

        guard.release(false).await.ok();

        // The pool's size drops when the closed connection's slot is given up, which
        // is not synchronous with `release` returning: poll rather than sleep.
        wait_until(
            || lock_pool.size() == size_before - 1,
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

        guard.release(false).await.ok();
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

    // ── the Drop backstop disposes its connection too (#174 U8) ─────────────

    /// U8 (P2): the `Drop` backstop carries the same hazard F3b closed in `release`.
    /// When the detached `pg_advisory_unlock` ERRORS on a live session, the async
    /// block ends and drops the moved `PoolConnection`, which RETURNS it to the pool
    /// while that session may still hold the lock, handing the next caller a
    /// connection holding a lock nobody tracks. The errored connection must be closed
    /// instead: that keeps it out of the pool and ends the session, which is what
    /// frees the lock server-side.
    ///
    /// Run against a pool with the idle reaper disabled, for the reason spelled out on
    /// `pool_without_idle_reaper`: with the reaper in play the session dies on its own
    /// about a second later and the assertion stops measuring the disposal.
    ///
    /// Load-bearing: RED before the fix (the connection goes back to the pool, so the
    /// size never drops and this times out), GREEN after.
    #[sqlx::test]
    async fn write_guard_drop_with_failing_unlock_does_not_return_the_connection(
        pool: sqlx::PgPool,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let store_pool = pool_without_idle_reaper(&pool).await;
        let store = RepoStore::for_testing(dir.path().to_path_buf(), store_pool.clone());
        let owner = "did:key:z6MkDropUnlockErrProofIIIIIIIIIIIIIIIIIIII";
        let name = "dropunlockerrtest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        // Distinct session for the probe, held out of the store's pool entirely.
        let mut checker = pool.acquire().await.expect("checker connection");

        let mut guard = store.acquire_write(owner, name).await.expect("acquire");
        poison_guard_connection(&mut guard).await;
        let lock_pool = store.lock_pool().clone();
        let size_before = lock_pool.size();
        assert!(size_before > 0, "the lock pool owns the guard's connection");

        // The backstop shape: dropped without release(), with an unlock that errors.
        drop(guard);

        wait_until(
            || lock_pool.size() == size_before - 1,
            "the connection whose detached unlock errored to be closed rather than \
             returned to the pool still holding the session lock",
        )
        .await;
        wait_until_lock_free(
            &mut checker,
            key,
            "an errored detached unlock must not leave the lock held: Drop must dispose \
             of the connection so the session ends",
        )
        .await;
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
    }

    /// U8 regression guard on the success path: a detached unlock that SUCCEEDS must
    /// still return the connection to the pool. Without this, "close the connection on
    /// Drop" could be widened to "always close" and the test above would not notice.
    #[sqlx::test]
    async fn write_guard_drop_with_successful_unlock_keeps_the_connection(pool: sqlx::PgPool) {
        let dir = tempfile::TempDir::new().unwrap();
        let store_pool = pool_without_idle_reaper(&pool).await;
        let store = RepoStore::for_testing(dir.path().to_path_buf(), store_pool.clone());
        let owner = "did:key:z6MkDropUnlockOkProofJJJJJJJJJJJJJJJJJJJJ";
        let name = "dropunlockoktest";
        let slug = owner.replace([':', '/'], "_");
        let key = advisory_lock_key(&slug, name);

        let mut checker = pool.acquire().await.expect("checker connection");
        let guard = store.acquire_write(owner, name).await.expect("acquire");
        let lock_pool = store.lock_pool().clone();
        let size_before = lock_pool.size();
        assert!(size_before > 0, "the lock pool owns the guard's connection");

        drop(guard);

        // The connection goes back only once the detached unlock task has finished.
        wait_until(
            || lock_pool.num_idle() > 0,
            "the detached unlock to finish and hand the connection back",
        )
        .await;
        assert_eq!(
            lock_pool.size(),
            size_before,
            "a successful detached unlock must leave the connection in the pool"
        );
        wait_until_lock_free(
            &mut checker,
            key,
            "the Drop backstop's successful unlock to free the lock",
        )
        .await;
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *checker)
            .await;
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

    // Needs a real pool: `release_after_write` uploads under the advisory lock.
    #[sqlx::test]
    async fn pending_marker_prevents_rollback_and_clears_on_next_upload(pool: PgPool) {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let blob: Arc<dyn crate::storage::BlobStore> =
            Arc::new(crate::storage::fs::FsBlobStore::new(store_root.path()).unwrap());
        let store = RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(crate::storage::archive::RepoArchive::new(blob)),
            pool,
        );

        // Storage holds v1; local downloads it.
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
            .sync_down_if_stale("owner", "repo", &local, true)
            .await
            .unwrap();

        // Simulate an acked write whose upload failed: local advances, the
        // pending marker (recording the storage etag the write was based on)
        // persists, and the in-memory cache was invalidated on failure.
        let base = store
            .archive
            .as_ref()
            .unwrap()
            .head_etag("owner", "repo")
            .await
            .unwrap()
            .unwrap();
        std::fs::write(local.join("HEAD"), b"ACKED-WRITE\n").unwrap();
        mark_pending_upload(&local, Some(&base)).unwrap();
        store.versions.lock().await.clear();

        // Both the read and the write path must serve local, not roll it back.
        for require_fresh in [false, true] {
            store
                .sync_down_if_stale("owner", "repo", &local, require_fresh)
                .await
                .unwrap();
            assert_eq!(
                std::fs::read(local.join("HEAD")).unwrap(),
                b"ACKED-WRITE\n",
                "pending marker must prevent rollback (require_fresh={require_fresh})"
            );
        }

        // The next successful write-path upload re-syncs storage and clears
        // the marker.
        let guard = store.acquire_write("owner", "repo").await.unwrap();
        guard.release(true).await.unwrap();
        assert!(
            !pending_upload_marker(&local).unwrap().exists(),
            "marker must be cleared by a successful upload"
        );
        let out = tempfile::tempdir().unwrap();
        let restored = out.path().join("restored.git");
        store
            .archive
            .as_ref()
            .unwrap()
            .download("owner", "repo", &restored)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(restored.join("HEAD")).unwrap(),
            b"ACKED-WRITE\n"
        );
    }

    #[tokio::test]
    async fn pending_marker_detects_cross_node_divergence() {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let store = store_with_fs_archive(repos_dir.path().to_path_buf(), store_root.path());

        // Storage v1; local synced, then advanced with a failed upload (marker
        // records v1's etag as its base).
        let seed = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("HEAD"), b"v1\n").unwrap();
        let archive = store.archive.as_ref().unwrap();
        archive.upload("owner", "repo", seed.path()).await.unwrap();
        let local = repos_dir.path().join("owner").join("repo.git");
        store
            .sync_down_if_stale("owner", "repo", &local, true)
            .await
            .unwrap();
        let base = archive.head_etag("owner", "repo").await.unwrap().unwrap();
        std::fs::write(local.join("HEAD"), b"LOCAL-AHEAD\n").unwrap();
        mark_pending_upload(&local, Some(&base)).unwrap();
        store.versions.lock().await.clear();

        // Another node advances storage past our base.
        let seed2 = tempfile::tempdir().unwrap();
        std::fs::write(seed2.path().join("HEAD"), b"OTHER-NODE\n").unwrap();
        archive.upload("owner", "repo", seed2.path()).await.unwrap();

        // Write path: refuse — proceeding would clobber one side or the other.
        assert!(
            store
                .sync_down_if_stale("owner", "repo", &local, true)
                .await
                .is_err(),
            "diverged marker must fail the write path closed"
        );
        // Read path: serve local (read-only cannot propagate damage), and the
        // local copy must be untouched either way.
        store
            .sync_down_if_stale("owner", "repo", &local, false)
            .await
            .unwrap();
        assert_eq!(std::fs::read(local.join("HEAD")).unwrap(), b"LOCAL-AHEAD\n");
    }

    #[tokio::test]
    async fn stale_pending_marker_without_local_copy_is_dropped() {
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

        // Marker exists but the repo dir does not (removed out from under us):
        // the marker is stale — drop it and download normally.
        let local = repos_dir.path().join("owner").join("repo.git");
        std::fs::create_dir_all(local.parent().unwrap()).unwrap();
        mark_pending_upload(&local, Some("whatever")).unwrap();
        store
            .sync_down_if_stale("owner", "repo", &local, true)
            .await
            .unwrap();
        assert_eq!(std::fs::read(local.join("HEAD")).unwrap(), b"v1\n");
        assert!(!pending_upload_marker(&local).unwrap().exists());
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
        // The fs backend's etag lives in a sidecar, so a direct file overwrite
        // must also bump it for the change to be visible (as any real writer's
        // put() would).
        std::fs::write(
            store_root.path().join("repos/v1/owner/repo.tar.zst.etag"),
            "corrupted-generation",
        )
        .unwrap();

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

    // ── failing-store double: exercises error branches no real backend can ──

    /// BlobStore wrapper whose `put`/`head` can be flipped to fail, unlocking
    /// deterministic coverage of the upload-failure and head-failure branches.
    struct FlakyStore {
        inner: crate::storage::fs::FsBlobStore,
        fail_put: std::sync::atomic::AtomicBool,
        fail_head: std::sync::atomic::AtomicBool,
    }

    impl FlakyStore {
        fn new(root: &Path) -> Arc<Self> {
            Arc::new(Self {
                inner: crate::storage::fs::FsBlobStore::new(root).unwrap(),
                fail_put: std::sync::atomic::AtomicBool::new(false),
                fail_head: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::BlobStore for FlakyStore {
        fn backend_name(&self) -> &'static str {
            "flaky"
        }
        async fn get(&self, key: &str) -> Result<Option<bytes::Bytes>> {
            self.inner.get(key).await
        }
        async fn put(&self, key: &str, body: bytes::Bytes) -> Result<crate::storage::ObjectMeta> {
            if self.fail_put.load(std::sync::atomic::Ordering::Relaxed) {
                anyhow::bail!("injected put failure");
            }
            self.inner.put(key, body).await
        }
        async fn head(&self, key: &str) -> Result<Option<crate::storage::ObjectMeta>> {
            if self.fail_head.load(std::sync::atomic::Ordering::Relaxed) {
                anyhow::bail!("injected head failure");
            }
            self.inner.head(key).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
    }

    fn store_with_flaky(repos_dir: PathBuf, flaky: Arc<FlakyStore>, pool: PgPool) -> RepoStore {
        let blob: Arc<dyn crate::storage::BlobStore> = flaky;
        let archive = crate::storage::archive::RepoArchive::new(blob);
        RepoStore::new(repos_dir, Some(archive), pool)
    }

    /// beardthelion P1 regression: two consecutive failed uploads must not
    /// corrupt the marker's base — the second `release` re-marks while the
    /// versions cache is empty, and overwriting the base with "" would make
    /// the third write read unchanged storage as divergence and wedge the
    /// repo's entire write surface.
    #[sqlx::test]
    async fn two_consecutive_failed_uploads_preserve_marker_base(pool: PgPool) {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let flaky = FlakyStore::new(store_root.path());
        let store = store_with_flaky(repos_dir.path().to_path_buf(), Arc::clone(&flaky), pool);

        // Storage v1, synced down.
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
            .sync_down_if_stale("owner", "repo", &local, true)
            .await
            .unwrap();

        // Write 1: mutate, upload fails.
        flaky
            .fail_put
            .store(true, std::sync::atomic::Ordering::Relaxed);
        std::fs::write(local.join("HEAD"), b"write-1\n").unwrap();
        let guard = store.acquire_write("owner", "repo").await.unwrap();
        assert!(guard.release(true).await.is_err(), "injected put must fail");
        let base_after_first = read_pending_marker(&local).base;
        assert!(!base_after_first.is_empty(), "base must be recorded");

        // Write 2: acquire must succeed (storage unchanged == local-ahead),
        // and the second failed release must NOT re-mark with an empty base.
        // (The in-flight line legitimately changes per attempt; the BASE is
        // the invariant.)
        let guard = store.acquire_write("owner", "repo").await.unwrap();
        std::fs::write(local.join("HEAD"), b"write-2\n").unwrap();
        assert!(guard.release(true).await.is_err());
        assert_eq!(
            read_pending_marker(&local).base,
            base_after_first,
            "an existing marker's base must be preserved on re-mark"
        );

        // Write 3: still not wedged — and once the store heals, everything
        // re-syncs and the marker clears.
        let guard = store
            .acquire_write("owner", "repo")
            .await
            .expect("repeated upload failures must not wedge the write surface");
        flaky
            .fail_put
            .store(false, std::sync::atomic::Ordering::Relaxed);
        guard.release(true).await.unwrap();
        assert!(!pending_upload_marker(&local).unwrap().exists());
    }

    /// jatmn P1 regression: the write-back ack window. `mark_pending` runs
    /// before the ack; if the process dies before the spawned release is ever
    /// polled (simulated by dropping the guard), the marker alone must keep
    /// the next sync from rolling the acked write back.
    #[sqlx::test]
    async fn mark_pending_alone_protects_the_ack_window(pool: PgPool) {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let flaky = FlakyStore::new(store_root.path());
        let store = store_with_flaky(repos_dir.path().to_path_buf(), Arc::clone(&flaky), pool);

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

        let guard = store.acquire_write("owner", "repo").await.unwrap();
        std::fs::write(local.join("HEAD"), b"ACKED\n").unwrap();
        guard.mark_pending().await.unwrap();
        drop(guard); // crash before release() is ever polled
                     // A real restart loses the in-memory etag cache; without this the
                     // cache-hit skip masks the marker and the test passes with
                     // mark_pending gutted.
        store.versions.lock().await.clear();

        store
            .sync_down_if_stale("owner", "repo", &local, true)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(local.join("HEAD")).unwrap(),
            b"ACKED\n",
            "the pre-ack marker alone must prevent rollback"
        );
    }

    /// beardthelion P1 regression: a crash between a successful upload and
    /// the marker clear must NOT read as divergence. The marker records the
    /// upload's intended etag (content MD5) before the PUT; recovery finding
    /// storage at exactly that etag recognizes its own completed upload and
    /// heals instead of wedging a byte-identical repo behind "reconcile
    /// manually".
    #[tokio::test]
    async fn crash_after_upload_before_clear_heals_via_inflight_etag() {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let store = store_with_fs_archive(repos_dir.path().to_path_buf(), store_root.path());
        let archive = store.archive.as_ref().unwrap();

        // Simulate the crash state: storage holds the content this node was
        // uploading (etag E), while the marker still names the pre-upload
        // base B plus the in-flight etag E.
        let seed = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("HEAD"), b"uploaded\n").unwrap();
        archive.upload("owner", "repo", seed.path()).await.unwrap();
        let remote = archive.head_etag("owner", "repo").await.unwrap().unwrap();

        let local = repos_dir.path().join("owner").join("repo.git");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("HEAD"), b"uploaded\n").unwrap();
        mark_pending_upload(&local, Some("pre-upload-base")).unwrap();
        record_inflight_upload(&local, &remote).unwrap();

        // Write path must heal, not wedge: marker cleared, cache adopted.
        store
            .sync_down_if_stale("owner", "repo", &local, true)
            .await
            .expect("own completed upload must not read as divergence");
        assert!(
            !pending_upload_marker(&local).unwrap().exists(),
            "marker must be cleared once storage is recognized as our upload"
        );
        assert_eq!(std::fs::read(local.join("HEAD")).unwrap(), b"uploaded\n");
        // And subsequent syncs skip on the adopted etag.
        store
            .sync_down_if_stale("owner", "repo", &local, true)
            .await
            .unwrap();
    }

    /// The lazy-migration existence check must propagate failure instead of
    /// reading it as "absent" and uploading over a possibly-newer archive.
    #[sqlx::test]
    async fn upload_under_lock_propagates_failed_existence_check(pool: PgPool) {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let flaky = FlakyStore::new(store_root.path());
        let store = store_with_flaky(repos_dir.path().to_path_buf(), Arc::clone(&flaky), pool);

        let local = repos_dir.path().join("owner").join("repo.git");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("HEAD"), b"local\n").unwrap();

        flaky
            .fail_head
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            store
                .upload_under_lock("owner", "repo", &local, true)
                .await
                .is_err(),
            "a failed existence check must not read as absent"
        );
        assert!(
            store
                .archive
                .as_ref()
                .unwrap()
                .head_etag("owner", "repo")
                .await
                .is_err(),
            "sanity: head still failing"
        );
    }

    /// init() must remove its local dir when the initial upload fails, so a
    /// retry of the same name doesn't hit an existing destination.
    #[sqlx::test]
    async fn init_removes_local_dir_when_upload_fails(pool: PgPool) {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let flaky = FlakyStore::new(store_root.path());
        let store = store_with_flaky(repos_dir.path().to_path_buf(), Arc::clone(&flaky), pool);

        flaky
            .fail_put
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(store.init("did:key:z6MkOwner", "newrepo").await.is_err());
        let local = repos_dir
            .path()
            .join("did_key_z6MkOwner")
            .join("newrepo.git");
        assert!(
            !local.exists(),
            "failed init must not leave a local dir behind"
        );
    }

    /// Marker + head failure: the write path fails closed, the read path
    /// serves the local copy.
    #[tokio::test]
    async fn marker_with_failing_head_fails_write_closed_serves_read() {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let flaky = FlakyStore::new(store_root.path());
        // sync_down never touches the pool — lazy is fine here.
        let pool = sqlx::PgPool::connect_lazy("postgres://invalid").unwrap();
        let store = store_with_flaky(repos_dir.path().to_path_buf(), Arc::clone(&flaky), pool);

        let local = repos_dir.path().join("owner").join("repo.git");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("HEAD"), b"pending\n").unwrap();
        mark_pending_upload(&local, Some("base-etag")).unwrap();

        flaky
            .fail_head
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            store
                .sync_down_if_stale("owner", "repo", &local, true)
                .await
                .is_err(),
            "write path must fail closed when freshness is unknowable"
        );
        store
            .sync_down_if_stale("owner", "repo", &local, false)
            .await
            .expect("read path serves the local copy");
        assert_eq!(std::fs::read(local.join("HEAD")).unwrap(), b"pending\n");
    }

    /// Startup sweep: re-uploads marked repos whose storage didn't move, and
    /// leaves diverged ones marked.
    #[sqlx::test]
    async fn retry_pending_uploads_heals_and_respects_divergence(pool: PgPool) {
        let store_root = tempfile::tempdir().unwrap();
        let repos_dir = tempfile::tempdir().unwrap();
        let flaky = FlakyStore::new(store_root.path());
        let store = store_with_flaky(repos_dir.path().to_path_buf(), Arc::clone(&flaky), pool);
        let archive = store.archive.as_ref().unwrap();

        // Repo A: storage v1, local ahead with matching base — heals.
        let seed = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("HEAD"), b"v1\n").unwrap();
        archive.upload("owner", "heals", seed.path()).await.unwrap();
        let base_a = archive.head_etag("owner", "heals").await.unwrap().unwrap();
        let local_a = repos_dir.path().join("owner").join("heals.git");
        std::fs::create_dir_all(&local_a).unwrap();
        std::fs::write(local_a.join("HEAD"), b"local-ahead\n").unwrap();
        mark_pending_upload(&local_a, Some(&base_a)).unwrap();

        // Repo B: marker base predates current storage — stays marked.
        archive
            .upload("owner", "diverged", seed.path())
            .await
            .unwrap();
        let local_b = repos_dir.path().join("owner").join("diverged.git");
        std::fs::create_dir_all(&local_b).unwrap();
        std::fs::write(local_b.join("HEAD"), b"local-b\n").unwrap();
        mark_pending_upload(&local_b, Some("stale-base")).unwrap();

        let (reuploaded, still_pending) = store.retry_pending_uploads().await;
        assert_eq!((reuploaded, still_pending), (1, 1));
        assert!(!pending_upload_marker(&local_a).unwrap().exists());
        assert!(pending_upload_marker(&local_b).unwrap().exists());

        // A's local content is now durably in storage.
        let out = tempfile::tempdir().unwrap();
        let restored = out.path().join("restored.git");
        archive.download("owner", "heals", &restored).await.unwrap();
        assert_eq!(
            std::fs::read(restored.join("HEAD")).unwrap(),
            b"local-ahead\n"
        );
    }
}
