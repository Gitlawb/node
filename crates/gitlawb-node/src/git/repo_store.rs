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
use tracing::{debug, warn};

use super::store;
use crate::storage::archive::RepoArchive;

/// Centralized repo storage: local disk cache + optional object-storage backend
/// (S3-compatible / filesystem / IPFS) behind the [`RepoArchive`] layer.
#[derive(Clone)]
pub struct RepoStore {
    repos_dir: PathBuf,
    archive: Option<RepoArchive>,
    /// Bounded pool dedicated to advisory-lock connections — the only DB pool
    /// RepoStore needs, as it touches Postgres solely for advisory locks. A push
    /// pins one connection for its whole lifetime (the lock is held across both
    /// receive-pack and the upload), so a separate budget keeps a burst of
    /// concurrent/slow pushes from draining the handler pool and starving every
    /// other DB handler.
    lock_pool: PgPool,
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
            lock_pool: pool,
            migrated: Arc::new(Mutex::new(HashSet::new())),
            versions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// `lock_pool` is a bounded pool that advisory-lock connections are pinned
    /// from, kept separate from the handler pool so push concurrency can't
    /// drain it.
    pub fn new(repos_dir: PathBuf, archive: Option<RepoArchive>, lock_pool: PgPool) -> Self {
        Self {
            repos_dir,
            archive,
            lock_pool,
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

        let marker = pending_upload_marker(local_path);
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
                // the storage etag that write was BASED on, so we can tell
                // "storage unchanged — local strictly ahead" apart from
                // "another node advanced storage — genuine divergence" rather
                // than treating local as authoritative forever.
                let base = std::fs::read_to_string(&marker).unwrap_or_default();
                let base = base.trim();
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
                    Some(r) if r == base => {
                        warn!(repo = %repo_name,
                            "local copy ahead of storage (pending upload) — skipping download");
                        return Ok(());
                    }
                    // Storage advanced past our base while this node held
                    // un-uploaded local changes: both sides have writes the
                    // other lacks. Overwriting either silently loses a push.
                    Some(_) => {
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
                let marker_pending = pending_upload_marker(&local_path).exists();
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
    /// The lock prevents concurrent writes to the same repo across machines.
    pub async fn acquire_write(&self, owner_did: &str, repo_name: &str) -> Result<RepoWriteGuard> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;
        let lock_key = advisory_lock_key(&owner_slug, repo_name);
        let label = format!("{owner_slug}/{repo_name}");
        let lock = LockedConn::acquire(&self.lock_pool, lock_key, &label).await?;

        // Ensure local matches the latest in storage before writing. The etag
        // cache skips the full download when our copy is already current (the
        // common single-machine case under sticky routing); a stale copy (another
        // machine pushed since) still triggers a download. The advisory lock above
        // serializes this so the post-write upload can't race a concurrent writer.
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
        })
    }

    /// Initialize a new bare repo on local disk and upload to storage.
    pub async fn init(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        if let Err(e) = store::init_bare(&local_path) {
            // A half-initialized dir would block a retry on "already exists".
            let _ = std::fs::remove_dir_all(&local_path);
            return Err(e).context("initializing bare repo");
        }
        // A marker left by a previous same-name repo (failed creation, deleted
        // repo) describes THAT repo's history, not this fresh one — once this
        // repo's archive exists, a stale empty-base marker would read as
        // divergence and wedge its writes.
        clear_pending_upload(&local_path);

        // Upload the new repo synchronously under the advisory lock: a background
        // upload could land the empty repo *after* a racing first push and clobber
        // it, and a silent failure would leave the repo absent from storage. Fail
        // closed instead — surface upload errors to the caller, and remove the
        // just-created local dir so a retry of the same name doesn't hit an
        // existing destination.
        if let Err(e) = self
            .upload_under_lock(&owner_slug, repo_name, &local_path, false)
            .await
        {
            if let Err(cleanup_err) = std::fs::remove_dir_all(&local_path) {
                warn!(repo = %repo_name, err = %cleanup_err,
                    "failed to remove local repo dir after init upload failure");
            }
            return Err(e).context("uploading new repo to storage");
        }

        Ok(local_path)
    }

    /// Upload a repo to storage after a write operation (merge, fork, etc.).
    /// Call this after any operation that modifies the git repo on disk. Returns
    /// `Err` if the durable upload fails so the caller can surface it rather than
    /// acking a write that never reached storage.
    ///
    /// The upload runs under the per-repo advisory lock: claim-first creation
    /// makes a fork addressable (and pushable) before this upload finishes, so
    /// an unlocked PUT could compress a pre-push snapshot and land it AFTER a
    /// concurrent locked push's upload — which that push's cleared marker no
    /// longer protects against.
    pub async fn release_after_write(&self, owner_did: &str, repo_name: &str) -> Result<()> {
        if self.archive.is_none() {
            return Ok(());
        }
        let (owner_slug, local_path) = self
            .local_path(owner_did, repo_name)
            .context("rejected unsafe path in release_after_write")?;
        let key = format!("{owner_slug}/{repo_name}");
        let base = self.versions.lock().await.get(&key).cloned();
        mark_pending_upload(&local_path, base.as_deref())
            .context("persisting pending-upload marker")?;
        // The marker's recorded base is authoritative, not the cache: if a
        // marker already existed (earlier failed upload), mark_pending_upload
        // preserved its ORIGINAL base while the versions cache was invalidated
        // by that failure — or emptied entirely by a restart. Comparing
        // against the cache value would misread that state as divergence.
        let base = std::fs::read_to_string(pending_upload_marker(&local_path))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| base.unwrap_or_default());
        match self
            .upload_locked_with_marker(&owner_slug, repo_name, &local_path, &base)
            .await
        {
            Ok(PendingUploadOutcome::Uploaded) => Ok(()),
            Ok(PendingUploadOutcome::Diverged) => {
                // Another writer advanced storage between our sync and this
                // upload. Refusing (rather than uploading) protects their
                // acked write; ours stays local behind the marker.
                self.versions.lock().await.remove(&key);
                anyhow::bail!(
                    "storage for {key} advanced during the write — upload aborted to \
                     avoid clobbering the concurrent writer; local copy left marked"
                )
            }
            Err(e) => {
                // Storage is now behind local. Drop the cached etag, and leave
                // the pending-upload marker in place so sync_down_if_stale
                // serves the local copy instead of rolling it back to the
                // stale archive.
                self.versions.lock().await.remove(&key);
                Err(e).context("uploading repo to storage after write")
            }
        }
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
        let Ok(owners) = std::fs::read_dir(&self.repos_dir) else {
            return (0, 0);
        };
        for owner in owners.flatten() {
            if !owner.path().is_dir() {
                continue;
            }
            let slug = owner.file_name().to_string_lossy().into_owned();
            let Ok(entries) = std::fs::read_dir(owner.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
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
                markers.push((
                    slug.clone(),
                    repo_name.to_string(),
                    owner.path().join(repo_dir),
                ));
            }
        }

        for (slug, repo_name, local_path) in markers {
            if !local_path.exists() {
                // Stale litter (repo dir gone) — storage is the best remaining
                // state; drop the marker.
                clear_pending_upload(&local_path);
                continue;
            }
            let base =
                std::fs::read_to_string(pending_upload_marker(&local_path)).unwrap_or_default();
            let base = base.trim().to_string();
            // The base-vs-remote decision and the upload both happen inside
            // `upload_locked_with_marker`, UNDER the advisory lock: an
            // unlocked pre-check here could pass, then block on a concurrent
            // push's lock for that push's whole duration, and the stale
            // decision would clobber the push's freshly-uploaded archive.
            match self
                .upload_locked_with_marker(&slug, &repo_name, &local_path, &base)
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
        crate::metrics::set_pending_upload_markers(still_pending as i64);
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
        base: &str,
    ) -> Result<PendingUploadOutcome> {
        let Some(ref archive) = self.archive else {
            anyhow::bail!("upload_locked_with_marker called without a storage backend");
        };
        let lock_key = advisory_lock_key(owner_slug, repo_name);
        let label = format!("{owner_slug}/{repo_name}");
        let lock = LockedConn::acquire(&self.lock_pool, lock_key, &label).await?;

        let outcome: Result<PendingUploadOutcome> = async {
            let remote = archive
                .head_etag(owner_slug, repo_name)
                .await
                .context("storage head under lock before pending upload")?;
            if remote.as_deref().unwrap_or("") != base {
                return Ok(PendingUploadOutcome::Diverged);
            }
            let etag = archive
                .upload(owner_slug, repo_name, local_path)
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
        let lock_key = advisory_lock_key(owner_slug, repo_name);
        let label = format!("{owner_slug}/{repo_name}");
        let lock = LockedConn::acquire(&self.lock_pool, lock_key, &label).await?;

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

/// How long to retry acquiring the per-repo advisory lock before giving up.
/// Matches the storage backends' total operation timeout (300s in `s3.rs` and
/// `ipfs.rs`): the writer holding the lock may legitimately be mid-upload of a
/// large archive, so a concurrent push must be willing to outwait the longest
/// possible upload rather than failing while the lock holder is still healthy.
pub(crate) const LOCK_ACQUIRE_TIMEOUT_SECS: u64 = 300;

/// A pool connection pinned for the lifetime of a session-scoped advisory lock.
///
/// Postgres advisory locks bind to one backend connection and only release on
/// that same connection; with a pool, acquiring and releasing on different
/// checked-out connections means the unlock silently no-ops while the lock
/// lingers on the original. So the lock's whole lifetime — acquire, use,
/// unlock — runs on this single pinned connection.
///
/// `unlock()` is the graceful path: it releases the lock and returns the
/// connection to the pool. If the holder is instead *dropped* while the lock is
/// held — e.g. a detached write-back task cancelled by runtime shutdown mid
/// upload — `Drop` detaches the connection from the pool and closes it, which
/// ends the Postgres session and frees the lock server-side. The one thing this
/// type never does is return a still-locked connection to the pool.
struct LockedConn {
    /// `None` once `unlock()` has run (or after a timed-out acquire hands the
    /// never-locked connection back to the pool).
    conn: Option<PoolConnection<Postgres>>,
    lock_key: i64,
    repo_label: String,
}

impl LockedConn {
    /// Acquire `lock_key` on a freshly pinned connection, polling
    /// `pg_try_advisory_lock` once per second up to [`LOCK_ACQUIRE_TIMEOUT_SECS`].
    /// Polling (rather than the blocking `pg_advisory_lock`) keeps a stale lock
    /// from a crashed session from wedging writers indefinitely.
    async fn acquire(pool: &PgPool, lock_key: i64, repo_label: &str) -> Result<Self> {
        let conn = pool
            .acquire()
            .await
            .context("acquiring db connection for advisory lock")?;
        // Wrap the connection before the first lock attempt so cancellation at
        // any point in the retry loop hits `Drop` and closes the connection —
        // a lock granted just as the caller was cancelled can't strand.
        let mut this = Self {
            conn: Some(conn),
            lock_key,
            repo_label: repo_label.to_string(),
        };
        for attempt in 0..LOCK_ACQUIRE_TIMEOUT_SECS {
            let conn = this.conn.as_mut().expect("connection present until unlock");
            let row: (bool,) = match sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut **conn)
                .await
            {
                Ok(row) => row,
                Err(e) => {
                    // The poll itself failed, so the lock's server-side state
                    // is unknown: if the query executed but the response was
                    // lost, this session HOLDS the lock, and repooling the
                    // connection would strand it. Close the connection
                    // deliberately (freeing any lock it may hold) instead of
                    // going through Drop's generic dropped-holder warning.
                    if let Some(conn) = this.conn.take() {
                        drop(conn.detach());
                    }
                    return Err(e).context("trying advisory lock");
                }
            };
            if row.0 {
                return Ok(this);
            }
            if attempt < LOCK_ACQUIRE_TIMEOUT_SECS - 1 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        // Timed out without ever holding the lock — return the connection to
        // the pool normally rather than letting `Drop` close it.
        drop(this.conn.take());
        anyhow::bail!(
            "could not acquire advisory lock for {} after {LOCK_ACQUIRE_TIMEOUT_SECS}s — \
             possible stale lock or a long-running upload",
            this.repo_label
        );
    }

    /// Release the lock on the pinned connection and return it to the pool.
    async fn unlock(mut self) {
        if let Some(mut conn) = self.conn.take() {
            if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.lock_key)
                .execute(&mut *conn)
                .await
            {
                // The unlock failed, so the session may still hold the lock —
                // close the connection (like `Drop`) instead of repooling it,
                // or the lock would wedge this repo's writes until the pool
                // happened to recycle that connection.
                warn!(repo = %self.repo_label, err = %e,
                    "failed to release advisory lock — closing its connection");
                drop(conn.detach());
            }
        }
    }
}

impl Drop for LockedConn {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // Dropped while the lock is (or may be) held: closing the socket
            // ends the Postgres session, which releases every advisory lock it
            // held. Detach first so the closed connection is never handed back
            // to the pool; the pool replaces it on demand.
            warn!(repo = %self.repo_label,
                "advisory-lock holder dropped without unlock — closing its connection to free the lock");
            drop(conn.detach());
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
                    .upload(&self.owner_slug, &self.repo_name, &self.local_path)
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
fn pending_upload_marker(local_path: &Path) -> PathBuf {
    let name = local_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    local_path.with_file_name(format!(".{name}.pending-upload"))
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
    let marker = pending_upload_marker(local_path);
    match marker.try_exists() {
        Ok(true) => return Ok(()), // keep the original base
        Ok(false) => {}
        Err(e) => return Err(e).context("probing pending-upload marker"),
    }
    let tmp = marker.with_file_name(format!(".pending-upload.tmp-{}", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, base_etag.unwrap_or_default()).context("writing pending-upload marker")?;
    std::fs::rename(&tmp, &marker)
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
        .context("publishing pending-upload marker")
}

pub(crate) fn clear_pending_upload(local_path: &Path) {
    let _ = std::fs::remove_file(pending_upload_marker(local_path));
}

/// Remove the marker after a *successful* upload, first atomically rewriting
/// its base to the just-uploaded etag. A crash between the rewrite and the
/// unlink then reads as "local ahead, base matches" — which self-heals on the
/// next write or startup retry — instead of "base predates storage", which
/// would wedge the repo behind a spurious permanent divergence even though
/// local and storage are identical.
fn clear_pending_upload_after_success(local_path: &Path, new_etag: Option<&str>) {
    let marker = pending_upload_marker(local_path);
    if let Some(etag) = new_etag {
        if marker.exists() {
            let tmp =
                marker.with_file_name(format!(".pending-upload.tmp-{}", uuid::Uuid::new_v4()));
            if std::fs::write(&tmp, etag).is_ok() {
                let _ = std::fs::rename(&tmp, &marker);
            } else {
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
    let _ = std::fs::remove_file(&marker);
}

/// Outcome of a marker-protected upload attempt.
enum PendingUploadOutcome {
    /// Uploaded, versions cache updated, marker cleared — all under the lock.
    Uploaded,
    /// Storage no longer matches the marker's base: another writer advanced it.
    /// Nothing was uploaded and the marker was left in place.
    Diverged,
}

/// Compute a stable i64 hash for a Postgres advisory lock key.
///
/// SHA-256 prefix, NOT `DefaultHasher`: the default hasher's algorithm is
/// explicitly unspecified across Rust releases, and this lock is the sole
/// cross-machine write serializer — two machines built with different
/// toolchains hashing the same repo to different keys would silently stop
/// excluding each other mid rolling deploy. (Changing the scheme is itself a
/// one-deploy exclusion gap between old and new binaries; accepted once,
/// here, to get onto a stable function.)
fn advisory_lock_key(owner_slug: &str, repo_name: &str) -> i64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{owner_slug}/{repo_name}").as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("digest has at least 8 bytes"))
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

        // The next successful upload re-syncs storage and clears the marker.
        store.release_after_write("owner", "repo").await.unwrap();
        assert!(
            !pending_upload_marker(&local).exists(),
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
        assert!(!pending_upload_marker(&local).exists());
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
        let base_after_first = std::fs::read_to_string(pending_upload_marker(&local)).unwrap();
        assert!(!base_after_first.trim().is_empty(), "base must be recorded");

        // Write 2: acquire must succeed (storage unchanged == local-ahead),
        // and the second failed release must NOT re-mark with an empty base.
        let guard = store.acquire_write("owner", "repo").await.unwrap();
        std::fs::write(local.join("HEAD"), b"write-2\n").unwrap();
        assert!(guard.release(true).await.is_err());
        assert_eq!(
            std::fs::read_to_string(pending_upload_marker(&local)).unwrap(),
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
        assert!(!pending_upload_marker(&local).exists());
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
        assert!(!pending_upload_marker(&local_a).exists());
        assert!(pending_upload_marker(&local_b).exists());

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
