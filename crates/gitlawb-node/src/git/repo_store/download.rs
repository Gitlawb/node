//! Read-path download coordination (KTD-3) for [`RepoStore`].
//!
//! The read path's cache-miss handling lives here: the per-repo async mutex
//! that serializes concurrent readers of the same repo, the holder's fetch +
//! extract + under-lock publish, and the RAII temp-dir cleanup. `acquire` and
//! `acquire_fresh` stay in the parent module and call into `download_published`.
//! These methods reach the parent's private fields (`download_locks`) and
//! private methods (`try_lock_repo`) directly, because a child module can see
//! its parent's private items.

use super::*;

/// Outcome of a coordinated read-path download (KTD-3).
pub(super) enum DownloadOutcome {
    /// The local dir is present: this reader downloaded and published it under
    /// the advisory lock, or a concurrent reader did and this one served it.
    Published,
    /// The download was discarded without publishing: the advisory lock was
    /// contended (a live writer or purge holds it), the lock pool errored, or
    /// the archive vanished under the lock (purged mid-download). The caller
    /// degrades to its missing-path or serve-local-copy outcome.
    Skipped,
}

/// RAII cleanup for a read-path download temp dir (finding 1). Its `Drop`
/// removes the dir (best effort), so a handler future cancelled mid-download
/// (axum drops it on client disconnect, the same hazard `RepoWriteGuard` /
/// `RepoLockGuard` Drop impls exist for) cannot leak a fully-populated repo
/// dir. `disarm` forgets the dir once the publish rename has consumed it.
struct TempDownloadDir {
    path: PathBuf,
    armed: bool,
}

impl TempDownloadDir {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Disarm: the temp has been consumed (renamed into place), so `Drop` must
    /// not try to remove it.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TempDownloadDir {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// RAII removal of a download-coordination map entry (finding 4). Its `Drop`
/// removes the entry from `download_locks` whenever the map still holds THIS
/// Arc (ptr_eq-guarded so a newer entry inserted after an earlier removal is
/// never clobbered). Removal is guaranteed on every path (a normal return or
/// `?` drops it in the holder; once a download is in flight it travels with
/// the spawned task and drops at settle, covering holder timeout and a
/// handler future cancelled mid cold-read, which axum triggers on client
/// disconnect), which is what keeps the map from growing per arbitrary
/// requested name: the pre-fix explicit removals ran only at the labelled
/// return points, which a cancelled future skipped, leaking the entry. The
/// outer map is a std::sync::Mutex so
/// this Drop can prune it synchronously (Drop cannot be async); it is only ever
/// held briefly for a get/insert/remove, never across an await.
struct DownloadEntryGuard {
    locks: Arc<std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    key: String,
    entry: Arc<Mutex<()>>,
}

impl Drop for DownloadEntryGuard {
    fn drop(&mut self) {
        // A poisoned map is still safe to prune — recover the guard and remove.
        let mut map = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        if map
            .get(&self.key)
            .is_some_and(|cur| Arc::ptr_eq(cur, &self.entry))
        {
            map.remove(&self.key);
        }
    }
}

impl RepoStore {
    /// Coordinated read-path download (KTD-3). Serializes concurrent readers
    /// of the same repo on a per-repo async mutex: the first one in becomes
    /// the holder and runs [`download_and_publish`](Self::download_and_publish);
    /// a contended reader awaits the holder, re-checks the local dir on wake,
    /// and serves what the holder published instead of re-downloading. Only
    /// callers that already confirmed the archive exists reach this, and the
    /// map entry is removed on completion, so the map cannot grow per
    /// arbitrary requested name.
    pub(super) async fn download_published(
        &self,
        owner_did: &str,
        repo_name: &str,
        owner_slug: &str,
        local_path: &Path,
        store: &Arc<dyn ObjectStore>,
        local_existed_at_entry: bool,
    ) -> Result<DownloadOutcome> {
        let map_key = format!("{owner_slug}/{repo_name}");
        let entry = {
            let mut map = self.download_locks.lock().unwrap();
            Arc::clone(
                map.entry(map_key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let held = match Arc::clone(&entry).try_lock_owned() {
            Ok(g) => g,
            Err(_) => {
                // Bounded coalescing wait: once a holder's download is in
                // flight, the spawned task owns this lock (and the map entry)
                // until it settles, whatever happens to the holder (timeout or
                // cancellation), so an unbounded lock().await here would park
                // this reader for as long as a stall lasts. On elapse, report
                // the same timeout error the holder would. Do NOT touch the
                // map entry on this path: pruning it while the download is in
                // flight would let the next arrival start a duplicate download.
                let waited = tokio::time::timeout(
                    self.release_upload_timeout,
                    Arc::clone(&entry).lock_owned(),
                )
                .await;
                let g = match waited {
                    Ok(g) => g,
                    Err(_) => {
                        if local_path.exists() {
                            // A concurrent reader published while we waited.
                            return Ok(DownloadOutcome::Published);
                        }
                        return Err(anyhow::anyhow!("read download timed out"));
                    }
                };
                if local_path.exists() {
                    // A concurrent reader published while we waited — serve it.
                    // The holder's own guard prunes the map entry on its exit.
                    return Ok(DownloadOutcome::Published);
                }
                // The holder degraded without publishing; this reader takes over.
                // The prior holder removed the map entry on its way out, so
                // re-register THIS entry before downloading, so readers arriving
                // now coalesce onto it instead of starting a duplicate download
                // (finding 3). Narrows the duplicate-download window; publishes
                // stay serialized by the advisory lock regardless.
                {
                    let mut map = self.download_locks.lock().unwrap();
                    map.entry(map_key.clone())
                        .or_insert_with(|| Arc::clone(&entry));
                }
                g
            }
        };
        // RAII: remove the map entry when this holder's work is done (finding
        // 4). Created only once THIS reader holds the per-repo lock, so a
        // parked or timed-out waiter never prunes the entry out from under a
        // live holder; its Drop is ptr_eq-guarded, so it never clobbers a
        // newer entry. Ownership moves into download_and_publish and from
        // there into the spawned download task itself, so on EVERY settle path
        // (success, download error, holder timeout, holder cancellation) the
        // entry stays registered and the lock stays held until the in-flight
        // download settles: waiters queue on the ONE download instead of each
        // timeout or cancel wave starting a fresh full download of the same
        // object.
        let entry_guard = DownloadEntryGuard {
            locks: Arc::clone(&self.download_locks),
            key: map_key,
            entry: Arc::clone(&entry),
        };
        self.download_and_publish(
            owner_did,
            repo_name,
            owner_slug,
            local_path,
            store,
            local_existed_at_entry,
            entry_guard,
            held,
        )
        .await
    }

    /// The holder's half of the coordinated download: fetch and extract the
    /// archive into a temp sibling with NO advisory lock held (the network
    /// phase must never pin a lock-pool connection — a cold-read burst across
    /// distinct repos must not drain the writer-sized pool), then take the
    /// per-repo advisory lock only around the publish: re-check the archive
    /// still exists under the lock (a purge deletes it under this same lock,
    /// so a post-purge downloader discards rather than resurrecting), swap
    /// the temp copy into place, release. Advisory contention or a lock-pool
    /// error discards the temp copy and degrades — no blocking lock or pool
    /// wait exists anywhere on the read path.
    ///
    /// `local_existed_at_entry` selects the stale-swap guard (finding 2): a cold
    /// `acquire` passes `false`, an `acquire_fresh` refresh passes `true`. Under
    /// the lock, before the swap, we detect a writer that published a fresher
    /// copy during our unlocked download window and serve theirs instead of
    /// clobbering it with our now-stale temp.
    ///
    /// `entry_guard` and `held` are this holder's per-repo coordination (the
    /// download_locks map entry and the locked per-repo mutex). Both move into
    /// the spawned download task, which returns them through its JoinHandle on
    /// success; on any other settle path (download error, task panic, holder
    /// timeout, holder cancellation) they drop when the task settles, so
    /// waiters keep queueing on the SAME in-flight download until it settles
    /// rather than each starting a duplicate one.
    #[allow(clippy::too_many_arguments)]
    async fn download_and_publish(
        &self,
        owner_did: &str,
        repo_name: &str,
        owner_slug: &str,
        local_path: &Path,
        store: &Arc<dyn ObjectStore>,
        local_existed_at_entry: bool,
        entry_guard: DownloadEntryGuard,
        held: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<DownloadOutcome> {
        let parent = local_path.parent().context("repo path has no parent")?;
        std::fs::create_dir_all(parent).context("creating repo parent dir")?;
        let file_name = local_path
            .file_name()
            .context("repo path has no file name")?
            .to_string_lossy();

        // Best-effort sweep of leftover temp siblings from a prior download whose
        // cleanup never ran (a process crash or kill mid-download, where no Drop
        // and no owning task survive to remove the temp). Serialized per
        // repo by the download mutex, so no concurrent same-repo download owns a
        // live temp here; scoped to THIS repo's prefix, so other repos are
        // untouched.
        let tmp_prefix = format!(".{file_name}.tmp-download.");
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with(&tmp_prefix) {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }

        // Stale-swap signal (finding 2): capture the local dir's mtime BEFORE the
        // unlocked download. Under the lock, a changed mtime (acquire_fresh,
        // refreshing over an existing copy) or the dir's mere appearance (cold
        // acquire) means a writer published a fresher copy during our download
        // window, so we serve theirs rather than swap our stale temp over it.
        let entry_mtime = std::fs::metadata(local_path)
            .and_then(|m| m.modified())
            .ok();

        // Unique per-download temp target (same parent as local_path so the
        // publish rename stays on one filesystem); mirrors the extract temp
        // naming in tigris.rs. Wrapped in an RAII guard so a handler future
        // cancelled mid-download (axum drops it on client disconnect) cannot
        // leak the populated temp dir (the same hazard the guard Drop impls
        // below exist for, finding 1).
        let temp = TempDownloadDir::new(parent.join(format!(
            ".{file_name}.tmp-download.{}",
            uuid::Uuid::new_v4()
        )));

        // Ownership of the download AND the temp-dir guard moves into a spawned
        // task, so timeout and handler cancellation share ONE cleanup path
        // (finding F3 and its cancellation twin). `store.download` runs its tar
        // extraction in `spawn_blocking`, and neither a tokio timeout nor a
        // dropped handler future cancels a spawn_blocking task: pre-fix,
        // dropping the download future (a timed-out await, or axum dropping the
        // whole handler on client disconnect) detached the extraction, whose
        // later rename resurrected `temp.path()` AFTER the guard's Drop had
        // removed it, leaving an orphan only a later same-repo download sweeps.
        // The spawned task is never dropped mid-flight, so the download future
        // always runs to settle. On success it returns the still-armed guard
        // through the JoinHandle: the caller consumes it and publishes below.
        // If the caller timed out or was cancelled, the JoinHandle is gone, so
        // the runtime drops the returned guard when the task settles and its
        // Drop removes the temp dir; cleanup is tied to the extraction's
        // completion, never racing it (this subsumes the previous detached
        // janitor). A download error drops the guard inside the task with the
        // same at-settle timing.
        let store_dl = Arc::clone(store);
        let (dl_owner, dl_repo, dl_target) = (
            owner_slug.to_string(),
            repo_name.to_string(),
            temp.path().to_path_buf(),
        );
        // The per-repo coordination (`held`, `entry_guard`) moves into the task
        // alongside the temp guard: whatever happens to THIS caller (timeout
        // below, or a handler future cancelled by axum on client disconnect),
        // the lock stays held and the map entry stays registered until the
        // in-flight download settles, so waiters and new arrivals queue on the
        // ONE download instead of starting duplicates. On success the tuple
        // returns through the JoinHandle: the caller publishes under `held` as
        // before. If the caller timed out or was cancelled, the runtime drops
        // the returned tuple when the task settles, in field order: `temp`
        // (dir removed), then `held` (lock released), then `entry_guard` (map
        // entry pruned), the same unlock-before-prune order as a normal
        // return.
        let dl_task = tokio::spawn(async move {
            // The guards travel as one `(held, entry_guard)` tuple so that
            // wherever it drops (here on error, in the runtime at settle after
            // a caller timeout or cancellation, or in the caller after a
            // normal publish), its field order gives unlock-before-prune.
            match store_dl.download(&dl_owner, &dl_repo, &dl_target).await {
                Ok(()) => Ok((temp, (held, entry_guard))),
                // The download settled, so cleanup is safe. Explicit drops pin
                // the order (async-block captures have no guaranteed one):
                // temp removed, lock released, map entry pruned last.
                Err(e) => {
                    drop(temp);
                    drop(held);
                    drop(entry_guard);
                    Err(e)
                }
            }
        });
        // Bound the wait, not the work: a stalled GET would park this reader
        // indefinitely. On timeout the caller gets the same error as before,
        // but the coordination does NOT unwind: it lives in the task (see
        // above) and is released only at settle. Waiters therefore stay queued
        // on the SAME in-flight download (each bounded by its own timeout in
        // download_published) instead of each timeout wave starting a fresh
        // full download of the same object; the task keeps running and cleans
        // up its temp when the download settles.
        // `_coordination` is `(held, entry_guard)`, kept alive to the end of
        // this function exactly as the separate guards were before: the
        // publish below still runs with the per-repo lock held, and the map
        // entry is pruned only on exit (unlock first, prune second, per the
        // tuple's field order).
        let (temp, _coordination) =
            match tokio::time::timeout(self.release_upload_timeout, dl_task).await {
                Ok(Ok(Ok(returned))) => returned,
                Ok(Ok(Err(e))) => return Err(e),
                // The task panicked; its unwind dropped the guards, removing
                // the dir, releasing the lock, and pruning the map entry.
                Ok(Err(join_err)) => {
                    return Err(anyhow::Error::from(join_err).context("read download task failed"))
                }
                Err(_) => {
                    warn!(repo = %repo_name, timeout_secs = self.release_upload_timeout.as_secs(),
                        "read download timed out — discarding");
                    // Dropping the JoinHandle detaches the task; the runtime
                    // frees temp dir, lock, and map entry at settle (see the
                    // spawn comment above).
                    return Err(anyhow::anyhow!("read download timed out"));
                }
            };

        let guard = match self.try_lock_repo(owner_did, repo_name).await {
            Ok(Some(g)) => g,
            Ok(None) => {
                debug!(repo = %repo_name,
                    "read download discarded — repo lock held by a live writer or purge");
                return Ok(DownloadOutcome::Skipped);
            }
            Err(e) => {
                warn!(repo = %repo_name, err = %e,
                    "read download discarded — could not acquire repo lock");
                return Ok(DownloadOutcome::Skipped);
            }
        };
        // Re-check under the lock: the archive gone here means a purge won the
        // key mid-download — discard, never publish (the read-side twin of the
        // upload paths' under-lock dir re-check). Bounded so a stalled HEAD
        // cannot pin the advisory lock + its lock-pool connection. Both a
        // timeout and an exists() error collapse to "not present" and take the
        // discard arm: fail closed rather than publish unconfirmed state.
        let archive_present = matches!(
            tokio::time::timeout(
                self.release_upload_timeout,
                store.exists(owner_slug, repo_name),
            )
            .await,
            Ok(Ok(true))
        );
        if !archive_present {
            warn!(repo = %repo_name,
                "read download discarded — archive gone under lock (purged?)");
            guard.release().await;
            return Ok(DownloadOutcome::Skipped);
        }

        // Stale-swap guard (finding 2): a writer that locked, published a fresher
        // copy, and released during our unlocked download window must not have
        // its work clobbered by our now-stale temp. The only concurrent mutator
        // of local_path is a writer or a purge (readers of the same repo
        // serialize on the download mutex), so the signals below unambiguously
        // mean "a writer published here."
        let writer_published = match (local_existed_at_entry, entry_mtime) {
            // acquire_fresh over an existing copy: presence is always true, so it
            // cannot signal a writer; a CHANGED mtime can (the writer replaced
            // the dir via rename, minting a fresh mtime).
            (true, Some(entry_m)) => std::fs::metadata(local_path)
                .and_then(|m| m.modified())
                .map(|now| now != entry_m)
                .unwrap_or(false),
            // Cold acquire, or acquire_fresh whose dir was absent at entry: the
            // dir being present now means a writer published it during the window.
            _ => local_path.exists(),
        };
        if writer_published {
            warn!(repo = %repo_name,
                "read download discarded: a writer published a fresher copy during the download window");
            guard.release().await;
            // temp guard's Drop removes the stale temp; serve the fresher local copy.
            return Ok(DownloadOutcome::Published);
        }

        let swapped = (|| -> std::io::Result<()> {
            if local_path.exists() {
                std::fs::remove_dir_all(local_path)?;
            }
            std::fs::rename(temp.path(), local_path)
        })();
        guard.release().await;
        match swapped {
            Ok(()) => {
                temp.disarm(); // the rename consumed the temp; nothing to clean up
                Ok(DownloadOutcome::Published)
            }
            // temp guard's Drop removes the temp if the rename left it behind.
            Err(e) => Err(e).context("publishing downloaded repo into place"),
        }
    }
}
