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
            let mut map = self.download_locks.lock().await;
            Arc::clone(
                map.entry(map_key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let held = match entry.try_lock() {
            Ok(g) => g,
            Err(_) => {
                let g = entry.lock().await;
                if local_path.exists() {
                    // A concurrent reader published while we waited — serve it.
                    drop(g);
                    self.remove_download_entry(&map_key, &entry).await;
                    return Ok(DownloadOutcome::Published);
                }
                // The holder degraded without publishing; this reader takes over.
                // The prior holder removed the map entry on its way out, so
                // re-register THIS entry before downloading, so readers arriving
                // now coalesce onto it instead of starting a duplicate download
                // (finding 3). Narrows the duplicate-download window; publishes
                // stay serialized by the advisory lock regardless.
                {
                    let mut map = self.download_locks.lock().await;
                    map.entry(map_key.clone())
                        .or_insert_with(|| Arc::clone(&entry));
                }
                g
            }
        };
        let outcome = self
            .download_and_publish(
                owner_did,
                repo_name,
                owner_slug,
                local_path,
                store,
                local_existed_at_entry,
            )
            .await;
        self.remove_download_entry(&map_key, &entry).await;
        drop(held);
        outcome
    }

    /// Remove a completed download-coordination entry, but only when the map
    /// still holds THIS entry — a newer entry inserted after an earlier
    /// removal must not be clobbered.
    async fn remove_download_entry(&self, key: &str, entry: &Arc<Mutex<()>>) {
        let mut map = self.download_locks.lock().await;
        if map.get(key).is_some_and(|cur| Arc::ptr_eq(cur, entry)) {
            map.remove(key);
        }
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
    async fn download_and_publish(
        &self,
        owner_did: &str,
        repo_name: &str,
        owner_slug: &str,
        local_path: &Path,
        store: &Arc<dyn ObjectStore>,
        local_existed_at_entry: bool,
    ) -> Result<DownloadOutcome> {
        let parent = local_path.parent().context("repo path has no parent")?;
        std::fs::create_dir_all(parent).context("creating repo parent dir")?;
        let file_name = local_path
            .file_name()
            .context("repo path has no file name")?
            .to_string_lossy();

        // Best-effort sweep of leftover temp siblings from a prior download whose
        // RAII guard dropped, or whose extract spawn_blocking completed
        // uninterruptibly AFTER that guard's Drop ran (finding 1). Serialized per
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

        // Bound the network download: a stalled GET would park this reader (and,
        // via the per-repo download mutex, every coalesced reader) indefinitely.
        // A timeout takes the SAME cleanup arm as a download error (return Err,
        // the temp guard's Drop removes the dir), so `download_published` frees
        // the map entry and wakes waiters rather than leaving them parked forever.
        match tokio::time::timeout(
            self.release_upload_timeout,
            store.download(owner_slug, repo_name, temp.path()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                warn!(repo = %repo_name, timeout_secs = self.release_upload_timeout.as_secs(),
                    "read download timed out — discarding");
                return Err(anyhow::anyhow!("read download timed out"));
            }
        }

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
