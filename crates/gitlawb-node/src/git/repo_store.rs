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
use sqlx::{PgPool, Postgres};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::store;
use super::tigris::{TigrisClient, UploadError, UploadPrecondition};

/// Centralized repo storage: local disk cache + optional Tigris backend.
#[derive(Clone)]
pub struct RepoStore {
    repos_dir: PathBuf,
    tigris: Option<TigrisClient>,
    /// Dedicated Postgres pool that advisory-lock connections come from, kept
    /// separate from the pool serving ordinary request handlers. Each write guard
    /// pins one connection here for its whole lifetime, so a push burst consumes
    /// this pool rather than starving application queries. Sized by
    /// `GITLAWB_DB_LOCK_POOL_MAX_CONNECTIONS`.
    lock_pool: PgPool,
    /// Bound on any object-storage transfer that runs while the lock is HELD.
    lock_held_transfer_timeout: Duration,
    /// Wall-clock cap on WAITING for the lock. A field rather than a bare const so
    /// the busy path can be driven in a test without a 90s wait.
    lock_acquire_deadline: Duration,
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
    pub fn for_testing(repos_dir: PathBuf, lock_pool: PgPool) -> Self {
        Self {
            repos_dir,
            tigris: None,
            lock_pool,
            lock_held_transfer_timeout: Duration::from_secs(300),
            lock_acquire_deadline: LOCK_ACQUIRE_DEADLINE,
            migrated: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            pre_unlock_gate: None,
        }
    }

    /// Same as [`RepoStore::for_testing`] but with Tigris enabled, so the paths
    /// that only run when a backend is configured are reachable in a test.
    #[cfg(test)]
    pub fn for_testing_with_tigris(
        repos_dir: PathBuf,
        lock_pool: PgPool,
        tigris: TigrisClient,
    ) -> Self {
        Self::new(repos_dir, Some(tigris), lock_pool, Duration::from_secs(300))
    }

    /// Shorten the lock-acquire deadline so the busy path is reachable in a test
    /// without waiting out the production default.
    #[cfg(test)]
    pub fn with_lock_acquire_deadline(mut self, deadline: Duration) -> Self {
        self.lock_acquire_deadline = deadline;
        self
    }

    pub fn new(
        repos_dir: PathBuf,
        tigris: Option<TigrisClient>,
        lock_pool: PgPool,
        lock_held_transfer_timeout: Duration,
    ) -> Self {
        Self {
            repos_dir,
            tigris,
            lock_pool,
            lock_held_transfer_timeout,
            lock_acquire_deadline: LOCK_ACQUIRE_DEADLINE,
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
                                // Create-only. This backfill was decided on a
                                // negative existence check that is already
                                // stale, so a refusal means someone else
                                // published this key in between and dropping
                                // our bytes is the correct outcome. An
                                // unconditional PUT here would overwrite their
                                // archive, which is the exact bug this fence
                                // exists to close.
                                match tigris
                                    .upload(&slug, &name, &path, UploadPrecondition::IfAbsent)
                                    .await
                                {
                                    Ok(()) => {
                                        info!(repo = %name, "lazy migration to tigris complete");
                                    }
                                    // Logged apart from the warn arm below so a
                                    // refusal, which is the fence working, does
                                    // not read as a storage failure. The key is
                                    // populated either way, so this still
                                    // counts as migrated.
                                    Err(UploadError::PreconditionLost { status }) => {
                                        info!(repo = %name, status, "lazy migration dropped: another writer already published this repo");
                                    }
                                    Err(e) => {
                                        warn!(repo = %name, err = %e, "lazy migration to tigris failed");
                                        return;
                                    }
                                }
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
    ///
    /// A failed existence check refuses the acquire rather than guessing the
    /// archive is absent, matching the under-lock path in `acquire_write()`.
    pub async fn acquire_fresh(&self, owner_did: &str, repo_name: &str) -> Result<PathBuf> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        if let Some(ref tigris) = self.tigris {
            // The HEAD and the download fail for epistemically DIFFERENT reasons,
            // so they are kept apart rather than collapsed into one `Result`. The
            // `unwrap_or(false)` this replaced read a HEAD error as "no archive"
            // and silently advertised a possibly-stale local copy to a client that
            // is about to push against it.
            match tigris.exists(&owner_slug, repo_name).await {
                Ok(true) => {
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
                        // No local copy, so the write cannot proceed and the archive's
                        // readability is unknowable. Same epistemic class as the HEAD arm
                        // and the under-lock refresh: a transient storage blip must be a
                        // retryable refusal, not a 500 that tells the client the failure
                        // is permanent. Wrap so the handler layer's `RepoUnavailable`
                        // downcast maps this to a retryable 503 with a fixed body; the
                        // detail (which repo, why) stays in this warn and the context.
                        warn!(repo = %repo_name, err = %e,
                            "acquire_fresh: tigris download failed and no local copy exists — refusing");
                        return Err(anyhow::Error::new(RepoUnavailable).context(format!(
                            "tigris download failed during acquire_fresh for {owner_slug}/{repo_name}: {e:#}"
                        )));
                    }
                    return Ok(local_path);
                }
                Ok(false) => {}
                Err(e) => {
                    // We do not know whether a newer archive exists, so we cannot
                    // tell whether the local copy is current. Advertising stale refs
                    // here sends the client into a push computed against the wrong
                    // base, so refuse for the same reason `acquire_write` refuses on
                    // this condition. A transient storage blip costs a retryable
                    // refusal, which is the cheaper failure.
                    warn!(repo = %repo_name, err = %e,
                        "acquire_fresh: tigris HEAD failed — refusing rather than \
                         guessing the archive is absent");
                    return Err(anyhow::Error::new(RepoUnavailable).context(format!(
                        "tigris HEAD failed during acquire_fresh for {owner_slug}/{repo_name}"
                    )));
                }
            }
        }

        // Tigris disabled or repo not in Tigris — fall back to local
        Ok(local_path)
    }

    /// Non-mutating snapshot of a repo's **latest** Tigris state, for reads that
    /// must see fresh data but must NOT write into the live repo path.
    ///
    /// Unlike `acquire_fresh`, which downloads and PUBLISHES into the live
    /// directory (removing the existing dir and renaming the extract into
    /// place), this unpacks into a throwaway temp dir and returns it. The live
    /// path is never touched, so an unlocked caller cannot delete or swap the
    /// directory under a concurrent guarded write.
    ///
    /// The returned snapshot owns its temp dir and removes it on drop; when
    /// there is no Tigris backend (or no archive), the snapshot borrows the live
    /// local path and owns nothing. A HEAD failure refuses rather than guessing,
    /// matching `acquire_fresh` and the under-lock refresh path: a transient
    /// storage blip must be a retryable refusal (`RepoUnavailable`), not a 500
    /// or a silently stale read.
    pub async fn read_snapshot(&self, owner_did: &str, repo_name: &str) -> Result<RepoSnapshot> {
        let (owner_slug, local_path) = self.local_path(owner_did, repo_name)?;

        if let Some(ref tigris) = self.tigris {
            match tigris.exists(&owner_slug, repo_name).await {
                Ok(true) => {
                    // Snapshot form: unpack into a temp dir, never the live path.
                    let snapshot = tigris
                        .download_to(&owner_slug, repo_name, &local_path, false)
                        .await
                        .map_err(|e| {
                            anyhow::Error::new(RepoUnavailable).context(format!(
                                "tigris snapshot download failed during read_snapshot for {owner_slug}/{repo_name}: {e:#}"
                            ))
                        })?;
                    return Ok(RepoSnapshot {
                        path: snapshot.clone(),
                        owned: true,
                    });
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(repo = %repo_name, err = %e,
                        "read_snapshot: tigris HEAD failed — refusing rather than guessing the archive is absent");
                    return Err(anyhow::Error::new(RepoUnavailable).context(format!(
                        "tigris HEAD failed during read_snapshot for {owner_slug}/{repo_name}"
                    )));
                }
            }
        }

        // Tigris disabled or repo not in Tigris — fall back to local.
        Ok(RepoSnapshot {
            path: local_path,
            owned: false,
        })
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
        let lock_key = advisory_lock_key(&owner_slug, repo_name);

        // Take the lock on a connection this guard will own for its whole
        // lifetime, so the release runs on the same session. `pg_try_advisory_lock`
        // with retry rather than a blocking acquire, so a stale lock from a crashed
        // connection cannot wedge us indefinitely.
        //
        // Each attempt checks a connection out and, on failure, returns it BEFORE
        // sleeping: a writer spinning on a contended repo must not pin a lock-pool
        // slot through its backoff, or a handful of spinners would starve the pool
        // for everyone else.
        //
        // Pool exhaustion is a DIFFERENT condition from "someone else holds the
        // lock" and is not retried here. Retrying it would burn all 60 attempts
        // against a pool that is full for reasons unrelated to this repo, and would
        // report a capacity problem as lock contention. It surfaces immediately with
        // its own message instead.
        // Cap the WALL CLOCK of the WAIT, not just the attempt count. 60 attempts
        // each pay a pool acquire (up to db_acquire_timeout_secs) plus a 1s sleep,
        // so an attempt-only bound reaches ~360s. This bounds the wait only; the
        // under-lock refresh below carries its own separate bound, so do not read
        // this as a total for `acquire_write` (see LOCK_ACQUIRE_DEADLINE).
        let deadline_budget = self.lock_acquire_deadline;
        let deadline = std::time::Instant::now() + deadline_budget;
        let mut lock_conn = None;
        for attempt in 0..60 {
            // The advertised cap is WALL CLOCK, so the remaining budget must bound
            // every await in the loop, not just the sleep between attempts. A pool
            // checkout or a slow advisory query that starts just before the deadline
            // and lands after it would otherwise hold the write task past the budget
            // it was promised, which is exactly what the deadline exists to prevent.
            let left = match deadline.checked_duration_since(std::time::Instant::now()) {
                Some(left) if !left.is_zero() => left,
                _ => break,
            };
            // Bound the pool checkout by the remaining budget. A checkout that
            // would outlive the deadline is not worth starting: it either waits out
            // the full DB acquire timeout and fails anyway, or lands a connection
            // with no budget left to use it.
            let conn = match tokio::time::timeout(left, self.lock_pool.acquire()).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    // Saturation is surfaced HERE, in the request path, and
                    // deliberately not through /ready. Failing readiness on a full
                    // pool would pull this node out of routing, taking its reads
                    // with it and pushing its write load onto peers carrying the
                    // same load — the documented downward spiral. So the signals
                    // are: a retryable 503 to the caller (via the sqlx downcast on
                    // this error) and this log line for the operator.
                    //
                    // Logged at warn with the pool's own counters so an incident can
                    // tell "the pool is full" from "the database is gone" without
                    // reproducing it. Once per failed acquire, and a failed acquire
                    // already costs a multi-second timeout, so this cannot itself
                    // become a log flood.
                    warn!(
                        repo = %repo_name,
                        owner = %owner_slug,
                        pool_size = self.lock_pool.size(),
                        pool_idle = self.lock_pool.num_idle(),
                        err = %e,
                        "advisory-lock pool acquire failed — writes are being shed; \
                         raise GITLAWB_DB_LOCK_POOL_MAX_CONNECTIONS or investigate long-held write locks"
                    );
                    return Err(e).context("advisory-lock pool exhausted or unreachable");
                }
                Err(_) => {
                    // The pool checkout itself outlived the remaining budget. Same
                    // refusal as running out of attempts: the wall-clock cap is what
                    // is advertised, so a checkout that blows past it is contention
                    // the caller was promised would not happen.
                    warn!(
                        repo = %repo_name,
                        owner = %owner_slug,
                        waited_secs = deadline_budget.as_secs(),
                        "advisory-lock pool checkout exceeded the acquire deadline — shedding the write as busy"
                    );
                    return Err(anyhow::Error::new(RepoBusy).context(format!(
                        "advisory-lock pool checkout exceeded the {}s deadline for {owner_slug}/{repo_name}",
                        deadline_budget.as_secs()
                    )));
                }
            };
            // Bound the advisory query by the remaining budget too: a query that
            // starts with budget left but answers after the deadline must not be
            // accepted, or the cap is only as good as the fast path.
            let left = match deadline.checked_duration_since(std::time::Instant::now()) {
                Some(left) if !left.is_zero() => left,
                _ => break,
            };
            let mut probe = LockProbe::new(conn);
            let acquired = match tokio::time::timeout(left, probe.try_lock(lock_key)).await {
                Ok(Ok(acquired)) => acquired,
                Ok(Err(e)) => return Err(e).context("trying advisory lock"),
                Err(_) => {
                    // The query outlived the remaining budget. The probe's Drop
                    // closes its session, which cannot hold the lock it never
                    // confirmed taking, so this is a plain shed.
                    warn!(
                        repo = %repo_name,
                        owner = %owner_slug,
                        waited_secs = deadline_budget.as_secs(),
                        "advisory-lock query exceeded the acquire deadline — shedding the write as busy"
                    );
                    return Err(anyhow::Error::new(RepoBusy).context(format!(
                        "advisory-lock query exceeded the {}s deadline for {owner_slug}/{repo_name}",
                        deadline_budget.as_secs()
                    )));
                }
            };
            if acquired {
                lock_conn = probe.take_conn();
                break;
            }
            // Not acquired, and nothing is locked, so hand the connection back
            // before the backoff rather than holding a slot while idle.
            drop(probe);
            // Clamp the backoff to what is left of the budget: sleeping a full
            // second past the deadline would turn a short deadline into a longer
            // wait than the caller was promised.
            if attempt < 59 {
                tokio::time::sleep(left.min(std::time::Duration::from_secs(1))).await;
            }
        }
        let Some(lock_conn) = lock_conn else {
            // Contention is transient, so this must NOT land as a 500. The detail
            // (which repo, which key, how long) goes to the log; the client gets a
            // retryable 503 with a fixed body via the `RepoBusy` downcast.
            warn!(
                repo = %repo_name,
                owner = %owner_slug,
                lock_key,
                waited_secs = deadline_budget.as_secs(),
                "advisory lock not acquired within the deadline — shedding the write as busy"
            );
            return Err(anyhow::Error::new(RepoBusy).context(format!(
                "could not acquire advisory lock within {}s for {owner_slug}/{repo_name}",
                deadline_budget.as_secs()
            )));
        };
        // From here the lock is HELD. Any early return must not simply drop the
        // connection back into the pool, so it is handed to the guard immediately
        // below and every exit after this point goes through the guard.
        let mut guard = RepoWriteGuard {
            owner_slug: owner_slug.clone(),
            repo_name: repo_name.to_string(),
            local_path: local_path.clone(),
            lock_key,
            conn: Some(lock_conn),
            tigris: self.tigris.clone(),
            lock_held_transfer_timeout: self.lock_held_transfer_timeout,
            // Overwritten by the refresh below with the generation actually
            // observed under the lock. Only reachable unset when no backend is
            // configured, in which case `release` publishes nothing at all.
            publish_fence: UploadPrecondition::Unconditional,
        };

        // Always download the latest from Tigris before writing. Local disk may be
        // stale if another machine pushed since our last access. The guard already
        // owns the lock + its connection, so a cancellation here drops through Drop.
        if let Some(ref tigris) = self.tigris {
            // ONE budget for the whole refresh, covering the HEAD and the download
            // together. Both run with the lock held and a lock-pool slot pinned, so
            // bounding only the download would leave a mute endpoint able to hold
            // both indefinitely on the HEAD, and bounding them separately would make
            // worst-case occupancy two budgets instead of one.
            let refreshed = bounded_transfer(
                "acquire-refresh",
                repo_name,
                self.lock_held_transfer_timeout,
                async {
                    // The HEAD and the download fail for epistemically DIFFERENT
                    // reasons, so they are kept apart rather than collapsed into one
                    // `Result`. A failed HEAD leaves us not knowing whether an archive
                    // exists at all, which is the same state a timeout leaves us in;
                    // a failed download after a successful HEAD tells us an archive is
                    // there and unreadable. Only the second licenses the local
                    // fallback. Collapsing them (the `unwrap_or(false)` this replaced
                    // read a HEAD error as "no archive") skipped the refresh silently
                    // and then re-uploaded over a possibly-newer archive.
                    //
                    // `head_etag` rather than `exists`: the same request answers
                    // both questions, and the ETag it carries is the generation
                    // this write is based on. Carrying it to the release-side
                    // publish is what lets the store refuse a stale PUT, which
                    // is the only place that fence can hold: dropping an
                    // in-flight upload's future does not stop the request the
                    // server is already processing.
                    match tigris.head_etag(&owner_slug, repo_name).await {
                        Ok(Some(etag)) => {
                            debug!(repo = %repo_name, "write acquire: downloading latest from tigris");
                            let fence = UploadPrecondition::IfMatch(etag);
                            match tigris.download(&owner_slug, repo_name, &local_path).await {
                                Ok(()) => Ok(fence),
                                Err(err) => Err(RefreshFailure::Download { err, fence }),
                            }
                        }
                        Ok(None) => Ok(UploadPrecondition::IfAbsent),
                        Err(e) => Err(RefreshFailure::Unknown(e)),
                    }
                },
            )
            .await;

            match refreshed {
                Some(Ok(fence)) => guard.publish_fence = fence,
                Some(Err(RefreshFailure::Download { err, fence })) => {
                    // The archive is present but unreadable: a corrupt or partial
                    // upload, or a transient GET failure. We KNOW the fetch failed,
                    // so falling back to a valid local copy is sound and
                    // release(success) re-uploads a good archive. Only hard-fail
                    // when there is no local copy to fall back to.
                    if local_path.exists() {
                        warn!(repo = %repo_name, err = %err,
                            "write acquire: tigris refresh failed — falling back to local copy");
                        // Still fence on what the HEAD saw. The download failing
                        // says nothing about the generation stored, so publishing
                        // unconditionally here would reintroduce exactly the
                        // overwrite this carries the ETag to prevent.
                        guard.publish_fence = fence;
                    } else {
                        return Err(err).context("downloading repo from tigris for write");
                    }
                }
                Some(Err(RefreshFailure::Unknown(e))) => {
                    // The HEAD itself failed, so we do not know whether a newer
                    // archive exists. Refuse for the same reason the timeout arm
                    // below refuses: proceeding would write against a possibly-stale
                    // tree and then re-upload over another node's newer archive. A
                    // transient object-storage blip costs a retryable refusal here,
                    // which is the cheaper failure than silent overwrite.
                    warn!(repo = %repo_name, err = %e,
                        "write acquire: tigris HEAD failed — refusing the write rather than \
                         guessing the archive is absent");
                    return Err(anyhow::Error::new(RepoUnavailable).context(format!(
                        "tigris HEAD failed before a write for {owner_slug}/{repo_name}"
                    )));
                }
                None => {
                    // TIMED OUT, which is NOT the same as failed, and must not reach
                    // the fallback above. Two reasons. We do not know whether we have
                    // the latest tree, so writing against the local copy and then
                    // re-uploading can silently overwrite another node's newer
                    // archive. Worse, the abandoned download's extraction runs in an
                    // uncancellable spawn_blocking that ends in remove_dir_all +
                    // rename over local_path, so proceeding would run git against a
                    // directory that a background task is about to delete.
                    //
                    // Refuse the acquire. Returning here drops the guard, whose Drop
                    // frees the lock and its pool slot.
                    //
                    // `error!`, not the sibling `warn!` above, and that is deliberate.
                    // The handler layer demotes every `RepoUnavailable` to warn because
                    // the common cause is an ordinary storage blip. A stall that ran out
                    // the whole bound is not that: it pinned a lock-pool slot for the
                    // full duration, and this raise-site `error!` is what keeps it
                    // paging. Do NOT "fix" it to match the arm above.
                    tracing::error!(
                        repo = %repo_name,
                        owner = %owner_slug,
                        bound_secs = self.lock_held_transfer_timeout.as_secs(),
                        "under-lock tigris refresh exceeded the transfer bound, refusing the write"
                    );
                    return Err(anyhow::Error::new(RepoUnavailable).context(format!(
                        "tigris refresh exceeded the {}s under-lock bound for {owner_slug}/{repo_name}",
                        self.lock_held_transfer_timeout.as_secs()
                    )));
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
                // Create-only, and load-bearing: this uploads a freshly
                // initialized EMPTY repo, so a user who pushes immediately
                // after creating one would have their archive replaced by this
                // background PUT if it were unconditional. A refusal means
                // someone else already published this key and dropping our
                // bytes is the correct outcome.
                match tigris
                    .upload(&owner_slug, &repo_name, &path, UploadPrecondition::IfAbsent)
                    .await
                {
                    Ok(()) => {}
                    // Distinct from the warn arm: the fence refusing is the
                    // design working, not a storage failure.
                    Err(UploadError::PreconditionLost { status }) => {
                        info!(repo = %repo_name, status, "dropped the empty-repo upload: another writer already published this repo");
                    }
                    Err(e) => {
                        warn!(repo = %repo_name, err = %e, "failed to upload new repo to tigris");
                    }
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
            // Create-only. The sole caller is fork creation, which rejects a
            // name conflict in the database before it clones anything, so the
            // key is expected absent here (and archive keys are never deleted:
            // `delete` has no callers). A refusal therefore means someone else
            // already published this key, and dropping our bytes is correct.
            match tigris
                .upload(
                    &owner_slug,
                    repo_name,
                    &local_path,
                    UploadPrecondition::IfAbsent,
                )
                .await
            {
                Ok(()) => {}
                // Kept apart from the warn arm so the fence working does not
                // read as a storage failure.
                Err(UploadError::PreconditionLost { status }) => {
                    info!(repo = %repo_name, status, "dropped the post-write upload: another writer already published this repo");
                }
                Err(e) => {
                    warn!(repo = %repo_name, err = %e, "failed to upload repo to tigris after write");
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

/// Owns a lock-pool connection across an in-flight `pg_try_advisory_lock`.
///
/// A cancelled `.await` does not cancel an already-sent SQL statement, so a
/// try-lock whose future is dropped still takes the lock server-side while the
/// caller abandons the result. Protection therefore has to exist *before* the
/// statement goes out, which is what this type is: its `Drop` closes any
/// connection still held, ending the session so Postgres frees the lock.
///
/// `close_on_drop()` is a one-way setter, so the arming lives here in `Drop`
/// rather than being set up front and cleared on success; "disarming" is
/// `Option::take`, which is what `take_conn` does once an acquire is observed.
/// This is the only place that issues `pg_try_advisory_lock`.
struct LockProbe {
    conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
    /// True only when we have POSITIVELY established that this session does not
    /// hold the lock, i.e. `try_lock` came back `false`.
    ///
    /// The predicate has to be "we know nothing was acquired," not "we saw an
    /// answer." A `true` answer means the lock IS held, so dropping without handing
    /// the connection to a guard leaks it exactly as a cancellation would; an
    /// earlier version of this flag meant "settled" and reopened that leak. Default
    /// false so both the cancelled-mid-flight and lock-acquired cases close, and
    /// only ordinary contention returns the connection.
    lock_not_taken: bool,
}

impl LockProbe {
    fn new(conn: sqlx::pool::PoolConnection<sqlx::Postgres>) -> Self {
        Self {
            conn: Some(conn),
            lock_not_taken: false,
        }
    }

    /// Send the try-lock on the owned connection.
    async fn try_lock(&mut self, key: i64) -> Result<bool> {
        let conn = self
            .conn
            .as_mut()
            .context("LockProbe::try_lock after the connection was taken")?;
        // Cleared BEFORE the statement is sent, not after it answers. Once the
        // statement is in flight this session may hold the lock, and an error or a
        // cancellation gives us no way to find out, so the connection must not be
        // returned to the pool on any path but a positive `false`. Assigning only on
        // success would leave a previous `true`-derived value standing.
        self.lock_not_taken = false;
        let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut **conn)
            .await
            .context("trying advisory lock")?;
        // Only a false answer licenses returning the connection: it means the
        // statement completed and took nothing. A true answer means this session
        // now holds the lock, so Drop must still close unless `take_conn` hands it
        // to a guard.
        self.lock_not_taken = !row.0;
        Ok(row.0)
    }

    /// Hand the lock-owning connection out, leaving `Drop` with nothing to close.
    /// Only call this after `try_lock` returned true.
    ///
    /// Named `take_` rather than `into_` deliberately: clippy expects an `into_*`
    /// method to consume `self`, which a type implementing `Drop` cannot do
    /// without tripping E0509.
    fn take_conn(&mut self) -> Option<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        self.conn.take()
    }
}

impl Drop for LockProbe {
    fn drop(&mut self) {
        let Some(mut conn) = self.conn.take() else {
            // take_conn already handed the connection to the guard.
            return;
        };
        if self.lock_not_taken {
            // The probe ran and reported that someone else holds the key, so nothing
            // was acquired here. Return the connection to the pool: closing would
            // make a 60-attempt spinner tear down 60 backends for ordinary
            // contention. Dropping `conn` unarmed does exactly that.
            return;
        }
        // Either the future was dropped before we saw an answer, or the answer was
        // that we DID take the lock and nobody took the connection off us. Both mean
        // a session may be holding the lock with no one to release it, so end the
        // session — which is what makes Postgres free it.
        warn!("advisory-lock probe dropped while its session may hold the lock — closing the session to free it");
        conn.close_on_drop();
    }
}

/// Non-mutating snapshot of a repo's latest Tigris state. Owns the throwaway
/// temp dir it was unpacked into and removes it on drop; a snapshot that
/// borrowed the live local path owns nothing and drops as a no-op.
pub struct RepoSnapshot {
    path: PathBuf,
    owned: bool,
}

impl RepoSnapshot {
    /// Path to the snapshot's bare repo directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RepoSnapshot {
    fn drop(&mut self) {
        if self.owned {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Guard returned by `acquire_write()`. Holds the Postgres advisory lock and
/// uploads to Tigris + releases the lock on `release()`.
pub struct RepoWriteGuard {
    owner_slug: String,
    repo_name: String,
    pub local_path: PathBuf,
    lock_key: i64,
    /// The connection that TOOK the lock. Postgres advisory locks are
    /// session-scoped, so only this session can release it; holding it here is
    /// what makes `release` land on the right backend instead of an arbitrary
    /// pooled one.
    conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
    tigris: Option<TigrisClient>,
    /// Bound on the release-side upload, which runs with the lock still held.
    lock_held_transfer_timeout: Duration,
    /// The generation of the stored archive as observed by the HEAD inside
    /// `acquire_write`, under the lock. `release` publishes fenced on it, so a
    /// PUT abandoned by an earlier writer's timeout cannot land on top of a
    /// successor's acknowledged archive.
    publish_fence: UploadPrecondition,
}

impl RepoWriteGuard {
    /// Backend pid of the session holding the lock. Test-only observable for the
    /// must-not-over-close check: if `release` closed the session instead of
    /// returning it, consecutive writes would report different pids.
    #[cfg(test)]
    async fn backend_pid_for_test(&mut self) -> i32 {
        let conn = self
            .conn
            .as_mut()
            .expect("guard still holds its connection");
        let pid: (i32,) = sqlx::query_as("SELECT pg_backend_pid()")
            .fetch_one(&mut **conn)
            .await
            .expect("backend pid");
        pid.0
    }

    /// Path to the bare repo on local disk.
    pub fn path(&self) -> &Path {
        &self.local_path
    }

    /// Publish the tree this guard wrote, fenced on the generation observed
    /// under the lock, with at most ONE supersede-retry after a definite loss.
    ///
    /// Hard bound of two PUT attempts per release. No loop, no recursion: a
    /// third attempt would have no more reason to terminate than the second.
    async fn publish(&self, tigris: &TigrisClient) -> std::result::Result<(), PublishRefusal> {
        match tigris
            .upload(
                &self.owner_slug,
                &self.repo_name,
                &self.local_path,
                self.publish_fence.clone(),
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(UploadError::PreconditionLost { status }) => {
                // EPISTEMIC ASYMMETRY, and it is why one retry is sound here
                // while the timeout arm in `release` deliberately does nothing.
                // A refused precondition is a DEFINITE outcome: the store told
                // us the generation we observed under the lock is gone, and that
                // our bytes did not land. A timeout tells us nothing at all.
                //
                // We also still hold the advisory lock, so no successor can have
                // acquired and published. Whatever landed underneath was written
                // WITHOUT the lock: init's create-only upload of a freshly
                // created empty repo, or a PUT abandoned by an earlier writer
                // whose own release timed out. This writer's tree is the
                // authority over both, which is what makes exactly one
                // supersede-retry correct rather than a race.
                //
                // Honest residual: when the thing underneath was a genuine
                // orphan that landed AFTER this writer's refresh, the retry
                // supersedes it with a tree that does not contain it. That is
                // the same outcome today's unconditional publish produces. The
                // fence protects an acknowledged successor from an orphan; it
                // does not protect an unlocked orphan from the lock holder.
                warn!(
                    repo = %self.repo_name,
                    status,
                    "publish fence lost: the stored archive changed under the lock, \
                     republishing once on the current generation"
                );
            }
            Err(e) => return Err(PublishRefusal::Failed(e)),
        }

        let fresh = match tigris.head_etag(&self.owner_slug, &self.repo_name).await {
            Ok(Some(etag)) => UploadPrecondition::IfMatch(etag),
            // Nothing is stored now, so create-only is the fence that matches
            // what was just observed.
            Ok(None) => UploadPrecondition::IfAbsent,
            Err(e) => return Err(PublishRefusal::Failed(UploadError::Other(e))),
        };
        match tigris
            .upload(&self.owner_slug, &self.repo_name, &self.local_path, fresh)
            .await
        {
            Ok(()) => Ok(()),
            Err(UploadError::PreconditionLost { status }) => {
                // Two definite losses in a row: something is publishing this key
                // without the lock faster than we can fence on it. Refuse rather
                // than escalate. The write is on local disk and in this node's
                // tree, but it is NOT durable in object storage, so the caller
                // must not report success.
                warn!(
                    repo = %self.repo_name,
                    status,
                    "publish fence lost again on the refreshed generation, refusing the \
                     write rather than attempting a third publish"
                );
                Err(PublishRefusal::Fenced)
            }
            Err(e) => Err(PublishRefusal::Failed(e)),
        }
    }

    /// Upload to Tigris (only when the write succeeded) and release the advisory
    /// lock. Pass `success = false` when the write operation failed — uploading a
    /// half-applied or otherwise inconsistent repo would propagate corruption to
    /// Tigris (and to every node that later downloads it). The lock is always
    /// released regardless, to avoid stale locks blocking future writes.
    pub async fn release(mut self, success: bool) -> ReleaseOutcome {
        let mut outcome = ReleaseOutcome::Released;
        // Upload to Tigris only on success.
        if success {
            if let Some(tigris) = self.tigris.clone() {
                // ONE budget for the whole publish, covering both attempts and
                // the HEAD between them, for the same reason the acquire-side
                // refresh uses one for its HEAD and download together: this runs
                // with the lock held and a lock-pool slot pinned, so bounding
                // each attempt separately would double the worst-case occupancy.
                match bounded_transfer(
                    "release-upload",
                    &self.repo_name,
                    self.lock_held_transfer_timeout,
                    self.publish(&tigris),
                )
                .await
                {
                    Some(Ok(())) => {}
                    // Both attempts were definitively refused. The raise site
                    // already logged which and why, so this only has to carry
                    // the refusal out to the caller.
                    Some(Err(PublishRefusal::Fenced)) => outcome = ReleaseOutcome::Fenced,
                    Some(Err(PublishRefusal::Failed(e))) => {
                        warn!(repo = %self.repo_name, err = %e, "failed to upload repo to tigris after write");
                    }
                    None => {
                        // Timed out is UNKNOWABLE, not failed: the PUT may well
                        // still land after this returns, so there is deliberately
                        // no compensating action here. The lock is released
                        // normally regardless. Holding it would fence nothing,
                        // because `release` takes `mut self`: the guard drops the
                        // moment this function returns and `Drop` closes the
                        // session, so the lock would free within milliseconds
                        // either way. What actually protects a successor from a
                        // late publish is the conditional PUT on the upload, not
                        // the lifetime of this lock.
                        warn!(
                            repo = %self.repo_name,
                            "release upload exceeded its bound; the PUT may still land, so the \
                             outcome is unknowable and the conditional upload is what keeps a \
                             late publish from overwriting a successor's archive"
                        );
                    }
                }
            }
        } else {
            warn!(repo = %self.repo_name, "write failed — skipping tigris upload to avoid propagating an inconsistent repo");
        }

        // Release the advisory lock on the SAME session that took it. Unlocking
        // through the pool would land on an arbitrary backend, where the call is a
        // silent no-op.
        //
        // Read the boolean. `pg_advisory_unlock` reports "you did not hold this
        // lock" as a false RETURN VALUE plus a server WARNING, never an error, so a
        // discarded result cannot distinguish a real release from a no-op. A false
        // here means this session's lock state is not what we believe it is, so the
        // connection is left in `self.conn` for `Drop` to close rather than being
        // handed back to the pool as clean. Only a confirmed unlock returns it.
        let lock_key = self.lock_key;
        let unlock = match self.conn.as_mut() {
            Some(conn) => Some(
                sqlx::query_as::<_, (bool,)>("SELECT pg_advisory_unlock($1)")
                    .bind(lock_key)
                    .fetch_one(&mut **conn)
                    .await,
            ),
            None => None,
        };
        match unlock {
            Some(Ok((true,))) => {
                // Confirmed released: safe to return to the pool.
                self.conn.take();
            }
            Some(Ok((false,))) => {
                warn!(
                    repo = %self.repo_name,
                    lock_key,
                    "advisory unlock reported the session did not hold this lock — closing the session instead of pooling it"
                );
            }
            Some(Err(e)) => {
                warn!(
                    repo = %self.repo_name,
                    lock_key,
                    err = %e,
                    "advisory unlock failed — closing the session so the lock cannot outlive it"
                );
            }
            None => {}
        }

        outcome
    }
}

impl Drop for RepoWriteGuard {
    fn drop(&mut self) {
        let Some(mut conn) = self.conn.take() else {
            // release() already unlocked and handed the connection back.
            return;
        };

        // Reached on any exit that skipped release(): an early `?`, a panic, or an
        // axum handler future cancelled when the client disconnected. The session
        // still holds the advisory lock, so returning it to the pool would block
        // every future write to this repo until sqlx recycles the connection.
        //
        // `PoolConnection::drop` spawns onto the runtime, both to close and to
        // return, and panics outright when no runtime handle exists. A panic here
        // would run inside a `Drop` and abort the process during unwind, so check
        // for a runtime first. With none, the process is already going away: leak
        // the handle deliberately rather than panic, and let socket teardown end
        // the session, which is what frees the lock at exit anyway.
        if tokio::runtime::Handle::try_current().is_ok() {
            warn!(
                repo = %self.repo_name,
                "write guard dropped without release() — closing its session to free the advisory lock"
            );
            conn.close_on_drop();
        } else {
            warn!(
                repo = %self.repo_name,
                "write guard dropped with no runtime alive — detaching the connection so Drop cannot panic"
            );
            // `PoolConnection::drop` spawns onto the runtime for BOTH closing and
            // returning, and panics without a handle; a panic inside Drop aborts the
            // process during unwind. `leak()` detaches the raw `PgConnection`, which
            // has no Drop impl of its own, so dropping it closes the socket
            // synchronously with no runtime involved. That frees the lock
            // immediately rather than at process exit, and leaks no fd — strictly
            // better than the mem::forget this replaced.
            drop(conn.leak());
        }
    }
}

/// Default wall-clock cap on WAITING for the per-repo advisory lock.
///
/// An attempt-count bound alone is not enough: 60 attempts each paying a pool
/// acquire plus a 1s sleep reach roughly 360s.
///
/// This bounds the wait only, NOT the whole of `acquire_write`. The under-lock
/// refresh carries its own separate bound (`lock_held_transfer_timeout`, default
/// 300s), so the two compose rather than nest and a caller can legitimately spend
/// this deadline waiting and then that bound refreshing. Do not read 90s as a
/// promise that `acquire_write` returns inside the 120s proxy idle timeout in
/// `infra/fly/fly.toml`; it is not, and reconciling the two is tracked separately.
const LOCK_ACQUIRE_DEADLINE: Duration = Duration::from_secs(90);

/// Why an under-lock refresh did not complete, split by what it leaves us knowing.
///
/// `Unknown` (the existence check failed) and `Download` (the archive is there and
/// unreadable) must not share a branch: only the second establishes that the local
/// copy is a sound thing to fall back to and re-upload.
enum RefreshFailure {
    Unknown(anyhow::Error),
    /// Carries the fence the HEAD observed alongside the error, because the
    /// fallback arm still publishes later and must be fenced on the generation
    /// it saw. `Unknown` carries none: that arm refuses the write outright.
    Download {
        err: anyhow::Error,
        fence: UploadPrecondition,
    },
}

/// What `release` was able to do with the writer's tree.
///
/// `#[must_use]` because dropping it is the whole defect this type exists to
/// prevent: a publish the store refused would otherwise return 201, fire
/// webhooks, and record a push that no successor can read.
#[derive(Debug)]
#[must_use = "a refused publish must reach the caller, or a write that never landed reports success"]
pub enum ReleaseOutcome {
    /// The lock was released and nothing definitively refused the publish.
    /// Also the answer when there was nothing to publish (a failed write, no
    /// storage backend) and when the outcome is unknowable (the upload
    /// exceeded its bound), which keeps those paths behaving as they do today.
    Released,
    /// The store refused the publish twice. The tree is on local disk but is
    /// NOT in object storage, so the caller must not report success.
    Fenced,
}

impl ReleaseOutcome {
    /// Fold into the `Result` a handler propagates with `?`.
    ///
    /// Call this at every publishing site IMMEDIATELY after `release`, before
    /// any post-release effect. A refusal that short-circuits after the DB
    /// write, the webhook, or the response body has already happened is not a
    /// refusal at all.
    pub fn into_result(self) -> anyhow::Result<()> {
        match self {
            ReleaseOutcome::Released => Ok(()),
            // The raise site inside `publish` already logged the repo and the
            // status, so this carries no detail: the handler layer turns it
            // into a fixed 503 body.
            ReleaseOutcome::Fenced => Err(anyhow::Error::new(RepoWriteFenced)
                .context("release-side publish refused by the store on both attempts")),
        }
    }
}

/// Why the release-side publish did not land, split by what it leaves the
/// caller able to claim.
///
/// `Fenced` is a DEFINITE refusal by the store after both attempts, so the
/// write is not durable and the caller must not report success. `Failed` is
/// every other upload failure, which keeps today's behavior (log it, release
/// the lock, let the caller answer normally).
enum PublishRefusal {
    Fenced,
    Failed(UploadError),
}

/// The per-repo advisory lock was not obtained within the acquire deadline.
///
/// A distinct type rather than a bare `anyhow` string so the handler layer can map
/// it to a retryable 503 with a FIXED body. Contention is transient and ordinary,
/// and the internal message names the owner slug and repo, which must stay in the
/// log rather than reaching the client.
#[derive(Debug)]
pub struct RepoBusy;

impl std::fmt::Display for RepoBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("repository is busy")
    }
}

impl std::error::Error for RepoBusy {}

/// The under-lock refresh could not establish what is in object storage, so the
/// write was refused rather than run against a possibly-stale tree.
///
/// A distinct type rather than a bare `anyhow` string so the handler layer can map
/// it to a retryable 503 with a FIXED body. The internal message names the owner
/// slug and repo, which must stay in the log at the raise site rather than reaching
/// the client.
#[derive(Debug)]
pub struct RepoUnavailable;

impl std::fmt::Display for RepoUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("repository is temporarily unavailable")
    }
}

impl std::error::Error for RepoUnavailable {}

/// The release-side publish was refused by the store on both attempts, so the
/// write is not durable in object storage.
///
/// A distinct type rather than a bare `anyhow` string, for the same reason as
/// its two siblings above: the handler layer maps it to a retryable 503 with a
/// FIXED body, and the detail (which repo, which status) stays in the log at
/// the raise site. Distinct FROM those siblings because the condition is
/// different: not contention and not an unreadable store, but another writer
/// holding the key. The client's retry re-runs the whole write against the tree
/// that actually won.
#[derive(Debug)]
pub struct RepoWriteFenced;

impl std::fmt::Display for RepoWriteFenced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("repository write was fenced by a concurrent publish")
    }
}

impl std::error::Error for RepoWriteFenced {}

/// Run a future under a wall-clock bound, returning `None` if it did not finish.
///
/// For the object-storage transfers that run while the per-repo advisory lock is
/// held. Those were free before the lock's connection was pinned to the guard;
/// now an unbounded transfer holds a lock-pool slot for as long as it stalls, and
/// enough of them deny every write on the node.
///
/// A timed-out transfer is **unknowable**, not failed: it may well have landed.
/// Callers must not compensate as though it definitely failed.
async fn bounded_transfer<F, T>(label: &str, repo: &str, limit: Duration, fut: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    match tokio::time::timeout(limit, fut).await {
        Ok(v) => Some(v),
        Err(_) => {
            warn!(
                repo = %repo,
                transfer = label,
                limit_secs = limit.as_secs(),
                "object-storage transfer exceeded its under-lock bound — giving up so the advisory lock and its pool slot are not held longer"
            );
            None
        }
    }
}

/// Test-only re-export of the advisory-lock key derivation, so handler tests can
/// hold a repo's lock from an independent session.
#[cfg(test)]
pub fn advisory_lock_key_for_test(owner_slug: &str, repo_name: &str) -> i64 {
    advisory_lock_key(owner_slug, repo_name)
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
        RepoStore::new(
            PathBuf::from("/var/lib/gitlawb/repos"),
            None,
            pool,
            Duration::from_secs(300),
        )
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
        let size_before = store_pool.size();
        assert!(size_before > 0, "the pool owns the guard's connection");

        // The backstop shape: dropped without release(), with an unlock that errors.
        drop(guard);

        wait_until(
            || store_pool.size() == size_before - 1,
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
        let size_before = store_pool.size();
        assert!(size_before > 0, "the pool owns the guard's connection");

        drop(guard);

        // The connection goes back only once the detached unlock task has finished.
        wait_until(
            || store_pool.num_idle() > 0,
            "the detached unlock to finish and hand the connection back",
        )
        .await;
        assert_eq!(
            store_pool.size(),
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

    /// U8, the off-runtime arm: with no Tokio runtime there is nothing to spawn the
    /// unlock onto, and the connection has already been taken out of the guard, so the
    /// old code dropped it with no unlock attempted at all, back to the pool, session
    /// lock still held. Dropping a `PoolConnection` off a runtime is worse than that:
    /// sqlx's return-to-pool path spawns, and its no-runtime fallback panics, so the
    /// old arm also panicked in a destructor.
    ///
    /// Reached by dropping the guard on a plain `std::thread`, where
    /// `Handle::try_current()` fails.
    ///
    /// Load-bearing: RED before the fix (the join sees the "requires a Tokio context"
    /// panic from sqlx's return-to-pool spawn), GREEN after (`detach` gives up the
    /// pool slot, so nothing is spawned and dropping the detached connection closes
    /// the socket, which ends the session and frees the lock).
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
        let size_before = store_pool.size();
        assert!(size_before > 0, "the pool owns the guard's connection");

        let dropped = std::thread::spawn(move || drop(guard)).join();
        assert!(
            dropped.is_ok(),
            "dropping a write guard off a Tokio runtime must not panic"
        );

        wait_until(
            || store_pool.size() == size_before - 1,
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
    // ── U1: cancellation-safe lock probe ───────────────────────────────────

    /// A pool with every reaping path disabled, so a leaked lock persists through
    /// the observation window instead of being freed by ambient recycling.
    async fn no_reap_pool(opts: &sqlx::postgres::PgConnectOptions, max: u32) -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .min_connections(0)
            .idle_timeout(None)
            .max_lifetime(None)
            .test_before_acquire(false)
            .connect_with(opts.clone())
            .await
            .expect("no-reap pool")
    }

    /// Poll a STANDALONE connection until the key is free, or the deadline passes.
    ///
    /// Standalone, never from the pool under test: pool reuse would hand the
    /// observer the lock-holding session itself, where `pg_try_advisory_lock`
    /// succeeds reentrantly and hides the very leak being measured. Polling rather
    /// than asserting once because `PoolConnection::drop` spawns the close.
    async fn poll_until_free(
        opts: &sqlx::postgres::PgConnectOptions,
        key: i64,
        deadline: std::time::Duration,
    ) -> bool {
        use sqlx::Connection;
        let start = std::time::Instant::now();
        let mut observer = sqlx::PgConnection::connect_with(opts)
            .await
            .expect("standalone observer connection");
        while start.elapsed() < deadline {
            let got: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
                .bind(key)
                .fetch_one(&mut observer)
                .await
                .expect("observer try-lock");
            if got.0 {
                let _: (bool,) = sqlx::query_as("SELECT pg_advisory_unlock($1)")
                    .bind(key)
                    .fetch_one(&mut observer)
                    .await
                    .expect("observer unlock");
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        false
    }

    /// THE COMMITTED GATE for the cancellation window (U1).
    ///
    /// Dropping the probe without taking its connection is exactly the state a
    /// cancellation between the try-lock's send and the guard's construction
    /// leaves behind. Deterministic on purpose: the timing sweep that first found
    /// this window leaks about 1 in 600, which is not a signal a CI gate can rest
    /// on. That sweep stays a local repro.
    #[sqlx::test]
    async fn lock_probe_dropped_without_taking_frees_the_lock(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 4).await;
        let key: i64 = 990_001;

        {
            let mut probe = LockProbe::new(lock_pool.acquire().await.unwrap());
            assert!(
                probe.try_lock(key).await.unwrap(),
                "probe should take a free key"
            );
            // dropped here WITHOUT take_conn(): the cancellation shape
        }

        assert!(
            poll_until_free(&opts, key, std::time::Duration::from_secs(10)).await,
            "lock must be freed after a probe is dropped without taking its connection"
        );
    }

    /// Must-not: a successful acquire hands the connection out intact, so the
    /// normal path does not pay a reconnect per write.
    #[sqlx::test]
    async fn lock_probe_take_conn_yields_a_usable_connection(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 4).await;
        let key: i64 = 990_002;

        let mut probe = LockProbe::new(lock_pool.acquire().await.unwrap());
        assert!(probe.try_lock(key).await.unwrap());
        let mut conn = probe
            .take_conn()
            .expect("connection after a successful acquire");
        drop(probe);

        let one: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&mut *conn)
            .await
            .expect("handed-out connection must still be usable");
        assert_eq!(one.0, 1);

        let released: (bool,) = sqlx::query_as("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert!(released.0, "the handed-out connection still owns the lock");
    }

    /// Must-not: a failed probe returns its connection without closing it. Nothing
    /// was locked, so closing would be pure churn, and closing on every failed
    /// probe would make a 60-attempt spinner tear down 60 backends.
    #[sqlx::test]
    async fn lock_probe_failed_acquire_does_not_hold_anything(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 4).await;
        let key: i64 = 990_003;

        // a standalone holder takes the key first
        use sqlx::Connection;
        let mut holder = sqlx::PgConnection::connect_with(&opts).await.unwrap();
        let held: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut holder)
            .await
            .unwrap();
        assert!(held.0);

        {
            let mut probe = LockProbe::new(lock_pool.acquire().await.unwrap());
            assert!(
                !probe.try_lock(key).await.unwrap(),
                "probe must observe false for a key held elsewhere"
            );
        }

        // the holder still owns it: the failed probe neither took nor released it
        let still: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' \
             AND ((classid::bigint<<32)|objid::bigint) = $1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(still.0, 1, "the original holder must still own the key");
    }

    // ── U3: the #279 acceptance tests ──────────────────────────────────────

    /// The store under test. Pre-U3 this ignores `opts` and shares the app pool,
    /// which is exactly the broken shape; the wiring change swaps in a dedicated
    /// no-reap lock pool without touching a single test body below.
    async fn write_store(pool: &PgPool, opts: &sqlx::postgres::PgConnectOptions) -> RepoStore {
        let _ = pool;
        RepoStore::for_testing(
            PathBuf::from("/tmp/gitlawb-u3"),
            no_reap_pool(opts, 8).await,
        )
    }

    fn advisory_locks_held(key: i64) -> String {
        format!(
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' \
             AND ((classid::bigint<<32)|objid::bigint) = {key}"
        )
    }

    /// ACCEPTANCE 1 (#279): two writers on one node and the same repo must not
    /// both hold the lock. On the pre-fix shape the second acquire succeeds
    /// because the pool hands it the very session holding the lock, where
    /// pg_try_advisory_lock is reentrant.
    #[sqlx::test]
    async fn two_writers_on_the_same_repo_are_not_both_admitted(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let store = write_store(&pool, &opts)
            .await
            .with_lock_acquire_deadline(std::time::Duration::from_millis(300));

        let _first = store
            .acquire_write("did:key:z6MkU3Excl", "same-repo")
            .await
            .expect("first writer acquires");

        let err = match store.acquire_write("did:key:z6MkU3Excl", "same-repo").await {
            Err(e) => e,
            Ok(second) => {
                let _ = second.release(false).await;
                panic!("a second writer must NOT be admitted while the first holds the guard");
            }
        };
        assert!(
            err.downcast_ref::<RepoBusy>().is_some(),
            "the second writer must be shed as RepoBusy, got {err:#}"
        );
    }

    /// ACCEPTANCE 2 (#279): a completed write leaves no advisory lock behind.
    /// On the pre-fix shape the unlock runs on a different pooled session and
    /// returns false, so the lock leaks on essentially every write.
    #[sqlx::test]
    async fn completed_write_releases_its_advisory_lock(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let store = write_store(&pool, &opts).await;

        let guard = store
            .acquire_write("did:key:z6MkU3Rel", "leak-check")
            .await
            .expect("acquire");
        let _ = guard.release(true).await;

        let key = advisory_lock_key("did_key_z6MkU3Rel", "leak-check");
        let held: (i64,) = sqlx::query_as(&advisory_locks_held(key))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            held.0, 0,
            "a completed write must leave zero advisory locks for its key"
        );
    }

    // ── U4: a guard that dies without releasing must free the lock ──────────

    /// A guard dropped without `release()` (an early `?`, a panic, or a handler
    /// future cancelled on client disconnect) must not return a lock-bearing
    /// connection to the pool, where it would block every future write to that
    /// repo until sqlx recycles the session.
    #[sqlx::test]
    async fn guard_dropped_without_release_frees_the_lock(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let store = write_store(&pool, &opts).await;
        let key = advisory_lock_key("did_key_z6MkU4Drop", "dropped");

        {
            let _guard = store
                .acquire_write("did:key:z6MkU4Drop", "dropped")
                .await
                .expect("acquire");
            // dropped here without release()
        }

        assert!(
            poll_until_free(&opts, key, std::time::Duration::from_secs(10)).await,
            "lock must be freed when a guard is dropped without release()"
        );
    }

    /// Must-not over-close: the normal path returns its connection to the pool, so
    /// a healthy write does not pay a reconnect. Sized to one connection so the
    /// backend pid is a direct observable: if `release` were closing the session,
    /// each cycle would land on a fresh backend.
    #[sqlx::test]
    async fn normal_release_reuses_the_same_backend(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let store = RepoStore::for_testing(
            PathBuf::from("/tmp/gitlawb-u4"),
            no_reap_pool(&opts, 1).await,
        );

        let mut pids = Vec::new();
        for i in 0..4 {
            let repo = format!("reuse-{i}");
            let mut guard = store
                .acquire_write("did:key:z6MkU4Reuse", &repo)
                .await
                .expect("acquire");
            pids.push(guard.backend_pid_for_test().await);
            let _ = guard.release(true).await;
        }
        assert!(
            pids.windows(2).all(|w| w[0] == w[1]),
            "a released guard must return its connection to the pool, so all four \
             writes share one backend; saw {pids:?}"
        );
    }

    /// A guard abandoned while the runtime is tearing down must not panic.
    /// `PoolConnection::drop` calls `crate::rt::spawn`, which panics without a
    /// runtime handle, and a panic inside `Drop` during unwind aborts the process.
    /// At real process exit the lock is freed by socket teardown, not by this Drop
    /// body, so this asserts no-panic rather than lock release.
    #[test]
    fn guard_dropped_at_runtime_teardown_does_not_panic() {
        // No silent skip: a test that returns green when its precondition is
        // absent is worse than one that fails, because it reports coverage it does
        // not have. CI provisions Postgres, so an absent DATABASE_URL is a broken
        // environment rather than an expected one.
        let url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set; this test cannot pass vacuously");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let guard = rt.block_on(async {
            let lock_pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("lock pool");
            let store = RepoStore::for_testing(PathBuf::from("/tmp/gitlawb-u4b"), lock_pool);
            store
                .acquire_write("did:key:z6MkU4Teardown", "teardown")
                .await
                .expect("acquire")
        });
        // Shut the runtime down first, then drop the guard with no runtime alive.
        drop(rt);
        drop(guard);
    }

    // ── U5: the unlock's boolean result must be observed ────────────────────

    /// `pg_advisory_unlock` reports "you did not hold this lock" as a `false`
    /// RETURN VALUE plus a server WARNING, never an error, so a discarded result
    /// cannot tell a real release from a no-op. A session that did not hold the
    /// key must not be returned to the pool as if it were clean.
    ///
    /// The observable is the backend pid: on a one-connection pool, a session that
    /// was closed forces the next acquire onto a fresh backend, while one returned
    /// normally is handed straight back.
    #[sqlx::test]
    async fn release_that_did_not_hold_the_lock_closes_the_session(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 1).await;

        let pid_before = {
            let mut c = lock_pool.acquire().await.unwrap();
            let pid: (i32,) = sqlx::query_as("SELECT pg_backend_pid()")
                .fetch_one(&mut *c)
                .await
                .unwrap();
            pid.0
        };

        // A guard whose key was never locked: release()'s unlock returns false.
        let guard = RepoWriteGuard {
            owner_slug: "did_key_z6MkU5".to_string(),
            repo_name: "never-locked".to_string(),
            local_path: PathBuf::from("/tmp/gitlawb-u5"),
            lock_key: 995_001,
            conn: Some(lock_pool.acquire().await.unwrap()),
            tigris: None,
            lock_held_transfer_timeout: Duration::from_secs(300),
            // No backend, so nothing is ever published and the fence is unread.
            publish_fence: UploadPrecondition::Unconditional,
        };
        let _ = guard.release(true).await;

        // Wait for the backend to actually go away rather than sleeping a fixed
        // span, which is flaky on slow CI. The observer is a STANDALONE
        // connection for the same reason `poll_until_free` uses one: taking it
        // from the pool under test would hand us the very session being measured.
        // Nothing but the close under test can retire that backend, because
        // `no_reap_pool` disables idle timeout and max lifetime, so a zero count
        // here is attributable to `release()` and to nothing else.
        {
            use sqlx::Connection;
            let deadline = std::time::Duration::from_secs(5);
            let start = std::time::Instant::now();
            let mut observer = sqlx::PgConnection::connect_with(&opts)
                .await
                .expect("standalone observer connection");
            while start.elapsed() < deadline {
                let alive: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM pg_stat_activity WHERE pid = $1")
                        .bind(pid_before)
                        .fetch_one(&mut observer)
                        .await
                        .expect("observer pg_stat_activity probe");
                if alive.0 == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }

        let pid_after = {
            let mut c = lock_pool.acquire().await.unwrap();
            let pid: (i32,) = sqlx::query_as("SELECT pg_backend_pid()")
                .fetch_one(&mut *c)
                .await
                .unwrap();
            pid.0
        };

        assert_ne!(
            pid_before, pid_after,
            "an unlock that returned false means the session's lock state is not \
             what we think it is; that connection must be closed, not pooled"
        );
    }

    // ── U6: under-lock transfers are bounded ────────────────────────────────

    /// The bound itself. Driving a real stalled transfer through `acquire_write`
    /// would need either the object-store abstraction (out of scope here) or a
    /// process-global `AWS_ENDPOINT_URL_S3` mutation, which would make the suite
    /// order-dependent under the concurrent test runner. So this covers the
    /// mechanism deterministically and the wiring is verified by reading, which is
    /// recorded as a coverage gap rather than papered over.
    #[tokio::test]
    async fn bounded_transfer_gives_up_past_the_limit() {
        let slow = async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok::<(), anyhow::Error>(())
        };
        let out =
            bounded_transfer("test", "repo", std::time::Duration::from_millis(50), slow).await;
        assert!(
            out.is_none(),
            "a transfer past its limit must report None so the caller stops holding the lock"
        );
    }

    /// Must-not: a transfer that finishes inside the limit is returned intact and
    /// is not truncated by the bound.
    #[tokio::test]
    async fn bounded_transfer_passes_through_a_prompt_result() {
        let quick = async { Ok::<u32, anyhow::Error>(7) };
        let out = bounded_transfer("test", "repo", std::time::Duration::from_secs(30), quick).await;
        assert!(
            matches!(out, Some(Ok(7))),
            "a prompt transfer must pass through untouched"
        );
    }

    /// F2 regression: an ordinary failed probe must RETURN its connection, not
    /// close it. The old test asserted the holder's pg_locks count, which cannot
    /// see what happened to the probe's own connection — so it passed while a
    /// 60-attempt spinner tore down 60 backends. The observable that discriminates
    /// is the backend pid on a one-connection pool.
    #[sqlx::test]
    async fn failed_probe_returns_its_connection_to_the_pool(pool: PgPool) {
        use sqlx::Connection;
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 1).await;
        let key: i64 = 991_100;

        // someone else holds the key, from an independent session
        let mut holder = sqlx::PgConnection::connect_with(&opts).await.unwrap();
        let held: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut holder)
            .await
            .unwrap();
        assert!(held.0);

        let mut pids = Vec::new();
        for _ in 0..3 {
            let mut probe = LockProbe::new(lock_pool.acquire().await.unwrap());
            let pid: (i32,) = sqlx::query_as("SELECT pg_backend_pid()")
                .fetch_one(&mut **probe.conn.as_mut().unwrap())
                .await
                .unwrap();
            pids.push(pid.0);
            assert!(!probe.try_lock(key).await.unwrap(), "key is held elsewhere");
            drop(probe);
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        assert!(
            pids.windows(2).all(|w| w[0] == w[1]),
            "a failed probe must return its connection so a spinner does not churn \
             backends; saw {pids:?}"
        );
    }

    // ── F5: the tests the plan required and the first pass never wrote ────────

    /// R4, the test the plan named as proving the pool split and the one that would
    /// have caught PR #215's node-wide two-write ceiling. Holding N guards on
    /// DISTINCT repos must pin N lock-pool connections while leaving the app pool
    /// free to serve ordinary queries.
    #[sqlx::test]
    async fn lock_pool_exhaustion_does_not_starve_the_app_pool(pool: PgPool) {
        const N: u32 = 3;
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, N).await;
        let store = RepoStore::for_testing(PathBuf::from("/tmp/gitlawb-f5"), lock_pool.clone());

        let mut guards = Vec::new();
        for i in 0..N {
            guards.push(
                store
                    .acquire_write(&format!("did:key:z6MkF5Iso{i}"), "iso")
                    .await
                    .expect("distinct repos each acquire"),
            );
        }

        // Every slot is accounted for by a guard, so the pool really is exhausted
        // rather than merely slow. Asserted directly, because the starvation check
        // below cannot tell the two apart on its own.
        assert_eq!(
            lock_pool.size() as usize - lock_pool.num_idle(),
            N as usize,
            "all N slots must be checked out by the guards"
        );

        // An N+1th checkout must be refused BY THE POOL. The specific error matters:
        // `Ok(Err(_)) | Err(_)` would also be satisfied by the outer tokio timeout
        // firing for an unrelated reason, which would let this pass without the pool
        // ever having refused anything.
        let starved =
            tokio::time::timeout(std::time::Duration::from_secs(8), lock_pool.acquire()).await;
        match starved {
            Ok(Err(sqlx::Error::PoolTimedOut)) => {}
            Ok(Err(e)) => panic!("expected the pool's own timeout, got {e:?}"),
            Ok(Ok(_)) => panic!("with N guards held, an N+1th lock-pool checkout must not succeed"),
            Err(_) => panic!(
                "the pool must refuse the checkout itself within its acquire_timeout; \
                 the outer timeout firing means it never did"
            ),
        }

        // ...while the APP pool still serves queries. This is the whole point of
        // the split: write pressure must not deny ordinary reads. Weak on its own (it
        // is a different pool object, so it would serve regardless), so it is the
        // exhaustion assertions above that carry the isolation claim; this only
        // confirms the reads are actually reachable in that state.
        let alive: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("app pool must remain usable while the lock pool is exhausted");
        assert_eq!(alive.0, 1);

        for g in guards.drain(..) {
            let _ = g.release(true).await;
        }
    }

    /// A waiter spinning on a contended repo must hand its pool slot back for the
    /// duration of each backoff, and must not block a write to an unrelated repo
    /// (R5, both halves).
    ///
    /// The pool-counter sampling is the load-bearing half. A second `acquire_write`
    /// succeeding proves only that two different lock keys do not collide, which is
    /// true whether or not the spinner released anything: with the slot held through
    /// the sleep, a pool of 3 still has room for it. So this samples what the
    /// spinner actually occupies across more than two backoff cycles. Moving
    /// `drop(probe)` after the backoff sleep turns it red.
    #[sqlx::test]
    async fn waiter_on_one_repo_does_not_block_another(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 3).await;
        let store = std::sync::Arc::new(RepoStore::for_testing(
            PathBuf::from("/tmp/gitlawb-f5b"),
            lock_pool.clone(),
        ));

        let held = store
            .acquire_write("did:key:z6MkF5Cont", "contended")
            .await
            .unwrap();

        let spinner = {
            let s = store.clone();
            tokio::spawn(async move { s.acquire_write("did:key:z6MkF5Cont", "contended").await })
        };

        // Sample across >2 backoff cycles. `held` accounts for exactly one
        // checked-out connection throughout, so every sample above that is the
        // spinner sitting on a slot it is not using.
        let mut spinner_idle = 0;
        let mut samples = 0;
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let checked_out = lock_pool.size() as usize - lock_pool.num_idle();
            if checked_out == 1 {
                spinner_idle += 1;
            }
            samples += 1;
        }
        assert!(
            spinner_idle * 10 >= samples * 7,
            "a spinner must hold no lock-pool slot through its backoff: only {spinner_idle}/{samples} \
             samples showed just the held guard checked out"
        );

        let unrelated = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            store.acquire_write("did:key:z6MkF5Other", "innocent"),
        )
        .await
        .expect("an unrelated repo must not wait on someone else's contention")
        .expect("and must acquire");
        let _ = unrelated.release(true).await;

        spinner.abort();
        let _ = held.release(true).await;
    }

    /// Lock contention that runs out the acquire deadline must surface as a
    /// retryable 503 with a fixed body, not a 500 carrying the owner slug and repo
    /// name. The deadline is a field so this does not wait out the 90s default.
    #[sqlx::test]
    async fn contended_acquire_sheds_as_repo_busy_not_internal_error(pool: PgPool) {
        use axum::response::IntoResponse;

        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 4).await;
        let store = RepoStore::for_testing(PathBuf::from("/tmp/gitlawb-busy"), lock_pool)
            .with_lock_acquire_deadline(std::time::Duration::from_millis(300));

        let held = store
            .acquire_write("did:key:z6MkBusyOwner", "busyrepo")
            .await
            .expect("first writer acquires");

        // Not `expect_err`: the guard is not Debug, and a guard obtained here must be
        // released rather than dropped on a panic path.
        let err = match store
            .acquire_write("did:key:z6MkBusyOwner", "busyrepo")
            .await
        {
            Err(e) => e,
            Ok(second) => {
                let _ = second.release(false).await;
                panic!("a second writer must be shed once the deadline expires");
            }
        };

        // The internal chain keeps the operator detail...
        let chain = format!("{err:#}");
        assert!(
            chain.contains("busyrepo"),
            "the log-side error must name the repo, got {chain}"
        );

        // ...and the client-visible mapping must carry neither it nor a 500.
        let resp = crate::error::AppError::from(err).into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "contention is transient and must be retryable"
        );
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("repo_busy") && !body.contains("busyrepo"),
            "the 503 body must be fixed and must not name the repo, got {body}"
        );

        let _ = held.release(true).await;
    }

    /// An under-lock refresh refusal must surface as a retryable 503 with a fixed
    /// body, not a 500 carrying the owner slug and repo name. Built directly from
    /// the typed error so it needs no database; the `.context()` layer is kept
    /// deliberately, because the real raise path wraps one and this proves anyhow
    /// preserves downcastability through it.
    #[tokio::test]
    async fn repo_unavailable_maps_to_retryable_503_with_fixed_body() {
        use axum::response::IntoResponse;

        let err = anyhow::Error::new(RepoUnavailable)
            .context("tigris HEAD failed before a write for did_key_z6MkTest/secret-repo");

        let resp = crate::error::AppError::from(err).into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "a storage blip is transient and must be retryable, not a 500"
        );
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("repo_unavailable"),
            "the 503 must carry the repo_unavailable code, got {body}"
        );
        assert!(
            !body.contains("secret-repo"),
            "the 503 body must be fixed and must not name the repo, got {body}"
        );
        assert!(
            !body.contains("did_key_z6MkTest"),
            "the 503 body must be fixed and must not name the owner, got {body}"
        );
    }

    /// The new downcast rung must be additive: an unrelated anyhow error still
    /// falls through to the internal 500.
    #[tokio::test]
    async fn repo_unavailable_rung_does_not_swallow_unrelated_errors() {
        use axum::response::IntoResponse;

        let resp =
            crate::error::AppError::from(anyhow::anyhow!("some other failure")).into_response();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "an unrelated failure must not be reclassified as retryable"
        );
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("internal_error"),
            "an unrelated failure must keep the internal_error code, got {body}"
        );
    }

    /// A Tigris client aimed at a closed port, so every call fails at the
    /// transport layer promptly and `exists()` returns `Err` rather than
    /// `Ok(false)`.
    #[cfg(test)]
    fn unreachable_tigris() -> TigrisClient {
        TigrisClient::for_testing_with_endpoint("test-bucket", "http://127.0.0.1:1")
    }

    /// A failed HEAD tells us nothing about whether a newer archive exists, so
    /// the pre-write refresh must refuse rather than read the failure as "no
    /// archive" and serve a possibly-stale local copy to the pushing client.
    ///
    /// Asserts on the downcast, not the message, so a context rewrite cannot
    /// quietly make this vacuous.
    #[sqlx::test]
    async fn acquire_fresh_refuses_when_the_head_check_fails(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 2).await;
        let store = RepoStore::for_testing_with_tigris(
            PathBuf::from("/tmp/gitlawb-headfail-fresh"),
            lock_pool,
            unreachable_tigris(),
        );

        let err = store
            .acquire_fresh("did:key:z6MkHeadFail", "freshrepo")
            .await
            .expect_err("a failed HEAD must refuse rather than serve the local copy");
        assert!(
            err.downcast_ref::<RepoUnavailable>().is_some(),
            "the refusal must be typed so the handler layer maps it to a retryable 503, got {err:#}"
        );
    }

    /// A download that fails when the HEAD succeeded tells us the archive is
    /// present but unreadable, and with no local copy to fall back on the
    /// pre-write refresh must refuse as `RepoUnavailable` — not leak a bare
    /// Tigris error that the handler layer would map to a non-retryable 500.
    ///
    /// The server answers HEAD 200 and GET 500, so `exists()` returns
    /// `Ok(true)` while `download()` fails at the transport layer, exactly the
    /// "archive present per HEAD, GET failed, no local fallback" state.
    #[sqlx::test]
    async fn acquire_fresh_refuses_when_the_download_fails_and_no_local_copy_exists(pool: PgPool) {
        use axum::response::IntoResponse;

        let app = axum::Router::new().route(
            "/{*key}",
            axum::routing::any(|method: axum::http::Method| async move {
                if method == axum::http::Method::HEAD {
                    axum::http::StatusCode::OK.into_response()
                } else {
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 2).await;
        let store = RepoStore::for_testing_with_tigris(
            PathBuf::from("/tmp/gitlawb-getfail-fresh"),
            lock_pool,
            TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint),
        );

        let err = store
            .acquire_fresh("did:key:z6MkGetFail", "freshrepo")
            .await
            .expect_err("a failed download with no local copy must refuse");
        assert!(
            err.downcast_ref::<RepoUnavailable>().is_some(),
            "the refusal must be typed so the handler layer maps it to a retryable 503, got {err:#}"
        );

        server.abort();
    }

    /// The under-lock sibling of the above. `acquire_write` already refuses on
    /// this condition; this proves the `RefreshFailure::Unknown` arm end to end
    /// against a real failing HEAD rather than by reading the code.
    #[sqlx::test]
    async fn acquire_write_refuses_when_the_head_check_fails(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 2).await;
        let store = RepoStore::for_testing_with_tigris(
            PathBuf::from("/tmp/gitlawb-headfail-write"),
            lock_pool,
            unreachable_tigris(),
        );

        // Not `expect_err`: the guard is not Debug, and a guard obtained here
        // must be released rather than dropped on a panic path.
        let err = match store
            .acquire_write("did:key:z6MkHeadFail", "writerepo")
            .await
        {
            Err(e) => e,
            Ok(guard) => {
                let _ = guard.release(false).await;
                panic!("a failed HEAD must refuse the write rather than proceed on a stale tree");
            }
        };
        assert!(
            err.downcast_ref::<RepoUnavailable>().is_some(),
            "the refusal must be typed so the handler layer maps it to a retryable 503, got {err:#}"
        );
    }

    /// The transfer bound is a knob, so it gets the same parse/default/reject-zero
    /// coverage its sibling lock-pool-size knob has.
    #[test]
    fn lock_held_transfer_timeout_defaults_and_rejects_zero() {
        use clap::Parser;
        assert_eq!(
            crate::config::Config::parse_from(["gitlawb-node"]).lock_held_transfer_timeout_secs,
            300
        );
        assert!(crate::config::Config::try_parse_from([
            "gitlawb-node",
            "--lock-held-transfer-timeout-secs",
            "0"
        ])
        .is_err());
    }

    /// P1a: the non-owner pre-check must refresh from a NON-MUTATING snapshot.
    /// A snapshot download must unpack into a throwaway temp dir and leave the
    /// live repo path untouched, so an unlocked pre-check cannot delete or swap
    /// the directory under a concurrent guarded write.
    ///
    /// Real S3 server (not a mock): upload an archive, then `read_snapshot` it,
    /// and assert the snapshot path is a fresh temp dir distinct from the live
    /// path, that the live path was never created, and that the snapshot reads
    /// the same content.
    #[sqlx::test]
    async fn read_snapshot_is_non_mutating(pool: PgPool) {
        use axum::response::IntoResponse;

        // A real in-process S3-compatible server via the SDK against an axum
        // router is more plumbing than this test needs; instead, upload through
        // the real Tigris client against an axum server that stores the object
        // in memory, then snapshot through the same store.
        //
        // Simpler and equally load-bearing: build the archive bytes, serve them
        // with a real HTTP server that answers HEAD 200 and GET with the bytes,
        // then call read_snapshot and assert the live path is untouched and the
        // snapshot content matches.
        let mut archive_bytes = Vec::new();
        {
            let dir =
                std::env::temp_dir().join(format!("gitlawb-snap-src-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(dir.join("objects/info")).unwrap();
            std::fs::create_dir_all(dir.join("refs/heads")).unwrap();
            std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
            std::fs::write(dir.join("objects/info/packs"), "").unwrap();
            let encoder = zstd::stream::Encoder::new(&mut archive_bytes, 3).unwrap();
            let mut tar = tar::Builder::new(encoder);
            tar.append_dir_all(".", &dir).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
        let archive = std::sync::Arc::new(archive_bytes);

        let app = axum::Router::new().route(
            "/{*key}",
            axum::routing::any(move |method: axum::http::Method| {
                let archive = archive.clone();
                async move {
                    match method {
                        axum::http::Method::HEAD => axum::http::StatusCode::OK.into_response(),
                        axum::http::Method::GET => {
                            use axum::body::Body;
                            (
                                [(axum::http::header::CONTENT_TYPE, "application/zstd")],
                                Body::from(archive.as_ref().clone()),
                            )
                                .into_response()
                        }
                        _ => axum::http::StatusCode::METHOD_NOT_ALLOWED.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let opts = (*pool.connect_options()).clone();
        let lock_pool = no_reap_pool(&opts, 2).await;
        let store = RepoStore::for_testing_with_tigris(
            PathBuf::from("/tmp/gitlawb-snapshot-nonmut"),
            lock_pool,
            TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint),
        );

        let owner_did = "did:key:z6MkSnap";
        let (owner_slug, live_path) = store.local_path(owner_did, "snaprepo").unwrap();
        assert!(
            !live_path.exists(),
            "the live path must not exist before the snapshot"
        );

        let snap = store
            .read_snapshot(owner_did, "snaprepo")
            .await
            .expect("snapshot reads the archive");
        let snap_path = snap.path().to_path_buf();
        assert_ne!(
            snap_path, live_path,
            "the snapshot must unpack into a temp dir, not the live path"
        );
        assert!(
            snap_path.starts_with(live_path.parent().unwrap()),
            "the snapshot temp dir must live under the repo parent"
        );
        assert!(
            !live_path.exists(),
            "the live path must remain untouched by a snapshot read"
        );
        assert_eq!(
            std::fs::read_to_string(snap_path.join("HEAD")).unwrap(),
            "ref: refs/heads/main\n",
            "the snapshot must contain the archive's content"
        );
        drop(snap);
        assert!(
            !snap_path.exists(),
            "dropping the snapshot must clean up its temp dir"
        );
        let _ = owner_slug;

        server.abort();
    }

    /// Build a store whose release-side upload lands on `mock` and gives up
    /// after 200ms, so a parked PUT reliably exceeds the bound. One lock-pool
    /// connection on purpose: with a single slot the backend pid is a direct
    /// observable for whether `release` pooled its session or closed it.
    async fn timed_out_upload_store(
        mock: &S3Mock,
        opts: &sqlx::postgres::PgConnectOptions,
        repos_dir: &str,
    ) -> RepoStore {
        RepoStore::new(
            PathBuf::from(repos_dir),
            Some(TigrisClient::for_testing_with_endpoint(
                "test-bucket",
                mock.endpoint(),
            )),
            no_reap_pool(opts, 1).await,
            std::time::Duration::from_millis(200),
        )
    }

    /// Seed the minimum bare-repo shape so the upload has something to archive.
    fn seed_bare_repo(path: &Path) {
        std::fs::create_dir_all(path.join("objects/info")).unwrap();
        std::fs::create_dir_all(path.join("refs/heads")).unwrap();
        std::fs::write(path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    /// A timed-out release upload must still unlock on its OWN session and hand
    /// that session back to the pool. The timeout says nothing about the lock:
    /// holding it cannot fence a late PUT (`release` takes `mut self`, so the
    /// guard drops and `Drop` frees the session the moment `release` returns),
    /// and what actually protects a successor is the conditional PUT.
    ///
    /// Observable: the backend pid. On a one-connection pool a session that was
    /// closed forces the next checkout onto a fresh backend, while a confirmed
    /// unlock returns the same one. So an equal pid is the proof that the unlock
    /// ran, returned true, and the connection was pooled rather than torn down.
    #[sqlx::test]
    async fn timed_out_release_upload_unlocks_on_its_own_session(pool: PgPool) {
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let store = timed_out_upload_store(&mock, &opts, "/tmp/gitlawb-u4-timeout-session").await;

        let mut guard = store
            .acquire_write("did:key:z6MkU4TimeoutSess", "timedrepo")
            .await
            .expect("acquire");
        seed_bare_repo(&guard.local_path);
        let pid_before = guard.backend_pid_for_test().await;

        // Park the upload so it is still in flight when the 200ms bound fires.
        mock.park_next_put();
        let _ = guard.release(true).await;
        assert_eq!(
            mock.put_attempts().len(),
            1,
            "the release upload must have reached the mock and parked, got {:?}",
            mock.put_attempts()
        );

        let pid_after = {
            let mut c = store.lock_pool.acquire().await.unwrap();
            let pid: (i32,) = sqlx::query_as("SELECT pg_backend_pid()")
                .fetch_one(&mut *c)
                .await
                .unwrap();
            pid.0
        };
        assert_eq!(
            pid_before, pid_after,
            "a timed-out upload must not change the unlock decision: the guard must \
             unlock on its own session and return that connection to the pool, so the \
             next checkout lands on the same backend"
        );

        mock.open_gate();
        mock.shutdown();
    }

    /// Admission after the same timed-out upload: a successor must be let in
    /// promptly. Useful as a property, but it is NOT what pins the removal of
    /// the skip-unlock branch, because the lock frees within milliseconds under
    /// either shape (the session closes as soon as `release` returns).
    #[sqlx::test]
    async fn successor_is_admitted_promptly_after_a_timed_out_release(pool: PgPool) {
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let store = timed_out_upload_store(&mock, &opts, "/tmp/gitlawb-u4-timeout-admit")
            .await
            .with_lock_acquire_deadline(std::time::Duration::from_secs(10));

        let guard = store
            .acquire_write("did:key:z6MkU4TimeoutAdmit", "timedrepo")
            .await
            .expect("acquire");
        seed_bare_repo(&guard.local_path);

        mock.park_next_put();
        let _ = guard.release(true).await;

        let started = std::time::Instant::now();
        let successor = store
            .acquire_write("did:key:z6MkU4TimeoutAdmit", "timedrepo")
            .await
            .expect("a successor must be admitted after a timed-out release");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the successor waited {}ms; a timed-out upload must not park the next writer",
            started.elapsed().as_millis()
        );
        let _ = successor.release(false).await;

        mock.open_gate();
        mock.shutdown();
    }

    /// P2: the lock-acquire deadline must bound EVERY await in the retry loop,
    /// not just the sleep between attempts. A pool checkout that would exceed
    /// the deadline must shed as `RepoBusy` rather than wait out the pool's own
    /// acquire timeout past the promised wall-clock cap.
    ///
    /// Observable: hold every lock-pool slot from an independent store, then
    /// acquire with a short deadline. The pool checkout will not complete within
    /// the deadline, so `acquire_write` must refuse as `RepoBusy` once the
    /// deadline fires — not hang for the pool's 5s acquire timeout.
    #[sqlx::test]
    async fn pool_checkout_past_the_deadline_sheds_as_repo_busy(pool: PgPool) {
        let opts = (*pool.connect_options()).clone();

        // Exhaust every slot of the lock pool. The checkouts must come from the
        // pool the store will use, not from independent connections: a separate
        // `PgConnection::connect_with` consumes no slot, so the store's checkout
        // would succeed immediately and the deadline would never be reached.
        const N: u32 = 2;
        let lock_pool = no_reap_pool(&opts, N).await;
        let mut holders = Vec::new();
        for _ in 0..N {
            holders.push(lock_pool.acquire().await.expect("hold a lock-pool slot"));
        }

        // The store shares that exhausted pool (`PgPool` is a handle to one
        // inner pool, so the clone is the same set of slots).
        let store =
            RepoStore::for_testing(PathBuf::from("/tmp/gitlawb-deadline"), lock_pool.clone())
                .with_lock_acquire_deadline(std::time::Duration::from_millis(400));

        // The pool is exhausted, so the checkout cannot complete within the
        // deadline; the deadline must fire and shed as RepoBusy rather than let
        // the pool's own 5s acquire timeout run.
        let started = std::time::Instant::now();
        let err = match store
            .acquire_write("did:key:z6MkDeadline", "deadline-repo")
            .await
        {
            Err(e) => e,
            Ok(guard) => {
                let _ = guard.release(false).await;
                panic!("with the pool exhausted, the deadline must shed, not succeed");
            }
        };
        assert!(
            err.downcast_ref::<RepoBusy>().is_some(),
            "a checkout past the deadline must shed as RepoBusy, got {err:#}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the refusal must come from the deadline, not the pool's own 5s acquire timeout"
        );

        // Release the holders so the test's pool can be torn down cleanly.
        drop(holders);
    }

    // ── conditional-semantics S3 mock (#279) ───────────────────────────────

    /// A captured PUT: the body and the conditional headers as they arrived.
    ///
    /// Capture is deliberately separate from evaluation. When tokio drops an
    /// SDK future the client can tear the TCP connection down and the server
    /// side handler task is cancelled with it, so a parked handler that resumes
    /// on its own is not something a test can depend on. Replaying what arrived
    /// models the real S3 arm we care about (body fully transmitted, commit
    /// decided later) with no timing in it.
    #[derive(Clone, Debug)]
    struct CapturedPut {
        body: Vec<u8>,
        if_match: Option<String>,
        if_none_match: Option<String>,
    }

    /// One PUT as the mock judged it, for tests that assert on attempt counts.
    /// `status` is `None` while a PUT is parked: it arrived and was logged, but
    /// no precondition has been evaluated for it yet.
    #[derive(Clone, Debug, PartialEq)]
    struct PutAttempt {
        if_match: Option<String>,
        if_none_match: Option<String>,
        status: Option<u16>,
    }

    #[derive(Default)]
    struct MockState {
        object: Option<Vec<u8>>,
        etag: Option<String>,
        next_etag: u64,
        puts: Vec<PutAttempt>,
        /// Set by `park_next_put`, consumed by the next arriving PUT.
        park_next_put: bool,
        /// Set by `roll_generation_after_next_heads`, decremented per HEAD.
        roll_after_heads: u32,
        captured: Option<CapturedPut>,
    }

    /// An in-process S3-compatible server with REAL conditional semantics.
    ///
    /// The fence tests downstream are only worth anything if a precondition can
    /// actually fail here, so this helper carries its own semantics tests below.
    struct S3Mock {
        endpoint: String,
        state: Arc<std::sync::Mutex<MockState>>,
        gate: Arc<tokio::sync::Notify>,
        server: tokio::task::JoinHandle<()>,
    }

    /// S3 quotes ETags. Compare unquoted so a value that round-tripped through
    /// the SDK (which surfaces `e_tag()` with the quotes intact) matches what
    /// the mock minted.
    fn unquote_etag(raw: &str) -> &str {
        raw.trim().trim_matches('"')
    }

    /// The conditional evaluation, in one place so a live PUT and a replayed
    /// one cannot drift apart. Returns the status, and on success the fresh
    /// ETag. Preconditions are read against the state passed in, which is
    /// always the state as of the CALL, never as of capture.
    fn evaluate_put(
        st: &mut MockState,
        body: Vec<u8>,
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> (u16, Option<String>) {
        let refuse = |st: &mut MockState| {
            st.puts.push(PutAttempt {
                if_match: if_match.map(str::to_string),
                if_none_match: if_none_match.map(str::to_string),
                status: Some(412),
            });
            (412u16, None)
        };

        if let Some(want) = if_match {
            // An absent object matches nothing, so If-Match cannot pass.
            match st.etag.as_deref() {
                Some(have) if unquote_etag(have) == unquote_etag(want) => {}
                _ => return refuse(st),
            }
        }
        if if_none_match.map(str::trim) == Some("*") && st.object.is_some() {
            return refuse(st);
        }

        // A fresh ETag per successful PUT, from a counter rather than a content
        // hash: two writers can publish byte-identical archives, and an ETag
        // that repeated across them would let a fence pass on a generation it
        // never observed.
        st.next_etag += 1;
        let etag = format!("\"mock-etag-{}\"", st.next_etag);
        st.object = Some(body);
        st.etag = Some(etag.clone());
        st.puts.push(PutAttempt {
            if_match: if_match.map(str::to_string),
            if_none_match: if_none_match.map(str::to_string),
            status: Some(200),
        });
        (200, Some(etag))
    }

    impl S3Mock {
        async fn start() -> Self {
            use axum::response::IntoResponse;

            let state = Arc::new(std::sync::Mutex::new(MockState::default()));
            let gate = Arc::new(tokio::sync::Notify::new());

            let app = axum::Router::new().route(
                "/{*key}",
                axum::routing::any({
                    let state = state.clone();
                    let gate = gate.clone();
                    move |method: axum::http::Method,
                          headers: axum::http::HeaderMap,
                          body: axum::body::Bytes| {
                        let state = state.clone();
                        let gate = gate.clone();
                        async move {
                            let header = |name: &str| {
                                headers
                                    .get(name)
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_string)
                            };
                            match method {
                                axum::http::Method::PUT => {
                                    let if_match = header("if-match");
                                    let if_none_match = header("if-none-match");

                                    // A parked PUT records what arrived and then
                                    // waits. The client will usually be gone by
                                    // the time the gate opens, which is exactly
                                    // why the deterministic arm is the replay.
                                    let parked = {
                                        let mut st = state.lock().unwrap();
                                        if st.park_next_put {
                                            st.park_next_put = false;
                                            st.puts.push(PutAttempt {
                                                if_match: if_match.clone(),
                                                if_none_match: if_none_match.clone(),
                                                status: None,
                                            });
                                            st.captured = Some(CapturedPut {
                                                body: body.to_vec(),
                                                if_match: if_match.clone(),
                                                if_none_match: if_none_match.clone(),
                                            });
                                            true
                                        } else {
                                            false
                                        }
                                    };
                                    if parked {
                                        gate.notified().await;
                                        return axum::http::StatusCode::OK.into_response();
                                    }

                                    let (status, etag) = {
                                        let mut st = state.lock().unwrap();
                                        evaluate_put(
                                            &mut st,
                                            body.to_vec(),
                                            if_match.as_deref(),
                                            if_none_match.as_deref(),
                                        )
                                    };
                                    match etag {
                                        Some(etag) => (
                                            axum::http::StatusCode::OK,
                                            [(axum::http::header::ETAG, etag)],
                                        )
                                            .into_response(),
                                        None => axum::http::StatusCode::from_u16(status)
                                            .unwrap()
                                            .into_response(),
                                    }
                                }
                                axum::http::Method::HEAD | axum::http::Method::GET => {
                                    let mut st = state.lock().unwrap();
                                    let answered = (st.object.clone(), st.etag.clone());
                                    // Fault injection for the two-consecutive-
                                    // losses arm, and the only deterministic way
                                    // to sit BETWEEN a caller's HEAD and the
                                    // conditional PUT it derives from it. The
                                    // gate cannot do this: a parked PUT is
                                    // captured rather than evaluated and answers
                                    // 200, so it can never produce a refusal.
                                    //
                                    // Only the generation moves, not the bytes,
                                    // which is a real state a store reaches (two
                                    // writers can publish byte-identical
                                    // archives) and keeps the stored object a
                                    // valid archive for whoever downloads next.
                                    // `evaluate_put` is untouched, and this logs
                                    // no PutAttempt, so attempt counts still
                                    // count only the caller's own PUTs.
                                    if method == axum::http::Method::HEAD
                                        && st.roll_after_heads > 0
                                        && st.object.is_some()
                                    {
                                        st.roll_after_heads -= 1;
                                        st.next_etag += 1;
                                        st.etag = Some(format!("\"mock-etag-{}\"", st.next_etag));
                                    }
                                    match answered {
                                        (Some(bytes), Some(etag)) => (
                                            axum::http::StatusCode::OK,
                                            [(axum::http::header::ETAG, etag)],
                                            axum::body::Body::from(bytes),
                                        )
                                            .into_response(),
                                        _ => axum::http::StatusCode::NOT_FOUND.into_response(),
                                    }
                                }
                                _ => axum::http::StatusCode::METHOD_NOT_ALLOWED.into_response(),
                            }
                        }
                    }
                }),
            );

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let server = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });

            Self {
                endpoint,
                state,
                gate,
                server,
            }
        }

        fn endpoint(&self) -> &str {
            &self.endpoint
        }

        fn current_etag(&self) -> Option<String> {
            self.state.lock().unwrap().etag.clone()
        }

        fn object(&self) -> Option<Vec<u8>> {
            self.state.lock().unwrap().object.clone()
        }

        fn put_attempts(&self) -> Vec<PutAttempt> {
            self.state.lock().unwrap().puts.clone()
        }

        /// Answer each of the next `n` HEADs from the current state, then
        /// immediately move the object to a new generation. A caller that HEADs
        /// to pick up a precondition and then PUTs on it is therefore fencing
        /// on a generation that is already gone, which is the only way to drive
        /// two consecutive lost preconditions deterministically.
        fn roll_generation_after_next_heads(&self, n: u32) {
            self.state.lock().unwrap().roll_after_heads = n;
        }

        /// Park the next arriving PUT so the caller's transfer bound elapses
        /// with the request in flight (the abandoned-writer arm).
        fn park_next_put(&self) {
            self.state.lock().unwrap().park_next_put = true;
        }

        /// Let a parked handler go. Only the socket-level arm needs this; the
        /// deterministic assertion is `replay_captured`.
        fn open_gate(&self) {
            self.gate.notify_waiters();
        }

        fn captured_put(&self) -> Option<CapturedPut> {
            self.state.lock().unwrap().captured.clone()
        }

        /// Re-run the captured PUT through the SAME evaluation the handler uses,
        /// against the state as it is NOW.
        fn replay_captured(&self) -> u16 {
            let mut st = self.state.lock().unwrap();
            let captured = st.captured.clone().expect("a PUT was captured");
            evaluate_put(
                &mut st,
                captured.body,
                captured.if_match.as_deref(),
                captured.if_none_match.as_deref(),
            )
            .0
        }

        fn shutdown(&self) {
            self.server.abort();
        }
    }

    /// An SDK client aimed at the mock. Built here rather than through
    /// `TigrisClient` because these tests exercise raw conditional PUTs, which
    /// the storage client does not expose.
    fn mock_s3_client(endpoint: &str) -> aws_sdk_s3::Client {
        use aws_sdk_s3::config::{retry::RetryConfig, Credentials, Region};

        let config = aws_sdk_s3::config::Config::builder()
            .endpoint_url(endpoint)
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .region(Region::new("auto"))
            .retry_config(RetryConfig::disabled())
            .behavior_version_latest()
            .build();
        aws_sdk_s3::Client::from_conf(config)
    }

    /// PUT through the SDK, returning either the fresh ETag or the HTTP status
    /// the mock refused with.
    async fn mock_put(
        client: &aws_sdk_s3::Client,
        body: &[u8],
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<String, u16> {
        let mut req = client
            .put_object()
            .bucket("test-bucket")
            .key("repos/v1/owner/repo.tar.zst")
            .body(aws_sdk_s3::primitives::ByteStream::from(body.to_vec()));
        if let Some(v) = if_match {
            req = req.if_match(v);
        }
        if let Some(v) = if_none_match {
            req = req.if_none_match(v);
        }
        match req.send().await {
            Ok(out) => Ok(out
                .e_tag()
                .expect("a successful PUT returns an ETag")
                .to_string()),
            Err(e) => Err(e
                .raw_response()
                .map(|r| r.status().as_u16())
                .unwrap_or_else(|| panic!("expected an HTTP response from the mock, got {e:?}"))),
        }
    }

    /// HEAD through the SDK, reported the way `TigrisClient::exists` reports it:
    /// `Ok(false)` for a not-found, `Ok(true)` for a hit whose ETag is present.
    async fn mock_head(client: &aws_sdk_s3::Client) -> Result<bool, String> {
        match client
            .head_object()
            .bucket("test-bucket")
            .key("repos/v1/owner/repo.tar.zst")
            .send()
            .await
        {
            Ok(out) => {
                out.e_tag().ok_or("a HEAD hit must carry an ETag")?;
                Ok(true)
            }
            Err(e) if e.as_service_error().is_some_and(|e| e.is_not_found()) => Ok(false),
            Err(e) => Err(format!("unexpected HEAD failure: {e}")),
        }
    }

    /// 1. A stale If-Match must be refused, and the refusal must not write.
    #[tokio::test]
    async fn mock_refuses_a_wrong_if_match_and_leaves_the_object_unchanged() {
        let mock = S3Mock::start().await;
        let client = mock_s3_client(mock.endpoint());

        let etag = mock_put(&client, b"first", None, None)
            .await
            .expect("the seeding PUT succeeds");

        let status = mock_put(&client, b"second", Some("\"not-the-current-etag\""), None)
            .await
            .expect_err("a stale If-Match must be refused");
        assert_eq!(status, 412, "a stale If-Match must answer 412");
        assert_eq!(
            mock.object().as_deref(),
            Some(b"first".as_slice()),
            "a refused PUT must leave the stored object unchanged"
        );
        assert_eq!(
            mock.current_etag().as_deref().map(unquote_etag),
            Some(unquote_etag(&etag)),
            "a refused PUT must leave the ETag unchanged"
        );

        mock.shutdown();
    }

    /// 2. The matching If-Match is the write that must go through.
    #[tokio::test]
    async fn mock_accepts_a_matching_if_match_and_rotates_the_etag() {
        let mock = S3Mock::start().await;
        let client = mock_s3_client(mock.endpoint());

        let first = mock_put(&client, b"first", None, None).await.expect("seed");
        let second = mock_put(&client, b"second", Some(&first), None)
            .await
            .expect("a matching If-Match must succeed");

        assert_ne!(
            unquote_etag(&first),
            unquote_etag(&second),
            "a successful conditional PUT must mint a fresh ETag"
        );
        assert_eq!(
            mock.object().as_deref(),
            Some(b"second".as_slice()),
            "the accepted body must be what is stored"
        );
        assert_eq!(
            mock.current_etag().as_deref().map(unquote_etag),
            Some(unquote_etag(&second)),
            "HEAD/GET must report the ETag the PUT returned"
        );

        mock.shutdown();
    }

    /// 3. If-None-Match `*` is the create-only fence, so an existing object
    /// must refuse it.
    #[tokio::test]
    async fn mock_refuses_if_none_match_star_against_an_existing_object() {
        let mock = S3Mock::start().await;
        let client = mock_s3_client(mock.endpoint());

        mock_put(&client, b"first", None, None).await.expect("seed");
        let status = mock_put(&client, b"second", None, Some("*"))
            .await
            .expect_err("create-only against an existing object must be refused");

        assert_eq!(status, 412, "If-None-Match * on an existing object is 412");
        assert_eq!(
            mock.object().as_deref(),
            Some(b"first".as_slice()),
            "the refused create-only PUT must not overwrite"
        );

        mock.shutdown();
    }

    /// 4. The same fence must ADMIT the first writer, or the fresh-repo path
    /// could never publish.
    #[tokio::test]
    async fn mock_accepts_if_none_match_star_against_an_empty_store() {
        let mock = S3Mock::start().await;
        let client = mock_s3_client(mock.endpoint());

        // HEAD both ways, because `exists()` reads a not-found as "fresh repo"
        // and any other status as a hard refusal. A mock that answered 200 on
        // an empty store would send every fresh-repo test down the wrong arm.
        assert!(
            !mock_head(&client).await.expect("HEAD on an empty store"),
            "an absent object must HEAD 404"
        );

        let etag = mock_put(&client, b"first", None, Some("*"))
            .await
            .expect("create-only against an empty store must succeed");
        assert_eq!(mock.object().as_deref(), Some(b"first".as_slice()));
        assert_eq!(
            mock.current_etag().as_deref().map(unquote_etag),
            Some(unquote_etag(&etag))
        );
        assert!(
            mock_head(&client).await.expect("HEAD after the create"),
            "a stored object must HEAD 200 with the ETag the PUT returned"
        );

        mock.shutdown();
    }

    /// 5. Identical bytes must still produce a new ETag. Without this, an
    /// If-Match fence would pass on a generation it never observed.
    #[tokio::test]
    async fn mock_mints_a_distinct_etag_per_successful_put() {
        let mock = S3Mock::start().await;
        let client = mock_s3_client(mock.endpoint());

        let first = mock_put(&client, b"same", None, None).await.expect("first");
        let second = mock_put(&client, b"same", Some(&first), None)
            .await
            .expect("second");

        assert_ne!(
            unquote_etag(&first),
            unquote_etag(&second),
            "successive successful PUTs of identical bytes must still differ in ETag"
        );

        mock.shutdown();
    }

    /// 6. The whole point of capture-and-replay: the commit is judged when it
    /// is replayed, not when the bytes arrived. A capture that was valid on
    /// arrival must lose to a write that landed in between.
    #[tokio::test]
    async fn mock_judges_a_replayed_put_against_the_state_at_replay_time() {
        let mock = S3Mock::start().await;
        let client = mock_s3_client(mock.endpoint());

        let first = mock_put(&client, b"first", None, None).await.expect("seed");

        // Park the abandoned writer's PUT. Its If-Match is valid at ARRIVAL.
        mock.park_next_put();
        let parked = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            mock_put(&client, b"abandoned", Some(&first), None),
        )
        .await;
        assert!(
            parked.is_err(),
            "the parked PUT must still be in flight when the caller's bound elapses"
        );
        let captured = mock
            .captured_put()
            .expect("the parked PUT must be captured at arrival");
        assert_eq!(captured.body, b"abandoned".to_vec());
        assert_eq!(
            captured.if_match.as_deref().map(unquote_etag),
            Some(unquote_etag(&first)),
            "the capture must record the conditional headers as they arrived"
        );
        assert_eq!(captured.if_none_match, None);

        // A successor commits while the capture sits parked.
        let second = mock_put(&client, b"successor", Some(&first), None)
            .await
            .expect("the successor's PUT is the one that lands");

        // Replaying now must be judged against the successor's state.
        assert_eq!(
            mock.replay_captured(),
            412,
            "a replayed PUT must be evaluated against the state at replay time, \
             not the state it was captured against"
        );
        assert_eq!(
            mock.object().as_deref(),
            Some(b"successor".as_slice()),
            "the refused replay must not clobber the successor's object"
        );
        assert_eq!(
            mock.current_etag().as_deref().map(unquote_etag),
            Some(unquote_etag(&second))
        );
        // Seed, parked, successor, replay. The log is what later tests assert
        // attempt counts against, so it is checked here rather than trusted.
        let attempts = mock.put_attempts();
        assert_eq!(
            attempts.len(),
            4,
            "every PUT attempt must be logged, got {attempts:?}"
        );
        assert_eq!(
            attempts.iter().map(|a| a.status).collect::<Vec<_>>(),
            vec![Some(200), None, Some(200), Some(412)],
            "the parked attempt is logged undecided; the replay is the 412"
        );
        assert_eq!(
            attempts[1].if_match.as_deref().map(unquote_etag),
            Some(unquote_etag(&first)),
            "the parked attempt must be logged with the headers it arrived with"
        );

        mock.open_gate();
        mock.shutdown();
    }

    // ── conditional upload through TigrisClient (#279) ─────────────────────

    /// A tiny directory for `upload` to compress. What is inside does not
    /// matter to a precondition test, only that a PUT carrying a body happens.
    fn payload_dir(marker: &str) -> TempDir {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("HEAD"), marker.as_bytes()).unwrap();
        dir
    }

    /// A router that answers every request with one fixed status. This is NOT a
    /// second semantics mock: it exists only to pin how a status the real mock
    /// never produces (409, 404, 500) is classified.
    async fn start_fixed_status_stub(status: u16) -> (String, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new().route(
            "/{*key}",
            axum::routing::any(
                move || async move { axum::http::StatusCode::from_u16(status).unwrap() },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (endpoint, server)
    }

    /// The one place the header itself is asserted: a matching If-Match must
    /// succeed AND must actually have travelled as an If-Match header. The
    /// store-level tests deliberately assert behavior rather than headers, so
    /// if this assertion is not here, nothing pins the wire format.
    #[tokio::test]
    async fn upload_if_match_with_the_current_etag_publishes_and_sends_the_header() {
        let mock = S3Mock::start().await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", mock.endpoint());
        let seeded = mock_put(&mock_s3_client(mock.endpoint()), b"seed", None, None)
            .await
            .expect("seeding PUT");

        let dir = payload_dir("winner");
        client
            .upload(
                "owner",
                "repo",
                dir.path(),
                UploadPrecondition::IfMatch(seeded.clone()),
            )
            .await
            .expect("a matching If-Match must publish");

        let last = mock
            .put_attempts()
            .last()
            .cloned()
            .expect("the upload must reach the mock");
        assert_eq!(
            last.if_match.as_deref().map(unquote_etag),
            Some(unquote_etag(&seeded)),
            "the upload must carry the ETag it was fenced on as If-Match"
        );
        assert_eq!(last.if_none_match, None);
        assert_eq!(last.status, Some(200));

        mock.shutdown();
    }

    #[tokio::test]
    async fn upload_if_match_with_a_stale_etag_is_precondition_lost() {
        let mock = S3Mock::start().await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", mock.endpoint());
        mock_put(&mock_s3_client(mock.endpoint()), b"seed", None, None)
            .await
            .expect("seeding PUT");

        let dir = payload_dir("loser");
        let err = client
            .upload(
                "owner",
                "repo",
                dir.path(),
                UploadPrecondition::IfMatch("\"stale\"".to_string()),
            )
            .await
            .expect_err("a stale If-Match must be refused");
        assert!(
            matches!(err, UploadError::PreconditionLost { status: 412 }),
            "a stale If-Match must classify as a lost precondition, got {err:?}"
        );
        assert_eq!(
            mock.object().as_deref(),
            Some(b"seed".as_slice()),
            "the refused upload must not have written"
        );

        mock.shutdown();
    }

    #[tokio::test]
    async fn upload_if_absent_into_an_empty_store_publishes() {
        let mock = S3Mock::start().await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", mock.endpoint());

        let dir = payload_dir("first");
        client
            .upload("owner", "repo", dir.path(), UploadPrecondition::IfAbsent)
            .await
            .expect("create-only into an empty store must publish");

        let last = mock.put_attempts().last().cloned().expect("one attempt");
        assert_eq!(last.if_none_match.as_deref(), Some("*"));
        assert_eq!(last.if_match, None);
        assert!(mock.object().is_some(), "the create must have stored bytes");

        mock.shutdown();
    }

    #[tokio::test]
    async fn upload_if_absent_over_an_existing_object_is_precondition_lost() {
        let mock = S3Mock::start().await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", mock.endpoint());
        mock_put(&mock_s3_client(mock.endpoint()), b"seed", None, None)
            .await
            .expect("seeding PUT");

        let dir = payload_dir("late-backfill");
        let err = client
            .upload("owner", "repo", dir.path(), UploadPrecondition::IfAbsent)
            .await
            .expect_err("create-only over an existing object must be refused");
        assert!(
            matches!(err, UploadError::PreconditionLost { status: 412 }),
            "got {err:?}"
        );
        assert_eq!(
            mock.object().as_deref(),
            Some(b"seed".as_slice()),
            "a refused backfill must not clobber what is already published"
        );

        mock.shutdown();
    }

    #[tokio::test]
    async fn upload_unconditional_overwrites_regardless() {
        let mock = S3Mock::start().await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", mock.endpoint());
        mock_put(&mock_s3_client(mock.endpoint()), b"seed", None, None)
            .await
            .expect("seeding PUT");

        let dir = payload_dir("overwrite");
        client
            .upload(
                "owner",
                "repo",
                dir.path(),
                UploadPrecondition::Unconditional,
            )
            .await
            .expect("an unconditional upload must succeed regardless of state");

        let last = mock.put_attempts().last().cloned().expect("one attempt");
        assert_eq!(last.if_match, None, "no precondition may be sent");
        assert_eq!(last.if_none_match, None);
        assert_ne!(
            mock.object().as_deref(),
            Some(b"seed".as_slice()),
            "the unconditional upload must have replaced the seed"
        );

        mock.shutdown();
    }

    /// Tigris answers a create-only conflict with 409 rather than 412, so that
    /// status has to classify as a lost precondition too, but ONLY when the
    /// request was create-only.
    #[tokio::test]
    async fn upload_classifies_409_under_if_absent_as_precondition_lost() {
        let (endpoint, server) = start_fixed_status_stub(409).await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint);
        let dir = payload_dir("conflict");

        let err = client
            .upload("owner", "repo", dir.path(), UploadPrecondition::IfAbsent)
            .await
            .expect_err("409 must be an error");
        assert!(
            matches!(err, UploadError::PreconditionLost { status: 409 }),
            "409 under IfAbsent is a lost precondition, got {err:?}"
        );

        server.abort();
    }

    /// MUST-NOT. A 404 is permanent (no such bucket, a misrouted endpoint), so
    /// reporting it as a lost precondition would tell a client to retry
    /// something that can never succeed. `delete` has no callers, so a racing
    /// delete cannot produce this.
    #[tokio::test]
    async fn upload_classifies_404_as_other_under_either_precondition() {
        let (endpoint, server) = start_fixed_status_stub(404).await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint);

        for precondition in [
            UploadPrecondition::IfAbsent,
            UploadPrecondition::IfMatch("\"whatever\"".to_string()),
        ] {
            let dir = payload_dir("gone");
            let err = client
                .upload("owner", "repo", dir.path(), precondition.clone())
                .await
                .expect_err("404 must be an error");
            assert!(
                matches!(err, UploadError::Other(_)),
                "404 under {precondition:?} must NOT be a lost precondition, got {err:?}"
            );
        }

        server.abort();
    }

    #[tokio::test]
    async fn upload_classifies_500_as_other() {
        let (endpoint, server) = start_fixed_status_stub(500).await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint);

        for precondition in [
            UploadPrecondition::IfAbsent,
            UploadPrecondition::IfMatch("\"whatever\"".to_string()),
            UploadPrecondition::Unconditional,
        ] {
            let dir = payload_dir("boom");
            let err = client
                .upload("owner", "repo", dir.path(), precondition.clone())
                .await
                .expect_err("500 must be an error");
            assert!(
                matches!(err, UploadError::Other(_)),
                "500 under {precondition:?} must be Other, got {err:?}"
            );
        }

        server.abort();
    }

    #[tokio::test]
    async fn head_etag_reports_the_current_etag_and_none_when_absent() {
        let mock = S3Mock::start().await;
        let client = TigrisClient::for_testing_with_endpoint("test-bucket", mock.endpoint());

        assert_eq!(
            client.head_etag("owner", "repo").await.expect("HEAD"),
            None,
            "an absent object must read as None, not an error"
        );

        let seeded = mock_put(&mock_s3_client(mock.endpoint()), b"seed", None, None)
            .await
            .expect("seeding PUT");
        let got = client
            .head_etag("owner", "repo")
            .await
            .expect("HEAD")
            .expect("a present object must report an ETag");
        assert_eq!(
            unquote_etag(&got),
            unquote_etag(&seeded),
            "head_etag must report the ETag the last successful PUT minted"
        );

        mock.shutdown();
    }

    // ── the fenced release publish (#279) ──────────────────────────────────

    /// A store whose acquire-side refresh and release-side publish both land on
    /// `mock`. The transfer bound is generous on purpose: these tests are about
    /// the fence arms, and a short bound would let the timeout arm answer first.
    async fn fenced_store(
        mock: &S3Mock,
        opts: &sqlx::postgres::PgConnectOptions,
        repos_dir: &Path,
    ) -> RepoStore {
        RepoStore::new(
            repos_dir.to_path_buf(),
            Some(TigrisClient::for_testing_with_endpoint(
                "test-bucket",
                mock.endpoint(),
            )),
            no_reap_pool(opts, 2).await,
            std::time::Duration::from_secs(30),
        )
    }

    /// A client aimed at the same key the store under test publishes to, so a
    /// test can seed the archive or land an interfering publish of its own.
    fn mock_tigris(mock: &S3Mock) -> TigrisClient {
        TigrisClient::for_testing_with_endpoint("test-bucket", mock.endpoint())
    }

    /// The slug `local_path` derives from a DID, needed because a test seeds
    /// and reads the archive key directly.
    fn owner_slug_of(owner_did: &str) -> String {
        owner_did.replace([':', '/'], "_")
    }

    /// A bare-repo-shaped directory carrying `marker`, so a test can tell whose
    /// tree is stored without comparing compressed bytes.
    fn marked_repo(path: &Path, marker: &str) {
        seed_bare_repo(path);
        std::fs::write(path.join("MARKER"), marker).unwrap();
    }

    /// The marker inside whatever archive is currently stored under the key.
    async fn stored_marker(mock: &S3Mock, owner_slug: &str, repo_name: &str) -> String {
        let out = TempDir::new().unwrap();
        let into = out.path().join("stored.git");
        mock_tigris(mock)
            .download(owner_slug, repo_name, &into)
            .await
            .expect("the stored archive must be readable");
        std::fs::read_to_string(into.join("MARKER")).expect("the stored archive must be marked")
    }

    /// A process-wide sink for warn-level tracing output, installed once.
    ///
    /// Global rather than per test on purpose. `tracing`'s scoped default is
    /// thread-local, and these events fire inside futures the test runtime may
    /// move between threads, so a scoped subscriber would drop them silently
    /// and every log assertion would go vacuous. Tests instead give their repo
    /// a unique name and read back only the lines carrying it.
    fn log_sink() -> Arc<std::sync::Mutex<Vec<u8>>> {
        static LOG_SINK: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<u8>>>> =
            std::sync::OnceLock::new();
        LOG_SINK
            .get_or_init(|| {
                let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
                let writer = sink.clone();
                // `try_init`, because another test may already have installed a
                // subscriber; the assertions below fail loudly if nothing was
                // captured, so a silent no-op here cannot pass for a green run.
                let _ = tracing_subscriber::fmt()
                    .with_writer(move || SinkWriter(writer.clone()))
                    .with_ansi(false)
                    .with_max_level(tracing::Level::WARN)
                    .try_init();
                sink
            })
            .clone()
    }

    struct SinkWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SinkWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Captured warn lines naming `repo_name`, joined back into one string.
    fn warn_lines_for(repo_name: &str) -> String {
        let raw = log_sink().lock().unwrap().clone();
        String::from_utf8_lossy(&raw)
            .lines()
            .filter(|l| l.contains(repo_name))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// An uncontended write publishes, and what lands is the writer's tree.
    ///
    /// This is the must-not-spuriously-fence negative, so it asserts ONLY the
    /// outcome and the stored bytes, never which precondition header travelled.
    /// Forcing the carried precondition back to `Unconditional` has to leave it
    /// green, or it is a second copy of the fix rather than a guard against it;
    /// the header itself is pinned by
    /// `upload_if_match_with_the_current_etag_publishes_and_sends_the_header`.
    #[sqlx::test]
    async fn uncontended_write_publishes_the_writers_tree(pool: PgPool) {
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let store = fenced_store(&mock, &opts, repos.path()).await;
        let owner = "did:key:z6MkFenceUncontended";
        let slug = owner_slug_of(owner);

        // Seed an archive so the acquire takes the download arm, which is the
        // ordinary case: the repo already exists in object storage.
        let seed = TempDir::new().unwrap();
        marked_repo(seed.path(), "seed");
        mock_tigris(&mock)
            .upload(
                &slug,
                "repo",
                seed.path(),
                UploadPrecondition::Unconditional,
            )
            .await
            .expect("seeding the archive");

        let guard = store.acquire_write(owner, "repo").await.expect("acquire");
        std::fs::write(guard.local_path.join("MARKER"), "writer").unwrap();
        guard
            .release(true)
            .await
            .into_result()
            .expect("an uncontended write must publish");

        assert_eq!(
            stored_marker(&mock, &slug, "repo").await,
            "writer",
            "an uncontended write must publish the writer's tree"
        );

        mock.shutdown();
    }

    /// The first write to an empty bucket, the absent-at-acquire path. Nothing
    /// is stored when the lock is taken, so the publish is the one that creates
    /// the key, and the writer's tree is what lands.
    #[sqlx::test]
    async fn first_write_to_an_empty_bucket_publishes_the_writers_tree(pool: PgPool) {
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let store = fenced_store(&mock, &opts, repos.path()).await;
        let owner = "did:key:z6MkFenceFirstWrite";
        let slug = owner_slug_of(owner);

        let guard = store.acquire_write(owner, "repo").await.expect("acquire");
        marked_repo(&guard.local_path, "writer");
        guard
            .release(true)
            .await
            .into_result()
            .expect("the first write into an empty key must publish");

        assert_eq!(
            stored_marker(&mock, &slug, "repo").await,
            "writer",
            "the first write must publish the writer's tree into the empty key"
        );

        mock.shutdown();
    }

    /// THE INIT RACE, and the reason the fence needs a supersede-retry at all.
    ///
    /// `init` uploads a freshly created EMPTY repo create-only in the
    /// background. A user who pushes immediately after creating a repo takes
    /// the lock, sees nothing stored, and is fenced create-only too; the
    /// background upload then wins the empty key and the push's publish loses.
    /// A fence with no retry would turn every such push into a refusal.
    ///
    /// The retry is sound because the loss is DEFINITE and this writer still
    /// holds the lock: what landed underneath was published without it, so this
    /// tree supersedes it.
    #[sqlx::test]
    async fn a_lost_fence_republishes_once_and_the_writers_tree_wins(pool: PgPool) {
        let _sink = log_sink();
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let store = fenced_store(&mock, &opts, repos.path()).await;
        let owner = "did:key:z6MkFenceInitRace";
        let repo = "fence-init-race-repo";
        let slug = owner_slug_of(owner);

        // Nothing is stored yet, so the acquire records the absent case.
        let guard = store.acquire_write(owner, repo).await.expect("acquire");
        marked_repo(&guard.local_path, "writer");

        // init's create-only background upload lands after that observation.
        let empty = TempDir::new().unwrap();
        marked_repo(empty.path(), "empty-init");
        mock_tigris(&mock)
            .upload(&slug, repo, empty.path(), UploadPrecondition::IfAbsent)
            .await
            .expect("the background init upload wins the empty key");
        let before = mock.put_attempts().len();
        assert_eq!(before, 1, "only the init upload has run so far");

        guard
            .release(true)
            .await
            .into_result()
            .expect("the supersede-retry must leave the release reporting success");

        let attempts = mock.put_attempts();
        assert_eq!(
            attempts.len(),
            before + 2,
            "the release must attempt exactly twice, the fenced publish and one \
             supersede-retry, got {attempts:?}"
        );
        assert_eq!(
            attempts[before].status,
            Some(412),
            "the create-only publish must lose to what landed underneath, got {attempts:?}"
        );
        assert_eq!(
            attempts[before + 1].status,
            Some(200),
            "the supersede-retry must publish, got {attempts:?}"
        );
        assert_eq!(
            stored_marker(&mock, &slug, repo).await,
            "writer",
            "the lock holder's tree must be what is stored after the retry"
        );
        assert!(
            warn_lines_for(repo).contains("republishing"),
            "the fired fence must be visible in the log, got {:?}",
            warn_lines_for(repo)
        );

        mock.shutdown();
    }

    /// Two consecutive definite losses: the retry is bounded at ONE, so the
    /// release refuses instead of escalating, and the refusal reaches the
    /// caller rather than being logged and swallowed.
    ///
    /// The second loss is arranged by replacing the object right after the
    /// re-HEAD answers, so the retry fences on a generation that is already
    /// gone. That is fault injection at the only point where it can be
    /// deterministic; the mock's PUT gate cannot do it, because a parked PUT is
    /// captured rather than evaluated and answers 200.
    #[sqlx::test]
    async fn a_second_consecutive_loss_refuses_and_never_attempts_a_third(pool: PgPool) {
        let _sink = log_sink();
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let store = fenced_store(&mock, &opts, repos.path()).await;
        let owner = "did:key:z6MkFenceDoubleLoss";
        let repo = "fence-double-loss-repo";
        let slug = owner_slug_of(owner);

        let seed = TempDir::new().unwrap();
        marked_repo(seed.path(), "seed");
        mock_tigris(&mock)
            .upload(&slug, repo, seed.path(), UploadPrecondition::Unconditional)
            .await
            .expect("seeding the archive");

        let guard = store.acquire_write(owner, repo).await.expect("acquire");
        std::fs::write(guard.local_path.join("MARKER"), "writer").unwrap();

        // An unlocked publish lands after the acquire, so the carried fence is
        // already stale before the release runs.
        let orphan = TempDir::new().unwrap();
        marked_repo(orphan.path(), "orphan");
        mock_tigris(&mock)
            .upload(
                &slug,
                repo,
                orphan.path(),
                UploadPrecondition::Unconditional,
            )
            .await
            .expect("an unconditional publish always lands");
        let before = mock.put_attempts().len();
        assert_eq!(before, 2, "the seed and the orphan have run so far");

        // ... and the generation the retry HEADs for moves on before its PUT
        // can use it, so the second attempt loses too.
        mock.roll_generation_after_next_heads(1);
        let outcome = guard.release(true).await;

        assert!(
            matches!(outcome, ReleaseOutcome::Fenced),
            "a publish refused twice must be reported to the caller, got {outcome:?}"
        );
        let attempts = mock.put_attempts();
        assert_eq!(
            attempts.len(),
            before + 2,
            "a release must attempt at most TWO publishes, never a third, got {attempts:?}"
        );
        assert_eq!(
            (attempts[before].status, attempts[before + 1].status),
            (Some(412), Some(412)),
            "both attempts must have been refused by the store, got {attempts:?}"
        );
        let logged = warn_lines_for(repo);
        assert!(
            logged.contains("republishing"),
            "the first loss must log the retry, got {logged:?}"
        );
        assert!(
            logged.contains("refusing the write"),
            "the second loss must log its own distinct refusal, got {logged:?}"
        );

        mock.shutdown();
    }

    /// Driven from the client side at a publishing site: a refused publish must
    /// render as the retryable 503 and never as a success body.
    ///
    /// `create_issue` bumps the author's trust score AFTER releasing the guard,
    /// so an unchanged score is what proves the short-circuit actually precedes
    /// the post-release effects rather than merely being written above them. A
    /// `?` placed after the bump would leave the status assertion green and
    /// this one red.
    #[sqlx::test]
    async fn a_fenced_publish_renders_as_503_and_skips_the_post_release_effects(pool: PgPool) {
        use tower::ServiceExt;

        let _sink = log_sink();
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let owner = "did:key:z6MkFenceHandlerAuthor";
        let repo = "fence-handler-repo";
        let slug = owner_slug_of(owner);

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.repo_store = fenced_store(&mock, &opts, repos.path()).await;
        let now = chrono::Utc::now();
        state
            .db
            .create_repo(&crate::db::RepoRecord {
                id: uuid::Uuid::new_v4().to_string(),
                name: repo.to_string(),
                owner_did: owner.to_string(),
                description: None,
                is_public: true,
                default_branch: "main".to_string(),
                created_at: now,
                updated_at: now,
                disk_path: format!("/tmp/{repo}"),
                forked_from: None,
                machine_id: None,
            })
            .await
            .expect("seed repo");
        // The trust bump only moves a row that already exists, so the author has
        // to be registered or the observable would be vacuously unchanged.
        state
            .db
            .register_agent(owner, &[])
            .await
            .expect("register the author");
        let score_before = state.db.get_trust_score(owner).await.expect("trust score");

        // A real bare repo, on disk and published, so the acquire refresh has a
        // valid archive to download and the handler's git work succeeds.
        let local = repos.path().join(&slug).join(format!("{repo}.git"));
        store::init_bare(&local).expect("init the bare repo");
        mock_tigris(&mock)
            .upload(&slug, repo, &local, UploadPrecondition::Unconditional)
            .await
            .expect("publish the archive");

        // Move the generation on after BOTH of the handler's HEADs: the one in
        // `acquire_write`, so the fence it carries is stale by the time it
        // publishes, and the one the supersede-retry does, so the retry loses
        // too and the release refuses.
        mock.roll_generation_after_next_heads(2);

        let router = axum::Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/issues",
                axum::routing::post(crate::api::issues::create_issue),
            )
            .with_state(state.clone());
        let resp = router
            .oneshot(crate::test_support::signed_request_as(
                owner,
                axum::http::Method::POST,
                &format!("/api/v1/repos/{owner}/{repo}/issues"),
                axum::body::Body::from(r#"{"title":"t","body":"b"}"#),
            ))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "a publish the store refused must be a retryable 503, not a success"
        );
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("repo_write_fenced"),
            "the 503 must carry its own code so a client can tell it from contention, got {body}"
        );
        assert!(
            !body.contains(repo) && !body.contains(&slug),
            "the body must be fixed and must not name the repo or owner, got {body}"
        );
        assert_eq!(
            state.db.get_trust_score(owner).await.expect("trust score"),
            score_before,
            "the post-release trust bump must not run when the publish was refused"
        );

        mock.shutdown();
    }

    // ── the abandoned writer's late PUT (#279) ─────────────────────────────

    /// A store whose under-lock transfer bound is short, so a parked PUT
    /// actually runs the release past its budget instead of making the test sit
    /// out `fenced_store`'s 30s. The acquire-side refresh shares the bound,
    /// which is fine here: it moves a few KiB against an in-process mock.
    async fn fenced_store_with_bound(
        mock: &S3Mock,
        opts: &sqlx::postgres::PgConnectOptions,
        repos_dir: &Path,
        bound: std::time::Duration,
    ) -> RepoStore {
        RepoStore::new(
            repos_dir.to_path_buf(),
            Some(TigrisClient::for_testing_with_endpoint(
                "test-bucket",
                mock.endpoint(),
            )),
            no_reap_pool(opts, 2).await,
            bound,
        )
    }

    /// The statuses of every logged PUT attempt, which is what the
    /// abandoned-writer tests assert their attempt counts on.
    fn attempt_statuses(mock: &S3Mock) -> Vec<Option<u16>> {
        mock.put_attempts().iter().map(|a| a.status).collect()
    }

    /// THE HEADLINE ARM. An abandoned writer's PUT that lands after a successor
    /// has published must be refused by the store, and the successor's archive
    /// must survive it.
    ///
    /// This is the whole point of the change. Dropping the future of an
    /// in-flight PUT does not cancel the request the server is already
    /// processing, so the advisory lock cannot fence it: A's release returns,
    /// the lock frees, B acquires and publishes, and A's bytes are still on
    /// their way to a store that has already moved on. Only the conditional PUT
    /// decides that race, and it decides it at COMMIT time, not at arrival.
    ///
    /// The mock models that by capturing A's PUT when it arrives and evaluating
    /// it on replay, against the state as of the replay. That is deliberately
    /// not a timing test: a parked handler whose client has gone away is
    /// cancelled with the connection, so a test that waited for it to resume on
    /// its own would be waiting on nothing.
    #[sqlx::test]
    async fn an_abandoned_writers_late_put_loses_to_the_successor(pool: PgPool) {
        let _sink = log_sink();
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let bound = std::time::Duration::from_millis(750);
        let store = fenced_store_with_bound(&mock, &opts, repos.path(), bound).await;
        let owner = "did:key:z6MkFenceLatePut";
        let repo = "fence-late-put-repo";
        let slug = owner_slug_of(owner);

        // Seed the key, so A's acquire observes a generation and carries
        // If-Match on it. This is the ordinary case: the repo already exists.
        let seed = TempDir::new().unwrap();
        marked_repo(seed.path(), "seed");
        mock_tigris(&mock)
            .upload(&slug, repo, seed.path(), UploadPrecondition::Unconditional)
            .await
            .expect("seeding the archive");
        let seeded = mock.current_etag().expect("the seed minted an ETag");

        // Writer A takes the lock, writes its tree, and has its publish parked
        // past the transfer bound.
        let guard_a = store.acquire_write(owner, repo).await.expect("A acquires");
        std::fs::write(guard_a.local_path.join("MARKER"), "writer-a").unwrap();
        mock.park_next_put();
        let started = std::time::Instant::now();
        let outcome_a = guard_a.release(true).await;
        assert!(
            started.elapsed() >= bound,
            "A's release must have run out its transfer bound with the PUT in flight"
        );
        // A timeout is UNKNOWABLE rather than failed, so the release reports an
        // ordinary success and the lock frees. That is exactly why the fence has
        // to live in the store: nothing here knows A's bytes are still coming.
        assert!(
            matches!(outcome_a, ReleaseOutcome::Released),
            "an abandoned publish reports a plain release, got {outcome_a:?}"
        );

        assert!(
            mock.captured_put().is_some(),
            "A's PUT must have arrived and been captured before the bound elapsed"
        );

        // Writer B acquires the freed lock and publishes for real.
        let b_started = std::time::Instant::now();
        let guard_b = store
            .acquire_write(owner, repo)
            .await
            .expect("B must acquire once A's release frees the lock");
        assert!(
            b_started.elapsed() < std::time::Duration::from_secs(5),
            "B's acquire must be prompt, not blocked behind A's abandoned transfer"
        );
        std::fs::write(guard_b.local_path.join("MARKER"), "writer-b").unwrap();
        guard_b
            .release(true)
            .await
            .into_result()
            .expect("B's publish is the one that must land");
        let after_b = mock.current_etag().expect("B's publish minted an ETag");
        assert_ne!(
            unquote_etag(&after_b),
            unquote_etag(&seeded),
            "B's publish must have moved the generation on"
        );

        // NOW A's bytes reach the store's commit point.
        assert_eq!(
            mock.replay_captured(),
            412,
            "A's late PUT must be refused: the generation it fenced on is gone"
        );
        assert_eq!(
            stored_marker(&mock, &slug, repo).await,
            "writer-b",
            "the successor's archive must survive the abandoned writer's late PUT"
        );
        assert_eq!(
            mock.current_etag().as_deref().map(unquote_etag),
            Some(unquote_etag(&after_b)),
            "a refused PUT must not rotate the generation either"
        );

        // Seed, A's parked PUT, B's publish, the deliberate replay. A never
        // attempted a second PUT of its own: the timeout arm takes no
        // compensating action precisely because the outcome is unknowable.
        assert_eq!(
            attempt_statuses(&mock),
            vec![Some(200), None, Some(200), Some(412)],
            "got {:?}",
            mock.put_attempts()
        );

        // The header detail comes LAST on purpose. Asserting it up front would
        // make a lost fence red here, on a wire-format check, rather than on the
        // outcome above, and the outcome is what this test is for.
        let captured = mock.captured_put().expect("A's PUT was captured");
        assert_eq!(
            captured.if_match.as_deref().map(unquote_etag),
            Some(unquote_etag(&seeded)),
            "A's in-flight PUT must carry the generation it observed under the lock"
        );
        assert_eq!(captured.if_none_match, None);

        mock.open_gate();
        mock.shutdown();
    }

    /// The create-only arm of the same race, and the one whose real-world
    /// failure mode is SILENT: an ignored If-None-Match just returns 200, so a
    /// publish that should have been fenced lands with no error anywhere.
    #[sqlx::test]
    async fn an_abandoned_writers_late_create_only_put_loses_to_the_successor(pool: PgPool) {
        let _sink = log_sink();
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let bound = std::time::Duration::from_millis(750);
        let store = fenced_store_with_bound(&mock, &opts, repos.path(), bound).await;
        let owner = "did:key:z6MkFenceLateCreate";
        let repo = "fence-late-create-repo";
        let slug = owner_slug_of(owner);

        // Nothing stored, so A's acquire records the absent case and is fenced
        // create-only.
        let guard_a = store.acquire_write(owner, repo).await.expect("A acquires");
        marked_repo(&guard_a.local_path, "writer-a");
        mock.park_next_put();
        let outcome_a = guard_a.release(true).await;
        assert!(
            matches!(outcome_a, ReleaseOutcome::Released),
            "an abandoned publish reports a plain release, got {outcome_a:?}"
        );

        assert!(
            mock.captured_put().is_some(),
            "A's PUT must have arrived and been captured before the bound elapsed"
        );

        // B wins the empty key.
        let guard_b = store
            .acquire_write(owner, repo)
            .await
            .expect("B must acquire once A's release frees the lock");
        std::fs::write(guard_b.local_path.join("MARKER"), "writer-b").unwrap();
        guard_b
            .release(true)
            .await
            .into_result()
            .expect("B's create must land");

        assert_eq!(
            mock.replay_captured(),
            412,
            "A's late create-only PUT must be refused now that the key exists"
        );
        assert_eq!(
            stored_marker(&mock, &slug, repo).await,
            "writer-b",
            "the successor's archive must survive the abandoned create-only PUT"
        );
        assert_eq!(
            attempt_statuses(&mock),
            vec![None, Some(200), Some(412)],
            "got {:?}",
            mock.put_attempts()
        );

        // Last, for the same reason as the If-Match arm: the outcome is the
        // claim, the header is the detail.
        let captured = mock.captured_put().expect("A's PUT was captured");
        assert_eq!(
            captured.if_none_match.as_deref(),
            Some("*"),
            "A's in-flight PUT must carry the create-only fence it observed"
        );
        assert_eq!(captured.if_match, None);

        mock.open_gate();
        mock.shutdown();
    }

    /// THE CONTROL, and it is what makes the two arms above attributable.
    ///
    /// Same abandonment, same replay, but no successor publishes in between, so
    /// the generation A fenced on is still current when its bytes commit and
    /// the PUT must LAND. Without this, a green headline test would prove only
    /// that replays are rejected, not that STALENESS is what rejects them.
    ///
    /// It must therefore stay green when the carried precondition is forced
    /// back to `Unconditional`: it asserts an outcome the fence does not
    /// change, which is the whole reason it can attribute the others' red.
    #[sqlx::test]
    async fn an_abandoned_put_still_on_the_current_generation_lands(pool: PgPool) {
        let _sink = log_sink();
        let mock = S3Mock::start().await;
        let opts = (*pool.connect_options()).clone();
        let repos = TempDir::new().unwrap();
        let bound = std::time::Duration::from_millis(750);
        let store = fenced_store_with_bound(&mock, &opts, repos.path(), bound).await;
        let owner = "did:key:z6MkFenceControl";
        let repo = "fence-control-repo";
        let slug = owner_slug_of(owner);

        let seed = TempDir::new().unwrap();
        marked_repo(seed.path(), "seed");
        mock_tigris(&mock)
            .upload(&slug, repo, seed.path(), UploadPrecondition::Unconditional)
            .await
            .expect("seeding the archive");

        let guard_a = store.acquire_write(owner, repo).await.expect("A acquires");
        std::fs::write(guard_a.local_path.join("MARKER"), "writer-a").unwrap();
        mock.park_next_put();
        let outcome_a = guard_a.release(true).await;
        assert!(
            matches!(outcome_a, ReleaseOutcome::Released),
            "an abandoned publish reports a plain release, got {outcome_a:?}"
        );

        assert_eq!(
            mock.replay_captured(),
            200,
            "with nothing published in between, the abandoned PUT is still current \
             and must be accepted"
        );
        assert_eq!(
            stored_marker(&mock, &slug, repo).await,
            "writer-a",
            "the accepted late PUT must be what is stored"
        );
        assert_eq!(
            attempt_statuses(&mock),
            vec![Some(200), None, Some(200)],
            "got {:?}",
            mock.put_attempts()
        );

        mock.open_gate();
        mock.shutdown();
    }
}
