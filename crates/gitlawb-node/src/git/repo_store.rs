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
use sqlx::PgPool;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::store;
use super::tigris::TigrisClient;

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
                        return Err(e).context("downloading repo from tigris (fresh)");
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

    /// Take a write lock (Postgres advisory lock), ensure repo is local, return guard.
    /// The lock prevents concurrent writes to the same repo across machines.
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
            let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
                break;
            };
            if left.is_zero() {
                break;
            }
            let conn = match self.lock_pool.acquire().await {
                Ok(c) => c,
                Err(e) => {
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
            };
            let mut probe = LockProbe::new(conn);
            if probe.try_lock(lock_key).await? {
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
        let guard = RepoWriteGuard {
            owner_slug: owner_slug.clone(),
            repo_name: repo_name.to_string(),
            local_path: local_path.clone(),
            lock_key,
            conn: Some(lock_conn),
            tigris: self.tigris.clone(),
            lock_held_transfer_timeout: self.lock_held_transfer_timeout,
        };

        // Always download the latest from Tigris before writing.
        // Local disk may be stale if another machine pushed since our last access.
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
                    match tigris.exists(&owner_slug, repo_name).await {
                        Ok(true) => {
                            debug!(repo = %repo_name, "write acquire: downloading latest from tigris");
                            tigris
                                .download(&owner_slug, repo_name, &local_path)
                                .await
                                .map_err(RefreshFailure::Download)
                        }
                        Ok(false) => Ok(()),
                        Err(e) => Err(RefreshFailure::Unknown(e)),
                    }
                },
            )
            .await;

            match refreshed {
                Some(Ok(())) => {}
                Some(Err(RefreshFailure::Download(e))) => {
                    // The archive is present but unreadable: a corrupt or partial
                    // upload, or a transient GET failure. We KNOW the fetch failed,
                    // so falling back to a valid local copy is sound and
                    // release(success) re-uploads a good archive. Only hard-fail
                    // when there is no local copy to fall back to.
                    if local_path.exists() {
                        warn!(repo = %repo_name, err = %e,
                            "write acquire: tigris refresh failed — falling back to local copy");
                    } else {
                        return Err(e).context("downloading repo from tigris for write");
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

    /// Upload to Tigris (only when the write succeeded) and release the advisory
    /// lock. Pass `success = false` when the write operation failed — uploading a
    /// half-applied or otherwise inconsistent repo would propagate corruption to
    /// Tigris (and to every node that later downloads it). The lock is always
    /// released regardless, to avoid stale locks blocking future writes.
    pub async fn release(mut self, success: bool) {
        // Upload to Tigris only on success.
        if success {
            if let Some(ref tigris) = self.tigris {
                // Bounded for the same reason as the acquire-side download: this
                // runs with the lock held and a lock-pool slot pinned.
                match bounded_transfer(
                    "release-upload",
                    &self.repo_name,
                    self.lock_held_transfer_timeout,
                    tigris.upload(&self.owner_slug, &self.repo_name, &self.local_path),
                )
                .await
                {
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        warn!(repo = %self.repo_name, err = %e, "failed to upload repo to tigris after write");
                    }
                    None => {
                        // Timed out is UNKNOWABLE, not failed: the PUT may well
                        // have landed, so there is deliberately no compensating
                        // action. The lock releases either way, so the repo is not
                        // wedged behind a stalled transfer. The tradeoff is a narrow
                        // last-writer-wins window if the slow PUT lands after
                        // another writer takes the lock.
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
    Download(anyhow::Error),
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
        let store = write_store(&pool, &opts).await;

        let _first = store
            .acquire_write("did:key:z6MkU3Excl", "same-repo")
            .await
            .expect("first writer acquires");

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            store.acquire_write("did:key:z6MkU3Excl", "same-repo"),
        )
        .await;

        assert!(
            second.is_err(),
            "second writer must NOT be admitted while the first holds the guard \
             (it should still be retrying when the deadline hits)"
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
        guard.release(true).await;

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
            guard.release(true).await;
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
        };
        guard.release(true).await;

        // Give the spawned close a moment, then see which backend we land on.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
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
            g.release(true).await;
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
        unrelated.release(true).await;

        spinner.abort();
        held.release(true).await;
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
                second.release(false).await;
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

        held.release(true).await;
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
                guard.release(false).await;
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
}
