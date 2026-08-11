//! IPFS pinning integration for gitlawb-node.
//!
//! After a git push lands, each new git object is pinned to a local Kubo node
//! via its HTTP API (`/api/v0/add`). Objects already recorded in the
//! `pinned_cids` DB table are skipped to avoid duplicate work.
//!
//! If `ipfs_api` is empty the functions are no-ops, so the node works fine
//! without a local IPFS daemon.

use anyhow::Result;
use gitlawb_core::cid::Cid;
use std::time::{Duration, Instant};

/// Attempts (including the first) for a transient DB-record retry.
const PIN_RECORD_ATTEMPTS: u32 = 3;
/// Backoff between DB-record retry attempts.
const PIN_RECORD_BACKOFF: Duration = Duration::from_millis(50);

/// Run an idempotent DB-record operation with a bounded retry so a sub-second
/// transient error does not silently leave the pin-source set permanently
/// incomplete. The resolver treats a nonempty below-cap source set as complete,
/// so a dropped `record_pin_source`/`record_pinned_cid` makes `GET /ipfs/{cid}`
/// 404 a valid public copy. Every wrapped insert is idempotent (`ON CONFLICT DO
/// NOTHING` / provenance-preserving upsert), so re-running is safe. On exhausted
/// attempts the last error is returned and the caller records the durable
/// `pin_sources_incomplete` marker (U3, #173), which is what keeps the resolver's
/// bounded scan fallback available for that object instead of 404ing a public copy.
/// Shared with the `pinata.rs` twin so both pin paths retry identically. Runs
/// inside the already-detached post-push task, so the backoff adds no push latency.
pub(crate) async fn retry_db_record<F, Fut>(mut op: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt >= PIN_RECORD_ATTEMPTS {
                    return Err(e);
                }
                tokio::time::sleep(PIN_RECORD_BACKOFF).await;
                attempt += 1;
            }
        }
    }
}

/// The smallest bound a durability write is given, however little of the batch
/// deadline is left.
///
/// `batch_budget_gate` only guarantees [`PIN_READ_FLOOR`] before an object STARTS,
/// and the add is handed the whole remainder, so a successful add can finish with
/// ~0 left. An unfloored bound would then fail a write that today completes in
/// milliseconds: on the add path the bytes would sit in Kubo with no `pinned_cids`
/// row, so nothing could resolve the CID, and on the skip branch the source record
/// would fail AND its compensating `mark_pin_sources_incomplete` would fail with
/// it, producing exactly the incomplete-set-without-marker state the marker exists
/// to prevent. The grace exists so a spent batch deadline degrades to a slightly
/// late permit release, never to a dropped durability write.
pub(crate) const DB_RECORD_GRACE: Duration = Duration::from_secs(2);

/// Why a DB call bounded by the batch deadline did not return a value.
///
/// The two arms are kept apart because an operator has to be able to tell a stalled
/// batch (every object timing out at once) from scattered per-object DB failures, and
/// because what an elapsed bound MEANS is not the same claim as a definite error even
/// where the two lead to the same compensation. Every warn line at a bounded site
/// names which arm fired.
#[derive(Debug)]
pub(crate) enum BoundedDbError {
    /// The batch deadline was reached with the call still in flight.
    ///
    /// Whether this means "definitely did not happen" or "outcome unknown" is a
    /// property of the OPERATION, not of the timeout, so each call site has to decide
    /// it from the shape of the call it wrapped. `tokio::time::timeout` cancels the
    /// client future; it does not cancel a statement Postgres has already started.
    /// The two shapes that follow from that:
    ///
    /// - a MULTI-STATEMENT operation that ends in an explicit `tx.commit()`
    ///   DEFINITELY did not land. The cancelled future never reaches the commit, so no
    ///   COMMIT is ever sent and Postgres discards the transaction when the connection
    ///   is reset. `Db::record_pin_source` and `Db::record_pinned_cid_with_source` are
    ///   this shape, and a site that compensates for a definite error must compensate
    ///   here too;
    /// - a SINGLE AUTOCOMMIT statement may still land server-side after this arm is
    ///   taken, because the statement is already running and nothing cancels it.
    ///   `Db::mark_pin_sources_incomplete` and `Db::record_pinata_cid` are this shape,
    ///   and nothing downstream may treat this arm as evidence the write did not
    ///   happen.
    Elapsed,
    /// The DB operation itself failed, definitely and with a cause.
    Db(anyhow::Error),
}

impl std::fmt::Display for BoundedDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elapsed => write!(f, "batch deadline reached with the DB call in flight"),
            Self::Db(e) => write!(f, "{e}"),
        }
    }
}

impl From<BoundedDbError> for anyhow::Error {
    fn from(e: BoundedDbError) -> Self {
        match e {
            BoundedDbError::Elapsed => anyhow::anyhow!("{e}"),
            // Keep the real cause chain rather than flattening it to a string.
            BoundedDbError::Db(inner) => inner,
        }
    }
}

/// Bound one DB operation by the batch deadline.
///
/// What this bounds is the PERMIT HOLD. Both pin loops run under a global
/// `pin_semaphore` permit and that pool defers rather than sheds, so a bare DB
/// await inside the budgeted region parks the permit for as long as the query is
/// stuck; once every pin permit is so held, post-push IPFS replication stops for
/// every repository on the node. `batch_budget_gate` cannot fix that, because it
/// only gates BETWEEN objects and cannot preempt a call already in flight.
///
/// Takes the ABSOLUTE `deadline`, not a duration, so a slow predecessor cannot hand
/// a later call a fresh full budget: the remainder is measured from the same fixed
/// point every time, which is what keeps N calls inside ONE budget instead of N.
///
/// Callers must map the elapsed arm PER SITE, from the shape of the operation they
/// wrapped, rather than folding it into their existing error arm or assuming one
/// meaning for all of them. `timeout` cancels the client future, never the statement
/// Postgres is already running, so an autocommit statement can land server-side after
/// this returns [`BoundedDbError::Elapsed`] while a multi-statement transaction whose
/// `tx.commit()` is never reached definitely cannot. See the arm's own docs for which
/// operations here are which.
pub(crate) async fn db_bounded<T, F>(deadline: Instant, fut: F) -> Result<T, BoundedDbError>
where
    F: std::future::Future<Output = Result<T>>,
{
    let left = deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout(left, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(BoundedDbError::Db(e)),
        Err(_elapsed) => Err(BoundedDbError::Elapsed),
    }
}

/// The deadline a durability write gets: the batch deadline, floored at
/// [`DB_RECORD_GRACE`] from now so a spent budget cannot drop the write.
pub(crate) fn db_record_deadline(deadline: Instant) -> Instant {
    std::cmp::max(deadline, Instant::now() + DB_RECORD_GRACE)
}

/// Opportunistically repair a legacy provider-CID row on the already-pinned skip
/// path (#173 R8, KTD8). Releases before this branch stored the PROVIDER CID
/// (Kubo dag-pb / Pinata CIDv0) in `pinned_cids.cid`; the `/ipfs` resolver
/// recomputes the raw CID from object bytes and 404s any row whose key does not
/// match, yet `list_pinned_cids` still advertises the stored key — so a client
/// gets a CID the resolver deliberately withholds. When a re-push carries the
/// object again, rewrite the key to the raw CID and stash the old provider value
/// in `legacy_provider_cid`.
///
/// COST GATE: candidacy is decided from the stored key's codec alone — a
/// CIDv1/raw key is already the resolver key and reads NO bytes, keeping the
/// steady-state skip cost DB-only. Only a legacy-codec row reads the object to
/// recompute. A row whose bytes are gone stays withheld (no destructive rewrite).
///
/// The read's `deadline` is the CALLER's to set, because the two kinds of caller can
/// afford very different holds. Both pin loops run this while holding a `pin_semaphore`
/// permit, so they clamp it to the batch deadline: left at `git_service_timeout_secs`
/// (600s by default) one wedged `cat-file` would hold a GLOBAL pin slot for five times
/// `PIN_BATCH_BUDGET` and starve every other repo's pin work, and the loop's own budget
/// gate cannot preempt a call already in flight. The boot sweep holds no permit and has
/// no batch to overrun, so it passes the plain `git_timeout`.
pub(crate) async fn repair_legacy_provider_cid(
    repo_path: &std::path::Path,
    git_bin: &str,
    deadline: std::time::Instant,
    sha: &str,
    db: &crate::db::Db,
) -> Result<RepairOutcome> {
    // Bounded by the SAME `deadline` the git read below uses (F3, #173): both pin
    // loops call this with the pin permit held, so a bare await here parked that
    // permit exactly the way the loop bodies' own awaits did. A grep over the loop
    // bodies cannot see this site, which is why it is bounded from inside.
    let stored = match db_bounded(deadline, db.cid_for_oid(sha)).await? {
        Some(c) => c,
        None => return Ok(RepairOutcome::Settled),
    };
    // Cost gate: a canonical raw CIDv1 key is already correct — never read bytes.
    if gitlawb_core::cid::is_raw_cidv1(&stored) {
        return Ok(RepairOutcome::Settled);
    }
    // Legacy-codec row: read the object to recompute. Counted so a test can prove
    // the gate above spares non-legacy rows this read.
    #[cfg(test)]
    note_legacy_repair_read();
    // `read_object_bounded` is SYNCHRONOUS `git cat-file`, and its budget is
    // `git_service_timeout_secs` (600 by default), so running it inline parks a tokio
    // worker for as long as git takes: one wedged read on the sweep's first pass at boot
    // holds a worker for ten minutes, per legacy row. Push it to the blocking pool, the
    // same shape `replication_withheld_set` uses in api/repos.rs (#173 round 11, F4).
    // Both callers of this function are async, so neither changes shape. The read-counter
    // increment above stays on THIS thread so the thread_local cost-gate assertion holds.
    let read = {
        let repo_path = repo_path.to_path_buf();
        let git_bin = git_bin.to_string();
        let sha = sha.to_string();
        // The shared-deadline form: `read_object_bounded` composes its type probe and
        // content read under ONE deadline, rather than granting each stage a full budget,
        // so a legacy row's repair read is bounded in total by whatever the caller set.
        tokio::task::spawn_blocking(move || {
            crate::git::store::read_object_bounded(&git_bin, &repo_path, &sha, deadline)
        })
        .await
    };
    let data = match read {
        Ok(Ok(Some((_ty, bytes)))) => bytes,
        // Bytes gone: the row stays withheld, never destructively rewritten. Nothing a
        // later pass changes, so this is a TERMINAL outcome for the sweep's re-walk gate.
        Ok(Ok(None)) => return Ok(RepairOutcome::Settled),
        // A wedged/D-state `git cat-file` (timeout/infra): the repair is opportunistic
        // and best-effort, so skip it and return Ok so the pin task PROCEEDS to
        // requeue_or_release rather than hanging the coalescing key until process death
        // (grok F2, #173). A later re-push or the deferred sweep retries the repair.
        Ok(Err(e)) => {
            tracing::warn!(sha = %sha, err = %e, "skipping legacy provider-CID repair: bounded object read failed");
            return Ok(RepairOutcome::Retryable);
        }
        // The blocking task panicked or was cancelled: same best-effort treatment, and
        // worth another walk because it says nothing about the row itself.
        Err(e) => {
            tracing::warn!(sha = %sha, err = %e, "skipping legacy provider-CID repair: object read task failed");
            return Ok(RepairOutcome::Retryable);
        }
    };
    let raw = Cid::from_git_object_bytes(&data).to_string();
    if raw == stored {
        return Ok(RepairOutcome::Settled);
    }
    db_bounded(deadline, db.repair_legacy_provider_cid(sha, &raw, &stored)).await?;
    Ok(RepairOutcome::Repaired)
}

/// What one opportunistic repair did with a row, so the sweep can tell a skip a later
/// run could fix from one nothing will (U4 re-walk, #173 round 11). The push skip path
/// ignores the value: it repairs whatever the push happens to carry and a failure there
/// is already warn-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepairOutcome {
    /// Nothing to do, or nothing a re-walk would change: the stored key is already the
    /// raw resolver key, the recomputed key matches it, or the object's bytes are gone.
    Settled,
    /// The bounded object read failed (a wedged `git cat-file`, an unreadable repo).
    /// The bytes may be readable later, so the row is worth walking again.
    Retryable,
    /// The row's key was rewritten to the raw-content CID.
    Repaired,
}

/// What one sweep pass (or a whole sweep run) did. `scanned` counts `pinned_cids`
/// rows READ, which is the quantity the batch size bounds; `repaired` counts rows
/// whose key was actually rewritten to the raw CID.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SweepStats {
    pub scanned: usize,
    pub repaired: usize,
    pub passes: usize,
    /// Rows left unrepaired for a reason a LATER run could fix (the source repo is not
    /// on this node's local disk, a DB read failed, a bounded object read failed). Rows
    /// that are unrepairable in principle (no provenance, the repo row is gone, the
    /// bytes are gone) are NOT counted here.
    ///
    /// This drives NO control decision. It gated the cursor rewind under round 11; the
    /// rewind now fires on reaching the end of the table, whatever happened on the way
    /// (see [`sweep_legacy_provider_cids`]). Re-gating it on this field reopens the
    /// below-cursor rolling-upgrade hole, because the run that parks the cursor is a
    /// clean one by definition. The field is reporting only.
    pub retryable_skips: usize,
    /// Object reads spent on rows that turned out to be unrepairable in principle: the
    /// bytes are gone, so the read is pure waste and the next run will waste it again.
    /// [`MAX_DEAD_ROW_READS_PER_RUN`] bounds this per run.
    pub dead_row_reads: usize,
}

/// How many fruitless object reads one sweep run will spend before it stops and leaves
/// the rest of the table for the next run (#173 round 12, second-model pass).
///
/// A completed run rewinds, so every later run re-attempts the read for every row whose
/// bytes are permanently gone. Without a bound that is `O(dead rows)` `git cat-file`
/// invocations on every single boot, and a node that accumulated a lot of them (a
/// deleted repo, a force-pushed history, a failed migration) pays it forever. Stopping
/// early keeps the cursor, so the next boot resumes past the rows already walked rather
/// than repeating them, and the table still gets covered across boots.
pub(crate) const MAX_DEAD_ROW_READS_PER_RUN: usize = 64;

/// One bounded pass of the U4 sweep: read at most `batch` `pinned_cids` rows after
/// the persisted cursor, repair the legacy ones, and persist the new cursor.
///
/// The batch is what bounds the pass. It caps rows READ, not rows repaired, because
/// the legacy predicate is a codec decode SQL cannot express; a table of raw rows
/// therefore costs one indexed range scan per pass and nothing else.
///
/// The cursor advances to the LAST row read whatever happened to each row, including
/// rows that were skipped as unrepairable. A cursor that only advanced on success
/// would re-read the same unrepairable row on every pass and the sweep would never
/// reach the rows behind it.
async fn sweep_pass(
    repos_dir: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    batch: i64,
    db: &crate::db::Db,
) -> Result<SweepStats> {
    let cursor = db.pin_repair_cursor().await?;
    let rows = db.pinned_cids_after(&cursor, batch).await?;
    let scanned = rows.len();
    let mut repaired = 0usize;
    let mut retryable_skips = 0usize;
    let mut dead_row_reads = 0usize;
    let mut last = cursor;

    for (sha, stored) in rows {
        // Advance FIRST: every path below this line may skip the row, and none of them
        // may wedge the walk (scenario 7).
        last = sha.clone();
        // Same cost gate as the skip-path repair: a canonical raw CIDv1 key is already
        // the resolver key, so it reads no bytes and resolves no repo.
        if gitlawb_core::cid::is_raw_cidv1(&stored) {
            continue;
        }
        // Resolve the row's repo from its recorded provenance (first-pinner plus the
        // bounded additional source set). An empty set is a pin recorded before
        // provenance existed: nothing to read the bytes from, so skip it.
        let sources = match db.pin_sources_for_oid(&sha).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "sweep: failed to read pin sources");
                // A DB read error says nothing about the row, so a later run retries it.
                retryable_skips += 1;
                continue;
            }
        };
        // Whether this row ended the source walk repaired, and whether anything it hit
        // along the way was a transient obstacle rather than a permanent one.
        let mut row_repaired = false;
        let mut row_retryable = false;
        // Whether any source got as far as spending an object read on this row, which is
        // what makes an unrepairable row COST something rather than just being skipped.
        let mut row_read_attempted = false;
        for repo_id in sources {
            let repo = match db.get_repo_by_id(&repo_id).await {
                Ok(Some(r)) => r,
                // The repo row is gone: a later source may still hold the bytes. A
                // deleted repo does not come back, so this is not a retryable skip.
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(repo_id = %repo_id, err = %e, "sweep: failed to read repo");
                    row_retryable = true;
                    continue;
                }
            };
            // Derive the LOCAL disk path rather than going through `repo_store.acquire`.
            // The sweep is opportunistic background maintenance over every pinned row on
            // the node, so it must never pull a cold repo back from remote storage: that
            // would turn a repair pass into a bulk restore. A repo that is not on local
            // disk simply reads no bytes here and stays withheld, but it IS a retryable
            // skip: on a Tigris-backed node the repo is cold now and warm later, and
            // without the re-walk that row would never be repaired by anything.
            // The path goes through the repo store's VALIDATED resolver (allowlisted
            // components, rooted at repos_dir, no ParentDir/CurDir segment), not the raw
            // join: the sweep is a second caller of that path logic and gets the same
            // barrier the acquire path has (#173 round 11, F3). It is the non-fetching
            // variant, so the no-cold-pull property above is untouched.
            let repo_path = match crate::git::repo_store::validated_repo_disk_path(
                repos_dir,
                &repo.owner_did,
                &repo.name,
            ) {
                Ok(p) => p,
                // An unsafe name is not something a later run fixes, so it is terminal.
                Err(e) => {
                    tracing::warn!(repo_id = %repo_id, err = %e, "sweep: rejected unsafe repo path");
                    continue;
                }
            };
            if !repo_path.is_dir() {
                row_retryable = true;
                continue;
            }
            // The sweep holds no pin permit and has no batch to overrun, so the plain
            // `git_timeout` is the right budget here.
            row_read_attempted = true;
            match repair_legacy_provider_cid(
                &repo_path,
                git_bin,
                std::time::Instant::now() + git_timeout,
                &sha,
                db,
            )
            .await
            {
                Ok(RepairOutcome::Repaired) => {
                    repaired += 1;
                    row_repaired = true;
                    break;
                }
                // The bytes could not be read from this source right now: try the next
                // source, and if none of them works, walk the row again on a later run.
                Ok(RepairOutcome::Retryable) => row_retryable = true,
                // Nothing to repair from this source and nothing a re-walk changes.
                Ok(RepairOutcome::Settled) => {}
                Err(e) => {
                    tracing::warn!(sha = %sha, err = %e, "sweep: legacy provider-CID repair failed");
                    row_retryable = true;
                }
            }
        }
        if !row_repaired && row_retryable {
            retryable_skips += 1;
        }
        // Read, not repaired, and nothing a later run would change: pure waste, and the
        // rewind means the next run repeats it. This is the quantity the run bounds.
        if row_read_attempted && !row_repaired && !row_retryable {
            dead_row_reads += 1;
        }
    }

    db.set_pin_repair_cursor(&last).await?;
    Ok(SweepStats {
        scanned,
        repaired,
        passes: 1,
        retryable_skips,
        dead_row_reads,
    })
}

/// Test seam for a single bounded pass (scenarios 4 and 5 drive passes by hand to
/// observe the batch bound and the restart-resumes-from-cursor behavior).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn sweep_legacy_provider_cids_once(
    repos_dir: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    batch: i64,
    db: &crate::db::Db,
) -> Result<SweepStats> {
    sweep_pass(repos_dir, git_bin, git_timeout, batch, db).await
}

/// U4 (#173): the one-shot legacy provider-CID migration sweep.
///
/// Releases before this branch stored the PROVIDER CID (Kubo dag-pb / Pinata CIDv0)
/// in `pinned_cids.cid`. This branch's `/ipfs/{cid}` resolver recomputes the raw
/// content CID and withholds any row whose key does not match, so those rows are
/// unresolvable. The opportunistic repair on the already-pinned skip path only fires
/// when a later push re-carries the object, and normal git negotiation omits objects
/// the node already has, so on an upgraded node that push generally never comes. This
/// walks the table instead.
///
/// Runs until a pass comes back short of a full batch, which is the end of the table.
/// Sleeps `delay` between full batches so it cannot monopolize the DB, and persists
/// its cursor every pass so a restart continues instead of rewinding. Errors reading
/// or repairing an individual row are warn-and-skip; only a failure of the batch query
/// or the cursor write ends the run, and a later run picks up from the stored cursor.
///
/// A run that REACHES THE END OF THE TABLE rewinds the cursor to the start on its way
/// out, so the next run walks the whole table again (#173 rounds 11 and 12). Without
/// that the cursor parked at the maximum `sha256_hex` for good and every later boot
/// read zero rows, which stranded two different kinds of row: one skipped for a
/// transient reason (its repo cold on a Tigris-backed node, a DB or object read error),
/// and one written BELOW the parked cursor afterwards by another node mid-rolling-
/// upgrade. Either way the row was unadvertised and unresolvable with nothing left to
/// fix it.
///
/// Round 11 gated the rewind on a transient skip having happened. That could not cover
/// the second case, because the run that parks the cursor is a clean one by definition:
/// the row it strands does not exist yet. So the rewind is unconditional on completion.
///
/// It is a per-RUN decision made after the walk has finished, never mid-walk, so it
/// cannot spin. The cost is one extra ordered scan per run, plus a repair attempt for
/// each row that is unrepairable in principle (bytes gone, provenance gone): the read is
/// attempted before the bytes are found missing. Those reads are the one cost that does
/// not shrink as the migration progresses, so `MAX_DEAD_ROW_READS_PER_RUN` bounds them
/// per run and the run stops early rather than paying `O(dead rows)` on every boot. A
/// row already carrying the canonical raw key costs a codec decode and no read at all,
/// so a node that has finished repairing pays the scan and nothing more.
///
/// A run that stops on a pass ERROR does NOT rewind: its cursor is mid-table and
/// discarding it would restart the walk from the beginning on a node whose DB is
/// failing part-way through.
pub(crate) async fn sweep_legacy_provider_cids(
    repos_dir: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    batch: i64,
    delay: Duration,
    db: &crate::db::Db,
) -> SweepStats {
    let mut totals = SweepStats::default();
    let mut completed = false;
    loop {
        let pass = match sweep_pass(repos_dir, git_bin, git_timeout, batch, db).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(err = %e, "legacy provider-CID sweep pass failed; stopping");
                break;
            }
        };
        totals.scanned += pass.scanned;
        totals.repaired += pass.repaired;
        totals.retryable_skips += pass.retryable_skips;
        totals.dead_row_reads += pass.dead_row_reads;
        totals.passes += 1;
        // A short batch means the ordered walk reached the end of the table. Stop here
        // rather than after an extra empty pass, and do NOT sleep on the way out.
        if (pass.scanned as i64) < batch {
            completed = true;
            break;
        }
        // Enough fruitless reads for one run. Stop WITHOUT completing, so the cursor
        // stays where the walk got to and the next run carries on from there instead of
        // re-reading these rows. Checked between passes, so a run can overshoot by at
        // most one batch.
        if totals.dead_row_reads >= MAX_DEAD_ROW_READS_PER_RUN {
            tracing::info!(
                dead_row_reads = totals.dead_row_reads,
                "legacy provider-CID sweep pausing: too many unrepairable rows this run"
            );
            break;
        }
        tokio::time::sleep(delay).await;
    }
    if completed {
        if let Err(e) = db.set_pin_repair_cursor("").await {
            tracing::warn!(err = %e, "failed to rewind the legacy provider-CID sweep cursor");
        }
    }
    totals
}

// Test-only cost-gate counter (R8, U7): how many times the opportunistic repair
// read an object's bytes on the skip path. The codec gate must spare a CIDv1/raw
// row this read; the counter is the both-ways guard (removing the gate reads the
// raw row and increments it). Same thread_local discipline as the serve-path
// oversize counter — the pin tests await `pin_new_objects` on a current-thread
// runtime, so the increment and the assertion share one thread.
#[cfg(test)]
thread_local! {
    static LEGACY_REPAIR_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_legacy_repair_reads() {
    LEGACY_REPAIR_READS.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn legacy_repair_reads() -> usize {
    LEGACY_REPAIR_READS.with(|c| c.get())
}

#[cfg(test)]
fn note_legacy_repair_read() {
    LEGACY_REPAIR_READS.with(|c| c.set(c.get() + 1));
}

/// Wall-clock ceiling on one [`pin_new_objects`] batch.
///
/// The loop runs under a `pin_semaphore` permit and that pool defers rather than
/// sheds, so without a ceiling the hold is O(N) with N (the push's object count)
/// chosen by the pusher. This bounds the drain of a saturated pool instead.
///
/// 120s is 12x the shared client's 10s whole-request ceiling, so a single large
/// healthy upload that needs more than the client default still has room to
/// finish (the per-request timeout is set to the remainder, not the default),
/// while a batch of them still cannot hold the permit indefinitely. Deliberately
/// a constant and not a config knob: the value only has to be large enough to be
/// uninteresting on a healthy node, and a knob is operator surface that would
/// have to be documented, validated, and kept meaningful.
pub const PIN_BATCH_BUDGET: Duration = Duration::from_secs(120);

/// The smallest remainder worth starting a bounded git read (or an add) with.
///
/// A 1ms remainder otherwise buys a child spawned already past its deadline, which
/// can only be reaped: the watchdog's SIGTERM grace plus its post-SIGKILL settle are
/// paid in full for work that produces nothing, once per remaining object. Breaking
/// the batch instead is the same spawn-to-reap amplification the bounded type probe
/// already refuses when it declines a confirming re-probe it cannot afford.
///
/// ~1100ms tracks `visibility_pack`'s 1s SIGTERM grace plus its 20ms settle plus
/// margin. Both of those are private to that module, so the value is named once here
/// and documented rather than guessed separately in each loop.
pub(crate) const PIN_READ_FLOOR: Duration = Duration::from_millis(1100);

/// The shared outbound client for both IPFS sinks.
///
/// `pin_new_objects` runs while holding a `pin_semaphore` permit and that pool
/// defers rather than sheds, so an unbounded await here parks the pool. A bare
/// `reqwest::Client::new()` has no timeout, which is exactly that. Built from
/// `crate::build_http_client` rather than a local builder: its docstring forbids
/// hand-rolling an equivalent, so that the redirect and timeout guarantees the
/// node's tests bind stay bound to the client every outbound path actually uses.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| crate::build_http_client().expect("failed to build production http client"))
}

/// Pin a single git object to the local IPFS/Kubo node.
///
/// - `ipfs_api`: base URL of the Kubo HTTP API, e.g. `http://127.0.0.1:5001`.
///   If empty the function returns `Ok("")` immediately.
/// - `sha256_hex`: the git SHA-256 hex object ID (used only for logging).
/// - `data`: raw git object content bytes (same bytes used for CID computation).
/// - `request_timeout`: overrides the shared client's whole-request timeout for
///   THIS request only. `RequestBuilder::timeout` replaces the client-level value
///   per request and leaks nothing to other calls on the same client, so the
///   batch loop can hand each add whatever is left of its budget without
///   loosening or tightening any other outbound path. `None` keeps the client's
///   own ceiling.
///
/// Returns the CID string on success, or `""` when IPFS is not configured.
pub async fn pin_git_object(
    ipfs_api: &str,
    sha256_hex: &str,
    data: &[u8],
    request_timeout: Option<Duration>,
) -> Result<String> {
    if ipfs_api.is_empty() {
        return Ok(String::new());
    }

    // Compute the expected CIDv1 from the content bytes
    let expected_cid = Cid::from_git_object_bytes(data).to_string();

    let url = format!(
        "{}/api/v0/add?cid-version=1&raw-leaves=true&pin=true",
        ipfs_api.trim_end_matches('/')
    );

    // Build multipart form with the object data
    let part = reqwest::multipart::Part::bytes(data.to_vec())
        .file_name("object")
        .mime_str("application/octet-stream")?;
    let form = reqwest::multipart::Form::new().part("file", part);

    let mut req = http_client().post(&url).multipart(form);
    if let Some(t) = request_timeout {
        req = req.timeout(t);
    }

    let resp = req
        .send()
        .await
        // Keep the `reqwest::Error` as this error's source rather than
        // formatting it away. Operators reading a pin failure want the concrete
        // transport cause in the logged chain, not a single flattened line, and
        // this module's tests downcast to it to prove a silent endpoint really
        // surfaces as a timeout rather than as some other failure that happens
        // to arrive in time.
        // The context keeps the old message verbatim so the callers that log
        // this at `%e` (here, `sync.rs`, `encrypted_pin.rs`) read the same.
        .map_err(|e| {
            let msg = format!("IPFS add request failed: {e}");
            anyhow::Error::new(e).context(msg)
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "IPFS /api/v0/add returned {status}: {body}"
        ));
    }

    // Kubo returns newline-delimited JSON; we only care about the last object
    // (there's typically just one for a single-file add).
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("IPFS add response body read failed: {e}"))?;
    let cid = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            v["Hash"].as_str().map(|s| s.to_string())
        })
        .next_back()
        .unwrap_or(expected_cid.clone());

    tracing::debug!(sha256 = %sha256_hex, %cid, "pinned git object to IPFS");
    Ok(cid)
}

/// Fetch raw bytes for a CID from the local Kubo node (`/api/v0/cat`).
pub async fn cat(ipfs_api: &str, cid: &str) -> Result<Vec<u8>> {
    if ipfs_api.is_empty() {
        return Err(anyhow::anyhow!("IPFS not configured"));
    }
    let url = format!("{}/api/v0/cat?arg={}", ipfs_api.trim_end_matches('/'), cid);
    let resp = http_client().post(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("ipfs cat {cid}: {}", resp.status()));
    }
    Ok(resp.bytes().await?.to_vec())
}

/// The batch's remaining wall-clock, or `None` once too little is left to be worth
/// starting an object's work with, after logging the truncation exactly once.
///
/// "Too little" is [`PIN_READ_FLOOR`], not zero: a remainder that cannot cover a
/// bounded git read's teardown buys a child spawned already past its deadline, and a
/// sub-millisecond per-request timeout buys a doomed add whose failure reads as an
/// endpoint fault rather than as budget truncation.
///
/// Shaped like `api::ipfs`'s `budget_gate` on purpose: the nonzero-ness rides in
/// the returned value, so every call site must consume it as
/// `let Some(x) = ... else { break }` and a zero `Duration` can never reach a
/// request as its timeout.
///
/// `sink` labels the backend in the truncation warn ("IPFS" or "Pinata"). The gate
/// is shared by both pin loops rather than copied per loop, so the two cannot drift
/// apart in how they report a truncated batch.
pub(crate) fn batch_budget_gate(
    sink: &str,
    deadline: Instant,
    pinned: usize,
    unattempted: usize,
) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left < PIN_READ_FLOOR {
        tracing::warn!(
            sink,
            pinned,
            unattempted,
            "pin batch deadline reached; the remaining objects are left unpinned"
        );
        return None;
    }
    Some(left)
}

/// Pin any of the given candidate git objects that are not yet recorded in
/// `pinned_cids`.
///
/// `object_list` is the already-withheld-filtered OID set to pin: the caller
/// applies `visibility_pack::replicable_objects` on the delta path or the
/// `..._fail_closed` filter on the full-scan path before calling, so this
/// function never sees a withheld blob. `repo_path` is still needed to read each
/// object's bytes, and `git_bin` names the binary those reads run: the production
/// callers pass the literal `"git"`, and a test passes a fake so the loop's own bound
/// can be driven with a git that never answers. `repo_id` records the pin's provenance
/// so `GET /ipfs/{cid}` resolves straight to this repo instead of scanning every repo
/// (#173).
///
/// # What `batch_budget` does and does not bound
///
/// The loop holds a `pin_semaphore` permit and that pool defers rather than
/// sheds, so the hold has to be bounded by something other than the pusher's
/// object count. Four things here are:
///
/// - this loop's own wall-clock: the deadline is taken once at loop start and
///   checked at the top of every iteration, so no object's work begins with less
///   than [`PIN_READ_FLOOR`] left. It is a gate, not a hard ceiling, since a started
///   iteration still runs to completion;
/// - the git read: `store::read_object_bounded` runs under `spawn_blocking` against the
///   ABSOLUTE batch deadline (not the loop-top remainder, which the `is_pinned` round-trip
///   sitting between the two would push past it), with SIGTERM-then-SIGKILL
///   process-group teardown, so a hung `git cat-file` costs this batch its remaining
///   budget plus one watchdog teardown instead of holding the permit for the child's
///   whole lifetime and blocking a runtime worker while it does;
/// - each HTTP add: `pin_git_object` is handed the remainder measured AFTER the read
///   as its per-request timeout, which is what lets one large healthy upload run past
///   the shared client's 10s default without letting the batch run forever. Measuring
///   it after the read is what keeps the read-plus-add pair inside one budget rather
///   than up to two of them;
/// - the DB round-trips: every DB operation reachable from inside the region is
///   bounded by the same absolute deadline through [`db_bounded`], including the two
///   inside `repair_legacy_provider_cid`, which the loop body's own call sites do not
///   show. `retry_db_record` is wrapped as a whole so its ladder cannot multiply one
///   remainder, and the durability writes (the post-add record, the skip branch's
///   source record and its incomplete marker) take the floored remainder
///   `max(remaining, DB_RECORD_GRACE)` so a spent budget delays the permit release
///   rather than dropping a write. A bound is not a rollback, and what an elapsed
///   bound MEANS is a property of the operation, so each site maps that arm from the
///   shape of the call it wrapped: a multi-statement transaction whose `tx.commit()`
///   is never reached definitely did not land and is compensated like a definite
///   error, while a single autocommit statement may still land server-side and is
///   never treated as a failed write. See [`BoundedDbError::Elapsed`].
///
/// So the LOOP's hold is bounded by roughly `batch_budget` plus one teardown plus the
/// record graces one iteration can chain. `db_record_deadline` re-floors from
/// `Instant::now()` at EVERY call, so the graces inside a single iteration add up
/// rather than sharing one floor: this loop's worst case is the skip branch at
/// `deadline + 4s` (the source record, then its incomplete marker). It does NOT stack
/// per object, because the next iteration's first statement is `batch_budget_gate`,
/// which breaks the batch, so the overrun is one iteration's worth however many
/// objects the push carried. Against the 120s `PIN_BATCH_BUDGET` that is roughly a 5%
/// overrun for the batch, not an unbounded hold. One thing inside that region still is
/// not bounded at all, and the gate cannot fix it:
///
/// - the pool. `api::repos` acquires the same `pin_semaphore` for the Pinata
///   replication task and holds it across `pinata_object_list_for_refs`, a full git
///   re-derivation that runs BEFORE `pinata::pin_new_objects` is entered and whose
///   per-child timeouts carry no aggregate deadline. What is bounded is each pin
///   loop's own hold, not the permit's total hold and not the semaphore's worst-case
///   queue.
///
/// # Truncation semantics
///
/// A batch stopped at the deadline leaves its remaining objects unpinned, and
/// nothing sweeps them up afterwards. There is no reconciliation pass over
/// `pinned_cids`; recovery is opportunistic, happening only if some later push
/// on the repo takes the full-scan fallback (`push_delta::list_all_objects`) and
/// re-derives the whole object set, which then re-offers the skipped OIDs.
///
/// The twin in `pinata.rs` is back at parity on everything that bounds or repairs an
/// object: it runs the same shared budget gate at the top of every iteration, the same
/// bounded and reaped git read against the earlier of the batch deadline and
/// `git_timeout`, and the same opportunistic legacy provider-CID repair on its skip
/// branch. It still has no per-request override, since `pinata::pin_object` takes no
/// timeout argument and its uploads are bounded by the shared client's own ceiling.
/// Everything else about the shape (the skip-if-pinned check, the provenance recording,
/// the fault arms) changes in lockstep. The returned pairs are the one deliberate
/// exception: this side omits an object whose DB record exhausted its retries, because
/// the return here is consumed for logging only, while the pinata side still returns it
/// because its return feeds the announcement `cid_map`. See the record step for the
/// reasoning.
///
/// Returns a list of `(sha256_hex, cid)` pairs pinned AND durably recorded this
/// call.
// Eight because #173's git seam (`git_bin`, `git_timeout`) and pin provenance
// (`repo_id`) sit alongside #174's batch budget. All four callers pass every one, and
// grouping them into a context struct would add a type whose only job is to be
// destructured back into these fields at the top of the loop.
#[allow(clippy::too_many_arguments)]
pub async fn pin_new_objects(
    ipfs_api: &str,
    repo_path: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    object_list: Vec<String>,
    db: &crate::db::Db,
    repo_id: &str,
    batch_budget: Duration,
) -> Vec<(String, String)> {
    if ipfs_api.is_empty() {
        return vec![];
    }

    let deadline = Instant::now() + batch_budget;
    let total = object_list.len();
    let mut pinned = Vec::new();

    for (attempted, sha) in object_list.into_iter().enumerate() {
        // Top of the iteration, before any of this object's work: an object is
        // never started with a remainder too small to cover a bounded read's
        // teardown. Consumed as a guard only: the read below runs against the
        // absolute batch deadline, and the add's timeout is measured again after
        // the read, so this remainder has no other consumer here.
        if batch_budget_gate("IPFS", deadline, pinned.len(), total - attempted).is_none() {
            break;
        }
        // Skip if already pinned, but first backfill provenance if the existing
        // pin has none. A legacy pin (recorded before repo_id existed, #173, jatmn)
        // is skipped here before record_pinned_cid ever runs, so its NULL provenance
        // would never resolve to one repo and known CIDs keep hitting the scan. The
        // backfill only sets repo_id (AND repo_id IS NULL guard preserves
        // first-pinner-owns) and never re-pins the bytes: the object is already on IPFS.
        // Every DB call from here to the end of the iteration is bounded by the
        // ABSOLUTE batch deadline (F3, #173): the loop runs under a global pin permit
        // and a bare await parked it for the whole stall. The elapsed arm is mapped per
        // site below, never as a blanket "existing error arm": a timeout cancels the
        // client future but not the statement Postgres is running, so it reports an
        // UNKNOWN outcome, not a failed write.
        match db_bounded(deadline, db.is_pinned(&sha)).await {
            Ok(true) => {
                // Elapsed here is free to skip: these are reads, so a late server-side
                // completion costs nothing, and the backfill's own `AND repo_id IS NULL`
                // guard makes a late-landing write idempotent.
                match db_bounded(deadline, db.provenance_for_oid(&sha)).await {
                    Ok(None) => {
                        if let Err(e) =
                            db_bounded(deadline, db.backfill_pin_provenance(&sha, repo_id)).await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to backfill pin provenance");
                        }
                    }
                    Ok(Some(_)) => {}
                    Err(e) => {
                        tracing::warn!(sha = %sha, err = %e, "DB error reading pin provenance");
                    }
                }
                // F1 (#173 round 8): record this repo as an ADDITIONAL source for the
                // already-pinned object. This is the load-bearing skip-branch insert —
                // a later repo pushing a shared object hits this path (already pinned),
                // and without it `GET /ipfs/{cid}` only ever knows the first pinner, so a
                // shared object first pinned from a private/quarantined repo 404s even
                // when this repo would serve it. Bounded per object (MAX_PIN_SOURCES).
                // The retry ladder is wrapped AS A WHOLE, not per attempt: three stalls
                // plus their backoff otherwise multiply one remainder by three. Floored
                // at DB_RECORD_GRACE because this is a durability write.
                match db_bounded(
                    db_record_deadline(deadline),
                    retry_db_record(|| db.record_pin_source(&sha, repo_id)),
                )
                .await
                {
                    Ok(()) => {}
                    // Elapsed here is a DEFINITE non-write, not an unknown outcome, and
                    // that follows from what was wrapped rather than from the timeout.
                    // `record_pin_source` is an explicit transaction (`pool.begin()`,
                    // the insert, a conditional marker clear, `tx.commit()`), so a
                    // cancelled future never reaches the commit, no COMMIT is ever sent,
                    // and the row cannot have landed. The source set is therefore
                    // incomplete and must be marked, exactly as on the definite-error
                    // arm below; leaving it unmarked is the state the marker exists to
                    // prevent, since the resolver reads a non-empty below-cap set as
                    // COMPLETE and 404s a copy this repo would serve. The cost of the
                    // marker is bounded: the fallback legacy scan is capped at
                    // `ipfs_max_legacy_probes` and charges the per-IP work rate limiter
                    // per probe. The arm stays separate only so the warn tells an
                    // operator a stalled batch from a scattered per-object failure.
                    Err(e @ BoundedDbError::Elapsed) => {
                        tracing::warn!(
                            sha = %sha,
                            err = %e,
                            "pin source record did not complete inside the batch deadline; \
                             a cancelled multi-statement transaction never commits, so the \
                             source is definitely missing and the set is marked incomplete"
                        );
                        if let Err(e) = db_bounded(
                            db_record_deadline(deadline),
                            db.mark_pin_sources_incomplete(&sha),
                        )
                        .await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                        }
                    }
                    // U3 (#173): the retries are spent on REAL errors, so this repo is
                    // definitely NOT in the source set and the set is known incomplete.
                    // Persist that, or the resolver reads a non-empty below-cap set as
                    // COMPLETE and 404s an object this repo would serve. Warn-only in
                    // turn: if the marker write also fails the object degrades to the
                    // pre-U3 behavior, never worse. Floored for the same reason the
                    // record above is: a spent budget must not drop the compensation.
                    // The marker write itself is a single autocommit statement, so ITS
                    // own elapsed arm genuinely is an unknown outcome; nothing branches
                    // on it, which is why warn-only is the right handling there.
                    Err(e) => {
                        tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                        if let Err(e) = db_bounded(
                            db_record_deadline(deadline),
                            db.mark_pin_sources_incomplete(&sha),
                        )
                        .await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                        }
                    }
                }
                // R8 (#173 round 10): opportunistically repair a legacy provider-CID
                // row (Kubo dag-pb / Pinata) to the raw-content resolver key on this
                // re-push. Cost-gated on the stored key's codec — a non-legacy row
                // reads no bytes. Warn-only: a failure leaves the row as-is for a
                // later re-push or the deferred one-shot sweep.
                // Clamped to the batch deadline: this runs with the pin permit held, so
                // an unclamped `git_timeout` would let one wedged read hold a global pin
                // slot for 600s against a 120s budget.
                if let Err(e) = repair_legacy_provider_cid(
                    repo_path,
                    git_bin,
                    std::cmp::min(deadline, std::time::Instant::now() + git_timeout),
                    &sha,
                    db,
                )
                .await
                {
                    tracing::warn!(sha = %sha, err = %e, "failed to repair legacy provider CID");
                }
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "DB error checking pinned status");
                continue;
            }
        }

        // Read raw object content, bounded and reaped, under `spawn_blocking`: this is
        // synchronous blocking work (child spawn, pipe drain, watchdog join), so
        // calling it from the runtime task would block a worker thread for its whole
        // duration. Placement mirrors the `/ipfs` serve path; the admission guard is
        // deliberately NOT moved into the closure there, since the pin permit is not
        // held by a future a client disconnect can drop and the child is reaped on its
        // own deadline regardless.
        //
        // The read runs against the ABSOLUTE batch deadline, not against the remainder
        // measured at the top of the iteration: the `is_pinned` round-trip above sits
        // between the two, so `Instant::now() + budget_left` would land past `deadline`
        // by however long the DB took, and under a saturated pool that is the dominant
        // term. A slow DB check must not push the read's own bound out.
        //
        // Bounded by the EARLIER of the batch deadline (#174) and this object's own
        // `git_timeout` (#173). Both bounds are load-bearing and neither implies the
        // other: the batch deadline alone would let ONE wedged `cat-file` hold the pin
        // permit for the whole 120s budget (the failure #173's reaper test drives), while
        // `git_timeout` alone would let a batch of merely-slow reads run past the budget.
        // Which arm actually binds depends on configuration, and at SHIPPED DEFAULTS it is
        // always the batch deadline: `git_service_timeout_secs` is 600 against a 120s
        // PIN_BATCH_BUDGET. The `git_timeout` arm is what an operator who tightens that
        // knob below the remaining budget gets, so do not read this as two bounds both
        // firing in a default deployment.
        let read_deadline = std::cmp::min(deadline, std::time::Instant::now() + git_timeout);
        let read_path = repo_path.to_path_buf();
        let read_sha = sha.clone();
        let read_git = git_bin.to_string();
        let read = tokio::task::spawn_blocking(move || {
            crate::git::store::read_object_bounded(&read_git, &read_path, &read_sha, read_deadline)
        })
        .await;
        let data = match read {
            Ok(Ok(Some((_obj_type, bytes)))) => bytes,
            // A verified absence, and the only outcome that is not a fault.
            Ok(Ok(None)) => continue,
            // A Transient fault does NOT by itself mean the store is gone. It also
            // covers a spawn or watchdog-timeout failure of the reaped child, an
            // unaffordable confirming re-probe, and, because readability is judged FOR
            // one oid, a single unreadable `objects/<xx>` fan-out, which is 1/256 of the
            // store. So re-check store-wide before deciding what the fault costs.
            Ok(Err(e @ crate::git::store::ProbeError::Transient(_))) => {
                if !crate::git::store::object_store_readable_store_wide(repo_path) {
                    // Genuinely store-wide: every remaining object fails identically, and
                    // continuing would spawn one doomed bounded child per object and spend
                    // the batch budget reaping them.
                    tracing::warn!(
                        sha = %sha,
                        err = %e,
                        unattempted = total - attempted,
                        "object store unreadable while pinning; stopping the batch"
                    );
                    break;
                }
                // The store still reads store-wide, so the fault is object-scoped or
                // transient to this read. Breaking would forfeit a healthy store's
                // remaining objects permanently: the documented recovery re-derives the
                // same list and breaks at the same index.
                tracing::warn!(
                    sha = %sha,
                    err = %e,
                    "transient fault reading git object for pinning; the object store is \
                     still readable store-wide, so this costs only this object"
                );
                continue;
            }
            // The store is readable and git still failed: a corrupt object, or a
            // repo-wide fault git reports immediately. Either way it is per-object
            // work that stays inside the budget, and breaking would forfeit a healthy
            // store's remaining objects over one bad one, permanently (a later
            // full-scan push re-offers the same object and breaks in the same place).
            Ok(Err(e)) => {
                tracing::warn!(sha = %sha, err = %e, "failed to read git object for pinning");
                continue;
            }
            // A panic in the read closure leaves no evidence that the failure is
            // object-scoped, so fail toward the conservative arm.
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "bounded git read task failed; stopping the batch");
                break;
            }
        };

        // Recompute the remainder AFTER the read rather than reusing `budget_left`:
        // the read is now allowed to spend the whole remainder, so handing the add the
        // loop-top value would make the pair a hold of up to 2x the batch budget. The
        // same gate, so a remainder too small to be worth a request truncates the batch
        // with one warn instead of shedding a doomed add that logs as an endpoint fault.
        let Some(add_timeout) =
            batch_budget_gate("IPFS", deadline, pinned.len(), total - attempted)
        else {
            break;
        };

        // Pin to IPFS
        match pin_git_object(ipfs_api, &sha, &data, Some(add_timeout)).await {
            Ok(cid) if !cid.is_empty() => {
                // The resolver key (`pinned_cids.cid`) must be the locally-computed
                // raw-content CID, never the provider Hash: Kubo returns a dag-pb/UnixFS
                // root for objects above its block size, which does not hash the raw
                // content, so `GET /ipfs/{provider_cid}` would resolve then fail the F2
                // integrity check (list-then-404). The serve path reads bytes from git and
                // verifies them against the requested CID, so the raw CID is the correct
                // key. Mirrors the pinata twin, which already records the raw CID.
                let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(&data).to_string();
                // F1 (#173 round 8): the first pinner is recorded in pin_repo_sources too,
                // so every source (first and subsequent) is tried uniformly by the
                // resolver. U3 (#173): the pin and its source go down in ONE transaction.
                // As two independent best-effort calls this path could land the pin while
                // dropping its own source, producing a source set silently missing its
                // first pinner; atomically there is no such window. When the transaction
                // still fails after every retry, Kubo is holding the bytes but the DB has
                // no row, so nothing can resolve that CID and there is no partial state to
                // clean up. Recovery is the next push, which re-offers the object and
                // retries the whole record; until then the object counts as unpinned, and
                // the returned vector says so by carrying only durably recorded pins.
                //
                // Returning the provider Hash rather than the resolver key is deliberate:
                // the DB `cid` is the raw resolver key (recorded above), the returned value
                // is the provider CID. On the record-failed case the twins DIVERGE and must
                // stay that way. This return is log-only (`api/repos.rs` turns it into a
                // count log plus one line per pair and consumes it nowhere else), so
                // dropping a record-failed pin costs nothing and stops the log claiming a
                // pin the resolver cannot serve. The pinata twin keeps its unconditional
                // push because ITS return is a real input: `api/repos.rs` builds the
                // sha-to-cid `cid_map` from it, which drives `upsert_branch_cid` and the
                // p2p `publish_ref_update` gossip CID. Do not re-align them without moving
                // that consumer first.
                //
                // The bound here is FLOORED at DB_RECORD_GRACE. The add was handed the
                // whole remainder, so a successful one can return with ~0 left, and an
                // unfloored bound would fail a write that today completes in
                // milliseconds, leaving the bytes in Kubo with no row to resolve them
                // by. If it still fires, both arms mean the same thing here and the site
                // takes one Err path for them: `record_pinned_cid_with_source` is an
                // explicit transaction, so a cancelled future never reaches its
                // `tx.commit()` and the rows definitely did not land, exactly as on a
                // real error. Either way the pin is not returned and the next push
                // re-offers the object. The warn still names the arm through the error's
                // own Display, so an operator can tell a stalled batch from a scattered
                // per-object failure.
                match db_bounded(
                    db_record_deadline(deadline),
                    retry_db_record(|| db.record_pinned_cid_with_source(&sha, &raw_cid, repo_id)),
                )
                .await
                {
                    Ok(()) => pinned.push((sha, cid)),
                    Err(e) => {
                        tracing::warn!(sha = %sha, err = %e, "failed to record pinned CID in DB");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "failed to pin git object to IPFS");
            }
        }
    }

    pinned
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // The retry helper is the load-bearing unit: it converts a sub-second
    // transient DB error at the three warn-only record sites into a landed row,
    // instead of a permanently incomplete pin-source set. These drive the helper
    // directly against a controlled closure (the record sites take a concrete
    // `&Db` over a `PgPool`, so a failing-first wrapper cannot slot in without
    // changing signatures — see U6 seam note).

    #[tokio::test]
    async fn retry_lands_after_transient_failures() {
        let calls = Cell::new(0u32);
        let result = retry_db_record(|| {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n < PIN_RECORD_ATTEMPTS {
                    Err(anyhow::anyhow!("transient failure on attempt {n}"))
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "retry lands the row after transient failures"
        );
        assert_eq!(
            calls.get(),
            PIN_RECORD_ATTEMPTS,
            "op is retried until it succeeds"
        );
    }

    #[tokio::test]
    async fn retry_returns_last_err_after_exhaustion() {
        let calls = Cell::new(0u32);
        let result = retry_db_record(|| {
            let n = calls.get() + 1;
            calls.set(n);
            async move { Err::<(), _>(anyhow::anyhow!("attempt {n} failed")) }
        })
        .await;

        let err = result.expect_err("all attempts fail so the last error surfaces");
        assert_eq!(
            calls.get(),
            PIN_RECORD_ATTEMPTS,
            "attempts are bounded to the cap"
        );
        assert_eq!(
            err.to_string(),
            "attempt 3 failed",
            "the LAST error is returned, not the first"
        );
    }

    // Happy path against a real DB: a single-attempt success lands the row, and a
    // redundant call is idempotent (`ON CONFLICT DO NOTHING`), so the source set
    // holds exactly one row.
    #[sqlx::test]
    async fn retry_records_pin_source_once(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let sha = "a".repeat(64);
        let repo_id = "repo-retry-1";

        retry_db_record(|| db.record_pin_source(&sha, repo_id))
            .await
            .expect("happy-path record succeeds in one attempt");
        retry_db_record(|| db.record_pin_source(&sha, repo_id))
            .await
            .expect("a redundant record is idempotent");

        let sources = db.pin_sources_for_oid(&sha).await.unwrap();
        assert_eq!(
            sources,
            vec![repo_id.to_string()],
            "exactly one source row lands under ON CONFLICT DO NOTHING"
        );
    }

    use std::time::Duration;

    /// Write `n` loose blobs into a fresh bare repo and return their oids.
    /// `read_object` shells to `git cat-file`, so the objects must genuinely
    /// exist on disk — a fabricated oid would `continue` past the pin call and
    /// the loop scenario below would prove nothing.
    fn seed_loose_blobs(repo_path: &std::path::Path, n: usize) -> Vec<String> {
        crate::git::store::init_bare(repo_path).expect("init bare repo");
        (0..n)
            .map(|i| {
                let mut cmd = std::process::Command::new("git");
                cmd.args(["hash-object", "-w", "--stdin"])
                    .current_dir(repo_path)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped());
                let mut child = cmd.spawn().expect("spawn git hash-object");
                {
                    use std::io::Write;
                    child
                        .stdin
                        .as_mut()
                        .expect("stdin")
                        .write_all(format!("pin loop object {i}\n").as_bytes())
                        .expect("write stdin");
                }
                let out = child.wait_with_output().expect("hash-object output");
                assert!(
                    out.status.success(),
                    "git hash-object: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            })
            .collect()
    }

    /// A live endpoint that answers every add with `500`. Counts the requests it
    /// received so a test can tell "the loop kept going" from "the loop stopped",
    /// which the returned pin list cannot (it is empty either way). Reads the
    /// full request, headers plus the `Content-Length` body, before answering:
    /// responding early and closing would surface as a write failure on the
    /// client and turn a rejection into something else.
    async fn rejecting_endpoint(
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut acc = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        acc.extend_from_slice(&buf[..n]);
                        // Once the headers are complete, keep reading until the
                        // declared body has arrived.
                        if let Some(hdr_end) =
                            acc.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
                        {
                            let headers = String::from_utf8_lossy(&acc[..hdr_end]).to_lowercase();
                            let len: usize = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse().ok())
                                .unwrap_or(0);
                            if acc.len() >= hdr_end + len {
                                break;
                            }
                        }
                    }
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                    let _ = sock.flush().await;
                });
            }
        });
        endpoint
    }

    /// A sleeping-but-live endpoint. Answers `200` with an empty body after
    /// `delays[i]` for the i-th request it accepts (the last entry repeats), so
    /// a test can make one add slow and the next fast. Drains the full request,
    /// headers plus the declared `Content-Length` body, before sleeping: exactly
    /// as in `rejecting_endpoint`, answering early and closing would surface as
    /// a write failure on the client and turn a slow-but-healthy add into a
    /// different failure shape.
    ///
    /// An empty body is a successful pin: `pin_git_object` falls back to the CID
    /// it computed from the bytes when the response carries no `Hash`.
    async fn delaying_endpoint(delays: Vec<Duration>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut seen = 0usize;
            while let Ok((mut sock, _)) = listener.accept().await {
                let delay = *delays
                    .get(seen)
                    .or_else(|| delays.last())
                    .unwrap_or(&Duration::ZERO);
                seen += 1;
                tokio::spawn(async move {
                    let mut acc = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        acc.extend_from_slice(&buf[..n]);
                        if let Some(hdr_end) =
                            acc.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
                        {
                            let headers = String::from_utf8_lossy(&acc[..hdr_end]).to_lowercase();
                            let len: usize = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse().ok())
                                .unwrap_or(0);
                            if acc.len() >= hdr_end + len {
                                break;
                            }
                        }
                    }
                    tokio::time::sleep(delay).await;
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = sock.flush().await;
                });
            }
        });
        endpoint
    }

    /// A `tracing` sink a test can read back, so the deadline warn can be
    /// asserted on rather than assumed. Installed with `set_default`, which is
    /// thread-local and scoped to the guard, so it cannot bleed into any other
    /// test in the binary.
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (logs, guard)
    }

    /// The add sink must be built from the shared no-redirect client, and the
    /// per-request override must actually reach the request. Against a silent
    /// endpoint (accept succeeds, no response ever written) a bare
    /// `reqwest::Client::new()` blocks forever. With `Some(2s)` the call must
    /// come back well inside that, and as a reqwest timeout: the elapsed
    /// assertion is the real RED signal, and the outer `tokio::time::timeout`
    /// is only a wedge guard so a regression fails the suite instead of hanging
    /// it (`cargo test` has no per-test timeout). The old "no elapsed assertion
    /// because the timeout is a process-global `OnceLock`" caveat no longer
    /// holds now that `request_timeout` overrides it per call.
    #[tokio::test]
    async fn pin_git_object_against_silent_endpoint_errors_within_its_own_timeout() {
        let endpoint = crate::test_support::silent_http_endpoint().await;
        let started = std::time::Instant::now();
        let inner = tokio::time::timeout(
            Duration::from_secs(30),
            pin_git_object(
                &endpoint,
                "deadbeef",
                b"some object bytes\n",
                Some(Duration::from_secs(2)),
            ),
        )
        .await
        .expect("wedge guard: pin_git_object must return long before 30s");
        let elapsed = started.elapsed();
        let err = inner.expect_err("a silent endpoint must not surface as a successful pin");
        assert!(
            elapsed < Duration::from_secs(5),
            "the 2s per-request override must bound this call, not the client's own ceiling (took {elapsed:?})"
        );
        assert!(
            err.downcast_ref::<reqwest::Error>()
                .is_some_and(|e| e.is_timeout()),
            "a silent endpoint must surface as a reqwest timeout, preserved as the error's source: {err:#}"
        );
    }

    /// The second unhardened sink, reached from `sync.rs`. Same shape as above.
    #[tokio::test]
    async fn cat_against_silent_endpoint_errors_within_its_own_timeout() {
        let endpoint = crate::test_support::silent_http_endpoint().await;
        let inner = tokio::time::timeout(Duration::from_secs(30), cat(&endpoint, "bafkqaaa"))
            .await
            .expect(
                "cat must return before the outer 30s timeout — an unbounded client hangs here",
            );
        assert!(
            inner.is_err(),
            "a silent endpoint must surface as a transport error, not successful bytes"
        );
    }

    /// The permit-hold bound. `pin_new_objects` runs under a deferring
    /// `pin_semaphore`, so without a batch deadline the hold is O(N) with N
    /// chosen by the pusher. Five objects against an endpoint that takes 2s
    /// each, under a 5.5s budget, must stop partway: only the first two can
    /// finish inside the budget, so the batch is truncated and the remainder is
    /// left unattempted with one warn naming how many.
    ///
    /// The windows are deliberately loose. Three pins would need every add to
    /// answer in under 1.83s, which the endpoint's own 2s sleep forbids, and one
    /// pin needs only the first add to land inside 5.5s, so both bounds hold
    /// with more than a second of slack on a loaded box.
    #[sqlx::test]
    async fn pin_new_objects_stops_the_batch_at_its_deadline(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("slow.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let endpoint = delaying_endpoint(vec![Duration::from_secs(2)]).await;

        let (logs, _guard) = capture_logs();
        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-batch-budget",
                Duration::from_millis(5500),
            ),
        )
        .await
        .expect("wedge guard: a 5.5s budget cannot take 30s");

        assert!(
            (1..=3).contains(&pinned.len()),
            "the batch must stop partway, not pin all five and not stall on the first: pinned {}",
            pinned.len()
        );
        let text = logs.text();
        let warns: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("pin batch deadline reached"))
            .collect();
        assert_eq!(
            warns.len(),
            1,
            "the deadline must be reported exactly once for the batch, not per object: {text}"
        );
        let unattempted: usize = warns[0]
            .split("unattempted=")
            .nth(1)
            .and_then(|s| {
                s.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|d| d.parse().ok())
            })
            .unwrap_or_else(|| panic!("the deadline warn must name the unattempted count: {text}"));
        assert!(
            unattempted >= 1 && unattempted + pinned.len() <= 5,
            "unattempted={unattempted} with {} pinned is not a partial batch of five",
            pinned.len()
        );
    }

    /// The must-not case, and the regression that killed the old transport
    /// classifier: an endpoint that is slow but genuinely alive must NOT cost
    /// the rest of the batch. The first add takes 13s, past the shared client's
    /// 10s ceiling, which is exactly what the classifier used to read as a dead
    /// endpoint; the second is immediate. Under a 90s budget both must pin, so
    /// this fails if the per-request timeout is left at the client default and
    /// fails if any error arm breaks the loop. Two objects, not one, because
    /// with one object "did not abandon the rest" would be vacuous.
    #[sqlx::test]
    async fn pin_new_objects_does_not_abandon_the_batch_on_a_slow_but_alive_endpoint(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("slow_alive.git");
        let oids = seed_loose_blobs(&repo_path, 2);
        let endpoint =
            delaying_endpoint(vec![Duration::from_secs(13), Duration::from_millis(0)]).await;

        let pinned = tokio::time::timeout(
            Duration::from_secs(60),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-batch-continues",
                Duration::from_secs(90),
            ),
        )
        .await
        .expect("wedge guard: a 13s add plus an immediate one cannot take 60s");
        assert_eq!(
            pinned.len(),
            2,
            "a slow but progressing endpoint must pin both objects: an upload past the client's \
             10s default is not a dead endpoint"
        );
    }

    /// The must-not case for the warn-and-continue arm: a live endpoint
    /// rejecting each object with `500` is a per-object failure, so the loop
    /// must still warn and continue and every object must be attempted. Without
    /// this, a `break` arm could be reintroduced and the deadline test above
    /// would not notice.
    #[sqlx::test]
    async fn pin_new_objects_continues_past_a_per_object_rejection(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("rejecting.git");
        let oids = seed_loose_blobs(&repo_path, 4);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint = rejecting_endpoint(std::sync::Arc::clone(&requests)).await;

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-batch-rejects",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("a rejecting endpoint answers immediately, so this cannot take 30s");
        assert!(pinned.is_empty(), "every add was rejected");
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "a non-2xx rejection is per-object: all four objects must still be attempted"
        );
    }

    /// Write an executable `/bin/sh` script. Copied per module rather than shared:
    /// `store.rs` and `visibility_pack.rs` each keep their own, since their test mods
    /// are private and not reachable from here.
    #[cfg(unix)]
    fn write_script(path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).expect("write fake git");
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }

    /// A `git_bin` wrapper that records every invocation's arguments and then execs
    /// the real git, so a test can tell which objects the loop actually attempted.
    /// The returned pin list cannot: it is empty both when the loop broke after one
    /// object and when it continued past all of them.
    #[cfg(unix)]
    fn counting_git(dir: &std::path::Path, log: &std::path::Path) -> String {
        let fake = dir.join("counting-git");
        write_script(
            &fake,
            &format!(
                "#!/bin/sh\necho \"$*\" >> {}\nexec git \"$@\"\n",
                log.display()
            ),
        );
        fake.to_str().unwrap().to_string()
    }

    /// How many objects the loop actually attempted, read off the invocation log.
    ///
    /// Counts `--batch-check` invocations, not log lines and not oid occurrences: the
    /// type probe carries its oid on stdin rather than in argv, so an oid appears in
    /// the log only once an object has already got past its probe, and a healthy
    /// object costs two invocations to a faulting one's one.
    fn objects_attempted(log: &std::path::Path) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("--batch-check"))
            .count()
    }

    /// #174 F3, the finding itself: the git read runs while the `pin_semaphore`
    /// permit is held, so a wedged `git cat-file` used to hold that permit for as
    /// long as the child lived, with no deadline and no reaping, on a path a pusher
    /// drives. With the read bounded, a git that never answers costs the batch its
    /// budget plus one watchdog teardown and no more.
    ///
    /// The fake traps SIGTERM and sleeps a BOUNDED 30s, following the fixture in
    /// `visibility_pack.rs`: with the deadline neutralized the read would otherwise
    /// leave the blocking closure and its child alive long after the test-level
    /// timeout fires, wedging the run instead of reporting a failure. The endpoint is
    /// never reached, since no object's bytes are ever produced.
    ///
    /// The batch ends on the BUDGET, not on the fault arm: the repo is a healthy bare
    /// store, so the timeout's `Transient` verdict is object-scoped and the loop moves on,
    /// only to find the budget spent. Capturing that warn is not decoration. `tracing`
    /// caches a callsite's interest globally the first time it is hit, and a hit from a
    /// thread with no subscriber caches it as never-interested for the whole binary, which
    /// silently blinds the deadline tests running beside this one.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_returns_by_budget_with_a_hung_git(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("wedged.git");
        let oids = seed_loose_blobs(&repo_path, 3);
        let fake = tmp.path().join("hanging-git");
        write_script(&fake, "#!/bin/sh\ntrap '' TERM\necho $$ > pid\nsleep 30\n");

        let (logs, _guard) = capture_logs();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(25),
            pin_new_objects(
                "http://127.0.0.1:9",
                &repo_path,
                fake.to_str().unwrap(),
                Duration::from_secs(30),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(2),
            ),
        )
        .await
        .expect(
            "a wedged git must not hold the pin permit past the batch budget: the read is \
             bounded and reaped, so this cannot reach the outer timeout",
        );
        let elapsed = started.elapsed();

        assert!(
            pinned.is_empty(),
            "a git that never answers cannot produce a pinned object: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "elapsed {elapsed:?} must stay inside the budget plus one watchdog teardown"
        );
        let text = logs.text();
        assert_eq!(
            text.lines()
                .filter(|l| l.contains("pin batch deadline reached"))
                .count(),
            1,
            "one wedged read must spend the whole budget and stop the batch there, exactly \
             once: {text}"
        );

        // The child's process group must be gone once the call returns; a bounded read
        // that leaves the child running has only moved the hold somewhere else.
        let pid: i32 = std::fs::read_to_string(repo_path.join("pid"))
            .expect("the fake git must have recorded its pid, or it was never on the read path")
            .trim()
            .parse()
            .unwrap();
        let mut gone = false;
        for _ in 0..200 {
            // SAFETY: kill(2) with signal 0 only probes existence; ESRCH means gone.
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            gone,
            "the reaped fake git ({pid}) must not outlive the call"
        );
    }

    /// [`PIN_READ_FLOOR`] itself, which nothing else in the suite makes load-bearing: with
    /// the floor at zero every test here still passes, because they all either finish
    /// inside their budget or run it down to nothing. The dead zone is the interesting
    /// region, a remainder that is nonzero but too small to cover a bounded read's
    /// teardown, and it takes a fixture built to land in it.
    ///
    /// The arithmetic, with `r` the time one healthy read costs: a 1500ms budget and a
    /// 700ms upload leave `800 - r` at the top of the second iteration, which is below the
    /// 1100ms floor for every `r`, while the first iteration's post-read gate needs only
    /// `r <= 400ms`. So the batch must stop after exactly one object, and it stops on the
    /// FLOOR rather than on exhaustion: 800ms is still a perfectly nonzero remainder, and a
    /// zero-floor gate would happily spend it spawning a child it cannot afford to reap.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_stops_when_the_remainder_falls_below_the_read_floor(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("floor.git");
        let oids = seed_loose_blobs(&repo_path, 3);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let endpoint = delaying_endpoint(vec![Duration::from_millis(700)]).await;

        let (logs, _guard) = capture_logs();
        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                &git_bin,
                Duration::from_secs(30),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_millis(1500),
            ),
        )
        .await
        .expect("wedge guard: a 1.5s budget cannot take 30s");

        // The named property first, so a regression reddens on it rather than on a
        // downstream count that a zero floor also happens to change.
        assert_eq!(
            objects_attempted(&log),
            1,
            "a remainder below the read floor must stop the batch, not buy a bounded child \
             that can only be spawned and reaped"
        );
        assert_eq!(
            pinned.len(),
            1,
            "the first object is inside the budget and must pin: {pinned:?}"
        );
        let text = logs.text();
        assert_eq!(
            text.lines()
                .filter(|l| l.contains("pin batch deadline reached"))
                .count(),
            1,
            "the truncation must be reported exactly once: {text}"
        );
    }

    /// A store-wide fault breaks the batch instead of amplifying it. When the object
    /// store itself cannot be read every remaining object fails identically, so
    /// continuing would spawn one doomed bounded child per object and burn the budget
    /// on reaping them.
    ///
    /// The fixture looks wrong and is not: with the objects LOOSE and only
    /// `objects/pack` unreadable, git still resolves each object, but it prints an
    /// `error:` diagnostic that the probe routes to a fault before the present/missing
    /// parse, so the read reaches `classify_store_fault` and (the store being
    /// unreadable) returns `Transient`.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_breaks_the_batch_on_an_unreadable_store(pool: sqlx::PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("unreadable.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;

        let pack_dir = repo_path.join("objects").join("pack");
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&pack_dir).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&pack_dir, perms).unwrap();
        };
        chmod(0o000);
        // Root bypasses permission bits, so witness the exact operation the probe
        // performs and skip rather than falsely fail.
        let genuinely_unreadable = std::fs::read_dir(&pack_dir).is_err();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                &git_bin,
                Duration::from_secs(30),
                oids.clone(),
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an immediately-faulting store cannot take 30s");
        let attempted = objects_attempted(&log);
        chmod(0o755); // restore BEFORE any assertion that can panic, so TempDir cleans up

        if genuinely_unreadable {
            assert!(
                pinned.is_empty(),
                "nothing can be pinned through a store that cannot be read: {pinned:?}"
            );
            assert_eq!(
                attempted, 1,
                "a store-wide fault must break the batch after the first object, not spawn \
                 one doomed bounded child per object: {attempted} of 5 objects were read"
            );
        }
    }

    /// The failure mode the store-wide re-check exists for. A `Transient` fault does not
    /// prove the store is gone: the readability verdict is judged FOR one oid, so a single
    /// unreadable `objects/<xx>` fan-out (1/256 of the store) taints only the objects that
    /// live in it. Breaking there forfeits every remaining object over a fault that costs
    /// at most a few of them, and permanently: the documented recovery re-derives the same
    /// list and breaks at the same index.
    ///
    /// Exactly ONE fan-out dir is chmod'd, and the expected pin count is derived from the
    /// oids that actually land in it rather than assumed to be one: two seeded blobs can
    /// share a fan-out prefix, and hardcoding "four must pin" would make this test flap on
    /// a collision instead of reporting it.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_continues_past_one_unreadable_fanout_dir(pool: sqlx::PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("one_bad_fanout.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;

        let prefix = oids[0][0..2].to_string();
        let tainted: Vec<String> = oids.iter().filter(|o| o[0..2] == prefix).cloned().collect();
        assert!(
            tainted.len() < oids.len(),
            "the fixture must leave healthy objects outside the tainted fan-out, or this \
             test cannot tell an object-scoped fault from a store-wide one"
        );

        let fanout = repo_path.join("objects").join(&prefix);
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&fanout).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&fanout, perms).unwrap();
        };
        chmod(0o000);
        // Root bypasses permission bits, so witness the exact operation the probe performs
        // (an open of this oid's loose path) and skip rather than falsely fail.
        let genuinely_unreadable = std::fs::File::open(fanout.join(&oids[0][2..])).is_err();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                &git_bin,
                Duration::from_secs(30),
                oids.clone(),
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an immediate endpoint and four healthy objects cannot take 30s");
        let attempted = objects_attempted(&log);
        chmod(0o755); // restore BEFORE any assertion that can panic, so TempDir cleans up

        if genuinely_unreadable {
            assert_eq!(
                attempted,
                oids.len(),
                "one unreadable fan-out is 1/256 of the store, not the store: every object \
                 must still be attempted, got {attempted} of {}",
                oids.len()
            );
            let pinned_shas: Vec<&String> = pinned.iter().map(|(sha, _)| sha).collect();
            let expected: Vec<&String> = oids.iter().filter(|o| !tainted.contains(o)).collect();
            assert_eq!(
                pinned_shas, expected,
                "every object outside the tainted fan-out must pin, and only those"
            );
        }
    }

    /// The must-not direction of the arm above: an object-scoped fault must NOT break
    /// the batch. One corrupt loose object among healthy ones is a `Deterministic`
    /// fault (the store is readable, git still fails), and the documented recovery path
    /// cannot repair it: a later full-scan push re-offers the same object and would
    /// break at the same place, so breaking here stops the repo pinning permanently.
    ///
    /// Deliberately not the bad-config corruption, which is repo-wide: all five objects
    /// would fault and the test would pin the store-wide case rather than the
    /// object-scoped one this arm rests on.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_continues_past_a_deterministic_fault(pool: sqlx::PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("corrupt.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;

        // Overwrite exactly one loose object with non-zlib garbage (0o444 by default).
        let victim = repo_path
            .join("objects")
            .join(&oids[0][0..2])
            .join(&oids[0][2..]);
        assert!(victim.is_file(), "fixture must leave the blob loose");
        let mut perms = std::fs::metadata(&victim).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&victim, perms).unwrap();
        std::fs::write(&victim, b"garbage not a zlib stream").unwrap();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                &git_bin,
                Duration::from_secs(30),
                oids.clone(),
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an immediate endpoint and four healthy objects cannot take 30s");

        assert_eq!(
            objects_attempted(&log),
            5,
            "an object-scoped fault must not stop the batch: every object must be read"
        );
        assert_eq!(
            pinned.len(),
            4,
            "one corrupt object must cost only itself: the other four must still pin"
        );
    }

    // ---------------------------------------------------------------------
    // F3 (#173, jatmn): the DB operations inside the budgeted region.
    //
    // `api/repos.rs` holds the GLOBAL `pin_semaphore` permit across the whole
    // `pin_new_objects` call. `batch_budget_gate` only gates BETWEEN objects and
    // the git read is already clamped, but every DB call in the region used to be
    // a bare await, so one stalled query parked the permit past every budget and,
    // once all pin permits were so held, post-push IPFS replication stopped for
    // every repo on the node. The tests below drive that stall with a
    // `LOCK TABLE .. IN ACCESS EXCLUSIVE MODE` held on a dedicated pooled
    // connection, the same technique as `get_by_cid_stalled_metadata_query_frees_
    // walk_permit` in api/ipfs.rs, and copy its tolerances (a ~1s budget, an
    // `elapsed < 3s` assertion, a 10s outer wrap). Pre-fix each one blocks on the
    // lock until the outer wrap fires.
    // ---------------------------------------------------------------------

    /// Take an `ACCESS EXCLUSIVE` lock on `table` on a dedicated pooled connection.
    /// Every SELECT needs `ACCESS SHARE`, which conflicts, so the next statement
    /// touching the table blocks at lock acquisition regardless of row count.
    async fn lock_table(
        pool: &sqlx::PgPool,
        table: &str,
    ) -> sqlx::pool::PoolConnection<sqlx::Postgres> {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::raw_sql(&format!(
            "BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE;"
        ))
        .execute(&mut *conn)
        .await
        .unwrap();
        conn
    }

    async fn rollback(conn: &mut sqlx::pool::PoolConnection<sqlx::Postgres>) {
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut **conn)
            .await
            .unwrap();
    }

    /// A raw CIDv1 to seed a pin with, so the opportunistic legacy repair takes its
    /// cost gate and reads no bytes. The value only has to be a canonical raw key.
    fn seed_cid() -> String {
        Cid::from_git_object_bytes(b"pin loop seed").to_string()
    }

    /// The helper's zero-remainder path, where the absolute deadline is the whole
    /// point: a spent deadline must error immediately rather than hand the call a
    /// fresh budget.
    ///
    /// This is a unit test rather than a loop-driven one on purpose. Driving a ~0
    /// `batch_budget` through `pin_new_objects` is VACUOUS: `batch_budget_gate`
    /// returns None below [`PIN_READ_FLOOR`] as the first statement of the loop body,
    /// so the batch breaks before any DB call and the test passes identically with
    /// `db_bounded` deleted. The helper is tested where the zero-remainder path
    /// actually runs.
    #[tokio::test]
    async fn db_bounded_elapsed_deadline_errors_promptly() {
        let spent = Instant::now() - Duration::from_secs(5);
        let started = std::time::Instant::now();
        let out: Result<u8, BoundedDbError> = db_bounded(spent, async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(7u8)
        })
        .await;

        assert!(
            matches!(out, Err(BoundedDbError::Elapsed)),
            "a spent deadline must yield the DISTINGUISHABLE timeout arm, not a value \
             and not a generic DB error: {out:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a spent deadline must error at once, not after a fresh full budget; got {:?}",
            started.elapsed()
        );
    }

    /// The ABSOLUTE half of the same helper, which no loop-level test actually binds.
    ///
    /// `db_bounded` takes an `Instant`, not a `Duration`, so every call sharing one
    /// deadline shares ONE budget: whatever an earlier call spends, a later one no
    /// longer has. `pin_new_objects_multi_object_stall_charges_one_budget` covers that
    /// end to end, but it only goes red under a per-call duration LARGER than the batch
    /// budget (its mutation grants `PIN_BATCH_BUDGET`, 120s, against a 1.5s budget). A
    /// defect that handed every call a fresh duration at or below the budget would slip
    /// straight past it, so the property is bound here instead, where it lives and where
    /// no lock, endpoint, or budget gate stands between the assertion and the helper.
    ///
    /// Two calls against one 3s deadline: the first spends 2s and succeeds, so the
    /// second sees ~1s left and must elapse even though its own work needs only 2s.
    /// Any fresh per-call duration of 2s or more, INCLUDING one exactly equal to the 3s
    /// budget, would return a value there instead.
    #[tokio::test]
    async fn db_bounded_shares_one_budget_across_sequential_calls() {
        let deadline = Instant::now() + Duration::from_secs(3);

        let first: Result<u8, BoundedDbError> = db_bounded(deadline, async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(1u8)
        })
        .await;
        assert!(
            matches!(first, Ok(1)),
            "the first call fits well inside the shared budget and must return its \
             value: {first:?}"
        );

        let started = std::time::Instant::now();
        let second: Result<u8, BoundedDbError> = db_bounded(deadline, async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(2u8)
        })
        .await;

        assert!(
            matches!(second, Err(BoundedDbError::Elapsed)),
            "a SHARED deadline is consumed by the calls before it: with ~1s of the 3s \
             left, a 2s call must elapse. A fresh per-call DURATION would let it \
             succeed even when that duration is exactly the budget, and N calls would \
             then charge N budgets instead of one: {second:?}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "the second call must be cut off by the REMAINDER (~1s) rather than run its \
             full 2s; got {:?}",
            started.elapsed()
        );
    }

    /// Scenario 1: the FIRST DB call in the region (`is_pinned`) stalls. With the
    /// batch deadline bounding it the loop abandons the object, the budget gate
    /// then breaks the batch, and the call returns at ~budget with nothing pinned.
    /// Pre-fix the bare await blocks on the lock for the lock's whole lifetime,
    /// holding the caller's global pin permit with it.
    #[sqlx::test]
    async fn pin_new_objects_stalled_db_returns_by_budget(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("stalled.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;
        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut lock = lock_table(&pool, "pinned_cids").await;

        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(10),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-stalled-db",
                Duration::from_millis(1500),
            ),
        )
        .await
        .expect(
            "a stalled DB must cost the batch its budget, not the lock's lifetime: the \
             bare await hangs past this wrap",
        );
        let elapsed = started.elapsed();

        assert!(
            pinned.is_empty(),
            "a stalled pinned-status check cannot produce a pinned object: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the batch deadline must end the call at ~budget (1.5s); got {elapsed:?}"
        );

        rollback(&mut lock).await;
    }

    /// Scenario 2, and the sharpest unknown-outcome must-not. The object is already
    /// pinned, so the loop takes the skip branch and tries to record this repo as an
    /// additional source; `pin_repo_sources` is locked, so that insert stalls inside
    /// `retry_db_record`. Two properties:
    ///
    /// - the whole retry ladder (three attempts plus backoff) lives inside ONE
    ///   remainder, so the call still returns promptly;
    /// - on the TIMEOUT arm the incomplete marker is NOT written. A cancelled client
    ///   future does not cancel the statement Postgres is running, so the source may
    ///   well be recorded; the marker would force every later `/ipfs` request for the
    ///   object onto the O(repos) legacy scan, from any unauthenticated caller, on the
    ///   strength of an outcome the code does not know. Only the definite-error arm
    ///   marks incomplete.
    ///
    /// The record site carries the durability floor, so the return lands at ~2s
    /// rather than at the 1.5s budget; that is the floor working, not a missed bound.
    #[sqlx::test]
    async fn pin_new_objects_skip_branch_stalled_record_returns_by_budget(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("skip_stalled.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();
        db.record_pinned_cid_with_source(&sha, &seed_cid(), "repo-seed")
            .await
            .unwrap();
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;
        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut lock = lock_table(&pool, "pin_repo_sources").await;

        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(10),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-skip-stalled",
                Duration::from_millis(1500),
            ),
        )
        .await
        .expect(
            "the wrapped retry ladder must fit inside one remainder: the bare \
             retry_db_record hangs past this wrap",
        );
        let elapsed = started.elapsed();

        assert!(
            pinned.is_empty(),
            "an already-pinned object is skipped, never re-pinned: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the record's floored remainder must end the call promptly; got {elapsed:?}"
        );

        rollback(&mut lock).await;
        drop(lock);

        assert!(
            db.pin_sources_incomplete(&sha).await.unwrap(),
            "a TIMED-OUT `record_pin_source` definitively did not land: it is an explicit \
             multi-statement transaction, and the cancelled future never reaches \
             `tx.commit()`, so no COMMIT is ever sent and the row cannot exist. The set is \
             therefore incomplete, and leaving it UNMARKED is the exact state the marker \
             exists to prevent: the resolver reads a non-empty below-cap set as complete \
             and 404s a copy this repo would serve"
        );
    }

    /// Scenario 7: three objects, one budget. Every object's first DB call stalls on
    /// the same lock, and the total must stay near ONE budget rather than one per
    /// object. This is the only loop-level scenario where an absolute-deadline bound
    /// and a per-call duration could differ; every single-object stall test above
    /// passes under either.
    #[sqlx::test]
    async fn pin_new_objects_multi_object_stall_charges_one_budget(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("multi_stalled.git");
        let oids = seed_loose_blobs(&repo_path, 3);
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;
        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut lock = lock_table(&pool, "pinned_cids").await;

        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(10),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-multi-stalled",
                Duration::from_millis(1500),
            ),
        )
        .await
        .expect("three stalled objects must still cost one budget, not three");
        let elapsed = started.elapsed();

        assert!(pinned.is_empty(), "nothing can pin against a stalled DB");
        assert!(
            elapsed < Duration::from_secs(3),
            "three stalled objects must charge ONE budget (1.5s), not one each; got {elapsed:?}"
        );

        rollback(&mut lock).await;
    }

    /// Scenario 8, Kubo half of the durability floor. `batch_budget_gate` only
    /// guarantees `PIN_READ_FLOOR` before an object STARTS and the add is handed the
    /// whole remainder, so a successful add can finish with ~0 left. Without the
    /// floor the post-add record would then be failed by a spent deadline, leaving
    /// bytes in Kubo with no `pinned_cids` row and nothing able to resolve the CID.
    ///
    /// Fixture: a 2s budget, a 1.7s add, and `pinned_cids` locked from 500ms (well
    /// after `is_pinned` has read it, and still well before the add returns) until
    /// 2.4s. The record therefore starts at ~1.72s with ~280ms of budget left and
    /// needs ~680ms of lock wait to land, which only the `DB_RECORD_GRACE` floor buys
    /// it.
    ///
    /// The lock time is a MARGIN, not a boundary: taking it at 100ms left `is_pinned`
    /// racing it on a loaded box, and losing that race makes the read block, time out,
    /// and break the batch, which fails on `pinned.len() == 1` for a reason that has
    /// nothing to do with the floor. Any time between the `is_pinned` round trip and
    /// the add's 1.7s return proves the same thing.
    #[sqlx::test]
    async fn pin_add_with_spent_budget_still_records_row(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("spent_budget.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();
        let endpoint = delaying_endpoint(vec![Duration::from_millis(1700)]).await;
        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let lock_pool = pool.clone();
        let locker = async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let mut conn = lock_table(&lock_pool, "pinned_cids").await;
            tokio::time::sleep(Duration::from_millis(1900)).await;
            rollback(&mut conn).await;
        };

        let pin = tokio::time::timeout(
            Duration::from_secs(15),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids.clone(),
                &db,
                "repo-spent-budget",
                Duration::from_millis(2000),
            ),
        );
        let (pinned, ()) = tokio::join!(pin, locker);
        let pinned = pinned.expect("the floored record must land well inside this wrap");

        assert!(
            db.is_pinned(&sha).await.unwrap(),
            "a successful add whose batch deadline is spent must still land its \
             pinned_cids row: without the floor the bytes sit in Kubo with no row and \
             nothing can resolve the CID"
        );
        assert_eq!(
            pinned.len(),
            1,
            "the durably recorded pin must be returned: {pinned:?}"
        );
    }

    /// Scenario 8, the other direction of the floor: the skip branch's DEFINITE-error
    /// arm with the budget already spent must still write the incomplete marker.
    /// Without it the source set is incomplete AND unmarked, which is exactly the
    /// state the marker exists to prevent: the resolver reads a non-empty below-cap
    /// set as complete and 404s an object this repo would serve.
    ///
    /// The definite error is a dropped `pin_repo_sources`, not a timeout: the DROP
    /// runs inside a transaction that commits at 1.5s, so the insert blocks on that
    /// transaction's lock and then fails outright. With a 1.2s budget the retry
    /// ladder therefore returns its definite error at ~1.6s, past the deadline, and
    /// only the floor lets the marker write run at all.
    #[sqlx::test]
    async fn pin_skip_branch_definite_error_with_spent_budget_marks_incomplete(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("definite_error.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();
        db.record_pinned_cid_with_source(&sha, &seed_cid(), "repo-seed")
            .await
            .unwrap();
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;
        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut dropper = pool.acquire().await.unwrap();
        sqlx::raw_sql("BEGIN; DROP TABLE pin_repo_sources;")
            .execute(&mut *dropper)
            .await
            .unwrap();

        let commit = async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            sqlx::raw_sql("COMMIT")
                .execute(&mut *dropper)
                .await
                .unwrap();
        };

        let pin = tokio::time::timeout(
            Duration::from_secs(15),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-definite-error",
                Duration::from_millis(1200),
            ),
        );
        let (pinned, ()) = tokio::join!(pin, commit);
        pinned.expect("a definite DB error resolves inside the record floor, not the wrap");

        assert!(
            db.pin_sources_incomplete(&sha).await.unwrap(),
            "the DEFINITE-error arm must still mark the source set incomplete with the \
             batch deadline spent: an incomplete-and-unmarked set is read as complete and \
             404s an object this repo would serve"
        );
    }

    /// The MARKER's own floor, which the two tests above leave unbound.
    ///
    /// Both of them assert the marker lands with the batch deadline spent, and both
    /// pass with the marker's `db_record_deadline` replaced by the bare `deadline`.
    /// The reason is timing, not coverage: the remainder there really is ~0, but
    /// `tokio::time::timeout` polls the inner future before it checks the timer, and a
    /// local Postgres UPDATE against an uncontended table round-trips inside that one
    /// poll. So the unfloored write lands anyway and the floor is never load-bearing.
    ///
    /// This makes the marker write SLOW, so a zero bound cannot smuggle it through.
    /// `mark_pin_sources_incomplete` is `UPDATE pinned_cids`, so `pinned_cids` is held
    /// under `ACCESS EXCLUSIVE` from 300ms (after `is_pinned` and `provenance_for_oid`
    /// have read it, both round trips inside the first few ms) until 3s.
    ///
    /// The schedule, with a 1.5s budget and `pin_repo_sources` locked for the whole
    /// run so the source record stalls:
    ///
    /// - ~10ms: `record_pin_source` starts and blocks on the sources lock. Its own
    ///   floored bound is `now + 2s`, so it elapses at ~2.01s;
    /// - ~2.01s: the elapsed arm runs the marker write, which blocks on the
    ///   `pinned_cids` lock. Floored, its bound is ~4.01s; unfloored it is the spent
    ///   1.5s batch deadline, so the bound is ~0 and the blocked UPDATE is cancelled at
    ///   once, leaving no marker;
    /// - ~3.0s: the lock lifts, a full second after the write started and a full second
    ///   before its floored bound expires, so the floored write lands.
    ///
    /// Both margins are a full second on purpose. The proof only needs the release to
    /// fall strictly between zero and `DB_RECORD_GRACE`, so there is no reason to put
    /// it near either end and make the test a race.
    #[sqlx::test]
    async fn pin_skip_branch_marker_write_needs_the_record_floor(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("marker_floor.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();
        db.record_pinned_cid_with_source(&sha, &seed_cid(), "repo-seed")
            .await
            .unwrap();
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;
        // Asserted on here, and installed for the sibling reason too: `tracing` caches
        // a callsite's interest globally on first hit, so a hit from a thread with no
        // subscriber caches it as never-interested for the whole binary.
        let (logs, _log_guard) = capture_logs();

        let mut sources_lock = lock_table(&pool, "pin_repo_sources").await;

        let lock_pool = pool.clone();
        let controller = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let mut cids_lock = lock_table(&lock_pool, "pinned_cids").await;
            tokio::time::sleep(Duration::from_millis(2700)).await;
            rollback(&mut cids_lock).await;
        };

        let started = std::time::Instant::now();
        let pin = tokio::time::timeout(
            Duration::from_secs(20),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-marker-floor",
                Duration::from_millis(1500),
            ),
        );
        let (pinned, ()) = tokio::join!(pin, controller);
        let pinned = pinned.expect("the floored marker write must land well inside this wrap");
        let elapsed = started.elapsed();

        rollback(&mut sources_lock).await;
        drop(sources_lock);

        assert!(
            pinned.is_empty(),
            "an already-pinned object is skipped, never re-pinned: {pinned:?}"
        );
        assert!(
            logs.text()
                .contains("did not complete inside the batch deadline"),
            "the fixture only proves anything if the marker was reached from the ELAPSED \
             arm of the source record, not from the definite-error arm: {}",
            logs.text()
        );
        assert!(
            elapsed < Duration::from_secs(8),
            "the call must end at one budget plus the one chained record grace the \
             blocked marker write costs (~3s), never at the lock's lifetime; got \
             {elapsed:?}"
        );
        assert!(
            db.pin_sources_incomplete(&sha).await.unwrap(),
            "the marker write must be given DB_RECORD_GRACE, not the spent batch \
             deadline: it starts here with ~0 of the budget left and needs ~1s to get \
             past the lock, so an unfloored bound cancels it and the source set is left \
             incomplete AND unmarked, which the resolver reads as complete and 404s a \
             copy this repo would serve"
        );
    }

    /// The TRANSITIVE site. `repair_legacy_provider_cid` runs on the skip branch under
    /// the same permit, and its own `deadline` argument used to bound only the
    /// `spawn_blocking` git read: the two DB awaits inside it (`cid_for_oid` and the
    /// key rewrite) were bare, so a stall there parked the permit exactly the way the
    /// loop-body awaits did. A grep over the loop bodies cannot see this site, which
    /// is why it is driven here rather than argued.
    ///
    /// Fixture, ordered so the stall lands on `cid_for_oid` and nothing earlier:
    /// `pin_repo_sources` is locked from the start so the skip branch's source record
    /// blocks; at 1.5s `pinned_cids` is locked (nothing is reading it by then) and at
    /// 1.6s the first lock is released.
    ///
    /// What the loop actually does with that, since the timing is easy to misread: when
    /// the `pin_repo_sources` lock lifts at 1.6s the insert succeeds, and then
    /// `record_pin_source`'s follow-up `UPDATE pinned_cids` immediately blocks on the
    /// `pinned_cids` lock taken at 1.5s and eats the rest of the budget, elapsing at
    /// 2.2s. The timeout arm then writes the incomplete marker, another `UPDATE
    /// pinned_cids`, which blocks on the same lock and elapses against its own floor at
    /// ~4.2s. So the repair is reached with its deadline long SPENT, not with ~600ms
    /// left, and ~4.2s is the fixture's expected total: one budget plus one chained
    /// record grace, which is the `db_record_deadline` re-flooring described on
    /// `pin_new_objects`.
    ///
    /// The test is load-bearing either way, and the 10s wrap is what makes it so: the
    /// `pinned_cids` lock is held until after the call returns, so an unbounded
    /// `cid_for_oid` inside the repair hangs past the wrap instead of returning here.
    #[sqlx::test]
    async fn pin_new_objects_stalled_legacy_repair_lookup_returns_by_budget(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("repair_stalled.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();
        db.record_pinned_cid_with_source(&sha, &seed_cid(), "repo-seed")
            .await
            .unwrap();
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;
        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut sources_lock = lock_table(&pool, "pin_repo_sources").await;

        let lock_pool = pool.clone();
        let controller = async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let cids_lock = lock_table(&lock_pool, "pinned_cids").await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            rollback(&mut sources_lock).await;
            cids_lock
        };

        let started = std::time::Instant::now();
        let pin = tokio::time::timeout(
            Duration::from_secs(10),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-repair-stalled",
                Duration::from_millis(2200),
            ),
        );
        let (pinned, mut cids_lock) = tokio::join!(pin, controller);
        pinned.expect(
            "the repair's own DB lookup must be bounded by the batch deadline: the bare \
             await hangs past this wrap",
        );
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_secs(6),
            "a stall inside repair_legacy_provider_cid must end the call at ~budget \
             (2.2s) plus the one chained record grace the marker write costs against the \
             same lock (~4.2s), never at the lock's lifetime; got {elapsed:?}"
        );

        rollback(&mut cids_lock).await;
    }
}
