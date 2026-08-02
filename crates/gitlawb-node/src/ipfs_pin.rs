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
async fn repair_legacy_provider_cid(
    repo_path: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    sha: &str,
    db: &crate::db::Db,
) -> Result<RepairOutcome> {
    let stored = match db.cid_for_oid(sha).await? {
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
        tokio::task::spawn_blocking(move || {
            crate::git::store::read_object_bounded(&git_bin, &repo_path, &sha, git_timeout)
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
    db.repair_legacy_provider_cid(sha, &raw, &stored).await?;
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
    /// on this node's local disk, a DB read failed, a bounded object read failed). A
    /// nonzero count is what makes the run rewind its cursor instead of parking it at
    /// the end of the table forever. Rows that are unrepairable in principle (no
    /// provenance, the repo row is gone, the bytes are gone) are NOT counted here.
    pub retryable_skips: usize,
}

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
            match repair_legacy_provider_cid(&repo_path, git_bin, git_timeout, &sha, db).await {
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
    }

    db.set_pin_repair_cursor(&last).await?;
    Ok(SweepStats {
        scanned,
        repaired,
        passes: 1,
        retryable_skips,
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
/// A run that skipped at least one RETRYABLE row rewinds the cursor to the start of the
/// table on its way out (#173 round 11). Without that the cursor parked at the maximum
/// `sha256_hex` for good: every later boot read zero rows, so a row skipped for a
/// transient reason (its repo cold on a Tigris-backed node, a DB or object read error)
/// was skipped permanently, unadvertised and unresolvable with nothing left to fix it.
/// The rewind is a per-RUN decision made after the walk has already finished, never
/// mid-walk, so it cannot spin: the cost is one extra ordered scan on the next run, and
/// a row that is unrepairable in principle (bytes gone, provenance gone) does not count
/// as retryable, so a node holding one does not re-walk on every boot forever.
pub(crate) async fn sweep_legacy_provider_cids(
    repos_dir: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    batch: i64,
    delay: Duration,
    db: &crate::db::Db,
) -> SweepStats {
    let mut totals = SweepStats::default();
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
        totals.passes += 1;
        // A short batch means the ordered walk reached the end of the table. Stop here
        // rather than after an extra empty pass, and do NOT sleep on the way out.
        if (pass.scanned as i64) < batch {
            break;
        }
        tokio::time::sleep(delay).await;
    }
    if totals.retryable_skips > 0 {
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

/// The batch's remaining wall-clock, or `None` once it is spent, after logging
/// the truncation exactly once.
///
/// Shaped like `api::ipfs`'s `budget_gate` on purpose: the nonzero-ness rides in
/// the returned value, so every call site must consume it as
/// `let Some(x) = ... else { break }` and a zero `Duration` can never reach a
/// request as its timeout.
fn batch_budget_gate(deadline: Instant, pinned: usize, unattempted: usize) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        tracing::warn!(
            pinned,
            unattempted,
            "IPFS pin batch deadline reached; the remaining objects are left unpinned"
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
/// object's bytes. `repo_id` records the pin's provenance so `GET /ipfs/{cid}`
/// resolves straight to this repo instead of scanning every repo (#173).
///
/// # What `batch_budget` does and does not bound
///
/// The loop holds a `pin_semaphore` permit and that pool defers rather than
/// sheds, so the hold has to be bounded by something other than the pusher's
/// object count. Two things here are:
///
/// - this loop's own wall-clock: the deadline is taken once at loop start and
///   checked at the top of every iteration, so no object's work begins with zero
///   budget left. It is a gate, not a hard ceiling, since a started iteration
///   still runs to completion;
/// - each HTTP add: `pin_git_object` is handed the remainder measured at the top
///   of the iteration as its per-request timeout, which is what lets one large
///   healthy upload run past the shared client's 10s default without letting the
///   batch run forever. The DB check and the git read spend a little of that
///   remainder before the request starts, so the add can finish marginally after
///   the deadline.
///
/// Three things are NOT bounded, and the gate cannot fix any of them:
///
/// - the git read. `store::read_object` composes two bare
///   `std::process::Command::output()` calls with no timeout and no
///   process-group reaping, and this loop does not run it under
///   `spawn_blocking`, so one hung `git cat-file` overruns the deadline and
///   blocks a runtime worker thread while it does.
/// - the DB round-trips (`is_pinned`, `record_pinned_cid`).
/// - the pool. `api::repos` acquires the same `pin_semaphore` for the Pinata
///   replication task and holds it across a full git re-derivation plus
///   `pinata::pin_new_objects`, neither of which has a deadline. This change
///   bounds this loop's hold, not the semaphore's worst-case queue.
///
/// # Truncation semantics
///
/// A batch stopped at the deadline leaves its remaining objects unpinned, and
/// nothing sweeps them up afterwards. There is no reconciliation pass over
/// `pinned_cids`; recovery is opportunistic, happening only if some later push
/// on the repo takes the full-scan fallback (`push_delta::list_all_objects`) and
/// re-derives the whole object set, which then re-offers the skipped OIDs.
///
/// The twin in `pinata.rs` mirrors this loop's shape but NOT its bound: it has
/// no batch deadline and no per-request override, so the two are no longer at
/// parity here. Everything else about the shape (the skip-if-pinned check, the
/// provenance recording, the warn-and-continue arm, the returned pairs) still
/// changes in lockstep.
///
/// Returns a list of `(sha256_hex, cid)` pairs for objects pinned this call.
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
        // never started with zero budget left. The remainder becomes this add's
        // request timeout below.
        let Some(budget_left) = batch_budget_gate(deadline, pinned.len(), total - attempted) else {
            break;
        };
        // Skip if already pinned, but first backfill provenance if the existing
        // pin has none. A legacy pin (recorded before repo_id existed, #173, jatmn)
        // is skipped here before record_pinned_cid ever runs, so its NULL provenance
        // would never resolve to one repo and known CIDs keep hitting the scan. The
        // backfill only sets repo_id (AND repo_id IS NULL guard preserves
        // first-pinner-owns) and never re-pins the bytes: the object is already on IPFS.
        match db.is_pinned(&sha).await {
            Ok(true) => {
                match db.provenance_for_oid(&sha).await {
                    Ok(None) => {
                        if let Err(e) = db.backfill_pin_provenance(&sha, repo_id).await {
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
                if let Err(e) = retry_db_record(|| db.record_pin_source(&sha, repo_id)).await {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                    // U3 (#173): the retries are spent and this repo is NOT in the source
                    // set, so the set is known incomplete. Persist that, or the resolver
                    // reads a non-empty below-cap set as COMPLETE and 404s an object this
                    // repo would serve. Warn-only in turn: if the marker write also fails
                    // the object degrades to the pre-U3 behavior, never worse.
                    if let Err(e) = db.mark_pin_sources_incomplete(&sha).await {
                        tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                    }
                }
                // R8 (#173 round 10): opportunistically repair a legacy provider-CID
                // row (Kubo dag-pb / Pinata) to the raw-content resolver key on this
                // re-push. Cost-gated on the stored key's codec — a non-legacy row
                // reads no bytes. Warn-only: a failure leaves the row as-is for a
                // later re-push or the deferred one-shot sweep.
                if let Err(e) =
                    repair_legacy_provider_cid(repo_path, git_bin, git_timeout, &sha, db).await
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

        // Read raw object content under a bounded read so a wedged/D-state `git
        // cat-file` (stuck NFS/Tigris backend) is reaped at `git_timeout` instead of
        // hanging pin_new_objects forever — which would pin the post-push coalescing
        // key until process death (grok F2, #173). On Err the object is simply not
        // pinned this pass; a later pass/push retries.
        let data =
            match crate::git::store::read_object_bounded(git_bin, repo_path, &sha, git_timeout) {
                Ok(Some((_obj_type, bytes))) => bytes,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(sha = %sha, err = %e, "failed to read git object for pinning");
                    continue;
                }
            };

        // Pin to IPFS
        match pin_git_object(ipfs_api, &sha, &data, Some(budget_left)).await {
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
                // first pinner; atomically there is no such window, and a total failure
                // leaves the object unpinned so the next push retries the whole thing.
                if let Err(e) =
                    retry_db_record(|| db.record_pinned_cid_with_source(&sha, &raw_cid, repo_id))
                        .await
                {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pinned CID in DB");
                }
                // Return the provider Hash (not the resolver key), mirroring the pinata
                // twin's contract: the DB `cid` is the raw resolver key (recorded above),
                // the returned value is the provider CID. Here the return is consumed only
                // for logging, but keeping the twins structurally identical avoids drift.
                pinned.push((sha, cid));
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
}
