use rand::Rng;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

use crate::config::Config;
use crate::db::Db;

/// How often to run a sweep pass.
const SWEEP_INTERVAL_SECS: u64 = 3600;

/// Maximum repos to process per pass — prevents the sweep from becoming
/// the O(repos) amplification the admission-control work exists to prevent.
const REPOS_PER_PASS: usize = 100;

/// Maximum objects to pin per backend per repo in a single pass — prevents one
/// large repo from monopolizing the blocking pool or the hourly budget. Applied
/// after filtering out already-pinned objects so the cap reflects actual work.
const MAX_OBJECTS_PER_REPO: usize = 50_000;

/// Per-repo deadline for the blocking git scan (list_all_objects + visibility
/// filter).  A pathological repo that stalls past this is skipped for the pass.
const REPO_SCAN_DEADLINE: Duration = Duration::from_secs(300);

/// Per-repo deadline for the pinning phase (IPFS + Pinata uploads).  An
/// unavailable backend that stalls per-object must not hold the sweep for
/// the entire backlog; this bounds the wall time of each pinning PHASE.
///
/// The phases do NOT share one budget (R2-P3): the scan, the mid-scan
/// visibility re-filter, the per-backend pin-boundary authorization
/// re-derivation, the withheld-blob walk, and each pin/seal phase each get
/// their own `REPO_SCAN_DEADLINE` / `PIN_PHASE_DEADLINE`. A repo's worst case
/// is therefore ADDITIVE, up to ~30min in pathological conditions (scan 5m +
/// mid-scan re-filter 5m + authz re-derivation 5m + withheld walk 5m + public
/// pin 5m + encrypted seal 5m), not bounded at a single deadline. That is a
/// deliberate trade: starving a later phase of the budget the scan consumed
/// would silently disable the authorization check or the recovery-copy seal
/// for exactly the large repos the sweep exists for. The sweep runs hourly
/// and each phase is still individually bounded, so a pathological repo delays
/// other repos by at most that phase, not the hour.
const PIN_PHASE_DEADLINE: Duration = Duration::from_secs(300);

/// node_state key under which the sweep's keyset cursor is persisted across
/// restarts (R2-P1).
const CURSOR_KEY: &str = "reconciliation_sweep_cursor";

/// Log message emitted when the Irys anchor call fails after a successful
/// seal. The contract is one-shot: `plan_seal` returns `SkipUnchanged` on
/// every subsequent pass once the recipients tag matches, so a failed
/// anchor here is permanent until a withheld change forces a new seal.
/// Factored to a const so the test
/// `encrypted_manifest_anchor_log_does_not_promise_retry` can pin the
/// "no retry promised" property at the cargo-test level.
const ENCRYPTED_MANIFEST_ANCHOR_FAILED_MSG: &str =
    "encrypted manifest anchor failed; this seal will NOT be \
     retried on a later pass (plan_seal returns SkipUnchanged \
     when the recipients tag is stable). A subsequent withheld \
     change forces a new seal and re-anchors the manifest.";

/// Per-backend continuation-cursor progress, expressed as an
/// effect-side state machine (#218 review round 9, guidance #4).
/// The tri-state `Option<Option<String>>` is the wire form; this
/// enum is the documented shape the closure maps from.
///
/// The contract: a cursor must reflect EFFECT, not plan. A
/// pre-dispatch failure (fence capture failed, refilter returned
/// `None`, dispatch produced an empty `to_pin`) cannot look like
/// work completed — the unattempted prefix must retry at the
/// head of the next pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProgressState {
    /// No work was attempted this pass (fence capture failed,
    /// refilter returned `None`, dispatch produced an empty
    /// `to_pin`). The cursor is preserved — the unattempted
    /// prefix retries at the head of the next pass.
    Idle,
    /// A subset of the cap was dispatched. The next pass
    /// rotates past `last_dispatched`, retrying everything
    /// beyond.
    Advanced { last_dispatched: String },
    /// The missing set was empty. The cursor is cleared
    /// (a future pass sees a fresh start).
    Drained,
}

impl ProgressState {
    /// Map the three states to the wire form: `Some(value)` for
    /// a write, `None` for "leave the row alone".
    ///
    /// The function [`next_offset_write`] is the same logic in
    /// callable form; this method exists so a future caller
    /// that has a `ProgressState` in hand (rather than the
    /// inputs to `next_offset_write`) can convert without
    /// re-deriving the decision.
    pub(crate) fn to_wire(&self) -> Option<Option<String>> {
        match self {
            ProgressState::Idle => None,
            ProgressState::Advanced { last_dispatched } => Some(Some(last_dispatched.clone())),
            ProgressState::Drained => Some(None),
        }
    }
}

/// The next-offset decision. Called by `run_pass` at the
/// cursor-write site and exposed at module scope so a test can
/// drive it with known `(scan_ok, had_work, dispatched)` triples
/// and assert that the returned `ProgressState` (and its
/// `to_wire()`) is what the cursor-write site will land. P2
/// (reviewer round 9): the previous test never called the
/// closure, so the wire-form test pinned itself to its own
/// arm-by-arm reproduction. Now there is one encoding and the
/// test calls the function under test.
pub(crate) fn next_offset_write(
    scan_ok: bool,
    had_work: bool,
    dispatched: Option<String>,
) -> ProgressState {
    if !scan_ok {
        ProgressState::Idle
    } else if let Some(last) = dispatched {
        ProgressState::Advanced {
            last_dispatched: last,
        }
    } else if !had_work {
        ProgressState::Drained
    } else {
        ProgressState::Idle
    }
}

/// Whether the sweep should spawn given the current configuration.
/// Extracted for testing — test both directions independently.
fn should_spawn(config: &Config) -> bool {
    if !config.reconciliation_sweep {
        return false;
    }
    !config.ipfs_api.is_empty() || !config.pinata_jwt.is_empty()
}

/// Spawn the periodic reconciliation sweep background task.
/// No-op when neither IPFS nor Pinata is configured, or when
/// `reconciliation_sweep` is disabled. Returns `true` when the worker was
/// actually spawned so the caller can gate its own "worker started" logging.
pub fn spawn(
    db: Arc<Db>,
    config: Arc<Config>,
    http_client: Arc<reqwest::Client>,
    node_keypair: Arc<gitlawb_core::identity::Keypair>,
    node_did: gitlawb_core::did::Did,
    pin_sem: Arc<tokio::sync::Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> bool {
    if !should_spawn(&config) {
        tracing::info!(
            "reconciliation sweep: disabled or neither IPFS nor Pinata configured, skipping spawn"
        );
        return false;
    }

    tokio::spawn(async move {
        let node_seed = *node_keypair.to_seed();
        // Resume from the persisted cursor (R2-P1): a node restart must not
        // re-walk every repo, and the cursor is only ever advanced after a
        // batch completes, so an interrupted pass resumes where it stopped.
        let mut cursor: Option<String> = match db.get_node_state(CURSOR_KEY).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(err = %e, "failed to load reconciliation sweep cursor from node_state; starting from scratch");
                None
            }
        };

        // First pass: random delay to desynchronize sweep starts across nodes
        // on a rolling restart (R1-P3). Subsequent passes use the fixed interval.
        // Generate the delay before the async block to avoid Send issues with thread_rng.
        let initial_delay = Duration::from_millis(rand::thread_rng().gen_range(0..60000));
        let mut first_pass = true;

        loop {
            // On first pass, wait for the initial random delay before starting
            if first_pass {
                tracing::debug!(
                    delay_ms = initial_delay.as_millis() as u64,
                    "reconciliation sweep: waiting initial jitter delay"
                );
                tokio::select! {
                    _ = tokio::time::sleep(initial_delay) => {}
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::info!("reconciliation sweep: shutdown signal received during initial delay, exiting");
                            return;
                        }
                    }
                }
                first_pass = false;
            }

            let start = std::time::Instant::now();
            match run_pass(
                &db,
                &config,
                &http_client,
                &node_seed,
                &node_did,
                &pin_sem,
                REPO_SCAN_DEADLINE,
                &mut cursor,
                &mut shutdown_rx,
            )
            .await
            {
                Ok((count, gaps, filled)) => {
                    tracing::info!(
                        repos = count,
                        gaps_found = gaps,
                        gaps_filled = filled,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "reconciliation sweep pass complete"
                    );
                }
                Err(e) => {
                    tracing::warn!(err = %e, "reconciliation sweep pass failed");
                }
            }

            if *shutdown_rx.borrow() {
                tracing::info!("reconciliation sweep: shutdown signal received, exiting");
                return;
            }

            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(SWEEP_INTERVAL_SECS)) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("reconciliation sweep: shutdown signal received, exiting");
                        return;
                    }
                }
            }
        }
    });

    true
}

/// Re-derive the *allowed* public-object set from fresh rules and intersect it
/// with the scanned object list. Returns `None` when the re-derivation failed
/// (caller skips the repo). This is the path-scoped-visibility re-filter that
/// runs against rules re-fetched after the git scan, so a narrowing made
/// mid-scan is honored before anything is pinned.
///
/// The caller hands an absolute `deadline`; the whole re-derivation
/// (replicable_blob_set_bounded + all_blob_oids) runs against the remaining
/// budget rather than granting each git child a fresh timeout. The mid-scan
/// re-filter and each pin-boundary re-derivation each get their OWN fresh
/// `REPO_SCAN_DEADLINE` (R2-P1) so a scan that exhausts its own budget cannot
/// disable the authorization-at-dispatch recheck — the read phase is additive
/// with the pin phases, documented at `PIN_PHASE_DEADLINE`.
async fn refilter_public_objects(
    disk: &std::path::Path,
    rules: &[crate::db::VisibilityRule],
    is_public: bool,
    owner_did: &str,
    object_list: Vec<String>,
    deadline: Instant,
) -> Option<Vec<String>> {
    let disk_clone = disk.to_path_buf();
    let rules_clone = rules.to_vec();
    let owner_clone = owner_did.to_string();

    match tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
            // The shared deadline spans this whole re-filter
            // (allowed_blob_tree_sets_bounded), so a slow walk is bounded as a
            // unit rather than granting each git child a fresh timeout.
            let (allowed, allowed_trees, all_blobs, all_trees) =
                crate::git::visibility_pack::allowed_blob_tree_sets_bounded(
                    &disk_clone,
                    "git",
                    deadline,
                    &rules_clone,
                    is_public,
                    &owner_clone,
                )?;
            Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
                object_list,
                &allowed,
                &all_blobs,
                &allowed_trees,
                &all_trees,
            ))
        }),
    )
    .await
    {
        Ok(Ok(Ok(list))) => Some(list),
        Ok(Ok(Err(e))) => {
            tracing::warn!(err = %e, "visibility re-derivation failed");
            None
        }
        Ok(Err(e)) => {
            tracing::warn!(err = %e, "visibility re-derivation task panicked");
            None
        }
        Err(_) => {
            tracing::warn!("visibility re-derivation deadline exceeded");
            None
        }
    }
}
// Test-only fault injection for the PIN-BOUNDARY re-derivation (#218 review
// round 8 P2). The "nothing was dispatched" branch of the continuation write is
// reached when a stage between the missing-set query and the backend call
// declines — a `PolicyFence` capture that fails, a quarantine recheck that says
// skip, a re-derivation that errors. Every one of those is a DB or git failure
// on a repo the test has just built healthy, and no fixture can produce one from
// the outside: the mid-scan re-filter runs first on the same rules and the same
// budget, so anything that would starve the pin-boundary call has already made
// the sweep `continue` well before the offset write. Rather than assert the
// contract at a lower layer than the one that owns it (the sweep loop's call
// site), the boundary gets an explicit seam.
//
// Thread-local because `#[sqlx::test]` drives each test on its own
// current-thread runtime, so the flag cannot race across tests.
#[cfg(test)]
thread_local! {
    static FAIL_PIN_BOUNDARY_REDERIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Force (or release) the pin-boundary re-derivation failure. Test-only.
#[cfg(test)]
fn set_fail_pin_boundary_rederive(on: bool) {
    FAIL_PIN_BOUNDARY_REDERIVE.with(|c| c.set(on));
}

/// [`refilter_public_objects`] at the pin boundary — the last authorization
/// stage before an irreversible public pin, and the one stage whose failure the
/// continuation write has to distinguish from "nothing to do". Identical to the
/// mid-scan call except for the test seam above.
async fn pin_boundary_refilter(
    disk: &std::path::Path,
    rules: &[crate::db::VisibilityRule],
    is_public: bool,
    owner_did: &str,
    object_list: Vec<String>,
    deadline: Instant,
) -> Option<Vec<String>> {
    #[cfg(test)]
    if FAIL_PIN_BOUNDARY_REDERIVE.with(|c| c.get()) {
        return None;
    }
    refilter_public_objects(disk, rules, is_public, owner_did, object_list, deadline).await
}

/// Re-check quarantine AND root visibility immediately before an irreversible
/// public pin (R1-P1). Returns the fresh repo row plus fresh rules, or `None`
/// when the pin must be skipped. DB failures are treated as skip (never pin on
/// a stale allow), so one repo's failure does not abort the pass.
async fn recheck_public_pin(
    db: &Db,
    repo_id: &str,
    repo_slug: &str,
) -> Option<(crate::db::RepoRecord, Vec<crate::db::VisibilityRule>)> {
    match db.is_repo_quarantined(repo_id).await {
        Ok(true) => {
            tracing::warn!(repo = %repo_slug, "repo quarantined, skipping pin");
            return None;
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(repo = %repo_slug, err = %e, "quarantine recheck failed, skipping pin");
            return None;
        }
    }
    let rules = match db.list_visibility_rules(repo_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(repo = %repo_slug, err = %e, "visibility rules re-fetch failed, skipping pin");
            return None;
        }
    };
    let fresh = match db.get_repo_by_id(repo_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::warn!(repo = %repo_slug, "repo disappeared from DB, skipping pin");
            return None;
        }
        Err(e) => {
            tracing::warn!(repo = %repo_slug, err = %e, "repo re-fetch failed, skipping pin");
            return None;
        }
    };
    if !crate::visibility::listable_at_root(&rules, fresh.is_public, &fresh.owner_did, None) {
        tracing::warn!(repo = %repo_slug, "visibility narrowed, skipping pin");
        return None;
    }
    Some((fresh, rules))
}

/// Compute the deterministic missing set: `all` minus `done`, sorted so two
/// passes over the same data yield the same pin order. Not capped here — the
/// caller applies the cap and logs a truncation warning.
///
/// `start_after` is the per-(repo, backend) continuation offset (#218
/// review P2). When `Some`, the sorted missing set is ROTATED so the
/// first OID is the smallest one strictly greater than `start_after`,
/// and every OID ≤ `start_after` is appended at the tail. The set as a
/// whole is unchanged; only the attempt order changes. Without the
/// rotation, a persistently failing early OID (e.g. one the local IPFS
/// daemon refuses for a transient-but-recurring reason) keeps landing
/// at the start of the sort and dominates the 50 000 cap every
/// hourly tick, so a healthy gap past the cap is never attempted.
/// With the rotation, the cap still bounds per-pass work but advances
/// fairly across passes: failed OIDs retried at the tail of the
/// next pass, the healthy gap moves into the cap window.
///
/// `start_after = None` preserves the pre-P2 deterministic head-first
/// order, which is what a fresh (repo, backend) or a `done = TRUE`
/// pair does.
fn missing_oids(all: &[String], done: &[String], start_after: Option<&str>) -> Vec<String> {
    let done_set: HashSet<&str> = done.iter().map(|s| s.as_str()).collect();
    let mut missing: Vec<String> = all
        .iter()
        .filter(|s| !done_set.contains(s.as_str()))
        .cloned()
        .collect();
    missing.sort();
    let Some(start) = start_after else {
        return missing;
    };
    // Find the rotation point: the first OID strictly greater than
    // `start`. OIDs ≤ start (typically: previously truncated, possibly
    // failing) move to the tail so the cap window sees fresh ground.
    // `partition_point` is the standard-library rotation seam: it
    // returns the index of the first element for which the predicate
    // is false, which is exactly the first `oid > start` after a sort.
    let split = missing.partition_point(|oid| oid.as_str() <= start);
    if split == 0 || split >= missing.len() {
        // Either nothing has been attempted yet (split == 0) or every
        // missing OID is ≤ start (the offset is past the end, which
        // should not happen on a well-formed pass but the rotation
        // would lose data — return sorted order as-is).
        return missing;
    }
    let mut rotated = Vec::with_capacity(missing.len());
    rotated.extend(missing[split..].iter().cloned());
    rotated.extend(missing[..split].iter().cloned());
    rotated
}

/// Cap a missing set, logging once when it was truncated.
fn cap_missing(v: Vec<String>, repo_slug: &str, backend: &str) -> Vec<String> {
    if v.len() > MAX_OBJECTS_PER_REPO {
        tracing::warn!(
            repo = %repo_slug,
            backend,
            cap = MAX_OBJECTS_PER_REPO,
            "per-repo missing cap reached, truncating"
        );
        let mut v = v;
        v.truncate(MAX_OBJECTS_PER_REPO);
        v
    } else {
        v
    }
}

/// Run one sweep pass. Returns `(repos_scanned, gaps_found, gaps_filled)`.
///
/// `repos_scanned` counts every repo actually visited this pass (mirror rows
/// and hard skips excluded, and the loop stops counting the moment a shutdown
/// signal breaks the batch), so the returned value never overreports work that
/// a mid-pass shutdown prevented (R1-P3).
///
/// Nine args but grouping them would churn every test caller for no behavioral
/// gain; the pins each arg names are independently documented at their use.
/// `rederive_budget` is the budget each authorization-at-dispatch
/// re-derivation runs against: the mid-scan re-filter and each pin-boundary
/// re-derivation compute their OWN fresh `Instant::now() + rederive_budget`
/// (R2-P1), so a scan that exhausts `REPO_SCAN_DEADLINE` cannot starve the
/// visibility recheck that runs right before anything is pinned. Plumbed
/// through the signature (rather than read as a module const) so the call-site
/// wiring is testable.
#[allow(clippy::too_many_arguments)]
async fn run_pass(
    db: &Db,
    config: &Config,
    http_client: &reqwest::Client,
    node_seed: &[u8; 32],
    node_did: &gitlawb_core::did::Did,
    pin_sem: &Arc<tokio::sync::Semaphore>,
    rederive_budget: Duration,
    cursor: &mut Option<String>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<(usize, usize, usize)> {
    // Keyset pagination over repos ordered by immutable id so the cursor is
    // robust against insertions, deletions, or updated_at shifts.  The LIMIT
    // is pushed into the SQL query so the hourly pass does not allocate,
    // transfer, or deduplicate every repo on every sweep.
    //
    // Fetch one EXTRA row as a lookahead (R1-P2): `batch.len() < REPOS_PER_PASS`
    // is a wrong "final page" proxy when the key space ends on an exact multiple
    // of the page size — that batch LOOKS full, yet no row follows. With a
    // lookahead row present, the batch is full for real (more remain); without
    // it, the batch is the terminal page even at exactly REPOS_PER_PASS rows.
    let fetched = db
        .list_all_repos_deduped_stable(cursor.as_deref(), REPOS_PER_PASS as i64 + 1)
        .await?;
    let has_more = fetched.len() > REPOS_PER_PASS;
    let batch: Vec<_> = fetched.into_iter().take(REPOS_PER_PASS).collect();

    if batch.is_empty() {
        // Covered everything: clear the persisted cursor so the next pass
        // starts a fresh cycle instead of wedging on a stale key.
        *cursor = None;
        db.set_node_state(CURSOR_KEY, None).await?;
        return Ok((0, 0, 0));
    }

    // Advance the in-memory cursor now so the next page in this run continues
    // after this batch; the PERSISTED cursor is only moved once the batch fully
    // completes below, so an interrupted batch is re-walked on restart.
    let batch_last = batch.last().unwrap().id.clone();
    *cursor = Some(batch_last.clone());

    let mut total_gaps_found = 0usize;
    let mut total_gaps_filled = 0usize;
    let mut repos_scanned = 0usize;
    let mut batch_completed = true;

    for repo in &batch {
        if *shutdown_rx.borrow() {
            tracing::info!("reconciliation sweep: shutdown signal received mid-pass, exiting");
            batch_completed = false;
            break;
        }

        let repo_slug = format!(
            "{}/{}",
            crate::db::normalize_owner_key(&repo.owner_did),
            repo.name
        );

        // Mirror rows carry a slash-form id written only by upsert_mirror_repo;
        // they hardcode is_public = true and replicate no visibility rules, so a
        // sweep over one would irreversibly publish content that the canonical
        // gate never admitted (R2-P1). Skip them — the canonical row (if any)
        // is swept under its own id.
        if repo.id.contains('/') {
            tracing::debug!(repo = %repo_slug, "mirror row (no canonical repo), skipping sweep");
            continue;
        }

        let disk = PathBuf::from(&repo.disk_path);
        if !disk.exists() {
            tracing::warn!(repo = %repo_slug, "disk path missing, skipping");
            continue;
        }

        // Counted only once the repo has a real chance of work: mirror rows and
        // missing-disk rows are hard skips and never count as scanned (R1-P3).
        repos_scanned += 1;

        // Cheap quarantine pre-check BEFORE the expensive git scan (R1-P3):
        // a repo quarantined since admission should not burn a full scan just
        // to be told to skip.
        match db.is_repo_quarantined(&repo.id).await {
            Ok(true) => {
                tracing::warn!(repo = %repo_slug, "repo quarantined, skipping");
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "quarantine check failed, skipping");
                continue;
            }
        }

        let rules = match db.list_visibility_rules(&repo.id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "visibility rules fetch failed, skipping");
                continue;
            }
        };

        if !crate::visibility::listable_at_root(&rules, repo.is_public, &repo.owner_did, None) {
            continue;
        }

        // ── Full git scan (bounded) ─────────────────────────────────────
        // One absolute deadline spans the whole scan. The mandatory visibility
        // re-filter below runs against its OWN fresh budget (`authz_deadline`),
        // NOT this spent deadline (R2-P1): a scan that legitimately consumes
        // its whole budget would otherwise compute a zero remaining duration
        // for the re-filter, time out immediately, and abort the repo
        // iteration — permanently skipping exactly the large repos the sweep
        // exists for. The pin-boundary re-derivations use the same fresh-
        // budget pattern per backend arm, so no later authorization stage can
        // be starved by the read phase's consumption.
        let scan_deadline = Instant::now() + REPO_SCAN_DEADLINE;
        let disk_clone = disk.clone();
        let owner_clone = repo.owner_did.clone();
        let rules_clone = rules.clone();
        let is_public = repo.is_public;

        let object_list = tokio::time::timeout(
            scan_deadline.saturating_duration_since(Instant::now()),
            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
                let all_objs =
                    crate::git::push_delta::list_all_objects(&disk_clone, "git", scan_deadline)?;
                let (allowed, allowed_trees, all_blobs, all_trees) =
                    crate::git::visibility_pack::allowed_blob_tree_sets_bounded(
                        &disk_clone,
                        "git",
                        scan_deadline,
                        &rules_clone,
                        is_public,
                        &owner_clone,
                    )?;
                // Fail closed for blobs and denied trees (#172): the
                // batch-all-objects enumeration carries dangling commits/trees
                // from an aborted push, which have no path scoping to fail
                // closed against. Requiring membership in the reachable object
                // set keeps their messages, authors, parent links, and
                // tree/file-name metadata off public pin backends (R2).
                let reachable = crate::git::push_delta::reachable_object_oids(
                    &disk_clone,
                    "git",
                    scan_deadline,
                )?;
                Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
                    all_objs,
                    &allowed,
                    &all_blobs,
                    &allowed_trees,
                    &all_trees,
                )
                .into_iter()
                .filter(|oid| reachable.contains(oid))
                .collect())
            }),
        )
        .await;

        let object_list: Vec<String> = match object_list {
            Ok(Ok(Ok(list))) => list,
            Ok(Ok(Err(e))) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan failed, skipping");
                continue;
            }
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan task panicked, skipping");
                continue;
            }
            Err(_) => {
                tracing::warn!(repo = %repo_slug, "full-scan deadline exceeded, skipping");
                continue;
            }
        };

        // #218 review round 10 (P1): a path-scoped repo whose only
        // reachable object is a direct blob/tree ref yields an
        // empty public list (the anonymous public classifier removes
        // the only object from the served set) while
        // `withheld_blob_recipients_bounded` still assigns that
        // object to the owner recovery set below. Skipping the
        // whole repo here would suppress encrypted recovery too,
        // and a lost/failed encrypted copy would never be
        // repaired. Track empty-public-work as a flag and run
        // the public phase conditionally; encrypted phase 2 runs
        // regardless.
        let has_public_work = !object_list.is_empty();

        // Backend enable flags live outside the `if has_public_work`
        // block because phase 2 (encrypted) consults `ipfs_enabled`
        // and `_pin_permit` regardless of public-work state. Pulling
        // them out of the inner block is a round 10 P1 follow-up:
        // before that, an empty public list (which made
        // `has_public_work` false) left these names out of scope
        // for phase 2 and the build failed.
        let ipfs_enabled = !config.ipfs_api.is_empty();
        let pinata_enabled = !config.pinata_jwt.is_empty();
        // `_pin_permit` is set by the public phase when it had gaps
        // to pin; phase 2 reuses it. When `has_public_work` is false
        // the public phase never ran, so the permit starts as
        // `None` and phase 2 acquires a fresh one.
        let mut _pin_permit: Option<tokio::sync::OwnedSemaphorePermit> = None;

        // Fresh budget for the authorization-at-dispatch re-derivations (R1/R2):
        // the scan may have legitimately consumed its whole `scan_deadline`, and
        // reusing that deadline here would compute a zero remaining duration,
        // return None, and turn an empty `to_pin` into a permanent hourly skip
        // for exactly the large/slow repos the sweep exists for. This deadline is
        // deliberately NOT shared with the scan. The mid-scan re-filter and each
        // backend arm each re-derive against their OWN fresh budget (R2-P1): the
        // IPFS arm re-derives first, and if two stages shared one budget a large
        // repo that consumed it on an earlier walk would leave the later stage
        // silently skipped every pass — empty `to_pin` behind a warn.

        // ── Phase 1: Public-object pinning (IPFS + Pinata) ────────────────
        // Wrapped in `if has_public_work` so an empty public set
        // (post-scan or post-refilter) still lets phase 2 run
        // (round 10 P1). The `recheck_public_pin` and the
        // mid-pass refilter inside this block BOTH have early
        // `continue` paths that would otherwise skip phase 2
        // entirely; we replaced the second with the flag flip
        // above.
        if has_public_work {
            // Re-check quarantine AND visibility right now (fresh rules + repo row),
            // then re-derive the allowed set from those fresh rules so a path-scoped
            // narrowing made mid-scan is honored before anything is pinned.
            let (fresh_repo, fresh_rules) = match recheck_public_pin(db, &repo.id, &repo_slug).await
            {
                Some(v) => v,
                None => continue,
            };

            // Visibility may have narrowed mid-scan with a path-scoped deny.
            // Recompute the allowed set from fresh rules and intersect it with the
            // existing object_list. Runs against its OWN fresh `authz_deadline`, NOT
            // the spent `scan_deadline` (R2-P1): the scan may have consumed the whole
            // read budget, and a reused deadline computes a zero remaining duration,
            // times out immediately, and aborts the repo iteration before the pin
            // phases ever run — permanently skipping exactly the large repos the
            // durability backstop exists for. The pin-boundary re-derivations below
            // use the same fresh-budget pattern per backend arm.
            let authz_deadline = Instant::now() + rederive_budget;
            let refiltered = refilter_public_objects(
                &disk,
                &fresh_rules,
                fresh_repo.is_public,
                &fresh_repo.owner_did,
                object_list,
                authz_deadline,
            )
            .await;
            let Some(object_list) = refiltered else {
                tracing::warn!(repo = %repo_slug, "fresh-visibility re-filter failed, skipping");
                continue;
            };
            if object_list.is_empty() {
                // #218 review round 10 (P1): a mid-pass visibility
                // narrowing can leave the public set empty while
                // withheld recipients are still non-empty. The
                // IPFS/Pinata dispatch arms below already no-op on an
                // empty `ipfs_missing`/`pinata_missing` (the lists the
                // block fills in), so we only need to skip the offset
                // bookkeeping and let phase 2 run.
                tracing::debug!(repo = %repo_slug, "refiltered public set is empty; encrypted recovery still runs");
            }

            // `ipfs_enabled` and `pinata_enabled` are declared outside
            // the `if has_public_work` block (see above) so phase 2
            // can read them when the public list is empty.

            // Per-(repo, backend) continuation offset (#218 review P2): loaded
            // here so the same offset is read once, used to rotate the
            // missing set, and then the loop below writes the new offset
            // back. A DB error on the load is treated as "start from the
            // head" — the worst case is one pass at the old sort order,
            // not a stalled sweep — so a corrupt row never blocks the
            // per-hour gap-fill.
            let ipfs_offset = if ipfs_enabled {
                match db.load_reconciliation_offset(&repo.id, "IPFS").await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(repo = %repo_slug, err = %e, "load_reconciliation_offset(IPFS) failed, starting from head");
                        None
                    }
                }
            } else {
                None
            };
            let pinata_offset = if pinata_enabled {
                match db.load_reconciliation_offset(&repo.id, "PINATA").await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(repo = %repo_slug, err = %e, "load_reconciliation_offset(PINATA) failed, starting from head");
                        None
                    }
                }
            } else {
                None
            };

            // IPFS-missing set.  A filter DB error skips only the IPFS gap-fill and
            // lets the Pinata path still run (R1-P3), instead of dropping the repo.
            //
            // `*_scan_ok` records whether the missing set is a TRUTHFUL answer
            // (#218 review round 8 P2). An empty set means two opposite things: "every
            // object is already pinned" (the happy path, which should mark the
            // continuation done) or "the filter query failed and we know nothing"
            // (which must leave the stored continuation exactly where it was). Writing
            // a done marker for the second case discards a resume point that a capped
            // pass paid for, so the two are tracked apart.
            let mut ipfs_scan_ok = ipfs_enabled;
            let ipfs_missing: Vec<String> = if ipfs_enabled {
                match db.filter_ipfs_pinned_oids(&object_list).await {
                    Ok(already) => cap_missing(
                        missing_oids(&object_list, &already, ipfs_offset.as_deref()),
                        &repo_slug,
                        "IPFS",
                    ),
                    Err(e) => {
                        tracing::warn!(repo = %repo_slug, err = %e, "filter_ipfs_pinned_oids failed, IPFS gap-fill skipped this pass");
                        ipfs_scan_ok = false;
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };

            let mut pinata_scan_ok = pinata_enabled;
            let pinata_missing: Vec<String> = if pinata_enabled {
                match db.filter_pinata_pinned_oids(&object_list).await {
                    Ok(already) => cap_missing(
                        missing_oids(&object_list, &already, pinata_offset.as_deref()),
                        &repo_slug,
                        "Pinata",
                    ),
                    Err(e) => {
                        tracing::warn!(repo = %repo_slug, err = %e, "filter_pinata_pinned_oids failed, Pinata gap-fill skipped this pass");
                        pinata_scan_ok = false;
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };

            // Whether this pass had gap-fill work to do at all, captured before the
            // missing sets are moved into the pin loops below. This is NOT the
            // continuation value — see `ipfs_dispatched` / `pinata_dispatched`.
            let ipfs_had_work = !ipfs_missing.is_empty();
            let pinata_had_work = !pinata_missing.is_empty();

            // The last OID each backend actually DISPATCHED — handed to
            // `pin_new_objects` — or `None` if this pass dispatched nothing.
            //
            // #218 review round 8 P2: the continuation used to be captured here, from
            // `missing.last()`, BEFORE the pin permit, both `PolicyFence` captures and
            // both pin loops, and was then written unconditionally. Every stage between
            // capture and dispatch can legitimately produce nothing — a fence capture
            // that fails, a quarantine/visibility recheck that says skip, a
            // pin-boundary re-derivation that errors — and each of those is a
            // TRANSIENT failure. Advancing the continuation past OIDs that were never
            // attempted rotates that whole unattempted prefix to the BACK of the next
            // pass's order, behind the entire backlog. For an at-cap repo (the only
            // kind the continuation exists for) the backlog never drains inside one
            // cap window, so those objects are not merely retried later — they are
            // starved indefinitely, which is exactly the durability hole this sweep is
            // the backstop for. The offset therefore moves only for work that was
            // really dispatched; a pass that dispatched nothing leaves the stored
            // resume point untouched and retries the same prefix next tick.
            let mut ipfs_dispatched: Option<String> = None;
            let mut pinata_dispatched: Option<String> = None;

            // Count UNIQUE missing objects across both backends (R1-P3): an object
            // absent from both must not be counted twice.
            let mut gap_union: HashSet<&str> = HashSet::new();
            gap_union.extend(ipfs_missing.iter().map(|s| s.as_str()));
            gap_union.extend(pinata_missing.iter().map(|s| s.as_str()));
            let repo_gaps = gap_union.len();
            if repo_gaps > 0 {
                total_gaps_found += repo_gaps;
                crate::metrics::record_reconciliation_gaps_found(repo_gaps as u64);
            }

            // Re-validate quarantine + visibility IMMEDIATELY before each backend
            // pin (R1-P1) and re-derive the allowed set from the rules read at that
            // moment, intersecting it with the to-pin list (R2-P1): for
            // content-addressed public pins a stale allow is effectively
            // irreversible, and the pin itself takes time. A path-scoped deny that
            // landed after the mid-scan refilter (which only checks root listability)
            // is honored here because the candidates are intersected with the set
            // allowed under the fresh rules, not just root-gated. Each backend runs
            // under a PolicyFence captured at ITS dispatch boundary, so a narrow that
            // lands mid-batch aborts the remaining uploads (R1-P1).
            //
            // Acquire the same global pin permit the push path holds (R2-P2): the
            // sweep's pin loops must not bypass `max_concurrent_pin_tasks`. Acquired
            // only when there is actual pin work; the scan above holds no permit.
            // The permit is held across the public pin loops AND the encrypted seal
            // below (which also writes to IPFS) and dropped at the end of this repo's
            // iteration.
            // Reassign the outer `_pin_permit` (declared before this
            // block so phase 2 can read it even when the public phase
            // did not run) instead of shadowing with `let`.
            _pin_permit = if !ipfs_missing.is_empty() || !pinata_missing.is_empty() {
                let permit = pin_sem.clone().acquire_owned().await?;
                Some(permit)
            } else {
                None
            };
            let ipfs_fence = if ipfs_enabled && !ipfs_missing.is_empty() {
                crate::ipfs_pin::PolicyFence::capture(db, &repo.id).await
            } else {
                None
            };
            let pinata_fence = if pinata_enabled && !pinata_missing.is_empty() {
                crate::ipfs_pin::PolicyFence::capture(db, &repo.id).await
            } else {
                None
            };

            let pinned_ipfs: Vec<(String, String)> = if ipfs_enabled && !ipfs_missing.is_empty() {
                match ipfs_fence {
                    None => {
                        tracing::warn!(repo = %repo_slug, "IPFS policy-epoch capture failed, skipping");
                        Vec::new()
                    }
                    Some(fence) => match recheck_public_pin(db, &repo.id, &repo_slug).await {
                        None => Vec::new(),
                        Some((fresh_repo, fresh_rules)) => {
                            let to_pin = match pin_boundary_refilter(
                                &disk,
                                &fresh_rules,
                                fresh_repo.is_public,
                                &fresh_repo.owner_did,
                                ipfs_missing,
                                Instant::now() + rederive_budget,
                            )
                            .await
                            {
                                Some(list) => list,
                                None => {
                                    tracing::warn!(repo = %repo_slug, "IPFS pin-boundary re-derivation failed, skipping");
                                    Vec::new()
                                }
                            };
                            if to_pin.is_empty() {
                                Vec::new()
                            } else {
                                // Dispatch boundary (round-8 P2): from here the OIDs
                                // in `to_pin` really are handed to the backend, so
                                // the continuation may advance to the last of them.
                                // Recorded BEFORE the call so a pin phase that times
                                // out mid-batch still counts as dispatched — those
                                // objects were attempted, and re-attempting them
                                // ahead of the rest of the backlog is the starvation
                                // the rotation exists to avoid. It is `to_pin`'s last
                                // element, not the missing set's: an OID the
                                // pin-boundary re-derivation dropped was never
                                // offered to the backend.
                                ipfs_dispatched = to_pin.last().cloned();
                                match tokio::time::timeout(
                                    PIN_PHASE_DEADLINE,
                                    crate::ipfs_pin::pin_new_objects(
                                        &config.ipfs_api,
                                        &disk,
                                        "git",
                                        Duration::from_secs(config.git_service_timeout_secs),
                                        to_pin,
                                        db,
                                        &repo.id,
                                        crate::ipfs_pin::PIN_BATCH_BUDGET,
                                        Some(&fence),
                                    ),
                                )
                                .await
                                {
                                    Ok(v) => v,
                                    Err(_) => {
                                        tracing::warn!(repo = %repo_slug, "IPFS pin phase timed out after {:?}", PIN_PHASE_DEADLINE);
                                        Vec::new()
                                    }
                                }
                            }
                        }
                    },
                }
            } else {
                Vec::new()
            };

            let pinned_pinata: Vec<(String, String)> = if pinata_enabled
                && !pinata_missing.is_empty()
            {
                match pinata_fence {
                    None => {
                        tracing::warn!(repo = %repo_slug, "Pinata policy-epoch capture failed, skipping");
                        Vec::new()
                    }
                    Some(fence) => match recheck_public_pin(db, &repo.id, &repo_slug).await {
                        None => Vec::new(),
                        Some((fresh_repo, fresh_rules)) => {
                            // Own budget (R2-P1): the IPFS arm above may have
                            // consumed the whole shared deadline, and a reused
                            // spent deadline here would silently skip Pinata every
                            // pass for exactly the large repos this sweep exists
                            // for.
                            let to_pin = match pin_boundary_refilter(
                                &disk,
                                &fresh_rules,
                                fresh_repo.is_public,
                                &fresh_repo.owner_did,
                                pinata_missing,
                                Instant::now() + rederive_budget,
                            )
                            .await
                            {
                                Some(list) => list,
                                None => {
                                    tracing::warn!(repo = %repo_slug, "Pinata pin-boundary re-derivation failed, skipping");
                                    Vec::new()
                                }
                            };
                            if to_pin.is_empty() {
                                Vec::new()
                            } else {
                                // Dispatch boundary (round-8 P2); see the IPFS arm
                                // above for why this is recorded here rather than
                                // from the missing set before the fence.
                                pinata_dispatched = to_pin.last().cloned();
                                match tokio::time::timeout(
                                    PIN_PHASE_DEADLINE,
                                    crate::pinata::pin_new_objects(
                                        http_client,
                                        &config.pinata_upload_url,
                                        &config.pinata_jwt,
                                        &disk,
                                        "git",
                                        Duration::from_secs(config.git_service_timeout_secs),
                                        to_pin,
                                        db,
                                        &repo.id,
                                        crate::ipfs_pin::PIN_BATCH_BUDGET,
                                        Some(&fence),
                                    ),
                                )
                                .await
                                {
                                    Ok(v) => v,
                                    Err(_) => {
                                        tracing::warn!(repo = %repo_slug, "Pinata pin phase timed out after {:?}", PIN_PHASE_DEADLINE);
                                        Vec::new()
                                    }
                                }
                            }
                        }
                    },
                }
            } else {
                Vec::new()
            };

            // `pin_new_objects` returns only objects whose DB record was written
            // (R1-P3), so a backend that uploaded bytes but failed to persist is
            // not counted as "filled". Count UNIQUE objects across both backends
            // (R2-P3): `gaps_found` is the union of missing OIDs, so an object
            // pinned to BOTH backends must not count twice against that union.
            let mut filled_union: HashSet<&String> = HashSet::new();
            filled_union.extend(pinned_ipfs.iter().map(|(sha, _)| sha));
            filled_union.extend(pinned_pinata.iter().map(|(sha, _)| sha));
            let repo_filled = filled_union.len();
            if repo_filled > 0 {
                total_gaps_filled += repo_filled;
                crate::metrics::record_reconciliation_gaps_filled(repo_filled as u64);

                tracing::info!(
                    repo = %repo_slug,
                    ipfs = pinned_ipfs.len(),
                    pinata = pinned_pinata.len(),
                    total = repo_filled,
                    "reconciliation sweep filled public-object gaps"
                );
            }

            // Persist the per-(repo, backend) continuation offset (#218 review
            // P2). The offset is the last DISPATCHED OID per backend — for a
            // non-truncated pass this is the OID at the tail of the missing
            // set, for a truncated pass it is the OID at the cap edge. The
            // next pass's `missing_oids` rotates the sorted set so the first
            // OID is strictly greater than this value, and the previously
            // attempted tail is retried at the end of the next pass — so a
            // persistent early failure does not monopolise the cap window.
            //
            // Three outcomes, and the round-8 P2 fix is that they are three
            // rather than two (see `ipfs_dispatched` above for the starvation
            // this prevents):
            //   * work dispatched      -> advance to the last dispatched OID.
            //   * nothing missing, and the missing-set query SUCCEEDED
            //                          -> `None`, which marks the row done and
            //                             starts the next pass at the head.
            //   * nothing dispatched from a non-empty missing set, or a failed
            //     missing-set query
            //                          -> write NOTHING. The stored resume
            //                             point is the only record of how far a
            //                             capped pass got; a transient fence,
            //                             recheck or re-derivation failure must
            //                             not be allowed to erase or advance it.
            //
            // A DB error on the write is logged but does NOT abort the pass: a
            // missed offset write means the next pass starts at the head
            // (the worst case is one pass at the old sort order).
            //
            // `next_offset_write` returns a `ProgressState` directly
            // (the documented shape), and the write site converts to
            // the wire form via `to_wire`. One encoding — the enum
            // is no longer a parallel implementation of the same
            // logic. P2 (reviewer round 9): the previous code held
            // `Option<Option<String>>` in the closure and the
            // `ProgressState` enum on the side, with the two only
            // cross-checked in a test that never called the closure.
            // Now there is one mapping.
            //
            // The three states:
            //   - `Idle`: no work was attempted this pass (fence
            //     capture failed, refilter returned `None`, dispatch
            //     produced an empty `to_pin`). The cursor is
            //     preserved — the unattempted prefix retries at the
            //     head of the next pass.
            //   - `Advanced { last_dispatched }`: a subset of the cap
            //     was dispatched. The next pass rotates past
            //     `last_dispatched`, retrying everything beyond.
            //   - `Drained`: the missing set was empty. The cursor is
            //     cleared (a future pass sees a fresh start).
            //
            // The two backends' cursors are independent: a drained
            // IPFS missing set clears the IPFS offset but does NOT
            // touch the Pinata offset, and vice versa. The write
            // site persists each backend's state without sharing.

            if ipfs_enabled {
                let next_wire =
                    next_offset_write(ipfs_scan_ok, ipfs_had_work, ipfs_dispatched).to_wire();
                if let Some(next) = next_wire {
                    if let Err(e) = db
                        .save_reconciliation_offset(&repo.id, "IPFS", next.as_deref())
                        .await
                    {
                        tracing::warn!(repo = %repo_slug, err = %e, "save_reconciliation_offset(IPFS) failed, next pass will start from head");
                    }
                } else {
                    tracing::debug!(repo = %repo_slug, "IPFS dispatched nothing this pass, continuation offset left unchanged");
                }
            }
            if pinata_enabled {
                let next_wire =
                    next_offset_write(pinata_scan_ok, pinata_had_work, pinata_dispatched).to_wire();
                if let Some(next) = next_wire {
                    if let Err(e) = db
                        .save_reconciliation_offset(&repo.id, "PINATA", next.as_deref())
                        .await
                    {
                        tracing::warn!(repo = %repo_slug, err = %e, "save_reconciliation_offset(PINATA) failed, next pass will start from head");
                    }
                } else {
                    tracing::debug!(repo = %repo_slug, "Pinata dispatched nothing this pass, continuation offset left unchanged");
                }
            }
        } // end of `if has_public_work { ... }` (round 10 P1)

        // ── Phase 2: Encrypted recovery-copy resealing (withheld blobs) ──

        // Fence the encrypted path from the point the recipients are derived:
        // the withheld-blob walk is long, and `encrypt_and_pin` re-checks the
        // epoch per blob, so a visibility rule moving mid-walk aborts the seal
        // loop before a stale recipient set is pinned (R1-P1). Captured BEFORE
        // the rules recheck below, mirroring the public path (R2-P1): if a rule
        // change landed between a recheck-first ordering's rule read and this
        // capture, the change would be baked into the recipient set while the
        // epoch captured after it already reflected the move — `is_current`
        // would then report current for the whole seal loop and the fence would
        // never fire for that narrow.
        let enc_fence = match crate::ipfs_pin::PolicyFence::capture(db, &repo.id).await {
            Some(f) => f,
            None => {
                tracing::warn!(repo = %repo_slug, "policy-epoch capture failed, skipping encrypted pin");
                continue;
            }
        };
        // Recheck quarantine AND root visibility before encrypted pinning, using
        // FRESH repo identity (R1-P2): the batch snapshot may predate a narrow.
        let (fresh_repo2, fresh_rules2) = match recheck_public_pin(db, &repo.id, &repo_slug).await {
            Some(v) => v,
            None => continue,
        };

        let has_path_scoped = crate::git::visibility_pack::has_path_scoped_rule(&fresh_rules2);
        if has_path_scoped && ipfs_enabled {
            let p = disk.clone();
            let owner = fresh_repo2.owner_did.clone();
            let r = fresh_rules2.clone();
            let is_public_2 = fresh_repo2.is_public;
            let recipients = tokio::time::timeout(
                REPO_SCAN_DEADLINE,
                tokio::task::spawn_blocking(move || {
                    crate::git::visibility_pack::withheld_blob_recipients_bounded(
                        &p,
                        "git",
                        REPO_SCAN_DEADLINE,
                        &r,
                        is_public_2,
                        &owner,
                    )
                }),
            )
            .await;

            let rec = match recipients {
                Ok(Ok(Ok(rec))) => rec,
                Ok(Ok(Err(e))) => {
                    tracing::warn!(
                        repo = %repo_slug, err = %e,
                        "withheld_blob_recipients failed, skipping encrypted pin"
                    );
                    continue;
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        repo = %repo_slug, err = %e,
                        "withheld_blob_recipients task panicked, skipping encrypted pin"
                    );
                    continue;
                }
                Err(_) => {
                    tracing::warn!(
                        repo = %repo_slug,
                        "encrypted recovery deadline exceeded, skipping"
                    );
                    continue;
                }
            };

            if !rec.is_empty() {
                // The encrypted seal writes to IPFS too, so it runs under the
                // same global pin permit as the public loops (R2-P2). Reuse the
                // permit `_pin_permit` already holds for this repo when the
                // public phase had gaps; only acquire a fresh one when it did
                // not. One permit per repo, never two (R2-P1): with
                // `max_concurrent_pin_tasks = 1` a second acquire here would
                // wait on the very permit this iteration holds and deadlock the
                // sweep past its guard timeout.
                let _enc_permit = match &_pin_permit {
                    Some(_) => None,
                    None => Some(pin_sem.clone().acquire_owned().await?),
                };
                // Bound the seal+pin work (R1-P2): an unavailable backend must
                // not hold the sweep past the pin-phase budget.
                let sealed = tokio::time::timeout(
                    PIN_PHASE_DEADLINE,
                    crate::encrypted_pin::encrypt_and_pin(
                        &config.ipfs_api,
                        &disk,
                        db,
                        &repo.id,
                        node_seed,
                        "git",
                        crate::ipfs_pin::PIN_BATCH_BUDGET,
                        &rec,
                        Some(&enc_fence),
                    ),
                )
                .await;

                let sealed: Vec<(String, String)> = match sealed {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::warn!(
                            repo = %repo_slug,
                            "encrypted pin phase timed out after {:?}",
                            PIN_PHASE_DEADLINE
                        );
                        Vec::new()
                    }
                };

                // Anchor only when something was newly sealed this pass.
                // This avoids unbounded Irys writes on a timer — repos
                // with no withheld changes do not re-anchor the manifest.
                //
                // Contract: anchoring is one-shot per seal. `plan_seal` returns
                // `SkipUnchanged` on every subsequent pass once the recipients
                // tag matches, so `sealed` stays empty and this block never
                // runs again. A transient Irys outage at the moment of a fresh
                // seal therefore LOSES that anchor permanently — the next pass
                // has no delta to anchor and no retry fires. This is
                // intentionally best-effort: re-anchoring an unchanged manifest
                // would burn Irys writes for no recovery benefit, and durable
                // retry of a failed seal would need a separate outbox that
                // survives across the seal-skip path. Operators who need a
                // guaranteed anchor after a transient outage should re-add a
                // withheld change (which forces a new seal and re-runs this
                // block) or anchor via a separate out-of-band process.
                if !sealed.is_empty() && !config.irys_url.is_empty() {
                    // Bind the manifest to the FRESH repo identity re-fetched at
                    // the pin boundary (`fresh_repo2`), not the batch snapshot:
                    // a renamed/ownership-changed repo must not anchor encrypted
                    // recovery copies under a stale owner (R1-P2).
                    let owner_short = crate::db::normalize_owner_key(&fresh_repo2.owner_did);
                    let slug = format!("{}/{}", owner_short, fresh_repo2.name);
                    let ts = chrono::Utc::now().to_rfc3339();
                    let node_did_str = node_did.to_string();

                    let manifest = crate::arweave::EncryptedManifest {
                        repo: &slug,
                        owner_did: &fresh_repo2.owner_did,
                        node_did: &node_did_str,
                        timestamp: &ts,
                        blobs: &sealed,
                    };
                    if let Err(e) = crate::arweave::anchor_encrypted_manifest(
                        http_client,
                        &config.irys_url,
                        &manifest,
                    )
                    .await
                    {
                        tracing::warn!(
                            repo = %slug,
                            err = %e,
                            "{}",
                            ENCRYPTED_MANIFEST_ANCHOR_FAILED_MSG
                        );
                    }
                }
            }
        }
    }

    // Persist the cursor only when the WHOLE batch completed. If shutdown
    // interrupted us, leave the persisted cursor at the previous batch's end so
    // the next run re-walks the unprocessed tail (R2-P1, R1-P3).
    if batch_completed {
        // A terminal page (no lookahead row) means the whole key space is
        // covered: clear the cursor now so the next tick starts a fresh cycle
        // instead of burning one pass on an empty batch. The lookahead is what
        // distinguishes "full because more remain" from "full because the key
        // space ends on an exact page boundary" (R1-P2).
        if !has_more {
            *cursor = None;
            if let Err(e) = db.set_node_state(CURSOR_KEY, None).await {
                tracing::warn!(err = %e, "failed to clear reconciliation sweep cursor on final page");
            }
        } else if let Err(e) = db.set_node_state(CURSOR_KEY, Some(&batch_last)).await {
            tracing::warn!(err = %e, "failed to persist reconciliation sweep cursor");
        }
    }

    Ok((repos_scanned, total_gaps_found, total_gaps_filled))
}

#[cfg(test)]
mod tests {
    use super::{next_offset_write, ProgressState};
    use tokio::sync::watch;

    /// Build a minimal Config with both IPFS and Pinata fields empty so the
    /// spawn() gate fires and the function returns without touching the DB.
    fn empty_pin_config() -> std::sync::Arc<crate::config::Config> {
        // Config derives clap::Parser; supply only argv[0] (the program name)
        // so all fields get their defaults (ipfs_api = "", pinata_jwt = "").
        let cfg = <crate::config::Config as clap::Parser>::parse_from(["gitlawb-node-test"]);
        std::sync::Arc::new(cfg)
    }

    /// Build a config with IPFS API set so the gate fires the other way.
    fn ipfs_config() -> std::sync::Arc<crate::config::Config> {
        let cfg = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            "http://127.0.0.1:5001",
        ]);
        std::sync::Arc::new(cfg)
    }

    /// #218 review round 9 (guidance #4): the wire-form test
    /// now drives `next_offset_write` directly with the same
    /// `(scan_ok, had_work, dispatched)` triples the
    /// cursor-write site uses, and asserts the returned
    /// `ProgressState` (and its `to_wire()`) is what the
    /// cursor-write site will land. P2 (reviewer round 9): the
    /// previous test never called the closure, so it pinned
    /// itself to its own arm-by-arm reproduction of the enum.
    /// Now there is one encoding and the test calls the function
    /// under test.
    #[test]
    fn next_offset_write_decision_table() {
        // scan_ok=false short-circuits to Idle regardless of the
        // other inputs — fence capture failed, the cursor must
        // be preserved.
        assert_eq!(
            next_offset_write(false, true, Some("Z".to_string())),
            ProgressState::Idle,
            "scan_ok=false must produce Idle (fence capture failed, cursor preserved)"
        );
        assert_eq!(
            next_offset_write(false, false, None),
            ProgressState::Idle,
            "scan_ok=false must produce Idle even with no work"
        );
        // dispatched.is_some() is Advanced, regardless of had_work.
        assert_eq!(
            next_offset_write(true, true, Some("X".to_string())),
            ProgressState::Advanced {
                last_dispatched: "X".to_string()
            },
            "dispatched.is_some() must produce Advanced (the next pass rotates past last)"
        );
        assert_eq!(
            next_offset_write(true, false, Some("Y".to_string())),
            ProgressState::Advanced {
                last_dispatched: "Y".to_string()
            },
            "dispatched.is_some() wins over !had_work"
        );
        // No dispatch, no work → Drained (cursor cleared).
        assert_eq!(
            next_offset_write(true, false, None),
            ProgressState::Drained,
            "scan_ok=true with no work and no dispatch must produce Drained (cursor cleared)"
        );
        // No dispatch, had_work → Idle (cursor preserved).
        assert_eq!(
            next_offset_write(true, true, None),
            ProgressState::Idle,
            "had_work but no dispatch must produce Idle (cursor preserved, retry at head)"
        );
    }

    /// The to_wire mapping for the three states, kept as a
    /// separate test so a future change to either side of the
    /// pair (enum variant vs. wire form) is caught. P2 (reviewer
    /// round 9): with the closure now returning `ProgressState`
    /// directly and the wire form derived via `to_wire`, this
    /// is a pure mapping test, not a guard on the closure
    /// logic.
    #[test]
    fn progress_state_to_wire_mapping() {
        assert_eq!(
            ProgressState::Idle.to_wire(),
            None,
            "Idle must produce None (caller preserves the previous offset)"
        );
        assert_eq!(
            ProgressState::Advanced {
                last_dispatched: "Z".to_string()
            }
            .to_wire(),
            Some(Some("Z".to_string())),
            "Advanced must produce Some(Some(last_dispatched)) (caller writes the offset)"
        );
        assert_eq!(
            ProgressState::Drained.to_wire(),
            Some(None),
            "Drained must produce Some(None) (caller clears the offset)"
        );
    }

    #[test]
    fn should_spawn_false_when_both_empty() {
        let cfg = empty_pin_config();
        assert!(!super::should_spawn(&cfg));
    }

    #[test]
    fn should_spawn_true_when_ipfs_set() {
        let cfg = ipfs_config();
        assert!(super::should_spawn(&cfg));
    }

    #[test]
    fn should_spawn_true_when_pinata_set() {
        let cfg = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--pinata-jwt",
            "test-jwt",
        ]);
        assert!(super::should_spawn(&cfg));
    }

    #[test]
    fn should_spawn_false_when_sweep_disabled() {
        let cfg = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            "http://127.0.0.1:5001",
            "--reconciliation-sweep",
            "false",
        ]);
        assert!(!super::should_spawn(&cfg));
    }

    /// spawn() must return `false` (and not spawn a task, touch the DB, or
    /// panic) when neither IPFS nor Pinata is configured. This proves the gate
    /// branch at the top of spawn() is actually reachable and observable.
    #[tokio::test]
    async fn test_spawn_gate_skips_when_no_pin_backends_configured() {
        let config = empty_pin_config();
        assert!(config.ipfs_api.is_empty(), "ipfs_api should be empty");
        assert!(config.pinata_jwt.is_empty(), "pinata_jwt should be empty");

        // Use a dummy Db built from a disconnected pool; spawn() must not
        // reach any code that would touch it.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgresql://localhost/gitlawb_test_nonexistent")
            .unwrap();
        let db = std::sync::Arc::new(crate::db::Db::for_testing(pool));
        let http = std::sync::Arc::new(reqwest::Client::new());
        let kp = std::sync::Arc::new(gitlawb_core::identity::Keypair::generate());
        let node_did = kp.did();
        let (_tx, rx) = watch::channel(false);
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        // spawn() should return false synchronously (no tokio::spawn) and never
        // await the DB.  The test completes without timeout == gate is live.
        assert!(
            !super::spawn(db, config, http, kp, node_did, pin_sem, rx),
            "gated spawn must report it did not start a worker"
        );
    }

    /// spawn() returns true and starts a worker when a backend is configured;
    /// the caller uses that to gate its own "worker started" logging.
    #[tokio::test]
    async fn test_spawn_returns_true_when_ipfs_configured() {
        let config = ipfs_config();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgresql://localhost/gitlawb_test_nonexistent")
            .unwrap();
        let db = std::sync::Arc::new(crate::db::Db::for_testing(pool));
        let http = std::sync::Arc::new(reqwest::Client::new());
        let kp = std::sync::Arc::new(gitlawb_core::identity::Keypair::generate());
        let node_did = kp.did();
        let (_tx, rx) = watch::channel(false);
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        assert!(
            super::spawn(db, config, http, kp, node_did, pin_sem, rx),
            "configured spawn must report it started a worker"
        );
    }

    /// The missing set must be deterministic, which is what makes the sweep's
    /// per-repo pin order reproducible across passes. The cap is applied by
    /// `cap_missing` at the call site, so `missing_oids` stays uncapped.
    /// `start_after = None` preserves the pre-P2 head-first order.
    #[test]
    fn missing_oids_is_deterministic() {
        let all = vec![
            "c".to_string(),
            "a".to_string(),
            "b".to_string(),
            "d".to_string(),
        ];
        let done = vec!["b".to_string()];

        let first = super::missing_oids(&all, &done, None);
        let second = super::missing_oids(&all, &done, None);
        assert_eq!(first, second, "missing set must be deterministic");
        assert_eq!(
            first,
            vec!["a".to_string(), "c".to_string(), "d".to_string()]
        );
    }

    /// Per-(repo, backend) continuation offset (#218 review P2). When
    /// `start_after` is the last OID the previous pass attempted, the
    /// next pass must rotate the sorted missing set so the first OID
    /// is strictly greater than that value, and the previously-attempted
    /// tail is retried at the end of the next pass. Without the
    /// rotation, a persistently failing early OID keeps landing at the
    /// start of the sort and dominates the cap window every hourly
    /// tick; with the rotation, the cap window advances fairly across
    /// passes and the healthy gap past the cap gets attempted.
    #[test]
    fn missing_oids_rotates_past_start_after() {
        let all: Vec<String> = (0..6).map(|i| format!("oid_{i:02}")).collect();
        let done: Vec<String> = Vec::new();

        // No offset: head-first order, the pre-P2 contract.
        let head = super::missing_oids(&all, &done, None);
        assert_eq!(
            head,
            vec!["oid_00", "oid_01", "oid_02", "oid_03", "oid_04", "oid_05"],
            "no offset preserves the deterministic head-first order"
        );

        // Offset = "oid_02": the next pass starts strictly past oid_02,
        // and the tail rotates to the end so previously-attempted OIDs
        // are retried last (not first).
        let rotated = super::missing_oids(&all, &done, Some("oid_02"));
        assert_eq!(
            rotated,
            vec!["oid_03", "oid_04", "oid_05", "oid_00", "oid_01", "oid_02"],
            "offset = oid_02 must rotate the set so oid_03..oid_05 lead and oid_00..oid_02 trail"
        );

        // Offset = "" (no OID has been attempted yet — the first ever
        // pass on this pair): the rotation is a no-op, same as None.
        let empty_offset = super::missing_oids(&all, &done, Some(""));
        assert_eq!(
            empty_offset, head,
            "an empty-string offset reads as 'nothing attempted yet', no rotation"
        );

        // Offset past the end: degenerate — the rotation would lose
        // data, so the helper returns sorted order as-is rather than
        // an empty list.
        let past_end = super::missing_oids(&all, &done, Some("oid_zz"));
        assert_eq!(
            past_end, head,
            "an offset past the end of the missing set must not lose data"
        );
    }

    /// Constant smoke-check kept as a compile-time tripwire.
    #[test]
    fn sweep_interval_constant_is_nonzero() {
        assert_ne!(super::SWEEP_INTERVAL_SECS, 0);
    }

    /// #218 P2 R3 (anchor log contract): the encrypted-manifest anchor is
    /// one-shot per seal. `plan_seal` returns `SkipUnchanged` on every
    /// subsequent pass once the recipients tag matches, so `sealed` stays
    /// empty and the anchor block never runs again. A transient Irys
    /// outage at the moment of a fresh seal therefore LOSES that anchor
    /// permanently — the next pass has no delta to anchor. The log MUST
    /// not promise a retry, because none will fire. This test pins the
    /// log content via the `ENCRYPTED_MANIFEST_ANCHOR_FAILED_MSG` constant
    /// so a future "helpful" revert to "will retry next pass" is caught at
    /// `cargo test` time.
    #[test]
    fn encrypted_manifest_anchor_log_does_not_promise_retry() {
        assert!(
            !super::ENCRYPTED_MANIFEST_ANCHOR_FAILED_MSG.contains("will retry"),
            "the encrypted-manifest anchor log must not promise a retry; \
             plan_seal returns SkipUnchanged on later passes, so a failed \
             anchor after a successful seal is permanent. See the comment \
             above the anchor block in run_pass for the one-shot contract. \
             Got: {:?}",
            super::ENCRYPTED_MANIFEST_ANCHOR_FAILED_MSG
        );
    }

    // ── run_pass integration tests ────────────────────────────────────────

    /// Minimal git repo builder (mirrors push_delta's test helper).
    struct Repo {
        _td: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    impl Repo {
        fn new() -> Self {
            let td = tempfile::TempDir::new().unwrap();
            let path = td.path().to_path_buf();
            let r = Repo { _td: td, path };
            r.git(&["init", "-q", "-b", "main"]);
            r.git(&["config", "user.email", "t@t"]);
            r.git(&["config", "user.name", "t"]);
            r
        }

        fn git(&self, args: &[&str]) -> String {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(&self.path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn commit_file(&self, name: &str, body: &str) -> String {
            std::fs::write(self.path.join(name), body).unwrap();
            self.git(&["add", name]);
            self.git(&["commit", "-qm", &format!("add {name}")]);
            self.git(&["rev-parse", "HEAD"])
        }
    }

    fn seed_repo(owner: &str, name: &str, disk_path: &str) -> crate::db::RepoRecord {
        let now = chrono::Utc::now();
        crate::db::RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: disk_path.to_string(),
            forked_from: None,
            machine_id: None,
        }
    }

    /// The sweep must repair an IPFS durability gap end to end: a public repo
    /// whose objects were never pinned gets every reachable blob pinned and
    /// recorded (R2-P2 "test the behavior the PR exists to change").
    #[sqlx::test]
    async fn sweep_fills_ipfs_gap_and_persists_cursor(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "public blob\n");

        let rec = seed_repo(
            "did:key:zSweepOwner",
            "sweep-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Mock IPFS: every /api/v0/add returns a fixed CID. mockito's unified
        // matcher compares the full "path?query" target, so the query string
        // pin_git_object appends must be part of the mock path.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmSweepMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);

        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(scanned, 1, "one repo scanned");
        assert!(gaps >= 1, "at least one missing blob found");
        assert_eq!(
            filled, gaps,
            "every found gap is filled in a clean mock-backed run"
        );
        _m.assert_async().await;

        // The recorded pin makes the blob "already done" on the next pass.
        let blob = repo_on_disk.git(&["rev-parse", "HEAD:a.txt"]);
        assert!(
            db.has_ipfs_cid(&blob).await.unwrap(),
            "pinned CID must be recorded and classified as IPFS-pinned"
        );

        // Cursor cleared on a short final page (R2-P1): with one repo the batch
        // is the whole key space, so persisting `batch_last` would just force an
        // empty tail pass next tick that scans nothing and then clears. Clearing
        // now means the next pass starts a fresh cycle immediately.
        let persisted = db.get_node_state(super::CURSOR_KEY).await.unwrap();
        assert!(
            persisted.is_none(),
            "cursor must be cleared after a fully-completed short final page"
        );
        assert!(
            cursor.is_none(),
            "in-memory cursor follows the persisted one"
        );

        // Second pass: no gaps remain.
        let (_, gaps2, filled2) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert_eq!(gaps2, 0, "second pass finds no remaining gaps");
        assert_eq!(filled2, 0);
    }

    /// Mirror rows (slash-form id, hardcoded is_public=true, no replicated
    /// visibility rules) must be skipped entirely: sweeping one would
    /// irreversibly publish content the canonical gate never admitted (R2-P1).
    #[sqlx::test]
    async fn sweep_skips_mirror_rows(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("secret.txt", "must not be published\n");

        // A mirror row pointing at a real, public-on-disk repo.
        db.upsert_mirror_repo(
            "zMirrorOwner",
            "mirror-repo",
            &repo_on_disk.path.display().to_string(),
            None,
            false,
        )
        .await
        .unwrap();

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            "http://127.0.0.1:1", // unreachable; must never be hit
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(scanned, 0, "mirror row is not scanned");
        assert_eq!(gaps, 0, "mirror row produces no gaps");
        assert_eq!(filled, 0, "mirror row is never pinned");

        // Nothing was recorded for the mirror's content.
        assert!(
            db.list_pinned_cids().await.unwrap().is_empty(),
            "no pinned_cids rows may exist after a mirror-only pass"
        );
    }

    /// A repo flagged `quarantined` after admission must produce zero mock IPFS
    /// traffic. The SQL dedup listing (`list_all_repos_deduped_stable`) filters
    /// `quarantined = FALSE` at the database, so the row never reaches the
    /// per-repo loop. The per-row `is_repo_quarantined` re-check is a
    /// race-only defense: the SQL filter is the primary gate. The strong
    /// assertion is on the side effects of the sweep pass, not on the
    /// counter, because a SQL filter that drops a row at the source makes the
    /// per-row check moot. (Reviewer-1 P2.)
    #[sqlx::test]
    async fn sweep_skips_quarantined_repos_before_scan(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("public.txt", "would be public if scanned\n");

        let rec = seed_repo(
            "did:key:zQuarOwner",
            "quar-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Flip quarantine AFTER admission (the realistic flow).
        let affected = db.set_repo_quarantine(&rec.id, true).await.unwrap();
        assert_eq!(affected, 1, "the new repo row must take the quarantine");

        // SQL-filter assertion: the dedup listing does not return quarantined
        // rows. If this changes, the per-row check below catches the race,
        // but a SQL filter regression would silently start scanning them.
        let dedup_rows = db.list_all_repos_deduped_stable(None, 100).await.unwrap();
        assert!(
            dedup_rows.iter().all(|r| r.id != rec.id),
            "quarantined repo is excluded from the dedup listing at SQL"
        );

        // Mock IPFS: any POST is a gate-ordering bug. expect(0) makes the
        // mock fail if hit.
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v0/add.*$".to_string()),
            )
            .expect(0)
            .with_status(200)
            .with_body(r#"{"Hash":"QmMustNotBeCalled"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(scanned, 0, "SQL filter drops the quarantined row");
        assert_eq!(gaps, 0);
        assert_eq!(filled, 0, "no pin work attempted");
        assert!(
            db.list_pinned_cids().await.unwrap().is_empty(),
            "no pinned_cids rows from a quarantined pass"
        );
        m.assert_async().await;
    }

    /// A non-public repo (`is_public = false`, no visibility rules) must also
    /// produce zero mock IPFS traffic. The dedup listing returns it (it is not
    /// quarantined), but the per-repo `listable_at_root` gate aborts before
    /// the expensive scan. (Reviewer-1 P2.)
    #[sqlx::test]
    async fn sweep_skips_private_repos_before_scan(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("private.txt", "never published\n");

        // Build a private repo row (seed_repo hardcodes is_public=true).
        let mut rec = seed_repo(
            "did:key:zPrivateOwner",
            "priv-repo",
            &repo_on_disk.path.display().to_string(),
        );
        rec.is_public = false;
        db.create_repo(&rec).await.unwrap();

        // No visibility rules: a private repo with no allow rules is unlistable.
        assert!(db.list_visibility_rules(&rec.id).await.unwrap().is_empty());

        // The dedup listing DOES return private (non-quarantined) rows, so
        // the per-repo gate is the actual filter under test.
        let dedup_rows = db.list_all_repos_deduped_stable(None, 100).await.unwrap();
        assert!(
            dedup_rows.iter().any(|r| r.id == rec.id),
            "private repo is in the dedup listing (filter is per-repo)"
        );

        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v0/add.*$".to_string()),
            )
            .expect(0)
            .with_status(200)
            .with_body(r#"{"Hash":"QmMustNotBeCalled"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        // The private row reaches the per-repo loop (the SQL filter is not
        // the gate here), the counter increments, then `listable_at_root`
        // returns false and the work aborts before the scan. Strong assertion
        // is on side effects.
        assert!(scanned >= 1, "the private row is in the dedup listing");
        assert_eq!(gaps, 0, "no gaps on a private-skip");
        assert_eq!(filled, 0, "no pin work attempted");
        assert!(
            db.list_pinned_cids().await.unwrap().is_empty(),
            "no pinned_cids rows from a private-only pass"
        );
        m.assert_async().await;
    }

    /// A public repo with a path-scoped deny must NOT have the withheld blob
    /// pinned in cleartext on a public backend (R2-P1 "must not pin"): the root
    /// stays listable, so the mid-scan refilter AND the pin-boundary re-derivation
    /// are the only layers between a narrowed subtree and irreversible public
    /// publication.
    #[sqlx::test]
    async fn sweep_never_pins_withheld_blob_in_cleartext(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("public.txt", "public content\n");
        // git needs the parent directory to exist before `git add` of a nested
        // path; create it, then stage via `git add -A` through the helper.
        std::fs::create_dir_all(repo_on_disk.path.join("secret")).unwrap();
        repo_on_disk.commit_file("secret/secret.txt", "must not go public\n");

        // Blob oids, not commit oids: commits are structural and legitimately
        // pinned publicly, so the must-not-pin assertion must key on the blob
        // whose content is denied at `secret/secret.txt`.
        let public_blob = repo_on_disk.git(&["rev-parse", "HEAD:public.txt"]);
        let secret_blob = repo_on_disk.git(&["rev-parse", "HEAD:secret/secret.txt"]);

        let rec = seed_repo(
            "did:key:zSweepWithheldOwner",
            "sweep-withheld",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Path-scoped deny with no readers: anonymous is allowed the repo root
        // (public) but denied every blob under /secret/**, whose content must
        // never reach the public pin backends.
        db.set_visibility_rule(
            &rec.id,
            "/secret/**",
            crate::db::VisibilityMode::B,
            &[],
            &rec.owner_did,
        )
        .await
        .unwrap();

        // Mock IPFS: every /api/v0/add returns a fixed CID (matches pin_git_object's
        // URL, which appends the cid-version/raw-leaves/pin query).
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .with_status(200)
            .with_body(r#"{"Hash":"QmWithheldMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(scanned, 1, "one repo scanned");

        assert!(gaps >= 1, "public blob is a real gap");
        let _ = filled; // encrypted/sealed copies do not count toward `filled`

        // The public blob is pinned and recorded as IPFS-pinned.
        assert!(
            db.has_ipfs_cid(&public_blob).await.unwrap(),
            "public blob must be pinned in cleartext"
        );

        // The withheld blob must NOT appear with an IPFS CID -- never pinned in
        // cleartext. (`has_ipfs_cid` only matches rows with a non-NULL cid, so an
        // encrypted copy recorded under `encrypted_blobs` cannot satisfy it.)
        assert!(
            !db.has_ipfs_cid(&secret_blob).await.unwrap(),
            "withheld blob must never be pinned to a public backend in cleartext"
        );
    }

    /// The final-page proxy must be the lookahead, not `batch.len() < page`
    /// (R1-P2): a key space ending on an exact page boundary looks "full" yet
    /// has no following row, so the cursor must be CLEARED, not persisted to a
    /// nonexistent next page (which would wedge the sweep into empty tail passes
    /// every tick). REPOS_PER_PASS repos and nothing more must behave exactly
    /// like one repo.
    #[sqlx::test]
    async fn sweep_clears_cursor_on_exact_page_boundary(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        // Exactly one full page of repos, each with a missing disk path (hard
        // skip, never scanned, so no pinning side effects).
        let n = super::REPOS_PER_PASS;
        for i in 0..n {
            let rec = seed_repo(
                "did:key:zExactPageOwner",
                &format!("exact-repo-{i:04}"),
                &format!("/nonexistent/disk/path-{i:04}"),
            );
            db.create_repo(&rec).await.unwrap();
        }

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            "http://127.0.0.1:1", // unreachable; must never be hit
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(scanned, 0, "missing-disk rows are hard skips, not scans");
        assert_eq!(gaps, 0);
        assert_eq!(filled, 0);

        let persisted = db.get_node_state(super::CURSOR_KEY).await.unwrap();
        assert!(
            persisted.is_none(),
            "an exact-page terminal batch must clear the cursor, not persist it \
             to a nonexistent next page (would wedge every subsequent tick)"
        );
        assert!(
            cursor.is_none(),
            "in-memory cursor follows the persisted one"
        );
    }

    /// R2-P1 regression: with `max_concurrent_pin_tasks = 1` (a semaphore of
    /// one permit) a repo that has BOTH public gaps AND encrypted seal work must
    /// still complete. The sweep holds one permit for the whole repo iteration
    /// and must reuse it for the seal phase; acquiring a SECOND permit for the
    /// same repo would wait on the very permit this iteration already holds,
    /// deadlocking the pass past its guard timeout. The run is wrapped in a
    /// timeout so a regression fails the test instead of hanging it.
    #[sqlx::test]
    async fn run_pass_reuses_the_pin_permit_for_the_seal_at_pool_size_one(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("public.txt", "public content\n");
        std::fs::create_dir_all(repo_on_disk.path.join("secret")).unwrap();
        repo_on_disk.commit_file("secret/secret.txt", "must not go public\n");

        let rec = seed_repo(
            "did:key:zSweepPoolOneOwner",
            "sweep-pool-one",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Path-scoped deny carrying one reader: yields withheld blobs whose
        // recipients make the seal phase reachable (the reviewer's probe).
        let reader = gitlawb_core::identity::Keypair::generate()
            .did()
            .to_string();
        db.set_visibility_rule(
            &rec.id,
            "/secret/**",
            crate::db::VisibilityMode::B,
            std::slice::from_ref(&reader),
            &rec.owner_did,
        )
        .await
        .unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmPoolOneMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        // Pool size 1: the permit the iteration holds is the only one.
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

        let pass = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            super::run_pass(
                &db,
                &config,
                &http,
                &node_seed,
                &node_did,
                &pin_sem,
                super::REPO_SCAN_DEADLINE,
                &mut cursor,
                &mut rx,
            ),
        )
        .await;

        let (scanned, gaps, _filled) = pass
            .expect("run_pass must complete, not deadlock waiting on its own permit")
            .expect("run_pass must succeed");
        assert_eq!(scanned, 1, "one repo scanned");
        assert!(gaps >= 1, "public blob is a real gap");
        _m.assert_async().await;
    }

    /// P2 regression: the mid-scan visibility re-filter must run against a
    /// FRESH deadline, not the spent `scan_deadline`. A spent deadline computes
    /// a zero remaining duration, `tokio::time::timeout` fires immediately, and
    /// the re-filter returns `None` — which `run_pass` turns into a `continue`
    /// that aborts the repo iteration before any pin work. That permanently
    /// skips exactly the large repos whose scans fill the read budget, the
    /// population the durability backstop exists for. This test proves both
    /// halves of the contract: a spent deadline starves the re-filter, and a
    /// fresh deadline lets it complete. `run_pass` passes the fresh
    /// `authz_deadline` at the mid-scan call site.
    #[tokio::test]
    async fn refilter_starves_on_spent_deadline_but_runs_on_fresh_deadline() {
        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "public blob\n");
        let blob = repo_on_disk.git(&["rev-parse", "HEAD:a.txt"]);

        // Empty rules + public repo: the blob is listable at root and passes the
        // re-derivation when it actually runs.
        let rules: Vec<crate::db::VisibilityRule> = Vec::new();

        // Spent deadline (the scan consumed its whole budget): the re-filter
        // times out immediately and returns None — the starvation class the fix
        // removes. `run_pass` would `continue` on this and never reach the pin
        // phases.
        let spent = std::time::Instant::now() - std::time::Duration::from_secs(1);
        let starved = super::refilter_public_objects(
            &repo_on_disk.path,
            &rules,
            true,
            "did:key:zStarvationOwner",
            vec![blob.clone()],
            spent,
        )
        .await;
        assert!(
            starved.is_none(),
            "a spent deadline must starve the visibility re-filter (immediate timeout)"
        );

        // Fresh deadline (the fix's `authz_deadline`): the re-filter runs to
        // completion and re-passes the blob.
        let fresh = std::time::Instant::now() + super::REPO_SCAN_DEADLINE;
        let ran = super::refilter_public_objects(
            &repo_on_disk.path,
            &rules,
            true,
            "did:key:zStarvationOwner",
            vec![blob.clone()],
            fresh,
        )
        .await;
        assert_eq!(
            ran,
            Some(vec![blob]),
            "a fresh deadline must let the visibility re-filter run to completion"
        );
    }

    /// P3 wiring: the mid-scan re-filter's FRESH budget must come from the
    /// `rederive_budget` plumbed through `run_pass`, not a module const computed
    /// inside it. With a spent budget `run_pass` must skip the repo entirely
    /// (nothing pinned) — if the mid-scan call site reverted to the fresh
    /// `scan_deadline`, the repo would get pinned and this assertion fails.
    #[sqlx::test]
    async fn run_pass_starves_repo_on_spent_rederive_budget_and_runs_on_fresh(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "public blob\n");

        let rec = seed_repo(
            "did:key:zWiringOwner",
            "sweep-wiring",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmWiringMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        // Spent budget: the mid-scan re-filter's `Instant::now() + ZERO` is
        // already exhausted by the time the scan finishes, so the recheck times
        // out immediately and run_pass skips the repo — nothing is pinned.
        let (scanned, gaps, _filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            std::time::Duration::ZERO,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert_eq!(scanned, 1, "repo is scanned before the re-filter");
        assert_eq!(gaps, 0, "a starved re-filter must not report gaps");
        assert!(
            db.list_pinned_cids().await.unwrap().is_empty(),
            "a spent re-derive budget must leave the repo unpinned (call-site wiring)"
        );

        // Fresh budget: the same repo now completes — proving the budget really
        // flows through the call site, not a module const a test cannot hold.
        let (_scanned, gaps2, _filled2) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert!(gaps2 >= 1, "fresh budget lets the re-filter find the gap");
        let blob = repo_on_disk.git(&["rev-parse", "HEAD:a.txt"]);
        assert!(
            db.has_ipfs_cid(&blob).await.unwrap(),
            "fresh re-derive budget must let the sweep record the pin"
        );
        _m.assert_async().await;
    }

    /// #218 review P1 regression: the local-IPFS provenance predicate
    /// (`local_ipfs_provenance = TRUE`, set by the local IPFS writer
    /// only) must let a previously-Pinata-only row be PROMOTED to
    /// local-IPFS-pinned the moment a real local pin lands, without
    /// requiring a config switch in the test. The contract Reviewer 1
    /// called out: "an object pinned directly to Pinata with no prior
    /// local IPFS pin gets `cid = raw_cid`, never the provider CID
    /// [never aliases bytes that don't hash to it, #173]; when IPFS
    /// is later enabled the sweep must re-derive and pin it locally."
    ///
    /// The test seeds a Pinata-only row via the production
    /// `record_pinata_cid` path with `raw_cid != pinata_cid`. In the
    /// pre-v30 schema, this row would have `cid = Some(raw_cid)` AND
    /// `pinata_cid = Some(provider_cid)` — a shape the old
    /// `cid IS NOT NULL` predicate read as "locally pinned", so the
    /// pre-v30 sweep would skip it as already durable. After v30, the
    /// `record_pinata_cid` writer never sets `local_ipfs_provenance`
    /// (the Pinata path never pins locally), so the new
    /// `local_ipfs_provenance = TRUE` predicate excludes the row from
    /// `filter_ipfs_pinned_oids` and the sweep sees it as a real
    /// local-IPFS gap. A later `record_pinned_cid_with_source` call
    /// brings it back in. The filter result before and after the
    /// local write is the durable contract.
    #[sqlx::test]
    async fn sweep_promotes_pinata_only_to_local_ipfs_when_writer_invoked(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();

        // Pinata-only row: distinct raw CID and provider CID, the
        // shape that the pre-v30 `cid IS NOT NULL` predicate
        // mis-classified as locally pinned. The raw_cid is the
        // locally-computed resolver key (per `pinata.rs` documentation,
        // never the dag-pb provider CID); the pinata_cid is the
        // provider's response.
        let sha = "sha_pinata_only_then_local";
        let raw_cid = "bafkreirawcontentcidv1sverifierkey";
        let pinata_cid = "QmPinataProviderCidForThisBlob";
        assert_ne!(
            raw_cid, pinata_cid,
            "the test fixture must use distinct raw and provider CIDs"
        );
        db.record_pinata_cid(sha, raw_cid, pinata_cid, None, i64::MAX)
            .await
            .unwrap();

        // Pre-condition: the Pinata-only row has `cid = Some(raw_cid)`
        // (the locally-computed resolver key, NOT the provider CID)
        // and `pinata_cid = Some(provider_cid)`. The pre-v30 sweep's
        // `cid IS NOT NULL` predicate would read this as locally
        // pinned. The post-v30 predicate `local_ipfs_provenance = TRUE`
        // — which the Pinata writer never sets — reads it as
        // Pinata-only, so the row is a real local-IPFS gap.
        let row: (Option<String>, Option<String>, Option<bool>) = sqlx::query_as(
            "SELECT cid, pinata_cid, local_ipfs_provenance FROM pinned_cids WHERE sha256_hex = $1",
        )
        .bind(sha)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            row.0.as_deref(),
            Some(raw_cid),
            "Pinata-only row must carry the raw CID in `cid` (the locally-computed resolver key, never the provider CID, #173)"
        );
        assert_eq!(
            row.1.as_deref(),
            Some(pinata_cid),
            "Pinata-only row must carry the provider CID in pinata_cid"
        );
        assert_eq!(
            row.2,
            Some(false),
            "Pinata-only row must have local_ipfs_provenance = FALSE — the Pinata writer never pins locally"
        );

        // The P1 contract: the gap filter used by the sweep
        // (`filter_ipfs_pinned_oids`) does NOT consider the row
        // already-done. Without this, a Pinata-only node that later
        // enables IPFS would never re-pin the object to local IPFS
        // (the pre-v30 filter would treat the existing `cid` value
        // as durable local evidence and skip it).
        let candidates = vec![sha.to_string()];
        let mut before = db.filter_ipfs_pinned_oids(&candidates).await.unwrap();
        before.sort();
        assert!(
            before.is_empty(),
            "a Pinata-only row must NOT be returned by filter_ipfs_pinned_oids — the sweep must still see it as a local-IPFS gap"
        );
        assert!(
            !db.has_ipfs_cid(sha).await.unwrap(),
            "a Pinata-only row must NOT be reported by has_ipfs_cid"
        );

        // The local-IPFS writer succeeds (the same call
        // `ipfs_pin.rs:2103` makes after a real Kubo `add`). The raw
        // CID is the same one the Pinata-only row already knows, so
        // the resolver key is unchanged.
        db.record_pinned_cid_with_source(sha, raw_cid, "repo-pinata-then-local")
            .await
            .unwrap();

        // Post-condition: the same row is now in the IPFS-pinned set.
        // The local writer upgraded `local_ipfs_provenance` to TRUE
        // on the conflict branch (the seam is the same row that v30
        // left at FALSE for the Pinata-only path).
        let mut after = db.filter_ipfs_pinned_oids(&candidates).await.unwrap();
        after.sort();
        assert_eq!(
            after,
            vec![sha.to_string()],
            "after the local-IPFS writer succeeds, the same row must be in the IPFS-pinned set"
        );
        assert!(
            db.has_ipfs_cid(sha).await.unwrap(),
            "after the local-IPFS writer succeeds, has_ipfs_cid must report TRUE"
        );

        // The resolver key on the row is still the raw CID, unchanged.
        // This is the durable contract for clients: `GET /ipfs/{cid}`
        // always resolves to the locally-computed raw CID, never the
        // Pinata provider CID (the bytes don't hash to it, #173).
        let stored_cid: Option<String> =
            sqlx::query_scalar("SELECT cid FROM pinned_cids WHERE sha256_hex = $1")
                .bind(sha)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            stored_cid.as_deref(),
            Some(raw_cid),
            "the resolver key is the raw CID, not the Pinata provider CID"
        );
    }

    /// #218 review P2 regression: the per-(repo, backend) continuation
    /// offset lifecycle. A pass that attempted at least one OID (the
    /// normal "found a gap, pinned it" path) persists
    /// `next_oid = last_attempted, done = FALSE`. A subsequent pass
    /// that finds zero missing OIDs (the post-pin happy path) marks
    /// the row `done = TRUE` so a stale resume can never re-derive
    /// against an empty missing set. The contract is owned at the
    /// sweep loop's call site to `save_reconciliation_offset`.
    #[sqlx::test]
    async fn sweep_persists_per_backend_continuation_offset(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        // Repo on disk with one blob — a 1-OID missing set is enough
        // to exercise the offset machinery (the rotation is the same
        // for any size, and the cap is the only place the production
        // sweep writes the offset).
        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "public blob\n");
        let rec = seed_repo(
            "did:key:zOffsetOwner",
            "offset-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Mock IPFS — generic accept.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmOffsetMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        // First pass: the public blob is a missing OID, the sweep
        // pins it. The missing set had one element, so the offset
        // is persisted as `next_oid = that_oid, done = FALSE` —
        // the resume point the next pass would consult, not a
        // "we are done" marker.
        let (_scanned, gaps1, _filled1) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert!(gaps1 >= 1, "first pass finds the public blob as a gap");
        let stored = db
            .load_reconciliation_offset(&rec.id, "IPFS")
            .await
            .unwrap();
        // After a pass that actually attempted work, the offset
        // is the last attempted OID with done = FALSE. The load
        // returns it (not None) — a future pass that finds the
        // same OID still missing would rotate past it.
        assert!(
            stored.is_some(),
            "a pass that attempted OIDs must persist a resume point (done = FALSE), not a done marker"
        );

        // Second pass: the OID is now IPFS-pinned (the gap filter
        // excludes it), so `ipfs_missing.is_empty()` and the offset
        // save call hands `next_oid = None` to `save_reconciliation_offset`,
        // which marks the row `done = TRUE`. The load filters done
        // rows out so subsequent passes see this as a fresh start.
        let (_scanned2, gaps2, _filled2) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert_eq!(gaps2, 0, "second pass finds no remaining gaps");
        let stored2 = db
            .load_reconciliation_offset(&rec.id, "IPFS")
            .await
            .unwrap();
        assert!(
            stored2.is_none(),
            "a no-missing pass must mark the offset done (load returns None)"
        );
    }

    /// #218 review round 8 P2: the continuation offset advances only for
    /// work that was actually DISPATCHED to a backend.
    ///
    /// The failure it guards: `ipfs_last` used to be captured from the missing
    /// set before the pin permit, both `PolicyFence` captures and both pin loops,
    /// and written afterwards under nothing but `if ipfs_enabled`. So a pass whose
    /// missing set was non-empty but whose pin boundary declined — a transient
    /// fence, recheck or re-derivation failure — still moved the offset to the end
    /// of a set it never attempted. `missing_oids` rotates strictly past the
    /// stored offset, so on the next pass that whole unattempted prefix lands
    /// BEHIND the entire backlog. For an at-cap repo the backlog never drains in
    /// one window, so those objects are starved indefinitely rather than retried
    /// — a durability hole in the durability backstop.
    ///
    /// The test seeds a resume point, then runs a pass whose pin boundary fails
    /// (the `set_fail_pin_boundary_rederive` seam; see its comment for why the
    /// stage cannot be starved from the outside). The stored offset must come back
    /// BYTE-IDENTICAL: not advanced, and not cleared to a done marker either.
    /// Then the seam is released and the same repo, unchanged, advances it — so
    /// the assertion cannot pass merely because the write site is dead.
    #[sqlx::test]
    async fn sweep_leaves_offset_untouched_when_nothing_was_dispatched(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "public blob\n");
        let rec = seed_repo(
            "did:key:zNoDispatchOwner",
            "no-dispatch-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .with_status(200)
            .with_body(r#"{"Hash":"QmNoDispatchMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        // A resume point a previous capped pass would have paid for. Chosen
        // below every real OID so it does not rotate the missing set empty.
        let seeded = "0".repeat(64);
        db.save_reconciliation_offset(&rec.id, "IPFS", Some(&seeded))
            .await
            .unwrap();

        // Pass 1: the missing set is non-empty (there is a real gap), but the
        // pin boundary declines, so nothing reaches the backend.
        super::set_fail_pin_boundary_rederive(true);
        let mut cursor = None;
        let (_scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        super::set_fail_pin_boundary_rederive(false);

        assert!(gaps >= 1, "the pass must have found real gap-fill work");
        assert_eq!(
            filled, 0,
            "the pin boundary declined, so nothing was filled"
        );
        assert!(
            db.list_pinned_cids().await.unwrap().is_empty(),
            "nothing may have been dispatched to the backend"
        );

        let after_fail = db
            .load_reconciliation_offset(&rec.id, "IPFS")
            .await
            .unwrap();
        assert_eq!(
            after_fail.as_deref(),
            Some(seeded.as_str()),
            "a pass that dispatched NOTHING must leave the continuation exactly \
             where it was — advancing it rotates the unattempted prefix behind the \
             whole backlog, and clearing it discards the resume point a capped pass \
             already paid for"
        );

        // Pass 2, same repo, seam released: real dispatch happens and the offset
        // does move. Without this the assertion above would also pass if the
        // write site were simply dead.
        let mut cursor2 = None;
        let (_s2, gaps2, filled2) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor2,
            &mut rx,
        )
        .await
        .unwrap();
        assert!(gaps2 >= 1, "the gap is still there to be filled");
        assert!(filled2 >= 1, "a dispatched pass fills the gap");
        let after_ok = db
            .load_reconciliation_offset(&rec.id, "IPFS")
            .await
            .unwrap();
        assert_ne!(
            after_ok.as_deref(),
            Some(seeded.as_str()),
            "a pass that DID dispatch must advance the continuation past the seed"
        );
    }

    /// #218 review P2 multi-pass regression: a previously-capped
    /// pass's persisted `next_oid` MUST rotate the next pass's
    /// attempt order so a healthy OID past the offset moves into the
    /// cap window. Reviewer 1's explicit ask: "a multi-pass
    /// regression with a permanently failing early OID and a later
    /// healthy missing OID, asserting the later object is attempted
    /// on a subsequent pass."
    ///
    /// The test simulates the production scenario at the smallest
    /// scale that still proves the contract: pre-seed an offset
    /// that points at the early OID `A` (as if a prior pass had
    /// attempted-and-failed `A` and the cap truncated everything
    /// past it), then run a fresh pass. The healthy OID `Z` (the
    /// later OID) must be attempted — without the rotation it would
    /// be at the tail of the missing set and could be skipped if
    /// the cap was tighter than the missing-set size. With the
    /// rotation, `Z` is the first OID strictly greater than the
    /// offset, so the gap-fill reaches it.
    #[sqlx::test]
    async fn sweep_attempts_healthy_oid_past_persistent_offset(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        // Repo on disk with two distinct blobs. Their OIDs sort as
        // `A < Z` (the first commit's blob sorts before the second
        // by sha). The names are anchors for the assertions, not
        // the actual sha values.
        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "would-fail-content\n");
        let a_blob = repo_on_disk.git(&["rev-parse", "HEAD:a.txt"]);
        repo_on_disk.commit_file("z.txt", "healthy-content\n");
        let z_blob = repo_on_disk.git(&["rev-parse", "HEAD:z.txt"]);
        assert!(
            a_blob < z_blob,
            "test fixture requires A's blob to sort before Z's so the rotation is observable"
        );

        let rec = seed_repo(
            "did:key:zMultiPassOwner",
            "multi-pass-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Pre-seed: a prior pass attempted-and-failed A, and the
        // cap truncated the rest. The persisted offset is A (the
        // last attempted OID). The next pass's `missing_oids` will
        // rotate so A moves to the tail and Z leads the cap window.
        // `done = FALSE` so the load returns the offset and the
        // rotation actually runs.
        db.save_reconciliation_offset(&rec.id, "IPFS", Some(&a_blob))
            .await
            .unwrap();

        // Sanity: the offset is exactly what we wrote.
        let loaded = db
            .load_reconciliation_offset(&rec.id, "IPFS")
            .await
            .unwrap();
        assert_eq!(
            loaded.as_deref(),
            Some(a_blob.as_str()),
            "the pre-seeded offset must round-trip through the load"
        );

        // Mock IPFS — generic accept. The actual `Z` success is
        // what the test asserts on (the rotation brings Z forward
        // and the sweep pins it; the post-pass offset is then
        // either Z (cap not hit on a 2-OID set, so done = TRUE)
        // or done with the row cleared).
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmMultiPassMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        // Single pass. The offset pre-seed drives the rotation, the
        // missing set is [A, Z] but rotates to [Z, A] (Z first
        // because it's strictly greater than the offset A). The
        // sweep pins both — Z succeeds (the mock returns a body)
        // and A may or may not (the mock returns a body for it
        // too on the same endpoint). The contract under test is
        // that Z is in the IPFS-pinned set after the pass.
        let (_scanned, _gaps, _filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        // The healthy OID Z is in the IPFS-pinned set. The
        // rotation brought it forward, and the sweep recorded the
        // pin. This is the durable contract Reviewer 1 called
        // out: a healthy gap past the cap is attempted on a
        // subsequent pass.
        assert!(
            db.has_ipfs_cid(&z_blob).await.unwrap(),
            "healthy OID Z (past the persistent offset) must be pinned on the next pass"
        );

        // The offset is now at `done = FALSE` with the last
        // attempted OID as `next_oid` (the pass DID attempt work
        // — both A and Z were rotated into the cap window and
        // handed to the backend). The rotation is observable in
        // the load: a future pass that finds A still missing
        // would rotate past the last attempted OID, advancing
        // forward through the missing set rather than getting
        // stuck on A every hourly tick. The exact `next_oid`
        // value depends on the order pin_git_object records the
        // pins (which is the rotated order [Z, A] from
        // `missing_oids`); we assert only that it is set, not
        // which OID it is.
        let after = db
            .load_reconciliation_offset(&rec.id, "IPFS")
            .await
            .unwrap();
        assert!(
            after.is_some(),
            "a pass that attempted the rotated OIDs must persist a resume point, not a done marker"
        );

        _m.assert_async().await;
    }

    /// #218 review P1b: the reconciliation sweep must not publish a
    /// public repo's root tree when the root tree's serialized bytes
    /// name a denied subtree entry. The root tree of a public commit
    /// with `/secret/**` deny is structurally unsafe: its entries
    /// include `secret -> <denied-subtree-oid>`, and pinning the
    /// root tree to a public IPFS/Pinata backend would let anyone who
    /// obtains the CID inspect the denied subtree's name and child
    /// OID — the same metadata a `/secret/**` deny is meant to
    /// withhold. The fix gates the root tree on the structural
    /// entry-level check in `allowed_blob_tree_sets_bounded`, which
    /// also covers the per-request `/ipfs/{cid}` tree gate (caller-
    /// aware variant).
    ///
    /// The test seeds a single public commit whose tree has two
    /// direct entries: `public.txt` (allowed) and `secret/`
    /// (denied). After a sweep pass with mock IPFS accepting every
    /// upload, the durable state must include exactly one
    /// `pinned_cids` row — for the public.txt blob, with
    /// `local_ipfs_provenance = TRUE` — and zero rows for the root
    /// tree or the secret subtree tree.
    #[sqlx::test]
    async fn sweep_never_pins_root_tree_naming_withheld_subtree(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        // Repo on disk: one public commit with a top-level file and a
        // top-level directory. The directory is itself a subtree
        // tree (`secret`) that holds the withheld blob.
        let repo_on_disk = Repo::new();
        std::fs::create_dir_all(repo_on_disk.path.join("secret")).unwrap();
        repo_on_disk.commit_file("public.txt", "public bytes\n");
        repo_on_disk.commit_file("secret/secret.txt", "withheld bytes\n");

        // Resolve oids so the assertions are precise.
        let public_blob = repo_on_disk.git(&["rev-parse", "HEAD:public.txt"]);
        let secret_blob = repo_on_disk.git(&["rev-parse", "HEAD:secret/secret.txt"]);
        let secret_tree = repo_on_disk.git(&["rev-parse", "HEAD:secret"]);
        let root_tree = repo_on_disk.git(&["rev-parse", "HEAD^{tree}"]);

        let rec = seed_repo(
            "did:key:zWithheldSubtreeOwner",
            "withheld-subtree-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // /secret/** deny, with no readers: the public.txt blob is
        // listable; the secret/ subtree tree and its blob are
        // withheld. The root tree is structurally unsafe (its entry
        // list names the denied subtree), and a previously-buggy
        // synthetic-"/" gate would have admitted it.
        db.set_visibility_rule(
            &rec.id,
            "/secret/**",
            crate::db::VisibilityMode::B,
            &[],
            &rec.owner_did,
        )
        .await
        .unwrap();

        // Mock IPFS: accept everything. The sweep would happily
        // upload the root tree + secret subtree tree if the gate
        // let them through; the test asserts they don't.
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmWithheldSubtreeMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, _filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert_eq!(scanned, 1, "one repo scanned");
        assert!(
            gaps >= 1,
            "the public.txt blob is a real gap (and the structural gate keeps the root \
             tree out of the gap set, so the only gap is the public blob)"
        );

        // The public blob is the only IPFS-pinned object: the root
        // tree and the secret subtree tree are absent from
        // `pinned_cids` because the structural gate excluded them
        // before they reached the writer.
        assert!(
            db.has_ipfs_cid(&public_blob).await.unwrap(),
            "public.txt blob must be IPFS-pinned (its path /public.txt is allowed)"
        );
        assert!(
            !db.has_ipfs_cid(&secret_blob).await.unwrap(),
            "secret.txt blob must not be IPFS-pinned (regression of the blob gate; the \
             public blob gate is exercised by sweep_never_pins_withheld_blob_in_cleartext)"
        );
        // The structural fix means the root tree was never a candidate
        // — assert the durable evidence directly.
        let pinned = db.list_pinned_cids().await.unwrap();
        for p in &pinned {
            assert_ne!(
                p.sha256_hex, root_tree,
                "root tree must not be replicated: its serialized bytes name the denied \
                 /secret subtree entry, which is the metadata /secret/** is meant to withhold"
            );
            assert_ne!(
                p.sha256_hex, secret_tree,
                "secret subtree tree must not be replicated: its only entry is the \
                 withheld secret.txt blob, and the structural check excludes it"
            );
        }

        m.assert_async().await;
    }

    /// #218 review P1b (recursive at every depth): the structural
    /// tree gate must deny the entire chain of ancestor trees
    /// whose entries point at a withheld subtree. This is the
    /// nested case: a public repo with `/public/secret/file.txt`
    /// and a `/public/secret/**` deny. The `/public` tree is at
    /// an allowed path AND its only top-level entry is `secret/`
    /// (a tree). The secret subtree is denied at `/public/secret`,
    /// so the secret subtree is excluded — and that propagates up
    /// through `/public`'s `secret/` entry. The root tree's
    /// `public/` entry is also denied because `/public` is denied.
    /// Net: the root tree, `/public` tree, and `/public/secret`
    /// subtree tree are all absent from `pinned_cids`; the
    /// `/public/secret/file.txt` blob is denied; only
    /// `/public/visible.txt` is IPFS-pinned.
    #[sqlx::test]
    async fn sweep_does_not_publish_public_ancestor_tree_naming_withheld_subtree(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        // Repo on disk: top-level `public/`, with `public/visible.txt`
        // and `public/secret/file.txt`. The `/public/secret/**` deny
        // makes the entire secret subtree off-limits to anon, and
        // the structural check propagates that up to the `/public`
        // tree (whose only entry is `secret/`) and to the root
        // tree (whose only entry is `public/`).
        let repo_on_disk = Repo::new();
        std::fs::create_dir_all(repo_on_disk.path.join("public").join("secret")).unwrap();
        repo_on_disk.commit_file("public/visible.txt", "public bytes\n");
        repo_on_disk.commit_file("public/secret/file.txt", "TOP SECRET\n");

        // Resolve oids for the assertions.
        let visible_blob = repo_on_disk.git(&["rev-parse", "HEAD:public/visible.txt"]);
        let secret_blob = repo_on_disk.git(&["rev-parse", "HEAD:public/secret/file.txt"]);
        let secret_subtree = repo_on_disk.git(&["rev-parse", "HEAD:public/secret"]);
        let public_tree = repo_on_disk.git(&["rev-parse", "HEAD:public"]);
        let root_tree = repo_on_disk.git(&["rev-parse", "HEAD^{tree}"]);

        let rec = seed_repo(
            "did:key:zNestedWithheldOwner",
            "nested-withheld-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        db.set_visibility_rule(
            &rec.id,
            "/public/secret/**",
            crate::db::VisibilityMode::B,
            &[],
            &rec.owner_did,
        )
        .await
        .unwrap();

        // Mock IPFS: accept everything. The sweep would happily
        // upload the whole tree chain if the structural gate let
        // any of it through; the test asserts none of it does.
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmNestedWithheldMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, gaps, _filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert_eq!(scanned, 1, "one repo scanned");
        assert!(
            gaps >= 1,
            "/public/visible.txt blob is a real gap (and the structural gate keeps the entire tree chain out)"
        );

        // Only /public/visible.txt is IPFS-pinned. Every tree in
        // the chain — root, /public, /public/secret — is denied by
        // the structural gate, and the secret blob is denied by
        // the path gate.
        assert!(
            db.has_ipfs_cid(&visible_blob).await.unwrap(),
            "/public/visible.txt must be IPFS-pinned (its path /public/visible.txt is allowed)"
        );
        assert!(
            !db.has_ipfs_cid(&secret_blob).await.unwrap(),
            "/public/secret/file.txt must NOT be IPFS-pinned (path /public/secret/** is denied)"
        );

        let pinned = db.list_pinned_cids().await.unwrap();
        for p in &pinned {
            assert_ne!(
                p.sha256_hex, root_tree,
                "root tree must not be replicated: its /public/ entry's child tree is structurally denied"
            );
            assert_ne!(
                p.sha256_hex, public_tree,
                "/public tree must not be replicated: its only entry is the withheld secret/ subtree"
            );
            assert_ne!(
                p.sha256_hex, secret_subtree,
                "/public/secret subtree tree must not be replicated: its only entry is the withheld file.txt blob"
            );
        }

        m.assert_async().await;
    }

    /// #218 review P1 (non-commit ref acceptance): a repo with a
    /// pushable tag-of-tree ref (a supported Git shape) must
    /// still get its commit-reachable public objects classified
    /// and pinned by the sweep. Before the fix, `all_object_paths`
    /// called `assert_all_refs_are_commits`, which bailed on any
    /// ref that didn't peel to a commit. A repo with an annotated
    /// tag pointing at the root tree would have its whole walk
    /// fail-closed — no IPFS pin, no Pinata pin, no sweep. The
    /// fix removes the assertion; `git rev-list --all` already
    /// silently skips non-commit refs, so the commit-reachable
    /// object set is what the sweep needs. The tag-of-tree
    /// itself is not commit-reachable and falls out as an
    /// empty-path entry that the path-based allow filter drops
    /// (fail-closed).
    #[sqlx::test]
    async fn sweep_repairs_commit_reachable_object_in_repo_with_tag_of_tree(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        // Repo on disk: one public commit with one blob, plus an
        // annotated tag pointing at a *separate* tree (a manually
        // mktree'd tree that is NOT commit-reachable). The tag is
        // a "tag-of-tree" — a valid Git shape, but `git rev-list
        // --all` skips it (it doesn't peel to a commit). The
        // separate tree lets the test distinguish the
        // commit-reachable root tree (which IS in the gap set) from
        // the unclassifiable tag-of-tree (which is NOT in the gap
        // set under the new tolerance).
        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "public bytes\n");
        let blob_oid = repo_on_disk.git(&["rev-parse", "HEAD:a.txt"]);
        let root_tree = repo_on_disk.git(&["rev-parse", "HEAD^{tree}"]);

        // Create a separate, unrelated tree via `git mktree` —
        // NOT commit-reachable. The annotated tag will point at
        // this tree, making the repo a "tag-of-tree" repo.
        let mktree = std::process::Command::new("git")
            .args(["mktree"])
            .current_dir(&repo_on_disk.path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let tree_only_oid =
            String::from_utf8_lossy(mktree.wait_with_output().unwrap().stdout.as_slice())
                .trim()
                .to_string();
        assert_ne!(
            tree_only_oid, root_tree,
            "mktree'd tree is distinct from root tree"
        );

        let tag_out = std::process::Command::new("git")
            .args([
                "tag",
                "-a",
                "treetag",
                &tree_only_oid,
                "-m",
                "tag of a tree",
            ])
            .current_dir(&repo_on_disk.path)
            .output()
            .unwrap();
        assert!(tag_out.status.success(), "git tag -a");

        let rec = seed_repo(
            "did:key:zTagOfTreeOwner",
            "tag-of-tree-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Mock IPFS: accept everything. The sweep must reach the
        // commit-reachable blob despite the unclassifiable
        // tag-of-tree ref.
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmTagOfTreeMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;
        let pin_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(2));

        let (scanned, _gaps, _filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &pin_sem,
            super::REPO_SCAN_DEADLINE,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert_eq!(scanned, 1, "one repo scanned");

        // The commit-reachable blob is IPFS-pinned.
        assert!(
            db.has_ipfs_cid(&blob_oid).await.unwrap(),
            "the commit-reachable public blob must be IPFS-pinned despite the \
             unclassifiable tag-of-tree ref (assert_all_refs_are_commits is removed)"
        );

        // The tag-of-tree itself is NOT pinned: it's not
        // commit-reachable, so it has no path in the ls-tree
        // walk, and the cat-file catch-all enumerates it with an
        // empty path which the path-based allow filter drops
        // (fail-closed). The commit-reachable root tree IS
        // structurally safe and IS pinned, so the assertion
        // compares against the tag-of-tree OID specifically.
        let pinned = db.list_pinned_cids().await.unwrap();
        for p in &pinned {
            assert_ne!(
                p.sha256_hex, tree_only_oid,
                "tag-of-tree must not be replicated: it's not commit-reachable and the \
                 empty-path allow filter drops it (fail-closed)"
            );
        }

        m.assert_async().await;
    }
}
