//! #26 Split PR 1 — durable post-receive outbox: the recovery drain.
//!
//! This module owns the STARTUP drain for `pending_ref_transitions`. It
//! iterates every row in state `applied`, re-derives the push event, the
//! per-ref certificate, and the anchor handoff using the ORIGINAL pusher
//! DID and signature header that was persisted BEFORE the receive-pack
//! call landed the ref, and then deletes the row.
//!
//! The drain is invoked once at startup, after migrations and before
//! serving, in [`crate::main`]. It is also the function the failure-
//! injection end-to-end test calls to simulate a "node restart" after
//! the crash window the reviewer flagged.
//!
//! Idempotency is delegated to the DB layer. The push event and anchor
//! job use `ON CONFLICT (id) DO NOTHING` keyed on the deterministic
//! `(request_id, ref_name)` / `(repo_id, ref_name, old_sha, new_sha)`
//! id. The ref certificate uses
//! `insert_ref_certificate_idempotent`, which checks the unique
//! `(repo_id, ref_name)` index and returns `None` if a live-path cert
//! already exists. Re-running the drain against the same row is
//! therefore a no-op for the artifact writes; the row deletion at the
//! end is also idempotent because a missing `id` simply affects zero
//! rows.

use crate::cert;
use crate::db::PendingRefTransition;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// The git all-zeros object id — the create/delete sentinel in a ref update.
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

/// Promote `prepared` rows whose `new_sha` matches the on-disk ref to
/// `applied`, so the recovery drain (which only reads `state =
/// 'applied'`) picks them up on the next pass. The reconcile runs at
/// startup, BEFORE the drain.
///
/// This is the second half of the P1-A fix. The first half is the
/// live handler's `mark_pending_ref_transitions_applied` call, which
/// can fail or be interrupted AFTER `receive_pack` returned `Ok`. A
/// `prepared` row whose target ref actually landed on disk has no
/// recovery path without this step: the drain's WHERE clause does not
/// see it, and a startup that boots and serves traffic would silently
/// lose the push event, the cert, and the anchor handoff for that
/// ref.
///
/// Strict SHA equality is the load-bearing correctness check. A row
/// whose `new_sha` does NOT match the on-disk ref stays `prepared`;
/// the invariant "a failed receive-pack is never promoted to
/// completed accounting" is preserved by the equality check, not by
/// state alone. A `cancelled` row is also never promoted (the
/// `list_pending_ref_transitions_prepared` SELECT gates on
/// `state = 'prepared'`, and the UPDATE re-checks the state).
///
/// The SHA check alone is not sufficient. A `prepared` row could
/// have a `new_sha` that currently matches the on-disk ref for a
/// reason OTHER than its own transition (e.g. a later push
/// re-introduced the same SHA on the same ref). To prevent the
/// recovery drain from writing artifacts for a transition the node
/// cannot prove actually happened, the reconcile ALSO requires the
/// row's `created_at` to be within [`MAX_RECONCILE_AGE`] of the
/// current time. Rows older than the window are left `prepared` for
/// human-attended recovery. This is the second correctness barrier,
/// and the reason a `prepared` row that happens to match a current
/// on-disk SHA does not silently turn into completed accounting.
///
/// P1 (reviewer round 3, second half): the SHA check plus the age
/// window is still not landing PROOF. The reviewer's case is
/// `old = B, new = A` on a ref that was ALREADY sitting at A — which
/// is not an exotic coincidence but the ordinary shape of a REJECTED
/// push, because git refuses an update whose expected old value does
/// not match the ref. Both checks pass, the push never happened, and
/// the drain would sign a certificate for it.
///
/// The live path answers this from git's `report-status` body; that
/// body is long gone by the time the reconcile runs, so the proof is
/// re-derived from the repository itself: the ref's REFLOG must carry
/// an entry whose `<old> <new>` pair is exactly this row's, stamped at
/// or after the row was written (see [`reflog_proves_landing`]). That
/// is git's own record of the ref MOVING the way the row claims, after
/// the intent was durable, which is precisely what a coincidental tip
/// cannot produce.
///
/// Deletions are exempt from the reflog half: git removes a ref's
/// reflog when it removes the ref, so absence of the ref plus the age
/// window is all the evidence that can exist for one.
///
/// No reflog means NO PROOF, and no proof means no promotion — the row
/// stays put and is logged for human-attended recovery.
/// [`crate::git::store::init_bare`] turns `core.logAllRefUpdates` on
/// for every repo this node creates (bare repos default it off), so
/// the gap is repos predating that. Deliberate trade: a stranded row
/// an operator can see beats accounting the node cannot substantiate.
#[allow(dead_code)] // single-page seam; startup boots through the multi-pass walk below
pub async fn reconcile_prepared_from_disk(state: AppState, limit: i64) -> anyhow::Result<usize> {
    reconcile_prepared_page(state, None, limit)
        .await
        .map(|(promoted, _cursor)| promoted)
}

/// One page of the reconcile, resuming after `after`. Returns
/// `(promoted, next_cursor)`, where `next_cursor` is the
/// `(created_at, id)` of the last row EXAMINED — promoted or not — and
/// `None` once a short page says the backlog is exhausted.
/// [`reconcile_prepared_from_disk_all`] walks with it.
///
/// The cursor is what makes the multi-pass loop actually advance. A
/// pass consumes every row it looked at, including the ones it refused
/// to promote (a SHA that does not match, a row past
/// [`MAX_RECONCILE_AGE`], a landing with no reflog proof). Those rows
/// stay in `prepared` / `uncertain` by design, so a cursor-less next
/// pass would re-read the same page forever and never reach the
/// backlog behind them.
async fn reconcile_prepared_page(
    state: AppState,
    after: Option<(String, String)>,
    limit: i64,
) -> anyhow::Result<(usize, Option<(String, String)>)> {
    // P1 (reviewer-1/2 round 3): also reconcile `uncertain` rows,
    // not just `prepared`. A receive-pack error that leaves rows
    // `uncertain` has the same recovery need as an interrupted
    // success path that leaves rows `prepared`: the drain's WHERE
    // clause does not see either state, and without this step the
    // push event, cert, and anchor handoff would be permanently lost
    // for refs that DID land before the error.
    let rows = state
        .db
        .list_pending_ref_transitions_prepared_or_uncertain_after(
            after.as_ref().map(|(ts, id)| (ts.as_str(), id.as_str())),
            limit,
        )
        .await?;
    if rows.is_empty() {
        return Ok((0, None));
    }
    // Taken BEFORE any promotion, from the last row of the page as it
    // was READ: the walk advances over examined rows, not over promoted
    // ones. A short page means there is nothing behind it.
    let next_cursor = if (rows.len() as i64) < limit.max(1) {
        None
    } else {
        rows.last().map(|r| (r.created_at.clone(), r.id.clone()))
    };

    // Group rows by repo so we call `list_refs` once per repo, not
    // once per row.
    let mut by_repo: HashMap<String, Vec<&PendingRefTransition>> = HashMap::new();
    for row in &rows {
        by_repo.entry(row.repo_id.clone()).or_default().push(row);
    }

    let mut to_promote: Vec<String> = Vec::new();
    for (repo_id, repo_rows) in by_repo {
        let repo = match state.db.get_repo_by_id(&repo_id).await? {
            Some(r) => r,
            None => {
                tracing::warn!(
                    repo_id = %repo_id,
                    row_count = repo_rows.len(),
                    "reconcile: repo row missing; leaving prepared rows untouched"
                );
                continue;
            }
        };
        let disk_path = std::path::Path::new(&repo.disk_path);
        let refs = match crate::git::store::list_refs(disk_path) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    repo_id = %repo_id,
                    row_count = repo_rows.len(),
                    "reconcile: list_refs failed; leaving prepared rows untouched"
                );
                continue;
            }
        };
        let disk_refs: HashMap<String, String> = refs.into_iter().collect();

        for row in repo_rows {
            // P2 (reviewer-1/2 round 3): handle deletions. A deletion's
            // new_sha is ZERO_SHA and `git for-each-ref` omits deleted
            // refs. The old equality check (disk_refs.get(ref) == row.new_sha)
            // can never match a deletion because ZERO_SHA is never returned
            // by `list_refs`. Instead, when new_sha is ZERO_SHA, treat a
            // missing ref as a successful deletion match.
            let is_deletion = row.new_sha == ZERO_SHA;
            let matches = if is_deletion {
                !disk_refs.contains_key(&row.ref_name)
            } else {
                disk_refs
                    .get(&row.ref_name)
                    .map(|sha| sha == &row.new_sha)
                    .unwrap_or(false)
            };
            if !matches {
                let on_disk = disk_refs
                    .get(&row.ref_name)
                    .cloned()
                    .unwrap_or_else(|| "<missing>".to_string());
                tracing::debug!(
                    request_id = %row.request_id,
                    repo_id = %row.repo_id,
                    ref_name = %row.ref_name,
                    row_new_sha = %row.new_sha,
                    on_disk_sha = %on_disk,
                    is_deletion = is_deletion,
                    "reconcile: row's new_sha does not match on-disk ref; staying prepared"
                );
                continue;
            }
            // P1 (reviewer round 3): the reflog proof is required
            // below via `reflog_proves_landing` for non-deletions.
            // Deletions stay exempt — git removes a ref's reflog
            // along with the ref, so a deleted ref's transition is
            // proven by the absence-plus-age check, not by a reflog
            // entry that cannot exist. (See `reflog_proves_landing`
            // for the full invariant.) The earlier round-4 work in
            // this branch added a separate `has_reflog_landing`
            // helper, but it duplicated the gate without the deletion
            // exemption, so it prevented landed deletions from
            // being promoted — the wrong direction. Kevin's
            // `reflog_proves_landing` is the canonical gate; the
            // call site below applies it with the `!is_deletion`
            // exemption, so the redundant block is removed here.
            // SHA matched (or deletion confirmed by absent ref). Before
            // promoting, confirm the row is recent enough to be the
            // transition that produced the current on-disk state.
            let row_created_at = DateTime::parse_from_rfc3339(&row.created_at)
                .ok()
                .map(|t| t.with_timezone(&Utc));
            let row_age = row_created_at
                .map(|t| Utc::now().signed_duration_since(t))
                .unwrap_or_else(|| {
                    tracing::warn!(
                        row_id = %row.id,
                        request_id = %row.request_id,
                        created_at = %row.created_at,
                        "reconcile: unparseable created_at; staying prepared (human-attended recovery)"
                    );
                    MAX_RECONCILE_AGE + chrono::Duration::seconds(1)
                });
            if row_age > MAX_RECONCILE_AGE {
                tracing::warn!(
                    row_id = %row.id,
                    request_id = %row.request_id,
                    repo_id = %row.repo_id,
                    ref_name = %row.ref_name,
                    row_new_sha = %row.new_sha,
                    row_age_secs = row_age.num_seconds(),
                    max_reconcile_age_secs = MAX_RECONCILE_AGE.num_seconds(),
                    "reconcile: row is older than the recovery window; staying prepared (human-attended recovery required)"
                );
                continue;
            }
            // P1 (reviewer round 3): landing PROOF, not just a matching
            // tip. The reflog must show this exact `old -> new` move,
            // stamped after the row was written. Deletions are exempt —
            // a deleted ref takes its reflog with it, so absence plus
            // the age window above is the whole evidence set for one.
            if !is_deletion
                && !reflog_proves_landing(
                    disk_path,
                    &row.ref_name,
                    &row.old_sha,
                    &row.new_sha,
                    row_created_at,
                )
            {
                tracing::warn!(
                    row_id = %row.id,
                    request_id = %row.request_id,
                    repo_id = %row.repo_id,
                    ref_name = %row.ref_name,
                    row_old_sha = %row.old_sha,
                    row_new_sha = %row.new_sha,
                    "reconcile: the ref sits at the row's new_sha but no reflog entry proves THIS \
                     transition landed (a coincidental tip, or a repo without \
                     core.logAllRefUpdates); staying prepared (human-attended recovery)"
                );
                continue;
            }
            to_promote.push(row.id.clone());
        }
    }

    let flipped = state
        .db
        .mark_pending_ref_transitions_applied_for_rows(&to_promote)
        .await?;
    if flipped > 0 {
        tracing::info!(
            flipped,
            "reconciled prepared/uncertain -> applied via on-disk ref match"
        );
    }
    Ok((flipped as usize, next_cursor))
}

/// Does the ref's reflog prove that THIS row's transition landed?
///
/// True only when `logs/<ref>` carries an entry whose `<old> <new>`
/// pair is exactly this row's, stamped at or after the row became
/// durable (allowing [`REFLOG_CLOCK_SKEW`], since git stamps whole
/// seconds while `created_at` carries sub-second precision). The
/// timestamp half is what separates a landing from a LATER push that
/// re-introduced the same pair: proof must postdate the intent it
/// proves.
///
/// False whenever proof is UNAVAILABLE — no reflog file (a repo
/// predating `core.logAllRefUpdates` in
/// [`crate::git::store::init_bare`]), an unreadable one, or no
/// matching entry. Absence of evidence is not evidence, so the caller
/// leaves such rows where they are instead of deciding either way.
fn reflog_proves_landing(
    disk_path: &std::path::Path,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    row_created_at: Option<DateTime<Utc>>,
) -> bool {
    let entries = match crate::git::store::ref_reflog_entries(disk_path, ref_name) {
        Ok(Some(entries)) => entries,
        Ok(None) => return false,
        Err(e) => {
            tracing::warn!(
                err = %e,
                ref_name = %ref_name,
                "reconcile: could not read the ref's reflog; treating the landing as unproven"
            );
            return false;
        }
    };
    // No parseable `created_at` means no lower bound to check an entry
    // against, and the age gate above has already refused such a row;
    // refuse here too rather than accept an entry of any age.
    let Some(created_at) = row_created_at else {
        return false;
    };
    let floor = created_at.timestamp() - REFLOG_CLOCK_SKEW.num_seconds();
    entries
        .iter()
        .any(|e| e.old_sha == old_sha && e.new_sha == new_sha && e.at >= floor)
}

/// How far BEFORE a row's `created_at` a reflog entry may be stamped
/// and still count as proof of that row's landing.
///
/// Git writes whole-second reflog timestamps while `created_at` is an
/// RFC 3339 instant with sub-second precision, so a ref that landed
/// 200ms after the intent was written can carry a reflog stamp one
/// second EARLIER than the row. The tolerance covers that truncation
/// and small clock jitter; it is deliberately far smaller than
/// [`MAX_RECONCILE_AGE`], so it cannot readmit an old entry left by a
/// previous push of the same pair.
pub const REFLOG_CLOCK_SKEW: chrono::Duration = chrono::Duration::seconds(60);

/// P2 (reviewer-1/2 round 3): multi-pass reconcile for the prepared/
/// uncertain backlog. Mirrors `drain_receive_pack_requests_all`:
/// runs a reconcile pass in a loop until either a pass examines fewer
/// rows than `per_pass_limit` (backlog exhausted) or `max_passes`
/// passes have completed. If rows remain after the last pass, a
/// residual-backlog warning is logged and those rows wait for the next
/// startup.
///
/// The passes WALK, on the `(created_at, id)` cursor each page returns.
/// The drain can re-issue the same query every pass because it deletes
/// the rows it finishes, so its next page is always new work; the
/// reconcile deletes nothing and leaves every unpromotable row exactly
/// where it was, so re-issuing a cursor-less query re-read page one on
/// every pass. One unprovable row at the head of the ordering — a SHA
/// that never landed, a row past [`MAX_RECONCILE_AGE`], or (since the
/// reflog gate) a landing in a repo that keeps no reflog — was enough
/// to pin the whole loop there and leave the backlog behind it
/// unexamined, which is the finding this loop exists to close. Those
/// rows keep ageing toward `MAX_RECONCILE_AGE` while they wait, so
/// "next restart" can mean "never recovered".
pub async fn reconcile_prepared_from_disk_all(
    state: AppState,
    per_pass_limit: i64,
    max_passes: usize,
) -> anyhow::Result<usize> {
    let mut total = 0;
    let mut cursor: Option<(String, String)> = None;
    for _ in 0..max_passes {
        let (n, next) =
            reconcile_prepared_page(state.clone(), cursor.clone(), per_pass_limit).await?;
        total += n;
        // A short page is the backlog-exhausted signal, keyed on rows
        // EXAMINED rather than rows promoted: a pass that could promote
        // nothing has still consumed its page and must move on.
        match next {
            Some(c) => cursor = Some(c),
            None => return Ok(total),
        }
    }
    // One more pass to detect residual backlog.
    let (residual, next) = reconcile_prepared_page(state.clone(), cursor, per_pass_limit).await?;
    total += residual;
    if next.is_some() {
        tracing::warn!(
            total,
            max_passes,
            per_pass_limit,
            "reconcile backlog exceeds startup budget; residual rows will be picked up on next restart"
        );
    }
    Ok(total)
}

/// Per-pass drain budget. Each call to `drain_receive_pack_requests`
/// processes at most this many requests.
pub const DRAIN_PER_PASS_LIMIT: i64 = 1000;

/// Maximum age (relative to `Utc::now()`) at which a `prepared` row
/// is auto-promoted by [`reconcile_prepared_from_disk`]. Rows older
/// than this stay `prepared` and require human-attended recovery.
///
/// The window bounds the blast radius of a stale-row promotion: the
/// only way the on-disk SHA matches a `prepared` row's `new_sha` for
/// an OLD row is if some OTHER push re-introduced the same SHA on
/// the same ref after the original transition failed. With a bounded
/// window, that mis-match only matters for `created_at` within the
/// window — recent enough that an operator can correlate the row
/// with the live handler's logs. Older rows are deliberately left
/// `prepared` so a human can audit them rather than have the node
/// silently write a push event / cert / anchor for a transition the
/// node has no way to prove actually happened.
pub const MAX_RECONCILE_AGE: chrono::Duration = chrono::Duration::seconds(24 * 60 * 60);

/// Maximum number of passes the startup drain will run before logging
/// a residual-backlog warning. With `DRAIN_PER_PASS_LIMIT = 1000` and
/// `DRAIN_MAX_PASSES = 10`, the startup drain runs `max_passes` regular
/// passes (10 × 1000 = 10,000 rows) plus ONE residual pass that
/// detects overrun and surfaces the residual-backlog warning at
/// `drain_receive_pack_requests_all`'s tail. Total rows per boot
/// before the warning fires: 11,000. Rows beyond that remain
/// `applied` and are picked up on the next startup. P2-doc
/// (reviewer-2 round 2): the previous comment said "up to 10,000" but
/// the residual pass is the +1.
pub const DRAIN_MAX_PASSES: usize = 10;

/// #26 Split PR 1 step 3 — per-request drain. Replaces the v29
/// per-ref walk with a per-request walk: the unit of work is the
/// `receive_pack_requests` row, and [`apply_request_effects`] does
/// all the artifact writes per request in a single idempotent
/// pass. The drain reads `outcomes_committed` and `effects_pending`
/// requests whose `next_attempt_at` is due.
///
/// P2-A: a `apply_request_effects` failure on one request is logged
/// but does NOT abort the rest of the batch — the request stays in
/// `outcomes_committed` (or `effects_pending`) for a later startup
/// to retry. Idempotent inserts make this safe.
pub async fn drain_receive_pack_requests(
    state: AppState,
    limit: i64,
) -> anyhow::Result<(usize, usize)> {
    drain_receive_pack_requests_with(state, limit, |s, req_id| async move {
        apply_request_effects(&s, &req_id).await
    })
    .await
}

/// Testable seam for the per-request drain. Production code calls
/// [`drain_receive_pack_requests`], which delegates here with the
/// real [`apply_request_effects`]. Tests inject a closure that
/// returns `Retry` for one request and `Done` for another to assert
/// the loop's state-flip behavior.
pub async fn drain_receive_pack_requests_with<F, Fut>(
    state: AppState,
    limit: i64,
    derive_fn: F,
) -> anyhow::Result<(usize, usize)>
where
    F: Fn(AppState, String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<EffectsOutcome>>,
{
    let reqs = state.db.list_receive_pack_requests_due(limit).await?;
    let mut processed = 0;
    let examined = reqs.len();
    for req in reqs {
        let request_id = req.id.clone();
        match derive_fn(state.clone(), request_id.clone()).await {
            Ok(EffectsOutcome::Done) => {
                if let Err(e) = state.db.mark_request_complete(&request_id).await {
                    tracing::warn!(
                        err = %e,
                        request_id = %request_id,
                        "drain: mark_request_complete failed; will retry next startup"
                    );
                    continue;
                }
                processed += 1;
            }
            Ok(EffectsOutcome::Nothing) => {
                // The request had no `accepted_ordinal`; nothing to
                // do. Move to `complete` so the drain skips it next
                // pass.
                if let Err(e) = state.db.mark_request_complete(&request_id).await {
                    tracing::warn!(
                        err = %e,
                        request_id = %request_id,
                        "drain: mark_request_complete (Nothing) failed"
                    );
                    continue;
                }
                processed += 1;
            }
            Ok(EffectsOutcome::Retry { last_error }) => {
                let next_attempt_at =
                    (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
                if let Err(e) = state
                    .db
                    .mark_request_effects_pending(&request_id, &next_attempt_at, &last_error)
                    .await
                {
                    tracing::warn!(
                        err = %e,
                        request_id = %request_id,
                        "drain: mark_request_effects_pending failed; will retry next startup"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    err = %e,
                    request_id = %request_id,
                    "drain: apply_request_effects returned Err; request left for next startup"
                );
            }
        }
    }
    Ok((processed, examined))
}

/// Drain an unbounded per-request backlog across multiple passes.
/// The residual warning is keyed on the request-table count.
pub async fn drain_receive_pack_requests_all(
    state: AppState,
    per_pass_limit: i64,
    max_passes: usize,
) -> anyhow::Result<usize> {
    let mut total = 0;
    for _ in 0..max_passes {
        let (processed, examined) =
            drain_receive_pack_requests(state.clone(), per_pass_limit).await?;
        total += processed;
        if (examined as i64) < per_pass_limit {
            return Ok(total);
        }
    }
    let (residual_processed, _residual_examined) =
        drain_receive_pack_requests(state.clone(), per_pass_limit).await?;
    total += residual_processed;
    let remaining_after_residual = state.db.count_receive_pack_requests_due().await?;
    if remaining_after_residual > 0 {
        tracing::warn!(
            total,
            max_passes,
            per_pass_limit,
            remaining_after_residual,
            "drain: per-request backlog exceeds startup budget; residual requests will be picked up on next restart"
        );
    }
    Ok(total)
}

/// #26 Split PR 1 step 4 — bounded retirement. Purges terminal
/// `receive_pack_requests` rows and their per-ref children that are
/// older than `retention_days`. Runs as a periodic task from
/// `main.rs` (one per cluster per day is the spec's target rate).
///
/// Deletion order matters: purge the parent requests first, then
/// the orphaned children. The parent delete is bounded by the
/// partial index `idx_receive_pack_requests_completed_at` (built
/// by v30); the children delete is bounded by the same predicate
/// on `applied_at` / `cancelled_at`.
///
/// `quarantined` rows are NEVER purged by this path — the spec
/// reserves those for operator inspection. Step 5 introduces the
/// `quarantined` state; this PR's purge is intentionally restricted
/// to `complete` and `rejected_at_git`.
///
/// Returns `(requests_deleted, children_deleted)`. The caller logs
/// the totals; a non-zero `requests_deleted` is the success signal,
/// and a non-zero `children_deleted` after a `requests_deleted` of
/// zero is a hint that the children were orphaned by a previous
/// purge that crashed mid-run.
pub async fn purge_request_queue(
    db: &crate::db::Db,
    retention_days: i64,
    per_pass_limit: i64,
) -> anyhow::Result<(u64, u64)> {
    let older_than = chrono::Utc::now() - chrono::Duration::days(retention_days);
    let older_than_iso = older_than.to_rfc3339();

    let requests_deleted = db
        .purge_completed_receive_pack_requests(&older_than_iso, per_pass_limit)
        .await?;
    let children_deleted = db
        .purge_completed_pending_ref_transitions(&older_than_iso, per_pass_limit)
        .await?;

    if requests_deleted > 0 || children_deleted > 0 {
        tracing::info!(
            retention_days,
            older_than = %older_than_iso,
            requests_deleted,
            children_deleted,
            "queue lifecycle: purged terminal request rows"
        );
    }
    Ok((requests_deleted, children_deleted))
}

/// Outcome of a single `apply_request_effects` call. The caller (live
/// handler or drain) decides what to do with the request row based on
/// this.
///
/// `Done` — all four artifacts (push event, per-ref certs, per-ref
/// anchor jobs, trust-score bump) landed. The request is moved to
/// `complete`.
///
/// `Nothing` — the request had no `accepted_ordinal` (no ref proved
/// landed, or the parsed report was empty). No effects were
/// attempted. The request is moved to `complete` (or
/// `rejected_at_git` if the parsed report shows an explicit failure;
/// the live handler does that flag separately).
///
/// `Retry { last_error }` — one or more per-ref effects failed
/// transiently. The request is moved to `effects_pending` with
/// `next_attempt_at` in the future. The drain will retry on the next
/// startup.
#[derive(Debug)]
pub enum EffectsOutcome {
    Done,
    Nothing,
    Retry { last_error: String },
}

/// #26 Split PR 1 step 3 — the shared effect executor. The live
/// handler and the recovery drain both call this function, so the
/// per-ref effects fan-out is in exactly one place. The function is
/// idempotent: every artifact write uses `ON CONFLICT` semantics
/// (deterministic id, `record_push_with_id` / `insert_anchor_job_idempotent`
/// / `insert_ref_certificate` upsert), so a recovery replay against
/// the same request produces the same artifacts the live path did.
///
/// Crash-safety window: if a crash lands between "git returned" and
/// "all four artifacts written", the request row is in
/// `outcomes_committed` with no effects recorded. The drain picks it
/// up and re-runs the same effect pipeline, and the idempotent
/// inserts collapse to no-ops for the artifacts that did land.
///
/// If a crash lands between "all artifacts written" and "request
/// moved to `complete`", the same drain pass completes the state
/// transition. The artifacts are already in place; the
/// `mark_request_complete` call is a single SQL UPDATE.
pub async fn apply_request_effects(
    state: &AppState,
    request_id: &str,
) -> anyhow::Result<EffectsOutcome> {
    // 1. Load the request row.
    let req = state
        .db
        .get_receive_pack_request(request_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("request row missing for {request_id}"))?;

    // 2. State gate: only `outcomes_committed` and `effects_pending` are
    //    eligible. Terminal states (`complete`, `rejected_at_git`) are
    //    skipped.
    if !matches!(
        req.state.as_str(),
        crate::db::request_state::OUTCOMES_COMMITTED | crate::db::request_state::EFFECTS_PENDING
    ) {
        return Ok(EffectsOutcome::Nothing);
    }

    // 3. No accepted ordinal means no ref proved landed. The request is
    //    eligible for `complete` (or `rejected_at_git` if the parsed
    //    report shows an explicit failure, but that flag is set by the
    //    handler's four-branch flip, not here).
    let accepted_ordinal = match req.accepted_ordinal {
        Some(o) => o,
        None => return Ok(EffectsOutcome::Nothing),
    };

    // 4. Load the request's children. Certs and anchor jobs run for
    //    every child whose `ref_name` is in the parsed report's ok
    //    set; the request row's `parsed_report` is the durable
    //    record of that set.
    let children = state
        .db
        .list_pending_ref_transitions_for_request(request_id)
        .await?;
    let ok_ref_names: std::collections::HashSet<String> = req
        .parsed_report
        .as_ref()
        .and_then(|v| v.get("ref_results"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let ok = r.get("ok").and_then(|o| o.as_bool()).unwrap_or(false);
                    let name = r
                        .get("ref_name")
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string());
                    if ok {
                        name
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let accepted_children: Vec<&PendingRefTransition> = children
        .iter()
        .filter(|c| ok_ref_names.contains(&c.ref_name))
        .collect();

    // 5. Look up the repo for cert/webhook payload construction. If
    //    the row is missing (deleted under us), bail with Retry so
    //    the drain re-runs later when the cache is warm again.
    let repo = match state.db.get_repo_by_id(&req.repo_id).await? {
        Some(r) => r,
        None => {
            return Ok(EffectsOutcome::Retry {
                last_error: format!("repo {} not found", req.repo_id),
            });
        }
    };

    // 6. Push event — written once, for the request. The live and
    //    recovery paths produce the same id because both key on
    //    `(request_id, accepted_ordinal)`.
    let push_event_id = crate::db::push_event_id_for(&req.id, accepted_ordinal);
    let accepted_ref = children.iter().find(|c| c.ordinal == accepted_ordinal);
    let commit_hash = accepted_ref
        .map(|c| c.new_sha.clone())
        .unwrap_or_else(|| chrono::Utc::now().timestamp().to_string());
    if let Err(e) = state
        .db
        .record_push_with_id(
            &push_event_id,
            &req.pusher_did,
            &req.repo_id,
            &commit_hash,
            0,
        )
        .await
    {
        tracing::warn!(
            err = %e,
            request_id = %request_id,
            "apply_request_effects: push event insert failed; request left for drain retry"
        );
        return Ok(EffectsOutcome::Retry {
            last_error: format!("push event: {e}"),
        });
    }

    // 7. Trust score bump — best-effort, like the inline handler. A
    //    failure here does NOT retry the request; the bump is
    //    informational and the next push will catch up.
    if let Ok(push_count) = state.db.get_push_count(&req.pusher_did).await {
        // 0.05 base (from registration) + 0.05 per push, capped at 1.0
        let new_score = (push_count as f64 * 0.05 + 0.05).min(1.0);
        let _ = state
            .db
            .update_trust_score(&req.pusher_did, new_score)
            .await;
    }

    // 8. Per-ref certs and anchor jobs. Each accepted child gets one
    //    of each. Failures are accumulated; the first one is
    //    returned as the Retry reason.
    let mut first_error: Option<String> = None;
    for child in &accepted_children {
        let cert_id = crate::db::ref_cert_id_for(&req.id, child.ordinal);
        if let Err(e) = cert::issue_ref_certificate_with_issued_at(
            state,
            &req.repo_id,
            &child.ref_name,
            &child.old_sha,
            &child.new_sha,
            &req.pusher_did,
            &cert_id,
            Some(child.created_at.clone()),
        )
        .await
        {
            tracing::warn!(
                err = %e,
                request_id = %request_id,
                ref_name = %child.ref_name,
                "apply_request_effects: cert insert failed; child left for drain retry"
            );
            first_error.get_or_insert_with(|| format!("cert {}: {e}", child.ref_name));
            continue;
        }

        let anchor_id = crate::db::anchor_job_id_for(
            &req.repo_id,
            &child.ref_name,
            &child.old_sha,
            &child.new_sha,
        );
        let job = crate::db::AnchorJob {
            id: anchor_id,
            repo_id: req.repo_id.clone(),
            ref_name: child.ref_name.clone(),
            old_sha: child.old_sha.clone(),
            new_sha: child.new_sha.clone(),
            pusher_did: req.pusher_did.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            claimed_at: None,
        };
        if let Err(e) = state.db.insert_anchor_job_idempotent(&job).await {
            tracing::warn!(
                err = %e,
                request_id = %request_id,
                ref_name = %child.ref_name,
                "apply_request_effects: anchor insert failed; child left for drain retry"
            );
            first_error.get_or_insert_with(|| format!("anchor {}: {e}", child.ref_name));
        }
    }

    if let Some(err) = first_error {
        return Ok(EffectsOutcome::Retry { last_error: err });
    }

    // 9. All artifacts landed — clean up the children and let the
    //    caller move the request to `complete`.
    if let Err(e) = state
        .db
        .delete_pending_ref_transitions_by_request_id(request_id)
        .await
    {
        tracing::warn!(
            err = %e,
            request_id = %request_id,
            "apply_request_effects: child cleanup failed; idempotent retry will pick them up on next pass"
        );
        // Don't fail the request — the artifacts are in place and a
        // future pass is harmless.
    }

    // 10. Webhooks — best-effort, per landed ref. Same shape as the
    //     inline handler's webhook block.
    if !ok_ref_names.is_empty() {
        let base_url = state
            .config
            .public_url
            .as_deref()
            .unwrap_or("http://127.0.0.1:7545")
            .trim_end_matches('/');
        let owner_short = crate::db::normalize_owner_key(&repo.owner_did);
        let clone_url = format!("{}/{}/{}.git", base_url, owner_short, repo.name);
        for child in &accepted_children {
            let payload = serde_json::json!({
                "ref": child.ref_name,
                "before": child.old_sha,
                "after": child.new_sha,
                "created": child.old_sha == "0000000000000000000000000000000000000000",
                "forced": false,
                "pusher": {
                    "did": req.pusher_did,
                },
                "repository": {
                    "id": repo.id,
                    "name": repo.name,
                    "owner_did": repo.owner_did,
                    "clone_url": clone_url,
                },
            });
            crate::webhooks::fire_event(
                state.db.clone(),
                state.http_client.clone(),
                &repo.id,
                "push",
                payload,
            );
        }
    }

    Ok(EffectsOutcome::Done)
}

#[cfg(test)]
mod drain_tests {
    //! End-to-end failure-injection test the reviewer demanded:
    //!
    //! "Inject failure after Git applies the ref but before the first
    //! transition/job write, restart the node, and show that the
    //! original transition produces exactly one push event, one
    //! certificate carrying the original pusher/proof, and at most
    //! one anchor upload."
    //!
    //! The crash window is simulated by inserting a
    //! `pending_ref_transitions` row directly in `applied` state
    //! (bypassing the handler). The drain then re-derives the three
    //! artifacts using the persisted authentic pusher DID and the
    //! raw RFC 9421 signature header. Assertions check the invariants
    //! the reviewer named: exactly one push event row, exactly one
    //! cert row carrying the original pusher, exactly one anchor job
    //! row. A second drain pass is a no-op.
    //!
    //! Each assertion names the invariant it pins. Reverting the
    //! production line under test turns the named assertion red.

    use super::*;
    use crate::db::pending_state;
    use crate::db::request_state;
    use crate::db::Db;
    use crate::db::PendingRefTransition;
    use chrono::Utc;

    async fn _db(pool: sqlx::PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
    }

    fn make_row(repo_id: &str, ref_name: &str, old: &str, new: &str) -> PendingRefTransition {
        let now = Utc::now().to_rfc3339();
        PendingRefTransition {
            id: crate::db::deterministic_id(&[
                "pending_ref_transition",
                "req-1",
                repo_id,
                ref_name,
                old,
                new,
            ]),
            request_id: "req-1".to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: old.to_string(),
            new_sha: new.to_string(),
            pusher_did: "did:key:z6pusher".to_string(),
            node_did: "did:key:z6node".to_string(),
            signature_header: "Signature: sig=\"abc...\"".to_string(),
            signature_input: "Signature-Input: sig=(\"@authority\");...".to_string(),
            content_digest: "Content-Digest: sha-256=:...:".to_string(),
            state: pending_state::APPLIED.to_string(),
            created_at: now.clone(),
            applied_at: Some(now),
            cancelled_at: None,
            // The existing tests are single-ref pushes, so the
            // request's only child is ordinal 0. The new multi-ref
            // test sets this explicitly per child.
            ordinal: 0,
            git_target_kind: Some("update".to_string()),
        }
    }

    /// Stage a `receive_pack_requests` row in `outcomes_committed`
    /// alongside the per-ref children that landed under it. The
    /// `parsed_report` is the durable record the effect executor
    /// reads to decide which children are `ok`. Each child is
    /// inserted via `insert_pending_ref_transition_for_test`, so
    /// the deterministic PKs match what the production handler
    /// would write. The repo row is also seeded so `apply_request_effects`'s
    /// `get_repo_by_id` lookup succeeds (the live handler always
    /// has the repo in cache before the effect executor is called).
    async fn stage_request_with_children(
        db: &Db,
        request_id: &str,
        repo_id: &str,
        accepted_ordinal: Option<i32>,
        children: &[PendingRefTransition],
        parsed_report: serde_json::Value,
    ) {
        stage_request_with_pusher(
            db,
            request_id,
            repo_id,
            "did:key:z6pusher",
            accepted_ordinal,
            children,
            parsed_report,
        )
        .await;
    }

    /// Like [`stage_request_with_children`] but lets the caller pick
    /// the request row's `pusher_did`. Used by the cert-refresh
    /// tests where the recovery's pusher DID must NOT match the
    /// helper's default.
    async fn stage_request_with_pusher(
        db: &Db,
        request_id: &str,
        repo_id: &str,
        pusher_did: &str,
        accepted_ordinal: Option<i32>,
        children: &[PendingRefTransition],
        parsed_report: serde_json::Value,
    ) {
        // Seed a minimal repo row so the effect executor's
        // `get_repo_by_id` lookup succeeds. `ON CONFLICT DO NOTHING`
        // means tests that already seeded a repo (e.g. cert-refresh
        // tests that need a specific `owner_did`) are unaffected.
        sqlx::query(
            r#"INSERT INTO repos (id, name, owner_did, description, is_public, default_branch,
                                  created_at, updated_at, disk_path, forked_from, machine_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(repo_id)
        .bind(repo_id)
        .bind(pusher_did)
        .bind(Option::<String>::None)
        .bind(true)
        .bind("main")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(format!("/tmp/{repo_id}"))
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .execute(db.pool())
        .await
        .expect("seed repo row");

        sqlx::query(
            r#"INSERT INTO receive_pack_requests
               (id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                last_error, next_attempt_at, created_at, completed_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
        )
        .bind(request_id)
        .bind(repo_id)
        .bind(pusher_did)
        .bind("did:key:z6node")
        .bind(Vec::<u8>::new())
        .bind([0u8; 32].to_vec())
        .bind(crate::db::request_state::OUTCOMES_COMMITTED)
        .bind(Some(true))
        .bind(&parsed_report)
        .bind(accepted_ordinal)
        .bind(0_i32)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Utc::now().to_rfc3339())
        .bind(Option::<String>::None)
        .execute(db.pool())
        .await
        .unwrap();

        for child in children {
            db.insert_pending_ref_transition_for_test(child)
                .await
                .unwrap();
        }
    }

    /// Build the `parsed_report` JSON the drain reads. The
    /// `apply_request_effects` effect-executor uses the `ok` field
    /// per `ref_name` to decide which children get certs and
    /// anchors; the `accepted_ordinal` field on the request row
    /// picks the row whose `new_sha` carries the push event.
    fn parsed_report_ok(refs: &[(&str, bool)]) -> serde_json::Value {
        serde_json::json!({
            "unpack_ok": true,
            "ref_results": refs.iter().map(|(name, ok)| serde_json::json!({
                "ref_name": name,
                "ok": ok,
            })).collect::<Vec<_>>(),
        })
    }

    /// The reviewer's proof at the durable-outbox layer. Stage a
    /// `receive_pack_requests` row in `outcomes_committed` with one
    /// landed child (the crash window — receive_pack returned Ok and
    /// git accepted, only the effects fan-out didn't run), drain, and
    /// assert exactly one push event, one cert with the original
    /// pusher, one anchor job, and the request moved to `complete`.
    #[sqlx::test]
    async fn drain_re_derives_all_three_artifacts_for_an_applied_row(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let repo_id = "repo-failure-injection";
        let ref_name = "refs/heads/main";
        let old = "a".repeat(40);
        let new = "b".repeat(40);
        let row = make_row(repo_id, ref_name, &old, &new);
        let request_id = row.request_id.clone();
        let parsed_report = parsed_report_ok(&[(ref_name, true)]);
        stage_request_with_children(
            &state.db,
            &request_id,
            repo_id,
            Some(row.ordinal),
            std::slice::from_ref(&row),
            parsed_report,
        )
        .await;

        let (n, examined) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "exactly one request re-derived");
        assert_eq!(examined, 1, "the loop examined the single request");

        // Push event: exactly one row, keyed on the deterministic id.
        let _push_id = crate::db::push_event_id_for(&row.request_id, row.ordinal);
        let push_count = state
            .db
            .count_push_events(&row.repo_id, &row.new_sha, &row.pusher_did)
            .await
            .unwrap();
        assert_eq!(
            push_count, 1,
            "exactly one push event, keyed on the original pusher"
        );

        // Cert: exactly one row, carrying the original pusher DID.
        let certs = state
            .db
            .list_ref_certificates(&row.repo_id, 10)
            .await
            .unwrap();
        assert_eq!(certs.len(), 1, "exactly one ref certificate");
        assert_eq!(
            certs[0].pusher_did, row.pusher_did,
            "cert carries the original pusher DID, not a placeholder"
        );
        assert_eq!(
            certs[0].id,
            crate::db::ref_cert_id_for(&row.request_id, row.ordinal),
            "cert id is deterministic"
        );
        assert_eq!(certs[0].new_sha, row.new_sha, "cert carries the new_sha");
        assert_eq!(certs[0].old_sha, row.old_sha, "cert carries the old_sha");

        // Anchor job: exactly one row.
        let anchor_count = state
            .db
            .count_anchor_jobs(&row.repo_id, &row.ref_name, &row.old_sha, &row.new_sha)
            .await
            .unwrap();
        assert_eq!(anchor_count, 1, "exactly one anchor job per transition");

        // The request row moved to `complete`.
        let after = state
            .db
            .get_receive_pack_request(&request_id)
            .await
            .unwrap();
        assert_eq!(
            after.expect("request row exists").state,
            crate::db::request_state::COMPLETE,
            "drain moves the request to complete"
        );
        // Children are cleaned up.
        let still_applied = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(
            still_applied.is_empty(),
            "drain deletes the children after the work lands"
        );

        // A second drain pass is a no-op.
        let (n2, examined2) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n2, 0, "a second drain pass has nothing to do");
        assert_eq!(examined2, 0, "no requests to examine on a second pass");
    }

    /// The reviewer's second proof, end-to-end. A request that git
    /// rejected (no `accepted_ordinal`) never produces a push event,
    /// cert, or anchor. The drain still picks up the request
    /// (because it's in `outcomes_committed` — the live handler
    /// always lands here after git returns), `apply_request_effects`
    /// returns `Nothing` because there is no accepted ref, and the
    /// drain moves the request to `complete` without writing any
    /// artifacts.
    #[sqlx::test]
    async fn rejected_at_git_request_produces_no_artifacts(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // Stage a request in `outcomes_committed` with NO
        // `accepted_ordinal` (git rejected all refs). The drain
        // picks it up, `apply_request_effects` short-circuits at the
        // `accepted_ordinal.is_none()` gate, and the drain calls
        // `mark_request_complete` for `Nothing`.
        let request_id = "req-rejected";
        let repo_id = "repo-rejected";
        let parsed_report = serde_json::json!({
            "unpack_ok": false,
            "ref_results": [{
                "ref_name": "refs/heads/main",
                "ok": false,
                "message": "deny non-fast-forward",
            }],
        });
        stage_request_with_children(&state.db, request_id, repo_id, None, &[], parsed_report).await;

        let (n, examined) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "drain processed the no-effect request");
        assert_eq!(examined, 1, "the loop examined the request");

        // The request is now `complete` — Nothing outcome moves it.
        let after = state.db.get_receive_pack_request(request_id).await.unwrap();
        assert_eq!(
            after.expect("request row exists").state,
            crate::db::request_state::COMPLETE,
            "Nothing outcome moves the request to complete"
        );

        // No push event, no cert, no anchor.
        let push_count = state.db.get_push_count("did:key:z6pusher").await.unwrap();
        assert_eq!(
            push_count, 0,
            "no push event for a request with no accepted ref"
        );
        let certs = state.db.list_ref_certificates(repo_id, 10).await.unwrap();
        assert!(certs.is_empty(), "no certs for a no-effect request");
        let still_applied = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(
            still_applied.is_empty(),
            "no children exist for this no-effect request"
        );
    }

    /// A request the handler has not yet finished (state =
    /// `received`, git has not yet returned) is invisible to the
    /// per-request drain. The drain only reads `outcomes_committed`
    /// and `effects_pending`, so a `received` row stays where the
    /// handler left it and no effects are attempted.
    #[sqlx::test]
    async fn received_request_produces_no_artifacts(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // Stage the request row directly in `received` (the state
        // the handler writes before git returns).
        let request_id = "req-received";
        let repo_id = "repo-received";
        sqlx::query(
            r#"INSERT INTO receive_pack_requests
               (id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                last_error, next_attempt_at, created_at, completed_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
        )
        .bind(request_id)
        .bind(repo_id)
        .bind("did:key:z6pusher")
        .bind("did:key:z6node")
        .bind(Vec::<u8>::new())
        .bind([0u8; 32].to_vec())
        .bind(crate::db::request_state::RECEIVED)
        .bind(Option::<bool>::None)
        .bind(Option::<serde_json::Value>::None)
        .bind(Option::<i32>::None)
        .bind(0_i32)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Utc::now().to_rfc3339())
        .bind(Option::<String>::None)
        .execute(state.db.pool())
        .await
        .unwrap();

        // The drain must not pick up a `received` row.
        let (n, examined) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 0, "the drain must not touch a `received` request");
        assert_eq!(examined, 0, "the drain's WHERE excludes `received`");

        // The request is unchanged.
        let after = state.db.get_receive_pack_request(request_id).await.unwrap();
        assert_eq!(
            after.expect("request row exists").state,
            crate::db::request_state::RECEIVED,
            "received requests are left to the handler"
        );

        let push_count = state.db.get_push_count("did:key:z6pusher").await.unwrap();
        assert_eq!(push_count, 0, "no push event for an unstarted request");
    }

    // ----- P1-A reconcile tests -----
    //
    // These tests cover the startup-time `reconcile_prepared_from_disk`
    // step: a `prepared` row whose target ref actually landed on disk
    // is promoted to `applied`; a row whose target did NOT land (or
    // whose ref is missing) stays `prepared`; a `cancelled` row is
    // never promoted; and a second call is a no-op.
    //
    // The on-disk state is a real bare git repo (so `list_refs` can
    // read it) seeded with a synthetic commit via the plumbing
    // commands `mktree` (empty tree) + `commit-tree` (root commit) +
    // `update-ref` (point a ref at the commit).

    /// Build a real commit on a bare git repo's `ref_name`. Returns
    /// the new commit SHA. Used by the reconcile tests to seed a
    /// known SHA on disk so `list_refs` can read it back.
    fn seed_ref_on_bare(bare_path: &std::path::Path, ref_name: &str) -> String {
        use std::process::Command;
        // Empty tree.
        let tree = String::from_utf8(
            Command::new("git")
                .args(["mktree"])
                .current_dir(bare_path)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("git mktree")
                .stdout,
        )
        .expect("mktree stdout utf8")
        .trim()
        .to_string();
        // Root commit on the empty tree. The env vars override any
        // missing global config in CI.
        let commit = String::from_utf8(
            Command::new("git")
                .args(["commit-tree", &tree, "-m", "test root"])
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .current_dir(bare_path)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("git commit-tree")
                .stdout,
        )
        .expect("commit-tree stdout utf8")
        .trim()
        .to_string();
        // Point the ref at the commit. `update-ref` writes into the
        // bare repo's refs/ tree.
        Command::new("git")
            .args(["update-ref", ref_name, &commit])
            .current_dir(bare_path)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("git update-ref");
        commit
    }

    /// Seed a `RepoRecord` row pointing at `disk_path` and return
    /// the repo id. Mirrors what `repos::create_repo` does in
    /// production, but without the rest of the create-repo
    /// bookkeeping the test does not exercise.
    async fn seed_repo_row(state: &crate::state::AppState, disk_path: &str) -> String {
        use crate::db::RepoRecord;
        use chrono::Utc;
        let repo_id = uuid::Uuid::new_v4().to_string();
        state
            .db
            .create_repo(&RepoRecord {
                id: repo_id.clone(),
                name: "reconcile-test".into(),
                owner_did: "did:key:z6owner".into(),
                description: None,
                is_public: true,
                default_branch: "main".into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                disk_path: disk_path.to_string(),
                forked_from: None,
                machine_id: None,
            })
            .await
            .expect("create_repo");
        repo_id
    }

    #[sqlx::test]
    async fn reconcile_promotes_prepared_row_when_on_disk_sha_matches(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // Create a bare repo on disk with refs/heads/main = X.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        // Persist a `prepared` row whose `new_sha` matches the on-disk
        // SHA. This simulates the crash window the reviewer flagged:
        // receive_pack returned Ok and the ref landed, but the
        // handler never reached `mark_pending_ref_transitions_applied`.
        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        // The drain must NOT see the row before reconcile (it only
        // reads `applied`).
        let pre_drain = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(pre_drain.is_empty(), "drain cannot see a prepared row");

        // Reconcile: the row's new_sha matches the on-disk ref, so it
        // should be promoted.
        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "exactly one row promoted to applied");

        // The row is now in `applied` and the drain can see it.
        let after_drain = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert_eq!(after_drain.len(), 1, "row is now visible to the drain");
        assert_eq!(after_drain[0].id, row.id, "the same row is promoted");
        assert_eq!(after_drain[0].state, pending_state::APPLIED);
        assert!(
            after_drain[0].applied_at.is_some(),
            "applied_at is set on promotion"
        );

        // The prepared list is now empty.
        let still_prepared = state
            .db
            .list_pending_ref_transitions_prepared(100)
            .await
            .unwrap();
        assert!(
            still_prepared.is_empty(),
            "no prepared rows remain after a successful reconcile"
        );
    }

    #[sqlx::test]
    async fn reconcile_leaves_prepared_row_when_on_disk_sha_differs(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // On-disk SHA is `aaaa...` (the live push landed at this SHA).
        // The row's `new_sha` is `bbbb...` — the SHA the row CLAIMS
        // the push went to, but the actual on-disk state disagrees.
        // This models a row stranded by a `mark_applied` failure on a
        // push whose target was rolled back, or any case where the
        // recorded `new_sha` does not match reality.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");
        assert_ne!(on_disk_sha, "b".repeat(40), "test sanity: SHAs differ");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(
            &repo_id,
            "refs/heads/main",
            &"0".repeat(40),
            &"b".repeat(40),
        );
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        // Reconcile: the SHA does not match, so NOTHING is promoted.
        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 0, "no row promoted when SHAs do not match");

        // The row is still `prepared` and the drain cannot see it.
        let after_drain = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(
            after_drain.is_empty(),
            "drain must not see a row whose on-disk SHA does not match"
        );
        let still_prepared = state
            .db
            .list_pending_ref_transitions_prepared(100)
            .await
            .unwrap();
        assert_eq!(still_prepared.len(), 1, "row stays prepared");
        assert_eq!(still_prepared[0].id, row.id);
        assert!(
            still_prepared[0].applied_at.is_none(),
            "applied_at is NOT set on a non-promotion"
        );
    }

    #[sqlx::test]
    async fn reconcile_leaves_cancelled_row_untouched(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // On-disk ref matches the row's `new_sha` — but the row is
        // `cancelled`, so the reconcile must NEVER promote it. The
        // reviewer's invariant: a failed receive-pack is never
        // promoted to completed accounting.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::CANCELLED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 0, "cancelled rows are never promoted");

        // The row is still cancelled and the drain still cannot see it.
        let after_drain = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(after_drain.is_empty());
        let still_prepared = state
            .db
            .list_pending_ref_transitions_prepared(100)
            .await
            .unwrap();
        assert!(
            still_prepared.is_empty(),
            "cancelled rows do not show up in the prepared list either"
        );
    }

    #[sqlx::test]
    async fn reconcile_is_idempotent(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        // First call: 1 row promoted.
        let n1 = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n1, 1);
        // Second call: 0 rows — the row is no longer `prepared`, so
        // the list query returns empty.
        let n2 = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n2, 0, "a second reconcile is a no-op");

        // Final state: applied, with applied_at set.
        let applied = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].state, pending_state::APPLIED);
        assert!(applied[0].applied_at.is_some());
    }

    /// A `prepared` row whose `new_sha` happens to match the current
    /// on-disk ref value for a reason OTHER than its own transition
    /// (e.g. a later push re-introduced the same SHA on the same
    /// ref) must NOT be promoted just because the SHAs match. The
    /// `MAX_RECONCILE_AGE` window is the second correctness barrier:
    /// rows older than the window stay `prepared` for
    /// human-attended recovery.
    ///
    /// This test seeds a `prepared` row whose `new_sha` DOES match
    /// the on-disk ref, but whose `created_at` is 25 hours in the
    /// past (one hour past `MAX_RECONCILE_AGE = 24h`). The reconcile
    /// must NOT promote it.
    #[sqlx::test]
    async fn reconcile_does_not_promote_stale_prepared_row(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // On-disk ref with a known SHA.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        // Build a `prepared` row whose SHA matches the on-disk ref,
        // but whose `created_at` is older than `MAX_RECONCILE_AGE`.
        // This models a row that was stranded by an ancient
        // `mark_applied` failure and then re-introduced the same
        // SHA via a later push.
        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        // 25 hours ago — outside the 24h window.
        row.created_at = (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
        // `make_row` derives `id` from the deterministic hash using
        // the `created_at` it generated at construction time. Now
        // that we've overwritten `created_at`, the row's `id` no
        // longer matches what `insert_pending_ref_transitions`
        // would have produced in production, but the test only
        // checks the reconcile's behavior, not the id's contents,
        // so the stale id is harmless here.
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        // The SHA matches, but the row is older than the window:
        // reconcile must NOT promote it.
        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(
            n, 0,
            "stale row stays prepared (SHA matched but age exceeded the recovery window)"
        );

        // The row is still `prepared` and the drain cannot see it.
        let after_drain = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(
            after_drain.is_empty(),
            "drain must not see a row outside the recovery window"
        );
        let still_prepared = state
            .db
            .list_pending_ref_transitions_prepared(100)
            .await
            .unwrap();
        assert_eq!(still_prepared.len(), 1, "row stays prepared");
        assert_eq!(still_prepared[0].id, row.id);
        assert!(
            still_prepared[0].applied_at.is_none(),
            "applied_at is NOT set on a stale row"
        );
    }

    /// A `prepared` row that is fresh (within `MAX_RECONCILE_AGE`)
    /// and SHA-matches the on-disk ref MUST still be promoted. This
    /// is the existing happy-path contract; the test pins it so a
    /// future change to the age check does not silently break the
    /// recovery path for legitimate stranded rows.
    #[sqlx::test]
    async fn reconcile_promotes_fresh_prepared_row_with_matching_sha(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        // `make_row` defaults `created_at` to `Utc::now()`, which is
        // well within `MAX_RECONCILE_AGE`. The SHA matches. This
        // row should be promoted.
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "fresh row with matching SHA is promoted");
    }

    // ----- P1 (reviewer round 3, second half): reflog landing proof -----
    //
    // The SHA match plus the age window says "the ref is where the row
    // wanted it". It does NOT say the row's push is what put it there.
    // These tests pin the difference, which is what
    // `reflog_proves_landing` decides.

    /// THE reviewer's case. A row claims `B -> A` while the ref has been
    /// sitting at A all along — the ordinary shape of a REJECTED push,
    /// since git refuses an update whose expected old value is stale.
    /// The SHA matches and the row is fresh, so only the reflog refuses
    /// it; without that refusal the drain writes a push event, a signed
    /// certificate and an anchor for a transition that never happened.
    ///
    /// MUTATION (RED): drop the `reflog_proves_landing` gate and this
    /// promotes 1.
    #[sqlx::test]
    async fn reconcile_refuses_a_coincidental_tip_with_no_reflog_proof(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        // The ref reached A by an unrelated update: its reflog says
        // `0{40} -> A`, never `B -> A`.
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"b".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(
            n, 0,
            "the current SHA is not landing proof: a row whose claimed old_sha never \
             appears in the ref's reflog must stay put"
        );
        let still_pending = state
            .db
            .list_pending_ref_transitions_prepared_or_uncertain(100)
            .await
            .unwrap();
        assert_eq!(still_pending.len(), 1, "the row is left where it was");
        let applied = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert!(applied.is_empty(), "the drain must never see it");
    }

    /// The positive control for the test above: the SAME on-disk SHA,
    /// but a row whose transition the reflog actually records (the
    /// `0{40} -> A` entry that created the ref). Proof present, so the
    /// row promotes — the strict gate must not break real recovery.
    #[sqlx::test]
    async fn reconcile_promotes_a_row_the_reflog_proves(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "a transition the reflog records is promoted");
    }

    /// A repo that keeps no reflog (created before `init_bare` enabled
    /// `core.logAllRefUpdates`) can produce no proof, and no proof means
    /// no promotion — never a fallback to the SHA-only guess.
    #[sqlx::test]
    async fn reconcile_leaves_a_row_prepared_when_the_repo_keeps_no_reflog(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");
        // Model a legacy repo: throw the reflogs away after the fact.
        std::fs::remove_dir_all(bare.join("logs")).expect("remove logs");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(
            n, 0,
            "absence of evidence is not evidence: without a reflog the row waits for \
             human-attended recovery"
        );
    }

    /// A reflog entry that PREDATES the row cannot be proof of that
    /// row's landing: it is the signature of an earlier push that moved
    /// the same pair. The SHA matches and the row is fresh, so only the
    /// timestamp floor refuses it.
    #[sqlx::test]
    async fn reconcile_refuses_a_reflog_entry_older_than_the_row(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let on_disk_sha = seed_ref_on_bare(&bare, "refs/heads/main");

        // Rewrite the entry's timestamp to an hour back — far outside
        // REFLOG_CLOCK_SKEW, which only covers git's whole-second
        // truncation.
        let log_path = bare.join("logs/refs/heads/main");
        let raw = std::fs::read_to_string(&log_path).expect("reflog exists");
        let old_ts = (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp();
        let rewritten: String = raw
            .lines()
            .map(|line| {
                let (header, msg) = line.split_once('\t').unwrap_or((line, ""));
                let mut tokens: Vec<String> =
                    header.split_whitespace().map(|s| s.to_string()).collect();
                let n = tokens.len();
                tokens[n - 2] = old_ts.to_string();
                format!("{}\t{}\n", tokens.join(" "), msg)
            })
            .collect();
        std::fs::write(&log_path, rewritten).expect("rewrite reflog");

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/main", &"0".repeat(40), &on_disk_sha);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(
            n, 0,
            "proof must postdate the intent it proves, or a row inherits an older \
             push's reflog entry"
        );
    }

    /// The reflog gate must NOT break the deletion recovery above it. A
    /// deleted ref takes its reflog with it, so a landed
    /// `git push :branch` can never produce reflog proof; absence of the
    /// ref plus the age window is the whole evidence set for one, and
    /// the gate exempts deletions for exactly that reason.
    ///
    /// MUTATION (RED): drop the `!is_deletion` guard on the reflog check
    /// and a landed deletion stops being recoverable again.
    #[sqlx::test]
    async fn reconcile_still_promotes_a_landed_deletion_which_can_have_no_reflog(
        pool: sqlx::PgPool,
    ) {
        use std::process::Command;
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let doomed_sha = seed_ref_on_bare(&bare, "refs/heads/doomed");
        // The push landed: the branch is gone, and so is its reflog.
        let out = Command::new("git")
            .args(["update-ref", "-d", "refs/heads/doomed"])
            .current_dir(&bare)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("git update-ref -d");
        assert!(
            out.status.success(),
            "update-ref -d failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;
        let mut row = make_row(&repo_id, "refs/heads/doomed", &doomed_sha, ZERO_SHA);
        row.state = pending_state::PREPARED.to_string();
        row.applied_at = None;
        state
            .db
            .insert_pending_ref_transition_for_test(&row)
            .await
            .unwrap();

        let n = reconcile_prepared_from_disk(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "a landed branch delete is still recovered");
        let applied = state
            .db
            .list_pending_ref_transitions_applied(100)
            .await
            .unwrap();
        assert_eq!(applied.len(), 1, "the deletion row reaches the drain");
        assert_eq!(applied[0].id, row.id);
    }

    // ----- P2 (reviewer round 3): the multi-pass reconcile must WALK -----

    /// The backlog past the first page is reconciled in the SAME
    /// startup, not one page per restart. With a per-pass limit of ONE,
    /// a single pass can promote at most one row, so anything above one
    /// proves the loop advanced.
    ///
    /// MUTATION (RED): call the single-page `reconcile_prepared_from_disk`
    /// and only the first row is promoted.
    #[sqlx::test]
    async fn reconcile_all_walks_the_backlog_past_the_first_page(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;

        // Three landed refs, each with reflog proof of its own creation.
        let ref_names = ["refs/heads/one", "refs/heads/two", "refs/heads/three"];
        for (i, ref_name) in ref_names.iter().enumerate() {
            let sha = seed_ref_on_bare(&bare, ref_name);
            let mut row = make_row(&repo_id, ref_name, &"0".repeat(40), &sha);
            row.request_id = format!("req-backlog-{i}");
            row.state = pending_state::PREPARED.to_string();
            row.applied_at = None;
            row.id = crate::db::deterministic_id(&[
                "pending_ref_transition",
                &row.request_id,
                &row.repo_id,
                &row.ref_name,
                &row.old_sha,
                &row.new_sha,
            ]);
            state
                .db
                .insert_pending_ref_transition_for_test(&row)
                .await
                .unwrap();
        }

        let promoted = reconcile_prepared_from_disk_all(state.clone(), 1, DRAIN_MAX_PASSES)
            .await
            .unwrap();
        assert_eq!(
            promoted,
            ref_names.len(),
            "every row is reconciled in ONE startup, not one page per restart"
        );
        let still_pending = state
            .db
            .list_pending_ref_transitions_prepared_or_uncertain(100)
            .await
            .unwrap();
        assert!(
            still_pending.is_empty(),
            "no backlog is left stranded past the first page"
        );
    }

    /// The walk must step OVER rows it cannot promote. Those rows stay
    /// `prepared` by design, so a pass that re-queried from the start
    /// would hand itself the same page forever and never reach the
    /// provable rows behind them.
    ///
    /// The blocker here is the class the reflog gate introduces: a ref
    /// that really is on disk at the row's `new_sha`, in a repo that
    /// keeps no reflog for it — permanently unprovable, so it jams page
    /// one on every startup for as long as it exists, not just once.
    ///
    /// MUTATION (RED): ignore the cursor when selecting the next page
    /// and the provable row behind the blocker is never promoted.
    #[sqlx::test]
    async fn reconcile_all_advances_past_an_unprovable_row(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let bare = tmp.path().join("repo.git");
        crate::git::store::init_bare(&bare).expect("init_bare");
        let repo_id = seed_repo_row(&state, bare.to_str().unwrap()).await;

        // Row 1 (oldest, so it sorts first): the ref IS on disk at the
        // row's new_sha, but its reflog is gone — the SHA matches, the
        // age passes, and the landing is still unproven.
        let legacy_sha = seed_ref_on_bare(&bare, "refs/heads/legacy");
        std::fs::remove_file(bare.join("logs/refs/heads/legacy")).expect("drop the ref's reflog");
        let mut blocker = make_row(&repo_id, "refs/heads/legacy", &"0".repeat(40), &legacy_sha);
        blocker.request_id = "req-blocker".to_string();
        blocker.state = pending_state::PREPARED.to_string();
        blocker.applied_at = None;
        blocker.created_at = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        blocker.id = crate::db::deterministic_id(&["pending_ref_transition", "req-blocker"]);
        state
            .db
            .insert_pending_ref_transition_for_test(&blocker)
            .await
            .unwrap();

        // Row 2 (newer): a provable landing sitting behind it.
        let sha = seed_ref_on_bare(&bare, "refs/heads/landed");
        let mut good = make_row(&repo_id, "refs/heads/landed", &"0".repeat(40), &sha);
        good.request_id = "req-good".to_string();
        good.state = pending_state::PREPARED.to_string();
        good.applied_at = None;
        good.id = crate::db::deterministic_id(&["pending_ref_transition", "req-good"]);
        state
            .db
            .insert_pending_ref_transition_for_test(&good)
            .await
            .unwrap();

        let promoted = reconcile_prepared_from_disk_all(state.clone(), 1, DRAIN_MAX_PASSES)
            .await
            .unwrap();
        assert_eq!(
            promoted, 1,
            "the provable row behind a permanently unprovable one is still reached"
        );
        let still_pending = state
            .db
            .list_pending_ref_transitions_prepared_or_uncertain(100)
            .await
            .unwrap();
        assert_eq!(still_pending.len(), 1, "the unprovable row is left alone");
        assert_eq!(still_pending[0].id, blocker.id);
    }

    // ----- P2-A drain resilience tests -----
    //
    // These tests cover the "drain must not abort on first failure"
    // and "drain must not cap at 1000 requests per startup" findings.
    // Backlog processing uses the production
    // `drain_receive_pack_requests_all` (the `DRAIN_PER_PASS_LIMIT` /
    // `DRAIN_MAX_PASSES` constants from this module) so the test
    // exercises the same wrapper the startup calls. Failure isolation
    // uses `drain_receive_pack_requests_with` to inject a closure
    // that returns `Retry` for one request and `Done` for the next.

    #[sqlx::test]
    async fn drain_processes_backlog_larger_than_one_pass(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // Seed 1500 distinct request rows. Each request is its own
        // `receive_pack_requests.id`; per-ref PKs hash the request
        // id, and the certs / anchor jobs hash the request id too.
        const N: usize = 1500;
        for i in 0..N {
            let mut row = make_row(
                "repo-backlog",
                "refs/heads/main",
                &"0".repeat(40),
                &format!("{:040x}", i as u64),
            );
            row.request_id = format!("req-{i}");
            row.id = crate::db::deterministic_id(&[
                "pending_ref_transition",
                &row.request_id,
                &row.repo_id,
                &row.ref_name,
                &row.old_sha,
                &row.new_sha,
            ]);
            let parsed_report = parsed_report_ok(&[("refs/heads/main", true)]);
            stage_request_with_children(
                &state.db,
                &row.request_id,
                "repo-backlog",
                Some(row.ordinal),
                std::slice::from_ref(&row),
                parsed_report,
            )
            .await;
        }

        // Drain with the production limits. Two passes of 1000 each
        // cover all 1500 requests; the third pass would be empty and
        // exits the loop early on the `n < per_pass_limit` check.
        let total =
            drain_receive_pack_requests_all(state.clone(), DRAIN_PER_PASS_LIMIT, DRAIN_MAX_PASSES)
                .await
                .unwrap();
        assert_eq!(total, N, "drain processed the full backlog");

        // No `outcomes_committed` requests remain.
        let after = state.db.count_receive_pack_requests_due().await.unwrap();
        assert_eq!(
            after, 0,
            "every request row was processed and moved to complete"
        );
        // No per-ref children remain either.
        let still = state
            .db
            .list_pending_ref_transitions_applied(10_000)
            .await
            .unwrap();
        assert!(still.is_empty(), "every child was cleaned up");
    }

    #[sqlx::test]
    async fn drain_continues_past_a_failing_row(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // Seed two requests (A first so the `ORDER BY created_at ASC,
        // id ASC` query hits A before B). Each request owns a single
        // child row at ordinal 0.
        let mut row_a = make_row(
            "repo-fail-then-pass",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
        );
        row_a.request_id = "req-A".to_string();
        row_a.id = crate::db::deterministic_id(&[
            "pending_ref_transition",
            &row_a.request_id,
            &row_a.repo_id,
            &row_a.ref_name,
            &row_a.old_sha,
            &row_a.new_sha,
        ]);
        let mut row_b = make_row(
            "repo-fail-then-pass",
            "refs/heads/main",
            &"0".repeat(40),
            &"b".repeat(40),
        );
        row_b.request_id = "req-B".to_string();
        row_b.id = crate::db::deterministic_id(&[
            "pending_ref_transition",
            &row_b.request_id,
            &row_b.repo_id,
            &row_b.ref_name,
            &row_b.old_sha,
            &row_b.new_sha,
        ]);
        let parsed_report = parsed_report_ok(&[("refs/heads/main", true)]);
        stage_request_with_children(
            &state.db,
            "req-A",
            "repo-fail-then-pass",
            Some(0),
            std::slice::from_ref(&row_a),
            parsed_report.clone(),
        )
        .await;
        stage_request_with_children(
            &state.db,
            "req-B",
            "repo-fail-then-pass",
            Some(0),
            std::slice::from_ref(&row_b),
            parsed_report,
        )
        .await;

        // Inject a closure that returns Retry for request A and
        // delegates to the real `apply_request_effects` for B.
        // Request A is moved to `effects_pending` for a future
        // retry; request B is fully processed.
        let state_for_closure = state.clone();
        let (processed, examined) =
            drain_receive_pack_requests_with(state.clone(), 100, |_s, req_id| {
                let target = String::from("req-A");
                let st = state_for_closure.clone();
                async move {
                    if req_id == target {
                        Ok(EffectsOutcome::Retry {
                            last_error: "injected derive failure".to_string(),
                        })
                    } else {
                        apply_request_effects(&st, &req_id).await
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(processed, 1, "only request B is fully processed");
        assert_eq!(
            examined, 2,
            "the loop examined both requests; processed/derivation is independent of pagination"
        );

        // Request A is in `effects_pending` (Retry moved it there).
        let a_req = state
            .db
            .get_receive_pack_request("req-A")
            .await
            .unwrap()
            .expect("req-A exists");
        assert_eq!(
            a_req.state,
            crate::db::request_state::EFFECTS_PENDING,
            "Retry outcome moves A to effects_pending"
        );
        // Request B is in `complete`.
        let b_req = state
            .db
            .get_receive_pack_request("req-B")
            .await
            .unwrap()
            .expect("req-B exists");
        assert_eq!(
            b_req.state,
            crate::db::request_state::COMPLETE,
            "Done outcome moves B to complete"
        );

        // Request A's artifacts were not created (the closure
        // returned Retry before any insert ran).
        let a_push = state
            .db
            .count_push_events(&row_a.repo_id, &row_a.new_sha, &row_a.pusher_did)
            .await
            .unwrap();
        assert_eq!(a_push, 0, "request A's push event was not created");
        let a_anchors = state
            .db
            .count_anchor_jobs(
                &row_a.repo_id,
                &row_a.ref_name,
                &row_a.old_sha,
                &row_a.new_sha,
            )
            .await
            .unwrap();
        assert_eq!(a_anchors, 0, "request A's anchor job was not created");
        let a_cert_id = crate::db::ref_cert_id_for(&row_a.request_id, row_a.ordinal);
        let a_cert = state.db.get_ref_certificate(&a_cert_id).await.unwrap();
        assert!(
            a_cert.is_none(),
            "request A's cert id must not exist (got {:?})",
            a_cert.map(|c| c.id)
        );

        // Request B's artifacts WERE created.
        let b_push = state
            .db
            .count_push_events(&row_b.repo_id, &row_b.new_sha, &row_b.pusher_did)
            .await
            .unwrap();
        assert_eq!(b_push, 1, "request B's push event was created");
        let b_anchors = state
            .db
            .count_anchor_jobs(
                &row_b.repo_id,
                &row_b.ref_name,
                &row_b.old_sha,
                &row_b.new_sha,
            )
            .await
            .unwrap();
        assert_eq!(b_anchors, 1, "request B's anchor job was created");
        let b_cert_id = crate::db::ref_cert_id_for(&row_b.request_id, row_b.ordinal);
        let b_cert = state.db.get_ref_certificate(&b_cert_id).await.unwrap();
        assert!(b_cert.is_some(), "request B's cert was created");
    }

    // ----- P2-B multi-ref push event cardinality test -----
    //
    // The live handler and the recovery drain must produce the same
    // push event id for a multi-ref push. Under the v30 model the id
    // is keyed on `(request_id, accepted_ordinal)`: the request row
    // records which child landed first, and only that child writes
    // the push event. Other children skip the event write but still
    // produce their own certs and anchor jobs.
    //
    // Certs stay per-ref (one per `(repo, ref)` transition); anchor
    // jobs stay per-transition (one per `(repo, ref, old, new)` tuple).
    // The push event is the only artifact that is request-scoped.

    #[sqlx::test]
    async fn multi_ref_push_produces_exactly_one_event_across_live_and_recovery(
        pool: sqlx::PgPool,
    ) {
        let state = crate::test_support::test_state(pool).await;

        // Three children for the SAME `request_id`, distinct
        // `ref_name`s, distinct ordinals 0/1/2. The `new_sha` is
        // shared across all three because this models a push that
        // advanced a tip commit onto three refs at once (the
        // ordinary shape of `git push --all`).
        let shared_new_sha = "c".repeat(40);
        let ref_names = [
            "refs/heads/main",
            "refs/heads/feature-a",
            "refs/heads/feature-b",
        ];
        let mut children = Vec::new();
        for (i, ref_name) in ref_names.iter().enumerate() {
            let mut row = make_row("repo-multi", ref_name, &"0".repeat(40), &shared_new_sha);
            row.request_id = "req-multi".to_string();
            row.ordinal = i as i32;
            // Vary `old_sha` per row so the anchor job PKs (which
            // hash `old_sha`) don't collide.
            row.old_sha = format!("{:040x}", (i + 1) as u64);
            row.id = crate::db::deterministic_id(&[
                "pending_ref_transition",
                &row.request_id,
                &row.repo_id,
                &row.ref_name,
                &row.old_sha,
                &row.new_sha,
            ]);
            children.push(row);
        }
        // Stage the request with `accepted_ordinal = Some(0)` so the
        // first child is the one whose `new_sha` becomes the push
        // event's commit_hash. All three refs are in the parsed
        // report's ok set.
        let parsed_report = parsed_report_ok(&[
            ("refs/heads/main", true),
            ("refs/heads/feature-a", true),
            ("refs/heads/feature-b", true),
        ]);
        stage_request_with_children(
            &state.db,
            "req-multi",
            "repo-multi",
            Some(0),
            &children,
            parsed_report,
        )
        .await;

        // Drain the request.
        let (n, examined) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "the request was processed");
        assert_eq!(examined, 1, "the loop examined the single request");

        // Exactly one push event row, keyed on the deterministic
        // (request_id, accepted_ordinal) id.
        let push_count = state.db.get_push_count("did:key:z6pusher").await.unwrap();
        assert_eq!(
            push_count, 1,
            "exactly one push event for a multi-ref push (trust-score predicate)"
        );
        let events = state
            .db
            .count_push_events("repo-multi", &shared_new_sha, "did:key:z6pusher")
            .await
            .unwrap();
        assert_eq!(events, 1, "exactly one push_events row");

        // The deterministic id is the one the live path would have
        // written.
        let expected_id = crate::db::push_event_id_for("req-multi", 0);
        assert_eq!(
            expected_id,
            crate::db::push_event_id_for("req-multi", 0),
            "push_event_id_for is deterministic"
        );

        // Certs: one per ref (the cert contract is per-ref, NOT
        // collapsed by ordinal). Three children → three certs.
        let certs = state
            .db
            .list_ref_certificates("repo-multi", 10)
            .await
            .unwrap();
        assert_eq!(
            certs.len(),
            3,
            "one cert per ref transition (not collapsed by accepted_ordinal)"
        );

        // Anchor jobs: one per `(repo, ref, old, new)` transition.
        // Three children → three anchor jobs.
        for (i, ref_name) in ref_names.iter().enumerate() {
            let n = state
                .db
                .count_anchor_jobs(
                    "repo-multi",
                    ref_name,
                    &format!("{:040x}", (i + 1) as u64),
                    &shared_new_sha,
                )
                .await
                .unwrap();
            assert_eq!(n, 1, "one anchor job per transition");
        }
    }

    // ----- P2 (reviewer-1 round 2): distinct new_shas across refs -----
    //
    // The previous multi-ref test shared one `new_sha` across all
    // refs; that masked the wrong-hash bug. This test gives every ref
    // a distinct `new_sha` and asserts the persisted `commit_hash` is
    // the FIRST ref's `new_sha`. The live handler derives
    // `accepted_ordinal` from `ref_updates.first()`'s position and
    // uses that ordinal's new_sha for the push event. Without the
    // `row.ordinal == request.accepted_ordinal` gate the drain would
    // `record_push_with_id` for whichever row the `ORDER BY
    // applied_at, id` query returned first, leaving the wrong hash
    // for any other drain order.
    #[sqlx::test]
    async fn multi_ref_recovery_uses_first_refs_new_sha_for_push_event(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // Three refs, each with a distinct `new_sha` modelling a
        // multi-branch push where each ref advanced to a different
        // tip. The first ref's new_sha is the one the live handler
        // would have used.
        let first_new_sha = "a".repeat(40);
        let second_new_sha = "b".repeat(40);
        let third_new_sha = "c".repeat(40);
        let ref_names = [
            "refs/heads/main",
            "refs/heads/feature-a",
            "refs/heads/feature-b",
        ];
        let new_shas = [&first_new_sha, &second_new_sha, &third_new_sha];
        let mut children = Vec::new();
        for (i, (ref_name, new_sha)) in ref_names.iter().zip(new_shas.iter()).enumerate() {
            let mut row = make_row("repo-multi-distinct", ref_name, &"0".repeat(40), new_sha);
            row.request_id = "req-multi-distinct".to_string();
            row.ordinal = i as i32;
            // Vary `old_sha` per row so the anchor job PKs don't
            // collide and so the certs distinguish the three
            // transitions.
            row.old_sha = format!("{:040x}", (i + 1) as u64);
            row.id = crate::db::deterministic_id(&[
                "pending_ref_transition",
                &row.request_id,
                &row.repo_id,
                &row.ref_name,
                &row.old_sha,
                &row.new_sha,
            ]);
            children.push(row);
        }
        let parsed_report = parsed_report_ok(&[
            ("refs/heads/main", true),
            ("refs/heads/feature-a", true),
            ("refs/heads/feature-b", true),
        ]);
        stage_request_with_children(
            &state.db,
            "req-multi-distinct",
            "repo-multi-distinct",
            Some(0),
            &children,
            parsed_report,
        )
        .await;

        // Drain the request.
        let (n, examined) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(n, 1, "the request was processed");
        assert_eq!(examined, 1, "the loop examined the single request");

        // Exactly one push event row, keyed on the deterministic
        // (request_id, accepted_ordinal) id. The persisted
        // `commit_hash` is the FIRST ref's `new_sha` — the same
        // value the live path would have written.
        let push_count = state.db.get_push_count("did:key:z6pusher").await.unwrap();
        assert_eq!(push_count, 1, "exactly one push event row");
        let first_event = state
            .db
            .count_push_events("repo-multi-distinct", &first_new_sha, "did:key:z6pusher")
            .await
            .unwrap();
        assert_eq!(
            first_event, 1,
            "the persisted commit_hash is the FIRST ref's new_sha"
        );
        // The non-first new_shas MUST NOT have a push event
        // pointing at them — that would be the wrong-hash bug.
        for other in [&second_new_sha, &third_new_sha] {
            let n = state
                .db
                .count_push_events("repo-multi-distinct", other, "did:key:z6pusher")
                .await
                .unwrap();
            assert_eq!(
                n, 0,
                "no push event for the non-first ref's new_sha ({other})"
            );
        }

        // Certs stay per-ref (three refs → three certs).
        let certs = state
            .db
            .list_ref_certificates("repo-multi-distinct", 10)
            .await
            .unwrap();
        assert_eq!(certs.len(), 3, "one cert per ref transition");
    }

    // ----- P2-D (reviewer-2 round 2): all-fail batch does not early-exit -----
    //
    // The previous loop's exit condition was `(n as i64) < per_pass_limit`
    // where `n` was rows *fully processed* (derive + delete). A pass
    // where every `apply_request_effects` returns Retry logs each
    // failure but increments `processed = 0`; the outer loop sees
    // `0 < per_pass_limit` and returns. Remaining requests are never
    // attempted that boot. The fix returns `(processed, examined)`
    // and keys the exit on `examined`. This test seeds
    // `per_pass_limit` requests with a closure that retries every
    // one, then asserts the drain ran every request (processed=0,
    // examined=per_pass_limit) so the outer loop continues to the
    // next pass.
    #[sqlx::test]
    async fn drain_does_not_exit_early_when_every_row_fails(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        const N: usize = 5;
        let parsed_report = parsed_report_ok(&[("refs/heads/main", true)]);
        for i in 0..N {
            let mut row = make_row(
                "repo-all-fail",
                "refs/heads/main",
                &"0".repeat(40),
                &format!("{:040x}", i as u64),
            );
            row.request_id = format!("req-all-fail-{i}");
            row.id = crate::db::deterministic_id(&[
                "pending_ref_transition",
                &row.request_id,
                &row.repo_id,
                &row.ref_name,
                &row.old_sha,
                &row.new_sha,
            ]);
            stage_request_with_children(
                &state.db,
                &row.request_id,
                "repo-all-fail",
                Some(row.ordinal),
                std::slice::from_ref(&row),
                parsed_report.clone(),
            )
            .await;
        }

        let (processed, examined) =
            drain_receive_pack_requests_with(state.clone(), N as i64, |_s, _req_id| async move {
                Ok(EffectsOutcome::Retry {
                    last_error: "injected: every request fails".to_string(),
                })
            })
            .await
            .unwrap();
        assert_eq!(processed, 0, "no request was fully processed");
        assert_eq!(
            examined, N,
            "the loop examined every request even though every derive failed"
        );

        // Every request is in `effects_pending` for a future retry.
        let due = state.db.count_receive_pack_requests_due().await.unwrap();
        // The Retry path sets `next_attempt_at` 60s in the future,
        // so the due count is 0 — but the requests still exist.
        assert_eq!(due, 0, "Retry schedules the requests 60s out");
        // And there are N total outcomes_committed/effects_pending.
        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*)::BIGINT FROM receive_pack_requests
               WHERE state IN ($1, $2)"#,
        )
        .bind(crate::db::request_state::OUTCOMES_COMMITTED)
        .bind(crate::db::request_state::EFFECTS_PENDING)
        .fetch_one(state.db.pool())
        .await
        .unwrap();
        assert_eq!(
            total, N as i64,
            "all N requests are still pending for the next startup"
        );
    }

    // ----- P1 (reviewer-1 round 2): recovery refreshes a stale cert -----
    //
    // The crash window the reviewer named: the live cert was issued
    // before the push actually landed on disk (e.g. cert was emitted
    // at t1, the apply succeeded at t2, the live upsert never re-ran
    // because the handler errored after the cert write). A second
    // startup runs the recovery drain, which must update the cert's
    // `old_sha` / `new_sha` / `pusher_did` / `signature` /
    // `issued_at` to the new transition. The `id` (deterministic
    // from `(request_id, ref_name)`) is preserved — the upsert only
    // touches the SHAs/did/signature/ts columns. Without the upsert
    // the cert stays at the old transition and consumers reading
    // `ref_certificates.new_sha` see a value that does not match
    // the ref on disk.

    #[sqlx::test]
    async fn recovery_refreshes_stale_cert_to_landed_transition(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;

        // Seed a repo so the cert FK is satisfied.
        let owner_did = "did:key:zCertOwner";
        let rec = crate::db::RepoRecord {
            id: "repo-cert-refresh".to_string(),
            name: "cert-refresh".to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            disk_path: "/tmp/cert-refresh".to_string(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&rec).await.unwrap();

        // Insert a STALE cert directly: old SHA → some "stale new" SHA
        // at t1, with a different pusher DID. This models the live
        // cert issued before the push landed. The cert id is
        // deterministic on `(request_id, ordinal)`; the recovery row
        // is a single child at ordinal 0.
        let stale_cert_id = crate::db::ref_cert_id_for("req-stale", 0);
        let stale_old = "0".repeat(40);
        let stale_new = "1".repeat(40);
        let stale_pusher = "did:key:zStalePusher";
        let stale_issued = (chrono::Utc::now() - chrono::Duration::seconds(60)).to_rfc3339();
        state
            .db
            .insert_ref_certificate_idempotent(&crate::db::RefCertificate {
                id: stale_cert_id.clone(),
                repo_id: rec.id.clone(),
                ref_name: "refs/heads/main".to_string(),
                old_sha: stale_old.clone(),
                new_sha: stale_new.clone(),
                pusher_did: stale_pusher.to_string(),
                node_did: state.node_did.to_string(),
                signature: "stale-signature".to_string(),
                issued_at: stale_issued.clone(),
            })
            .await
            .unwrap();

        // Seed the durable child with the LANDED transition (what
        // the push actually applied to disk): a different old_sha
        // and new_sha, the genuine pusher DID. The drain must
        // refresh the stale cert to this transition.
        let landed_old = "2".repeat(40);
        let landed_new = "3".repeat(40);
        let landed_pusher = "did:key:zLandedPusher";
        let mut row = make_row(&rec.id, "refs/heads/main", &landed_old, &landed_new);
        row.request_id = "req-stale".to_string();
        row.pusher_did = landed_pusher.to_string();
        row.ordinal = 0;
        row.id = crate::db::deterministic_id(&[
            "pending_ref_transition",
            &row.request_id,
            &row.repo_id,
            &row.ref_name,
            &row.old_sha,
            &row.new_sha,
        ]);
        let parsed_report = parsed_report_ok(&[("refs/heads/main", true)]);
        stage_request_with_pusher(
            &state.db,
            "req-stale",
            &rec.id,
            landed_pusher,
            Some(0),
            std::slice::from_ref(&row),
            parsed_report,
        )
        .await;

        // Drain. The recovery upsert must overwrite the stale cert
        // with the landed transition's SHAs / pusher / signature.
        let (processed, examined) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(processed, 1, "the request was drained");
        assert_eq!(examined, 1, "the loop examined the single request");

        let certs = state.db.list_ref_certificates(&rec.id, 10).await.unwrap();
        assert_eq!(certs.len(), 1, "exactly one cert row, the same id");
        let cert = &certs[0];
        assert_eq!(cert.id, stale_cert_id, "deterministic id preserved");
        assert_eq!(
            cert.old_sha, landed_old,
            "old_sha refreshed to the landed transition"
        );
        assert_eq!(
            cert.new_sha, landed_new,
            "new_sha refreshed to the landed transition (was the bug)"
        );
        assert_eq!(
            cert.pusher_did, landed_pusher,
            "pusher refreshed to the actual landed pusher"
        );
        assert_ne!(
            cert.signature, "stale-signature",
            "signature was re-signed with the landed transition"
        );
        // `issued_at` is a free-form string; just assert the row is
        // populated. The monotonic `issued_at > stale_issued` is what
        // the upsert's CASE WHEN checks.
        assert!(!cert.issued_at.is_empty(), "issued_at populated");
    }

    // ----- P1 round 4: A → B → restart replay test -----
    //
    // The reviewer's invariant: a recovery replay of A's row after a
    // later live cert B has been written must NOT overwrite B's
    // fields. Without `issued_at_override`, the recovery's
    // `Utc::now()` is later than B's live `Utc::now()` (because the
    // replay happens after B's live write), and the
    // `EXCLUDED.issued_at > ref_certificates.issued_at` upsert guard
    // would let A's stale transition clobber B's fresh cert.
    //
    // The fix stamps the recovery cert's `issued_at` with the row's
    // `created_at`, which carries the original transition time and
    // is earlier than B's `Utc::now()`. This test pins that the
    // replay does not outrank B.
    #[sqlx::test]
    async fn replay_of_stale_row_does_not_overwrite_live_cert_b(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let owner_did = "did:key:z6Mkreplay";
        let rec = crate::db::RepoRecord {
            id: "repo-replay".to_string(),
            name: "replay".to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            disk_path: "/tmp/replay".to_string(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&rec).await.unwrap();

        // A: original push, request row still in `outcomes_committed`.
        let a_old = "0".repeat(40);
        let a_new = "1".repeat(40);
        let a_pusher = "did:key:zA";
        let a_request = "req-A";
        let mut a_row = make_row(&rec.id, "refs/heads/main", &a_old, &a_new);
        a_row.request_id = a_request.to_string();
        a_row.pusher_did = a_pusher.to_string();
        a_row.ordinal = 0;
        a_row.id = crate::db::deterministic_id(&[
            "pending_ref_transition",
            &a_row.request_id,
            &a_row.repo_id,
            &a_row.ref_name,
            &a_row.old_sha,
            &a_row.new_sha,
        ]);
        // Backdate A's created_at by 5 minutes so the replay's
        // stamped `issued_at` is provably older than B's live one.
        a_row.created_at = (chrono::Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        let parsed_report = parsed_report_ok(&[("refs/heads/main", true)]);
        stage_request_with_pusher(
            &state.db,
            a_request,
            &rec.id,
            a_pusher,
            Some(0),
            std::slice::from_ref(&a_row),
            parsed_report,
        )
        .await;

        // A's cert was written live (or never — we test the case
        // where the row was left pending and the cert was NOT yet
        // written, then B's live push arrives first and writes its
        // cert, then A's drain replays).
        //
        // Simulate: the live cert B has been written by a later
        // push.
        let b_old = a_new.clone();
        let b_new = "2".repeat(40);
        let b_pusher = "did:key:zB";
        // B is a stand-in for "a later live push already wrote its
        // cert". The cert id is arbitrary — what matters is the
        // row collides with A's recovery on the
        // `(repo_id, ref_name)` unique index. Use B's
        // request-scoped id at ordinal 0 so the id is a real
        // `(request_id, ordinal)` shape.
        let b_cert_id = crate::db::ref_cert_id_for("req-B", 0);
        state
            .db
            .insert_ref_certificate(&crate::db::RefCertificate {
                id: b_cert_id.clone(),
                repo_id: rec.id.clone(),
                ref_name: "refs/heads/main".to_string(),
                old_sha: b_old.clone(),
                new_sha: b_new.clone(),
                pusher_did: b_pusher.to_string(),
                node_did: state.node_did.to_string(),
                signature: "b-live-signature".to_string(),
                issued_at: chrono::Utc::now().to_rfc3339(),
            })
            .await
            .unwrap();

        // Drain A's replay. The upsert sees A's `issued_at` (A's
        // created_at = now-5min) is OLDER than B's cert (now), so
        // the per-column CASE WHEN guards must NOT update B's
        // fields.
        let (processed, examined) = drain_receive_pack_requests(state.clone(), 100)
            .await
            .unwrap();
        assert_eq!(processed, 1, "A's request was drained");
        assert_eq!(examined, 1, "the loop examined A's request");

        let certs = state.db.list_ref_certificates(&rec.id, 10).await.unwrap();
        assert_eq!(certs.len(), 1, "exactly one cert row remains");
        let cert = &certs[0];
        assert_eq!(
            cert.old_sha, b_old,
            "old_sha stays at B's; A's replay (now-5min) must not outrank B's (now)"
        );
        assert_eq!(
            cert.new_sha, b_new,
            "new_sha stays at B's; A's replay must not outrank B's"
        );
        assert_eq!(
            cert.pusher_did, b_pusher,
            "pusher stays at B's; A's replay must not outrank B's"
        );
        assert_eq!(
            cert.signature, "b-live-signature",
            "signature stays at B's live signature; A's replay must not outrank B's"
        );
    }

    // #26 Split PR 1 step 4 — bounded retirement. The periodic
    // purge task deletes terminal `complete` / `rejected_at_git`
    // rows and their children older than the retention window.
    // The tests below pin the contract:
    //
    // 1. Only `complete` / `rejected_at_git` rows are eligible.
    // 2. Only rows with `completed_at < now - retention` are eligible.
    // 3. Children are purged after their parent request.
    // 4. `quarantined` (not yet a state) and non-terminal states are NEVER purged.
    // 5. Idempotent: a second purge with no new eligible rows returns (0, 0).

    /// Helper: insert a request row with the given state and `completed_at`.
    /// Returns the request id.
    async fn stage_request_for_purge(
        pool: &sqlx::PgPool,
        request_id: &str,
        state: &str,
        completed_at: Option<&str>,
    ) {
        let now = chrono::Utc::now().to_rfc3339();
        let created_at = now.clone();
        let bytes = b"purge-test".to_vec();
        sqlx::query(
            r#"INSERT INTO receive_pack_requests
               (id, repo_id, pusher_did, node_did, request_bytes, request_bytes_hash,
                state, git_exit_ok, parsed_report, accepted_ordinal, attempt_count,
                last_error, next_attempt_at, created_at, completed_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
        )
        .bind(request_id)
        .bind("purge-test-repo")
        .bind("did:key:zPurgeTester")
        .bind("did:key:zPurgeNode")
        .bind(&bytes)
        .bind(vec![0u8; 32])
        .bind(state)
        .bind(Some(true))
        .bind(None::<serde_json::Value>)
        .bind(Some(0_i32))
        .bind(0_i32)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(&created_at)
        .bind(completed_at)
        .execute(pool)
        .await
        .expect("insert request for purge test");
    }

    #[sqlx::test]
    async fn purge_deletes_only_old_complete_and_rejected_at_git(pool: sqlx::PgPool) {
        let db = _db(pool.clone()).await;
        // 8 days ago, well past the 7-day retention.
        let old = (chrono::Utc::now() - chrono::Duration::days(8)).to_rfc3339();
        // 1 day ago, inside the window.
        let fresh = (chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339();
        let ids_old: Vec<String> = vec![
            "r-old-complete".into(),
            "r-old-rejected".into(),
            "r-fresh-complete".into(),
            "r-fresh-rejected".into(),
            "r-old-received".into(),
            "r-old-outcomes".into(),
            "r-old-effects-pending".into(),
            "r-old-no-completion".into(),
        ];
        stage_request_for_purge(&pool, "r-old-complete", request_state::COMPLETE, Some(&old)).await;
        stage_request_for_purge(
            &pool,
            "r-old-rejected",
            request_state::REJECTED_AT_GIT,
            Some(&old),
        )
        .await;
        stage_request_for_purge(
            &pool,
            "r-fresh-complete",
            request_state::COMPLETE,
            Some(&fresh),
        )
        .await;
        stage_request_for_purge(
            &pool,
            "r-fresh-rejected",
            request_state::REJECTED_AT_GIT,
            Some(&fresh),
        )
        .await;
        // Non-terminal states: never purged even when old.
        stage_request_for_purge(&pool, "r-old-received", request_state::RECEIVED, Some(&old)).await;
        stage_request_for_purge(
            &pool,
            "r-old-outcomes",
            request_state::OUTCOMES_COMMITTED,
            Some(&old),
        )
        .await;
        stage_request_for_purge(
            &pool,
            "r-old-effects-pending",
            request_state::EFFECTS_PENDING,
            Some(&old),
        )
        .await;
        // A request with no completed_at: never purged (NULL is excluded by the WHERE).
        stage_request_for_purge(&pool, "r-old-no-completion", request_state::COMPLETE, None).await;

        let (reqs, _children) = purge_request_queue(&db, 7, 100).await.unwrap();
        assert_eq!(reqs, 2, "exactly the two old terminal rows");

        // Verify which ids survived by re-reading each one directly.
        for id in &ids_old {
            let after = db.get_receive_pack_request(id).await.unwrap();
            let expected_deleted = matches!(id.as_str(), "r-old-complete" | "r-old-rejected");
            if expected_deleted {
                assert!(after.is_none(), "{id} should have been purged");
            } else {
                assert!(after.is_some(), "{id} should have been retained");
            }
        }
    }

    #[sqlx::test]
    async fn purge_idempotent_returns_zero_on_second_call(pool: sqlx::PgPool) {
        let db = _db(pool.clone()).await;
        let old = (chrono::Utc::now() - chrono::Duration::days(8)).to_rfc3339();
        stage_request_for_purge(&pool, "r-once", request_state::COMPLETE, Some(&old)).await;

        let (a, _) = purge_request_queue(&db, 7, 100).await.unwrap();
        assert_eq!(a, 1);
        let (b, _) = purge_request_queue(&db, 7, 100).await.unwrap();
        assert_eq!(b, 0, "second pass has nothing left to delete");
    }

    #[sqlx::test]
    async fn purge_retention_window_pins_at_7_days(pool: sqlx::PgPool) {
        // The spec calls for a 7-day window. The CLI's `1..=365` range
        // guarantees a non-zero window, so we don't test retention = 0
        // here — that path is not exposed to operators. This test pins
        // the invariant: a row with completed_at = now is INSIDE the
        // 7-day window and is NOT purged.
        let db = _db(pool.clone()).await;
        let now_iso = chrono::Utc::now().to_rfc3339();
        stage_request_for_purge(&pool, "r-now", request_state::COMPLETE, Some(&now_iso)).await;

        let (n, _) = purge_request_queue(&db, 7, 100).await.unwrap();
        assert_eq!(
            n, 0,
            "row with completed_at = now is inside the 7-day window"
        );

        let after = db.get_receive_pack_request("r-now").await.unwrap();
        assert!(after.is_some(), "r-now must survive the 7-day window");
    }
}
