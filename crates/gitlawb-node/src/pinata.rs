//! Pinata IPFS pinning integration for Filecoin-backed warm storage.
//!
//! After git objects land on the node, this module uploads them to Pinata
//! so they are pinned off-node and available via the public IPFS gateway.
//!
//! Set `GITLAWB_PINATA_JWT` to enable. Leave empty and every call is a
//! no-op, so nodes without Pinata backing work fine.

use anyhow::Result;
use std::time::{Duration, Instant};

/// Pin a single git object's raw bytes on Pinata (v3 API).
///
/// - `client`:     shared reqwest client
/// - `upload_url`: Pinata v3 upload URL (configured via `GITLAWB_PINATA_UPLOAD_URL`)
/// - `jwt`:        Pinata bearer JWT; returns `Ok("")` immediately if empty
/// - `sha`:        git object hash hex (used as the pin name)
/// - `data`:       raw git object bytes
///
/// Returns the IPFS CID assigned by Pinata on success.
pub async fn pin_object(
    client: &reqwest::Client,
    upload_url: &str,
    jwt: &str,
    sha: &str,
    data: &[u8],
) -> Result<String> {
    if jwt.is_empty() {
        return Ok(String::new());
    }

    let filename = format!("git-{}.bin", &sha[..sha.len().min(8)]);
    let part = reqwest::multipart::Part::bytes(data.to_vec())
        .file_name(filename)
        .mime_str("application/octet-stream")?;
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("network", "public")
        .text("name", format!("git-{sha}"));

    let resp = client
        .post(upload_url)
        .bearer_auth(jwt)
        .multipart(form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Pinata request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Pinata returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Pinata response: {e}"))?;

    // v3 response: {"data": {"cid": "...", "name": "...", ...}}
    let cid = json["data"]["cid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'data.cid' in Pinata response: {json}"))?
        .to_string();

    tracing::debug!(sha = %sha, %cid, "pinned git object to Pinata");
    Ok(cid)
}

/// Pin any of the given candidate git objects that haven't yet been sent to
/// Pinata.
///
/// `object_list` is the already-withheld-filtered OID set to pin: the caller
/// applies `visibility_pack::replicable_objects` on the delta path or the
/// `..._fail_closed` filter on the full-scan path before calling. `repo_path` is
/// still needed to read each object's bytes, and `git_bin` names the binary those
/// reads run: the production caller passes the literal `"git"`, and a test passes a
/// fake so the loop's own bound can be driven with a git that never answers.
/// `git_timeout` is the per-object read bound, the same value and the same role it has
/// in the twin: it bounds both the pin read and the skip branch's opportunistic repair.
/// Objects already recorded with a `pinata_cid` are skipped, and `repo_id` records the
/// pin's provenance (#173). Returns `(sha_hex, provider_cid)` pairs for each newly
/// pinned object: the provider CID is the Pinata gateway CID (used for branch->CID
/// recording and ref-update gossip), NOT the raw resolver-key CID stored in
/// `pinned_cids.cid`.
///
/// # What `batch_budget` does and does not bound
///
/// The loop runs under a `pin_semaphore` permit and that pool defers rather than
/// sheds, so the hold has to be bounded by something other than the pusher's object
/// count. Three things here are:
///
/// - this loop's own wall-clock: the deadline is taken once at loop start and
///   checked at the top of every iteration, so no object's work begins with less
///   than the read floor left. It is a gate, not a hard ceiling, since a started
///   iteration still runs to completion;
/// - the git read: `store::read_object_bounded` runs under `spawn_blocking` against the
///   earlier of the ABSOLUTE batch deadline (not the loop-top remainder, which the
///   `has_pinata_cid` round-trip sitting between the two would push past it) and this
///   object's own `git_timeout`, with SIGTERM-then-SIGKILL process-group teardown, so a
///   hung `git cat-file` costs this batch one `git_timeout` plus one watchdog teardown
///   instead of holding the permit for the child's whole lifetime and blocking a runtime
///   worker while it does;
/// - the DB round-trips: every DB operation reachable from inside the region is
///   bounded by the same absolute deadline through `crate::ipfs_pin::db_bounded`,
///   including the two inside `repair_legacy_provider_cid`, which this loop body's own
///   call sites do not show. `retry_db_record` is wrapped as a whole so its ladder
///   cannot multiply one remainder, and the durability writes (the post-upload
///   `record_pinata_cid` and source record, the skip branch's source record, and both
///   incomplete markers) take the floored remainder `max(remaining, DB_RECORD_GRACE)`
///   so a spent budget delays the permit release rather than dropping a write. That
///   floor matters more here than on the twin: `pinned.push` is unconditional, so a
///   dropped record would leave `api::repos` advertising a CID the resolver 404s. A
///   bound is not a rollback, and what an elapsed bound MEANS is a property of the
///   operation, so each site maps that arm from the shape of the call it wrapped. Both
///   source-record sites wrap `record_pin_source`, an explicit transaction whose
///   `tx.commit()` a cancelled future never reaches, so a timeout there definitely did
///   not land and both write the incomplete marker exactly as the definite-error arm
///   does. `record_pinata_cid` is a single autocommit upsert, so ITS timeout is a
///   genuine unknown outcome and is never treated as a failed write. See
///   `crate::ipfs_pin::BoundedDbError::Elapsed`.
///
/// So the LOOP's hold is bounded by roughly `batch_budget`, plus one watchdog
/// teardown, one upload (the shared client's whole-request timeout bounds the
/// upload; `pin_object` takes no per-request override), and the record graces one
/// iteration can chain. `db_record_deadline` re-floors from `Instant::now()` at EVERY
/// call, so the graces inside a single iteration add up rather than sharing one floor:
/// the worst case here is the add path at `deadline + 6s` (`record_pinata_cid`, then
/// `record_pin_source`, then its incomplete marker), against the skip branch's
/// `deadline + 4s`. It does NOT stack per object, because the next iteration's first
/// statement is `batch_budget_gate`, which breaks the batch, so the overrun is one
/// iteration's worth however many objects the push carried. Against the 120s
/// `PIN_BATCH_BUDGET` that is roughly a 5% overrun for the batch, not an unbounded
/// hold. The PERMIT's hold is NOT bounded by any of this, and that stays out of
/// scope: `api::repos` acquires the permit (repos.rs ~2688) and only then re-derives
/// the object list with `pinata_object_list_for_refs` (~2697), BEFORE this function is
/// entered, and that walk carries no aggregate deadline. What is bounded is this
/// loop's own hold, not the permit's total hold and not the semaphore's worst-case
/// queue.
///
/// The twin in `ipfs_pin.rs` is at parity with this loop on everything that bounds or
/// repairs an object: the shared budget gate, the read bounded by the earlier of the
/// batch deadline and `git_timeout`, the skip branch's opportunistic legacy
/// provider-CID repair, and the DB bound above, which is the SAME helper and the same
/// floor on both sides rather than a copy. Change them in lockstep: the
/// skip-if-pinned check, the provenance and source recording, the fault arms, and the
/// budget handling.
///
/// The RETURNED PAIRS are the one deliberate divergence, and it is not drift. This side
/// pushes a pin whose DB record exhausted its retries, because this return is a real
/// input: `api::repos` builds the sha-to-cid `cid_map` from it, which drives
/// `upsert_branch_cid` and the p2p `publish_ref_update` gossip CID. The twin's return is
/// log-only, so it omits a record-failed pin rather than logging a pin the resolver
/// cannot serve. Moving this side to match would need that consumer moved first.
// Ten arguments, over clippy's threshold: the three the budget and the git seam add
// (`git_bin`, `git_timeout`, `batch_budget`) plus #173's `repo_id` are what put the read
// under test injection and under a deadline, and grouping them into a struct would only
// move the same values behind a name the twin in `ipfs_pin.rs` does not use. Same allow
// as the sibling call sites in `api::repos`.
#[allow(clippy::too_many_arguments)]
pub async fn pin_new_objects(
    client: &reqwest::Client,
    upload_url: &str,
    jwt: &str,
    repo_path: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    object_list: Vec<String>,
    db: &crate::db::Db,
    repo_id: &str,
    batch_budget: Duration,
    fence: Option<&crate::ipfs_pin::PolicyFence>,
) -> Vec<(String, String)> {
    if jwt.is_empty() {
        return vec![];
    }

    let deadline = Instant::now() + batch_budget;
    let total = object_list.len();
    let mut pinned = Vec::new();

    for (attempted, sha) in object_list.into_iter().enumerate() {
        // Policy fence (R1-P1): a visibility narrow that lands after the caller
        // built this batch must abort it before the next irreversible upload.
        if let Some(f) = fence {
            if !f.is_current().await {
                tracing::warn!(
                    repo = %f.repo_id(),
                    unattempted = total - attempted,
                    "visibility policy changed mid-batch; stopping the Pinata pin loop"
                );
                break;
            }
        }
        // Top of the iteration, before any of this object's work: an object is never
        // started with a remainder too small to cover a bounded read's teardown. The
        // gate is shared with the IPFS loop so the two cannot drift apart in how they
        // report a truncated batch. Consumed as a guard only: the read below runs against
        // the absolute batch deadline, and `pin_object` takes no per-request override, so
        // the remainder has no other consumer here.
        if crate::ipfs_pin::batch_budget_gate("Pinata", deadline, pinned.len(), total - attempted)
            .is_none()
        {
            break;
        }

        // Every DB call from here to the end of the iteration is bounded by the
        // ABSOLUTE batch deadline (F3, #173), through the same `db_bounded` helper the
        // ipfs_pin twin routes through: this loop runs under the same global pin permit
        // and a bare await parked it for the whole stall. The elapsed arm is mapped per
        // site below, never as a blanket "existing error arm": a timeout cancels the
        // client future but not the statement Postgres is running, so it reports an
        // UNKNOWN outcome, not a failed write.
        match crate::ipfs_pin::db_bounded(deadline, db.has_pinata_cid(&sha)).await {
            Ok(true) => {
                // Backfill NULL first-pinner provenance from a known source, in lockstep
                // with the ipfs_pin skip branch: a pinata-only node otherwise leaves
                // pre-provenance rows' `pinned_cids.repo_id` NULL forever (grok P2-D). The
                // resolver still finds the object via the pin_repo_sources union below, so
                // this is a consistency backfill, not a correctness fix.
                //
                // Elapsed here is free to skip: the read costs nothing when it lands late,
                // and the backfill's own `AND repo_id IS NULL` guard makes a late-landing
                // write idempotent.
                match crate::ipfs_pin::db_bounded(deadline, db.provenance_for_oid(&sha)).await {
                    Ok(None) => {
                        if let Err(e) = crate::ipfs_pin::db_bounded(
                            deadline,
                            db.backfill_pin_provenance(&sha, repo_id),
                        )
                        .await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to backfill pin provenance");
                        }
                    }
                    Ok(Some(_)) => {}
                    Err(e) => {
                        tracing::warn!(sha = %sha, err = %e, "DB error reading pin provenance");
                    }
                }
                // F1 (#173 round 8): record this repo as an additional source for the
                // already-pinned object (mirrors the ipfs_pin skip-branch insert) so the
                // resolver can serve a shared object from any pin-path source. U3 (#173):
                // retried through the SHARED helper (this was a bare call, so a single
                // transient error dropped the source outright) and, on exhaustion, marked
                // durably so the resolver keeps the bounded scan fallback for the object.
                // The retry ladder is bounded AS A WHOLE, not per attempt: three stalls
                // plus their backoff otherwise multiply one remainder by three. Floored at
                // DB_RECORD_GRACE because this is a durability write.
                match crate::ipfs_pin::db_bounded(
                    crate::ipfs_pin::db_record_deadline(deadline),
                    crate::ipfs_pin::retry_db_record(|| db.record_pin_source(&sha, repo_id)),
                )
                .await
                {
                    Ok(()) => {}
                    // Elapsed here is a DEFINITE non-write, in lockstep with the twin,
                    // and for a reason that comes from the operation rather than the
                    // timeout: `record_pin_source` is an explicit transaction whose
                    // `tx.commit()` a cancelled future never reaches, so no COMMIT is
                    // sent and the row cannot have landed. Mark the set incomplete
                    // exactly as the definite-error arm does; an incomplete-and-unmarked
                    // set is read as COMPLETE and 404s a copy this repo would serve. The
                    // marker's cost is bounded (the fallback scan is capped at
                    // `ipfs_max_legacy_probes` and charges the per-IP work rate limiter
                    // per probe). The arm stays separate only so the warn tells an
                    // operator a stalled batch from a scattered per-object failure.
                    Err(e @ crate::ipfs_pin::BoundedDbError::Elapsed) => {
                        tracing::warn!(
                            sha = %sha,
                            err = %e,
                            "pin source record did not complete inside the batch deadline; \
                             a cancelled multi-statement transaction never commits, so the \
                             source is definitely missing and the set is marked incomplete"
                        );
                        if let Err(e) = crate::ipfs_pin::db_bounded(
                            crate::ipfs_pin::db_record_deadline(deadline),
                            db.mark_pin_sources_incomplete(&sha, repo_id),
                        )
                        .await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                        }
                    }
                    // The retries are spent on REAL errors, so this repo is definitely NOT
                    // in the source set and the set is known incomplete. Floored for the
                    // same reason the record above is: a spent budget must not drop the
                    // compensation. The marker write is a single autocommit statement, so
                    // ITS own elapsed arm is a genuine unknown outcome; nothing branches
                    // on it, which is why warn-only is right there.
                    Err(e) => {
                        tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                        if let Err(e) = crate::ipfs_pin::db_bounded(
                            crate::ipfs_pin::db_record_deadline(deadline),
                            db.mark_pin_sources_incomplete(&sha, repo_id),
                        )
                        .await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                        }
                    }
                }
                // R8 (#173 round 10), in lockstep with the ipfs_pin skip branch:
                // opportunistically repair a legacy provider-CID row (Kubo dag-pb /
                // Pinata) to the raw-content resolver key on this re-push. Cost-gated on
                // the stored key's codec, so a non-legacy row reads no bytes. Warn-only:
                // a failure leaves the row as-is for a later re-push or the deferred
                // one-shot sweep.
                // Clamped to the batch deadline, in lockstep with the ipfs_pin twin: this
                // runs with the pin permit held, so an unclamped `git_timeout` would let
                // one wedged read hold a global pin slot for 600s against a 120s budget.
                if let Err(e) = crate::ipfs_pin::repair_legacy_provider_cid(
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
                tracing::warn!(sha = %sha, err = %e, "DB error checking pinata_cid");
                continue;
            }
        }

        // Read raw object content, bounded and reaped, under `spawn_blocking`: this is
        // synchronous blocking work (child spawn, pipe drain, watchdog join), so calling
        // it from the runtime task would block a worker thread for its whole duration.
        // Placement mirrors the `/ipfs` serve path and the IPFS pin loop.
        //
        // The read runs against the ABSOLUTE batch deadline, not against the remainder
        // measured at the top of the iteration: the `has_pinata_cid` round-trip above sits
        // between the two, so `Instant::now() + budget_left` would land past `deadline` by
        // however long the DB took, and under a saturated pool that is the dominant term.
        // A slow DB check must not push the read's own bound out.
        //
        // Bounded by the EARLIER of the batch deadline (#174) and this object's own
        // `git_timeout` (#173), the same pair the ipfs_pin twin uses. Both bounds are
        // load-bearing and neither implies the other: the batch deadline alone would let
        // ONE wedged `cat-file` hold the pin permit for the whole budget, while
        // `git_timeout` alone would let a batch of merely-slow reads run past the budget.
        // As on the twin, at SHIPPED DEFAULTS the batch deadline is the arm that binds
        // (600s git timeout against a 120s budget); the `git_timeout` arm is for an
        // operator who tightens that knob below the remaining budget.
        let read_deadline = std::cmp::min(deadline, std::time::Instant::now() + git_timeout);
        let read_path = repo_path.to_path_buf();
        let read_sha = sha.clone();
        let read_git = git_bin.to_string();
        let read = tokio::task::spawn_blocking(move || {
            crate::git::store::read_object_bounded(&read_git, &read_path, &read_sha, read_deadline)
        })
        .await;
        let data = match read {
            Ok(Ok(Some((_kind, bytes)))) => bytes,
            // A verified absence, and the only outcome that is not a fault.
            Ok(Ok(None)) => continue,
            // A Transient fault does NOT by itself mean the store is gone. It also covers
            // a spawn or watchdog-timeout failure of the reaped child, an unaffordable
            // confirming re-probe, and, because readability is judged FOR one oid, a
            // single unreadable `objects/<xx>` fan-out, which is 1/256 of the store. So
            // re-check store-wide before deciding what the fault costs.
            Ok(Err(e @ crate::git::store::ProbeError::Transient(_))) => {
                if !crate::git::store::object_store_readable_store_wide(repo_path) {
                    // Genuinely store-wide: every remaining object fails identically, and
                    // continuing would spawn one doomed bounded child per object and spend
                    // the batch budget reaping them.
                    tracing::warn!(
                        sha = %sha,
                        err = %e,
                        unattempted = total - attempted,
                        "object store unreadable while pinning to Pinata; stopping the batch"
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
                    "transient fault reading git object for Pinata; the object store is \
                     still readable store-wide, so this costs only this object"
                );
                continue;
            }
            // The store is readable and git still failed: a corrupt object, or a
            // repo-wide fault git reports immediately. Either way it is per-object work
            // that stays inside the budget, and breaking would forfeit a healthy store's
            // remaining objects over one bad one, permanently (a later full-scan push
            // re-offers the same object and breaks in the same place).
            Ok(Err(e)) => {
                tracing::warn!(sha = %sha, err = %e, "failed to read git object for Pinata");
                continue;
            }
            // A panic in the read closure leaves no evidence that the failure is
            // object-scoped, so fail toward the conservative arm.
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "bounded git read task failed; stopping the batch");
                break;
            }
        };

        // Dispatch fence (R1-P1): re-read the policy epoch immediately before
        // the irreversible HTTP POST. The iteration-top check catches a narrow
        // that landed before work began; THIS check catches a narrow that landed
        // during the has_pinata_cid round-trip or the bounded Git read.
        if let Some(f) = fence {
            if !f.is_current().await {
                tracing::warn!(
                    repo = %f.repo_id(),
                    unattempted = total - attempted,
                    "visibility policy changed during preparation; aborting Pinata upload"
                );
                break;
            }
        }

        match pin_object(client, upload_url, jwt, &sha, &data).await {
            Ok(cid) if !cid.is_empty() => {
                // The resolver key (`pinned_cids.cid`) must be the locally-computed
                // raw-content CID, never the provider CID: Pinata wraps the bytes in
                // dag-pb/UnixFS, so its returned CID does not hash the raw content and
                // must not become an alias `/ipfs/{cid}` serves raw git bytes for (#173).
                let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(&data).to_string();
                // U3 (#173): both records go through the shared retry helper, at parity
                // with the ipfs_pin twin. These were bare calls, so one transient DB error
                // permanently dropped a pin source.
                //
                // Both bounds here are FLOORED at DB_RECORD_GRACE (F3, #173). The upload
                // runs under the shared client's own ceiling, so a successful one can
                // return with ~0 of the batch budget left, and an unfloored bound would
                // fail a write that today completes in milliseconds. That costs more on
                // this side than on the twin: `pinned.push` below is UNCONDITIONAL, so
                // `api/repos.rs` builds its `cid_map` from the pair either way and drives
                // `upsert_branch_cid` plus the p2p `publish_ref_update` gossip from it. A
                // dropped record therefore makes the node ADVERTISE a CID whose `/ipfs`
                // read 404s. If the floored bound still fires, THIS site's outcome really
                // is unknown, and unlike the source record below that is a property of
                // the operation: `record_pinata_cid` is a single autocommit upsert, so
                // the statement Postgres already started can still land after the client
                // future is cancelled. The warn names the arm through the error's own
                // Display and the site keeps its existing behavior: the pair is still
                // returned, and the row may or may not exist.
                // Round 10 P2: a closed/failed DB write means the
                // (sha, cid) pair is not durable; we suppress the
                // `pinned.push` for this sha so the reconcile cannot
                // count a Pinata gap as filled when no row exists.
                // The autocommit timeout case (the `BoundedDbError`
                // other than `Elapsed`) is genuinely unknown, so we
                // keep the previous single-statement reasoning and
                // push in that case. The source-record failure arms
                // are also a hard failure (multi-statement
                // transaction never committed) and suppress the push
                // in the same way.
                let mut db_record_durable = false;
                match crate::ipfs_pin::db_bounded(
                    crate::ipfs_pin::db_record_deadline(deadline),
                    crate::ipfs_pin::retry_db_record(|| {
                        // P2 (reviewer round 9): Pinata's POST is
                        // irreversible exactly like IPFS's, so
                        // route the record through the fenced
                        // variant when a fence is in scope. The
                        // `i64::MAX` sentinel tells the helper
                        // to skip the lock + comparison (the
                        // unfenced caller path).
                        let fence_epoch = fence.map(|f| f.captured_epoch()).unwrap_or(i64::MAX);
                        db.record_pinata_cid(&sha, &raw_cid, &cid, Some(repo_id), fence_epoch)
                    }),
                )
                .await
                {
                    Ok(()) => db_record_durable = true,
                    Err(crate::ipfs_pin::BoundedDbError::Elapsed) => {
                        // Autocommit: statement may have committed.
                        // Treat as unknown-but-persisted, keep the
                        // old behavior (push the pair).
                        tracing::warn!(
                            sha = %sha,
                            "record_pinata_cid deadline elapsed for autocommit upsert; \
                             the row may or may not exist (the previous comment's reasoning)"
                        );
                        db_record_durable = true;
                    }
                    Err(e) => {
                        tracing::warn!(
                            sha = %sha,
                            err = %e,
                            "failed to record pinata_cid in DB; suppressing the (sha, cid) push \
                             so the reconcile cannot count this gap as filled"
                        );
                        // db_record_durable stays false → push suppressed
                    }
                }
                // F1 (#173 round 8): also record the first pinner in pin_repo_sources.
                // U3: an exhausted retry marks the set incomplete so the resolver keeps
                // the scan fallback rather than 404ing a copy it could serve.
                match crate::ipfs_pin::db_bounded(
                    crate::ipfs_pin::db_record_deadline(deadline),
                    crate::ipfs_pin::retry_db_record(|| db.record_pin_source(&sha, repo_id)),
                )
                .await
                {
                    Ok(()) => {}
                    // Same rule as the skip branch above, and the same reason: this
                    // wraps `record_pin_source`, an explicit transaction, so a timed-out
                    // call definitely never committed and the source is definitely
                    // missing. Mark the set incomplete rather than leaving it incomplete
                    // and unmarked. Round 10 P2: also suppress the (sha, cid) push
                    // because the durable record set is now incomplete; the next pass
                    // re-offers the gap.
                    Err(e @ crate::ipfs_pin::BoundedDbError::Elapsed) => {
                        tracing::warn!(
                            sha = %sha,
                            err = %e,
                            "pin source record did not complete inside the batch deadline; \
                             a cancelled multi-statement transaction never commits, so the \
                             source is definitely missing and the set is marked incomplete"
                        );
                        if let Err(e) = crate::ipfs_pin::db_bounded(
                            crate::ipfs_pin::db_record_deadline(deadline),
                            db.mark_pin_sources_incomplete(&sha, repo_id),
                        )
                        .await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                        }
                        db_record_durable = false;
                    }
                    Err(e) => {
                        tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                        if let Err(e) = crate::ipfs_pin::db_bounded(
                            crate::ipfs_pin::db_record_deadline(deadline),
                            db.mark_pin_sources_incomplete(&sha, repo_id),
                        )
                        .await
                        {
                            tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                        }
                        db_record_durable = false;
                    }
                }
                if db_record_durable {
                    pinned.push((sha, cid));
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "Pinata pin failed — continuing");
            }
        }
    }

    pinned
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `n` loose blobs into a fresh bare repo and return their oids. The read
    /// path shells to `git cat-file`, so the objects must genuinely exist on disk: a
    /// fabricated oid would `continue` past the upload and the loop scenarios below
    /// would prove nothing. Copied from `ipfs_pin.rs`'s test mod rather than shared,
    /// since test mods are private.
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
                        .write_all(format!("pinata loop object {i}\n").as_bytes())
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

    /// A live Pinata-shaped endpoint that answers each upload with a v3 `data.cid`
    /// body after `delays[i]` for the i-th request it accepts (the last entry
    /// repeats), counting the requests it received.
    ///
    /// Hand rolled rather than driven with `mockito` like the `pin_object` tests
    /// above: mockito has no per-response delay primitive, and the batch-budget test
    /// needs uploads that are slow enough to exhaust the budget partway. Drains the
    /// full request, headers plus the declared `Content-Length` body, before
    /// sleeping: answering early and closing would surface as a write failure on the
    /// client and turn a slow-but-healthy upload into a different failure shape.
    /// Same fixture shape as `ipfs_pin.rs`'s `delaying_endpoint`.
    async fn delaying_pinata_endpoint(
        delays: Vec<Duration>,
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> String {
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
                    let body = br#"{"data":{"cid":"QmPinataBatchTestCid","name":"git.bin"}}"#;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.flush().await;
                });
            }
        });
        endpoint
    }

    /// A `tracing` sink a test can read back, so the truncation warn and its sink
    /// label can be asserted on rather than assumed. Installed with `set_default`,
    /// which is thread-local and scoped to the guard, so it cannot bleed into any
    /// other test in the binary.
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

    /// Write an executable `/bin/sh` script. Copied per module rather than shared:
    /// `store.rs`, `visibility_pack.rs` and `ipfs_pin.rs` each keep their own, since
    /// their test mods are private and not reachable from here.
    #[cfg(unix)]
    fn write_script(path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).expect("write fake git");
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }

    /// The permit-hold bound on this branch. `pin_new_objects` runs under the same
    /// deferring `pin_semaphore` as the IPFS loop, so without a batch deadline the
    /// hold is O(N) with N chosen by the pusher. Five objects against an endpoint
    /// that takes 2s each, under a 5.5s budget, must stop partway: the batch is
    /// truncated and the remainder is left unattempted with exactly one warn naming
    /// how many, labelled for this sink.
    ///
    /// The windows are deliberately loose. Four pins would need every upload to
    /// answer in under 1.4s, which the endpoint's own 2s sleep forbids, and one pin
    /// needs only the first upload to land inside 5.5s, so both bounds hold with
    /// more than a second of slack on a loaded box.
    #[sqlx::test]
    async fn pin_new_objects_stops_the_batch_at_its_deadline(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("slow.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint = delaying_pinata_endpoint(
            vec![Duration::from_secs(2)],
            std::sync::Arc::clone(&requests),
        )
        .await;

        let (logs, _guard) = capture_logs();
        let client = reqwest::Client::new();
        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_millis(5500),
                None,
            ),
        )
        .await
        .expect("wedge guard: a 5.5s budget cannot take 30s");

        assert!(
            (1..=3).contains(&pinned.len()),
            "the batch must stop partway, not pin all five and not stall on the first: pinned {}",
            pinned.len()
        );
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            pinned.len(),
            "no upload may be issued for an object the budget stopped short of"
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
        assert!(
            warns[0].contains("Pinata"),
            "the truncation warn must name this sink, not the twin's: {}",
            warns[0]
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

    /// #174 F3 on this branch: the git read runs while the `pin_semaphore` permit is
    /// held, so a wedged `git cat-file` used to hold that permit for as long as the
    /// child lived, with no deadline and no reaping, on a path a pusher drives. With
    /// the read bounded, a git that never answers costs the batch its budget plus one
    /// watchdog teardown and no more.
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
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(25),
            pin_new_objects(
                &client,
                "http://127.0.0.1:9",
                "test-jwt",
                &repo_path,
                fake.to_str().unwrap(),
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(2),
                None,
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

    /// U3 scenario 5 (#173): the read is bounded by the EARLIER of the batch deadline and
    /// this object's own `git_timeout`, the same pair the ipfs_pin twin uses. The batch
    /// budget here is generous (60s) so the budget gate cannot be what ends the call: only
    /// the 1s `git_timeout` can. A wedged `git cat-file` that traps SIGTERM and sleeps 30s
    /// must therefore be reaped in the `git_timeout` order and the call must return, rather
    /// than holding the pin permit for the whole budget.
    ///
    /// RED with `let read_deadline = deadline;` (the pre-U3 bare batch deadline): the read
    /// waits out the wedged child, the call runs ~30s, and the outer 20s timeout fires.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_bounds_the_read_by_git_timeout_not_the_batch_budget(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("git-timeout.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let fake = tmp.path().join("hanging-git");
        write_script(&fake, "#!/bin/sh\ntrap '' TERM\necho $$ > pid\nsleep 30\n");

        let (_logs, _guard) = capture_logs();
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(20),
            pin_new_objects(
                &client,
                "http://127.0.0.1:9",
                "test-jwt",
                &repo_path,
                fake.to_str().unwrap(),
                // The bound under test.
                Duration::from_secs(1),
                oids,
                &db,
                "repo-git-timeout",
                // Generous, so a call that ends on time ended on `git_timeout`.
                Duration::from_secs(60),
                None,
            ),
        )
        .await
        .expect(
            "the read must be bounded by git_timeout, not by the batch budget: a wedged git \
             cannot hold the pin permit for the whole 60s budget",
        );
        let elapsed = started.elapsed();

        assert!(
            pinned.is_empty(),
            "a git that never answers cannot produce a pinned object: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "elapsed {elapsed:?} must stay in the git_timeout order (1s plus one watchdog \
             teardown), not the 60s batch budget"
        );
    }

    /// A `git_bin` wrapper that records every invocation's arguments and then execs the
    /// real git, so a test can tell which objects the loop actually attempted. The returned
    /// pin list cannot: it is empty both when the loop broke after one object and when it
    /// continued past all of them. Copied from `ipfs_pin.rs`'s test mod, like the fixtures
    /// above, since test mods are private.
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
    /// Counts `--batch-check` invocations, not log lines and not oid occurrences: the type
    /// probe carries its oid on stdin rather than in argv, so an oid appears in the log only
    /// once an object has already got past its probe, and a healthy object costs two
    /// invocations to a faulting one's one.
    fn objects_attempted(log: &std::path::Path) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("--batch-check"))
            .count()
    }

    /// The store-wide fault arm, the twin of the IPFS loop's. When the object store cannot
    /// be read at all every remaining object fails identically, so continuing would spawn
    /// one doomed bounded child per object and burn the batch budget on reaping them.
    ///
    /// The fixture looks wrong and is not: with the objects LOOSE and only `objects/pack`
    /// unreadable, git still resolves each object, but it prints an `error:` diagnostic
    /// that the probe routes to a fault before the present/missing parse, so the read
    /// reaches the fault classification and (the store being unreadable) returns
    /// `Transient`, which the store-wide re-check then confirms really is store-wide.
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
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

        let pack_dir = repo_path.join("objects").join("pack");
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&pack_dir).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&pack_dir, perms).unwrap();
        };
        chmod(0o000);
        // Root bypasses permission bits, so witness the exact operation the probe performs
        // and skip rather than falsely fail.
        let genuinely_unreadable = std::fs::read_dir(&pack_dir).is_err();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                &git_bin,
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
                None,
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
            assert_eq!(
                requests.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "no upload may be issued for an object whose bytes were never read"
            );
        }
    }

    /// The must-not direction of the arm above, the twin of the IPFS loop's. One corrupt
    /// loose object among healthy ones is a `Deterministic` fault (the store is readable,
    /// git still fails), and the documented recovery path cannot repair it: a later
    /// full-scan push re-offers the same object and would break at the same place, so
    /// breaking here stops the repo replicating permanently.
    ///
    /// Deliberately not the bad-config corruption, which is repo-wide: all five objects
    /// would fault and the test would pin the store-wide case rather than the object-scoped
    /// one this arm rests on.
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
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

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
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                &git_bin,
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
                None,
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
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "exactly the readable objects may reach the endpoint"
        );
    }

    /// The normal direction, and the dedup branch driven both ways: on a healthy
    /// store with a healthy endpoint and a generous budget every object pins and the
    /// CID is recorded, and a second call over the same list uploads nothing because
    /// `has_pinata_cid` now answers true for all of them.
    #[sqlx::test]
    async fn pin_new_objects_pins_every_object_then_skips_the_recorded_ones(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("healthy.git");
        let oids = seed_loose_blobs(&repo_path, 3);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(60),
                oids.clone(),
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
                None,
            ),
        )
        .await
        .expect("an immediate endpoint and three healthy objects cannot take 30s");

        assert_eq!(pinned.len(), 3, "every healthy object must pin: {pinned:?}");
        for (i, (sha, cid)) in pinned.iter().enumerate() {
            assert_eq!(sha, &oids[i], "the pairs must carry the objects' own oids");
            assert_eq!(cid, "QmPinataBatchTestCid");
            assert!(
                db.has_pinata_cid(sha).await.unwrap(),
                "a pinned object must be recorded so the next batch skips it"
            );
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 3);

        let again = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
                None,
            ),
        )
        .await
        .expect("a fully deduped batch cannot take 30s");
        assert!(again.is_empty(), "already-recorded objects must be skipped");
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "the skip must happen before the upload, not after it"
        );
    }

    /// The no-op configuration still short-circuits with the budgeted signature: an
    /// empty JWT must return before any git child is spawned and before any request
    /// is issued. The `git_bin` here records every invocation, so "git was never
    /// touched" is observed rather than assumed.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_with_an_empty_jwt_touches_neither_git_nor_the_endpoint(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("unconfigured.git");
        let oids = seed_loose_blobs(&repo_path, 2);
        let log = tmp.path().join("calls.log");
        let fake = tmp.path().join("counting-git");
        write_script(
            &fake,
            &format!(
                "#!/bin/sh\necho \"$*\" >> {}\nexec git \"$@\"\n",
                log.display()
            ),
        );
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "",
                &repo_path,
                fake.to_str().unwrap(),
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
                None,
            ),
        )
        .await
        .expect("an unconfigured sink returns immediately");

        assert!(pinned.is_empty(), "an empty JWT pins nothing");
        assert!(
            !log.exists(),
            "no git child may be spawned when the sink is not configured"
        );
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // ── Stalled-DB bound (F3, #173) ───────────────────────────────────────
    //
    // `api/repos.rs` acquires the GLOBAL `pin_semaphore` for the Pinata
    // replication task and holds it across this whole function, the same permit
    // the IPFS lane takes. `batch_budget_gate` only gates BETWEEN objects and the
    // git read is already clamped, so a bare DB await in the region parked that
    // permit for as long as the query was stuck. The tests below drive the stall
    // with a `LOCK TABLE .. IN ACCESS EXCLUSIVE MODE` held on a dedicated pooled
    // connection, the same technique the ipfs_pin twin's stall tests use, and copy
    // their tolerances (a 1.5s budget, an `elapsed < 3s` assertion, a 10s outer
    // wrap). The budget is above `PIN_READ_FLOOR` on purpose: below it
    // `batch_budget_gate` breaks the batch as the loop body's FIRST statement, so a
    // ~1s budget would never reach a DB call and the test would pass with the bound
    // deleted.
    // ---------------------------------------------------------------------

    /// Take an `ACCESS EXCLUSIVE` lock on `table` on a dedicated pooled connection.
    /// Every SELECT needs `ACCESS SHARE`, which conflicts, so the next statement
    /// touching the table blocks at lock acquisition regardless of row count.
    /// Copied from `ipfs_pin.rs`'s test mod rather than shared, since test mods are
    /// private, the same way `seed_loose_blobs` and `capture_logs` are.
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

    /// Scenario 3: the FIRST DB call in this lane's budgeted region
    /// (`has_pinata_cid`) stalls. With the batch deadline bounding it the loop
    /// abandons the object, the budget gate then breaks the batch, and the call
    /// returns at ~budget having uploaded nothing. Pre-fix the bare await blocks for
    /// the lock's whole lifetime, holding the caller's global pin permit with it.
    ///
    /// The upload mock is at `.expect(0)`: a stalled pinned-status check must never
    /// fall through to an upload, since that would re-send bytes Pinata may already
    /// hold and, worse, return a CID this node then advertises.
    #[sqlx::test]
    async fn pinata_pin_new_objects_stalled_db_returns_by_budget(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("pinata_stalled.git");
        let oids = seed_loose_blobs(&repo_path, 1);

        let mut server = mockito::Server::new_async().await;
        let upload = server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"data":{"cid":"QmShouldNotHappen"}}"#)
            .expect(0)
            .create_async()
            .await;

        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut lock = lock_table(&pool, "pinned_cids").await;

        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(10),
            pin_new_objects(
                &client,
                &server.url(),
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-pinata-stalled",
                Duration::from_millis(1500),
                None,
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
            "a stalled pinata-status check cannot produce a pinned object: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "the batch deadline must end the call at ~budget (1.5s); got {elapsed:?}"
        );
        upload.assert_async().await;

        rollback(&mut lock).await;
    }

    /// The Pinata half of the timed-out source record, driven rather than argued: the
    /// twin's `pin_new_objects_skip_branch_stalled_record_returns_by_budget` covers the
    /// Kubo lane and this covers the site that has to change in lockstep with it.
    ///
    /// The object already has a `pinata_cid`, so the loop takes the skip branch and
    /// tries to record this repo as an additional source; `pin_repo_sources` is locked
    /// for the whole run, so that insert stalls inside `retry_db_record` and the whole
    /// ladder elapses against one floored remainder. Two properties:
    ///
    /// - the call still returns promptly, at the record floor rather than the lock's
    ///   lifetime;
    /// - on the TIMEOUT arm the incomplete marker IS written. `record_pin_source` is an
    ///   explicit transaction, so the cancelled future never reaches `tx.commit()`, no
    ///   COMMIT is ever sent, and the source definitely did not land. Withholding the
    ///   marker there would leave the set incomplete AND unmarked, which the resolver
    ///   reads as complete and 404s a copy this repo would serve.
    ///
    /// `pinned_cids` is deliberately NOT locked, so the marker write itself is free to
    /// land and the assertion below is about the branch, not about lock contention.
    #[sqlx::test]
    async fn pinata_skip_branch_stalled_record_marks_incomplete(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("pinata_skip_stalled.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();
        // Seed the object as already Pinata-pinned, by a DIFFERENT repo, so the skip
        // branch is taken and the source record below is a genuine additional-source
        // insert rather than a no-op on the conflict. The resolver key is a canonical
        // raw CIDv1 so the opportunistic legacy repair takes its cost gate and reads no
        // bytes.
        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"pinata skip seed").to_string();
        db.record_pinata_cid(
            &sha,
            &raw_cid,
            "QmSeedProviderCid",
            Some("repo-seed"),
            i64::MAX,
        )
        .await
        .unwrap();
        db.record_pin_source(&sha, "repo-seed").await.unwrap();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint = delaying_pinata_endpoint(
            vec![Duration::from_millis(0)],
            std::sync::Arc::clone(&requests),
        )
        .await;
        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut lock = lock_table(&pool, "pin_repo_sources").await;

        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(15),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-pinata-skip-stalled",
                Duration::from_millis(1500),
                None,
            ),
        )
        .await
        .expect(
            "the wrapped retry ladder must fit inside one floored remainder: the bare \
             retry_db_record hangs past this wrap",
        );
        let elapsed = started.elapsed();

        assert!(
            pinned.is_empty(),
            "an already-pinned object is skipped, never re-uploaded: {pinned:?}"
        );
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the skip branch must not reach the upload at all"
        );
        assert!(
            elapsed < Duration::from_secs(5),
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

    /// Scenario 8, the Pinata half of the durability floor. `batch_budget_gate` only
    /// guarantees `PIN_READ_FLOOR` before an object STARTS and the upload runs under
    /// the shared client's own ceiling, so a successful upload can return with ~0 of
    /// the batch budget left. Without the floor the post-upload `record_pinata_cid`
    /// would then be failed by a spent deadline, and this lane's `pinned.push` is
    /// UNCONDITIONAL: `api/repos.rs` builds `cid_map` from the return and drives
    /// `upsert_branch_cid` plus the p2p `publish_ref_update` gossip from it, so a
    /// dropped record makes the node advertise a CID whose `/ipfs` read 404s.
    ///
    /// Fixture: a 2s budget, a 1.7s upload, and `pinned_cids` locked from 500ms (well
    /// after `has_pinata_cid` has read it, and still well before the upload returns)
    /// until 2.4s. The record therefore starts at ~1.72s with ~280ms of budget left
    /// and needs ~680ms of lock wait to land, which only the `DB_RECORD_GRACE` floor
    /// buys it.
    ///
    /// The lock time is a MARGIN, not a boundary: taking it at 100ms left
    /// `has_pinata_cid` racing it on a loaded box, and losing that race makes the read
    /// block, time out, and break the batch, which fails on `pinned.len() == 1` for a
    /// reason that has nothing to do with the floor. Any time between the
    /// `has_pinata_cid` round trip and the upload's 1.7s return proves the same thing.
    #[sqlx::test]
    async fn pinata_pin_add_with_spent_budget_still_records_cid(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("pinata_spent_budget.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint = delaying_pinata_endpoint(
            vec![Duration::from_millis(1700)],
            std::sync::Arc::clone(&requests),
        )
        .await;
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

        let client = reqwest::Client::new();
        let pin = tokio::time::timeout(
            Duration::from_secs(20),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids.clone(),
                &db,
                "repo-pinata-spent-budget",
                Duration::from_millis(2000),
                None,
            ),
        );
        let (pinned, ()) = tokio::join!(pin, locker);
        let pinned = pinned.expect("the floored record must land well inside this wrap");

        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the fixture only proves anything if the upload actually ran"
        );
        assert!(
            db.has_pinata_cid(&sha).await.unwrap(),
            "a successful upload whose batch deadline is spent must still land its \
             pinned_cids row: this lane pushes the pair unconditionally, so a dropped \
             record makes api/repos.rs advertise a CID the resolver cannot serve"
        );
        assert_eq!(
            pinned.len(),
            1,
            "the uploaded pin must still be returned: {pinned:?}"
        );
    }

    /// The POST-UPLOAD source record's timeout arm, the one site of the three that
    /// nothing else executes. The skip-branch twin above and the ipfs_pin lane cover
    /// the other two; this arm sits after a SUCCESSFUL `pin_object`, so no skip-branch
    /// fixture can reach it.
    ///
    /// Why it has to write the marker at all: `record_pin_source` is an explicit
    /// transaction ending in `tx.commit()`, and a cancelled future never gets there, so
    /// no COMMIT is sent and the row definitely does not exist. The set is therefore
    /// incomplete, and leaving it unmarked is the state the marker exists to prevent.
    ///
    /// Fixture: the object is NOT seeded as Pinata-pinned, so `has_pinata_cid` is false
    /// and the run takes the upload path. The mock answers the upload at once, then
    /// `pin_repo_sources` is held under `ACCESS EXCLUSIVE` for the whole run, so the
    /// post-upload `record_pin_source` blocks and elapses against its floored bound at
    /// ~2s. `pinned_cids` is deliberately left UNLOCKED, so both `record_pinata_cid`
    /// and the marker write itself are free to land and the assertion is about the arm
    /// rather than about my own lock.
    ///
    /// The upload assertion is what keeps this from being vacuous: without it the test
    /// would pass just as well if the run never reached the post-upload path at all.
    #[sqlx::test]
    async fn pinata_post_upload_stalled_record_marks_incomplete(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("pinata_post_upload.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let sha = oids[0].clone();

        let mut server = mockito::Server::new_async().await;
        let upload = server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"data":{"cid":"QmPostUploadProviderCid"}}"#)
            .expect(1)
            .create_async()
            .await;

        // Install a log capture even though nothing here asserts on it: `tracing`
        // caches a callsite's interest globally the first time it is hit, and a hit
        // from a thread with no subscriber caches it as never-interested for the whole
        // binary, which silently blinds the sibling tests that DO assert on the batch
        // deadline warn.
        let (_logs, _log_guard) = capture_logs();

        let mut lock = lock_table(&pool, "pin_repo_sources").await;

        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(20),
            pin_new_objects(
                &client,
                &server.url(),
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(30),
                oids,
                &db,
                "repo-pinata-post-upload",
                Duration::from_millis(1500),
                None,
            ),
        )
        .await
        .expect(
            "the wrapped retry ladder must fit inside one floored remainder: the bare \
             retry_db_record hangs past this wrap",
        );
        let elapsed = started.elapsed();

        rollback(&mut lock).await;
        drop(lock);

        upload.assert_async().await;
        assert_eq!(
            pinned.len(),
            1,
            "the upload succeeded, so this lane still returns the pair: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(8),
            "the record's floored remainder must end the call promptly, never at the \
             lock's lifetime; got {elapsed:?}"
        );
        assert!(
            db.pin_sources_incomplete(&sha).await.unwrap(),
            "the POST-UPLOAD arm must mark the source set incomplete when its record \
             times out: `record_pin_source` is an explicit transaction whose cancelled \
             future never reaches `tx.commit()`, so the row definitely did not land, and \
             an incomplete-and-unmarked set is read as complete and 404s a copy this \
             repo would serve"
        );
    }

    #[tokio::test]
    async fn test_pin_skipped_when_jwt_empty() {
        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            "https://uploads.pinata.cloud/v3/files",
            "",
            "deadbeef",
            b"data",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "", "empty JWT must return empty CID");
    }

    #[tokio::test]
    async fn test_pin_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","name":"git-deadbeef.bin","size":20}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "test-jwt",
            "deadbeef00000000",
            b"raw git object bytes",
        )
        .await;

        assert!(result.is_ok(), "pin should succeed: {result:?}");
        assert_eq!(
            result.unwrap(),
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        );
        _mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_pin_auth_failure_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(401)
            .with_body(r#"{"error":"UNAUTHORIZED"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "bad-jwt",
            "deadbeef00000000",
            b"data",
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[tokio::test]
    async fn test_pin_server_error_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(&client, &server.url(), "jwt", "deadbeef00000000", b"data").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    #[tokio::test]
    async fn test_pin_missing_cid_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"name":"git-deadbeef.bin"}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(&client, &server.url(), "jwt", "deadbeef00000000", b"data").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no 'data.cid'"));
    }

    #[tokio::test]
    async fn test_pin_uses_bearer_auth() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer my-pinata-jwt")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"cid":"QmTest","name":"git-deadbeef.bin","size":4}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "my-pinata-jwt",
            "deadbeef00000000",
            b"data",
        )
        .await;

        assert!(result.is_ok());
        _mock.assert_async().await;
    }
}
