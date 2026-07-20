//! GET /ipfs/{cid} — content-addressed retrieval of git objects by CIDv1.
//!
//! Every git object stored on this node is addressable by its IPFS CIDv1.
//! The CID is computed as:
//!
//!   CIDv1(codec=raw, multihash=sha2-256(content_bytes))
//!
//! where `content_bytes` is the raw object content as returned by
//! `git cat-file <type> <sha256>` (i.e. without the git framing header).
//! This is consistent with how `gitlawb_core::cid::Cid::from_git_object_bytes`
//! computes CIDs when objects are pushed.
//!
//! Serving is access-controlled: an object is returned only from a repo row the
//! requesting caller is permitted to read (per-caller path-scoped visibility,
//! see `get_by_cid`).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use cid::CidGeneric;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::git::store;
use crate::git::visibility_pack::{allowed_blob_set_for_caller_bounded, has_path_scoped_rule};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

/// GET /ipfs/{cid}
///
/// Search all repos on the node for a git object whose SHA-256 hash matches
/// the given CIDv1, returning its raw content if the caller may read it.
///
/// Visibility (#110, #126): the object is served only from a repo row the
/// caller passes. For each iterated row we gate against that row's OWN rules
/// (`visibility_check` at `"/"`), never re-resolving via `authorize_repo_read`
/// — `get_repo`'s fuzzy match could otherwise authorize a different physical
/// row than the one read (KTD2a). We check object existence via
/// `store::object_type` *before* the expensive reachability walk so random-CID
/// spray cannot trigger full-history git walks on repos that don't carry the
/// object. When the row carries path-scoped rules (KTD4) the served object
/// must be either a non-blob (trees/commits are structural; KTD3) OR a blob
/// in the caller's *reachable* allowed-set (`allowed_blob_set_for_caller`).
/// The reachable allowed-set excludes dangling blobs — a blob written via
/// `git hash-object -w` and never committed has no path to gate, so it is
/// fail-closed 404'd under path-scoped rules (#126). Denial and genuine
/// not-found both fall through to an opaque 404.
///
/// Scan completeness (F2): the 404 above is returned ONLY when every candidate
/// repo reached a VERDICT — visibility deny, probe-says-absent, walk-gate deny,
/// or served. A candidate skipped WITHOUT a verdict (acquire failure/timeout,
/// probe error, walk failure/panic, content-read error, or truncation by
/// `ipfs_max_repos_walked` / `ipfs_max_repo_visits` /
/// `ipfs_request_budget_secs`) taints the scan, and a
/// tainted scan that found nothing sheds a retryable 503 + Retry-After naming
/// the truncation sources — existing content is never misreported absent
/// because of unrelated repos or transient faults.
///
/// Deterministic fault (F5/U4): a candidate repo that is persistently broken (a
/// corrupt repo, a bad `.git/config`) also yields no absence verdict, but a retry
/// cannot fix it, so a scan that found nothing sheds a TERMINAL, non-retryable 500
/// (opaque body) rather than the retryable 503 — checked first so a deterministic
/// fault is never downgraded, and gated on nothing-served so a healthy repo that
/// carries the object still serves.
///
/// Request budget (F3): one absolute clock (`ipfs_request_budget_secs`) spans
/// the whole admitted request. No stage (acquire, probe, walk, content read)
/// starts once it is exhausted, and the acquire wait and walk deadline are
/// clamped to the remainder. The probe and content-read subprocesses have no
/// duration bound of their own past their pre-start budget check, so a hung
/// git probe holds the request's walk slot for the full duration of the hang.
///
/// Scope: this closes the direct unauthenticated scan, including the dangling
/// case. A stale-public mirror row still serves withheld content (tracked
/// separately, #124).
pub async fn get_by_cid(
    Path(cid_str): Path<String>,
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    // Per-source keying for the walk concurrency sub-cap. Infallible extractors
    // (mirror the git handlers in `repos.rs`): `PeerAddr` yields `None` under
    // `oneshot` with no `ConnectInfo`, and the header map falls back per `client_key`.
    crate::rate_limit::PeerAddr(peer): crate::rate_limit::PeerAddr,
    req_headers: HeaderMap,
) -> Result<Response> {
    // 1. Decode the CID and extract the SHA-256 digest
    let cid = CidGeneric::<64>::from_str(&cid_str)
        .map_err(|e| AppError::BadRequest(format!("invalid CID: {e}")))?;

    let mh = cid.hash();
    // multihash code 0x12 = sha2-256
    const SHA2_256_CODE: u64 = 0x12;
    if mh.code() != SHA2_256_CODE {
        return Err(AppError::BadRequest(
            "only sha2-256 CIDs are supported".to_string(),
        ));
    }

    let sha256_hex = hex::encode(mh.digest());
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let caller_owned = caller.map(|c| c.to_string());

    // One absolute budget bounds this request's whole acquire+walk lifetime (F3),
    // captured before admission so the clock covers everything the walk permit
    // holds. Each stage below (acquire, probe, walk, read) starts only while
    // budget remains, and the acquire wait + walk deadline run clamped to the
    // remainder, so an admitted request cannot hold its scarce walk slot for
    // hours by drawing a fresh per-stage timeout every iteration. The budget
    // NEVER aborts a running spawn_blocking walk: the clamped git deadline
    // inside the walk is what ends it (a tokio timeout around the walk future
    // would free the walk permit while the blocking thread still runs, the
    // exact hole the held permit closes).
    let request_deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(state.config.ipfs_request_budget_secs);

    // Bounded walk admission (#174 P1-3), taken before any DB/git work so a flood sheds
    // cheaply. The per-repo `spawn_blocking` walk below is a full-history git walk with
    // no served-git admission of its own; a permissionless caller could otherwise fan
    // out concurrent walks past every git pool, exhausting the blocking pool + PIDs.
    // Acquire the global permit (and, for a resolvable source, the per-source
    // sub-permit) ONCE here and hold BOTH for the whole request — across every
    // `spawn_blocking` walk in the loop below — so the slot reflects real blocking-thread
    // occupancy (a tokio walk-timeout cannot free it while the blocking work still runs)
    // and one request cannot open more than its share of concurrent walks. On
    // unavailability shed a clean 503. The per-source key is the resolved source IP
    // (`client_key`), never the DID (`/ipfs` admits any `did:key` unthrottled, so a DID
    // key would be free to mint around); a `None` key (no trusted header, no peer) is
    // bounded by the global pool only, never the per-source sub-cap.
    let _ipfs_walk_permit = state
        .git_ipfs_walk_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            tracing::warn!("/ipfs walk concurrency cap reached; shedding request with 503");
            AppError::Overloaded("ipfs service at capacity, retry shortly".into())
        })?;
    let source_key = crate::rate_limit::client_key(&req_headers, peer, state.push_limiter_trust);
    let _ipfs_caller_permit = match &source_key {
        Some(ip) => Some(state.git_ipfs_walk_per_caller.try_acquire(ip).ok_or_else(|| {
            tracing::warn!(key = %ip, "/ipfs per-source walk cap reached; shedding request with 503");
            AppError::Overloaded("ipfs service at capacity for this source, retry shortly".into())
        })?),
        None => None,
    };

    // 2. Search all repos for an object with this SHA-256
    let repos = state
        .db
        .list_all_repos()
        .await
        .map_err(AppError::Internal)?;

    // Fetch every repo's visibility rules in one query rather than one per row
    // (the gate runs each row against its OWN rules — KTD2a). A row absent from
    // the map has no rules.
    let repo_ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
    let rules_by_repo = state
        .db
        .list_visibility_rules_for_repos(&repo_ids)
        .await
        .map_err(AppError::Internal)?;

    // Request-scoped memo of the per-repo allowed-blob set (KTD1, #126). The
    // caller is constant for one request, so `repo.id` alone is a safe,
    // sufficient key — never a coarse caller "class", which
    // `visibility_check`'s exact full-DID reader match would make unsafe.
    //
    // We flipped from a deny-set (`withheld_blob_oids`) to an allowed-set
    // (`allowed_blob_set_for_caller`) so dangling blobs — never enumerated by
    // the reachable walk — fail closed instead of slipping through an empty
    // deny entry (#126).
    let mut allowed_memo: HashMap<String, HashSet<String>> = HashMap::new();

    // Verdict-or-taint bookkeeping (F2): a candidate repo the loop cannot bring to a
    // VERDICT (visibility deny / probe-says-absent / walk-gate deny / served) marks
    // the scan truncated with its source. A truncated scan that finds nothing must
    // NOT report 404 — the object may sit in a repo we skipped — so the terminal arm
    // sheds a retryable 503 naming the sources, keyed so the operator can tell which
    // knob (or backend) to look at.
    let mut truncated_by: Vec<&'static str> = Vec::new();
    fn taint(truncated_by: &mut Vec<&'static str>, source: &'static str) {
        if !truncated_by.contains(&source) {
            truncated_by.push(source);
        }
    }
    // A DETERMINISTIC probe fault (a corrupt repo / bad `.git/config`; #174 F5/U4) is
    // separate from a transient taint: a retry cannot fix it, so a scan that found
    // nothing must NOT shed the retryable 503 (which would invite a conformant client
    // to retry-storm a fresh `git cat-file` per attempt against the broken repo). It
    // sheds a terminal, non-retryable 500 instead — but only if nothing served, so one
    // corrupt repo never masks a healthy repo that carries the object.
    let mut deterministic_fault = false;

    // Budget gate shared by the four per-stage checks (F3): the remaining
    // request budget, or — once exhausted — None, after logging the stage and
    // knob and tainting "budget"; the call site only breaks (the scan STOPS,
    // leaving this and every later candidate unproven, never a false 404). A
    // stage is never started with zero remaining; the probe and read
    // subprocesses carry no internal duration clamp, so this pre-start check is
    // their entire bound (a hung one holds the request's walk slot for the
    // duration of the hang). The acquire and walk stages clamp their deadlines
    // to the returned remainder.
    fn budget_gate(
        truncated_by: &mut Vec<&'static str>,
        deadline: std::time::Instant,
        budget_secs: u64,
        repo_name: &str,
        stage: &'static str,
    ) -> Option<std::time::Duration> {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            tracing::warn!(
                repo = %repo_name,
                stage,
                budget_secs,
                "/ipfs request budget exhausted before the stage \
                 (GITLAWB_IPFS_REQUEST_BUDGET_SECS); stopping the scan without a verdict"
            );
            taint(truncated_by, "budget");
            return None;
        }
        Some(left)
    }

    // Cap on EXPENSIVE walks only (F2): counts the repos that actually require the
    // full-history `allowed_blob_set_for_caller_bounded` walk (a path-scoped blob),
    // checked immediately before the spawn_blocking below. Cheap probe-only visits
    // are bounded by `repos_visited` — counting them here starved later-ordered
    // repos out of a plain 200 on nodes with more readable repos than the cap.
    let mut repos_walked: usize = 0;
    // Ceiling on VISITS (F2): every repo past the visibility gate costs an acquire
    // (worst case a full Tigris archive download on a cache miss) plus a cat-file
    // probe, so one request can trigger at most `ipfs_max_repo_visits` object-store
    // fetches. On exhaustion the scan STOPS — there is no cheaper way to continue.
    let mut repos_visited: usize = 0;

    for repo in &repos {
        // Repo-level read gate against THIS row's own rules (KTD2a). Deny is a
        // VERDICT: this repo would never serve the caller, so skipping it cannot
        // hide content from them.
        let rules: &[crate::db::VisibilityRule] = rules_by_repo
            .get(&repo.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if visibility_check(rules, repo.is_public, &repo.owner_did, caller, "/") == Decision::Deny {
            continue;
        }

        // Budget gate for the acquire stage (F3), checked ahead of the visit
        // bookkeeping so an unstarted acquire is not counted as a visit.
        let Some(budget_left) = budget_gate(
            &mut truncated_by,
            request_deadline,
            state.config.ipfs_request_budget_secs,
            &repo.name,
            "repo acquire",
        ) else {
            break;
        };

        // Visit ceiling (F2): bound the acquire+probe cost class. Stopping here
        // leaves the remaining candidates unproven, so the scan is truncated.
        if repos_visited >= state.config.ipfs_max_repo_visits {
            tracing::warn!(
                ceiling = state.config.ipfs_max_repo_visits,
                "/ipfs request hit the per-request repo-visit ceiling \
                 (GITLAWB_IPFS_MAX_REPO_VISITS); stopping the scan without a verdict"
            );
            taint(&mut truncated_by, "visit-ceiling");
            break;
        }
        repos_visited += 1;

        // Bound the per-repo acquire under `git_acquire_timeout_secs`: this loop shares
        // the P1-2 stall vector (a hung Tigris HEAD/GET on one repo would otherwise
        // block the whole /ipfs request). On expiry keep the fail-closed skip — never
        // serve an un-acquired repo; a public copy (if any) still gets its turn — but
        // the repo got no verdict, so the skip taints the scan. Clamped to the
        // remaining request budget (F3) so per-repo acquires cannot each draw a
        // fresh full timeout past it.
        let acquire_deadline = std::cmp::min(
            std::time::Duration::from_secs(state.config.git_acquire_timeout_secs),
            budget_left,
        );
        let repo_path = match tokio::time::timeout(
            acquire_deadline,
            state.repo_store.acquire(&repo.owner_did, &repo.name),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo.name, err = %e, "repo acquire failed during /ipfs scan; skipping repo without a verdict");
                taint(&mut truncated_by, "acquire");
                continue;
            }
            Err(_elapsed) => {
                tracing::warn!(repo = %repo.name, "repo acquire timed out during /ipfs scan; skipping repo without a verdict");
                taint(&mut truncated_by, "acquire");
                continue;
            }
        };

        // Budget gate for the probe stage (F3): a probe is never STARTED with zero
        // remaining, and a started probe now runs its git child under a deadline
        // clamped to the remainder (below), so it can never complete past the budget.
        let Some(probe_budget) = budget_gate(
            &mut truncated_by,
            request_deadline,
            state.config.ipfs_request_budget_secs,
            &repo.name,
            "object-type probe",
        ) else {
            break;
        };

        // Check whether the object exists in this repo before any expensive
        // reachability walk. This prevents random-CID spray from triggering
        // full-history git walks on repos that don't carry the object. Absent
        // (`Ok(None)`) is a VERDICT; a probe that could not run is not. The
        // `git cat-file -t` shells out, so run it OFF the async worker under the
        // reaped bounded runner (#174 F3) — a hung/corrupt object store cannot pin a
        // runtime worker or the held IPFS permits past the deadline.
        let probe_deadline = std::time::Instant::now()
            + std::cmp::min(
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                probe_budget,
            );
        // The probe shells to the real `git` (as `object_type` historically did),
        // independent of `state.git_bin` (which tests point at a fake walk git).
        let probe_path = repo_path.clone();
        let probe_sha = sha256_hex.clone();
        let obj_type = match tokio::task::spawn_blocking(move || {
            store::object_type_bounded("git", &probe_path, &probe_sha, probe_deadline)
        })
        .await
        {
            Ok(Ok(Some(t))) => t,
            Ok(Ok(None)) => continue,
            // Transient probe fault (unreadable/mid-repack store): unproven, retryable.
            Ok(Err(store::ProbeError::Transient(e))) => {
                tracing::warn!(repo = %repo.name, err = %e, "object-type probe hit a transient store fault during /ipfs scan; skipping repo without a verdict");
                taint(&mut truncated_by, "probe");
                continue;
            }
            // Deterministic probe fault (corrupt repo / bad config): a retry cannot fix
            // it, so it does NOT taint (which would shed a retryable 503). It records a
            // terminal condition that the terminal arm renders as a non-retryable 500
            // only if nothing served. The raw git detail stays in the log; the client
            // body is opaque.
            Ok(Err(store::ProbeError::Deterministic(e))) => {
                tracing::warn!(repo = %repo.name, err = %e, "object-type probe hit a deterministic fault (corrupt repo/config) during /ipfs scan; skipping repo without a verdict");
                deterministic_fault = true;
                continue;
            }
            Err(join_err) => {
                tracing::warn!(repo = %repo.name, err = %join_err, "object-type probe task panicked during /ipfs scan; skipping repo without a verdict");
                taint(&mut truncated_by, "probe");
                continue;
            }
        };

        // Per-blob gating only applies when a path-scoped rule exists (KTD4).
        // Without any path-scoped rule, the "/" gate above is the whole story.
        // Trees/commits are always served under path-scoped rules (KTD3).
        let path_scoped = has_path_scoped_rule(rules);
        if path_scoped && obj_type == "blob" {
            if !allowed_memo.contains_key(&repo.id) {
                // Budget gate for the walk stage (F3): a walk is never STARTED
                // with zero remaining (probed-present is not a serve), and a
                // started walk runs its git children under a deadline clamped
                // to the remainder (the min below), so a walk can never
                // complete past the budget.
                let Some(budget_left) = budget_gate(
                    &mut truncated_by,
                    request_deadline,
                    state.config.ipfs_request_budget_secs,
                    &repo.name,
                    "visibility walk",
                ) else {
                    break;
                };
                // Walk cap (F2), checked at the one site that actually spends a walk:
                // on exhaustion skip THIS repo without a verdict and KEEP scanning —
                // later candidates may still reach a cheap probe-only verdict (a plain
                // public copy serves its 200 with no walk at all).
                if repos_walked >= state.config.ipfs_max_repos_walked {
                    tracing::warn!(
                        cap = state.config.ipfs_max_repos_walked,
                        repo = %repo.name,
                        "/ipfs request hit the per-request walk cap \
                         (GITLAWB_IPFS_MAX_REPOS_WALKED); skipping repo without a verdict"
                    );
                    taint(&mut truncated_by, "walk-cap");
                    continue;
                }
                repos_walked += 1;
                let rp = repo_path.clone();
                let r = rules.to_vec();
                let is_public = repo.is_public;
                let owner = repo.owner_did.clone();
                let caller_for_walk = caller_owned.clone();
                let git_bin = state.git_bin.clone();
                let walk_timeout = std::cmp::min(
                    std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                    budget_left,
                );
                // Full-history walk shells out to git — keep it off the async runtime,
                // bounded and reaped like the served-git ops (#174).
                let walk = tokio::task::spawn_blocking(move || {
                    allowed_blob_set_for_caller_bounded(
                        &rp,
                        &git_bin,
                        walk_timeout,
                        &r,
                        is_public,
                        &owner,
                        caller_for_walk.as_deref(),
                    )
                })
                .await;
                // Fail closed on EITHER a task panic (JoinError) or a walk error:
                // we cannot prove the caller may read here, so skip this repo and
                // let a public copy (if any) serve. Never serve on an unproven gate
                // — and never report absent on one either (no verdict, taint).
                let set = match walk {
                    Ok(Ok(set)) => set,
                    Ok(Err(e)) => {
                        tracing::warn!(repo = %repo.name, err = %e, "allowed-blob walk failed during /ipfs scan; skipping repo without a verdict");
                        taint(&mut truncated_by, "walk-failure");
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(repo = %repo.name, err = %e, "allowed-blob walk task panicked during /ipfs scan; skipping repo without a verdict");
                        taint(&mut truncated_by, "walk-failure");
                        continue;
                    }
                };
                allowed_memo.insert(repo.id.clone(), set);
            }
            // Not in the caller's reachable allowed-set: a VERDICT (deny), the walk
            // proved this repo would never serve the blob to this caller.
            let in_allowed = allowed_memo
                .get(&repo.id)
                .is_some_and(|set| set.contains(&sha256_hex));
            if !in_allowed {
                continue;
            }
        }

        // Budget gate for the content-read stage (F3): the read subprocess is
        // unclamped, so it never starts past the budget. Tainting instead of
        // serving keeps the terminal arm honest and the stop unconditional; the
        // retryable 503 tells the caller to come back rather than letting an
        // over-budget request keep spending.
        let Some(read_budget) = budget_gate(
            &mut truncated_by,
            request_deadline,
            state.config.ipfs_request_budget_secs,
            &repo.name,
            "content read",
        ) else {
            break;
        };

        // Now that we've passed the gate, read the content. A failed read after a
        // passed gate is not an absence verdict — the probe just said the object
        // exists here — so the skip taints the scan. Like the probe, the read shells
        // out to `git cat-file <type>`, so run it OFF the async worker under the reaped
        // bounded runner clamped to the remaining budget (#174 F3).
        let read_deadline = std::time::Instant::now()
            + std::cmp::min(
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                read_budget,
            );
        // Real `git`, as the read historically used, independent of `state.git_bin`.
        let read_path = repo_path.clone();
        let read_sha = sha256_hex.clone();
        let read_type = obj_type.clone();
        let content = match tokio::task::spawn_blocking(move || {
            store::read_object_content_bounded(
                "git",
                &read_path,
                &read_sha,
                &read_type,
                read_deadline,
            )
        })
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo.name, err = %e, "object content read failed during /ipfs scan; skipping repo without a verdict");
                taint(&mut truncated_by, "read");
                continue;
            }
            Err(join_err) => {
                tracing::warn!(repo = %repo.name, err = %join_err, "object content read task panicked during /ipfs scan; skipping repo without a verdict");
                taint(&mut truncated_by, "read");
                continue;
            }
        };

        // 3. Return the content with IPFS-style headers
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            HeaderName::from_static("x-content-cid"),
            HeaderValue::from_str(&cid_str).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        );
        headers.insert(
            HeaderName::from_static("x-git-hash"),
            HeaderValue::from_str(&sha256_hex)
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        );

        return Ok((StatusCode::OK, headers, content).into_response());
    }

    // Deterministic fault (F5/U4): a candidate repo is persistently broken (corrupt
    // repo / bad `.git/config`), so the object is not proven absent AND a retry cannot
    // change that. Shed a TERMINAL, non-retryable 500 rather than the retryable 503
    // below — a 503 would let a conformant client retry-storm a fresh `git cat-file`
    // per attempt against the broken repo. This is checked before the transient 503 so
    // a deterministic fault is never downgraded to a retryable status. The body is
    // opaque (a generic message via `AppError::Git` -> 500, no Retry-After): the raw
    // git stderr — which leaks filesystem paths / config — was logged at the probe, and
    // never reaches the client.
    if deterministic_fault {
        return Err(AppError::Git(
            "ipfs object probe could not complete: a candidate repository is corrupt".into(),
        ));
    }

    // Truncated scan (F2): at least one candidate repo yielded no verdict, so the
    // object is not proven absent. A 404 here would misreport existing content, so
    // shed retryable instead — Overloaded is the single 503 + Retry-After site in
    // error.rs, and the message names the truncation sources so the operator can
    // map the shed to the right knob or backend.
    if !truncated_by.is_empty() {
        return Err(AppError::Overloaded(format!(
            "ipfs scan incomplete ({}) for CID {cid_str}; retry shortly",
            truncated_by.join("+")
        )));
    }

    // Complete scan: every candidate reached a verdict and none served, so the
    // object is definitively absent (or denied) for this caller.
    Err(AppError::RepoNotFound(format!(
        "no git object found for CID {cid_str}"
    )))
}

/// GET /api/v1/ipfs/pins
///
/// Returns all CIDs that have been pinned to the local IPFS node from git
/// objects received via push. Each entry includes the git SHA-256 hex, the
/// CIDv1 string, and the timestamp when it was pinned.
pub async fn list_pins(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let pins = state
        .db
        .list_pinned_cids()
        .await
        .map_err(AppError::Internal)?;

    Ok(Json(serde_json::json!({
        "pins": pins,
        "count": pins.len(),
    })))
}

#[cfg(test)]
mod tests {
    //! #174 P1-3 (U3): the public `GET /ipfs/{cid}` walk carries bounded CONCURRENCY
    //! admission (a global pool + per-source sub-cap) held through the `spawn_blocking`
    //! walk, plus a per-IP route rate limit. These are handler-layer proofs: mount the
    //! real handler/router, drive one request, assert the exact 503 shed, then name the
    //! mutation that turns each RED. The per-source key resolves an IP only (`Some(ip)`
    //! vs `None`), never a DID — both arms are driven so neither is vacuous.

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Method, Request, StatusCode};
    use axum::Router;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use tower::ServiceExt;

    /// A router mounting the real `get_by_cid` on `/ipfs/{cid}` with `optional_signature`,
    /// matching production wiring for the extractors (`PeerAddr` reads `ConnectInfo`).
    fn ipfs_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route(
                "/ipfs/{cid}",
                axum::routing::get(crate::api::ipfs::get_by_cid),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state)
    }

    /// A syntactically valid CIDv1(raw, sha2-256) string the handler decodes past its
    /// CID/hash-code validation, so the request reaches the walk admission (not a 400).
    fn valid_cid() -> String {
        gitlawb_core::cid::Cid::from_git_object_bytes(b"blob 5\0hello")
            .as_str()
            .to_string()
    }

    fn get_cid(cid: &str, peer: Option<SocketAddr>) -> Request<Body> {
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(format!("/ipfs/{cid}"))
            .body(Body::empty())
            .unwrap();
        if let Some(p) = peer {
            req.extensions_mut().insert(ConnectInfo(p));
        }
        req
    }

    /// Run real git, asserting success. Shared by the F2 scan-verdict tests.
    fn run_git(args: &[&str], cwd: &std::path::Path) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Seed a repo row plus a REAL sha256 bare repo at its acquired path holding one
    /// committed blob (`src/secret.txt` = `content`). Returns `(repo_id, blob_oid)`.
    /// Same recipe as `get_by_cid_walk_permit_held_through_blocking_walk`: the CID
    /// digest IS the sha256 object id under `--object-format=sha256`, so the real
    /// `cat-file` probe finds the blob.
    async fn seed_repo_with_blob(
        state: &crate::state::AppState,
        tmp: &std::path::Path,
        owner: &str,
        name: &str,
        content: &[u8],
    ) -> (String, String) {
        state
            .db
            .upsert_mirror_repo(owner, name, &format!("/unused-{name}"), None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        let bare = state
            .repo_store
            .acquire(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(&bare);
        std::fs::create_dir_all(&bare).unwrap();
        let work = tmp.join(format!("work-{owner}-{name}"));
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(work.join("src/secret.txt"), content).unwrap();
        run_git(
            &["init", "-q", "--object-format=sha256", "-b", "main"],
            &work,
        );
        run_git(&["config", "user.email", "t@t"], &work);
        run_git(&["config", "user.name", "t"], &work);
        run_git(&["add", "src/secret.txt"], &work);
        run_git(&["commit", "-q", "-m", "seed"], &work);
        run_git(
            &[
                "clone",
                "--bare",
                "-q",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            tmp,
        );
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD:src/secret.txt"])
            .current_dir(&work)
            .output()
            .expect("git rev-parse runs");
        assert!(out.status.success(), "rev-parse failed");
        let oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (rec.id, oid)
    }

    /// CIDv1(raw, sha2-256) for a sha256 object id, as the handler resolves it.
    fn cid_for_oid(oid: &str) -> String {
        let oid_bytes = gitlawb_core::cid::sha256_hex_to_bytes(oid).unwrap();
        gitlawb_core::cid::Cid::from_sha256_bytes(&oid_bytes)
            .as_str()
            .to_string()
    }

    /// A local endpoint whose TCP accept succeeds instantly but that never writes
    /// an HTTP response, so a Tigris HEAD against it stalls deterministically
    /// until the caller's timeout. (A non-routable address hangs only if the
    /// network blackholes the SYN — a fast RST would end the stall early.) The
    /// accepted sockets are parked in the spawned task, which dies with the
    /// test's runtime, so the peer never sees a close mid-test.
    async fn silent_tigris_endpoint() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        endpoint
    }

    /// Fake git for the WALK only (`state.git_bin`): empty refs, `rev-parse`
    /// resolves, and each `rev-list` appends one line to `log` and prints nothing —
    /// every walked repo yields an EMPTY allowed-set (path-gate deny verdict) and
    /// the log's line count == the number of expensive walks run. The probe and the
    /// content read shell to the real `git`, so seeded objects must genuinely exist.
    #[cfg(unix)]
    fn walk_logging_fake_git(dir: &std::path::Path, log: &std::path::Path) -> String {
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               for-each-ref) : ;;\n\
               rev-parse) echo deadbeef ;;\n\
               rev-list) echo walk >> \"{}\" ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            log.display()
        );
        let git_path = dir.join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }
        git_path.to_str().unwrap().to_string()
    }

    /// F2 buried-row repro: with more readable repos than `ipfs_max_repos_walked`,
    /// existing PUBLIC content past the cap must still serve. The cap counts
    /// EXPENSIVE walks only — this request has no path-scoped rules anywhere, so it
    /// runs ZERO walks (the fake-git walk log stays empty) and the cap can never cut
    /// the scan: the blob buried in the OLDER-updated repo (iterated last under
    /// `list_all_repos`' updated_at DESC) serves its 200. Before F2 the cap counted
    /// visibility-passing VISITS and broke the loop into the opaque 404 — existing
    /// content misreported absent because of unrelated repos. MUTATION (RED): count
    /// visits against the cap again (re-add the check+increment at the visibility
    /// gate) and the buried row 503s instead of serving.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_buried_public_row_past_walk_cap_still_serves(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let walk_log = tmp.path().join("walks.log");
        state.git_bin = walk_logging_fake_git(tmp.path(), &walk_log);
        // Tighter than the repo count: the old visit-counting cap cut the scan here.
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repos_walked = 1;
        state.config = Arc::new(cfg);

        // Seed the blob-carrying repo FIRST so its updated_at is OLDER: the empty
        // repo is iterated first and the blob row sits past the old visit budget.
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f2buried",
            "buried",
            b"buried row proof\n",
        )
        .await;
        seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f2buried",
            "fresh",
            b"unrelated content\n",
        )
        .await;

        let peer: SocketAddr = "203.0.113.60:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid_for_oid(&oid), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a public blob in a repo past the walk cap must still serve — the cap \
             counts expensive walks and this scan needs none"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(&body[..], b"buried row proof\n");
        let walks = std::fs::read_to_string(&walk_log)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        assert_eq!(
            walks, 0,
            "a request with no path-scoped rules anywhere must run zero expensive walks"
        );
    }

    /// F2 walk-cap skip-and-continue: exhausting `ipfs_max_repos_walked` skips the
    /// walk-NEEDING repo without a verdict but keeps the scan alive. Three public
    /// repos carry the same blob, newest first: the first (path-scoped) consumes the
    /// cap-of-1 walk and denies (empty allowed-set — a verdict); the second
    /// (path-scoped) needs a walk the cap forbids and is skipped WITHOUT one (taint);
    /// the third is plain public and serves the 200 from a cheap probe — found beats
    /// taint, and exactly one expensive walk ran. Before F2 the cap broke the loop at
    /// the second repo and the request 404'd despite the public copy. MUTATION (RED):
    /// turn the walk-cap skip back into a `break` and the public copy never serves.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_walk_cap_skip_continues_to_later_public_copy(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let walk_log = tmp.path().join("walks.log");
        state.git_bin = walk_logging_fake_git(tmp.path(), &walk_log);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repos_walked = 1;
        state.config = Arc::new(cfg);

        // Insert order = oldest first, so iteration (updated_at DESC) is reversed:
        // gatedwalk, then gatedskip, then pubcopy. Identical content -> one CID.
        let content = b"skip and continue proof\n";
        let (_, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2skip", "pubcopy", content).await;
        let (skip_id, _) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2skip", "gatedskip", content).await;
        let (walk_id, _) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2skip", "gatedwalk", content).await;
        for id in [&walk_id, &skip_id] {
            state
                .db
                .set_visibility_rule(
                    id,
                    "src/**",
                    crate::db::VisibilityMode::B,
                    &["did:key:z6MkU3IpfsReaderCCCCCCCCCCCCCCCCCCCCCCCC".to_string()],
                    "z6f2skip",
                )
                .await
                .unwrap();
        }

        let peer: SocketAddr = "203.0.113.61:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid_for_oid(&oid), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the walk-cap skip must continue the scan so the plain public copy serves"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(&body[..], content.as_slice());
        let walks = std::fs::read_to_string(&walk_log)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        assert_eq!(
            walks, 1,
            "cap honored exactly: the first path-scoped repo walks, the second is cut"
        );
    }

    /// F2 visit ceiling: `ipfs_max_repo_visits` bounds the acquire+probe cost class
    /// (each visit can be a full Tigris archive fetch on a cache miss). Unlike the
    /// walk cap there is no cheap way to keep scanning, so exhaustion STOPS the scan
    /// — and the stop is a truncation, not an absence: with ceiling 1 the newer
    /// empty repo consumes the only visit and the blob-carrying older repo is never
    /// probed, so the request sheds a retryable 503 + Retry-After, never a false
    /// 404. MUTATION (RED): drop the ceiling check and the blob serves (200); drop
    /// only the taint on the break and the 503 decays to a 404.
    #[sqlx::test]
    async fn get_by_cid_visit_ceiling_stops_scan_with_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repo_visits = 1;
        state.config = Arc::new(cfg);

        // Blob repo first (older, iterated second); empty repo second (newer,
        // consumes the single visit).
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f2visit",
            "buried",
            b"visit ceiling proof\n",
        )
        .await;
        seed_repo_with_blob(&state, tmp.path(), "z6f2visit", "fresh", b"unrelated\n").await;

        let peer: SocketAddr = "203.0.113.62:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid_for_oid(&oid), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a visit-ceiling truncation must shed a retryable 503, not report absent"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );
    }

    /// F2 negative arm: a COMPLETE scan that finds nothing keeps its definitive 404
    /// — the truncation 503 must never fire when every candidate reached a verdict.
    /// Two public repos both probe clean (the requested CID is nowhere), no rules,
    /// no cap or ceiling hit: 404 with no Retry-After. MUTATION (RED): taint the
    /// scan unconditionally and this decays into a 503.
    #[sqlx::test]
    async fn get_by_cid_complete_scan_keeps_definitive_404(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        seed_repo_with_blob(&state, tmp.path(), "z6f2clean", "one", b"content one\n").await;
        seed_repo_with_blob(&state, tmp.path(), "z6f2clean", "two", b"content two\n").await;

        // valid_cid() is the "hello" blob — present in neither repo.
        let peer: SocketAddr = "203.0.113.63:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a complete clean scan is a definitive absence — 404, never the 503 shed"
        );
        assert!(
            resp.headers().get("retry-after").is_none(),
            "a definitive 404 must not advertise a retry"
        );
    }

    /// F2 acquire taint: a repo row with NO local copy over a Tigris backend that
    /// stalls (a silent local endpoint — accepted, never answered) hits the 1s
    /// acquire timeout at the read-acquire site. The skip carries no verdict, so the
    /// scan is truncated: retryable 503 + Retry-After, never the old silent-skip 404.
    /// MUTATION (RED): drop the taint on the acquire-timeout arm and this decays to
    /// a 404.
    #[sqlx::test]
    async fn get_by_cid_acquire_timeout_taints_scan_to_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        // Endpoint-pinned test client (no AWS_* env reads — env is racy under a
        // parallel test run); the silent local endpoint stalls the HEAD
        // deterministically.
        let endpoint = silent_tigris_endpoint().await;
        let tigris =
            crate::git::tigris::TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint)
                .await;
        state.repo_store = crate::git::repo_store::RepoStore::new(repos_dir, Some(tigris), pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let mut cfg = (*state.config).clone();
        cfg.git_acquire_timeout_secs = 1;
        state.config = Arc::new(cfg);

        // Row exists in the DB but has no local copy, so the read acquire must
        // consult Tigris (local-miss path) and stall until the timeout.
        state
            .db
            .upsert_mirror_repo("z6f2acq", "ghost", "/unused-ghost", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.64:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an acquire timeout leaves the repo unproven — the scan must shed 503, not 404"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );
    }

    /// F2 found-beats-taint on the acquire arm: an acquire timeout taints the
    /// scan but must NOT stop it — the loop `continue`s, and a later repo that
    /// genuinely carries the object still serves. The NEWER row (visited first
    /// under `list_all_repos`' updated_at DESC) is a Tigris-backed ghost whose
    /// acquire stalls against the silent endpoint and times out at 1s; the
    /// OLDER row is a plain public repo carrying the blob, reached next and
    /// served from a cheap probe — found beats taint: 200 with the blob bytes,
    /// never the truncation 503. MUTATION (RED): turn the acquire-timeout arm's
    /// `continue` into a `break` and the public copy never serves (503).
    #[sqlx::test]
    async fn get_by_cid_acquire_taint_does_not_block_later_public_copy(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Seed the blob repo through a LOCAL-ONLY store first, so seeding never
        // consults the (deliberately unreachable) Tigris endpoint.
        state.repo_store =
            crate::git::repo_store::RepoStore::for_testing(repos_dir.clone(), pool.clone());
        let content = b"acquire taint continue proof\n";
        let (_, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2acqcont", "pubcopy", content).await;
        // Swap in a Tigris-backed store over the SAME repos_dir (the seeded bare
        // repo stays a fast local hit) and add a NEWER ghost row with no local
        // copy: its acquire consults the silent local endpoint and stalls to the
        // 1s timeout (endpoint-pinned test client, no AWS_* env reads).
        let endpoint = silent_tigris_endpoint().await;
        let tigris =
            crate::git::tigris::TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint)
                .await;
        state.repo_store = crate::git::repo_store::RepoStore::new(repos_dir, Some(tigris), pool);
        state
            .db
            .upsert_mirror_repo("z6f2acqcont", "ghost", "/unused-ghost", None, false)
            .await
            .unwrap();
        let mut cfg = (*state.config).clone();
        cfg.git_acquire_timeout_secs = 1;
        state.config = Arc::new(cfg);

        // Ordering precondition: the ghost must be iterated FIRST (updated_at
        // DESC — it was upserted after the blob repo), otherwise the pubcopy
        // would serve before the taint ever fires and the continue-vs-break
        // distinction would go untested.
        let order: Vec<String> = state
            .db
            .list_all_repos()
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        let ghost_pos = order.iter().position(|n| n == "ghost").unwrap();
        let pub_pos = order.iter().position(|n| n == "pubcopy").unwrap();
        assert!(
            ghost_pos < pub_pos,
            "precondition: the stalling ghost must be iterated before the blob repo; got {order:?}"
        );

        let peer: SocketAddr = "203.0.113.73:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid_for_oid(&oid), Some(peer)))
            .await
            .unwrap();
        // The taint arm demonstrably FIRED on this run: the response can only
        // arrive after the ghost's stalled acquire burned its full 1s timeout
        // (a cheap skip or a deny verdict would answer near-instantly).
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(900),
            "the ghost's acquire must stall to its timeout before the scan continues; \
             got {:?}",
            started.elapsed()
        );
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an acquire taint must not stop the scan — the later public copy serves"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            content.as_slice(),
            "the served body must be the blob content from the later public copy"
        );
    }

    /// F2 probe taint: a repo row whose local dir does not exist (no Tigris) —
    /// `RepoStore::acquire` returns the path anyway (local passthrough), and the
    /// `cat-file -t` probe cannot even spawn (missing working dir), so
    /// `object_type` is Err. That is not an absence verdict, so the scan is
    /// truncated: 503, never 404. A second, real repo probes clean (absent verdict)
    /// — the one bad row is what taints. NOTE: the probe shells to the real `git`
    /// (not `state.git_bin`), and a clean missing/invalid-object nonzero exit is
    /// still `Ok(None)` (an absent verdict) — this arm needs a probe that could
    /// not RUN, hence the missing-dir spawn failure here; the corrupt-repo test
    /// below drives the stderr-discriminated Err. MUTATION (RED): drop the
    /// taint on the probe-error arm and this decays to a 404.
    #[sqlx::test]
    async fn get_by_cid_probe_error_taints_scan_to_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        // Older row: a real repo that probes clean. Newer row: no dir on disk.
        seed_repo_with_blob(&state, tmp.path(), "z6f2probe", "real", b"probe clean\n").await;
        state
            .db
            .upsert_mirror_repo("z6f2probe", "ghost", "/unused-ghost", None, false)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.65:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a failed probe leaves the repo unproven — the scan must shed 503, not 404"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );
    }

    /// F2 probe taint, corrupt-repo arm: a repo whose git dir EXISTS but is broken
    /// (objects/ removed, HEAD garbage) makes the real `cat-file -t` die with the
    /// repo-level `fatal: not a git repository` — a probe that could not examine
    /// the object store, not an absence verdict, so `object_type` must map it to
    /// Err and the scan must shed the probe-tainted 503, never the silent-absence
    /// 404. A second, real repo probes clean (absent verdict) — the corrupt row is
    /// what taints. MUTATION (RED): map every nonzero cat-file exit back to
    /// `Ok(None)` in `object_type` (drop the stderr discrimination) and this
    /// decays to a 404.
    #[sqlx::test]
    async fn get_by_cid_corrupt_repo_dir_probe_error_taints_scan_to_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        // Older row: a real repo that probes clean. Newer row: a bare repo whose
        // git dir exists on disk but is corrupt at the repo level.
        seed_repo_with_blob(&state, tmp.path(), "z6f2corrupt", "real", b"probe clean\n").await;
        state
            .db
            .upsert_mirror_repo("z6f2corrupt", "broken", "/unused-broken", None, false)
            .await
            .unwrap();
        let rec = state
            .db
            .get_repo("z6f2corrupt", "broken")
            .await
            .unwrap()
            .unwrap();
        let bare = state
            .repo_store
            .acquire(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        std::fs::create_dir_all(&bare).unwrap();
        run_git(&["init", "-q", "--bare", "--object-format=sha256"], &bare);
        std::fs::remove_dir_all(bare.join("objects")).unwrap();
        std::fs::write(bare.join("HEAD"), b"junk\n").unwrap();

        let peer: SocketAddr = "203.0.113.68:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a repo-level cat-file fatal leaves the repo unproven — the scan must \
             shed 503, not report the object absent"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("probe"),
            "the shed must name the probe taint; got: {body}"
        );
    }

    /// #174 F5/U4 (RED-before/GREEN-after): a candidate repo with a corrupt
    /// `.git/config` makes `git cat-file` die with `fatal: bad config line N` while
    /// `objects/` stays readable. That is a DETERMINISTIC fault, not an absence, and a
    /// retry cannot fix it — so the scan must shed a TERMINAL, non-retryable 500, never
    /// the old false 404 (`Ok(None)` fell through) and never the retryable 503 (which
    /// would invite a conformant client to retry-storm a fresh `cat-file` per attempt).
    /// A second, healthy repo probes clean (absent verdict); the corrupt row is what
    /// forces the 500. The body must be OPAQUE — no raw git stderr, no filesystem path.
    /// MUTATION (RED): route the deterministic fault back to `Ok(None)` in
    /// `object_type_bounded` and this decays to a 404; classify it Transient and it
    /// decays to a retryable 503.
    #[sqlx::test]
    async fn get_by_cid_bad_config_repo_is_terminal_500_not_404_or_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        // A healthy repo that probes clean (would give a definitive 404 on its own) plus
        // a repo whose bare git dir has a corrupt config (objects/ intact).
        seed_repo_with_blob(&state, tmp.path(), "z6f5clean", "real", b"probe clean\n").await;
        state
            .db
            .upsert_mirror_repo("z6f5badcfg", "broken", "/unused-badcfg", None, false)
            .await
            .unwrap();
        let rec = state
            .db
            .get_repo("z6f5badcfg", "broken")
            .await
            .unwrap()
            .unwrap();
        let bare = state
            .repo_store
            .acquire(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        std::fs::create_dir_all(&bare).unwrap();
        run_git(&["init", "-q", "--bare", "--object-format=sha256"], &bare);
        // Corrupt the config; leave objects/ readable (the readable-store + git-fails
        // combination is exactly what makes this deterministic, not transient).
        {
            use std::io::Write;
            let mut cfg = std::fs::OpenOptions::new()
                .append(true)
                .open(bare.join("config"))
                .unwrap();
            cfg.write_all(b"\n[broken section\nnot a valid = = = line\n")
                .unwrap();
        }

        let peer: SocketAddr = "203.0.113.69:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a bad-config (deterministic) repo fault must shed a terminal 500, never a \
             404 (false absence) or a retryable 503"
        );
        assert!(
            resp.headers().get("retry-after").is_none(),
            "a terminal 500 must NOT advertise a retry (that is the whole point vs 503)"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            !body.contains("bad config")
                && !body.contains(tmp.path().to_str().unwrap())
                && !body.contains(".git")
                && !body.contains("fatal"),
            "the 500 body must be opaque — no raw git stderr / config text / filesystem \
             path; got: {body}"
        );
    }

    /// F2 read taint: the gate passes (the probe reads the truncated loose object's
    /// intact "blob 64" header) but the content read fails (`cat-file blob` dies on
    /// the deflate stream cut mid-content) — the probe just said the object EXISTS
    /// here, so the failed read is no absence verdict: 503, never 404. The loose
    /// object is hand-rolled: zlib header + one stored deflate block declaring 72
    /// bytes ("blob 64\0" + 64), truncated after the header NUL + 4 content bytes,
    /// no adler trailer. MUTATION (RED): drop the taint on the read-error arm and
    /// this decays to a 404.
    #[sqlx::test]
    async fn get_by_cid_read_error_taints_scan_to_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        state
            .db
            .upsert_mirror_repo("z6f2read", "corrupt", "/unused-corrupt", None, false)
            .await
            .unwrap();
        let rec = state
            .db
            .get_repo("z6f2read", "corrupt")
            .await
            .unwrap()
            .unwrap();
        let bare = state
            .repo_store
            .acquire(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        std::fs::create_dir_all(&bare).unwrap();
        run_git(&["init", "-q", "--bare", "--object-format=sha256"], &bare);
        // Hand-rolled truncated loose object (dangling is fine: no path-scoped rules,
        // so the "/" gate is the whole story and the read follows the probe).
        let oid = "6bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459c";
        let mut corrupt: Vec<u8> = vec![0x78, 0x01, 0x01, 0x48, 0x00, 0xb7, 0xff];
        corrupt.extend_from_slice(b"blob 64\0AAAA");
        let obj_dir = bare.join("objects").join(&oid[..2]);
        std::fs::create_dir_all(&obj_dir).unwrap();
        std::fs::write(obj_dir.join(&oid[2..]), &corrupt).unwrap();
        // Preconditions: the probe classifies it as a blob, the full read fails —
        // otherwise the test would pass vacuously via some other arm.
        assert_eq!(
            crate::git::store::object_type(&bare, oid)
                .unwrap()
                .as_deref(),
            Some("blob"),
            "the truncated loose object's header must still probe as a blob"
        );
        assert!(
            crate::git::store::read_object_content(&bare, oid, "blob").is_err(),
            "the truncated loose object's content read must fail"
        );

        let peer: SocketAddr = "203.0.113.66:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid_for_oid(oid), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a failed read after a passed gate leaves the repo unproven — 503, not 404"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );
    }

    /// F2 denied-is-a-verdict: repos that DENY the caller at the visibility gate
    /// are settled, not skipped — an all-denied scan is COMPLETE: 404, zero visits.
    /// The private rows deliberately have no local dirs: if the deny didn't
    /// short-circuit before the visit, the missing-dir probe would taint the scan
    /// into a 503, which the 404 assertion rules out — so the 404 also proves zero
    /// acquires, probes, or walks ran for denied rows.
    #[sqlx::test]
    async fn get_by_cid_all_denied_is_complete_scan_404(pool: sqlx::PgPool) {
        let state = crate::test_support::test_state(pool).await;
        for name in ["priv-a", "priv-b"] {
            let now = chrono::Utc::now();
            state
                .db
                .create_repo(&crate::db::RepoRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: name.to_string(),
                    owner_did: "did:key:z6MkF2DenyOwnerAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    description: None,
                    is_public: false,
                    default_branch: "main".to_string(),
                    created_at: now,
                    updated_at: now,
                    disk_path: format!("/nonexistent/{name}"),
                    forked_from: None,
                    machine_id: None,
                })
                .await
                .unwrap();
        }

        let peer: SocketAddr = "203.0.113.67:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "an anonymous caller denied by every repo gets a complete-scan 404 — a deny \
             is a verdict and must not visit, taint, or 503"
        );
    }

    /// F3 budget expiry mid-loop: one absolute request budget
    /// (`ipfs_request_budget_secs`) bounds the whole admitted scan; per-repo
    /// stages may not each draw a fresh timeout past it. Budget 1s, per-iteration
    /// acquire timeout 2s; the NEWER row is a Tigris-backed ghost (no local copy,
    /// silent local endpoint) whose acquire stalls, the OLDER row is a plain
    /// public repo carrying the blob. The ghost's acquire runs clamped to the ~1s
    /// remainder and times out; at the next repo the budget gate sees zero
    /// remaining, taints "budget", and STOPS the scan, so the blob repo is never
    /// visited (a visit would probe the healthy public copy and serve 200, which
    /// the 503 assertion rules out) and the shed names the budget. Without the
    /// budget the acquire would time out at its own 2s, the scan would continue,
    /// and the buried blob would serve 200 (the recorded RED). MUTATION (RED):
    /// remove the `request_deadline` capture (or make the remaining budget
    /// infinite) and this serves 200 again.
    #[sqlx::test]
    async fn get_by_cid_request_budget_expiry_stops_scan_with_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Seed the blob repo through a LOCAL-ONLY store first, so seeding never
        // consults the (deliberately unreachable) Tigris endpoint.
        state.repo_store =
            crate::git::repo_store::RepoStore::for_testing(repos_dir.clone(), pool.clone());
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f3budget",
            "buried",
            b"budget expiry proof\n",
        )
        .await;
        // Swap in a Tigris-backed store over the SAME repos_dir (the seeded bare
        // repo stays a fast local hit) and add a NEWER ghost row with no local
        // copy: its acquire consults the silent local endpoint and stalls past
        // the budget (endpoint-pinned test client, no AWS_* env reads).
        let endpoint = silent_tigris_endpoint().await;
        let tigris =
            crate::git::tigris::TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint)
                .await;
        state.repo_store = crate::git::repo_store::RepoStore::new(repos_dir, Some(tigris), pool);
        state
            .db
            .upsert_mirror_repo("z6f3budget", "ghost", "/unused-ghost", None, false)
            .await
            .unwrap();
        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        cfg.git_acquire_timeout_secs = 2;
        state.config = Arc::new(cfg);

        let peer: SocketAddr = "203.0.113.70:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid_for_oid(&oid), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exhausted request budget must stop the scan with a retryable 503; \
             scanning on into the later public blob repo would have served 200"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the budget-truncation 503 must carry Retry-After"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("budget"),
            "the truncation body must name the budget taint so the operator can \
             map the shed to GITLAWB_IPFS_REQUEST_BUDGET_SECS; got: {body}"
        );
    }

    /// F3 clamped walk at expiry: a walk that starts with little budget left runs
    /// its git children under `min(git_service_timeout_secs, remaining)`, so the
    /// clamp (not any tokio-level abort) is what ends it and a walk can never
    /// complete past the budget. Budget 2s, service timeout at its 600s default,
    /// fake walk git that sleeps 8s: the walk STARTS (pid file), the walk permit
    /// stays held while the blocking walk runs (`available_permits == 0`), the
    /// clamped deadline SIGTERM/SIGKILLs the child group at ~2s remaining (the
    /// response lands after the ~1s watchdog grace, far before the 8s sleep, and
    /// the recorded pid is already dead: a tokio abort would have left it
    /// running), the log shows the walk started but never completed, and the
    /// request sheds the terminal budget-truncated 503 without ever reaching the
    /// OLDER public copy of the same blob (which would have served 200). After
    /// the response the permit is free: the spawn_blocking closure genuinely
    /// returned. MUTATION (RED): drop the `min` clamp on `walk_timeout` and the
    /// walk runs its full 8s sleep (elapsed and log-completion assertions fail).
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_budget_clamps_walk_deadline_and_holds_permit(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let walk_log = tmp.path().join("walks.log");
        let revlist_pid = tmp.path().join("revlist.pid");
        // Fake git for the WALK only: `rev-list` records its pid and a start
        // marker, sleeps far past the budget, then records a done marker. Under
        // the clamped walk deadline the whole process group is torn down mid
        // sleep, so "done" never appears. The 8s sleep also bounds a RED run.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               for-each-ref) : ;;\n\
               rev-parse) echo deadbeef ;;\n\
               rev-list) echo $$ > \"{pid}\"; echo start >> \"{log}\"; sleep 8; echo done >> \"{log}\" ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            pid = revlist_pid.display(),
            log = walk_log.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.git_bin = git_path.to_str().unwrap().to_string();
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Global walk pool of 1 so the held permit is observable; per-source cap
        // permissive so only the global pool matters.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        let mut cfg = (*state.config).clone();
        // The budget is the ONLY thing that can end this walk early: the service
        // timeout stays at its generous 600s default.
        cfg.ipfs_request_budget_secs = 2;
        state.config = Arc::new(cfg);

        // Older row: a plain public copy of the same blob, which must never be
        // reached. Newer row: path-scoped, so its blob costs the clamped walk.
        let content = b"budget walk clamp proof\n";
        let (_, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6f3clamp", "pubcopy", content).await;
        let (walk_id, _) =
            seed_repo_with_blob(&state, tmp.path(), "z6f3clamp", "gated", content).await;
        state
            .db
            .set_visibility_rule(
                &walk_id,
                "src/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkU3IpfsReaderDDDDDDDDDDDDDDDDDDDDDDDD".to_string()],
                "z6f3clamp",
            )
            .await
            .unwrap();

        let sem = state.git_ipfs_walk_semaphore.clone();
        let router = ipfs_router(state);
        let started = std::time::Instant::now();
        let peer: SocketAddr = "203.0.113.71:5000".parse().unwrap();
        let mut fut = Box::pin(router.oneshot(get_cid(&cid_for_oid(&oid), Some(peer))));

        // Drive until the fake git's rev-list records its pid: the walk is now in
        // the blocking pool and the request future is `.await`ing its join. Stop
        // polling the instant the future completes (re-polling would panic).
        let mut walk_pid: Option<i32> = None;
        let mut early = None;
        for _ in 0..500 {
            let done = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            if let Some(p) = std::fs::read_to_string(&revlist_pid)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                walk_pid = Some(p);
                break;
            }
            if let Ok(resp) = done {
                early = Some(resp.map(|r| r.status()));
                break;
            }
        }
        let pid = walk_pid.unwrap_or_else(|| {
            panic!(
                "the budget-clamped walk must have STARTED (nonzero remaining); early: {early:?}"
            )
        });
        // Reap the sleeping child on drop so a RED run leaks no orphan.
        struct ReapOnDrop(i32);
        impl Drop for ReapOnDrop {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                }
            }
        }
        let _cleanup = ReapOnDrop(pid);

        // While the blocking walk runs the permit is HELD: the budget never frees
        // a slot whose blocking thread is still burning.
        assert_eq!(
            sem.available_permits(),
            0,
            "the walk permit must stay held while the budget-clamped walk runs"
        );

        let resp = tokio::time::timeout(std::time::Duration::from_secs(20), &mut fut)
            .await
            .expect("the clamped walk deadline must end the request; it never hung")
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a budget-clamped walk that could not finish leaves no verdict: 503, not 404/200"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("budget"),
            "the terminal shed must name the budget taint; got: {body}"
        );
        // Deadline-killed at ~remaining, not run to completion: the response
        // lands at ~budget + the watchdog's kill/reap slack, well before the 8s
        // sleep could have finished.
        assert!(
            elapsed < std::time::Duration::from_secs(7),
            "the clamped git deadline must end the walk at ~remaining; got {elapsed:?}"
        );
        // The child group is already dead AT response time: the clamp killed it.
        // (A tokio-level abort of the walk future would have answered while the
        // blocking thread and its child still ran.)
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "the walk's git child must be reaped by the clamped deadline before the response"
        );
        let log = std::fs::read_to_string(&walk_log).unwrap_or_default();
        assert!(
            log.contains("start"),
            "the walk must have started (the budget gate passed with remaining > 0)"
        );
        assert!(
            !log.contains("done"),
            "the walk must never complete past the budget; the clamp kills it mid-run"
        );
        // The spawn_blocking closure returned and the handler finished: the
        // permit is free again (held through the blocking run, no longer).
        assert_eq!(
            sem.available_permits(),
            1,
            "the walk permit must free once the blocking walk genuinely returns"
        );
    }

    /// #174 F3 hung-probe reap (RED-before/GREEN-after): the `git cat-file -t`
    /// probe runs OFF the async worker under the reaped bounded runner, so a hung or
    /// corrupt object store cannot pin a runtime worker or the held IPFS permits.
    /// `objects/info/alternates` is a FIFO with no writer, so real `git cat-file -t`
    /// blocks at odb setup forever. With the probe bounded to
    /// `min(git_service_timeout, remaining budget)` (~1s here), the watchdog tears the
    /// git process group down at the deadline and the probe returns Err — a taint, not
    /// a verdict — so the scan sheds a retryable 503 naming the probe, no walk ever
    /// starts, and the whole request returns in bounded time.
    ///
    /// Load-bearing: with the probe on the bare async worker (pre-fix) this FIFO blocks
    /// the handler forever (no feeder frees it) and the request hangs — the wrapping
    /// timeout fires (RED). With the reaped bounded probe it returns 503 promptly.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_hung_probe_is_reaped_and_sheds_503(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let walk_log = tmp.path().join("walks.log");
        state.git_bin = walk_logging_fake_git(tmp.path(), &walk_log);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        state.config = Arc::new(cfg);

        let (repo_id, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f3probe",
            "gated",
            b"probe-then-expire proof\n",
        )
        .await;
        state
            .db
            .set_visibility_rule(
                &repo_id,
                "src/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkU3IpfsReaderEEEEEEEEEEEEEEEEEEEEEEEE".to_string()],
                "z6f3probe",
            )
            .await
            .unwrap();

        // Hang the REAL-git probe indefinitely: `objects/info/alternates` as a FIFO
        // with no writer blocks `git cat-file -t` at odb setup forever. There is no
        // feeder — the reaped bounded runner must tear the git process group down at
        // the deadline; a bare unbounded probe would block the handler here.
        let rec = state
            .db
            .get_repo("z6f3probe", "gated")
            .await
            .unwrap()
            .unwrap();
        let bare = state
            .repo_store
            .acquire(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        let fifo = bare.join("objects").join("info").join("alternates");
        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) },
            0,
            "mkfifo(objects/info/alternates) must succeed"
        );
        let peer: SocketAddr = "203.0.113.72:5000".parse().unwrap();
        // The request must return in bounded time: the reaped probe sheds a 503; a
        // bare unbounded probe would block on the FIFO forever (no feeder frees it).
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            ipfs_router(state).oneshot(get_cid(&cid_for_oid(&oid), Some(peer))),
        )
        .await
        .expect("the hung probe must be reaped, not block the handler")
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "probed-present with the budget gone must shed the truncation 503: \
             never the walked 404, never a serve"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("probe"),
            "the shed must name the reaped-probe taint; got: {body}"
        );
        let walks = std::fs::read_to_string(&walk_log)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        assert_eq!(
            walks, 0,
            "no walk may START once the budget is exhausted, even for a probed-present object"
        );
    }

    /// Shed at capacity: an exhausted `git_ipfs_walk_semaphore` sheds a `/ipfs/{cid}`
    /// request with 503 BEFORE any DB/git walk (the acquire is the first thing after CID
    /// validation), so a lazy DB-free state suffices — exactly like the served-git shed
    /// tests. MUTATION (RED): delete the `git_ipfs_walk_semaphore` acquire in
    /// `get_by_cid` and the request no longer sheds here (it falls through to the DB /
    /// walk and returns something other than 503).
    #[tokio::test]
    async fn get_by_cid_sheds_with_503_when_walk_pool_exhausted() {
        let mut state = crate::test_support::test_state_lazy();
        // Global /ipfs walk pool exhausted; per-source cap permissive so only the global
        // pool can shed. Route rate limit is applied as a layer in production, not here.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(0));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let peer: SocketAddr = "203.0.113.9:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exhausted /ipfs walk pool must shed the request with 503"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the 503 shed must carry Retry-After"
        );
    }

    /// Per-source sub-cap, the `Some(ip)` arm: with per-source = 1 and the source pinned
    /// at its single slot, a request from THAT source sheds 503 (global pool has room),
    /// while a request from a DIFFERENT source is NOT shed by the cap (it proceeds past
    /// admission). Pinning proves the `PeerAddr`/`HeaderMap` extractors resolved the key
    /// — an inert `None` key would never shed on the per-source cap. MUTATION (RED):
    /// delete the `git_ipfs_walk_per_caller` acquire and the capped source no longer
    /// sheds.
    #[tokio::test]
    async fn get_by_cid_per_source_cap_sheds_same_source_admits_other() {
        let mut state = crate::test_support::test_state_lazy();
        // Global pool has room; the per-source cap is 1.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(8));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let capped: SocketAddr = "203.0.113.20:5000".parse().unwrap();
        let other: SocketAddr = "203.0.113.21:5000".parse().unwrap();

        // Pin the capped source at its single walk slot.
        let _slot = state
            .git_ipfs_walk_per_caller
            .try_acquire(&capped.ip().to_string())
            .expect("first walk slot for the capped source IP");

        let cid = valid_cid();
        // The capped source sheds on the per-source cap even with global capacity free.
        let resp = ipfs_router(state.clone())
            .oneshot(get_cid(&cid, Some(capped)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a source at its per-source /ipfs walk cap must shed 503 with global capacity free"
        );

        // A DIFFERENT source is NOT shed by the per-source cap: it clears admission and
        // proceeds (then errors on the lazy DB, which is not a 503).
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(other)))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a different source must not be shed by the per-source cap"
        );
    }

    /// The `None`-key arm: a request with no resolvable source key (no trusted-proxy
    /// header, no `ConnectInfo`) is bounded by the GLOBAL pool only, never the per-source
    /// sub-cap. With the global pool exhausted it still sheds 503 (the counterpart to the
    /// `Some(ip)` arm above, so neither arm is vacuous).
    #[tokio::test]
    async fn get_by_cid_none_key_arm_sheds_on_global_pool() {
        let mut state = crate::test_support::test_state_lazy();
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(0));
        // Per-source cap permissive so only the global pool can shed.
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        // No ConnectInfo + no trusted header -> client_key resolves None.
        let resp = ipfs_router(state)
            .oneshot(get_cid(&valid_cid(), None))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a None-key request must still shed 503 on the exhausted GLOBAL /ipfs walk pool"
        );
    }

    /// Map self-bound (INV-15): the `/ipfs` per-source map is a `PerCallerConcurrency`
    /// built via `with_default_max_keys`, so a distinct-source-key flood cannot grow it
    /// past the cap and a rejected key never allocates (reject-before-insert). Mirrors
    /// `per_caller_concurrency_map_is_self_bounding_and_reject_before_insert` for the
    /// pool U3 adds.
    #[tokio::test]
    async fn ipfs_walk_per_caller_map_is_self_bounding_and_reject_before_insert() {
        let lim = crate::rate_limit::PerCallerConcurrency::new(4, 3);
        // Acquire+drop a flood of distinct keys — the map self-empties (a key is removed
        // the instant its in-flight count hits zero).
        for i in 0..50 {
            let _p = lim.try_acquire(&format!("src{i}"));
        }
        assert_eq!(
            lim.tracked_keys(),
            0,
            "an acquire+drop flood of distinct sources leaves the /ipfs map empty"
        );
        // Reject-before-insert: hold max_keys distinct sources, then a new one sheds
        // without growing the map.
        let held: Vec<_> = (0..3)
            .map(|i| lim.try_acquire(&format!("h{i}")).unwrap())
            .collect();
        assert_eq!(
            lim.tracked_keys(),
            3,
            "three distinct sources held concurrently"
        );
        assert!(
            lim.try_acquire("h3").is_none(),
            "a new source key at max_keys is rejected"
        );
        assert_eq!(
            lim.tracked_keys(),
            3,
            "the rejected key did not allocate an entry (reject-before-insert)"
        );
        drop(held);
    }

    /// Retain-through-blocking (R3, the load-bearing async property): the walk
    /// admission is held until the `spawn_blocking` walk actually RETURNS, not when a
    /// tokio timeout fires. With the global pool at size 1, drive a request until its
    /// walk (a fake git that hangs on `rev-list`) is in flight; the slot must stay held
    /// (`available_permits() == 0`) and a replacement from a DIFFERENT source must shed
    /// 503 for as long as the blocking walk runs — even though the request future is
    /// only `.await`ing the blocking join. When the blocking walk ends the permit frees
    /// and a replacement is admitted. The permit lives INSIDE the handler across the
    /// blocking `.await`; move it out (drop before the walk) and the replacement would
    /// be admitted while the walk still burns a blocking thread (the bug this guards).
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_walk_permit_held_through_blocking_walk(pool: sqlx::PgPool) {
        use std::process::Command;

        let tmp = tempfile::TempDir::new().unwrap();
        let revlist_pid = tmp.path().join("revlist.pid");
        // Fake git for the /ipfs WALK only (object_type/read_object_content use the real
        // `git`, so the object must genuinely exist below). Empty refs (so
        // assert_all_refs_are_commits returns Ok without the peel), `rev-parse` resolves,
        // and `rev-list` records its pid then sleeps ~6s so the walk BLOCKS
        // deterministically. The sleep bounds the walk so a broken fix cannot wedge the
        // suite.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               for-each-ref) : ;;\n\
               rev-parse) echo deadbeef ;;\n\
               rev-list) echo $$ > \"{}\"; sleep 6 ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            revlist_pid.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        // Isolate the global walk pool at size 1; per-source cap permissive so only the
        // held global permit can shed the replacement.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        state.git_bin = git_path.to_str().unwrap().to_string();
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let owner = "z6ipfs1";
        let name = "ip1";
        state
            .db
            .upsert_mirror_repo(owner, name, "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        // The exact bare path the handler's `acquire` resolves. Build a REAL SHA-256 bare
        // repo there with a committed blob under `src/`, so real `git cat-file -t <cid
        // digest>` classifies it as a blob (the CID digest IS the sha256 object id in
        // object-format=sha256) and the handler reaches the path-scoped walk branch.
        let bare = state
            .repo_store
            .acquire(&rec.owner_did, &rec.name)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(&bare);
        std::fs::create_dir_all(&bare).unwrap();
        let run = |args: &[&str], cwd: &std::path::Path| {
            let out = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .expect("git runs");
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let work = tmp.path().join("work");
        std::fs::create_dir_all(work.join("src")).unwrap();
        std::fs::write(work.join("src/secret.txt"), b"ipfs walk retain proof\n").unwrap();
        run(
            &["init", "-q", "--object-format=sha256", "-b", "main"],
            &work,
        );
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "src/secret.txt"], &work);
        run(&["commit", "-q", "-m", "seed"], &work);
        run(
            &[
                "clone",
                "--bare",
                "-q",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            tmp.path(),
        );
        // The blob's SHA-256 object id (= the CID's digest); build the CID from it.
        let oid = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD:src/secret.txt"])
                .current_dir(&work)
                .output()
                .expect("git rev-parse runs");
            assert!(out.status.success(), "rev-parse failed");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let oid_bytes = gitlawb_core::cid::sha256_hex_to_bytes(&oid).unwrap();
        let cid = gitlawb_core::cid::Cid::from_sha256_bytes(&oid_bytes)
            .as_str()
            .to_string();
        // Precondition: real git classifies the object as a blob (so the handler reaches
        // the walk branch, not an early `continue`).
        assert_eq!(
            crate::git::store::object_type(&bare, &oid)
                .unwrap()
                .as_deref(),
            Some("blob"),
            "the seeded sha256 blob must exist so the handler reaches the walk"
        );
        // A path-scoped rule so has_path_scoped_rule() is true (the walk branch) without
        // denying the "/" gate on the public repo.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "src/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkU3IpfsReaderAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
                &rec.owner_did,
            )
            .await
            .unwrap();

        let sem = state.git_ipfs_walk_semaphore.clone();
        assert_eq!(
            sem.available_permits(),
            1,
            "one walk slot before the request"
        );

        let router = ipfs_router(state);
        let make_req = |peer: SocketAddr| {
            let mut req = Request::builder()
                .method(Method::GET)
                .uri(format!("/ipfs/{cid}"))
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            req
        };

        let peer: SocketAddr = "203.0.113.81:5000".parse().unwrap();
        let mut fut = Box::pin(router.clone().oneshot(make_req(peer)));
        // Drive until the fake git's rev-list records its pid — the walk is now in the
        // blocking pool and the request future is `.await`ing its join, holding the walk
        // permit. Stop polling the instant the future completes (re-polling a completed
        // oneshot panics).
        let mut walk_pid: Option<i32> = None;
        let mut early = None;
        for _ in 0..500 {
            let done = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            if let Some(p) = std::fs::read_to_string(&revlist_pid)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                walk_pid = Some(p);
                break;
            }
            if let Ok(resp) = done {
                early = Some(resp.map(|r| r.status()));
                break;
            }
        }
        let pid = walk_pid
            .unwrap_or_else(|| panic!("the fake git rev-list must have spawned; early: {early:?}"));
        // Reap the sleeping child on drop so a RED run leaks no orphan.
        struct ReapOnDrop(i32);
        impl Drop for ReapOnDrop {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                }
            }
        }
        let _cleanup = ReapOnDrop(pid);

        // Load-bearing: while the blocking walk runs, the slot is HELD and a replacement
        // from a DIFFERENT source sheds 503 — proving the permit is retained across the
        // spawn_blocking join, not freed by a tokio timeout.
        assert_eq!(
            sem.available_permits(),
            0,
            "the walk slot must be held while the spawn_blocking walk runs"
        );
        let peer2: SocketAddr = "203.0.113.82:5000".parse().unwrap();
        let resp = router.clone().oneshot(make_req(peer2)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a replacement must shed 503 while the prior request's blocking walk still runs"
        );

        // Drop the in-flight request; the detached blocking walk keeps running (a
        // spawn_blocking cannot be cancelled), but on the fix the permit is a handler
        // local, so dropping the future releases it once the blocking join is abandoned.
        // Either way, kill the sleeping child so the slot frees promptly and poll for
        // recovery — the point already proven above is that the slot stayed held for the
        // duration of the blocking work.
        drop(fut);
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut freed = false;
        for _ in 0..400 {
            if sem.available_permits() == 1 {
                freed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            freed,
            "once the blocking walk ends the walk permit must free the global slot"
        );
    }

    /// Loop bound (cap N) + F2 truncation verdict: one `/ipfs/{cid}` request against a
    /// CID present in many path-scoped repos must not serialize an unbounded number of
    /// full-history walks — and cutting a candidate WITHOUT a verdict must not report
    /// the object absent. With `ipfs_max_repos_walked = 1` and TWO public, path-scoped
    /// repos both carrying the blob, the first candidate is walked (empty allowed-set →
    /// a deny VERDICT) and the second is cut by the cap (no verdict), so the fake git's
    /// `rev-list` runs exactly once and the request sheds a retryable 503 + Retry-After
    /// — never the old false 404 (the blob genuinely sits in the second repo).
    /// MUTATION (RED): remove the `repos_walked >= cap` skip and both repos are walked
    /// (count 2); drop the truncation taint on the skip and the 503 decays to a 404.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_caps_repos_walked_per_request(pool: sqlx::PgPool) {
        use std::process::Command;

        let tmp = tempfile::TempDir::new().unwrap();
        let walk_log = tmp.path().join("walks.log");
        // Fake git for the WALK: empty refs, `rev-parse` resolves, and each `rev-list`
        // appends one line to a log (so the number of walks == the line count) and exits
        // with EMPTY output (the allowed-set is empty, so every repo path-gates to a
        // `continue` and the request 404s after walking). object_type uses the REAL git,
        // so the seeded blob below must genuinely exist.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               for-each-ref) : ;;\n\
               rev-parse) echo deadbeef ;;\n\
               rev-list) echo walk >> \"{}\" ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            walk_log.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.git_bin = git_path.to_str().unwrap().to_string();
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // The bound under test: walk at most one candidate repo per request.
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repos_walked = 1;
        state.config = Arc::new(cfg);

        // Seed TWO public repos, each with the SAME blob (same content -> same sha256 OID
        // -> same CID) under a path-scoped rule, so both are walk candidates for one CID.
        let run = |args: &[&str], cwd: &std::path::Path| {
            let out = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .expect("git runs");
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let mut oid = String::new();
        for (i, name) in ["ipa", "ipb"].iter().enumerate() {
            let owner = "z6ipfsN";
            state
                .db
                .upsert_mirror_repo(owner, name, &format!("/unused-{name}"), None, false)
                .await
                .unwrap();
            let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
            let bare = state
                .repo_store
                .acquire(&rec.owner_did, &rec.name)
                .await
                .unwrap();
            let _ = std::fs::remove_dir_all(&bare);
            std::fs::create_dir_all(&bare).unwrap();
            let work = tmp.path().join(format!("work{i}"));
            std::fs::create_dir_all(work.join("src")).unwrap();
            // Identical content in both repos -> identical sha256 blob OID -> one CID.
            std::fs::write(work.join("src/secret.txt"), b"loop bound proof\n").unwrap();
            run(
                &["init", "-q", "--object-format=sha256", "-b", "main"],
                &work,
            );
            run(&["config", "user.email", "t@t"], &work);
            run(&["config", "user.name", "t"], &work);
            run(&["add", "src/secret.txt"], &work);
            run(&["commit", "-q", "-m", "seed"], &work);
            run(
                &[
                    "clone",
                    "--bare",
                    "-q",
                    work.to_str().unwrap(),
                    bare.to_str().unwrap(),
                ],
                tmp.path(),
            );
            if oid.is_empty() {
                let out = Command::new("git")
                    .args(["rev-parse", "HEAD:src/secret.txt"])
                    .current_dir(&work)
                    .output()
                    .expect("git rev-parse runs");
                oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }
            state
                .db
                .set_visibility_rule(
                    &rec.id,
                    "src/**",
                    crate::db::VisibilityMode::B,
                    &["did:key:z6MkU3IpfsReaderBBBBBBBBBBBBBBBBBBBBBBBB".to_string()],
                    &rec.owner_did,
                )
                .await
                .unwrap();
        }
        let oid_bytes = gitlawb_core::cid::sha256_hex_to_bytes(&oid).unwrap();
        let cid = gitlawb_core::cid::Cid::from_sha256_bytes(&oid_bytes)
            .as_str()
            .to_string();

        let peer: SocketAddr = "203.0.113.90:5000".parse().unwrap();
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(format!("/ipfs/{cid}"))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = ipfs_router(state).oneshot(req).await.unwrap();
        // The first repo's walk yields the empty allowed-set (deny verdict); the second
        // repo NEEDS a walk the cap forbids, so the scan is truncated without a verdict
        // on it: retryable 503, never a false 404 for the blob it genuinely carries.
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a walk-cap truncation must shed a retryable 503, not report the object absent"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the truncation 503 must carry Retry-After"
        );

        let walks = std::fs::read_to_string(&walk_log)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        assert_eq!(
            walks, 1,
            "with the per-request repo-walk cap at 1, only the first candidate repo is \
             walked (the second is cut by the cap), so exactly one walk runs; got {walks}"
        );
    }

    /// Route rate limit is WIRED (not a silent no-op): the production `build_router`
    /// attaches an `IpRateLimiter` extension to the `/ipfs/{cid}` route, so a per-IP
    /// flood is braked with 429. A bare `rate_limit_by_ip` layer with no extension does
    /// nothing, so this proves the extension is attached. Drive it through the real
    /// router with a tight limiter (1/hr): the second request from the same IP is 429.
    /// MUTATION (RED): drop the `axum::Extension(ipfs_limiter)` layer in `server.rs` and
    /// the second request is no longer braked (it reaches the handler, 404, not 429).
    #[sqlx::test]
    async fn ipfs_route_ip_rate_limit_is_attached(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        // Tight per-IP /ipfs bucket so the second request from one IP trips 429.
        state.ipfs_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, std::time::Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let router = crate::server::build_router(state);
        let cid = valid_cid();
        let make = |peer: SocketAddr| {
            let mut req = Request::builder()
                .method(Method::GET)
                .uri(format!("/ipfs/{cid}"))
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            req
        };
        let peer: SocketAddr = "203.0.113.99:5000".parse().unwrap();

        // First request from this IP passes the brake and reaches the handler (404 — no
        // such object anywhere), debiting the single-slot bucket.
        let resp = router.clone().oneshot(make(peer)).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "the first /ipfs request from an IP must pass the rate brake"
        );
        // Second request from the SAME IP is braked with 429 — proving the limiter
        // extension is attached (a bare no-op layer would let it through to 404).
        let resp = router.clone().oneshot(make(peer)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "an exhausted per-IP /ipfs bucket must brake with 429 — the IpRateLimiter \
             extension must be attached to the route"
        );
        // A DIFFERENT IP still has its own budget (independent bucket).
        let other: SocketAddr = "203.0.113.100:5000".parse().unwrap();
        let resp = router.oneshot(make(other)).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a different IP must not be braked by another IP's exhausted bucket"
        );
    }
}
