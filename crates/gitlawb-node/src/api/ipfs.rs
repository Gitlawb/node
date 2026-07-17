//! GET /ipfs/{cid} — content-addressed retrieval of git objects by CIDv1.
//!
//! Every git object pinned on this node is addressable by its IPFS CIDv1.
//! The CID is computed as:
//!
//!   CIDv1(codec=raw, multihash=sha2-256(content_bytes))
//!
//! where `content_bytes` is the raw object content as returned by
//! `git cat-file <type> <sha256>` (i.e. without the git framing header) — the
//! same bytes `gitlawb_core::cid::Cid::from_git_object_bytes` hashes when the
//! object is pinned. That digest is NOT the object's git oid: git frames the
//! content with a `"<type> <len>\0"` header before hashing, so `sha2-256(content)`
//! and the git oid differ. The handler therefore maps the CID back to its oid via
//! the `pinned_cids` table rather than treating the digest as an oid (#173).
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
use crate::git::visibility_pack::{
    allowed_blob_set_for_caller_bounded, allowed_tree_set_for_caller_bounded, has_path_scoped_rule,
    reachable_commit_tag_oids_bounded,
};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

/// Hard ceiling on the number of full-history reachability walks a single
/// `GET /ipfs/{cid}` request may spawn. The per-request `ipfs_rate_limiter`
/// check brakes *repeat* requests, but within one request the object can exist
/// under path-scoped rules in many repos, and each distinct repo pays its own
/// `spawn_blocking` walk (the memo only dedups the same repo). Without a ceiling
/// a single request fans out to O(repos) walks for one rate-limiter token — an
/// amplification sink (INV-10). Once this many walks have run, no further walk is
/// spawned for the rest of the request: any remaining candidate that still needs
/// a walk is skipped (and, with nothing else readable, the request falls through
/// to the opaque 404). The bound is deliberately generous: a legitimate caller
/// serves on the first repo that grants them, so reaching it requires being
/// denied by this many path-scoped repos first, which real traffic effectively
/// never does. Tunable if that assumption stops holding.
///
/// Kept at `MAX_PIN_SOURCES + 1` so the ceiling can never truncate a request
/// BEFORE its whole bounded provenance source set (first-pinner + up to
/// `MAX_PIN_SOURCES` additional) has been tried: an authorizing public source that
/// sorts after `MAX_PIN_SOURCES` path-scoped denials must still be reached and
/// served, not falsely 503'd as a truncated search. The legacy scan's fan-out is
/// separately bounded by `MAX_LEGACY_PROBES_PER_REQUEST`, so widening this by one
/// does not loosen that path.
pub(crate) const MAX_HISTORY_WALKS_PER_REQUEST: u32 = crate::db::MAX_PIN_SOURCES as u32 + 1;

/// Hard per-request ceiling on how many legacy (NULL-provenance) repositories
/// the CID resolver's scan fallback may PROBE (`acquire` + `git cat-file -t`).
/// The provenance path targets one repo; the legacy scan, absent this bound,
/// fans one anonymous request out to O(repos) subprocess spawns and cold-cache
/// Tigris fetches for a CID enumerable from the public pins index (#173 round 3,
/// F1, INV-10). Deliberately generous: a normal node has far fewer repos than
/// this, so a genuine miss still completes the whole scan and returns a truthful
/// 404; only a node larger than the cap truncates, and a truncated search
/// surfaces as a retryable 503 (never a false "absent"). Legacy pins are a
/// shrinking set — each re-pin backfills provenance — so this fallback is a
/// transitional path, not the steady state. Tunable via `AppState`.
pub(crate) const MAX_LEGACY_PROBES_PER_REQUEST: u32 = 256;

/// Hard ceiling on the byte size of an object `GET /ipfs/{cid}` buffers and serves
/// (#173 round 8, F6, INV-10). The serve reads via a blocking `git cat-file` and
/// buffers the whole object; unbounded, a large public blob (enumerable from the pins
/// index) could exhaust memory or block a runtime worker. A content-addressed serve
/// must verify the whole object hashes to the requested CID before any byte egresses
/// (F2), so it cannot stream — it buffers up to this cap and withholds anything larger
/// (raise the cap if a class of legitimate objects legitimately exceeds it; never
/// stream unverified). 32 MiB is generous for git blobs/trees/commits. Tunable via
/// `AppState` for the test seam, like the sibling caps.
pub(crate) const MAX_SERVED_OBJECT_BYTES: u64 = 32 * 1024 * 1024;

/// Lazily-loaded context for the legacy (NULL-provenance) scan fallback in
/// `get_by_cid`: all repos, their visibility rules keyed by repo id, and the set of
/// quarantined repo ids. Loaded once per request only if a legacy pin is hit.
type LegacyScanCtx = (
    Vec<crate::db::RepoRecord>,
    HashMap<String, Vec<crate::db::VisibilityRule>>,
    HashSet<String>,
);

/// GET /ipfs/{cid}
///
/// Resolve the CIDv1 to its git oid via the `pinned_cids` table, then search all
/// repos on the node for that object, returning its raw content if the caller may
/// read it.
///
/// Visibility (#110, #126): the object is served only from a repo row the
/// caller passes. For each iterated row we gate against that row's OWN rules
/// (`visibility_check` at `"/"`), never re-resolving via `authorize_repo_read`
/// — `get_repo`'s fuzzy match could otherwise authorize a different physical
/// row than the one read (KTD2a). We check object existence via
/// `store::object_type` *before* the expensive reachability walk so random-CID
/// spray cannot trigger full-history git walks on repos that don't carry the
/// object. When the row carries path-scoped rules (KTD4) the served object is
/// gated by type: a `blob`/`tree` must be in the caller's *reachable* allowed-set
/// (`allowed_blob_set_for_caller` / `allowed_tree_set_for_caller`), and a
/// `commit`/`tag` must be in the repo's *reachable* commit/tag set
/// (`reachable_commit_tag_oids`, #173). A withheld subtree's tree object is denied
/// here exactly as `get_tree` denies its path, so its child names and oids cannot
/// leak by CID (#135). All these sets exclude dangling objects — a blob, tree,
/// commit, or tag written via plumbing and never referenced has no reachable path,
/// so it is fail-closed 404'd under path-scoped rules (#126, #173). Denial and
/// genuine not-found both fall through to an opaque 404.
///
/// Scope: this closes the direct unauthenticated scan, including the dangling
/// case. A stale-public mirror row still serves withheld content (tracked
/// separately, #124).
pub async fn get_by_cid(
    Path(cid_str): Path<String>,
    State(state): State<AppState>,
    crate::rate_limit::PeerAddr(peer): crate::rate_limit::PeerAddr,
    headers: HeaderMap,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Response> {
    // 1. Decode and validate the CID (uniform 400 on a malformed / non-sha2-256
    //    CID, before any DB or git work).
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

    // Canonicalize the CID for the pinned_cids lookup. Pins are stored under the
    // canonical base32 `cid.to_string()`, but a client may send any equivalent
    // multibase spelling (base58/base64) of the same CID; those parse and pass
    // the sha2-256 check yet miss the canonical key, so they must be normalized
    // before the DB lookup (#173). Response headers and error messages still echo
    // the original `cid_str` the client sent.
    let canonical_cid = cid.to_string();

    // Bounded walk admission (#174 P1-3), taken before any DB/git work so a flood sheds
    // cheaply. The per-repo `spawn_blocking` walk below is a full-history git walk with
    // no served-git admission of its own; a permissionless caller could otherwise fan
    // out concurrent walks past every git pool, exhausting the blocking pool + PIDs.
    // Acquire the global permit (and, for a resolvable source, the per-source
    // sub-permit) ONCE here and hold BOTH for the whole request — across every
    // `spawn_blocking` walk below — so the slot reflects real blocking-thread
    // occupancy (a tokio walk-timeout cannot free it while the blocking work still runs)
    // and one request cannot open more than its share of concurrent walks. Holding a
    // slot across a walk is only safe because every walk child is duration-bounded
    // (`*_bounded` + `run_bounded_git` teardown), so a hung git cannot pin the slot
    // past `git_service_timeout_secs`. On unavailability shed a clean 503. The
    // per-source key is the resolved source IP (`client_key`), never the DID (`/ipfs`
    // admits any `did:key` unthrottled, so a DID key would be free to mint around); a
    // `None` key (no trusted header, no peer) is bounded by the global pool only,
    // never the per-source sub-cap.
    let _ipfs_walk_permit = state
        .git_ipfs_walk_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            tracing::warn!("/ipfs walk concurrency cap reached; shedding request with 503");
            AppError::Overloaded("ipfs service at capacity, retry shortly".into())
        })?;
    let source_key = crate::rate_limit::client_key(&headers, peer, state.push_limiter_trust);
    let _ipfs_caller_permit = match &source_key {
        Some(ip) => Some(state.git_ipfs_walk_per_caller.try_acquire(ip).ok_or_else(|| {
            tracing::warn!(key = %ip, "/ipfs per-source walk cap reached; shedding request with 503");
            AppError::Overloaded("ipfs service at capacity for this source, retry shortly".into())
        })?),
        None => None,
    };

    // Resolve the content-addressed CID to the object's git oid(s). A real pin
    // CID digests the raw object content (`Cid::from_git_object_bytes`), NOT the
    // git oid (git frames content with a `"<type> <len>\0"` header first), so we
    // map it back through `pinned_cids` rather than treating the digest as an oid
    // (#173). The cid index is non-unique, so one CID can map to several oids (a
    // tree and a blob whose raw bytes collide, or content pinned under two oids);
    // we try each candidate below rather than pick one arbitrarily and false-404
    // when the chosen one is withheld or absent while another is readable (#173).
    // An empty result is an opaque 404, uniform with a genuine not-found and a
    // visibility denial.
    let oids = state
        .db
        .oids_for_cid(&canonical_cid)
        .await
        .map_err(AppError::Internal)?;
    if oids.is_empty() {
        return Err(AppError::RepoNotFound(format!(
            "no git object found for CID {cid_str}"
        )));
    }
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let caller_owned = caller.map(|c| c.to_string());

    // Per-request walk budget + memos + throttle flag, shared by the provenance path
    // and the legacy scan so both honor the same fan-out ceiling, per-repo memo, and
    // IP brake. The caller is constant for one request, so `repo.id` alone keys the memo.
    let mut walk = WalkState {
        walks: 0,
        probes: 0,
        truncated: false,
        allowed_blob_memo: HashMap::new(),
        allowed_tree_memo: HashMap::new(),
        reachable_ct_memo: HashMap::new(),
    };
    // Set when a walk-requiring candidate is skipped because the source IP's walk quota
    // is spent (#173 review, F-C): the scan keeps going so a later walk-free copy still
    // serves; only if nothing is servable is it turned into the 429.
    let mut throttled = false;
    let rctx = ResolveCtx {
        caller,
        caller_owned: &caller_owned,
        headers: &headers,
        peer,
        cid_str: &cid_str,
        canonical_cid: &canonical_cid,
    };

    // Legacy scan context (repos + rules + quarantined ids), loaded LAZILY only when a
    // legacy NULL-provenance pin is hit — the provenance path must never trigger the
    // O(repos) load (that fan-out is exactly what provenance removes, #173 round 2).
    let mut scan_ctx: Option<LegacyScanCtx> = None;

    for sha256_hex in &oids {
        // A pinned object records EVERY repo it was pinned from (#173 round 8, F1).
        // Resolve a PROVENANCED pin by trying each source repo (bounded to
        // MAX_PIN_SOURCES) through the SAME gate; the first that authorizes serves — no
        // scan fan-out. A shared object first pinned from a private/quarantined repo
        // still serves from a later PUBLIC source. Deterministic (ORDER BY on the
        // union), so no ordering can turn an authorized copy into a 404.
        let sources = state
            .db
            .pin_sources_for_oid(sha256_hex)
            .await
            .map_err(AppError::Internal)?;
        // Provenance fast-path: try each recorded source repo through the SAME gate
        // (bounded to first-pinner + MAX_PIN_SOURCES). Empty for a legacy NULL-provenance
        // pin. The first source that authorizes serves — no scan fan-out on the common
        // path.
        for repo_id in &sources {
            let repo = match state
                .db
                .get_repo_by_id(repo_id)
                .await
                .map_err(AppError::Internal)?
            {
                Some(r) => r,
                // A source repo is gone: skip it; a later source or the scan fallback
                // below may still resolve.
                None => continue,
            };
            let quarantined = state
                .db
                .is_repo_quarantined(repo_id)
                .await
                .map_err(AppError::Internal)?;
            let rules_map = state
                .db
                .list_visibility_rules_for_repos(std::slice::from_ref(repo_id))
                .await
                .map_err(AppError::Internal)?;
            let rules = rules_map.get(repo_id).map(Vec::as_slice).unwrap_or(&[]);
            match gate_and_serve(
                &state,
                &repo,
                rules,
                quarantined,
                sha256_hex,
                &rctx,
                &mut walk,
                false,
            )
            .await
            {
                GateOutcome::Served(resp) => return Ok(resp),
                GateOutcome::Throttled => {
                    throttled = true;
                    continue;
                }
                GateOutcome::Skip => continue,
            }
        }

        // Bounded legacy-scan fallback. Run it when the provenance set could not have
        // served the caller AND may be INCOMPLETE:
        //   - empty  -> a legacy NULL-provenance pin (recorded before provenance existed), or
        //   - at_cap -> `record_pin_source` stops inserting at MAX_PIN_SOURCES and drops
        //               later sources SILENTLY, so a full table may hide a servable source
        //               (e.g. a later PUBLIC pinner buried by 16 attacker sources — the
        //               pin-source griefing hole). The scan gates every repo through the
        //               real per-caller gate, so it finds that copy.
        // A non-empty, non-full set is COMPLETE (every recorded source was just tried), so
        // skip the scan and let the tail 404 — ordinary denials never fan out to O(repos)
        // (INV-10 / F3). The at_cap query runs only on a provenance MISS (we return above
        // on Served), so it never costs the serve path.
        let needs_scan = sources.is_empty()
            || state
                .db
                .pin_sources_at_cap(sha256_hex)
                .await
                .map_err(AppError::Internal)?;
        if needs_scan {
            // F3 (#173, INV-10/INV-15): peek the per-IP limiter WITHOUT consuming a token
            // so an already-throttled source is shed BEFORE the O(repos) preload; the
            // consuming per-probe charge inside gate_and_serve is left UNCHANGED (it is
            // load-bearing for the across-request bound), so this adds no double-charge.
            if let Some(key) =
                crate::rate_limit::client_key(rctx.headers, rctx.peer, state.push_limiter_trust)
            {
                if state.ipfs_rate_limiter.is_throttled(&key).await {
                    throttled = true;
                    continue;
                }
            }
            // Load the scan context once, lazily (shared across oid candidates).
            if scan_ctx.is_none() {
                #[cfg(test)]
                bump_preload_queries();
                let repos = state
                    .db
                    .list_all_repos()
                    .await
                    .map_err(AppError::Internal)?;
                let repo_ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
                let rules_by_repo = state
                    .db
                    .list_visibility_rules_for_repos(&repo_ids)
                    .await
                    .map_err(AppError::Internal)?;
                let quarantined: HashSet<String> = state
                    .db
                    .list_quarantined_repos()
                    .await
                    .map_err(AppError::Internal)?
                    .into_iter()
                    .map(|r| r.id)
                    .collect();
                scan_ctx = Some((repos, rules_by_repo, quarantined));
            }
            let (repos, rules_by_repo, quarantined) = scan_ctx.as_ref().unwrap();
            for repo in repos {
                let rules = rules_by_repo
                    .get(&repo.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                let is_quar = quarantined.contains(&repo.id);
                match gate_and_serve(
                    &state, repo, rules, is_quar, sha256_hex, &rctx, &mut walk, true,
                )
                .await
                {
                    GateOutcome::Served(resp) => return Ok(resp),
                    // A throttled walk-requiring candidate is skipped, not fatal:
                    // keep scanning for a later walk-free copy (#173 review, F-C).
                    GateOutcome::Throttled => throttled = true,
                    GateOutcome::Skip => {}
                }
            }
        }
    }

    // Nothing served — three distinct tails, in precedence order:
    //  1. The scan was cut short by a cap (legacy probe ceiling or walk ceiling), so
    //     the object was NOT proven absent/unreadable everywhere → 503, retryable, and
    //     explicitly NOT a definitive not-found (#173, F2). This outranks the throttle:
    //     an incomplete search must not masquerade as a clean rate-limit outcome, and
    //     it carries only the caller-supplied CID (no object/OID/metadata leak).
    //  2. A walk-requiring candidate was skipped for a spent IP quota while the scan
    //     otherwise completed → 429 (the brake bit; a cheaper copy was sought first).
    //  3. A full scan under the caps found nothing readable → opaque 404, uniform with
    //     a genuine not-found and a visibility denial.
    if walk.truncated {
        return Err(AppError::SearchIncomplete(format!(
            "CID {cid_str} search incomplete — retry"
        )));
    }
    if throttled {
        return Err(AppError::TooManyRequests(
            "ipfs retrieval rate limit exceeded — try again later".into(),
        ));
    }
    Err(AppError::RepoNotFound(format!(
        "no git object found for CID {cid_str}"
    )))
}

/// Outcome of gating one repo for one candidate oid.
enum GateOutcome {
    /// The object passed the gate; serve this response.
    Served(Response),
    /// This repo does not serve the object (absent, denied, quarantined, walk-capped,
    /// or a walk error) — try the next candidate.
    Skip,
    /// A walk-requiring candidate hit the per-IP walk quota; skip it but let the caller
    /// record the throttle so a later walk-free copy can still serve.
    Throttled,
}

/// Outcome of the bounded, off-worker object read for one gated candidate (F6, #173).
enum ServedRead {
    /// Verified: the object's bytes hash to the requested CID; serve them.
    Ok(Vec<u8>),
    /// The bytes do not hash to the requested CID (a legacy provider-CID row); withhold.
    Mismatch(String),
    /// The object exceeds the served-object size cap; withhold rather than buffer it.
    TooLarge(u64),
    /// The object is genuinely absent (git reported it does not exist); try the next
    /// candidate. Distinct from `ReadErr` so an infra failure is never silently rendered
    /// as a clean not-found.
    Gone,
    /// A git subprocess failed to run (spawn/IO error, not a "no such object"). Logged at
    /// the handler layer and skipped — an infra failure must surface as an error, not a
    /// silent 404 for an authorized caller (INV-25 spirit, #173).
    ReadErr(String),
}

/// Immutable per-request context threaded into the gate.
struct ResolveCtx<'a> {
    caller: Option<&'a str>,
    caller_owned: &'a Option<String>,
    headers: &'a HeaderMap,
    peer: Option<std::net::SocketAddr>,
    cid_str: &'a str,
    /// Canonical base32 form of the requested CID (`cid.to_string()`), used by the
    /// serve-side integrity check to confirm the served bytes actually hash to the
    /// requested content address (F2, #173). Compared against the recomputed CID, NOT
    /// `cid_str` — a client may send an equivalent non-canonical multibase spelling.
    canonical_cid: &'a str,
}

/// Per-request walk budget + memos, shared across the provenance path and the legacy
/// scan so the fan-out ceiling and per-repo memoization span the whole request.
struct WalkState {
    walks: u32,
    /// Count of legacy (NULL-provenance) repos actually probed this request, so the
    /// scan can stop at `ipfs_max_legacy_probes` instead of fanning out to O(repos)
    /// `acquire` + `cat-file` (#173, F1, INV-10). Only the legacy path bumps it.
    probes: u32,
    /// Set when any cap (the legacy probe ceiling or the walk ceiling) cut the scan
    /// short. A truncated scan did NOT prove the object absent/unreadable everywhere,
    /// so the tail returns a retryable 503 rather than a definitive 404 (#173, F2).
    truncated: bool,
    allowed_blob_memo: HashMap<String, HashSet<String>>,
    allowed_tree_memo: HashMap<String, HashSet<String>>,
    reachable_ct_memo: HashMap<String, HashSet<String>>,
}

/// Gate ONE repo for ONE candidate oid and, if the caller may read it, serve it. The
/// SINGLE gate both the provenance path and the legacy scan call, so INV-11 (quarantine
/// hard-drops before visibility), INV-2 (the repo's own "/" gate), and the per-object
/// reachability walk hold identically on both paths (KTD5). Never re-resolves via
/// `authorize_repo_read`, whose fuzzy match could authorize a different physical row
/// than the one read (KTD2a).
// The per-repo gate genuinely needs the row, its rules, its quarantine bit, the oid,
// the request context, the shared walk budget, and whether this is the fan-out-bounded
// legacy scan; bundling them buys nothing over the existing threshold.
#[allow(clippy::too_many_arguments)]
async fn gate_and_serve(
    state: &AppState,
    repo: &crate::db::RepoRecord,
    rules: &[crate::db::VisibilityRule],
    quarantined: bool,
    sha256_hex: &str,
    ctx: &ResolveCtx<'_>,
    walk: &mut WalkState,
    // True only for the legacy NULL-provenance scan, which iterates every repo. The
    // provenance path targets one repo (no fan-out) and passes false, so it does not
    // consume the per-request probe budget below.
    legacy_scan: bool,
) -> GateOutcome {
    // Quarantine gate (INV-11): a quarantined mirror is hidden from every reader, owner
    // included, BEFORE any visibility check — so an owner whom visibility would Allow
    // still 404s.
    if quarantined {
        return GateOutcome::Skip;
    }
    // Repo-level "/" read gate against THIS row's own rules (INV-2, KTD2a).
    if visibility_check(rules, repo.is_public, &repo.owner_did, ctx.caller, "/") == Decision::Deny {
        return GateOutcome::Skip;
    }
    // Legacy-scan fan-out control (#173, F1/F3, INV-10). The legacy path probes every
    // root-visible repo, and the probe below (`acquire` — a possible cold-cache
    // Tigris fetch — plus a `git cat-file -t` subprocess) is the expensive part.
    // Cap it per request BEFORE that work runs, so an anonymous caller wielding a
    // CID from the public pins index cannot amplify one request into O(repos)
    // subprocesses. A legacy scan is inherently fan-out (unlike a targeted
    // provenance fetch), so EVERY legacy probe is charged to the source IP from the
    // first one, not just the ones past a free budget. A per-request-only budget
    // reset each request, leaving a NULL-provenance CID open to unbounded ACROSS-
    // request amplification: N requests spending N x budget cold `acquire` calls
    // against Tigris with zero limiter contact (#173, F3, jatmn). Charging the first
    // probe makes those requests accumulate against the per-IP `ipfs_rate_limiter`,
    // closing that path. The per-request cap below stays as the second bound (a
    // single request's ceiling). A spent quota is the same non-fatal Throttled as the
    // walk brake: keep scanning for a walk-free copy, and only a wholly-unservable
    // request becomes the 429. No resolvable key (a test oneshot with no peer/header)
    // skips the brake, as the walk brake does. The provenance path targets one repo
    // (no fan-out) and is exempt (`legacy_scan == false`).
    if legacy_scan {
        if walk.probes >= state.ipfs_max_legacy_probes {
            // Budget spent: stop probing and mark the scan truncated so the tail
            // reports an incomplete search (503), not a false 404 (#173, F2).
            walk.truncated = true;
            return GateOutcome::Skip;
        }
        if let Some(key) =
            crate::rate_limit::client_key(ctx.headers, ctx.peer, state.push_limiter_trust)
        {
            if !state.ipfs_rate_limiter.check(&key).await {
                return GateOutcome::Throttled;
            }
        }
        walk.probes += 1;
    }
    // Bound the per-repo acquire under `git_acquire_timeout_secs`: this gate runs while
    // the /ipfs walk permit is held (F5), so a hung or cold-Tigris acquire would otherwise
    // pin the global walk slot for the whole request. On expiry skip the repo (a public
    // copy may still serve) and mark the search truncated so a wholly-unserved request
    // tails to a retryable 503, never a false 404 (reopened the #174 P1-2 stall vector on
    // this path otherwise).
    let acquire_deadline = std::time::Duration::from_secs(state.config.git_acquire_timeout_secs);
    let repo_path = match tokio::time::timeout(
        acquire_deadline,
        state.repo_store.acquire(&repo.owner_did, &repo.name),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => return GateOutcome::Skip,
        Err(_elapsed) => {
            tracing::warn!(repo = %repo.name, "repo acquire timed out during /ipfs gate; skipping repo");
            walk.truncated = true;
            return GateOutcome::Skip;
        }
    };

    // Existence probe before any walk (random-CID spray must not trigger a walk on a
    // repo that lacks the object). Off the async runtime — it shells out to
    // `git cat-file -t`. Fail closed (skip) on a task panic.
    let obj_type = {
        let rp = repo_path.clone();
        let sha = sha256_hex.to_string();
        // Bound the blocking `git cat-file -t` under `git_service_timeout_secs`: this probe
        // runs while the /ipfs walk permit is held, so a wedged cat-file (corrupt pack, NFS
        // stall) would otherwise pin the global walk slot for the request's life. On timeout
        // free the slot (mark truncated -> retryable 503) and skip the repo. spawn_blocking
        // cannot be cancelled, so the child may linger on a blocking-pool thread, but it no
        // longer holds the walk permit.
        let probe_deadline = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        match tokio::time::timeout(
            probe_deadline,
            tokio::task::spawn_blocking(move || store::object_type(&rp, &sha)),
        )
        .await
        {
            Ok(Ok(Ok(Some(t)))) => t,
            Ok(Ok(Ok(None))) => return GateOutcome::Skip,
            Ok(Ok(Err(e))) => {
                tracing::warn!(repo = %repo.name, err = %e, "error checking git object type");
                return GateOutcome::Skip;
            }
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo.name, err = %e, "object-type probe task panicked; skipping repo");
                return GateOutcome::Skip;
            }
            Err(_elapsed) => {
                tracing::warn!(repo = %repo.name, "object-type probe timed out under the /ipfs walk permit; skipping repo");
                walk.truncated = true;
                return GateOutcome::Skip;
            }
        }
    };

    // Per-object gating applies only under a path-scoped rule (KTD4); otherwise the "/"
    // gate above is the whole story. A blob is gated on the caller's allowed-blob set, a
    // tree on the allowed-tree set (#135), a commit/tag on the repo's reachable
    // commit/tag set (#173) — each a full-history walk sharing the per-request cap and
    // per-walk IP quota.
    let path_scoped = has_path_scoped_rule(rules);
    let gated = path_scoped && matches!(obj_type.as_str(), "blob" | "tree" | "commit" | "tag");
    if gated {
        let already = match obj_type.as_str() {
            "blob" => walk.allowed_blob_memo.contains_key(&repo.id),
            "tree" => walk.allowed_tree_memo.contains_key(&repo.id),
            "commit" | "tag" => walk.reachable_ct_memo.contains_key(&repo.id),
            other => unreachable!("gated admits only blob/tree/commit/tag, got {other}"),
        };
        if !already {
            // Per-request fan-out ceiling (INV-10): once this many walks have run, skip
            // THIS walk-requiring candidate and keep scanning (a later walk-free copy
            // must still serve). `walks` is bumped only inside this block, so walk-free
            // candidates never consume budget.
            if walk.walks >= state.ipfs_max_history_walks {
                // The walk ceiling truncated the search: a later repo (possibly one that
                // authorizes this caller) is left unwalked, so absence is unproven —
                // record it so the tail returns 503, not a false 404 (#173, F2).
                walk.truncated = true;
                return GateOutcome::Skip;
            }
            // Brake each spawned walk on the source IP (#173, F3, INV-15), BEFORE
            // spending walk budget: a throttled candidate neither walks nor consumes
            // budget and must not end the request — skip it and keep scanning
            // (#173 review, F-C). No key (a test oneshot with no peer/header) skips the
            // brake, as the other IP brakes do. On the LEGACY path the probe brake
            // above already charged THIS candidate to the source (#173, F3, jatmn), so
            // the walk brake must not double-charge it: only the provenance path
            // (`legacy_scan == false`, no probe toll) charges here.
            if !legacy_scan {
                if let Some(key) =
                    crate::rate_limit::client_key(ctx.headers, ctx.peer, state.push_limiter_trust)
                {
                    if !state.ipfs_rate_limiter.check(&key).await {
                        return GateOutcome::Throttled;
                    }
                }
            }
            walk.walks += 1;

            let rp = repo_path.clone();
            let r = rules.to_vec();
            let is_public = repo.is_public;
            let owner = repo.owner_did.clone();
            let caller_for_walk = ctx.caller_owned.clone();
            let kind = obj_type.clone();
            // Every walk is the DURATION-BOUNDED twin (`run_bounded_git` teardown under
            // `git_service_timeout_secs`): the handler holds its /ipfs walk permit
            // across this spawn_blocking, and a held permit is only safe if no walk
            // child can outlive the deadline (#174 F5).
            let git_bin = state.git_bin.clone();
            let walk_timeout =
                std::time::Duration::from_secs(state.config.git_service_timeout_secs);
            let result = tokio::task::spawn_blocking(move || match kind.as_str() {
                "blob" => allowed_blob_set_for_caller_bounded(
                    &rp,
                    &git_bin,
                    walk_timeout,
                    &r,
                    is_public,
                    &owner,
                    caller_for_walk.as_deref(),
                ),
                "tree" => allowed_tree_set_for_caller_bounded(
                    &rp,
                    &git_bin,
                    walk_timeout,
                    &r,
                    is_public,
                    &owner,
                    caller_for_walk.as_deref(),
                ),
                "commit" | "tag" => reachable_commit_tag_oids_bounded(&rp, &git_bin, walk_timeout),
                other => unreachable!("gated admits only blob/tree/commit/tag, got {other}"),
            })
            .await;
            // Fail closed on a walk error or task panic: we cannot prove readability, so
            // skip rather than serve on an unproven gate.
            let set = match result {
                Ok(Ok(set)) => set,
                Ok(Err(e)) => {
                    tracing::warn!(repo = %repo.name, err = %e, "allowed-set walk failed; skipping repo");
                    return GateOutcome::Skip;
                }
                Err(e) => {
                    tracing::warn!(repo = %repo.name, err = %e, "allowed-set walk task panicked; skipping repo");
                    return GateOutcome::Skip;
                }
            };
            match obj_type.as_str() {
                "blob" => walk.allowed_blob_memo.insert(repo.id.clone(), set),
                "tree" => walk.allowed_tree_memo.insert(repo.id.clone(), set),
                _ => walk.reachable_ct_memo.insert(repo.id.clone(), set),
            };
        }
        let in_set = match obj_type.as_str() {
            "blob" => walk.allowed_blob_memo.get(&repo.id),
            "tree" => walk.allowed_tree_memo.get(&repo.id),
            _ => walk.reachable_ct_memo.get(&repo.id),
        }
        .is_some_and(|set| set.contains(sha256_hex));
        if !in_set {
            return GateOutcome::Skip;
        }
    }

    // Passed the gate — bound the object, read it OFF the async worker, and verify the
    // content address, all before any byte egresses. F6 (#173): read_object_content runs a
    // blocking `git cat-file` and buffers the whole object; called directly on the Axum
    // worker (the type-probe and walk are already off-worker) it blocks a runtime thread,
    // and unbounded it can exhaust memory for a large public blob (enumerable from the pins
    // index). Precheck the SIZE and run size + read + verify inside spawn_blocking. A
    // content-addressed serve cannot verify a STREAMED body (the digest is known only after
    // the last byte, by which point the prefix has already egressed), so we never stream:
    // buffer-verify-then-serve up to the cap and withhold anything larger. F2's integrity
    // check moves in here too, so no unverified bytes are ever assembled into a response.
    let max_bytes = state.ipfs_max_served_object_bytes;
    let read_repo = repo_path.clone();
    let read_sha = sha256_hex.to_string();
    let read_type = obj_type.clone();
    let want_cid = ctx.canonical_cid.to_string();
    // Bound the blocking size+read+verify under `git_service_timeout_secs` (same rationale
    // as the object-type probe): a hung cat-file must not pin the held /ipfs walk permit.
    let read_deadline = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    let read = tokio::time::timeout(
        read_deadline,
        tokio::task::spawn_blocking(move || -> ServedRead {
            match store::object_size(&read_repo, &read_sha) {
                Ok(Some(size)) if size > max_bytes => return ServedRead::TooLarge(size),
                Ok(Some(_)) => {}
                // git ran and reported no such object (or an unparseable size): genuine
                // not-found for this candidate.
                Ok(None) => return ServedRead::Gone,
                // git itself failed to run: an infra failure, not a not-found.
                Err(e) => return ServedRead::ReadErr(e.to_string()),
            }
            let content = match store::read_object_content(&read_repo, &read_sha, &read_type) {
                Ok(c) => c,
                Err(e) => return ServedRead::ReadErr(e.to_string()),
            };
            let served = gitlawb_core::cid::Cid::from_git_object_bytes(&content).to_string();
            if served != want_cid {
                return ServedRead::Mismatch(served);
            }
            ServedRead::Ok(content)
        }),
    )
    .await;
    let served_read = match read {
        Ok(Ok(sr)) => sr,
        Ok(Err(e)) => {
            tracing::warn!(repo = %repo.name, err = %e, "object read task panicked");
            walk.truncated = true;
            return GateOutcome::Skip;
        }
        Err(_elapsed) => {
            tracing::warn!(repo = %repo.name, "object read timed out under the /ipfs walk permit; skipping repo");
            walk.truncated = true;
            return GateOutcome::Skip;
        }
    };
    let content = match served_read {
        ServedRead::Ok(c) => c,
        ServedRead::TooLarge(size) => {
            tracing::warn!(
                repo = %repo.name, size, max = max_bytes,
                "withholding object: exceeds the served-object size cap (F6)"
            );
            #[cfg(test)]
            note_oversize_reject();
            return GateOutcome::Skip;
        }
        ServedRead::Mismatch(served) => {
            tracing::warn!(
                repo = %repo.name, requested = %ctx.canonical_cid, served = %served,
                "withholding object: served bytes do not hash to the requested CID (legacy provider-CID row?)"
            );
            return GateOutcome::Skip;
        }
        ServedRead::Gone => return GateOutcome::Skip,
        ServedRead::ReadErr(e) => {
            // Infra failure (git spawn/IO), NOT a not-found: mark the search truncated so
            // a wholly-unserved request tails to a retryable 503, never a definitive 404
            // for an authorized caller (INV-25 spirit — logging alone is not surfacing).
            tracing::warn!(repo = %repo.name, err = %e, "error reading git object content");
            walk.truncated = true;
            return GateOutcome::Skip;
        }
    };
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/octet-stream"),
    );
    resp_headers.insert(
        HeaderName::from_static("x-content-cid"),
        HeaderValue::from_str(ctx.cid_str).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    resp_headers.insert(
        HeaderName::from_static("x-git-hash"),
        HeaderValue::from_str(sha256_hex).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    GateOutcome::Served((StatusCode::OK, resp_headers, content).into_response())
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

// Test-only INV-10 cost counter (F3, U3/U7): how many times the legacy NULL-provenance
// scan built its O(repos) preload (`scan_ctx`) this test. The F3 admission peek must
// shed an already-throttled source BEFORE the preload runs, so a throttled replay
// leaves the count at 0 (the guard is driven both ways). Thread-local because
// `#[sqlx::test]` drives each test on its own current-thread runtime, so the async
// preload runs on the test's thread — no cross-test races on a shared global.
#[cfg(test)]
thread_local! {
    static PRELOAD_QUERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_preload_queries() {
    PRELOAD_QUERIES.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn preload_queries() -> usize {
    PRELOAD_QUERIES.with(|c| c.get())
}

#[cfg(test)]
fn bump_preload_queries() {
    PRELOAD_QUERIES.with(|c| c.set(c.get() + 1));
}

// Test-only INV-10 cost counter (F6, U6/U7): how many times the serve path withheld an
// object because it exceeded `ipfs_max_served_object_bytes`. The bounded read must reject
// an oversized object rather than buffer it on the worker; the counter is the both-ways
// guard (a removed size precheck stops incrementing it and serves the oversized object).
// Set from the match arm after `spawn_blocking` resolves, i.e. on the test's runtime
// thread, so the thread-local is read on the same thread it is written.
#[cfg(test)]
thread_local! {
    static OVERSIZE_REJECTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_oversize_rejects() {
    OVERSIZE_REJECTS.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn oversize_rejects() -> usize {
    OVERSIZE_REJECTS.with(|c| c.get())
}

#[cfg(test)]
fn note_oversize_reject() {
    OVERSIZE_REJECTS.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
mod tests {
    //! #174 P1-3 (U3): the public `GET /ipfs/{cid}` walk carries bounded CONCURRENCY
    //! admission (a global pool + per-source sub-cap) held through the `spawn_blocking`
    //! walk, plus a per-IP route rate limit. These are handler-layer proofs: mount the
    //! real handler/router, drive one request, assert the exact 503 shed, then name the
    //! mutation that turns each RED. The per-source key resolves an IP only (`Some(ip)`
    //! vs `None`), never a DID — both arms are driven so neither is vacuous. The
    //! CID-resolution / visibility-gate behavior of the handler itself is covered by the
    //! `#[sqlx::test]` suite in `test_support.rs`.

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

    /// Retain-through-blocking (#174 F5, the load-bearing async property, on the
    /// NEWLY-BOUNDED TREE path): the walk admission is held until the `spawn_blocking`
    /// walk actually RETURNS, not when a tokio timeout fires. The requested CID
    /// resolves to a TREE object under a path-scoped rule, so the gate runs
    /// `allowed_tree_set_for_caller_bounded` — the walk this integration converts to
    /// `run_bounded_git` — rather than the blob walk #174 already proved. With the
    /// global pool at size 1, drive a request until its walk (a fake git that hangs on
    /// `rev-list`) is in flight; the slot must stay held (`available_permits() == 0`)
    /// and a replacement from a DIFFERENT source must shed 503 for as long as the
    /// blocking walk runs — even though the request future is only `.await`ing the
    /// blocking join. When the blocking walk ends the permit frees and a replacement
    /// is admitted. The permit lives INSIDE the handler across the blocking `.await`;
    /// move it out (drop before the walk) and the replacement would be admitted while
    /// the walk still burns a blocking thread (the bug this guards).
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_walk_permit_held_through_bounded_tree_walk(pool: sqlx::PgPool) {
        use std::process::Command;

        let tmp = tempfile::TempDir::new().unwrap();
        let revlist_pid = tmp.path().join("revlist.pid");
        // Fake git for the /ipfs TREE walk only (object_type/read_object_content use
        // the real `git`, so the tree must genuinely exist below). `rev-parse`
        // resolves (so the lenient enumeration appends HEAD) and `rev-list` records
        // its pid then sleeps ~6s so the walk BLOCKS deterministically inside
        // `run_bounded_git`. The sleep bounds the walk so a broken fix cannot wedge
        // the suite.
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

        let owner = "z6ipfstree";
        let name = "iptree";
        state
            .db
            .upsert_mirror_repo(owner, name, "/unused", None, false)
            .await
            .unwrap();
        let rec = state.db.get_repo(owner, name).await.unwrap().unwrap();
        // The exact bare path the handler's `acquire` resolves. Build a REAL SHA-256
        // bare repo there with a committed `src/` directory, so real
        // `git cat-file -t <oid>` classifies the requested object as a TREE and the
        // handler routes into the tree-walk arm of the gate.
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
        std::fs::write(
            work.join("src/secret.txt"),
            b"ipfs tree walk retain proof\n",
        )
        .unwrap();
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
        // The `src` directory's TREE oid — the object the request asks for.
        let tree_oid = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD:src"])
                .current_dir(&work)
                .output()
                .expect("git rev-parse runs");
            assert!(out.status.success(), "rev-parse failed");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        // Precondition: real git classifies the object as a TREE (so the handler
        // reaches the tree-walk arm, not the blob arm or an early `continue`).
        assert_eq!(
            crate::git::store::object_type(&bare, &tree_oid)
                .unwrap()
                .as_deref(),
            Some("tree"),
            "the seeded sha256 tree must exist so the handler reaches the tree walk"
        );
        // Pin the tree's content CID WITH provenance so the resolver targets this one
        // repo (no legacy scan). A real pin CID digests the raw object content, not
        // the git oid, so build it exactly as the pin path does (#173).
        let (_ty, raw) = crate::git::store::read_object(&bare, &tree_oid)
            .unwrap()
            .expect("tree object readable");
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(&raw).to_string();
        state
            .db
            .record_pinned_cid(&tree_oid, &cid, Some(&rec.id))
            .await
            .unwrap();
        // A path-scoped rule so has_path_scoped_rule() is true (the tree-gate branch)
        // without denying the "/" gate on the public repo.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/src/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkF5IpfsTreeReaderAAAAAAAAAAAAAAAAAAAA".to_string()],
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
        // Drive until the fake git's rev-list records its pid — the TREE walk is now in
        // the blocking pool and the request future is `.await`ing its join, holding the
        // walk permit. Stop polling the instant the future completes (re-polling a
        // completed oneshot panics).
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

        // Load-bearing: while the blocking TREE walk runs, the slot is HELD and a
        // replacement from a DIFFERENT source sheds 503 — proving the permit is
        // retained across the spawn_blocking join, not freed by a tokio timeout.
        assert_eq!(
            sem.available_permits(),
            0,
            "the walk slot must be held while the spawn_blocking tree walk runs"
        );
        let peer2: SocketAddr = "203.0.113.82:5000".parse().unwrap();
        let resp = router.clone().oneshot(make_req(peer2)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a replacement must shed 503 while the prior request's blocking tree walk still runs"
        );

        // Drop the in-flight request; the detached blocking walk keeps running (a
        // spawn_blocking cannot be cancelled), but the permit is a handler local, so
        // dropping the future releases it once the blocking join is abandoned. Either
        // way, kill the sleeping child so the slot frees promptly and poll for
        // recovery — the point already proven above is that the slot stayed held for
        // the duration of the blocking work.
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
