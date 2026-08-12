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
/// `GET /ipfs/{cid}` request may spawn. The route brake (`ipfs_rate_limiter`, charged
/// once per request by the middleware) caps request RATE, and the per-walk charge on
/// the separate `ipfs_work_rate_limiter` bounds the walk work across requests, but
/// within ONE request the object can exist under path-scoped rules in many repos, and
/// each distinct repo pays its own `spawn_blocking` walk (the memo only dedups the same
/// repo). Without a ceiling a single request fans out to O(repos) walks — an
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

/// How many repo rows the legacy scan pulls from the database per keyset page
/// (#173, jatmn, INV-10). The probe ceiling above bounds the EXPENSIVE work, but
/// it only starts counting once a probe runs; before that, loading the node's whole
/// repo inventory and every matching visibility rule is itself work proportional to
/// the node's size, bought by one anonymous GET while the scarce walk permits are
/// held. Paging makes the database-facing selection bounded too: the scan reads one
/// page, gates it, and asks for another only while its probe and visit budgets have
/// room. Not an operator knob — sized so a full default-budget scan (256 probes)
/// costs two pages, and a field on `AppState` for the same test-seam reason as the
/// sibling caps.
pub(crate) const LEGACY_SCAN_PAGE_ROWS: usize = 128;

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

/// Keyset pager for the legacy (NULL-provenance) scan fallback in `get_by_cid`.
///
/// Replaces the old "load every repo, every matching rule, and the whole node's
/// quarantine set up front" preload (#173, jatmn, INV-10). That preload ran before
/// the probe ceiling had spent a single probe, so an anonymous GET for a CID
/// enumerable from the public pins index bought allocation and queries proportional
/// to the node's entire repo and rule inventory, with the scarce walk permits held
/// throughout. Here the scan reads one bounded page at a time and asks for another
/// only while its probe and visit budgets have room.
///
/// Per REQUEST, not per oid candidate. `get_by_cid` may try several oids under one
/// CID, and a pager that reset between them would restore the full fan-out; instead
/// the cursor, the fetched rows, and their rules persist across the whole request,
/// so a later candidate re-reads the pages already paid for and only ever extends
/// the cursor forward.
#[derive(Default)]
struct LegacyScanPager {
    /// Rows fetched so far this request, in `(created_at, id)` ASC order. Bounded by
    /// the budgets that gate the next fetch, never by the node's repo count.
    rows: Vec<crate::db::ScanRepoRow>,
    /// Visibility rules for the fetched rows only, keyed by repo id.
    rules: HashMap<String, Vec<crate::db::VisibilityRule>>,
    /// Keyset cursor: the `(created_at, id)` of the last row fetched, `None` before
    /// the first page. Both halves are immutable columns, so paging is exact.
    cursor: Option<(String, String)>,
    /// Set once a short page proves no rows remain after the cursor.
    exhausted: bool,
}

impl LegacyScanPager {
    /// Fetch the next page and its rules, appending both.
    ///
    /// INV-22: these awaits happen while the scarce walk admission is held and the
    /// pool sets no `statement_timeout`, so each is clamped to the remaining request
    /// budget exactly as the old preload's queries were. A timeout on the rules query
    /// FAILS CLOSED — it returns the retryable budget 503 rather than letting the scan
    /// continue against an empty rule map and serve a path-scoped object to a caller
    /// the rules would have denied.
    async fn fetch_next_page(
        &mut self,
        state: &AppState,
        request_deadline: std::time::Instant,
        cid_str: &str,
    ) -> Result<()> {
        #[cfg(test)]
        bump_preload_queries();
        let budget_secs = state.config.ipfs_request_budget_secs;
        let budget_shed = || {
            AppError::Overloaded(format!(
                "ipfs scan incomplete (budget) for CID {cid_str}; retry shortly"
            ))
        };
        let after = self
            .cursor
            .as_ref()
            .map(|(created_at, id)| (created_at.as_str(), id.as_str()));
        let page = match tokio::time::timeout(
            request_deadline.saturating_duration_since(std::time::Instant::now()),
            state
                .db
                .list_repos_page_for_scan(after, state.ipfs_legacy_scan_page_rows as i64),
        )
        .await
        {
            Ok(Ok(page)) => page,
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {
                tracing::warn!(
                    budget_secs,
                    "/ipfs list_repos_page_for_scan exceeded the request budget \
                     (GITLAWB_IPFS_REQUEST_BUDGET_SECS); shedding a retryable 503 and freeing the walk permit"
                );
                return Err(budget_shed());
            }
        };
        #[cfg(test)]
        note_scan_rows(page.len());
        if page.len() < state.ipfs_legacy_scan_page_rows {
            self.exhausted = true;
        }
        if page.is_empty() {
            return Ok(());
        }
        let last = page.last().expect("non-empty page has a last row");
        self.cursor = Some((last.created_at_key.clone(), last.repo.id.clone()));
        let repo_ids: Vec<String> = page.iter().map(|r| r.repo.id.clone()).collect();
        let rules = match tokio::time::timeout(
            request_deadline.saturating_duration_since(std::time::Instant::now()),
            state.db.list_visibility_rules_for_repos(&repo_ids),
        )
        .await
        {
            Ok(Ok(rules)) => rules,
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {
                tracing::warn!(
                    budget_secs,
                    "/ipfs list_visibility_rules_for_repos exceeded the request budget \
                     (GITLAWB_IPFS_REQUEST_BUDGET_SECS); denying (fail closed) and freeing the walk permit"
                );
                return Err(budget_shed());
            }
        };
        self.rules.extend(rules);
        self.rows.extend(page);
        Ok(())
    }
}

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
/// clamped to the remainder. The probe and content-read subprocesses each ALSO
/// run under their own deadline, the lesser of `git_service_timeout_secs` and the
/// remaining budget, reaped by process-group teardown at that deadline, so a hung
/// `cat-file` cannot hold the request's walk slot past it.
///
/// Residual, still true: the probe's object-store readability check
/// (`store::object_store_readable`, reached on the `missing` branch that a
/// random-CID spray drives) is a synchronous `read_dir` + `File::open` sweep with
/// no deadline and nothing to reap, so a wedged filesystem can still hold the
/// walk slot past the deadline. Same class as the D-state git survivor residual.
///
/// Scope: this closes the direct unauthenticated scan, including the dangling
/// case. A stale-public mirror row still serves withheld content (tracked
/// separately, #124).
///
/// One `/ipfs` request's walk admission: the global pool permit plus the
/// optional per-source sub-permit, both RAII (#174 U1).
///
/// Held behind an `Arc` whose clones go into every `spawn_blocking` walk this
/// request runs, so the permits release only when the last clone drops — the
/// handler's, or an abandoned/panicking closure's, whichever outlives the other.
/// Admission therefore tracks real blocking-thread occupancy rather than the
/// lifetime of the future that requested it.
struct WalkAdmission {
    _global: tokio::sync::OwnedSemaphorePermit,
    _per_source: Option<crate::rate_limit::PerCallerPermit>,
}

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
    let global_permit = state
        .git_ipfs_walk_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            tracing::warn!("/ipfs walk concurrency cap reached; shedding request with 503");
            AppError::Overloaded("ipfs service at capacity, retry shortly".into())
        })?;
    let source_key = crate::rate_limit::client_key(&headers, peer, state.push_limiter_trust);
    let caller_permit = match &source_key {
        Some(ip) => Some(state.git_ipfs_walk_per_caller.try_acquire(ip).ok_or_else(|| {
            tracing::warn!(key = %ip, "/ipfs per-source walk cap reached; shedding request with 503");
            AppError::Overloaded("ipfs service at capacity for this source, retry shortly".into())
        })?),
        None => None,
    };
    // Share the admission rather than holding it as a handler local (#174 U1). A
    // clone goes into every `spawn_blocking` closure below, so the permits release
    // only when the LAST holder drops. That makes the two failure directions one
    // case: a client disconnect drops the handler's clone while the abandoned
    // closure's clone keeps the slot taken for as long as its git child runs, and a
    // panicking closure drops its clone while the handler's keeps the slot taken.
    //
    // Deliberately NOT a move-and-return shuttle. That shape is correct only if
    // every arm continuing the loop re-binds the returned value, which the compiler
    // cannot enforce — including the absent-object arm `Ok(Ok(None)) => continue`
    // that a random-CID scan takes on nearly every iteration — and it forces a
    // second decision about the arms where a panic destroys the moved-in permits.
    let admission = std::sync::Arc::new(WalkAdmission {
        _global: global_permit,
        _per_source: caller_permit,
    });

    // Caller DID (owned): the `spawn_blocking` closures below cannot borrow the
    // handler's `auth` extension, so resolve it once here.
    let caller_owned = auth.as_ref().map(|e| e.0 .0.as_str().to_string());

    // Every DB await from here on runs while the scarce walk permits are ALREADY
    // held, and the pool sets no statement_timeout, so an unclamped query blocked in
    // Postgres would pin those slots for the whole stall, past the request budget,
    // and capacity-503 later requests from any unauthenticated caller (#174 F2).
    // Each one is clamped to the request deadline; returning on the timeout arm
    // RAII-drops `admission`, which is the whole mechanism, so no new state is
    // needed. Defined once here so the clamp sites on the provenance path share one
    // definition (the legacy-scan preload below keeps its own `budget_shed` inside
    // its nested scope).
    let budget_shed = || {
        AppError::Overloaded(format!(
            "ipfs scan incomplete (budget) for CID {cid_str}; retry shortly"
        ))
    };
    let remaining = || request_deadline.saturating_duration_since(std::time::Instant::now());

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
    let oids = match tokio::time::timeout(remaining(), state.db.oids_for_cid(&canonical_cid)).await
    {
        Ok(Ok(v)) => v,
        // Bare conversion, never `AppError::Internal`: a connection-class sqlx failure
        // downcasts to `AppError::Db` and answers 503 `db_unavailable` rather than a 500
        // (#251). Every clamped site in this handler uses this arm for the same reason,
        // so a stalled pool and a closed pool stay distinguishable to the caller.
        Ok(Err(e)) => return Err(e.into()),
        Err(_elapsed) => {
            tracing::warn!(
                budget_secs = state.config.ipfs_request_budget_secs,
                "/ipfs oids_for_cid exceeded the request budget \
                 (GITLAWB_IPFS_REQUEST_BUDGET_SECS); shedding a retryable 503 and freeing the walk permit"
            );
            return Err(budget_shed());
        }
    };
    if oids.is_empty() {
        return Err(AppError::RepoNotFound(format!(
            "no git object found for CID {cid_str}"
        )));
    }
    let caller = caller_owned.as_deref();

    // Per-request walk budget + memos + throttle flag, shared by the provenance path
    // and the legacy scan so both honor the same fan-out ceiling, per-repo memo, and
    // IP brake. The caller is constant for one request, so `repo.id` alone keys the memo.
    let mut walk = WalkState {
        walks: 0,
        probes: 0,
        visits: 0,
        truncated_by: Vec::new(),
        deterministic_fault: false,
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
        request_deadline,
        admission: &admission,
    };

    // Legacy scan pager, advanced LAZILY only when a legacy NULL-provenance pin is hit
    // — the provenance path must never trigger it (that fan-out is exactly what
    // provenance removes, #173 round 2). Declared here, outside the oid loop, so its
    // cursor and its fetched rows are accounted per REQUEST: a per-candidate pager
    // would restore the very fan-out the paging removes.
    let mut pager = LegacyScanPager::default();

    for sha256_hex in &oids {
        // A pinned object records EVERY repo it was pinned from (#173 round 8, F1).
        // Resolve a PROVENANCED pin by trying each source repo (bounded to
        // MAX_PIN_SOURCES) through the SAME gate; the first that authorizes serves — no
        // scan fan-out. A shared object first pinned from a private/quarantined repo
        // still serves from a later PUBLIC source. Deterministic (ORDER BY on the
        // union), so no ordering can turn an authorized copy into a 404.
        let sources = match tokio::time::timeout(
            remaining(),
            state.db.pin_sources_for_oid(sha256_hex),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e.into()),
            Err(_elapsed) => {
                tracing::warn!(
                    budget_secs = state.config.ipfs_request_budget_secs,
                    "/ipfs pin_sources_for_oid exceeded the request budget \
                     (GITLAWB_IPFS_REQUEST_BUDGET_SECS); shedding a retryable 503 and freeing the walk permit"
                );
                return Err(budget_shed());
            }
        };
        // Provenance fast-path: try each recorded source repo through the SAME gate
        // (bounded to first-pinner + MAX_PIN_SOURCES). Empty for a legacy NULL-provenance
        // pin. The first source that authorizes serves — no scan fan-out on the common
        // path.
        for repo_id in &sources {
            // These three per-source lookups run while the scarce walk permits are
            // ALREADY held, exactly like the legacy scan's preload below, so they carry
            // the same clamp (#174 F6/KTD-5). The pool sets no statement_timeout, so an
            // unclamped query blocked in Postgres would pin a walk slot for the whole
            // stall, past the request budget, and capacity-503 later requests. Returning
            // here drops the permits. The quarantine bit and the visibility rules are
            // both access control, so a timeout must DENY rather than fall through with
            // an empty answer (FAIL CLOSED).
            let repo = match tokio::time::timeout(remaining(), state.db.get_repo_by_id(repo_id))
                .await
            {
                Ok(Ok(Some(r))) => r,
                // A source repo is gone: skip it; a later source or the scan fallback
                // below may still resolve.
                Ok(Ok(None)) => continue,
                Ok(Err(e)) => return Err(e.into()),
                Err(_elapsed) => {
                    tracing::warn!(
                        budget_secs = state.config.ipfs_request_budget_secs,
                        "/ipfs get_repo_by_id exceeded the request budget \
                         (GITLAWB_IPFS_REQUEST_BUDGET_SECS); shedding a retryable 503 and freeing the walk permit"
                    );
                    return Err(budget_shed());
                }
            };
            let quarantined = match tokio::time::timeout(
                remaining(),
                state.db.is_repo_quarantined(repo_id),
            )
            .await
            {
                Ok(Ok(q)) => q,
                Ok(Err(e)) => return Err(e.into()),
                Err(_elapsed) => {
                    tracing::warn!(
                        budget_secs = state.config.ipfs_request_budget_secs,
                        "/ipfs is_repo_quarantined exceeded the request budget \
                         (GITLAWB_IPFS_REQUEST_BUDGET_SECS); denying (fail closed) and freeing the walk permit"
                    );
                    return Err(budget_shed());
                }
            };
            let rules_map = match tokio::time::timeout(
                remaining(),
                state
                    .db
                    .list_visibility_rules_for_repos(std::slice::from_ref(repo_id)),
            )
            .await
            {
                Ok(Ok(rules)) => rules,
                Ok(Err(e)) => return Err(e.into()),
                Err(_elapsed) => {
                    tracing::warn!(
                        budget_secs = state.config.ipfs_request_budget_secs,
                        "/ipfs per-source list_visibility_rules_for_repos exceeded the request budget \
                         (GITLAWB_IPFS_REQUEST_BUDGET_SECS); denying (fail closed) and freeing the walk permit"
                    );
                    return Err(budget_shed());
                }
            };
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
        //   - marked  -> a `record_pin_source` for this object failed outright (U3, #173).
        //               `record_pin_source` is best effort at every pin call site, so a
        //               non-empty below-cap set is NOT self-evidently complete: an object
        //               first pinned from a PRIVATE repo and later pushed from a PUBLIC
        //               one whose record failed names only the private source. The
        //               durable `pin_sources_incomplete` marker is the node's own record
        //               that a source is missing, so the fallback stays available for
        //               exactly those objects instead of 404ing a servable public copy.
        // Only a set with NONE of these three signals is treated as complete (every
        // recorded source was just tried), so it skips the scan and lets the tail 404, and
        // ordinary denials never fan out to O(repos) (INV-10 / F3). Both extra queries run
        // only on a provenance MISS (we return above on Served) by a caller that still has
        // work budget, so neither costs the serve path nor a shed caller, and the fallback
        // is not an authorization bypass: the scan gates every repo
        // through the SAME per-caller gate, so a caller who may not read the object is
        // still denied.
        //
        // F3 (#173, INV-10/INV-15): peek the per-IP WORK-budget limiter WITHOUT
        // consuming a token so an already-throttled source is shed BEFORE the
        // O(repos) preload; the consuming per-probe charge inside gate_and_serve is
        // left UNCHANGED (it is load-bearing for the across-request bound), so this
        // adds no double-charge. This peeks `ipfs_work_rate_limiter`, the SAME bucket
        // the per-probe charge below debits — NOT the route limiter (`ipfs_rate_limiter`,
        // charged once per request by the middleware): peeking the route bucket here
        // would re-shed a request the route already admitted (R6, U5).
        //
        // The peek runs BEFORE the two marker queries (#173 round 11, F5): shedding is
        // the whole point of a peek, so a spent-budget caller should not pay two
        // lookups per request first. It stays AFTER the provenance walk, so no caller
        // who could have been served is shed. The one caller this moves: a spent-budget
        // caller whose source set turns out COMPLETE now takes the 429 tail instead of
        // the 404 tail. That is the honest answer (its search never ran), and it drops
        // an oracle, since the old order let a throttled caller tell a complete source
        // set from an incomplete one by 404 vs 429.
        if let Some(key) =
            crate::rate_limit::client_key(rctx.headers, rctx.peer, state.push_limiter_trust)
        {
            if state.ipfs_work_rate_limiter.is_throttled(&key).await {
                throttled = true;
                continue;
            }
        }
        let needs_scan = sources.is_empty()
            || {
                #[cfg(test)]
                bump_marker_queries();
                let at_cap = match tokio::time::timeout(remaining(), async {
                    #[cfg(test)]
                    stall_marker_query(MarkerQuery::AtCap).await;
                    state.db.pin_sources_at_cap(sha256_hex).await
                })
                .await
                {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_elapsed) => {
                        tracing::warn!(
                        budget_secs = state.config.ipfs_request_budget_secs,
                        "/ipfs pin_sources_at_cap exceeded the request budget \
                         (GITLAWB_IPFS_REQUEST_BUDGET_SECS); shedding a retryable 503 and freeing the walk permit"
                    );
                        return Err(budget_shed());
                    }
                };
                at_cap
                    || match tokio::time::timeout(remaining(), async {
                        #[cfg(test)]
                        stall_marker_query(MarkerQuery::Incomplete).await;
                        state.db.pin_sources_incomplete(sha256_hex).await
                    })
                    .await
                    {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_elapsed) => {
                            tracing::warn!(
                            budget_secs = state.config.ipfs_request_budget_secs,
                            "/ipfs pin_sources_incomplete exceeded the request budget \
                             (GITLAWB_IPFS_REQUEST_BUDGET_SECS); shedding a retryable 503 and freeing the walk permit"
                        );
                            return Err(budget_shed());
                        }
                    }
            };
        if needs_scan {
            // Walk the candidate repos one bounded page at a time. Pages already
            // fetched by an earlier oid candidate are re-read from `pager.rows` for
            // free; only the tail of the scan costs another query.
            let mut idx = 0usize;
            loop {
                if idx == pager.rows.len() {
                    if pager.exhausted {
                        break;
                    }
                    // Buying another page is only worth its query if a row on it could
                    // still reach a verdict, and a verdict needs the probe and the
                    // acquire these ceilings are refusing. Spent means stop reading —
                    // this is the check that keeps the DB-facing selection bounded, so
                    // a one-probe request cannot pull the node's whole inventory.
                    //
                    // Note what is deliberately NOT a stop condition: a page of pure
                    // denials. A quarantined row or a visibility deny costs no probe,
                    // so paging must continue past them or a public object buried
                    // behind many private repos would falsely 404. The budgets above,
                    // not a page count, are what bound that case.
                    //
                    // Stopping here leaves every unread repo unproven, so it TAINTS:
                    // the tail sheds a retryable 503 naming the ceiling, never a
                    // definitive 404 (#173, F2).
                    if walk.probes >= state.ipfs_max_legacy_probes {
                        walk.taint("probe-ceiling");
                        break;
                    }
                    if walk.visits >= state.config.ipfs_max_repo_visits {
                        walk.taint("visit-ceiling");
                        break;
                    }
                    pager
                        .fetch_next_page(&state, request_deadline, &cid_str)
                        .await?;
                    if idx == pager.rows.len() {
                        break;
                    }
                }
                let row = &pager.rows[idx];
                idx += 1;
                let rules = pager
                    .rules
                    .get(&row.repo.id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                match gate_and_serve(
                    &state,
                    &row.repo,
                    rules,
                    row.quarantined,
                    sha256_hex,
                    &rctx,
                    &mut walk,
                    true,
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

    // Nothing served — four distinct tails, in precedence order:
    //  1. A candidate repo is persistently broken (a corrupt repo, a bad `.git/config`),
    //     and that was the SOLE reason nothing served → terminal, non-retryable 500
    //     (#174 F5/U4). A retry cannot fix it, and a 503 here would invite a conformant
    //     client to retry-storm a fresh `cat-file` per attempt against the broken repo.
    //     Gated on nothing else having tainted: when a transient skip co-occurs, the
    //     object may live in the repo that was skipped transiently, so a retry CAN
    //     surface it and the retryable 503 below is the honest answer. The body is
    //     opaque; the raw git detail was logged at the probe and never reaches the client.
    //  2. The scan was cut short (a cap, the request budget, or a transient stage
    //     failure), so the object was NOT proven absent/unreadable everywhere → 503,
    //     retryable, and explicitly NOT a definitive not-found (#173 F2). This outranks
    //     the throttle: an incomplete search must not masquerade as a clean rate-limit
    //     outcome. The message names the truncation sources so an operator can map the
    //     shed to the right knob or backend, and carries no object/OID/metadata.
    //  3. A walk-requiring candidate was skipped for a spent IP quota while the scan
    //     otherwise completed → 429 (the brake bit; a cheaper copy was sought first).
    //  4. A full scan under the caps found nothing readable → opaque 404, uniform with
    //     a genuine not-found and a visibility denial.
    if walk.deterministic_fault && walk.truncated_by.is_empty() {
        return Err(AppError::Git(
            "ipfs object probe could not complete: a candidate repository is corrupt".into(),
        ));
    }
    if !walk.truncated_by.is_empty() {
        return Err(AppError::SearchIncomplete(format!(
            "CID {cid_str} search incomplete ({}) — retry",
            walk.truncated_by.join("+")
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
    /// One absolute clock for the whole admitted request (#174 F3). No stage starts
    /// once it is exhausted, and the acquire wait plus the probe/walk/read child
    /// deadlines clamp to the remainder, so an admitted request cannot hold its scarce
    /// walk slot by drawing a fresh per-stage timeout on every candidate.
    request_deadline: std::time::Instant,
    /// The request's walk admission (#174 U1). A clone goes into every `spawn_blocking`
    /// below, so the permits release only when the last holder drops — the handler's
    /// clone, or an abandoned or panicking closure's, whichever outlives the other.
    admission: &'a std::sync::Arc<WalkAdmission>,
}

/// Per-request walk budget + memos, shared across the provenance path and the legacy
/// scan so the fan-out ceiling and per-repo memoization span the whole request.
struct WalkState {
    walks: u32,
    /// Count of legacy (NULL-provenance) repos actually probed this request, so the
    /// scan can stop at `ipfs_max_legacy_probes` instead of fanning out to O(repos)
    /// `acquire` + `cat-file` (#173, F1, INV-10). Only the legacy path bumps it.
    probes: u32,
    /// Count of repos this request has VISITED: every candidate that got past the
    /// visibility gate and reached the acquire stage, on the provenance path as well
    /// as the legacy scan (#174 F2). Every visit costs an acquire (worst case a full
    /// Tigris archive download on a cache miss) plus a `cat-file` probe, so one
    /// request can trigger at most `ipfs_max_repo_visits` object-store fetches. This
    /// is the broader of the two ceilings: the probe ceiling above bounds only the
    /// legacy scan's fan-out, and a provenance-only request never reaches it.
    visits: usize,
    /// Why the scan reached no verdict on one or more candidates: a cap cut it short
    /// (the legacy probe ceiling, the walk ceiling, the request budget) or a stage
    /// failed transiently (acquire, probe, walk, read). A truncated scan did NOT prove
    /// the object absent/unreadable everywhere, so the tail returns a retryable 503
    /// rather than a definitive 404 (#173 F2), and the sources name the knob or backend
    /// the operator should look at (#174 F2). Deduplicated, so one source appears once
    /// however many candidates hit it.
    truncated_by: Vec<&'static str>,
    /// Set when a candidate repo is persistently broken (a corrupt repo, a bad
    /// `.git/config`; #174 F5/U4). It yields no absence verdict either, but a retry
    /// cannot fix it, so the tail sheds a terminal 500 instead of the retryable 503 —
    /// and only when nothing else tainted, so one broken repo never converts a
    /// retryable outcome into a terminal one.
    deterministic_fault: bool,
    allowed_blob_memo: HashMap<String, HashSet<String>>,
    allowed_tree_memo: HashMap<String, HashSet<String>>,
    reachable_ct_memo: HashMap<String, HashSet<String>>,
}

impl WalkState {
    /// Record that a candidate was skipped WITHOUT a verdict, naming the stage.
    fn taint(&mut self, source: &'static str) {
        if !self.truncated_by.contains(&source) {
            self.truncated_by.push(source);
        }
    }

    /// Remaining request budget, or `None` once it is spent. A stage is never started
    /// with zero remaining: the call site taints "budget" and stops, leaving this and
    /// every later candidate unproven rather than reporting a false absence.
    fn budget_left(
        &mut self,
        ctx: &ResolveCtx<'_>,
        budget_secs: u64,
        repo_name: &str,
        stage: &'static str,
    ) -> Option<std::time::Duration> {
        let left = ctx
            .request_deadline
            .saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            tracing::warn!(
                repo = %repo_name,
                stage,
                budget_secs,
                "/ipfs request budget exhausted before the stage \
                 (GITLAWB_IPFS_REQUEST_BUDGET_SECS); stopping without a verdict"
            );
            self.taint("budget");
            return None;
        }
        Some(left)
    }
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
    // probe makes those requests accumulate against the per-IP `ipfs_work_rate_limiter`
    // (the resolver's WORK bucket, separate from the once-per-request route brake
    // `ipfs_rate_limiter` — R6, U5), closing that path. The per-request cap below stays
    // as the second bound (a single request's ceiling). A spent quota is the same non-fatal Throttled as the
    // walk brake: keep scanning for a walk-free copy, and only a wholly-unservable
    // request becomes the 429. No resolvable key (a test oneshot with no peer/header)
    // skips the brake, as the walk brake does. The provenance path targets one repo
    // (no fan-out) and is exempt (`legacy_scan == false`).
    if legacy_scan {
        if walk.probes >= state.ipfs_max_legacy_probes {
            // Budget spent: stop probing and mark the scan truncated so the tail
            // reports an incomplete search (503), not a false 404 (#173, F2).
            walk.taint("probe-ceiling");
            return GateOutcome::Skip;
        }
        if let Some(key) =
            crate::rate_limit::client_key(ctx.headers, ctx.peer, state.push_limiter_trust)
        {
            if !state.ipfs_work_rate_limiter.check(&key).await {
                return GateOutcome::Throttled;
            }
        }
        walk.probes += 1;
    }
    // Visit ceiling (#174 F2), checked before the acquire it bounds. On exhaustion the
    // scan STOPS on this candidate without a verdict: there is no cheaper way to reach
    // one, since a verdict needs the acquire and probe this ceiling is refusing.
    if walk.visits >= state.config.ipfs_max_repo_visits {
        tracing::warn!(
            ceiling = state.config.ipfs_max_repo_visits,
            repo = %repo.name,
            "/ipfs request hit the per-request repo-visit ceiling \
             (GITLAWB_IPFS_MAX_REPO_VISITS); skipping repo without a verdict"
        );
        walk.taint("visit-ceiling");
        return GateOutcome::Skip;
    }
    walk.visits += 1;

    // Budget gate for the acquire stage (#174 F3).
    let Some(acquire_budget) = walk.budget_left(
        ctx,
        state.config.ipfs_request_budget_secs,
        &repo.name,
        "repo acquire",
    ) else {
        return GateOutcome::Skip;
    };
    // Bound the per-repo acquire under `git_acquire_timeout_secs`: this gate runs while
    // the /ipfs walk permit is held (F5), so a hung or cold-Tigris acquire would otherwise
    // pin the global walk slot for the whole request. On expiry skip the repo (a public
    // copy may still serve) and mark the search truncated so a wholly-unserved request
    // tails to a retryable 503, never a false 404 (reopened the #174 P1-2 stall vector on
    // this path otherwise). Clamped to the remaining request budget so per-repo acquires
    // cannot each draw a fresh full timeout past it (#174 F3).
    let acquire_deadline = std::cmp::min(
        std::time::Duration::from_secs(state.config.git_acquire_timeout_secs),
        acquire_budget,
    );
    let repo_path = match tokio::time::timeout(
        acquire_deadline,
        state.repo_store.acquire(&repo.owner_did, &repo.name),
    )
    .await
    {
        Ok(Ok(p)) => p,
        // An acquire FAILURE is not an absence verdict either: the repo may well hold the
        // object, we just could not open it.
        Ok(Err(e)) => {
            tracing::warn!(repo = %repo.name, err = %e, "repo acquire failed during /ipfs gate; skipping repo without a verdict");
            walk.taint("acquire");
            return GateOutcome::Skip;
        }
        Err(_elapsed) => {
            tracing::warn!(repo = %repo.name, "repo acquire timed out during /ipfs gate; skipping repo without a verdict");
            walk.taint("acquire");
            return GateOutcome::Skip;
        }
    };

    // Existence probe before any walk (random-CID spray must not trigger a walk on a
    // repo that lacks the object). Off the async runtime — it shells out to
    // `git cat-file -t`. Fail closed (skip) on a task panic.
    let Some(probe_budget) = walk.budget_left(
        ctx,
        state.config.ipfs_request_budget_secs,
        &repo.name,
        "object-type probe",
    ) else {
        return GateOutcome::Skip;
    };
    let obj_type = {
        let rp = repo_path.clone();
        let sha = sha256_hex.to_string();
        // The probe shells to the REAL `git`, as the unbounded `object_type` always
        // did, independent of `state.git_bin`. That knob is the WALK binary: tests
        // point it at a fake that answers `rev-list` and friends, and routing the
        // existence probe through it would ask that fake to impersonate
        // `cat-file --batch-check` as well (#174).
        let git_bin = "git".to_string();
        // Bound the probe CHILD itself (process-group teardown via
        // `object_type_bounded` -> `run_bounded_git`), not just an outer tokio timeout
        // racing an uncancellable `spawn_blocking`: this probe runs while the /ipfs walk
        // permit is held, so a wedged cat-file (corrupt pack, NFS stall) must be REAPED
        // at the deadline rather than left to linger and delay admission release
        // (#173 round-10, KTD2). No outer timeout, mirroring the bounded walk below. The
        // child's own deadline is the lesser of `git_service_timeout_secs` and the
        // remaining request budget (#174 F3), so a started probe cannot finish past it.
        let probe_deadline = std::time::Instant::now()
            + std::cmp::min(
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                probe_budget,
            );
        let probe_admission = std::sync::Arc::clone(ctx.admission);
        match tokio::task::spawn_blocking(move || {
            // Admission clone (#174 U1): the slot stays taken until this blocking work
            // returns, even if the handler future was dropped or this closure panics.
            let _admission = probe_admission;
            store::object_type_bounded(&git_bin, &rp, &sha, probe_deadline)
        })
        .await
        {
            Ok(Ok(Some(t))) => t,
            // Absence is the one verdict the probe can reach on its own.
            Ok(Ok(None)) => return GateOutcome::Skip,
            // Transient fault (an unreadable or mid-repack store, or the reaped
            // deadline): unproven and retryable, so taint rather than 404.
            Ok(Err(store::ProbeError::Transient(e))) => {
                tracing::warn!(repo = %repo.name, err = %e, "object-type probe hit a transient store fault under the /ipfs walk permit; skipping repo without a verdict");
                walk.taint("probe");
                return GateOutcome::Skip;
            }
            // Deterministic fault (a corrupt repo, a bad `.git/config`): a retry cannot
            // fix it, so it must NOT taint — a retryable 503 would invite a conformant
            // client to retry-storm a fresh `cat-file` per attempt against the broken
            // repo. The tail renders it as a terminal 500, and only if nothing served.
            Ok(Err(store::ProbeError::Deterministic(e))) => {
                tracing::warn!(repo = %repo.name, err = %e, "object-type probe hit a deterministic fault (corrupt repo/config); skipping repo without a verdict");
                walk.deterministic_fault = true;
                return GateOutcome::Skip;
            }
            Err(e) => {
                tracing::warn!(repo = %repo.name, err = %e, "object-type probe task panicked; skipping repo without a verdict");
                walk.taint("probe");
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
            // Budget gate for the walk stage (#174 F3): probed-present is not a serve, so
            // a walk is never STARTED with no budget left.
            if walk
                .budget_left(
                    ctx,
                    state.config.ipfs_request_budget_secs,
                    &repo.name,
                    "visibility walk",
                )
                .is_none()
            {
                return GateOutcome::Skip;
            }
            // Per-request fan-out ceiling (INV-10): once this many walks have run, skip
            // THIS walk-requiring candidate and keep scanning (a later walk-free copy
            // must still serve). `walks` is bumped only inside this block, so walk-free
            // candidates never consume budget.
            // Both parents bound this loop, under different knobs: #173's
            // `ipfs_max_history_walks` (an AppState field, seeded from config) and
            // #174's `GITLAWB_IPFS_MAX_REPOS_WALKED`. Honor the tighter of the two, so
            // neither knob silently stops working after the merge.
            let walk_cap = std::cmp::min(
                state.ipfs_max_history_walks as usize,
                state.config.ipfs_max_repos_walked,
            );
            if walk.walks as usize >= walk_cap {
                // The walk ceiling truncated the search: a later repo (possibly one that
                // authorizes this caller) is left unwalked, so absence is unproven —
                // record it so the tail returns 503, not a false 404 (#173, F2).
                tracing::warn!(
                    cap = walk_cap,
                    repo = %repo.name,
                    "/ipfs request hit the per-request walk cap; skipping repo without a verdict"
                );
                walk.taint("walk-cap");
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
                    if !state.ipfs_work_rate_limiter.check(&key).await {
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
            let git_service_timeout =
                std::time::Duration::from_secs(state.config.git_service_timeout_secs);
            let walk_deadline = ctx.request_deadline;
            let walk_admission = std::sync::Arc::clone(ctx.admission);
            let result = tokio::task::spawn_blocking(move || {
                // Admission clone (#174 U1): the slot stays taken until this blocking
                // work returns, even if the handler future was dropped or this closure
                // panics.
                let _admission = walk_admission;
                // Derive the walk's budget from the request deadline HERE, inside the
                // closure, not on the async side before the task is queued. The walk
                // starts its own clock when it runs, so a budget computed at queue time
                // would hand it the full remainder measured from whenever the blocking
                // pool got to it — the queue delay would go uncharged and the walk could
                // finish past the request budget. Computing it at task start charges the
                // delay against the deadline; a queue delay that eats the whole remainder
                // saturates this to zero and the walk fails closed (no verdict, taint),
                // which is the safe direction. Same fix as the upload-pack walk in
                // `api/repos.rs`, and this route is anonymously reachable.
                // TESTING GAP: the queue-delay path is reasoned, not executed. Observing
                // it needs a runtime with the blocking pool pinned and parked, and the
                // `#[sqlx::test]` harness gives no seam for that.
                let walk_timeout = std::cmp::min(
                    git_service_timeout,
                    walk_deadline.saturating_duration_since(std::time::Instant::now()),
                );
                match kind.as_str() {
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
                    "commit" | "tag" => {
                        reachable_commit_tag_oids_bounded(&rp, &git_bin, walk_timeout)
                    }
                    other => unreachable!("gated admits only blob/tree/commit/tag, got {other}"),
                }
            })
            .await;
            // Fail closed on a walk error or task panic: we cannot prove readability, so
            // skip rather than serve on an unproven gate — and never report absent on one
            // either, so the skip taints the scan.
            let set = match result {
                Ok(Ok(set)) => set,
                Ok(Err(e)) => {
                    tracing::warn!(repo = %repo.name, err = %e, "allowed-set walk failed; skipping repo without a verdict");
                    walk.taint("walk-failure");
                    return GateOutcome::Skip;
                }
                Err(e) => {
                    tracing::warn!(repo = %repo.name, err = %e, "allowed-set walk task panicked; skipping repo without a verdict");
                    walk.taint("walk-failure");
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
    //
    // Budget gate for the read stage (#174 F3): the read never starts past the request
    // budget, and its shared deadline clamps to the remainder.
    let Some(read_budget) = walk.budget_left(
        ctx,
        state.config.ipfs_request_budget_secs,
        &repo.name,
        "content read",
    ) else {
        return GateOutcome::Skip;
    };
    let max_bytes = state.ipfs_max_served_object_bytes;
    let read_repo = repo_path.clone();
    let read_sha = sha256_hex.to_string();
    let read_type = obj_type.clone();
    let want_cid = ctx.canonical_cid.to_string();
    // Real `git` for the size and content reads, as the probe above and for the same
    // reason: `state.git_bin` is the walk binary.
    let git_bin = "git".to_string();
    // Bound the size+read CHILDREN themselves (process-group teardown at
    // `git_service_timeout_secs` via the `*_bounded` twins), not an outer tokio timeout
    // over an uncancellable `spawn_blocking`: a hung cat-file must be REAPED at the
    // deadline rather than left to pin the held /ipfs walk permit (#173 round-10, KTD2).
    // No outer timeout, mirroring the bounded walk; a `GitServiceTimeout` from either
    // twin surfaces as `ServedRead::ReadErr` -> truncated (retryable 503).
    // ONE deadline spans the size and content reads, so a single served candidate
    // holds the /ipfs walk permit for at most `git_service_timeout_secs` total, not
    // one full timeout per stage (mirrors `build_filtered_pack`'s shared deadline).
    let read_deadline = std::time::Instant::now()
        + std::cmp::min(
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            read_budget,
        );
    let read_admission = std::sync::Arc::clone(ctx.admission);
    let read = tokio::task::spawn_blocking(move || -> ServedRead {
        // Admission clone (#174 U1): the slot stays taken until this blocking work
        // returns, even if the handler future was dropped or this closure panics.
        let _admission = read_admission;
        #[cfg(test)]
        break_size_probe_if_armed(&read_repo, &read_sha);
        match store::object_size_bounded(&git_bin, &read_repo, &read_sha, read_deadline) {
            Ok(size) if size > max_bytes => return ServedRead::TooLarge(size),
            Ok(_) => {}
            // Every failure of this stage is a fault, never a not-found: the type probe
            // above already returned Present, and the probe no longer has an absence
            // value to collapse a corrupt object or a failed spawn into (#173 round 12).
            Err(e) => return ServedRead::ReadErr(e.to_string()),
        }
        let content = match store::read_object_content_bounded(
            &git_bin,
            &read_repo,
            &read_sha,
            &read_type,
            read_deadline,
        ) {
            Ok(c) => c,
            Err(e) => return ServedRead::ReadErr(e.to_string()),
        };
        let served = gitlawb_core::cid::Cid::from_git_object_bytes(&content).to_string();
        if served != want_cid {
            return ServedRead::Mismatch(served);
        }
        ServedRead::Ok(content)
    })
    .await;
    let served_read = match read {
        Ok(sr) => sr,
        Err(e) => {
            tracing::warn!(repo = %repo.name, err = %e, "object read task panicked");
            walk.taint("read");
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
        ServedRead::ReadErr(e) => {
            // Infra failure (git spawn/IO), NOT a not-found: mark the search truncated so
            // a wholly-unserved request tails to a retryable 503, never a definitive 404
            // for an authorized caller (INV-25 spirit — logging alone is not surfacing).
            tracing::warn!(repo = %repo.name, err = %e, "error reading git object content");
            walk.taint("read");
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
    // Bare `?` so connection-class sqlx failures downcast to `AppError::Db` and
    // map to 503 `db_unavailable` (not 500 via `.map_err(AppError::Internal)`) (#251).
    let pins = state.db.list_pinned_cids().await?;

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
// Test seam for the SIZE stage of the serve read (#173 round 12). The size probe runs
// after the type probe has already reported the object present, and the interesting case
// is a failure THERE, which no fixture can produce from the outside: the size read
// deliberately uses the real `git` rather than `state.git_bin`, so a shim cannot be
// injected the way it can for the walk.
//
// A shared set rather than a `thread_local` like the seams below, because this one has to
// fire inside the read's `spawn_blocking`, on a different thread from the test.
//
// Keyed by (repo path, oid), and the repo path is the load-bearing half. An oid alone is
// NOT unique across the test binary: fixture oids are content-derived, so every test
// seeding the same fixture bytes shares them, and arming one oid deleted the object out
// from under two unrelated tests running in parallel. The repo path carries a per-test
// slug, so it is what makes the key private to the test that armed it. The entry is also
// consumed on the first fire, so a test's later requests see an intact repo.
#[cfg(test)]
static SIZE_PROBE_BREAKERS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn size_probe_seam_key(repo_path: &std::path::Path, sha256_hex: &str) -> String {
    format!("{}::{sha256_hex}", repo_path.display())
}

/// Arm the seam: the next serve read of `sha256_hex` FROM `repo_path` loses its loose
/// object between the type probe and the size probe, so the size probe fails on an object
/// git just confirmed present.
#[cfg(test)]
pub(crate) fn break_size_probe_for(repo_path: &std::path::Path, sha256_hex: &str) {
    SIZE_PROBE_BREAKERS
        .get_or_init(Default::default)
        .lock()
        .expect("size-probe seam mutex")
        .insert(size_probe_seam_key(repo_path, sha256_hex));
}

#[cfg(test)]
fn break_size_probe_if_armed(repo_path: &std::path::Path, sha256_hex: &str) {
    let armed = SIZE_PROBE_BREAKERS.get().is_some_and(|s| {
        s.lock()
            .expect("size-probe seam mutex")
            .remove(&size_probe_seam_key(repo_path, sha256_hex))
    });
    if armed {
        let _ = std::fs::remove_file(
            repo_path
                .join("objects")
                .join(&sha256_hex[0..2])
                .join(&sha256_hex[2..]),
        );
    }
}

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

// Test-only INV-10 cost counter (#173, jatmn): how many repo ROWS the legacy scan's
// database-facing selection actually materialized this request. The query counter above
// cannot see the failure it guards — one unbounded `SELECT ... FROM repos` is a single
// query that pulls the node's entire inventory, so it reads 1 either way. Counting rows
// is what goes red if the paging is reverted.
#[cfg(test)]
thread_local! {
    static SCAN_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_scan_rows() {
    SCAN_ROWS.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn scan_rows() -> usize {
    SCAN_ROWS.with(|c| c.get())
}

#[cfg(test)]
fn note_scan_rows(n: usize) {
    SCAN_ROWS.with(|c| c.set(c.get() + n));
}

// Test-only cost counter (F5, #173 round 11): how many times the fallback gate ran the
// `pin_sources_at_cap` / `pin_sources_incomplete` pair. The work-budget peek sits ahead
// of them, so an already-throttled caller leaves this at 0; putting the peek back after
// the pair turns that assertion red. Same thread_local discipline as the preload counter.
#[cfg(test)]
thread_local! {
    static MARKER_QUERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_marker_queries() {
    MARKER_QUERIES.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn marker_queries() -> usize {
    MARKER_QUERIES.with(|c| c.get())
}

#[cfg(test)]
fn bump_marker_queries() {
    MARKER_QUERIES.with(|c| c.set(c.get() + 1));
}

/// Which of the two `needs_scan` marker queries a test wants to stall.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum MarkerQuery {
    AtCap,
    Incomplete,
}

// Test-only fault-injection seam for the `needs_scan` marker pair
// (`pin_sources_at_cap`, `pin_sources_incomplete`), same idea as
// `RepoStore::tigris_stall`: hold one specific await open so the clamp around it is
// the one observed to fire.
//
// A `LOCK TABLE` fixture cannot isolate these two. `pin_sources_at_cap` reads
// `pin_repo_sources` and `pin_sources_incomplete` reads `pinned_cids`, and BOTH tables
// are already read by `oids_for_cid` and `pin_sources_for_oid` earlier in the same
// admission-held region, so a lock taken before the request stalls one of those instead
// and the RED is attributed to the wrong clamp. Taking the lock mid-request does not
// help either: the window between `pin_sources_for_oid` returning and this pair running
// is a single `get_repo_by_id` round trip (measured at ~0.15ms against this Postgres),
// so timing a lock into it is a race that flakes under load.
//
// Armed per target so the second query can be reached with the first left untouched
// (`at_cap` must return `false` for the `||` to evaluate `pin_sources_incomplete`).
// `thread_local` for the same reason as the counters above: `#[sqlx::test]` runs each
// case on its own current-thread runtime, so arming here is invisible to cases running
// in parallel.
#[cfg(test)]
thread_local! {
    static MARKER_QUERY_STALL: std::cell::Cell<Option<(MarkerQuery, std::time::Duration)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn arm_marker_query_stall(which: MarkerQuery, stall: std::time::Duration) {
    MARKER_QUERY_STALL.with(|c| c.set(Some((which, stall))));
}

#[cfg(test)]
pub(crate) fn disarm_marker_query_stall() {
    MARKER_QUERY_STALL.with(|c| c.set(None));
}

/// Awaited INSIDE each marker query's `tokio::time::timeout`, never before it: a stall
/// placed outside the clamp would elapse with the clamp never firing and prove nothing.
#[cfg(test)]
async fn stall_marker_query(which: MarkerQuery) {
    let armed = MARKER_QUERY_STALL.with(|c| c.get());
    if let Some((target, stall)) = armed {
        if target == which {
            tokio::time::sleep(stall).await;
        }
    }
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
mod closed_pool_tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use serde_json::Value;
    use sqlx::PgPool;
    use tower::ServiceExt;

    /// #251: a closed pool on /api/v1/ipfs/pins must be 503 db_unavailable,
    /// not 500 internal_error from `.map_err(AppError::Internal)`.
    #[sqlx::test]
    async fn list_pins_closed_pool_returns_503_db_unavailable(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        pool.close().await;

        let resp = Router::new()
            .route("/api/v1/ipfs/pins", axum::routing::get(list_pins))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/ipfs/pins")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "closed-pool outage must be retryable 503, not 500"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v,
            serde_json::json!({
                "error": crate::error::DB_UNAVAILABLE_CODE,
                "message": crate::error::DB_UNAVAILABLE_MESSAGE,
            })
        );
    }

    /// #251 / CodeRabbit nit: cover `get_by_cid`'s DB-error conversion path — a
    /// valid CID must still yield 503 on a closed pool.
    #[sqlx::test]
    async fn get_by_cid_closed_pool_returns_503_db_unavailable(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        pool.close().await;

        // Any sha2-256 CIDv1 passes the codec gate and then hits the DB.
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(b"closed-pool-probe").to_string();

        let resp = Router::new()
            .route("/ipfs/{cid}", axum::routing::get(get_by_cid))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/ipfs/{cid}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "closed-pool outage on get_by_cid must be retryable 503, not 500"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v,
            serde_json::json!({
                "error": crate::error::DB_UNAVAILABLE_CODE,
                "message": crate::error::DB_UNAVAILABLE_MESSAGE,
            })
        );
    }
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

    use super::{arm_marker_query_stall, disarm_marker_query_stall, MarkerQuery};
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
        // Register the CID index entry the resolver needs to map a requested CID back
        // to this oid, keyed on the object's raw CONTENT (what the serve path
        // recomputes and verifies against) and with NULL provenance, which is what
        // routes a request to the bounded legacy scan (#173).
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(content)
            .as_str()
            .to_string();
        state
            .db
            .record_pinned_cid(&oid, &cid, None)
            .await
            .expect("register the seeded blob in the CID index");
        (rec.id, oid)
    }

    /// A 64-hex object id that exists in no repo, for the scan-verdict tests whose
    /// whole point is that nothing serves.
    fn absent_oid() -> String {
        "f2".repeat(32)
    }

    /// Register a LEGACY (NULL-provenance) `pinned_cids` row and return its CID.
    ///
    /// The scan-verdict tests below predate the CID index (#173): they drove a bare
    /// CID and relied on the handler treating the CID's own digest as the git oid.
    /// The index-backed resolver does not do that (a pin CID digests raw object
    /// content, not the framed git object), so without a row `oids_for_cid` comes back
    /// empty and the handler 404s before any repo is visited. NULL provenance is what
    /// routes the request to the bounded legacy scan, which is the loop these tests
    /// are about.
    async fn seed_legacy_pin(state: &crate::state::AppState, oid: &str) -> String {
        let cid = cid_for_oid(oid);
        state
            .db
            .record_pinned_cid(oid, &cid, None)
            .await
            .expect("seed a legacy NULL-provenance pin row");
        cid
    }

    /// The CID to request for an object a test seeded through `seed_repo_with_blob`.
    ///
    /// That helper registers the index entry keyed on the object's raw CONTENT, which
    /// is what the serve path recomputes and compares the requested CID against
    /// (#173 F2). Deriving the key from the oid instead yields a CID the gate passes
    /// and the integrity check then rejects as a legacy provider-CID row, so the
    /// candidate is withheld and a serving test sees a skip rather than its 200.
    async fn seed_legacy_pin_for_oid(state: &crate::state::AppState, oid: &str) -> String {
        if let Some(cid) = state.db.cid_for_oid(oid).await.expect("read the CID index") {
            return cid;
        }
        // A test that built its object by hand (to corrupt it, say) has no entry yet.
        // Its object never serves, so the content check never runs and any stable key
        // will do; derive one from the oid.
        seed_legacy_pin(state, oid).await
    }

    /// CIDv1(raw, sha2-256) for a sha256 object id, as the handler resolves it.
    fn cid_for_oid(oid: &str) -> String {
        let oid_bytes = gitlawb_core::cid::sha256_hex_to_bytes(oid).unwrap();
        gitlawb_core::cid::Cid::from_sha256_bytes(&oid_bytes)
            .as_str()
            .to_string()
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

    /// #173 (jatmn, INV-10): the legacy scan's DATABASE-facing selection is bounded
    /// too, not just its probes. The probe ceiling only starts counting once a probe
    /// runs, so before this fix an anonymous GET for a CID enumerable from the public
    /// pins index loaded every repo row, every matching visibility rule, and the whole
    /// node's quarantine set — work proportional to the node's inventory, bought at a
    /// probe budget of 1, with the scarce walk permits held throughout.
    ///
    /// Page size 1 and probe budget 1 against THREE candidate repos: the scan may read
    /// exactly one page, spend its one probe, and stop. It must then report the
    /// truncation (503), never a false 404 — the two later repos were never looked at.
    ///
    /// The ROW count is the load-bearing assertion. A query counter cannot see this
    /// regression: reverting to one unbounded `SELECT ... FROM repos` is a single query
    /// that pulls the entire inventory, so the query count reads 1 either way.
    /// MUTATION (RED): drop the pre-fetch probe-budget check and the pager walks every
    /// page anyway — 3 rows materialized and 4 queries instead of 1 and 1.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_legacy_scan_stops_paging_when_the_probe_budget_is_spent(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // One row per page and one probe per request: the smallest configuration in
        // which "stopped early" and "read everything" are distinguishable.
        state.ipfs_legacy_scan_page_rows = 1;
        state.ipfs_max_legacy_probes = 1;

        for name in ["one", "two", "three"] {
            seed_repo_with_blob(
                &state,
                tmp.path(),
                "z6pager",
                name,
                format!("pager row {name}\n").as_bytes(),
            )
            .await;
        }

        // An oid no repo carries, so every probe reaches a clean absent verdict and the
        // only thing that can cut the scan short is the budget under test.
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        crate::api::ipfs::reset_scan_rows();
        crate::api::ipfs::reset_preload_queries();
        let peer: SocketAddr = "203.0.113.90:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "stopping early must taint the scan: a truncated search is a retryable 503, \
             never a definitive 404"
        );
        assert_eq!(
            crate::api::ipfs::scan_rows(),
            1,
            "the selection must materialize only the page it can afford to gate, never \
             the node's whole repo inventory (INV-10)"
        );
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            1,
            "and it must stop asking for pages once the probe budget is spent"
        );
    }

    /// #173 (jatmn, INV-10): the pager is per REQUEST, not per oid candidate.
    ///
    /// The `pinned_cids` index is unique on the git oid but NOT on the cid, so one CID
    /// can resolve to several oids and `get_by_cid` tries each. If the pager were
    /// re-created inside that loop, every extra candidate would re-page the whole
    /// inventory and the fan-out this fix removes would come straight back — a CID with
    /// k source-less candidates would cost k full scans of the node.
    ///
    /// Two DISTINCT absent oids seeded under ONE cid, both source-less so both reach
    /// `needs_scan`. Three candidate repos at one row per page, with the probe and visit
    /// budgets left at their generous defaults so nothing truncates: the scan runs to
    /// exhaustion and 404s honestly. The whole request must cost ONE pass — 4 page
    /// queries (3 full pages plus the short page that proves exhaustion) and 3 rows —
    /// because the second candidate re-reads rows the first already paid for.
    ///
    /// MUTATION (RED): shadow `pager` with a fresh `LegacyScanPager::default()` inside
    /// the `for sha256_hex in &oids` loop and the counters double to 8 and 6.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_second_oid_candidate_reuses_pages_from_the_first(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // One row per page so each page is individually visible in the counters. The
        // probe and visit budgets stay at their defaults: this is about page REUSE, so
        // nothing may truncate.
        state.ipfs_legacy_scan_page_rows = 1;

        for name in ["one", "two", "three"] {
            seed_repo_with_blob(
                &state,
                tmp.path(),
                "z6reuse",
                name,
                format!("reuse row {name}\n").as_bytes(),
            )
            .await;
        }

        // Two oids no repo carries, sharing one cid: every probe reaches a clean absent
        // verdict, so the scan completes for both candidates and nothing taints.
        let first_oid = absent_oid();
        let second_oid = "f3".repeat(32);
        let cid = seed_legacy_pin(&state, &first_oid).await;
        state
            .db
            .record_pinned_cid(&second_oid, &cid, None)
            .await
            .expect("co-locate a second source-less oid under the same cid");
        assert_eq!(
            state.db.oids_for_cid(&cid).await.unwrap().len(),
            2,
            "precondition: the CID must resolve to two candidates, or the reuse this \
             test is about never happens"
        );

        crate::api::ipfs::reset_scan_rows();
        crate::api::ipfs::reset_preload_queries();
        let peer: SocketAddr = "203.0.113.92:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "every candidate reached a verdict under generous budgets, so the honest \
             answer is the definitive 404 — a 503 here would mean something truncated \
             and the counters below would be measuring the wrong thing"
        );
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            4,
            "the pager is per REQUEST: a second oid candidate re-reads the pages the \
             first already paid for and must never re-query. Expected one pass over 3 \
             repos at 1 row per page = 4 page queries (3 full + the short page that \
             proves exhaustion); a per-candidate pager reads 8"
        );
        assert_eq!(
            crate::api::ipfs::scan_rows(),
            3,
            "and one pass materializes each repo row exactly once (3), not once per \
             oid candidate (6)"
        );
    }

    /// F2 buried-row repro: with more readable repos than `ipfs_max_repos_walked`,
    /// existing PUBLIC content past the cap must still serve. The cap counts
    /// EXPENSIVE walks only — this request has no path-scoped rules anywhere, so it
    /// runs ZERO walks (the fake-git walk log stays empty) and the cap can never cut
    /// the scan: the blob buried in the LAST-iterated repo serves its 200. Iteration
    /// is `(created_at, id)` ASC since the scan was paged (#173, jatmn), so the
    /// blob-carrying repo is seeded LAST to keep it buried. Before F2 the cap counted
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

        // Seed the blob-carrying repo LAST so its created_at is NEWEST: under the
        // paged `(created_at, id)` ASC order the empty repo is iterated first and the
        // blob row sits past the old visit budget.
        seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f2buried",
            "fresh",
            b"unrelated content\n",
        )
        .await;
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f2buried",
            "buried",
            b"buried row proof\n",
        )
        .await;

        let peer: SocketAddr = "203.0.113.60:5000".parse().unwrap();
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
    /// repos carry the same blob, in iteration order: the first (path-scoped) consumes the
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

        // Iteration is `(created_at, id)` ASC since the scan was paged (#173, jatmn),
        // so insert order IS iteration order: gatedwalk, then gatedskip, then pubcopy.
        // Identical content -> one CID.
        let content = b"skip and continue proof\n";
        let (walk_id, _) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2skip", "gatedwalk", content).await;
        let (skip_id, _) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2skip", "gatedskip", content).await;
        let (_, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2skip", "pubcopy", content).await;
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
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
    /// — and the stop is a truncation, not an absence: with ceiling 1 the
    /// first-iterated empty repo consumes the only visit and the blob-carrying repo
    /// behind it is never probed, so the request sheds a retryable 503 + Retry-After, never a false
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

        // Empty repo seeded first, so under the paged `(created_at, id)` ASC order it
        // is iterated first and consumes the single visit; the blob repo behind it is
        // never probed.
        seed_repo_with_blob(&state, tmp.path(), "z6f2visit", "fresh", b"unrelated\n").await;
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f2visit",
            "buried",
            b"visit ceiling proof\n",
        )
        .await;

        let peer: SocketAddr = "203.0.113.62:5000".parse().unwrap();
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
        let endpoint = crate::test_support::silent_http_endpoint().await;
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
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
    /// genuinely carries the object still serves. The FIRST-iterated row (the paged
    /// scan orders on `(created_at, id)` ASC since #173/jatmn, so it is the row
    /// created first) is a Tigris-backed ghost whose acquire stalls against the
    /// silent endpoint and times out at 1s; the row behind it is a plain public
    /// repo carrying the blob, reached next and
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
        // Seed through a LOCAL-ONLY store first, so seeding never consults the
        // (deliberately unreachable) Tigris endpoint. The ghost row goes in FIRST:
        // it is a bare DB insert, and under the paged `(created_at, id)` ASC order
        // the row created first is the row iterated first.
        state.repo_store =
            crate::git::repo_store::RepoStore::for_testing(repos_dir.clone(), pool.clone());
        state
            .db
            .upsert_mirror_repo("z6f2acqcont", "ghost", "/unused-ghost", None, false)
            .await
            .unwrap();
        let content = b"acquire taint continue proof\n";
        let (_, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2acqcont", "pubcopy", content).await;
        // Swap in a Tigris-backed store over the SAME repos_dir (the seeded bare
        // repo stays a fast local hit). The ghost has no local copy, so its acquire
        // consults the silent local endpoint and stalls to the 1s timeout
        // (endpoint-pinned test client, no AWS_* env reads).
        let endpoint = crate::test_support::silent_http_endpoint().await;
        let tigris =
            crate::git::tigris::TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint)
                .await;
        state.repo_store = crate::git::repo_store::RepoStore::new(repos_dir, Some(tigris), pool);
        let mut cfg = (*state.config).clone();
        cfg.git_acquire_timeout_secs = 1;
        state.config = Arc::new(cfg);

        // Ordering precondition: the ghost must be iterated FIRST, otherwise the
        // pubcopy would serve before the taint ever fires and the continue-vs-break
        // distinction would go untested. Read through the same paged selection the
        // scan uses, so the precondition cannot drift from the real order.
        let order: Vec<String> = state
            .db
            .list_repos_page_for_scan(None, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.repo.name)
            .collect();
        let ghost_pos = order.iter().position(|n| n == "ghost").unwrap();
        let pub_pos = order.iter().position(|n| n == "pubcopy").unwrap();
        assert!(
            ghost_pos < pub_pos,
            "precondition: the stalling ghost must be iterated before the blob repo; got {order:?}"
        );

        let peer: SocketAddr = "203.0.113.73:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
            "an acquire taint must not stop the scan: the later public copy serves"
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
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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

    /// #174 F5 co-occurrence (RED-before/GREEN-after): a deterministic fault on ONE
    /// repo and a TRANSIENT taint on a DIFFERENT repo occur in the same scan, and the
    /// requested CID is served by neither. The transiently-skipped repo could hold the
    /// object, so a retry can surface it — the correct shed is the RETRYABLE 503, not
    /// the terminal 500. Two broken repos drive it, both local so the outcome is
    /// deterministic: a bad-`config` repo whose `objects/` stays readable is a
    /// DETERMINISTIC probe fault (`deterministic_fault = true`), while a repo whose
    /// `objects/` dir is removed is a TRANSIENT probe fault (taints "probe"). A third
    /// healthy repo probes clean (absent verdict) so nothing serves. Before the fix the
    /// terminal `if deterministic_fault` arm fired first and shed 500 unconditionally,
    /// hiding the transiently-skipped repo behind a non-retryable status. MUTATION
    /// (RED): drop the `&& truncated_by.is_empty()` gate and this shes 500 again.
    #[sqlx::test]
    async fn get_by_cid_deterministic_fault_with_cooccurring_transient_taint_is_503_not_500(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        // Healthy repo that probes clean (definitive absence on its own).
        seed_repo_with_blob(&state, tmp.path(), "z6f5coclean", "real", b"probe clean\n").await;

        // Bad-config repo: objects/ readable, config corrupt -> DETERMINISTIC fault.
        state
            .db
            .upsert_mirror_repo("z6f5cobadcfg", "broken", "/unused-badcfg", None, false)
            .await
            .unwrap();
        let rec = state
            .db
            .get_repo("z6f5cobadcfg", "broken")
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
        {
            use std::io::Write;
            let mut cfg = std::fs::OpenOptions::new()
                .append(true)
                .open(bare.join("config"))
                .unwrap();
            cfg.write_all(b"\n[broken section\nnot a valid = = = line\n")
                .unwrap();
        }

        // Corrupt-dir repo: objects/ removed -> TRANSIENT probe fault (taints "probe"),
        // a DIFFERENT repo than the deterministic one above.
        state
            .db
            .upsert_mirror_repo("z6f5cocorrupt", "broken", "/unused-corrupt", None, false)
            .await
            .unwrap();
        let rec2 = state
            .db
            .get_repo("z6f5cocorrupt", "broken")
            .await
            .unwrap()
            .unwrap();
        let bare2 = state
            .repo_store
            .acquire(&rec2.owner_did, &rec2.name)
            .await
            .unwrap();
        std::fs::create_dir_all(&bare2).unwrap();
        run_git(&["init", "-q", "--bare", "--object-format=sha256"], &bare2);
        std::fs::remove_dir_all(bare2.join("objects")).unwrap();
        std::fs::write(bare2.join("HEAD"), b"junk\n").unwrap();

        let peer: SocketAddr = "203.0.113.71:5000".parse().unwrap();
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a deterministic fault co-occurring with a transient taint on a DIFFERENT \
             repo must shed the retryable 503 (a retry can surface the object in the \
             transiently-skipped repo), never the terminal 500"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the co-occurrence 503 must carry Retry-After"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("probe"),
            "the shed must name the transient probe taint; got: {body}"
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
        let cid = seed_legacy_pin_for_oid(&state, oid).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
    /// acquire timeout 2s; the FIRST-iterated row is a Tigris-backed ghost (no local
    /// copy, silent local endpoint) whose acquire stalls, the row behind it is a plain
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
        // Seed through a LOCAL-ONLY store first, so seeding never consults the
        // (deliberately unreachable) Tigris endpoint. The ghost row goes in FIRST: the
        // paged scan orders on `(created_at, id)` ASC (#173, jatmn), so the row created
        // first is the row iterated first.
        state.repo_store =
            crate::git::repo_store::RepoStore::for_testing(repos_dir.clone(), pool.clone());
        state
            .db
            .upsert_mirror_repo("z6f3budget", "ghost", "/unused-ghost", None, false)
            .await
            .unwrap();
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6f3budget",
            "buried",
            b"budget expiry proof\n",
        )
        .await;
        // Swap in a Tigris-backed store over the SAME repos_dir (the seeded bare
        // repo stays a fast local hit). The ghost has no local copy, so its acquire
        // consults the silent local endpoint and stalls past the budget
        // (endpoint-pinned test client, no AWS_* env reads).
        let endpoint = crate::test_support::silent_http_endpoint().await;
        let tigris =
            crate::git::tigris::TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint)
                .await;
        state.repo_store = crate::git::repo_store::RepoStore::new(repos_dir, Some(tigris), pool);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        cfg.git_acquire_timeout_secs = 2;
        state.config = Arc::new(cfg);

        let peer: SocketAddr = "203.0.113.70:5000".parse().unwrap();
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
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
    /// public copy of the same blob behind it (which would have served 200). After
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

        // First-iterated row (seeded first, `(created_at, id)` ASC): path-scoped, so
        // its blob costs the clamped walk. Behind it, a plain public copy of the same
        // blob which must never be reached.
        let content = b"budget walk clamp proof\n";
        let (walk_id, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6f3clamp", "gated", content).await;
        seed_repo_with_blob(&state, tmp.path(), "z6f3clamp", "pubcopy", content).await;
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
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let router = ipfs_router(state);
        let started = std::time::Instant::now();
        let peer: SocketAddr = "203.0.113.71:5000".parse().unwrap();
        let mut fut = Box::pin(router.oneshot(get_cid(&cid, Some(peer))));

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
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            ipfs_router(state).oneshot(get_cid(&cid, Some(peer))),
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

    /// Build the shared `/ipfs` TREE-walk fixture. A fake `git` whose `rev-list` records
    /// its pid then sleeps ~6s (so the tree walk blocks deterministically inside
    /// `run_bounded_git`) and whose `cat-file -t` answers "tree" (so the bounded
    /// object-type probe, `object_type_bounded` on `state.git_bin`, routes into the
    /// tree-gate arm); a real SHA-256 bare repo with a committed `src/` tree pinned WITH
    /// provenance; and a path-scoped rule so the gate takes the tree-walk branch. Returns
    /// the tempdir (keep it alive for the whole test), the state (the caller sets the walk
    /// semaphores), the requested CID, and the rev-list pidfile path.
    #[cfg(unix)]
    async fn seed_tree_walk_fixture(
        pool: sqlx::PgPool,
    ) -> (
        tempfile::TempDir,
        crate::state::AppState,
        String,
        std::path::PathBuf,
    ) {
        use std::process::Command;

        let tmp = tempfile::TempDir::new().unwrap();
        let revlist_pid = tmp.path().join("revlist.pid");
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               for-each-ref) : ;;\n\
               rev-parse) echo deadbeef ;;\n\
               cat-file) if [ \"$2\" = \"-t\" ]; then echo tree; fi ;;\n\
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
        let tree_oid = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD:src"])
                .current_dir(&work)
                .output()
                .expect("git rev-parse runs");
            assert!(out.status.success(), "rev-parse failed");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(
            crate::git::store::object_type(&bare, &tree_oid)
                .unwrap()
                .as_deref(),
            Some("tree"),
            "the seeded sha256 tree must exist so the handler reaches the tree walk"
        );
        let (_ty, raw) = crate::git::store::read_object(&bare, &tree_oid)
            .unwrap()
            .expect("tree object readable");
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(&raw).to_string();
        state
            .db
            .record_pinned_cid(&tree_oid, &cid, Some(&rec.id))
            .await
            .unwrap();
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

        (tmp, state, cid, revlist_pid)
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
        let (tmp, mut state, cid, revlist_pid) = seed_tree_walk_fixture(pool).await;
        // Isolate the global walk pool at size 1; per-source cap permissive so only the
        // held global permit can shed the replacement.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        // Keep the fixture tempdir alive for the whole test (its Drop removes the repos).
        let _tmp = tmp;

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

        // Drop the in-flight request — a client disconnect. The detached blocking walk
        // keeps running (a spawn_blocking cannot be cancelled) and its git child is still
        // occupying a blocking thread and a PID, so the slot it was admitted under must
        // STAY TAKEN. Admission is released by the blocking work finishing, never by the
        // handler future going away (#174 U1).
        //
        // MUTATION (RED): make the admission a handler local again (drop the Arc clone
        // moved into the spawn_blocking closures) and this assertion fails immediately —
        // the permit count returns to 1 the moment the future is dropped, while the
        // sleeping child is still alive.
        drop(fut);
        // Give the runtime a chance to actually run the drop and any woken tasks, so
        // this is not merely observing a not-yet-processed release.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            unsafe { libc::kill(pid, 0) } == 0,
            "precondition: the blocking walk's git child must still be alive, or this \
             assertion proves nothing"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "a client disconnect must NOT release the walk slot while the uncancellable \
             blocking walk it admitted is still running"
        );

        // Now end the blocking work; the slot frees when the closure returns.
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
            "once the blocking walk tears down, the last admission clone drops and frees the slot"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "admission released exactly once — the single slot is back, not double-freed"
        );
    }

    /// Amplification negative (#173 round-10, R1): sequential cancel-spam from ONE source
    /// cannot hold more than the per-source cap of concurrent walks. An abandoned
    /// blocking walk keeps its per-source permit until its bounded work finishes (up
    /// to `git_service_timeout_secs`), so with a per-source cap of 1 a second request from
    /// the SAME source sheds 503 even though the GLOBAL pool has room — the source cannot
    /// amplify its concurrent walk children past the cap by dropping-and-retrying. (The
    /// worst case: an abandoned walk can occupy its global/per-source permit for one
    /// bound-interval, so distributed cancel-spam can hold the global pool that long — the
    /// accepted bounded-admission tradeoff, not a leak.)
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_cancel_spam_bounded_by_per_source_cap(pool: sqlx::PgPool) {
        let (tmp, mut state, cid, revlist_pid) = seed_tree_walk_fixture(pool).await;
        // Global pool has ample room (4); the per-source cap is 1. So any shed of a
        // same-source replacement is the PER-SOURCE cap, never global exhaustion.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(4));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1, 100);
        let _tmp = tmp;

        let sem = state.git_ipfs_walk_semaphore.clone();
        let per_caller = state.git_ipfs_walk_per_caller.clone();
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

        // Source S fires request 1; drive until its tree walk is in flight (the task now
        // holds source S's single per-source permit).
        let source_s: SocketAddr = "203.0.113.71:5000".parse().unwrap();
        let mut fut = Box::pin(router.clone().oneshot(make_req(source_s)));
        let mut walk_pid: Option<i32> = None;
        for _ in 0..500 {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut).await;
            if let Some(p) = std::fs::read_to_string(&revlist_pid)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                walk_pid = Some(p);
                break;
            }
        }
        let pid = walk_pid.expect("the fake git rev-list must have spawned");
        struct ReapOnDrop(i32);
        impl Drop for ReapOnDrop {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                }
            }
        }
        let _cleanup = ReapOnDrop(pid);

        // Cancel-spam: drop request 1's future. The uncancellable blocking walk keeps
        // running and KEEPS holding source S's single per-source permit.
        drop(fut);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        // A SECOND request from source S sheds 503. The global pool still has room (only 1
        // of 4 taken), so this is the per-source cap, not global exhaustion.
        let resp = router.clone().oneshot(make_req(source_s)).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a same-source cancel-spam replacement must shed 503 on the per-source cap \
             while the abandoned walk still holds the source's permit"
        );
        assert!(
            sem.available_permits() >= 3,
            "the shed was the per-source cap, not global exhaustion (global pool still has room)"
        );
        assert_eq!(
            per_caller.tracked_keys(),
            1,
            "exactly one per-source permit is outstanding for the one source — no amplification"
        );

        // Tear the walk down; the closure returns and releases source S's permit
        // (tracked_keys returns to 0), so the source is no longer over the cap.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut released = false;
        for _ in 0..400 {
            if per_caller.tracked_keys() == 0 {
                released = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            released,
            "once the blocking walk tears down it releases source S's per-source permit"
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
    /// This drives the GITLAWB_IPFS_MAX_REPOS_WALKED knob specifically. The merge left
    /// two walk caps in play, this one and the branch's own history-walk ceiling, and
    /// the gate takes the tighter of the two; setting this knob to 1 is what makes it
    /// the binding one here. A sibling case covers the ceiling.
    ///
    /// MUTATION (RED): drop `config.ipfs_max_repos_walked` from the `min()` in the walk
    /// gate and both repos are walked (count 2); drop the truncation taint on the skip
    /// and the 503 decays to a 404.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_caps_repos_walked_knob_bounds_the_walks(pool: sqlx::PgPool) {
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
        // The resolver maps a requested CID back to an oid through the CID index, so a
        // bare digest-as-oid CID resolves to nothing and 404s before any repo is
        // visited. Register a legacy NULL-provenance row, which is also what routes the
        // request to the bounded legacy scan this cap governs. Neither repo serves, so
        // the key need not be the content CID.
        let cid = seed_legacy_pin(&state, &oid).await;

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

    /// F6/KTD-5: the legacy scan's page queries (`list_repos_page_for_scan`,
    /// `list_visibility_rules_for_repos`) run AFTER the scarce walk permits are
    /// acquired (held RAII for the whole request) but BEFORE the per-repo loop's
    /// first budget gate. Pre-fix they were bare awaits with no deadline, so a query
    /// blocked in Postgres pinned the walk slot for the whole stall, past the request
    /// budget. Here we hold an ACCESS EXCLUSIVE lock on `repos` so the page query
    /// blocks; with the budget clamp the request sheds a retryable budget 503 within
    /// ~budget and FREES the walk permit, and a follow-up (lock released) is served.
    ///
    /// Load-bearing: pre-fix the bare await blocks on the lock until the 10s wrapping
    /// timeout fires (RED — "never returned within budget"). After the fix it returns
    /// the 503 at ~1s and the permit is free again. MUTATION (RED): drop the
    /// `tokio::time::timeout` around `list_repos_page_for_scan` and this hangs past
    /// the wrap.
    #[sqlx::test]
    async fn get_by_cid_stalled_metadata_query_frees_walk_permit(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Global walk pool of 1 so the held/freed permit is directly observable;
        // per-source cap permissive so only the global pool matters.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        state.config = Arc::new(cfg);

        let sem = state.git_ipfs_walk_semaphore.clone();
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let router = ipfs_router(state);

        // Hold an ACCESS EXCLUSIVE lock on `repos` on a dedicated pooled connection:
        // the page SELECT needs ACCESS SHARE, which conflicts, so it blocks at lock
        // acquisition regardless of row count.
        let mut lock_conn = pool.acquire().await.unwrap();
        sqlx::raw_sql("BEGIN; LOCK TABLE repos IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut *lock_conn)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.80:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            router.clone().oneshot(get_cid(&cid, Some(peer))),
        )
        .await
        .expect("the budget clamp must return within budget; a bare await hangs on the lock")
        .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a metadata query blocked past the request budget must shed a retryable 503"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the clamp must end the request at ~budget (1s); got {elapsed:?} \
             (pre-fix the bare await blocks on the lock for the whole stall)"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("budget"),
            "the shed must name the budget taint so it maps to \
             GITLAWB_IPFS_REQUEST_BUDGET_SECS; got: {body}"
        );
        // The scarce walk permit was RAII-dropped on the early return, not pinned for
        // the stall: the slot is free again the instant the request returns.
        assert_eq!(
            sem.available_permits(),
            1,
            "the walk permit must be freed on the budget-shed path, not held for the stall"
        );

        // Release the lock; a follow-up request is now SERVED (404 — empty DB), never
        // capacity-503'd, proving the slot was not left pinned.
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut *lock_conn)
            .await
            .unwrap();
        drop(lock_conn);
        let resp2 = router.oneshot(get_cid(&cid, Some(peer))).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::NOT_FOUND,
            "with the permit freed and the lock released, a follow-up is served (404), \
             not capacity-503'd"
        );
    }

    /// F2 (#174): `oids_for_cid` is the FIRST DB await inside the admission-held
    /// region, and pre-fix it was a bare await with no deadline. A query blocked in
    /// Postgres there pinned both walk permits for the whole stall, past the request
    /// budget, so later /ipfs requests took capacity 503s long after
    /// GITLAWB_IPFS_REQUEST_BUDGET_SECS elapsed, reachable by any unauthenticated
    /// caller. Here `pinned_cids` (the only table `oids_for_cid` reads) is held
    /// ACCESS EXCLUSIVE so the query blocks at lock acquisition.
    ///
    /// The follow-up after ROLLBACK is a 404 rather than a 200 because this scenario
    /// seeds no pin at all; "admitted and answered, never capacity-503'd" is what
    /// proves the permit came back.
    ///
    /// Load-bearing: pre-fix the bare await blocks on the lock until the 10s wrapping
    /// timeout fires (RED). MUTATION (RED): drop the `tokio::time::timeout` around
    /// `oids_for_cid` and this hangs past the wrap.
    #[sqlx::test]
    async fn get_by_cid_stalled_oids_query_frees_walk_permit(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Global walk pool of 1 so the held/freed permit is directly observable;
        // per-source cap permissive so only the global pool matters.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        state.config = Arc::new(cfg);

        let sem = state.git_ipfs_walk_semaphore.clone();
        // A well-formed CID with no `pinned_cids` row: the request still runs the
        // `oids_for_cid` lookup, which is the await under test.
        let cid = cid_for_oid(&absent_oid());
        let router = ipfs_router(state);

        let mut lock_conn = pool.acquire().await.unwrap();
        sqlx::raw_sql("BEGIN; LOCK TABLE pinned_cids IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut *lock_conn)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.81:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            router.clone().oneshot(get_cid(&cid, Some(peer))),
        )
        .await
        .expect("the budget clamp must return within budget; a bare await hangs on the lock")
        .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an oid lookup blocked past the request budget must shed a retryable 503"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the clamp must end the request at ~budget (1s); got {elapsed:?} \
             (pre-fix the bare await blocks on the lock for the whole stall)"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("budget"),
            "the shed must name the budget taint so it maps to \
             GITLAWB_IPFS_REQUEST_BUDGET_SECS; got: {body}"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "the walk permit must be freed on the budget-shed path, not held for the stall"
        );

        sqlx::raw_sql("ROLLBACK")
            .execute(&mut *lock_conn)
            .await
            .unwrap();
        drop(lock_conn);
        let resp2 = router.oneshot(get_cid(&cid, Some(peer))).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::NOT_FOUND,
            "with the permit freed and the lock released, a follow-up is ADMITTED and \
             answers 404 (no pin was seeded), never capacity-503'd"
        );
    }

    /// F2 (#174), second lockable site: `pin_sources_for_oid` runs once per candidate
    /// oid, still inside the admission-held region, and was likewise a bare await.
    ///
    /// The lock isolates it from the first await: `oids_for_cid` reads only
    /// `pinned_cids`, which stays unlocked, so it completes and the handler reaches
    /// the per-oid loop; `pin_sources_for_oid` also reads `pin_repo_sources`, which is
    /// held ACCESS EXCLUSIVE, so it is the query that blocks. A seeded legacy pin is
    /// what gives the loop an oid to iterate.
    ///
    /// Load-bearing: pre-fix the bare await blocks on the lock until the 10s wrap
    /// fires (RED). MUTATION (RED): drop the `tokio::time::timeout` around
    /// `pin_sources_for_oid`; that mutation must leave the `oids_for_cid` scenario
    /// above GREEN, which is what proves the two tests isolate their own queries.
    #[sqlx::test]
    async fn get_by_cid_stalled_pin_sources_query_frees_walk_permit(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        state.config = Arc::new(cfg);

        let sem = state.git_ipfs_walk_semaphore.clone();
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let router = ipfs_router(state);

        let mut lock_conn = pool.acquire().await.unwrap();
        sqlx::raw_sql("BEGIN; LOCK TABLE pin_repo_sources IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut *lock_conn)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.82:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            router.clone().oneshot(get_cid(&cid, Some(peer))),
        )
        .await
        .expect("the budget clamp must return within budget; a bare await hangs on the lock")
        .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a pin-source lookup blocked past the request budget must shed a retryable 503"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the clamp must end the request at ~budget (1s); got {elapsed:?} \
             (pre-fix the bare await blocks on the lock for the whole stall)"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("budget"),
            "the shed must name the budget taint so it maps to \
             GITLAWB_IPFS_REQUEST_BUDGET_SECS; got: {body}"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "the walk permit must be freed on the budget-shed path, not held for the stall"
        );

        sqlx::raw_sql("ROLLBACK")
            .execute(&mut *lock_conn)
            .await
            .unwrap();
        drop(lock_conn);
        let resp2 = router.oneshot(get_cid(&cid, Some(peer))).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::NOT_FOUND,
            "with the permit freed and the lock released, a follow-up is served (404 \
             against an empty repo set), never capacity-503'd"
        );
    }

    /// F6/KTD-5 FAIL CLOSED (security-critical): `list_visibility_rules_for_repos` is
    /// the access-control query. If its timeout let the handler fall through with an
    /// empty rule map, the loop would apply no visibility rules and serve an unfiltered
    /// listing — exposing a public repo's path-restricted blob. Here a PUBLIC repo
    /// carries the blob under a path-scoped rule that denies anon; `visibility_rules`
    /// is locked ACCESS EXCLUSIVE so the rule query blocks. The fix returns the budget
    /// 503 BEFORE the loop, so the handler NEVER serves (never 200). Since the scan was
    /// paged (#173, jatmn) the rules are fetched per PAGE, so this covers the clamp on
    /// every page rather than on one whole-inventory load.
    ///
    /// Load-bearing: pre-fix the bare await blocks on the lock until the 10s wrap fires
    /// (RED). After the fix it sheds the 503 at ~1s. The `assert_ne!(200)` is the
    /// fail-closed guard: a naive fix that `unwrap_or_default()`s the rules on timeout
    /// and falls through would serve the blob 200 and trip it.
    #[sqlx::test]
    async fn get_by_cid_visibility_rule_timeout_fails_closed(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);

        // A PUBLIC repo (upsert_mirror_repo sets is_public=true) carrying the blob,
        // with a path-scoped rule restricting src/** to a reader that is NOT the anon
        // caller. Rules applied => the blob is denied; rules skipped (fall-through) =>
        // the public repo serves it (the exposure this guard forbids).
        let (repo_id, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6f3failclosed", "gated", b"private\n").await;
        state
            .db
            .set_visibility_rule(
                &repo_id,
                "src/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkU3IpfsReaderDDDDDDDDDDDDDDDDDDDDDDDD".to_string()],
                "z6f3failclosed",
            )
            .await
            .unwrap();

        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        state.config = Arc::new(cfg);
        let sem = state.git_ipfs_walk_semaphore.clone();
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let router = ipfs_router(state);

        // Lock `visibility_rules` ACCESS EXCLUSIVE: the page query (on `repos`) still
        // succeeds, but list_visibility_rules_for_repos blocks on the rule query.
        let mut lock_conn = pool.acquire().await.unwrap();
        sqlx::raw_sql("BEGIN; LOCK TABLE visibility_rules IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut *lock_conn)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.81:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            router.oneshot(get_cid(&cid, Some(peer))),
        )
        .await
        .expect("the budget clamp must return within budget; a bare await hangs on the lock")
        .unwrap();
        let elapsed = started.elapsed();

        let status = resp.status();
        // Fail closed: the handler must NEVER emit the listing with no rules applied.
        assert_ne!(
            status,
            StatusCode::OK,
            "a visibility-rule query timeout must DENY, never serve the path-restricted \
             blob from the public repo (that would expose private content)"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a visibility-rule query blocked past the budget must shed the retryable budget 503"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the clamp must end the request at ~budget (1s); got {elapsed:?}"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("budget"),
            "the fail-closed shed must name the budget taint; got: {body}"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "the walk permit must be freed on the fail-closed budget-shed path"
        );

        sqlx::raw_sql("ROLLBACK")
            .execute(&mut *lock_conn)
            .await
            .unwrap();
        drop(lock_conn);
    }

    /// Seed a PROVENANCED pin whose single recorded source repo does not exist, and
    /// return its CID. `pin_sources_for_oid` therefore comes back NON-EMPTY (so
    /// `needs_scan` cannot short-circuit on `sources.is_empty()`) while the per-source
    /// loop takes the `get_repo_by_id -> None` arm and falls straight through to the
    /// marker pair. `pin_repo_sources` stays empty, so `pin_sources_at_cap` is `false`
    /// and the `||` goes on to evaluate `pin_sources_incomplete`.
    async fn seed_provenanced_pin_with_missing_source(
        state: &crate::state::AppState,
        oid: &str,
    ) -> String {
        let cid = cid_for_oid(oid);
        state
            .db
            .record_pinned_cid(oid, &cid, Some("repo-id-that-does-not-exist"))
            .await
            .expect("seed a provenanced pin row");
        cid
    }

    /// Shared body for the two marker-query stall cases. Arms the seam for `which`,
    /// drives one request, and asserts the whole budget-shed contract: a 503 inside the
    /// budget, a body naming the budget taint, the walk permit BACK in the pool rather
    /// than pinned for the stall, and a follow-up that is ADMITTED (404 here, since the
    /// fixture seeds no servable object) instead of capacity-shed.
    async fn assert_marker_query_stall_frees_walk_permit(
        pool: sqlx::PgPool,
        which: MarkerQuery,
        peer: SocketAddr,
        label: &str,
    ) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Global walk pool of 1 so the held/freed permit is directly observable;
        // per-source cap permissive so only the global pool matters.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_request_budget_secs = 1;
        state.config = Arc::new(cfg);

        let sem = state.git_ipfs_walk_semaphore.clone();
        let cid = seed_provenanced_pin_with_missing_source(&state, &absent_oid()).await;
        let router = ipfs_router(state);

        // 30s so the stall is decided by the 1s budget clamp, never by the sleep
        // finishing on its own.
        arm_marker_query_stall(which, std::time::Duration::from_secs(30));
        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            router.clone().oneshot(get_cid(&cid, Some(peer))),
        )
        .await
        .unwrap_or_else(|_| {
            disarm_marker_query_stall();
            panic!("{label}: the budget clamp must return within budget; a bare await hangs")
        })
        .unwrap();
        let elapsed = started.elapsed();
        disarm_marker_query_stall();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{label}: a marker query blocked past the request budget must shed a retryable 503"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "{label}: the clamp must end the request at ~budget (1s); got {elapsed:?} \
             (an unclamped await runs the full 30s stall)"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("budget"),
            "{label}: the shed must name the budget taint so it maps to \
             GITLAWB_IPFS_REQUEST_BUDGET_SECS; got: {body}"
        );
        // The scarce walk permit was RAII-dropped on the early return, not pinned for
        // the stall: the slot is free again the instant the request returns.
        assert_eq!(
            sem.available_permits(),
            1,
            "{label}: the walk permit must be freed on the budget-shed path, not held \
             for the stall"
        );

        // With the seam disarmed the follow-up is ADMITTED and answered (404, since the
        // fixture seeds no servable object), never capacity-503'd, which is what proves
        // the slot came back rather than staying pinned.
        let resp2 = router.oneshot(get_cid(&cid, Some(peer))).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::NOT_FOUND,
            "{label}: with the permit freed, a follow-up is admitted and answers 404, \
             never capacity-503'd"
        );
    }

    /// F2 (#174), marker pair, first query: `pin_sources_at_cap` runs on a provenance
    /// MISS, still inside the admission-held region, and pre-fix was a bare await. A
    /// query blocked in Postgres there pinned the walk permits for the whole stall,
    /// past the request budget, capacity-503'ing later requests from any
    /// unauthenticated caller.
    ///
    /// This one needs the `#[cfg(test)]` fault-injection seam rather than a `LOCK TABLE`
    /// fixture: it reads `pin_repo_sources`, which `pin_sources_for_oid` already read
    /// earlier in the same region, so a table lock stalls that earlier await and the RED
    /// lands on the wrong clamp. See `MARKER_QUERY_STALL` for the full reasoning. The
    /// injected sleep sits INSIDE the `tokio::time::timeout`, so the clamp is what ends
    /// the request.
    ///
    /// MUTATION (RED): replace the clamp around `pin_sources_at_cap` with the bare
    /// await, keeping the seam, and the request runs the full 30s stall past the 10s
    /// wrap.
    #[sqlx::test]
    async fn get_by_cid_stalled_pin_sources_at_cap_frees_walk_permit(pool: sqlx::PgPool) {
        assert_marker_query_stall_frees_walk_permit(
            pool,
            MarkerQuery::AtCap,
            "203.0.113.83:5000".parse().unwrap(),
            "pin_sources_at_cap",
        )
        .await;
    }

    /// F2 (#174), marker pair, second query: `pin_sources_incomplete` is a SEPARATE
    /// clamp, evaluated only when `pin_sources_at_cap` came back `false`, and carries
    /// the same pre-fix bare-await exposure. The fixture leaves `pin_repo_sources`
    /// empty so `at_cap` is `false` and the `||` actually reaches this query; the seam
    /// is armed for `Incomplete` only, so the first query is untouched and the RED is
    /// attributable to this clamp alone.
    ///
    /// It reads `pinned_cids`, which `oids_for_cid` and `pin_sources_for_oid` already
    /// read, so it is unlockable for the same reason as its sibling above.
    ///
    /// MUTATION (RED): replace the clamp around `pin_sources_incomplete` with the bare
    /// await, keeping the seam, and the request runs the full 30s stall past the 10s
    /// wrap.
    #[sqlx::test]
    async fn get_by_cid_stalled_pin_sources_incomplete_frees_walk_permit(pool: sqlx::PgPool) {
        assert_marker_query_stall_frees_walk_permit(
            pool,
            MarkerQuery::Incomplete,
            "203.0.113.84:5000".parse().unwrap(),
            "pin_sources_incomplete",
        )
        .await;
    }
}
