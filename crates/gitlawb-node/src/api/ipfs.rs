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
/// amplification sink (INV-10). Once this many walks have run IN A PHASE, no further
/// walk is spawned for that phase: any remaining candidate there that still needs
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
///
/// The ceiling is charged PER PHASE (#173 round 13, F3), and that is what makes the
/// paragraph above hold for the fallback too: the legacy-scan fallback gets its own
/// equal budget rather than the provenance phase's remainder, so one request can spawn
/// up to `2 * walk_cap` walks in total and no more. Without the split, a source set of
/// root-readable but path-scoped denials spends the whole ceiling reaching its denials,
/// and the fallback armed to find the PUBLIC source `record_pin_source` silently
/// dropped cannot walk to it, a deterministic 503 on every retry for an object that is
/// public.
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

/// Hard per-request ceiling on how many repo ROWS the legacy scan's pager may fetch
/// (#173 round 13, F2, INV-10). The probe ceiling above only starts counting once a
/// probe runs, and the two denial classes that dominate a hostile inventory
/// (quarantine and a root-scope visibility deny) return before either `walk.probes`
/// or `walk.visits` increments. So an all-quarantined or all-root-denying node paged
/// through its ENTIRE repo table at zero probes, anonymously, retaining every row and
/// rule set, while holding one of the scarce global walk permits for up to the whole
/// request budget. This ceiling is what the DB-facing selection actually stops on.
///
/// Reaching a holder buried past the ceiling costs `ceil(repos / ceiling) + 1`
/// token-echoing retries: a truncated scan sheds the retryable 503 with a sealed
/// continuation (`ScanPosition`), and the caller echoes it as `?scan=` to resume
/// exactly where the previous page stopped. No server-side scan state exists, so
/// concurrent callers cannot advance or reset each other's ladder.
///
/// Above roughly `ceiling * (work-budget page term)` rows the bound's total page cost
/// exceeds one work-budget window, so a caller laddering a very large inventory will
/// meet the per-IP page toll before the end and resume after their bucket refills.
///
/// Tuning DOWN has a cost worth stating: token presence is a coarse inventory-size
/// oracle. A ceiling truncation emits a token; a wrapped scan does not, so laddering
/// until the `scan-wrapped` taint tells an anonymous caller the node's TOTAL repo
/// count (private and quarantined rows included) to within one ceiling. At the 2048
/// default that is tolled and coarse; it sharpens as the ceiling is lowered.
///
/// Tunable via `GITLAWB_IPFS_MAX_LEGACY_SCAN_ROWS` / `AppState`.
pub(crate) const MAX_LEGACY_SCAN_ROWS_PER_REQUEST: usize = 2048;

/// Hard per-request ceiling on the BYTES of visibility rules the legacy scan's pager may
/// retain (#173 round 13, F2, INV-10). The row ceiling bounds the row count but not the
/// memory each row drags in: `fetch_next_page` keeps every fetched page's rules in
/// `LegacyScanPager::rules` for the whole request (a later oid candidate re-reads them
/// rather than re-querying), so a node whose repos each carry many path-scoped rules is
/// retained-memory-unbounded at a row count well under the row ceiling.
///
/// Bytes, not a rule count, because a count is the wrong unit for a memory bound: an
/// owner controls how many rules their repos carry AND how long each rule's
/// `reader_dids` list is, so a handful of rules can retain as much as thousands.
///
/// Enforced IN THE QUERY (`Db::list_visibility_rules_for_repos_bounded`), not by summing
/// the page once it has landed. A post-fetch sum truncates the request but leaves the
/// transfer and the allocation already paid, so it bounds the result and not the work,
/// which is the wrong half of INV-10 on an anonymously reachable route. The query cuts on
/// a repo boundary and reports where; `fetch_next_page` drops the page's tail there and
/// mints a continuation, so the page that would have blown the budget truncates the
/// request that bought it without ever being materialized.
///
/// Not an operator knob: it is a memory guard, not a reach/coverage tradeoff. 4 MiB is
/// about 2 KiB per row at the default row ceiling, which is a generous rule set per repo
/// and still a bounded allocation for one anonymous GET.
pub(crate) const MAX_LEGACY_SCAN_RULE_BYTES_PER_REQUEST: usize = 4 * 1024 * 1024;

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
    /// True when `cursor` was seeded from a caller-supplied continuation token rather
    /// than starting at the front. Half of the `"scan-wrapped"` condition: absence is
    /// only ever proven over `[start, end)`, so a resumed scan that runs off the end
    /// has NOT covered `[front, start)` and must never reach the definitive 404.
    resumed: bool,
    /// Rows fetched THIS request, the quantity the row ceiling bounds. Distinct from
    /// `rows.len()`, which is the same number today but would silently stop tracking
    /// the DB-facing cost if the pager ever dropped gated rows.
    fetched_rows: usize,
    /// Bytes of visibility rules retained this request, the quantity the rules ceiling
    /// bounds.
    fetched_rule_bytes: usize,
    /// Set by `fetch_next_page` when the rules query CUT the page it just fetched, that
    /// is when the byte budget stopped the query part-way through the page's repos. The
    /// flag exists because the decision has to happen where the fetch happens: measuring
    /// only when another page is contemplated lets the page that actually blew the budget
    /// go unnoticed on a scan that ends there, and measuring after the fetch bounds the
    /// result rather than the work.
    rule_bytes_exceeded: bool,
}

/// Retained size of one visibility rule, in bytes.
///
/// The heap the pager holds for a rule is its owned strings, and the one an owner can
/// grow without limit is `reader_dids` (there is no per-repo rule cap and no per-rule
/// reader cap). Counting the strings rather than the struct is what makes this track
/// the thing that can actually get large; the fixed fields are noise beside a long
/// reader list.
fn rule_retained_bytes(rule: &crate::db::VisibilityRule) -> usize {
    rule.id.len()
        + rule.repo_id.len()
        + rule.path_glob.len()
        + rule.created_by.len()
        + rule.reader_dids.iter().map(String::len).sum::<usize>()
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
        // The row ceiling bounds what this REQUEST costs the database, so the ask is the
        // smaller of one page and what is left of the budget. Capped in the LIMIT rather
        // than by trimming the page once it has landed, because a trim bounds the result
        // and leaves the selection, the transfer and the allocation already paid, which is
        // the wrong half of the guarantee on an anonymously reachable route.
        let remaining = state
            .ipfs_max_legacy_scan_rows
            .saturating_sub(self.fetched_rows);
        let limit = state.ipfs_legacy_scan_page_rows.min(remaining);
        // The caller's arm ordering is what guarantees this: `get_by_cid`'s row-ceiling
        // arm breaks and mints a continuation before reaching this fetch once
        // `fetched_rows >= ipfs_max_legacy_scan_rows`, so the budget always has room here.
        debug_assert!(
            limit >= 1,
            "legacy scan LIMIT must ask for at least one row"
        );
        // Record the DB-facing ask before it is made. It sits above the timeout opener
        // because the committed guard that checks this query is deadline-wrapped reads a
        // fixed lookback from the query call, and anything inserted inside that window
        // eats its margin.
        #[cfg(test)]
        note_scan_limit(limit);
        let page = match tokio::time::timeout(
            request_deadline.saturating_duration_since(std::time::Instant::now()),
            state.db.list_repos_page_for_scan(after, limit as i64),
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
        self.fetched_rows += page.len();
        // Measured on the FULL page the query returned, before any rules cut shortens it:
        // this is the DB-facing row cost the row ceiling bounds, and a page that is short
        // is a page with nothing behind it whatever the rules do. Compared against the
        // limit ACTUALLY sent, not the page size: once the budget can shorten the ask, a
        // page shorter than a full page proves nothing about the table, and marking the
        // scan exhausted there breaks at the top-of-loop arm that sits ahead of every
        // ceiling arm, taints nothing and mints no token, so existing content returns a
        // false definitive 404.
        if page.len() < limit {
            self.exhausted = true;
        }
        if page.is_empty() {
            return Ok(());
        }
        let mut page = page;
        let repo_ids: Vec<String> = page.iter().map(|r| r.repo.id.clone()).collect();
        // The budget is per REQUEST, so what this page may spend is what is left of it.
        // A cut ends the scan, so the remaining budget is only ever zero on a page bought
        // after the always-admit escape overshot, and zero still admits one repo.
        let budget_left = state
            .ipfs_max_legacy_scan_rule_bytes
            .saturating_sub(self.fetched_rule_bytes);
        let (rules, cut_at) = match tokio::time::timeout(
            request_deadline.saturating_duration_since(std::time::Instant::now()),
            state
                .db
                .list_visibility_rules_for_repos_bounded(&repo_ids, budget_left),
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
        #[cfg(test)]
        note_scan_rule_rows(rules.values().map(Vec::len).sum());
        // The bound lives in the QUERY, not in a sum taken once the page has landed. A
        // rules query answers with whatever the matched repos carry, and nothing caps
        // that per repo: a post-fetch sum truncated the request but left the transfer and
        // the allocation already paid, which bounds the RESULT rather than the WORK. So
        // the cut comes back from the database and the oversized tail is never
        // materialized at all. Bytes rather than a rule count for the same reason as
        // before: the quantity an owner can grow is the length of each `reader_dids`
        // list, not the number of rows in `visibility_rules`.
        if let Some(cut) = cut_at {
            // The rows from the cut onward were never rule-loaded. Gating them against an
            // empty rule map would read as "no restrictions" and FAIL OPEN, so they are
            // dropped from the page entirely and the cursor stops in front of them.
            //
            // `max(1)` is belt and braces over the query's own guarantee that the first
            // rule-carrying repo is always admitted. A cut at 0 would leave the cursor
            // where it was, the caller's next request would reproduce this page exactly,
            // and the ladder would be wedged on a permanent 503.
            page.truncate(cut.max(1));
            self.rule_bytes_exceeded = true;
            // This page had rows behind the cut, so the table is NOT covered even if the
            // page itself was short. This replaces the old `!exhausted` condition: the
            // taint now keys on the query having left repos unloaded rather than on the
            // page's length. A short final page whose rules all fit produces no cut, so a
            // scan that genuinely covered the table is still the definitive 404 it was,
            // and a short final page that IS cut is honestly incomplete and resumable.
            self.exhausted = false;
        }
        let last = page.last().expect("the cut always leaves at least one row");
        self.cursor = Some((last.created_at_key.clone(), last.repo.id.clone()));
        self.fetched_rule_bytes += rules
            .values()
            .flat_map(|v| v.iter())
            .map(rule_retained_bytes)
            .sum::<usize>();
        self.rules.extend(rules);
        self.rows.extend(page);
        Ok(())
    }
}

/// Query string of `GET /ipfs/{cid}`.
#[derive(serde::Deserialize)]
pub struct ScanQuery {
    /// Sealed continuation from a previous truncated scan's 503 body. Opened with the
    /// key derived from the node's persistent identity (`AppState::derive_scan_token_key`,
    /// so a restart does not invalidate it) and the request's canonical CID as associated data; ANY
    /// failure (undecryptable, tampered, expired, malformed, minted for another CID) is
    /// treated as absent and the scan starts at the front, identically and silently, so
    /// the token is no oracle.
    scan: Option<String>,
}

/// How long a continuation stays usable. Long enough for a caller to walk a ladder at a
/// human pace and to ride out a work-bucket throttle; short enough that a leaked token
/// stops being a valid scan seed quickly. An expired token is simply absent.
const SCAN_TOKEN_TTL_SECS: i64 = 3600;

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
    axum::extract::Query(scan_query): axum::extract::Query<ScanQuery>,
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

    // A SECOND, much shorter absolute clock, anchored here at admission, bounding only
    // the pre-walk CID resolve below (#174 F4). The request budget alone is 600s by
    // default, and a syntactically valid CID with no `pinned_cids` row runs zero probes
    // and zero walks, so a resolve stalled in Postgres held these scarce permits for the
    // whole 600s while nothing walked; enough distinct source keys doing that
    // capacity-503 every real `/ipfs` retrieval at admission. Admission deliberately
    // stays FIRST: resolving before taking it would let arbitrarily many unadmitted
    // permissionless callers stack concurrent DB queries, trading one amplification for
    // another, so the repair is a shorter deadline on the stage rather than a reorder.
    let resolve_deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(state.config.ipfs_resolve_budget_secs);

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
    //
    // Which of the two clocks each await runs on (#174 F4), enumerated once here:
    //   - `oids_for_cid` runs on the SHORT resolve budget (clamped by the request
    //     budget). It is the one await that decides whether the request does any
    //     admitted work at all; nothing has been paid for yet when it runs, so a shed
    //     there discards nothing but the permits it is holding.
    //   - EVERYTHING after it stays on the FULL request budget. `pin_sources_for_oid`
    //     runs once per oid candidate and from the second candidate on runs after real
    //     probe and walk work; the marker pair runs only on a provenance miss, which is
    //     after the per-source loop may already have walked; the per-source trio and the
    //     legacy pager's fetches interleave with admitted walk work by construction. A
    //     short deadline anchored at admission would be long spent by the time those run
    //     in a legitimately slow scan, so putting any of them under it sheds a
    //     PROGRESSING request rather than an idle one.
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
    //
    // Clamped to the LESSER of the resolve budget and the request budget, so a resolve
    // budget set larger than the request budget degrades to the request budget instead
    // of extending it.
    let resolve_remaining = resolve_deadline.saturating_duration_since(std::time::Instant::now());
    let oids = match tokio::time::timeout(
        std::cmp::min(resolve_remaining, remaining()),
        state.db.oids_for_cid(&canonical_cid),
    )
    .await
    {
        Ok(Ok(v)) => v,
        // Bare conversion, never `AppError::Internal`: a connection-class sqlx failure
        // downcasts to `AppError::Db` and answers 503 `db_unavailable` rather than a 500
        // (#251). Every clamped site in this handler uses this arm for the same reason,
        // so a stalled pool and a closed pool stay distinguishable to the caller.
        Ok(Err(e)) => return Err(e.into()),
        Err(_elapsed) => {
            // Name the clock that actually bound this await, in the log AND in the body:
            // the two budgets are separately settable, so pointing an operator at the
            // knob that did nothing here is the same defect as not naming one at all.
            // Compared as DEADLINES, not as remainders read at two different instants:
            // when the two clocks coincide the later read is always the smaller one, so
            // a remainder comparison would attribute a tie to whichever was read second.
            if resolve_deadline <= request_deadline {
                tracing::warn!(
                    resolve_budget_secs = state.config.ipfs_resolve_budget_secs,
                    "/ipfs oids_for_cid exceeded the pre-walk resolve budget \
                     (GITLAWB_IPFS_RESOLVE_BUDGET_SECS); shedding a retryable 503 and freeing the walk permit"
                );
                return Err(AppError::Overloaded(format!(
                    "ipfs resolve incomplete (resolve budget) for CID {cid_str}; retry shortly"
                )));
            }
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
        provenance_walks: 0,
        scan_walks: 0,
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
    // Resume from the caller's sealed continuation, if they sent one that opens. The
    // node holds NO scan state of its own: the position rides in the token, which is
    // what keeps concurrent ladders from advancing or resetting each other. Every
    // failure class (tampered, a prior boot's key, expired, malformed, minted for a
    // different CID) lands on the same `None` and starts at the front, silently,
    // so no probe distinguishes them (INV-13).
    //
    // The position names the CANDIDATE it resumes as well as the row, so opening it is
    // two steps: locate that candidate in the freshly ordered list, then seed the row.
    // A sealed hex that is no longer in the list (the object was unpinned under that oid
    // between rungs) is treated exactly like an absent token, restarting at the front,
    // rather than resumed against some other candidate or turned into a 404 built from a
    // table this request never looked at.
    let mut resumed_at: Option<usize> = None;
    // Where this REQUEST started, kept for the strictly-ahead filter at the mint site. A
    // front-started request leaves it `None`, which reads as "before everything", so every
    // seal it proposes passes.
    let mut scan_start: Option<(String, (String, String))> = None;
    if let Some(token) = scan_query.scan.as_deref() {
        if let Some(pos) = gitlawb_core::scan_token::open_scan_token(
            &state.ipfs_scan_token_key,
            &canonical_cid,
            token,
            chrono::Utc::now().timestamp(),
        ) {
            if let Some(at) = oids.iter().position(|oid| *oid == pos.sha256_hex) {
                resumed_at = Some(at);
                scan_start = Some((
                    pos.sha256_hex.clone(),
                    (pos.created_at_key.clone(), pos.id.clone()),
                ));
                // The empty row pair is the front-of-table sentinel: "this candidate, no
                // row cursor yet", which is what the advance to the next candidate seals.
                // It cannot collide with a real row: `repos.created_at` is NOT NULL and
                // written from a serialized timestamp, and `repos.id` is `{owner}/{name}`
                // so it always contains a slash.
                pager.cursor = (!pos.created_at_key.is_empty() || !pos.id.is_empty())
                    .then_some((pos.created_at_key, pos.id));
                // Set even under the sentinel, where the row walk does start at the front:
                // this request SKIPPED the candidates ordered before the resumed one, so
                // absence is not proven within it and the tail must keep the retryable
                // shed rather than fall through to the definitive 404.
                pager.resumed = true;
            }
        }
    }
    // The one position the caller echoes back, written at most once per request: by the
    // ceiling that truncated the request's proposer, or by that proposer's finish handing
    // the ladder to the next oid candidate. Sealed at the tail rather than here so
    // exactly one site mints a token and the wrap case can clear it in one place.
    let mut scan_continuation: Option<SealedScanPos> = None;
    // True while every candidate ahead of the one being walked FINISHED this request.
    // On a front-started request that is the proposer rule: the first candidate that did
    // not finish owns the seal, and once it finishes the role passes to the next one.
    let mut earlier_all_finished = true;

    for (cand_idx, sha256_hex) in oids.iter().enumerate() {
        // Exactly ONE candidate per request may seal a position or advance the ladder,
        // and which one depends on where the REQUEST started, not on which candidate is
        // interesting.
        //
        // RESUMED: only the resumed candidate. The pager was seeded from the caller's
        // cursor, so `pager.rows` holds the suffix `[start_row, end)`; a later candidate
        // that walks "from index 0" walked that suffix and has never seen
        // `[front, start_row)`. Letting it seal would record coverage it does not have
        // and strand every row in front of the caller's cursor.
        //
        // FRONT-STARTED: the first candidate that has not finished. Here the suffix
        // argument does not exist: every candidate's row loop covers the fetched table
        // from the front, so a later candidate's ceiling stop is honest coverage. This
        // arm is what mints rung 1 when the first candidate wraps under budget and a
        // later one stops on a settled row; silencing it would shed a tainted tokenless
        // 503 and end a ladder that works today.
        let is_proposer = match resumed_at {
            Some(at) => cand_idx == at,
            None => earlier_all_finished,
        };
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
                // The provenance path targets a bounded source list rather than the
                // table, so there is no scan position to resume from: taint and move on,
                // exactly as before. Only the visit ceiling can reach here (the probe
                // ceiling is `legacy_scan`-only).
                GateOutcome::CeilingStop(reason) => {
                    record_scan_truncation(
                        &mut walk,
                        &mut scan_continuation,
                        reason,
                        None,
                        sha256_hex,
                        is_proposer,
                    );
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
                // Skipped for a spent bucket is NOT finished: no scan ran, so nothing was
                // covered. Leaving it unfinished keeps the proposer role here, so the
                // caller's existing token resumes this candidate once the bucket refills
                // instead of the ladder advancing past work that never happened.
                earlier_all_finished = false;
                continue;
            }
        }
        // Earlier candidates were finished by earlier rungs, so their scans are owed
        // nothing. The skip sits HERE on purpose: above it the provenance phase can still
        // serve outright from a recorded source, and below it the two marker queries would
        // charge a spent-for-nothing lookup pair per skipped candidate.
        if resumed_at.is_some_and(|at| cand_idx < at) {
            continue;
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
        // Set when THIS candidate's row loop exits having walked every row the pager
        // fetched. It is the witness that the candidate covered the table, and it must be
        // per candidate: the shared `pager.exhausted` is a per-REQUEST flag set the moment
        // any short page is fetched, so a candidate that a ceiling stopped mid-page would
        // read as covered and the ladder would advance over the rows it refused.
        let mut wrapped = false;
        if needs_scan {
            // Walk the candidate repos one bounded page at a time. Pages already
            // fetched by an earlier oid candidate are re-read from `pager.rows` for
            // free; only the tail of the scan costs another query.
            let mut idx = 0usize;
            loop {
                if idx == pager.rows.len() {
                    if pager.exhausted {
                        wrapped = true;
                        break;
                    }
                    // Buying another page is only worth its query if a row on it could
                    // still reach a verdict, and a verdict needs the probe and the
                    // acquire these ceilings are refusing. Spent means stop reading —
                    // this is the check that keeps the DB-facing selection bounded, so
                    // a one-probe request cannot pull the node's whole inventory.
                    //
                    // A page of pure denials is still NOT a hard stop into a 404: a
                    // quarantined row or a visibility deny costs no probe, so paging
                    // must continue past them or a public object buried behind many
                    // private repos would falsely 404. What bounds that case is not a
                    // denial count but the DB-facing ceilings just below, and every
                    // truncation they cause carries a continuation so the buried object
                    // stays reachable across requests (#173 round 13, F2).
                    //
                    // Stopping at any of these leaves every unread repo unproven, so
                    // each TAINTS: the tail sheds a retryable 503 naming the ceiling,
                    // never a definitive 404 (#173, F2).
                    //
                    // All four breaks fire at `idx == pager.rows.len()`, so
                    // `pager.cursor` is the same well-defined resume boundary in every
                    // arm and every one of them mints a continuation. These two are not
                    // an afterthought to the two below: the probe and visit ceilings
                    // BIND FIRST on any inventory carrying root-readable repos, long
                    // before the far larger row ceiling, so a tokenless break here is
                    // the common case rather than the rare one, and a tokenless shed is
                    // byte-identical to the wrapped-scan answer that tells the caller
                    // their ladder is over.
                    if walk.probes >= state.ipfs_max_legacy_probes {
                        record_scan_truncation(
                            &mut walk,
                            &mut scan_continuation,
                            "probe-ceiling",
                            pager.cursor.clone(),
                            sha256_hex,
                            is_proposer,
                        );
                        break;
                    }
                    if walk.visits >= state.config.ipfs_max_repo_visits {
                        record_scan_truncation(
                            &mut walk,
                            &mut scan_continuation,
                            "visit-ceiling",
                            pager.cursor.clone(),
                            sha256_hex,
                            is_proposer,
                        );
                        break;
                    }
                    // Row ceiling (F2). The two checks above only bind once a probe or a
                    // visit has been spent, and the gate returns Skip on quarantine and
                    // on a root-scope deny BEFORE either counter moves, so an
                    // all-denying inventory paged the node's whole repo table at zero
                    // probes, anonymously, while holding a scarce walk permit. This is
                    // the check that actually stops that scan.
                    if pager.fetched_rows >= state.ipfs_max_legacy_scan_rows {
                        record_scan_truncation(
                            &mut walk,
                            &mut scan_continuation,
                            "row-ceiling",
                            pager.cursor.clone(),
                            sha256_hex,
                            is_proposer,
                        );
                        break;
                    }
                    // Rule-bytes ceiling: the row ceiling bounds rows, not the rules each
                    // row drags in, and the pager retains every fetched page's rules for
                    // the whole request. The cut is made by the QUERY, so the oversized
                    // tail is never materialized; `fetch_next_page` drops the rows behind
                    // it and the request that asked for them is the one that truncates.
                    if pager.rule_bytes_exceeded {
                        record_scan_truncation(
                            &mut walk,
                            &mut scan_continuation,
                            "rules-ceiling",
                            pager.cursor.clone(),
                            sha256_hex,
                            is_proposer,
                        );
                        break;
                    }
                    // Page toll (F2). Every page is work bought by an anonymous caller,
                    // so it is charged to the per-IP WORK bucket (the same bucket the
                    // per-probe charge debits) immediately before the query it pays
                    // for. Without it a denial-only inventory could be re-paged for free
                    // by re-requesting, which is the across-request half of the same
                    // amplification. Reuses the `source_key` already resolved at
                    // admission; no resolvable key (a test oneshot with no peer or
                    // trusted header) skips the charge, exactly as the walk and probe
                    // brakes do.
                    //
                    // A spent bucket sets `throttled` and breaks WITHOUT tainting and
                    // WITHOUT a token: the caller's own bucket stopped them, their
                    // previous token still resumes them after it refills, and the tail
                    // renders the 429 when nothing else tainted.
                    if let Some(key) = &source_key {
                        if !state.ipfs_work_rate_limiter.check(key).await {
                            throttled = true;
                            break;
                        }
                    }
                    pager
                        .fetch_next_page(&state, request_deadline, &cid_str)
                        .await?;
                    if idx == pager.rows.len() {
                        // The other walked-every-fetched-row exit, and on any inventory
                        // whose row count is a multiple of the page size it is the NORMAL
                        // end of the table: `fetch_next_page` only sets `exhausted` on a
                        // SHORT page, so a full last page leaves the flag clear and the
                        // empty page after it lands here. Instrumenting only the
                        // `exhausted` break above leaves `wrapped` false on that path and
                        // the ladder dies tokenless with later candidates unexamined.
                        wrapped = true;
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
                    // A ceiling refused THIS row, so the resume position is the row in
                    // front of it, not `pager.cursor`, which by now sits at the end of
                    // the fetched page and would skip every row the ceiling refused. The
                    // four arms at the top of the loop seal `pager.cursor` legitimately:
                    // they only fire once every fetched row has been walked.
                    //
                    // Stopping here rather than skipping on is also why the FINAL page is
                    // covered: the `pager.exhausted` break sits ahead of every mint arm,
                    // so a ceiling reached while walking the last page used to shed with
                    // no token at all.
                    GateOutcome::CeilingStop(reason) => {
                        // Nothing in front of it means nothing was settled, so there is
                        // no position to seal and this stop contributes none. Only a
                        // LATER candidate reaches this with nothing settled: it re-walks
                        // the already-fetched rows from index 0 without passing the
                        // ceiling arms above, so it can be refused on its very first row.
                        // The candidate that fetched those rows cannot, because those
                        // arms run before every fetch and a spent budget breaks there
                        // instead. Sealing `pager.cursor` here would push the resume
                        // position past rows this candidate never examined.
                        let resume = (idx >= 2).then(|| {
                            let prev = &pager.rows[idx - 2];
                            (prev.created_at_key.clone(), prev.repo.id.clone())
                        });
                        record_scan_truncation(
                            &mut walk,
                            &mut scan_continuation,
                            reason,
                            resume,
                            sha256_hex,
                            is_proposer,
                        );
                        break;
                    }
                    GateOutcome::Skip => {}
                }
            }
        }

        // FINISHED: this candidate covered everything it was owed this request, either by
        // walking every fetched row (`wrapped`) or by owing no scan at all. The
        // `needs_scan` arm is not a nicety: a properly provenanced candidate runs no row
        // loop, so without it the resumed candidate can never finish, the advance below
        // never fires, and the ladder dies tokenless with later candidates unexamined.
        //
        // No "and sealed nothing" conjunct: every truncation arm in the row loop breaks
        // out of it immediately, so one candidate cannot both seal and walk to the end in
        // a single request.
        let finished = wrapped || !needs_scan;
        if !finished {
            earlier_all_finished = false;
        }
        // The advance. On a RESUMED request the proposer's finish is what moves the ladder
        // to the next candidate, sealed at the front-of-table sentinel because that
        // candidate has to walk the whole table with a fresh budget. It goes through
        // `record_scan_truncation` so the walk is TAINTED as well as sealed: the tail
        // emits a continuation only on a tainted walk, so a bare seal here would be
        // discarded and the request would fall through to a definitive 404.
        //
        // Not on a front-started request: there the proposer role simply passes to the
        // next unfinished candidate within this same rung, and that candidate seals its
        // own stop row.
        //
        // The final candidate's finish deliberately seals nothing. Absence of a token is
        // the ladder's end-of-run signal, and the scan-wrapped clause below turns it into
        // the retryable shed.
        if is_proposer && finished && resumed_at.is_some() {
            if let Some(next) = oids.get(cand_idx + 1) {
                record_scan_truncation(
                    &mut walk,
                    &mut scan_continuation,
                    "candidate-advance",
                    Some((String::new(), String::new())),
                    next,
                    true,
                );
            }
        }
    }

    // A RESUMED scan that reached the end of the table has proven absence only over
    // `[token, end)`; the rows before the token were never looked at this request, so
    // the definitive 404 is not available and the honest answer is the retryable 503.
    //
    // The condition is evaluated HERE, on `pager.exhausted`, and deliberately not at any
    // particular break site. That is what covers the degenerate zero-row resume: a token
    // at or past the last row (which the row ceiling emits whenever the row count is an
    // exact multiple of the ceiling, and which repo deletion between ladder steps also
    // reaches) fetches an EMPTY short page, sets `exhausted`, and breaks without
    // gating anything. An implementation keying this on having fetched a page passes
    // every other case and turns exactly that incomplete search into a false 404.
    //
    // A wrapped scan emits NO continuation: there is nothing left to resume, and the
    // absence of the token is what tells the caller their ladder is over. With several
    // oid candidates that is the FINAL candidate's wrap; an earlier one's hands the
    // ladder on instead, and the seal it leaves in the slot is what keeps this clause off.
    //
    // Gated on nothing having been sealed, for two reasons now. A ceiling can stop a
    // resumed scan PART WAY through the last page, which leaves `exhausted` set with rows
    // still unwalked in front of the cursor; and on a multi-candidate CID the request may
    // already carry the advance to the next candidate. Either way the walk is over for
    // this rung but the search is not, and clearing the seal would strand exactly what
    // the token was minted to reach.
    if pager.resumed && pager.exhausted && scan_continuation.is_none() {
        walk.taint("scan-wrapped");
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
    //     shed to the right knob or backend, and carries no object/OID/metadata. When a
    //     ceiling was the cut, the shed also carries the sealed continuation the caller
    //     echoes as `?scan=` to resume.
    //
    //     ONE deliberate exception to that precedence (#173 round 13, F2): the legacy
    //     scan's PAGE toll breaks the pager WITHOUT tainting, so a request stopped only
    //     by its own spent work bucket falls through to the 429 below rather than the
    //     503 here. The reason is that a 503 says "the node's search was cut short,
    //     retry" and invites an immediate retry straight back into the same empty
    //     bucket; a 429 names what actually stopped the caller and carries the honest
    //     wait. Their previously issued token is still valid, so the retry after the
    //     refill resumes rather than restarts. A request that tainted for any OTHER
    //     reason and then also ran its bucket dry still lands here, per the ordering
    //     as written.
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
        // Seal the continuation HERE, the single mint site. The position is the last
        // row the pager FETCHED, and on a scan that served nothing every fetched row is
        // by construction private or quarantined, so its `created_at` and its `id`
        // (which carries the owner's DID) are withheld fields and the token must be
        // confidential, not merely tamper-evident (INV-13). A seal failure is not fatal
        // to the shed: drop the continuation and answer the plain 503, which degrades to
        // the pre-token behaviour rather than turning a truncation into a 500.
        // A rung owes a token only when it reached somewhere the caller has not already
        // been. `walk.visits` is charged by the provenance phase as well as the scan, so a
        // resumed request whose sources spend the ceiling reaches the scan's top-of-loop
        // visit arm with nothing fetched, and `pager.cursor` is still the caller's own
        // incoming position: sealing it hands them back the token they just sent. `gl`
        // echoes a token up to its resume cap, each rung re-running the whole provenance
        // phase, so the ladder amplifies one anonymous request into nine while advancing
        // nothing and the token makes it look like progress.
        //
        // Strictly ahead has two arms. A proposal naming the SAME candidate must carry a
        // row past the start row. A proposal naming a DIFFERENT candidate is the advance,
        // which only a finished candidate can produce, so it is ahead by construction even
        // though the front sentinel it seals sorts below every real row.
        //
        // ONE site, the same argument the single mint site is already built on: a filter
        // here cannot be bypassed by a future sealing arm. The ceiling arms stay uniform
        // (all of them seal `pager.cursor`) rather than each carrying a copy of this rule.
        //
        // The row comparison is Rust's byte-wise `Ord` on `(created_at_key, id)`, while the
        // pager's keyset predicate ordered the same TEXT columns under the DATABASE's
        // collation, so on a non-`C` collation the two can disagree for ids differing in
        // case or punctuation. It cannot skip rows: a dropped seal claims no coverage, it
        // only ends the rung, and the caller's recovery is a fresh ladder from the front.
        // The case this filter exists for is exact equality of a value with itself, which
        // no collation moves.
        let advancing = scan_continuation.filter(|sealed| {
            let advanced = match &scan_start {
                None => true,
                Some((start_hex, start_row)) => {
                    sealed.sha256_hex != *start_hex || sealed.row > *start_row
                }
            };
            if !advanced {
                // `record_scan_truncation` already logged `sealed_continuation = true` for
                // this seal, and a 503 carrying no token next to that line is exactly the
                // confusion that log exists to prevent. This is the correction, and like
                // the line it corrects it is a boolean fact only: the position and the
                // candidate it names are withheld data.
                tracing::debug!(
                    seal_dropped_not_advancing = true,
                    "/ipfs dropped a scan continuation that reached no row past the \
                     request's own start; shedding without one"
                );
            }
            advanced
        });
        let continuation = advancing.and_then(|sealed| {
            let SealedScanPos {
                row: (created_at_key, id),
                sha256_hex,
            } = sealed;
            match gitlawb_core::scan_token::seal_scan_token(
                &state.ipfs_scan_token_key,
                &canonical_cid,
                &gitlawb_core::scan_token::ScanPosition {
                    created_at_key,
                    id,
                    sha256_hex,
                },
                chrono::Utc::now().timestamp() + SCAN_TOKEN_TTL_SECS,
            ) {
                Ok(token) => Some(token),
                Err(e) => {
                    tracing::warn!(error = %e, "/ipfs could not seal a scan continuation; \
                         shedding the truncation 503 without one");
                    None
                }
            }
        });
        return Err(AppError::SearchIncomplete {
            message: format!(
                "CID {cid_str} search incomplete ({}); retry",
                walk.truncated_by.join("+")
            ),
            continuation,
        });
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
    /// A per-request CEILING (probes, repo visits) refused this row before it could reach
    /// a verdict, and will refuse every row after it too. Distinct from `Skip` because the
    /// caller owes the ladder a resume position in front of this row, not just a taint:
    /// the taint alone sheds a 503 whose missing token reads as "ladder over", stranding
    /// this row and everything behind it on an inventory that never changes. The caller is
    /// the only one that can name that position, which is why this returns rather than
    /// tainting here.
    CeilingStop(&'static str),
}

/// A sealed resume position together with the candidate whose walk produced it.
///
/// The candidate rides along because one CID can map to several git oids, so a bare row
/// pair names a row without naming whose walk it belongs to. It is carried by IDENTITY
/// (the oid hex), never by position in the candidate list, which is ordered by hex and
/// mutates between rungs.
struct SealedScanPos {
    /// The keyset row pair to resume that candidate at. The empty pair is the
    /// front-of-table sentinel: resume this candidate with no cursor.
    row: (String, String),
    /// The candidate oid this position resumes.
    sha256_hex: String,
}

/// Taint the walk with a truncation reason and seal the position the caller echoes back,
/// together, at one site.
///
/// Keeping the two together is the point. Every earlier drip on this path was a CEILING
/// that tainted somewhere the mint could not see, so the shed carried no token. This is
/// not the only place the walk is tainted: the transient skips (`acquire`, `read`,
/// `budget`, the walk cap) taint directly and seal nothing, because they refuse one row
/// rather than stopping the scan, and the rows behind them are still walked. A ceiling is
/// what stops the scan, so a ceiling is what owes the caller a position.
///
/// `may_seal` is the caller's proposer verdict, and it is the whole of the multi-candidate
/// rule. Exactly one candidate per request may seal: on a resumed request the resumed
/// candidate (every other one walked only the suffix `[start_row, end)` the pager holds,
/// so its stop is not coverage of the table), and on a front-started request the first
/// candidate that has not finished (there every candidate walks from the front, so a later
/// candidate's stop IS honest coverage). A non-proposer's truncation still TAINTS, since
/// the scan really was cut short, but it contributes no position.
///
/// That scope, not an ordering comparison, is what keeps the ladder moving forward. Every
/// sealing arm breaks its row loop and only one candidate may seal, so the slot is written
/// at most once per request; the debug assertion below states that invariant where a future
/// change would trip it. The forward-only keep-the-maximum comparison this replaced was
/// the defect: a budget-starved later candidate contributing nothing could not lower a
/// maximum, so the token resumed past rows that candidate had never examined and the CID
/// became permanently unretrievable.
fn record_scan_truncation(
    walk: &mut WalkState,
    slot: &mut Option<SealedScanPos>,
    reason: &'static str,
    pos: Option<(String, String)>,
    sha256_hex: &str,
    may_seal: bool,
) {
    walk.taint(reason);
    let pos = pos.filter(|_| may_seal);
    // The one log that separates a rung from a dead end. A truncation that seals nothing
    // sheds a tokenless 503, which the client reads as "your ladder is over", so an
    // operator staring at a stranded caller needs to see WHICH ceiling stopped the scan
    // and whether it handed back a way to continue. The position itself is withheld data
    // (its `created_at` and its `id` carry a private repo's owner DID), so log only
    // whether one exists, never its value. A `true` here is the seal being RECORDED, not
    // the response carrying it: the mint site drops a seal that reached no row past the
    // request's own start, and logs its own line saying so when it does.
    tracing::debug!(
        reason,
        sealed_continuation = pos.is_some(),
        "/ipfs legacy scan truncated"
    );
    if let Some(pos) = pos {
        debug_assert!(
            slot.is_none(),
            "one candidate per request may seal, and every sealing arm breaks its row \
             loop, so the slot is written at most once"
        );
        *slot = Some(SealedScanPos {
            row: pos,
            sha256_hex: sha256_hex.to_string(),
        });
    }
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
    /// Walks spent by the PROVENANCE phase, checked against `walk_cap` on its own.
    provenance_walks: u32,
    /// Walks spent by the legacy-scan fallback, checked against the SAME `walk_cap`
    /// but from its own zero. The two phases are budgeted separately because they are
    /// not alternatives: the fallback exists precisely to reach a source the
    /// provenance set dropped, and a shared counter let the provenance phase's denials
    /// spend the budget the fallback needs to get there (#173 round 13, F3).
    scan_walks: u32,
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
            // reports an incomplete search (503), not a false 404 (#173, F2). The
            // CALLER records it, because the resume position belongs to the row this
            // refused and only the caller knows it.
            return GateOutcome::CeilingStop("probe-ceiling");
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
        return GateOutcome::CeilingStop("visit-ceiling");
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
            // must still serve). Only this block bumps a counter, so walk-free
            // candidates never consume budget.
            // Both parents bound this loop, under different knobs: #173's
            // `ipfs_max_history_walks` (an AppState field, seeded from config) and
            // #174's `GITLAWB_IPFS_MAX_REPOS_WALKED`. Honor the tighter of the two, so
            // neither knob silently stops working after the merge.
            //
            // The cap is charged PER PHASE (#173 round 13, F3): the provenance path and
            // the legacy-scan fallback each get their own `walk_cap`, so the total walk
            // work one request can buy is `2 * walk_cap` and no more. A single shared
            // counter made a public object permanently unservable: every provenance
            // source that is root-readable but path-scoped needs a walk to reach its
            // deny, so a full source set of them spends the whole ceiling, and the
            // fallback armed to find the source `record_pin_source` dropped then has
            // nothing left to walk with: it skips that source here, taints, and every
            // retry reproduces the same 503.
            //
            // Raising a single shared ceiling instead was rejected. The adversary
            // controls how many provenance slots exist (they are grindable repo ids
            // filling `pin_repo_sources`), so for any constant N a set of
            // `walk_cap + N` path-scoped denials re-creates the exhaustion. Only a
            // budget the provenance phase cannot draw from bounds the fallback's reach
            // independently of what the source set contains. The taint name stays
            // "walk-cap": to an operator the meaning is unchanged (a walk ceiling cut
            // the search), and the knobs still mean what they say, now per phase.
            //
            // `AppState::ipfs_work_budget` in `crates/gitlawb-node/src/state.rs`
            // duplicates this same `min()` as the walk term of the work-bucket floor,
            // because a floor that does not reserve what this cap can spend 429s the
            // legacy fallback short of its configured reach (#173 round 15, F2). The two
            // `min()`s must move together, so an edit starting on this side finds the
            // floor rather than only the other way round.
            let walk_cap = std::cmp::min(
                state.ipfs_max_history_walks as usize,
                state.config.ipfs_max_repos_walked,
            );
            let spent = if legacy_scan {
                walk.scan_walks
            } else {
                walk.provenance_walks
            };
            if spent as usize >= walk_cap {
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
            if legacy_scan {
                walk.scan_walks += 1;
            } else {
                walk.provenance_walks += 1;
            }

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
/// Returns all CIDs that have been pinned from git objects received via push.
/// Each entry includes the git SHA-256 hex, a CIDv1 string, and the timestamp
/// when it was pinned.  For Pinata-only rows (no local IPFS pin), the `cid`
/// field carries `pinata_cid` so CLI consumers see a usable value.
///
/// Rows with neither a local nor a Pinata CID are omitted so the response
/// only contains rows with at least one backend. Both `cid` (local IPFS) and
/// `pinata_cid` (Pinata) are nullable: a row with only `cid` set is local-only,
/// a row with only `pinata_cid` set is remote-only, and a row with both has
/// been replicated to both backends.
pub async fn list_pins(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    // Bare `?` so connection-class sqlx failures downcast to `AppError::Db` and
    // map to 503 `db_unavailable` (not 500 via `.map_err(AppError::Internal)`) (#251).
    let pins = state.db.list_pinned_cids().await?;

    let pins: Vec<serde_json::Value> = pins
        .into_iter()
        .filter(|p| p.cid.is_some() || p.pinata_cid.is_some())
        .map(|p| {
            // Backward compatibility: `cid` in the response is the local CID
            // when present, falling back to the Pinata CID for remote-only rows.
            // Clients like `gl ipfs list` read only `pin["cid"]`; a NULL here
            // would render as "?". Both provenance fields are always included so
            // consumers can distinguish local-only, remote-only, and dual rows.
            let effective_cid = p.cid.as_deref().or(p.pinata_cid.as_deref());
            serde_json::json!({
                "sha256_hex": p.sha256_hex,
                "cid": effective_cid,
                "local_cid": p.cid,
                "pinata_cid": p.pinata_cid,
                "pinned_at": p.pinned_at,
            })
        })
        .collect();

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

// Test-only counter for the LIMIT the legacy scan actually sends to SQL, summed over
// the request's fetches. The row counter above measures what came BACK, so it cannot
// tell a query that asked for the remaining budget from one that asked for a full page
// and then dropped the tail: both return the same rows. The limit is the DB-facing ask,
// which is the quantity the operator ceiling is supposed to bound.
#[cfg(test)]
thread_local! {
    static SCAN_LIMIT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_scan_limit() {
    SCAN_LIMIT.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn scan_limit() -> usize {
    SCAN_LIMIT.with(|c| c.get())
}

#[cfg(test)]
fn note_scan_limit(n: usize) {
    SCAN_LIMIT.with(|c| c.set(c.get() + n));
}

// Test-only INV-10 cost counter: how many visibility-rule ROWS the legacy scan actually
// pulled out of the database this request. The byte ceiling is the guard, but a byte
// count computed from the rows AFTER they arrive cannot tell a bounded query from an
// unbounded one -- both report the same total. Counting the rows the query returned is
// what goes red when the bound moves back out of the query and into a post-fetch sum.
#[cfg(test)]
thread_local! {
    static SCAN_RULE_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_scan_rule_rows() {
    SCAN_RULE_ROWS.with(|c| c.set(0));
}

#[cfg(test)]
pub(crate) fn scan_rule_rows() -> usize {
    SCAN_RULE_ROWS.with(|c| c.get())
}

#[cfg(test)]
fn note_scan_rule_rows(n: usize) {
    SCAN_RULE_ROWS.with(|c| c.set(c.get() + n));
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

    /// Status plus decoded JSON body, for the F2 row-ceiling tests that assert on the
    /// error code and the `continuation` field together.
    async fn status_and_body(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        let json = serde_json::from_slice(&bytes).unwrap_or_else(
            |_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }),
        );
        (status, json)
    }

    /// The `continuation` token from a `search_incomplete` body, or `None`.
    fn continuation_of(body: &serde_json::Value) -> Option<String> {
        body.get("continuation")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    /// Deterministic ascending `created_at` for the seeded-inventory fixtures. The
    /// paged scan orders on the STORED `created_at` TEXT then `id`, so whole-second
    /// stamps from one base keep text order and time order identical (a `to_rfc3339`
    /// with sub-second digits on some rows and not others would not).
    fn scan_order_stamp(i: usize) -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone;
        chrono::Utc
            .with_ymd_and_hms(2020, 1, 1, 0, 0, 0)
            .unwrap()
            .checked_add_signed(chrono::Duration::seconds(i as i64))
            .expect("in-range stamp")
    }

    /// Stamp an already-seeded repo row's `created_at` with [`scan_order_stamp`], for a
    /// fixture whose RED depends on WHICH row the scan reaches last.
    ///
    /// `upsert_mirror_repo` (under `seed_repo_with_blob`) stamps `Utc::now()`, so a
    /// mirror row's scan position is its seeding instant rendered by `to_rfc3339`, whose
    /// fractional-second field is variable-width. The scan compares the stored TEXT, so
    /// two rows seeded milliseconds apart can order by digit count rather than by time.
    /// Restamping with the whole-second values keeps text order and seed order identical.
    async fn stamp_scan_order(pool: &sqlx::PgPool, repo_id: &str, i: usize) {
        let at = scan_order_stamp(i).to_rfc3339();
        let done = sqlx::query("UPDATE repos SET created_at = $1 WHERE id = $2")
            .bind(&at)
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("restamp a seeded repo's scan position");
        assert_eq!(
            done.rows_affected(),
            1,
            "restamping {repo_id} must hit exactly the row the fixture seeded"
        );
    }

    /// Seed `n` PRIVATE repos owned by a foreign DID, in scan order, with `rules_each`
    /// path-scoped rules apiece. An anonymous caller is denied at the root gate on every
    /// one, and a root deny costs neither a probe nor a visit, which is exactly the
    /// hole the row ceiling closes. Their `disk_path`s do not exist on purpose: if a
    /// deny ever stopped short-circuiting, the missing-dir probe would taint the scan
    /// with a different source and the tests' taint assertions would catch it.
    async fn seed_root_denying_repos(
        state: &crate::state::AppState,
        prefix: &str,
        n: usize,
        rules_each: usize,
    ) {
        let owner = "did:key:z6MkF2RowCeilingOwnerAAAAAAAAAAAAAAAAAAA";
        for i in 0..n {
            let at = scan_order_stamp(i);
            let id = format!("{prefix}-{i:04}");
            state
                .db
                .create_repo(&crate::db::RepoRecord {
                    id: id.clone(),
                    name: format!("{prefix}-{i:04}"),
                    owner_did: owner.to_string(),
                    description: None,
                    is_public: false,
                    default_branch: "main".to_string(),
                    created_at: at,
                    updated_at: at,
                    disk_path: format!("/nonexistent/{prefix}-{i:04}"),
                    forked_from: None,
                    machine_id: None,
                })
                .await
                .expect("seed a root-denying repo");
            for r in 0..rules_each {
                state
                    .db
                    .set_visibility_rule(
                        &id,
                        &format!("withheld-{r}/**"),
                        crate::db::VisibilityMode::B,
                        &["did:key:z6MkU3NotTheCallerBBBBBBBBBBBBBBBBBBBBBB".to_string()],
                        owner,
                    )
                    .await
                    .expect("seed a visibility rule");
            }
        }
    }

    /// Seed `n` QUARANTINED mirror rows in scan order. Quarantine is the other denial
    /// class that returns from the gate before a probe or a visit is spent, so it drives
    /// the same unbounded pager the private-repo fixture does.
    async fn seed_quarantined_repos(state: &crate::state::AppState, prefix: &str, n: usize) {
        for i in 0..n {
            state
                .db
                .upsert_mirror_repo(
                    "z6quarantine",
                    &format!("{prefix}-{i:04}"),
                    &format!("/nonexistent/{prefix}-{i:04}"),
                    None,
                    true,
                )
                .await
                .expect("seed a quarantined mirror row");
        }
    }

    /// A GET carrying an optional `?scan=` continuation token.
    fn get_cid_scan(cid: &str, peer: Option<SocketAddr>, scan: Option<&str>) -> Request<Body> {
        let uri = match scan {
            Some(t) => format!("/ipfs/{cid}?scan={}", urlencode(t)),
            None => format!("/ipfs/{cid}"),
        };
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        if let Some(p) = peer {
            req.extensions_mut().insert(ConnectInfo(p));
        }
        req
    }

    /// Percent-encode the few characters base64url tokens cannot contain but a hostile
    /// or tampered token can. Keeps the invalid-token probes honest: a raw `+` in a
    /// query string decodes to a space, which would make a tamper test pass for the
    /// wrong reason.
    fn urlencode(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
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

    /// Walk-counting shim that runs the REAL walk (`state.git_bin`): each `rev-list`
    /// appends one line to `log`, then every invocation execs the real `git`, so the
    /// allowed-set a walk produces is the repo's genuine one.
    ///
    /// `walk_logging_fake_git` below answers every subcommand with nothing, so under it
    /// EVERY walked repo yields an empty allowed set and no repo can ever authorize. The
    /// per-phase budget tests need one candidate to deny after a real walk and a later
    /// one to allow after another, so they need the real sets and the tally both.
    #[cfg(unix)]
    fn walk_logging_real_git(dir: &std::path::Path, log: &std::path::Path) -> String {
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               rev-list) echo walk >> \"{}\" ;;\n\
             esac\n\
             exec git \"$@\"\n",
            log.display()
        );
        let git_path = dir.join("walkgit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }
        git_path.to_str().unwrap().to_string()
    }

    /// How many expensive walks the shim above has recorded so far.
    #[cfg(unix)]
    fn walks_logged(log: &std::path::Path) -> usize {
        std::fs::read_to_string(log)
            .map(|s| s.lines().count())
            .unwrap_or(0)
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

    /// A reader DID that is on no rule in these fixtures, so every path-scoped rule
    /// naming it denies the anonymous caller at the rule's path.
    #[cfg(unix)]
    const OTHER_READER: &str = "did:key:z6MkU3IpfsReaderCCCCCCCCCCCCCCCCCCCCCCCC";

    /// Seed a repo holding `content` at `/src/secret.txt` and give it a path-scoped
    /// rule over `/src/**` naming a reader that is not the caller. The repo stays
    /// readable at "/" (the rule does not match "/", so the mirror row's public flag
    /// decides), which is what makes the object cost a real allowed-set walk before it
    /// is denied: a root deny would short-circuit ahead of the walk and spend nothing.
    #[cfg(unix)]
    async fn seed_path_denying_repo(
        state: &crate::state::AppState,
        tmp: &std::path::Path,
        owner: &str,
        name: &str,
        content: &[u8],
    ) -> (String, String) {
        let (id, oid) = seed_repo_with_blob(state, tmp, owner, name, content).await;
        state
            .db
            .set_visibility_rule(
                &id,
                "/src/**",
                crate::db::VisibilityMode::B,
                &[OTHER_READER.to_string()],
                owner,
            )
            .await
            .expect("seed the path-scoped deny rule");
        (id, oid)
    }

    /// F3 per-phase walk budgets: a PUBLIC source that only the legacy-scan fallback
    /// can reach must still serve after path-scoped provenance denials spent the whole
    /// walk cap.
    ///
    /// One shared `walks` counter made that impossible. Every provenance source that is
    /// root-readable but path-scoped needs its own allowed-set walk to reach its deny,
    /// so `MAX_PIN_SOURCES + 1` such sources consume the entire cap; the fallback the
    /// at-cap/incomplete markers then arm has nothing left to spend, skips its first
    /// walk-needing candidate at `walk-cap`, and the request tails to a retryable 503
    /// that every retry reproduces. A public object, permanently unservable.
    ///
    /// The existing buried-public test cannot see this: its extra repos do not exist on
    /// disk, so they never reach the `!already` block and consume no walk. This fixture
    /// uses REAL repos with REAL denying rules, and the walk log is what proves each one
    /// genuinely spent a walk rather than being skipped for free.
    ///
    /// Both caps are set to 2, so `walk_cap` is 2 per phase. The first request runs
    /// WITHOUT the fallback armed and pins the provenance phase's own bound (exactly 2
    /// walks, never more, for a complete source set). The second arms the fallback and
    /// is the RED: pre-fix the public repo is skipped at `walk-cap` and the request 503s.
    /// The third pins that the fresh scan budget is capacity, not a gate change: an
    /// object held ONLY by a path-denying repo is still not served to the anonymous
    /// caller, with the fallback armed for it too.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_fallback_reaches_public_source_past_provenance_walk_spend(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let walk_log = tmp.path().join("walks.log");
        state.git_bin = walk_logging_real_git(tmp.path(), &walk_log);
        // `walk_cap` is the min of the two knobs, so both go to 2.
        state.ipfs_max_history_walks = 2;
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repos_walked = 2;
        state.config = Arc::new(cfg);

        // Identical content in every holder, so one CID resolves to one oid that all of
        // them carry. Iteration is `(created_at, id)` ASC, so insert order is scan order.
        let content = b"per-phase walk budget proof\n";
        let (prov_one, oid) =
            seed_path_denying_repo(&state, tmp.path(), "z6f3phase", "provdeny-one", content).await;
        let (prov_two, _) =
            seed_path_denying_repo(&state, tmp.path(), "z6f3phase", "provdeny-two", content).await;
        // The fallback's holder. Its rule IS path-scoped (so the object still costs a
        // walk) but covers a path this object is not at, so the walk's allowed-set
        // decides on the mirror row's public flag and ALLOWS. A path-scoped rule can
        // never name an anonymous reader, so this is the only shape in which a walked
        // repo authorizes anon.
        let (public_id, _) =
            seed_repo_with_blob(&state, tmp.path(), "z6f3phase", "pubreach", content).await;
        state
            .db
            .set_visibility_rule(
                &public_id,
                "/decoy/**",
                crate::db::VisibilityMode::B,
                &[OTHER_READER.to_string()],
                "z6f3phase",
            )
            .await
            .unwrap();
        // A second object held ONLY by a path-denying repo, for the denial-class check.
        let denied_content = b"held only where anon is denied\n";
        let (denied_id, denied_oid) = seed_path_denying_repo(
            &state,
            tmp.path(),
            "z6f3phase",
            "deniedsolo",
            denied_content,
        )
        .await;

        // Provenance: the two denying repos are the recorded sources of `oid`; the
        // public holder is NOT, which is exactly the dropped-source case.
        state.db.record_pin_source(&oid, &prov_one).await.unwrap();
        state.db.record_pin_source(&oid, &prov_two).await.unwrap();
        state
            .db
            .record_pin_source(&denied_oid, &denied_id)
            .await
            .unwrap();
        state
            .db
            .mark_pin_sources_incomplete(&denied_oid, "")
            .await
            .unwrap();

        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let denied_cid = seed_legacy_pin_for_oid(&state, &denied_oid).await;
        let router = ipfs_router(state.clone());

        // 1. Provenance only: the source set carries no incompleteness signal, so no
        //    fallback runs. Both sources walk and deny, and the phase spends its cap
        //    exactly, never more, whatever the fallback later gets.
        let (status, body) =
            status_and_body(router.clone().oneshot(get_cid(&cid, None)).await.unwrap()).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a complete source set that denies everywhere is a definitive miss: {body}"
        );
        assert_eq!(
            walks_logged(&walk_log),
            2,
            "the provenance phase must spend exactly its own walk_cap of 2: two REAL \
             path-denying sources, each walked to reach its deny"
        );

        // 2. Arm the fallback (the node's own record that a source is missing) and the
        //    buried public holder must serve, on the scan phase's own budget.
        state
            .db
            .mark_pin_sources_incomplete(&oid, "")
            .await
            .unwrap();
        std::fs::remove_file(&walk_log).unwrap();
        let resp = router.clone().oneshot(get_cid(&cid, None)).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "a public source reachable only through the fallback must serve even after \
             path-scoped provenance denials spent the whole walk cap: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            &body[..],
            content.as_slice(),
            "the served bytes must be the public holder's object"
        );
        assert_eq!(
            walks_logged(&walk_log),
            3,
            "two provenance-phase walks plus ONE scan-phase walk: the phases hold \
             separate budgets and neither exceeds the cap of 2"
        );

        // 3. The fresh scan budget is capacity, not a gate change: an object held only
        //    where anon is denied stays denied, fallback armed and all.
        std::fs::remove_file(&walk_log).unwrap();
        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid(&denied_cid, None))
                .await
                .unwrap(),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "a path-scoped deny must still deny under the per-phase budgets: {body}"
        );
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "every holder of that object reached a real deny verdict, so the miss is \
             definitive rather than truncated: {body}"
        );
    }

    /// F3 must-not: the per-phase split raises the total walk work to `2 * walk_cap`
    /// and no further. Two provenance sources spend the provenance budget; three more
    /// path-denying repos, none of them recorded sources, offer the fallback more
    /// walk-needing candidates than its own budget. The scan takes two and skips the
    /// rest at `walk-cap`, so the request tails to the tainted 503 rather than walking
    /// on.
    ///
    /// The walk count is asserted BEFORE the status so an unbounded scan fails HERE,
    /// on the bound, and not on some downstream difference.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_per_phase_walk_budgets_stay_bounded_at_twice_the_cap(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        let walk_log = tmp.path().join("walks.log");
        state.git_bin = walk_logging_real_git(tmp.path(), &walk_log);
        state.ipfs_max_history_walks = 2;
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repos_walked = 2;
        state.config = Arc::new(cfg);

        let content = b"bounded total walk work\n";
        let (prov_one, oid) =
            seed_path_denying_repo(&state, tmp.path(), "z6f3total", "provdeny-one", content).await;
        let (prov_two, _) =
            seed_path_denying_repo(&state, tmp.path(), "z6f3total", "provdeny-two", content).await;
        for name in ["fallback-one", "fallback-two", "fallback-three"] {
            seed_path_denying_repo(&state, tmp.path(), "z6f3total", name, content).await;
        }
        state.db.record_pin_source(&oid, &prov_one).await.unwrap();
        state.db.record_pin_source(&oid, &prov_two).await.unwrap();
        state
            .db
            .mark_pin_sources_incomplete(&oid, "")
            .await
            .unwrap();

        let cid = seed_legacy_pin_for_oid(&state, &oid).await;
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid(&cid, None))
                .await
                .unwrap(),
        )
        .await;
        let walks = walks_logged(&walk_log);
        assert!(
            walks <= 4,
            "total walk work must stay within 2 * walk_cap = 4 however many walk-needing \
             candidates the fallback is offered, got {walks}"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the fallback's own budget runs out on the surplus candidates, so the tail \
             is the truncated-search 503: {body}"
        );
        assert_eq!(body["error"], "search_incomplete", "{body}");
    }

    /// F2 (#173 round 15): the derived work floor must fit ONE COMPLETE COMBINED
    /// resolution, provenance walks included, not just the legacy search.
    ///
    /// `AppState::ipfs_work_budget` floors the per-IP work bucket at
    /// `ipfs_max_legacy_probes + pages`, but the SAME bucket is debited once per
    /// provenance visibility walk, before the fallback the markers arm has run at all.
    /// So with `GITLAWB_IPFS_RATE_LIMIT` below the floor (the only configuration where
    /// the floor is what sizes the bucket), the provenance phase eats into the budget
    /// the floor exists to reserve for the search, and the "one complete legacy search
    /// per window" guarantee stops holding: the search 429s short of its configured
    /// reach, and the retry re-pays the same provenance charges.
    ///
    /// The seams, stated the way the sibling fixtures do, and the ledger they produce:
    ///
    ///   * `ipfs_rate_limit = 1`, below the floor, so the floor is what binds.
    ///   * `ipfs_max_legacy_probes = 4`, above the three probes the scan spends, so the
    ///     probe ceiling is NOT what stops the holder (it is a second brake that can
    ///     strand it independently of the work bucket, which is why the GREEN is
    ///     asserted as a SERVED 200 rather than as merely not-429).
    ///   * `ipfs_max_legacy_scan_rows = 128`, one page at the production page size, so
    ///     the scan buys exactly one page toll.
    ///   * `ipfs_max_repos_walked = 2`, so `walk_cap` is `min(17, 2) = 2` and exactly
    ///     fits the two path-scoped provenance deniers per phase.
    ///   * `ipfs_max_repo_visits` stays at its 1024 default against the 5 visits here,
    ///     so no other ceiling binds.
    ///
    /// Debits, in order: 2 provenance walks (the `!legacy_scan` charge, one per denier,
    /// with no probe toll on that phase), 1 page toll, then one probe per legacy
    /// candidate. The two deniers are re-visited by the scan for free as far as WALKS
    /// go (the allowed-set memo persists across phases) but each still pays its probe,
    /// so the holder's own probe is the SIXTH debit.
    ///
    /// Old floor `4 + 1 = 5`: that sixth debit finds the bucket empty,
    /// `gate_and_serve` returns `Throttled` WITHOUT tainting, and the tail renders the
    /// work-path 429. New floor `4 + 1 + min(17, 2) = 7`: the holder is reached,
    /// walked on the scan phase's own budget, and served, with one token to spare.
    ///
    /// The route limiter is deliberately left at `test_support`'s default rather than
    /// sized from this cfg. `ipfs_router` layers no `rate_limit_by_ip` at all, so that
    /// saves nothing today, but a route bucket sized from `ipfs_rate_limit = 1` would
    /// shed the request at the door and the RED would be a 429-vs-429 collision with no
    /// discriminant. For the same reason the RED assertion pins the "ipfs retrieval"
    /// prefix: the route brake's body is "rate limit exceeded", a substring of the
    /// work path's "ipfs retrieval rate limit exceeded", so a bare status check or the
    /// shorter string cannot tell the two brakes apart.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_work_floor_fits_provenance_walks_plus_one_full_legacy_search(
        pool: sqlx::PgPool,
    ) {
        use crate::state::AppState;
        use clap::Parser;
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        let cfg = crate::config::Config::parse_from([
            "gitlawb-node",
            "--ipfs-rate-limit",
            "1",
            "--ipfs-max-legacy-probes",
            "4",
            "--ipfs-max-legacy-scan-rows",
            "128",
            "--ipfs-max-repos-walked",
            "2",
        ]);
        // The knobs live in TWO places: `build_state` seeds the probe and scan-row
        // ceilings the resolver enforces as AppState fields from constants, independent
        // of Config, while `walk_cap` reads `state.config.ipfs_max_repos_walked`. A cfg
        // installed without the seams would size the bucket from one set of values and
        // run the scan under another.
        state.ipfs_max_legacy_probes = AppState::ipfs_legacy_probe_budget(&cfg);
        state.ipfs_max_legacy_scan_rows = AppState::ipfs_legacy_scan_row_budget(&cfg);
        assert_eq!(
            state.ipfs_legacy_scan_page_rows,
            crate::api::ipfs::LEGACY_SCAN_PAGE_ROWS,
            "fixture precondition: the page seam stays at the production page size, so \
             the row ceiling above is exactly one page and the scan buys one page toll"
        );
        assert_eq!(
            state.ipfs_max_history_walks,
            crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST,
            "fixture precondition: the history-walk seam stays at the constant, so \
             walk_cap is min(17, 2) = 2 and the repos-walked knob is what binds"
        );
        state.config = Arc::new(cfg.clone());
        // The bucket is sized from the seam under test, never by hand: that is what
        // makes the floor change, and nothing else, the difference between RED and GREEN.
        let floor = AppState::ipfs_work_budget(&cfg);
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(floor, std::time::Duration::from_secs(3600));

        // Identical content everywhere, so one CID resolves to one oid all three repos
        // carry. Scan order is `(created_at, id)` ASC and the holder must be paged AFTER
        // both deniers, or its probe is not the debit that finds the bucket empty.
        let content = b"one complete combined resolution\n";
        let (prov_one, oid) =
            seed_path_denying_repo(&state, tmp.path(), "z6f2floor", "provdeny-one", content).await;
        let (prov_two, _) =
            seed_path_denying_repo(&state, tmp.path(), "z6f2floor", "provdeny-two", content).await;
        // The holder's rule IS path-scoped, so reaching its verdict still costs a walk,
        // but it covers a path this object is not at, so the walk's allowed set decides
        // on the mirror row's public flag and ALLOWS an anonymous reader.
        let (holder_id, _) =
            seed_repo_with_blob(&state, tmp.path(), "z6f2floor", "holder", content).await;
        state
            .db
            .set_visibility_rule(
                &holder_id,
                "/decoy/**",
                crate::db::VisibilityMode::B,
                &[OTHER_READER.to_string()],
                "z6f2floor",
            )
            .await
            .unwrap();
        stamp_scan_order(&pool, &prov_one, 0).await;
        stamp_scan_order(&pool, &prov_two, 1).await;
        stamp_scan_order(&pool, &holder_id, 2).await;

        // The two deniers are the recorded sources; the holder is not, which is the
        // dropped-source case. Two sources sits well under MAX_PIN_SOURCES (16), so
        // `pin_sources_at_cap` cannot arm the fallback: the durable incomplete marker is
        // what arms it.
        state.db.record_pin_source(&oid, &prov_one).await.unwrap();
        state.db.record_pin_source(&oid, &prov_two).await.unwrap();
        state
            .db
            .mark_pin_sources_incomplete(&oid, "")
            .await
            .unwrap();
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let work_bucket = state.ipfs_work_rate_limiter.clone();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.173:5000".parse().unwrap();
        let resp = router.oneshot(get_cid(&cid, Some(peer))).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let rendered = String::from_utf8_lossy(&body).to_string();
        // Drain what the request left, so the failure messages carry the measured
        // ledger rather than only its consequence.
        let mut spare = 0usize;
        while work_bucket.check("203.0.113.173").await {
            spare += 1;
        }

        assert!(
            !rendered.contains("ipfs retrieval"),
            "the work floor must reserve a full legacy search AFTER the provenance \
             phase has taken its walks off the same bucket. The holder's own probe \
             found the bucket empty and the tail rendered the work-path 429 (floor \
             {floor}, {spare} of it unspent): {rendered}"
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "the buried public holder must be SERVED within one window, not merely \
             spared the 429: the probe ceiling is a second brake that can strand it on \
             its own (floor {floor}, {spare} unspent): {rendered}"
        );
        assert_eq!(
            &body[..],
            content.as_slice(),
            "the served bytes must be the holder's object"
        );
        assert_eq!(
            spare, 1,
            "the measured ledger is 2 provenance walks + 1 page toll + 3 legacy probes \
             = 6 debits against a floor of {floor}, so exactly one token is left. A \
             different remainder means the debit order moved and the RED above is no \
             longer pinned on the holder's probe"
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

    // ----------------------------------------------------------------------------
    // #173 round 13, F2: the legacy scan's ROW ceiling, its caller-carried
    // continuation token, and the per-page toll.
    //
    // The hole: the pager bought another page unless `walk.probes` or `walk.visits`
    // was exhausted, but the gate returns Skip on quarantine and on a root-scope
    // visibility deny BEFORE either counter increments. An all-quarantined or
    // all-root-denying inventory therefore paged the node's entire repo table at zero
    // probes, anonymously, retaining every row and rule set, while holding one of the
    // scarce global walk permits for up to the whole request budget.
    // ----------------------------------------------------------------------------

    /// Scenario 0, the case every other scan test skips: a ceiling that EXCEEDS the
    /// table, on a scan that was never resumed. This is the one path that still owes
    /// the caller a definitive 404.
    ///
    /// The three fixtures above and beside it all park the holder PAST a ceiling, so
    /// each one proves the truncating half: nothing unproven may answer 404. Nobody
    /// was covering the converse, and it is the more dangerous direction to lose,
    /// because a scan that quietly stops short and STILL answers 404 reports existing
    /// content as absent. Here five rows sit under a ceiling of 64, the requested CID
    /// genuinely resolves to nothing, and the scan runs off the end of the table with
    /// its ceilings untouched.
    ///
    /// The counters are what make "ran to exhaustion" an observation rather than an
    /// inference. `scan_rows` reaching all five says the walk covered the table, and
    /// `scan_limit` at 8 says both asks went out at the full page size, so no budget
    /// ever shortened one. A 404 with either counter short would be the false-absent
    /// answer wearing the right status.
    ///
    /// MUTATION (RED): drop the `pager.resumed &&` guard on the wrapped-scan taint and
    /// this exhausted scan taints as `scan-wrapped`, so the tail becomes a 503 and the
    /// definitive answer is never reached.
    #[sqlx::test]
    async fn get_by_cid_unresumed_scan_under_the_ceiling_is_a_definitive_404(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 4;
        // Well clear of the five rows below: the point is a ceiling that never binds.
        state.ipfs_max_legacy_scan_rows = 64;
        seed_root_denying_repos(&state, "underceiling", 5, 0).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let peer: SocketAddr = "203.0.113.160:5000".parse().unwrap();
        crate::api::ipfs::reset_scan_rows();
        crate::api::ipfs::reset_scan_limit();
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;

        let rows = crate::api::ipfs::scan_rows();
        let limit = crate::api::ipfs::scan_limit();
        assert_eq!(
            rows, 5,
            "the scan must reach every seeded row before it may call the object absent. \
             Read {rows} of 5"
        );
        assert_eq!(
            limit, 8,
            "two asks at the full page size (4 + 4): with the ceiling far above the \
             table, nothing may shorten the query, and a shortened one would mean the \
             404 below rested on a bounded walk. Asked for {limit}"
        );
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a scan that ran off the end of the table with no ceiling touched and no \
             resume token has proven absence over the whole inventory, so the answer is \
             the definitive 404, not a truncation 503: {body}"
        );
        assert!(
            continuation_of(&body).is_none(),
            "there is nothing left to resume, so a definitive 404 must carry no \
             continuation: {body}"
        );
        assert_ne!(
            body["error"], "search_incomplete",
            "the answer is an absence, not a truncation: {body}"
        );
    }

    /// Scenario 1: an all-root-denied inventory stops at the row ceiling.
    ///
    /// Every seeded repo is private and the caller is anonymous, so each row is a root
    /// deny: no probe, no visit, and pre-fix nothing that could stop the pager. The
    /// scan must stop at the ceiling, taint (so the tail is the retryable 503, never a
    /// false 404), free the walk permit, and hand back a continuation token.
    ///
    /// MUTATION A (RED): delete the row-ceiling check and `scan_rows()` reads the whole
    /// seeded inventory instead of one ceiling's worth.
    #[sqlx::test]
    async fn get_by_cid_denial_only_scan_stops_at_row_ceiling(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 4;
        seed_root_denying_repos(&state, "deny", 12, 0).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let walk_pool = state.git_ipfs_walk_semaphore.clone();
        let free_before = walk_pool.available_permits();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.140:5000".parse().unwrap();

        crate::api::ipfs::reset_scan_rows();
        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;

        // The row COUNT first: it is the cost this ceiling exists to bound, and a
        // status-first ordering would attribute a missing ceiling to the tail instead.
        let rows = crate::api::ipfs::scan_rows();
        assert_eq!(
            rows, 4,
            "the ceiling (4) bounds the DB-facing selection exactly; a denial-only \
             inventory must not page the whole table. Read {rows} of 12 seeded rows"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a scan cut short at the row ceiling left rows unproven, so the honest tail \
             is the retryable 503, never a definitive 404; got body {body}"
        );
        assert_eq!(
            body["error"], "search_incomplete",
            "the shed must name the incomplete search: {body}"
        );
        assert!(
            continuation_of(&body).is_some(),
            "a ceiling truncation must hand back a continuation so a holder past the \
             ceiling is still reachable: {body}"
        );
        assert_eq!(
            walk_pool.available_permits(),
            free_before,
            "the shed must free the scarce walk admission, not hold it for the request budget"
        );

        // The follow-up is ADMITTED: the shed released the walk permit rather than
        // parking it, so the next caller is not capacity-503'd behind it.
        let (status, _) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the follow-up must be admitted and reach the same truncation verdict, not \
             shed at capacity behind a held permit"
        );
    }

    /// Scenario 2: an all-QUARANTINED inventory, same contract. Quarantine is the other
    /// denial class that returns from the gate before a probe or a visit is spent, so a
    /// ceiling keyed on either counter would miss it entirely.
    ///
    /// MUTATION A (RED): as scenario 1.
    #[sqlx::test]
    async fn get_by_cid_quarantined_only_scan_stops_at_row_ceiling(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 4;
        seed_quarantined_repos(&state, "quar", 12).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let peer: SocketAddr = "203.0.113.141:5000".parse().unwrap();
        crate::api::ipfs::reset_scan_rows();
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a quarantined-only inventory truncates at the ceiling like a denied one: {body}"
        );
        assert_eq!(body["error"], "search_incomplete", "{body}");
        let rows = crate::api::ipfs::scan_rows();
        assert_eq!(
            rows, 4,
            "quarantine costs neither a probe nor a visit, so only the ROW ceiling can \
             stop this pager, and it stops it exactly. Read {rows} of 12 seeded rows"
        );
        assert!(
            continuation_of(&body).is_some(),
            "the quarantined-inventory truncation carries a continuation too: {body}"
        );
    }

    /// Scenario 3 (must-not): a buried PUBLIC row inside the ceiling still serves. The
    /// ceiling bounds the search; it must never convert reachable content into a shed.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_public_row_inside_row_ceiling_still_serves(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        // Ceiling comfortably ABOVE the inventory: nothing may truncate here.
        state.ipfs_max_legacy_scan_rows = 64;

        seed_root_denying_repos(&state, "buried", 5, 0).await;
        // Seeded last, and `upsert_mirror_repo` stamps `now`, so this row sorts after
        // every 2020-stamped denial row and is genuinely reached last.
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6inside",
            "holder",
            b"inside ceiling\n",
        )
        .await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let peer: SocketAddr = "203.0.113.142:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid_scan(&cid, Some(peer), None))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a public holder inside the ceiling must serve; a ceiling that sheds \
             reachable content is worse than the unbounded scan it replaced"
        );
    }

    /// Scenario 4 (must-not): no ceiling ever produces a 404.
    ///
    /// Three legs against one genuinely-absent object over 5 denial rows at ceiling 2:
    ///   * a front-started truncated scan is 503 `search_incomplete` WITH a token;
    ///   * a token-resumed scan that reaches the table end taints `scan-wrapped` and
    ///     emits NO token (absence was proven only over `[start, end)`);
    ///   * only a front-started scan that exhausts under every ceiling reaches the 404.
    ///
    /// MUTATION B (RED): replace taint-and-break with a bare `break` and the first leg
    /// becomes the 404 tail.
    #[sqlx::test]
    async fn get_by_cid_row_ceiling_never_returns_404(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 2;
        seed_root_denying_repos(&state, "no404", 5, 0).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let router = ipfs_router(state.clone());
        let peer: SocketAddr = "203.0.113.143:5000".parse().unwrap();

        // Leg 1: front-started truncation.
        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a truncated scan is never a 404: {body}"
        );
        assert_eq!(body["error"], "search_incomplete", "{body}");
        let mut token = continuation_of(&body).expect("leg 1 must emit a continuation");

        // Leg 2: ladder to the end. 5 rows at ceiling 2 truncates twice, then the third
        // resume reads the short final page and WRAPS.
        let mut wrapped = None;
        for step in 0..6 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "every rung of the ladder over an absent object is a retryable 503, \
                 never a 404 (step {step}): {body}"
            );
            match continuation_of(&body) {
                Some(next) => token = next,
                None => {
                    wrapped = Some(body);
                    break;
                }
            }
        }
        let wrapped = wrapped.expect("the ladder must reach the table end within its bound");
        assert!(
            wrapped["message"]
                .as_str()
                .unwrap_or_default()
                .contains("scan-wrapped"),
            "a resumed scan that reaches the end must taint scan-wrapped, so absence \
             proven only over [start, end) is never reported as a definitive 404: {wrapped}"
        );
        assert!(
            continuation_of(&wrapped).is_none(),
            "a wrapped scan emits NO token, since there is nothing left to resume: {wrapped}"
        );

        // Leg 3: the 404 tail stays reachable for a front-started scan that exhausts
        // under every ceiling.
        let mut wide = state.clone();
        wide.ipfs_max_legacy_scan_rows = 1000;
        let (status, body) = status_and_body(
            ipfs_router(wide)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a front-started scan that exhausts under every ceiling still gets the \
             definitive 404; a ceiling that swallowed it would make every miss retryable \
             forever: {body}"
        );
    }

    /// Scenario 5: a holder buried PAST the ceiling becomes servable within the stated
    /// bound by echoing tokens, under the PRODUCTION toll at its raised derived floor.
    ///
    /// Ceiling 4 over 10 denial rows with the public holder behind them: the bound is
    /// `ceil(10 / 4) + 1 = 4` requests. Every intermediate response is the retryable
    /// 503 with a token, and no 429 interrupts the ladder, which is what the floor fix
    /// pins. The work bucket is sized to the DERIVED floor of a config whose page term
    /// dominates (probe knob 1, row knob 896 = 7 pages, walk knob 1, so floor = 9);
    /// under the old floor (`max(route, probes)` = 1) the very first page would 429.
    ///
    /// The walk knob is pinned at 1 rather than left at its default of 64. This ladder
    /// is a pure legacy scan with no provenance phase, so the floor's walk term
    /// (`min(17, ipfs_max_repos_walked)`, #173 round 15) buys nothing the fixture
    /// spends; at the default it would hand the bucket 17 tokens of slack and the page
    /// toll, which is the thing this test exists to hold the floor against, would stop
    /// being what binds.
    ///
    /// The floor is 9 rather than the honest ladder's exact cost (6 pages + 1 probe = 7)
    /// on purpose. A ladder that never resumes re-pages from the front every request and
    /// costs 8, so at a bucket of 7 mutation C would trip the 429 guard one step before
    /// the reach guard and its RED would be attributed to the toll rather than to the
    /// missing continuation. A token of headroom keeps each guard reporting its own
    /// property.
    ///
    /// MUTATION C (RED): emit the token but never open it on the way in, and the ladder
    /// restarts at the front every time so the 200 never arrives.
    ///
    /// This test has NO pre-fix RED, and that is by design rather than an omission.
    /// Mutation A (delete the row ceiling) must leave it GREEN, which means its
    /// assertions have to tolerate the holder being served on the very first request,
    /// exactly what an unbounded scan does. So the pre-fix head passes it. Its
    /// load-bearing proof is mutation C, its designated mutant: C keeps the ceiling and
    /// keeps minting tokens but never honours one, which is the only shape that makes
    /// the holder permanently unservable.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_holder_past_scan_ceiling_serves_via_token_ladder(pool: sqlx::PgPool) {
        use crate::state::AppState;
        use clap::Parser;
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 4;

        // The production toll, sized exactly at its derived floor. The row knob here
        // sizes the FLOOR (it reads the production 128-row page size); the ceiling the
        // scan actually enforces is the AppState seam above, as with page rows.
        let cfg = crate::config::Config::parse_from([
            "gitlawb-node",
            "--ipfs-rate-limit",
            "1",
            "--ipfs-max-legacy-probes",
            "1",
            "--ipfs-max-legacy-scan-rows",
            "896",
            "--ipfs-max-repos-walked",
            "1",
        ]);
        let floor = AppState::ipfs_work_budget(&cfg);
        assert_eq!(
            floor, 9,
            "fixture precondition: 1 probe + 896/128 = 7 pages + min(17, 1) = 1 walk"
        );
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(floor, std::time::Duration::from_secs(3600));

        seed_root_denying_repos(&state, "ladder", 10, 0).await;
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6ladder",
            "holder",
            b"past the ceiling\n",
        )
        .await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.144:5000".parse().unwrap();
        let bound = 10usize.div_ceil(4) + 1;

        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=bound {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            assert_ne!(
                status,
                StatusCode::TOO_MANY_REQUESTS,
                "no 429 may interrupt an honest caller's ladder at step {step}: the work \
                 floor must fit a full deep scan's page toll, or the reach bound is a \
                 promise the toll breaks: {body}"
            );
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            assert_eq!(body["error"], "search_incomplete", "{body}");
            token = Some(
                continuation_of(&body)
                    .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}")),
            );
        }
        assert!(
            served_at.is_some(),
            "a holder past the ceiling must be served within ceil(10/4)+1 = {bound} \
             token-echoing requests, or the ceiling has made it permanently unservable"
        );
    }

    /// Scenario 7 (#173 round 14, F4): an operator ceiling BELOW the page size must
    /// bound the QUERY, not just the loop that reads its result.
    ///
    /// Page size 4, ceiling 2. The scan may prove two rows, so two rows is what it may
    /// select and rule-load inside the admission-held, budget-clamped region. A fetch
    /// that always asks for a full page buys twice the ceiling and the row arm only
    /// notices afterwards, which makes the page size an implicit floor under the knob.
    /// `scan_limit()` is what separates the fix from a post-fetch trim: it records the
    /// DB-facing ask, so a trim that hands back the same two rows still reads 4 here.
    ///
    /// The fixture also carries the fail-open boundary case. The LAST row is a real bare
    /// repo, public at "/", holding a real blob at /src/secret.txt behind a path-scoped
    /// rule naming a reader the anonymous caller is not, and its pin is LEGACY (NULL
    /// provenance) so the gate reads the page's own `pager.rules` rather than re-querying
    /// per repo. Every fetch here is budget-shortened, so that repo arrives as the last
    /// row of a shortened page: the boundary where a page carrying a rule set loaded for
    /// a different row set would fail OPEN and serve a withheld object.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_scan_ceiling_below_page_size_bounds_the_query(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 4;
        state.ipfs_max_legacy_scan_rows = 2;
        // The probe, visit, and walk budgets stay at their defaults on purpose: the
        // boundary repo below spends a probe, a visit, and a history walk that the
        // denial-only rows do not, and a fixture that starved them would withhold it for
        // a reason that has nothing to do with its rules.

        seed_root_denying_repos(&state, "capbelow", 6, 0).await;
        // Both repos below are mirror rows, so `upsert_mirror_repo` stamps `now` and they
        // sort after every 2020-stamped denial row. The boundary repo is seeded second,
        // so `(created_at, id)` puts it eighth and last.
        let (_, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6capbelow",
            "holder",
            b"past a ceiling below the page size\n",
        )
        .await;
        let holder_cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;
        let (_, withheld_oid) = seed_path_denying_repo(
            &state,
            tmp.path(),
            "z6capbelow",
            "boundary",
            b"withheld at the boundary row\n",
        )
        .await;
        let withheld_cid = seed_legacy_pin_for_oid(&state, &withheld_oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.150:5000".parse().unwrap();

        crate::api::ipfs::reset_scan_rows();
        crate::api::ipfs::reset_scan_limit();
        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&holder_cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        // Both counters sum over the whole request and are cleared only by their resets,
        // so they are captured HERE, before the ladder below adds its own fetches.
        let rows = crate::api::ipfs::scan_rows();
        let limit = crate::api::ipfs::scan_limit();
        assert_eq!(
            limit, 2,
            "one fetch, and it must ask the database for the ceiling (2), not the page \
             size (4). Asked for {limit}"
        );
        assert_eq!(
            rows, 2,
            "a ceiling below the page size still bounds the selection exactly. Read \
             {rows} of 8 seeded rows"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the holder is row 7, past the ceiling, so this request must not serve it \
             and must tail to the retryable 503: {body}"
        );
        assert_eq!(
            body["error"], "search_incomplete",
            "the shed must name the incomplete search: {body}"
        );

        // The ladder still reaches the holder: rungs covering rows 3-4, 5-6, then 7-8.
        let bound = 8usize.div_ceil(2) + 1;
        let mut token = Some(
            continuation_of(&body)
                .unwrap_or_else(|| panic!("rung 1 must carry a continuation: {body}")),
        );
        let mut served_at = None;
        for step in 2..=bound {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&holder_cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            token = Some(
                continuation_of(&body)
                    .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}")),
            );
        }
        assert!(
            served_at.is_some(),
            "a holder past the ceiling must still be served within ceil(8/2)+1 = {bound} \
             token-echoing requests; a ceiling that shortens the query must not shorten \
             the reach"
        );

        // The withheld blob gets its OWN full ladder, and is denied on every rung.
        //
        // A not-served assertion alone is satisfied by a ladder that never reached the
        // boundary row: the per-IP work limiter ends one with a shed that carries no
        // continuation, and so does an early taint, and a bare `None => break` cannot
        // tell either from an honest exhaustion. So this half also witnesses HOW the
        // ladder ended: every intermediate rung is specifically the retryable 503, and
        // the last one is the `scan-wrapped` taint, which only a resumed scan that
        // reached the END of the table emits. That is what makes "the rules withheld
        // it" the reading. (Not a 404: a resumed scan has proven absence only over
        // `[token, end)`, so the node deliberately withholds the definitive 404 and
        // answers 503 with no continuation instead.)
        let mut token: Option<String> = None;
        let mut exhausted_at = None;
        for step in 1..=bound {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&withheld_cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            assert_ne!(
                status,
                StatusCode::OK,
                "the /src/** rule names a reader the anonymous caller is not, so the \
                 boundary repo's blob must never be served, including on the rung that \
                 reaches it as the last row of a shortened page (step {step}): {body}"
            );
            match continuation_of(&body) {
                Some(t) => {
                    assert_eq!(
                        status,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "an intermediate rung of the withheld ladder is the retryable \
                         503 (step {step}): {body}"
                    );
                    token = Some(t);
                }
                None => {
                    assert_eq!(
                        status,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "the withheld ladder's last rung is the retryable 503 (step \
                         {step}): {body}"
                    );
                    assert!(
                        body["message"]
                            .as_str()
                            .unwrap_or_default()
                            .contains("scan-wrapped"),
                        "the withheld ladder must end by EXHAUSTING the inventory, which \
                         only the scan-wrapped taint witnesses, not by a per-IP brake \
                         that stopped it short of the boundary row (step {step}): {body}"
                    );
                    exhausted_at = Some(step);
                    break;
                }
            }
        }
        assert!(
            exhausted_at.is_some(),
            "the withheld ladder must reach the end of the inventory within {bound} \
             rungs, otherwise no rung ever evaluated the rule that withholds the blob"
        );
    }

    /// The positive control for the fixture above: the identical inventory with the
    /// `/src/**` rule ABSENT serves the same blob through the same ladder.
    ///
    /// Its job is attribution. Without it, a not-served assertion is satisfied by any
    /// fixture that never reaches the repo at all (a spent probe, a skipped walk, a
    /// budget cut), so a RED there could not be read as "the rules decided". This test
    /// is GREEN before and after the ceiling fix; only the pairing carries meaning.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_boundary_repo_serves_the_same_blob_without_the_path_rule(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 4;
        state.ipfs_max_legacy_scan_rows = 2;

        seed_root_denying_repos(&state, "capbelowctl", 6, 0).await;
        let (_, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6capbelowctl",
            "holder",
            b"past a ceiling below the page size\n",
        )
        .await;
        let _ = seed_legacy_pin_for_oid(&state, &holder_oid).await;
        // Same recipe as the fixture above, minus the path-scoped rule.
        let (_, allowed_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6capbelowctl",
            "boundary",
            b"withheld at the boundary row\n",
        )
        .await;
        let allowed_cid = seed_legacy_pin_for_oid(&state, &allowed_oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.151:5000".parse().unwrap();
        let bound = 8usize.div_ceil(2) + 1;

        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=bound {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&allowed_cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            token = Some(
                continuation_of(&body)
                    .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}")),
            );
        }
        assert!(
            served_at.is_some(),
            "the boundary repo is public at \"/\" and the rule is what withholds its \
             blob, so with the rule absent the same blob must be served within {bound} \
             rungs"
        );
    }

    /// Scenario 8 (#173 round 14, F4): a ceiling that is not a multiple of the page size
    /// must shorten the LAST fetch to what is left of the budget.
    ///
    /// Page size 2, ceiling 3. The first fetch may ask for a full page; the second may
    /// ask for one row only. A pager that asks for a page either way overshoots the
    /// operator's ceiling by a page on every scan whose ceiling is not an exact multiple,
    /// which is the general case. `scan_limit()` reads 2 + 1 = 3 for the fix and 2 + 2 =
    /// 4 for a pager that trims after the query.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_scan_ceiling_not_a_page_multiple_shortens_the_last_fetch(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 3;

        seed_root_denying_repos(&state, "capodd", 6, 0).await;
        // Seventh and last: `upsert_mirror_repo` stamps `now`, past every 2020 stamp.
        let (_, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6capodd",
            "holder",
            b"past a ceiling that is not a page multiple\n",
        )
        .await;
        let holder_cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.152:5000".parse().unwrap();

        crate::api::ipfs::reset_scan_rows();
        crate::api::ipfs::reset_scan_limit();
        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&holder_cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        // Captured before the ladder: both counters sum across the whole request.
        let rows = crate::api::ipfs::scan_rows();
        let limit = crate::api::ipfs::scan_limit();
        assert_eq!(
            limit, 3,
            "two fetches, of 2 then 1: the second may ask only for the remaining budget. \
             Asked for {limit} rows in total"
        );
        assert_eq!(
            rows, 3,
            "the ceiling (3) bounds the selection exactly, page size (2) or not. Read \
             {rows} of 7 seeded rows"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the holder is row 7, past the ceiling, so this request must not serve it \
             and must tail to the retryable 503: {body}"
        );
        assert_eq!(
            body["error"], "search_incomplete",
            "the shed must name the incomplete search: {body}"
        );

        let bound = 7usize.div_ceil(3) + 1;
        let mut token = Some(
            continuation_of(&body)
                .unwrap_or_else(|| panic!("rung 1 must carry a continuation: {body}")),
        );
        let mut served_at = None;
        for step in 2..=bound {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&holder_cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            token = Some(
                continuation_of(&body)
                    .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}")),
            );
        }
        assert!(
            served_at.is_some(),
            "a holder past the ceiling must still be served within ceil(7/3)+1 = {bound} \
             token-echoing requests"
        );
    }

    /// Seed `n` PUBLIC (root-READABLE) mirror rows in scan order, with disk paths that
    /// do not exist.
    ///
    /// The distinction from `seed_root_denying_repos` is the whole point: a private row
    /// is denied at the root gate before `walk.probes` moves, so a denial-only fixture
    /// can never reach the probe or visit ceilings. These rows pass the root gate, so
    /// each one is CHARGED a probe, which is what drives the pager to the probe ceiling.
    async fn seed_root_readable_repos(state: &crate::state::AppState, prefix: &str, n: usize) {
        for i in 0..n {
            state
                .db
                .upsert_mirror_repo(
                    &format!("z6readable{prefix}"),
                    &format!("{prefix}-{i:04}"),
                    &format!("/nonexistent/{prefix}-{i:04}"),
                    None,
                    false,
                )
                .await
                .expect("seed a root-readable mirror row");
        }
    }

    /// The continuation must survive a repo id at the WRITE PATH's maximum.
    ///
    /// `repos.id` is `{owner}/{name}`, and the node's own slug validators admit 255
    /// bytes of owner and 100 of name, so a 356-byte id is reachable and repo names are
    /// peer-controllable. When such a row lands on a truncation boundary the seal is the
    /// only thing standing between it and a tokenless 503, and a tokenless 503 is
    /// byte-identical to the wrapped-scan answer whose contract is "your ladder is
    /// over". The boundary row is deterministic for a stable inventory, so every retry
    /// reproduces it and every row past it is permanently unreachable.
    ///
    /// MUTATION (RED): narrow the token's id width back to 128 and the shed loses its
    /// continuation.
    #[sqlx::test]
    async fn get_by_cid_row_ceiling_continuation_survives_a_max_length_repo_id(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 1;
        state.ipfs_max_legacy_scan_rows = 1;

        let owner = format!("did:key:{}", "z".repeat(247));
        assert_eq!(
            owner.len(),
            255,
            "the largest owner the slug validator admits"
        );
        let name = "n".repeat(100);
        let at = scan_order_stamp(0);
        state
            .db
            .create_repo(&crate::db::RepoRecord {
                id: format!("{owner}/{name}"),
                name: name.clone(),
                owner_did: owner.clone(),
                description: None,
                is_public: false,
                default_branch: "main".to_string(),
                created_at: at,
                updated_at: at,
                disk_path: "/nonexistent/max-length-id".to_string(),
                forked_from: None,
                machine_id: None,
            })
            .await
            .expect("seed the boundary row");

        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let peer: SocketAddr = "203.0.113.150:5000".parse().unwrap();
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["error"], "search_incomplete", "{body}");
        assert!(
            continuation_of(&body).is_some(),
            "a truncation on a row whose id the write path admits must still carry a \
             continuation; without one the ladder ends here forever: {body}"
        );
    }

    /// The PROBE ceiling must advance the ladder, not end it.
    ///
    /// `ipfs_max_legacy_probes` binds first on any inventory containing root-readable
    /// repos, long before the row ceiling that does mint a token. A probe-ceiling break
    /// with no continuation makes the shed tokenless, which reads to the caller as "the
    /// ladder is over", so a holder past the probe ceiling is unreachable on every
    /// retry.
    ///
    /// The fixture seeds ROOT-READABLE rows on purpose: every other scan test in this
    /// file uses `seed_root_denying_repos`, and a root deny returns before a probe is
    /// charged, which is exactly why the shipped suite could not see this.
    ///
    /// MUTATION (RED): drop the continuation from the probe-ceiling arm and the ladder
    /// never reaches the holder.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_probe_ceiling_ladders_to_a_holder_past_it(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        // The row ceiling is deliberately far out of reach: the probe ceiling is what
        // must stop this scan, and it is what must carry the ladder forward.
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        // Generous so no 429 interrupts an honest caller's ladder; the toll is covered
        // by its own test.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_readable_repos(&state, "probe", 6).await;
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6probe",
            "holder",
            b"past the probes\n",
        )
        .await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.151:5000".parse().unwrap();
        let bound = 6usize.div_ceil(2) + 1;

        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=bound {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            assert_eq!(body["error"], "search_incomplete", "{body}");
            token = Some(continuation_of(&body).unwrap_or_else(|| {
                panic!(
                    "the probe-ceiling shed at step {step} must carry a continuation; \
                     a tokenless shed is indistinguishable from a finished ladder: {body}"
                )
            }));
        }
        assert!(
            served_at.is_some(),
            "a holder past the probe ceiling must be reached within {bound} \
             token-echoing requests, not stranded forever"
        );
    }

    /// The probe ceiling must ladder past the row it STOPPED ON, not past the page.
    ///
    /// The sibling test above sets `ipfs_legacy_scan_page_rows == ipfs_max_legacy_probes`,
    /// so the budget runs out exactly at a page boundary and the page-boundary cursor
    /// happens to be the right resume point. Misalign the two and it is not: the ceiling
    /// taints INSIDE `gate_and_serve`, the loop keeps consuming the rest of the page as
    /// `Skip`, and the mint arms at the top of the loop seal `pager.cursor`, which by
    /// then sits PAST every row the ceiling refused to probe. Those rows are skipped on
    /// the resume as well, and the inventory is stable, so every ladder step reproduces
    /// the same gap.
    ///
    /// Two rows, one probe: the filler spends the budget, the holder is the row the
    /// ceiling stops on.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_probe_ceiling_ladders_past_the_row_it_stopped_on(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        // Deliberately NOT equal to the page size: one probe, two rows per page.
        state.ipfs_max_legacy_probes = 1;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_readable_repos(&state, "midpage", 1).await;
        stamp_scan_order(&pool, "z6readablemidpage/midpage-0000", 0).await;
        let (holder_id, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6midpage",
            "holder",
            b"stopped on this row\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 1).await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.161:5000".parse().unwrap();

        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=4 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            token = Some(continuation_of(&body).unwrap_or_else(|| {
                panic!("the probe-ceiling shed at step {step} must carry a continuation: {body}")
            }));
        }
        assert!(
            served_at.is_some(),
            "the row the probe ceiling stopped on must be reachable on the ladder; \
             a cursor sealed past it strands it on every retry"
        );
    }

    /// A ceiling reached on the FINAL page must still mint a continuation.
    ///
    /// `pager.exhausted` breaks at the top of the loop AHEAD of every mint arm, so a
    /// probe or visit ceiling that taints inside `gate_and_serve` while the last page is
    /// being walked sheds `search_incomplete` with no token at all. `gl ipfs get` reads a
    /// tokenless shed as "the ladder is over" (that is the wrapped-scan contract), so a
    /// holder on that page is unreachable, permanently, on an inventory that never
    /// changes.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_probe_ceiling_on_the_final_page_still_mints_a_continuation(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // One page holds the whole inventory, so the scan is exhausted the moment it
        // starts and the break at `pager.exhausted` is the one that fires.
        state.ipfs_legacy_scan_page_rows = 8;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_readable_repos(&state, "finalpage", 1).await;
        stamp_scan_order(&pool, "z6readablefinalpage/finalpage-0000", 0).await;
        let (holder_id, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6finalpage",
            "holder",
            b"on the last page\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 1).await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.162:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a probe ceiling on the final page is an incomplete search, not a verdict: {body}"
        );
        let token = continuation_of(&body).unwrap_or_else(|| {
            panic!(
                "a ceiling reached on the final page must still carry a continuation; \
                 a tokenless shed tells the caller their ladder is over: {body}"
            )
        });
        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "echoing the final-page continuation must reach the holder: {body}"
        );
    }

    /// A ceiling on the final page of a RESUMED scan must keep its continuation.
    ///
    /// `pager.resumed && pager.exhausted` is the wrapped-scan tail: the caller has walked
    /// to the end of the table, so there is nothing left to resume and the absent token
    /// is the signal. That is only true when the walk actually reached the end. A ceiling
    /// stopping part way through the last page leaves rows unwalked in front of the
    /// cursor, and clearing the seal there strands them exactly as a tokenless shed does.
    ///
    /// Four rows, three per page, one probe: the third rung is the one that resumes into
    /// a short page and stops on the holder.
    ///
    /// MUTATION (RED): drop `scan_continuation.is_none()` from the wrap clause.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_ceiling_on_a_resumed_final_page_keeps_its_continuation(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 3;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_readable_repos(&state, "wrapguard", 3).await;
        for i in 0..3 {
            stamp_scan_order(&pool, &format!("z6readablewrapguard/wrapguard-{i:04}"), i).await;
        }
        let (holder_id, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6wrapguard",
            "holder",
            b"behind a resumed ceiling\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 3).await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.163:5000".parse().unwrap();

        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=6 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            token = Some(
                continuation_of(&body)
                    .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}")),
            );
        }
        assert!(
            served_at.is_some(),
            "a ceiling that stops part way through the last page of a resumed scan must \
             still ladder; the wrap tail is for a walk that reached the end"
        );
    }

    /// A CID with several oid candidates must ladder to a holder only a LATER candidate
    /// can serve.
    ///
    /// `pinned_cids` is unique on the oid, not the cid, so one CID resolves to several
    /// candidates and every one of them shares the request's pager, budgets, and resume
    /// slot. With a single shared slot the first candidate's truncation seals a row the
    /// SECOND candidate never examined: the next rung resumes past the holder, the scan
    /// wraps, and the tokenless shed tells the caller the ladder is over. The holder is
    /// then unreachable on every retry, because the inventory never changes.
    ///
    /// Two rows and a two-probe ceiling, with the holder on the second row. The absent
    /// candidate sorts first (`oids_for_cid` orders by hex), so it is the one that spends
    /// the budget and the holder is reachable only through candidate 2.
    ///
    /// PRE-FIX (observed RED): rung 1 sheds a token sealing row 1, rung 2 resumes past it,
    /// wraps, and sheds with NO token; the holder is never served.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_multi_oid_ladder_reaches_a_holder_only_a_later_candidate_serves(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        // Two probes: exactly the two rows, so candidate 1 spends the whole budget and
        // candidate 2 cannot probe anything this rung.
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_readable_repos(&state, "multioid", 1).await;
        stamp_scan_order(&pool, "z6readablemultioid/multioid-0000", 0).await;
        let (holder_id, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6multioid",
            "holder",
            b"only the later candidate can serve this\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 1).await;
        let cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;

        // A second, absent candidate under the SAME cid, sorting ahead of the holder's
        // oid so the ordered candidate list puts it first.
        let absent_first = "00".repeat(32);
        state
            .db
            .record_pinned_cid(&absent_first, &cid, None)
            .await
            .expect("co-locate a second source-less oid under the same cid");
        let candidates = state.db.oids_for_cid(&cid).await.unwrap();
        assert_eq!(
            candidates,
            vec![absent_first.clone(), holder_oid.clone()],
            "precondition: the holder's oid must be the SECOND candidate, or the \
             starvation this test is about never happens"
        );

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.164:5000".parse().unwrap();

        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=8 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            token = Some(continuation_of(&body).unwrap_or_else(|| {
                panic!(
                    "rung {step} shed with no continuation, which tells the caller the \
                     ladder is over while a later candidate still holds the object: {body}"
                )
            }));
        }
        assert!(
            served_at.is_some(),
            "a holder reachable only through a later oid candidate must be served by \
             driving the ladder, not stranded behind the first candidate's seal"
        );
    }

    /// Seed `n` root-readable filler rows in scan order, at ascending stamps from
    /// `first`. They pass the root gate and hold nothing, so each costs exactly one probe
    /// and reaches a clean absent verdict, which is what drives a scan to its probe
    /// ceiling on a known row.
    async fn seed_ladder_filler(
        state: &crate::state::AppState,
        pool: &sqlx::PgPool,
        prefix: &str,
        n: usize,
        first: usize,
    ) {
        seed_root_readable_repos(state, prefix, n).await;
        for i in 0..n {
            stamp_scan_order(
                pool,
                &format!("z6readable{prefix}/{prefix}-{i:04}"),
                first + i,
            )
            .await;
        }
    }

    /// Open a continuation the node just minted, under the node's own key. The ladder
    /// tests that assert WHICH candidate a rung names need the position itself; the status
    /// code alone cannot tell "advanced to the next candidate" from "sealed a row of the
    /// current one that happens to work".
    fn opened(key: &[u8; 32], cid: &str, token: &str) -> gitlawb_core::scan_token::ScanPosition {
        gitlawb_core::scan_token::open_scan_token(key, cid, token, chrono::Utc::now().timestamp())
            .expect("the node's own token must open under the node's own key")
    }

    /// Mint a continuation the handler will accept, for the fixtures that need to start
    /// mid-ladder rather than drive every rung to get there.
    fn minted(key: &[u8; 32], cid: &str, sha256_hex: &str, row: (&str, &str)) -> String {
        gitlawb_core::scan_token::seal_scan_token(
            key,
            cid,
            &gitlawb_core::scan_token::ScanPosition {
                created_at_key: row.0.to_string(),
                id: row.1.to_string(),
                sha256_hex: sha256_hex.to_string(),
            },
            chrono::Utc::now().timestamp() + 300,
        )
        .expect("seal a continuation for the fixture")
    }

    /// The multi-candidate ladder TERMINATES, and the terminating shed lands exactly on
    /// the rung in which the FINAL candidate reaches the end of the table.
    ///
    /// Every rung must make progress of one of two kinds: advance the row within the
    /// resumed candidate, or advance to the next candidate. Neither an endless ladder nor
    /// a rung that hands back a token it already issued is acceptable, and a tokenless
    /// shed before the last candidate has been walked is the starvation bug wearing the
    /// "ladder over" signal.
    ///
    /// Four rows at two per page against a two-probe ceiling, and two candidates neither
    /// of which can serve. The ladder is then fully determined: candidate A takes rungs
    /// 1 and 2 on rows (0,1) and (2,3), rung 3 walks A off the end and advances to B,
    /// rungs 4 and 5 repeat the table for B, and rung 6 walks B off the end. There are no
    /// provenance sources anywhere, so the visit budget is untouched when the scan starts
    /// and the settled-no-row shed cannot fire here; the ONLY tokenless rung is the last.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_multi_oid_ladder_ends_when_the_final_candidate_reaches_the_end(
        pool: sqlx::PgPool,
    ) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "term", 4, 0).await;
        let first = "00".repeat(32);
        let second = "11".repeat(32);
        let cid = seed_legacy_pin(&state, &first).await;
        state
            .db
            .record_pinned_cid(&second, &cid, None)
            .await
            .expect("co-locate a second source-less oid under the same cid");
        assert_eq!(
            state.db.oids_for_cid(&cid).await.unwrap(),
            vec![first, second],
            "precondition: two candidates in a known order"
        );

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.165:5000".parse().unwrap();

        let mut token: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        let mut tokenless_at = None;
        for step in 1..=12 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "no candidate can serve, so every rung is the truncated-search 503 \
                 (step {step}): {body}"
            );
            assert_eq!(body["error"], "search_incomplete", "{body}");
            match continuation_of(&body) {
                Some(t) => {
                    assert!(
                        !seen.contains(&t),
                        "rung {step} handed back a token it already issued, which is the \
                         ladder spinning in place rather than advancing"
                    );
                    seen.push(t.clone());
                    token = Some(t);
                }
                None => {
                    tokenless_at = Some(step);
                    break;
                }
            }
        }
        assert_eq!(
            tokenless_at,
            Some(6),
            "the ladder must end on the rung where the SECOND candidate walks off the end \
             of the table: two rungs of rows plus one wrap rung per candidate. An earlier \
             tokenless rung means a candidate was abandoned unexamined"
        );
    }

    /// The tokenless shed did not widen: a single-candidate resumed scan that wraps with
    /// nothing sealed still ends the ladder exactly as before.
    ///
    /// This is the negative control for the advance. The advance mints a token whenever a
    /// finished candidate has a successor, so an implementation that forgets the successor
    /// check would keep minting forever and the caller would never learn the search is
    /// over.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_single_candidate_wrap_still_sheds_tokenless(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "solowrap", 2, 0).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        assert_eq!(
            state.db.oids_for_cid(&cid).await.unwrap().len(),
            1,
            "precondition: exactly one candidate, so no advance is ever available"
        );

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.166:5000".parse().unwrap();
        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let token = continuation_of(&body).expect("the probe ceiling mints rung 1");

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a resumed scan that ran off the end has not covered the rows before the \
             token, so it is still the retryable shed: {body}"
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("scan-wrapped")),
            "and the reason must still be the wrap, not an advance: {body}"
        );
        assert_eq!(
            continuation_of(&body),
            None,
            "with no later candidate the wrap ends the ladder, and the absent token is \
             what tells the caller so: {body}"
        );
    }

    /// The advance names the NEXT candidate at the front-of-table sentinel.
    ///
    /// Asserted on the token's contents rather than on the ladder's outcome, because the
    /// outcome alone cannot tell "advanced to candidate B" from "sealed some row of
    /// candidate A that happens to work". The sentinel matters on its own: candidate B has
    /// walked nothing, so resuming it anywhere but the front skips rows for it.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_finished_candidate_advances_to_the_next_at_the_front_sentinel(
        pool: sqlx::PgPool,
    ) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "advance", 2, 0).await;
        let first = "00".repeat(32);
        let second = "11".repeat(32);
        let cid = seed_legacy_pin(&state, &first).await;
        state
            .db
            .record_pinned_cid(&second, &cid, None)
            .await
            .unwrap();

        let key = state.ipfs_scan_token_key.clone();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.167:5000".parse().unwrap();

        let (_, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        let rung1 = continuation_of(&body).expect("rung 1 mints on the probe ceiling");
        let pos = gitlawb_core::scan_token::open_scan_token(
            &key,
            &cid,
            &rung1,
            chrono::Utc::now().timestamp(),
        )
        .expect("the node's own token opens under the node's own key");
        assert_eq!(
            pos.sha256_hex, first,
            "rung 1 seals the candidate that was actually walking"
        );
        assert!(
            !pos.created_at_key.is_empty(),
            "and it seals a real row, not the sentinel"
        );

        let (_, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&rung1)))
                .await
                .unwrap(),
        )
        .await;
        let rung2 = continuation_of(&body)
            .expect("the finished candidate must advance the ladder, not end it");
        let pos = gitlawb_core::scan_token::open_scan_token(
            &key,
            &cid,
            &rung2,
            chrono::Utc::now().timestamp(),
        )
        .expect("the advance token opens");
        assert_eq!(
            pos.sha256_hex, second,
            "the finished candidate hands the ladder to the NEXT candidate"
        );
        assert_eq!(
            (pos.created_at_key.as_str(), pos.id.as_str()),
            ("", ""),
            "at the front-of-table sentinel: the next candidate has walked nothing, so \
             any row cursor would skip rows for it"
        );
    }

    /// On a FRONT-STARTED request a later candidate's stop is honest coverage, and it is
    /// what mints rung 1 when the first candidate wraps under budget.
    ///
    /// The rule that silences later candidates is keyed on where the REQUEST started, not
    /// on which candidate is walking. On a resumed request the pager holds only the suffix
    /// from the caller's cursor, so a later candidate's walk covers a suffix and must not
    /// seal. Front-started, the pager starts at the front and every candidate's row loop
    /// covers the fetched table from the beginning, so the first candidate that has NOT
    /// finished owns the seal, later candidates included.
    ///
    /// Three rows at three per page against a four-probe ceiling: candidate A walks all
    /// three, wraps on the empty page after them, and seals nothing; candidate B spends
    /// the fourth probe on row 0 and stops on row 1, with row 0 settled behind it. The
    /// holder is row 2, reachable only for B.
    ///
    /// Over-applying the resumed-only rule here sheds a tainted TOKENLESS 503 at rung 1
    /// and the holder is never served.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_front_started_later_candidate_still_seals_its_stop_row(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 3;
        state.ipfs_max_legacy_scan_rows = 1024;
        // One more probe than candidate A spends walking the whole table, so A wraps
        // UNTRUNCATED and B gets exactly one probe before the ceiling stops it.
        state.ipfs_max_legacy_probes = 4;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "frontprop", 2, 0).await;
        let (holder_id, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6frontprop",
            "holder",
            b"reachable only for the later candidate\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 2).await;
        let cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;
        let absent_first = "00".repeat(32);
        state
            .db
            .record_pinned_cid(&absent_first, &cid, None)
            .await
            .unwrap();
        assert_eq!(
            state.db.oids_for_cid(&cid).await.unwrap(),
            vec![absent_first, holder_oid.clone()],
            "precondition: the holder's oid is the SECOND candidate"
        );

        let key = state.ipfs_scan_token_key.clone();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.168:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let rung1 = continuation_of(&body).unwrap_or_else(|| {
            panic!(
                "the first candidate wrapped under budget and sealed nothing, so the \
                 LATER candidate's ceiling stop is the only thing that can mint rung 1; \
                 a tokenless shed here ends a ladder that works today: {body}"
            )
        });
        let pos = opened(&key, &cid, &rung1);
        assert_eq!(
            pos.sha256_hex, holder_oid,
            "rung 1 belongs to the candidate that actually stopped"
        );
        assert!(
            !pos.created_at_key.is_empty(),
            "and it seals that candidate's own stop row, not the front sentinel: it \
             walked from the front, so there is nothing to restart"
        );

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&rung1)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "echoing rung 1 must reach the holder: {body}"
        );
    }

    /// A candidate that a ceiling stopped PART WAY through the last page has not wrapped,
    /// however the shared pager's exhausted flag reads.
    ///
    /// `pager.exhausted` is per REQUEST and is set the moment any short page comes back,
    /// so it is true while rows the ceiling refused are still sitting in front of the
    /// cursor. Reading it at the tail as the wrap witness marks the truncated candidate
    /// finished, advances the ladder to the next one, and strands those rows forever. The
    /// witness has to be the per-candidate exit the row loop actually took.
    ///
    /// Four rows at three per page against a one-probe ceiling. Rung 3 resumes into a
    /// SHORT page (two rows), spends its probe on the first and is stopped on the second,
    /// so the request ends with `exhausted` set and a row unwalked.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_truncation_on_an_exhausted_page_does_not_advance_the_candidate(
        pool: sqlx::PgPool,
    ) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 3;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "wrapwitness", 4, 0).await;
        let first = "00".repeat(32);
        let second = "11".repeat(32);
        let cid = seed_legacy_pin(&state, &first).await;
        state
            .db
            .record_pinned_cid(&second, &cid, None)
            .await
            .unwrap();

        let key = state.ipfs_scan_token_key.clone();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.169:5000".parse().unwrap();

        let mut token: Option<String> = None;
        for step in 1..=3 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            let t = continuation_of(&body)
                .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}"));
            let pos = opened(&key, &cid, &t);
            assert_eq!(
                pos.sha256_hex, first,
                "rung {step} stopped the FIRST candidate at a ceiling, so it is still \
                 that candidate's rung. Rung 3 is the one that matters: it resumes into \
                 a short page, so the shared exhausted flag is set while a row it refused \
                 is still unwalked, and an implementation reading that flag as the wrap \
                 witness advances here and strands the row"
            );
            assert!(
                !pos.created_at_key.is_empty(),
                "rung {step} seals a real row, not the sentinel"
            );
            token = Some(t);
        }

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let pos = opened(
            &key,
            &cid,
            &continuation_of(&body).expect("rung 4 walks the first candidate off the end"),
        );
        assert_eq!(
            (pos.sha256_hex.as_str(), pos.created_at_key.as_str()),
            (second.as_str(), ""),
            "only once the first candidate has actually walked every fetched row does \
             the ladder advance, and then to the front of the next candidate"
        );
    }

    /// A resumed rung does not re-run the scans of candidates earlier rungs already
    /// finished, and the skip lands after the provenance phase, not before it.
    ///
    /// `walk.probes` has no test seam, so the observable is the marker-query pair the
    /// fallback gate runs per candidate that reaches `needs_scan`. Both candidates carry
    /// recorded sources marked incomplete, so both would bump the counter if both were
    /// scanned; resuming at the second must leave it at one.
    ///
    /// The counter also pins the skip's exact position. Skipping at the top of the oid
    /// loop would cut off the provenance phase, which can serve outright; skipping inside
    /// `needs_scan` would charge the skipped candidate two lookups for nothing and read 2
    /// here.
    #[sqlx::test]
    async fn get_by_cid_resumed_rung_skips_the_scans_of_earlier_candidates(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1024;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        // One private repo, used both as the scan inventory and as the recorded pin
        // source for each candidate: it denies at the root gate either way, so the
        // provenance phase runs and serves nothing.
        seed_root_denying_repos(&state, "skipearlier", 2, 0).await;
        let source = "skipearlier-0000".to_string();
        let first = "00".repeat(32);
        let second = "11".repeat(32);
        let cid = seed_legacy_pin(&state, &first).await;
        state
            .db
            .record_pinned_cid(&second, &cid, None)
            .await
            .unwrap();
        for oid in [&first, &second] {
            state.db.record_pin_source(oid, &source).await.unwrap();
            // Incomplete keeps `needs_scan` true past a non-empty source set, which is
            // what puts the marker pair on the path for every candidate that is NOT
            // skipped.
            state.db.mark_pin_sources_incomplete(oid, "").await.unwrap();
        }

        let key = state.ipfs_scan_token_key.clone();
        let token = minted(&key, &cid, &second, ("", ""));
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.170:5000".parse().unwrap();

        crate::api::ipfs::reset_marker_queries();
        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            crate::api::ipfs::marker_queries(),
            1,
            "only the resumed candidate owes a scan this rung; the one before it was \
             finished by an earlier rung and must not pay the fallback gate again: {body}"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the resumed candidate walked the table from the sentinel but the rows \
             before the ladder started were skipped, so the honest tail is the retryable \
             shed: {body}"
        );
    }

    /// A resumed request still lets LATER candidates serve off the pages it already
    /// bought. They are silenced for sealing, not deferred.
    ///
    /// Skipping them would waste page fetches the caller has already paid for and would
    /// turn a rung that could have ended the ladder outright into another 503.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_resumed_rung_still_serves_from_a_later_candidate(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1024;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "opportune", 1, 0).await;
        let (holder_id, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6opportune",
            "holder",
            b"served off a page the resumed candidate bought\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 1).await;
        let cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;
        let absent_first = "00".repeat(32);
        state
            .db
            .record_pinned_cid(&absent_first, &cid, None)
            .await
            .unwrap();

        let key = state.ipfs_scan_token_key.clone();
        let token = minted(&key, &cid, &absent_first, ("", ""));
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.171:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a later candidate that can serve off the already-fetched rows must serve in \
             this same rung: {body}"
        );
    }

    /// A token naming a candidate that is no longer pinned degrades to a front restart.
    ///
    /// The hex is sealed by the node so it cannot be forged, but an unpin between rungs
    /// can retire it. The open path must then treat the token as absent: never resume
    /// some other candidate at that row, never fabricate a 404 out of a table this
    /// request has not looked at, and never panic on a lookup that misses.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_token_naming_an_unpinned_candidate_restarts_at_the_front(
        pool: sqlx::PgPool,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1024;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "stalehex", 1, 0).await;
        let (holder_id, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6stalehex",
            "holder",
            b"still reachable after the sealed candidate went away\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 1).await;
        let cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;

        let key = state.ipfs_scan_token_key.clone();
        // A well-formed token under the node's own key, naming an oid the CID no longer
        // resolves to, sealed at a row PAST the holder. Resuming it against the wrong
        // candidate would skip the holder; treating it as absent restarts at the front.
        let token = minted(
            &key,
            &cid,
            &"cc".repeat(32),
            (&scan_order_stamp(9).to_rfc3339(), "zzz/zzz"),
        );
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.172:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a stale candidate identity restarts the scan at the front, so the holder is \
             still found: {body}"
        );
    }

    /// The ladder only ever names the resumed candidate, or the one immediately after it.
    ///
    /// Three candidates, resumed at the first with ceilings that truncate it. Every rung
    /// until the first candidate finishes must keep naming it, and the rung that finally
    /// moves must hand the ladder to candidate 2 at the front, never skip to candidate 3.
    /// Skipping one would mark it finished over a table it never walked.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_ladder_never_skips_a_candidate(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "noskip", 4, 0).await;
        let first = "00".repeat(32);
        let second = "11".repeat(32);
        let third = "22".repeat(32);
        let cid = seed_legacy_pin(&state, &first).await;
        for oid in [&second, &third] {
            state.db.record_pinned_cid(oid, &cid, None).await.unwrap();
        }
        assert_eq!(
            state.db.oids_for_cid(&cid).await.unwrap(),
            vec![first.clone(), second.clone(), third.clone()],
            "precondition: three candidates in a known order"
        );

        let key = state.ipfs_scan_token_key.clone();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.173:5000".parse().unwrap();

        let mut token = Some(minted(&key, &cid, &first, ("", "")));
        let mut moved_to = None;
        for step in 1..=8 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            let t = continuation_of(&body)
                .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}"));
            let pos = opened(&key, &cid, &t);
            assert_ne!(
                pos.sha256_hex, third,
                "rung {step} handed the ladder to the THIRD candidate while the second \
                 had not been walked; that marks it finished over a table it never saw"
            );
            if pos.sha256_hex != first {
                moved_to = Some((pos.sha256_hex.clone(), pos.created_at_key.clone()));
                break;
            }
            token = Some(t);
        }
        assert_eq!(
            moved_to,
            Some((second, String::new())),
            "the ladder moves one candidate at a time, to the front of the next"
        );
    }

    /// R11: a four-candidate CID must be served inside the client's resume budget.
    ///
    /// `gl ipfs get` stops after `MAX_SCAN_RESUMES` resumes (see
    /// `crates/gl/src/ipfs_cmd.rs`; it is private to that crate, so the 8 is repeated
    /// here and a change to the cap should bring you to this fixture). Ladder length
    /// scales with candidate count, so this is the shape that pins the cost.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_four_candidates_serve_within_the_client_resume_budget(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "fourcand", 1, 0).await;
        let (holder_id, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6fourcand",
            "holder",
            b"four candidates deep\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 1).await;
        let cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;
        // Three absent candidates, all sorting ahead of the holder's oid, so the holder
        // is reachable only through the LAST of the four.
        for oid in ["00", "11", "22"] {
            state
                .db
                .record_pinned_cid(&oid.repeat(32), &cid, None)
                .await
                .unwrap();
        }
        let candidates = state.db.oids_for_cid(&cid).await.unwrap();
        assert_eq!(candidates.len(), 4, "precondition: four candidates");
        assert_eq!(
            candidates[3], holder_oid,
            "precondition: the holder's oid sorts last"
        );

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.174:5000".parse().unwrap();

        // One initial request plus at most MAX_SCAN_RESUMES echoes, exactly as the client
        // drives it.
        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=9 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            token = Some(
                continuation_of(&body)
                    .unwrap_or_else(|| panic!("rung {step} must carry a continuation: {body}")),
            );
        }
        assert!(
            served_at.is_some_and(|s| s <= 9),
            "a four-candidate CID must be served inside the client's 8-resume budget, \
             got {served_at:?}"
        );
    }

    /// A resumed candidate that owes NO scan still advances the ladder.
    ///
    /// Finished means covered, and a candidate whose recorded provenance is complete is
    /// covered without a single row being walked. Gating the advance on the row loop
    /// having wrapped leaves that candidate permanently unfinished: the rung sheds with
    /// no token and every candidate behind it is never examined, which is the starvation
    /// bug in a third shape.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_resumed_candidate_owing_no_scan_still_advances(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool.clone());
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "noscan", 1, 0).await;
        let (holder_id, holder_oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6noscan",
            "holder",
            b"behind a candidate that owes no scan\n",
        )
        .await;
        stamp_scan_order(&pool, &holder_id, 1).await;
        let cid = seed_legacy_pin_for_oid(&state, &holder_oid).await;

        // The first candidate has a COMPLETE recorded source that denies, so its
        // provenance phase answers for it and `needs_scan` is false: no row loop runs and
        // it can never wrap.
        let absent_first = "00".repeat(32);
        state
            .db
            .record_pinned_cid(&absent_first, &cid, None)
            .await
            .unwrap();
        seed_root_denying_repos(&state, "noscansrc", 1, 0).await;
        state
            .db
            .record_pin_source(&absent_first, "noscansrc-0000")
            .await
            .unwrap();

        let key = state.ipfs_scan_token_key.clone();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.175:5000".parse().unwrap();

        let mut token = Some(minted(&key, &cid, &absent_first, ("", "")));
        let mut served_at = None;
        for step in 1..=6 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            token = Some(continuation_of(&body).unwrap_or_else(|| {
                panic!(
                    "rung {step} shed with no continuation: a candidate that owes no scan \
                     is finished, and finished must hand the ladder on: {body}"
                )
            }));
        }
        assert!(
            served_at.is_some(),
            "the ladder must reach the holder behind the no-scan candidate"
        );
    }

    /// Resuming the FINAL candidate at the front sentinel keeps the retryable shed.
    ///
    /// Under the sentinel the row walk really does start at the front, so it is tempting
    /// to treat the request as front-started. It is not: this rung SKIPPED every candidate
    /// before the sealed one, so absence has not been proven within it and the definitive
    /// 404 is not available.
    #[sqlx::test]
    async fn get_by_cid_front_sentinel_resume_keeps_the_retryable_shed(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1024;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_denying_repos(&state, "sentinelshed", 2, 0).await;
        let first = "00".repeat(32);
        let second = "11".repeat(32);
        let cid = seed_legacy_pin(&state, &first).await;
        state
            .db
            .record_pinned_cid(&second, &cid, None)
            .await
            .unwrap();

        let key = state.ipfs_scan_token_key.clone();
        let token = minted(&key, &cid, &second, ("", ""));
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.176:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the candidates before the sealed one were skipped this request, so their \
             absence is unproven and the 404 is not available: {body}"
        );
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|m| m.contains("scan-wrapped")),
            "{body}"
        );
        assert_eq!(
            continuation_of(&body),
            None,
            "the last candidate reached the end of the table, so the ladder is over: {body}"
        );
    }

    /// A rung that advanced nothing must not hand the caller back the token they sent.
    ///
    /// `walk.visits` is charged by the provenance phase as well as by the scan, so a CID
    /// whose recorded sources spend the whole visit budget reaches the scan's top-of-loop
    /// visit arm before a single page has been fetched. On a RESUMED request `pager.cursor`
    /// is still the caller's own incoming position at that moment, so sealing it emits
    /// their own token back verbatim. `gl` echoes a token up to `MAX_SCAN_RESUMES` times
    /// inside its deadline, and every one of those rungs re-runs the whole provenance phase
    /// (up to `MAX_PIN_SOURCES` acquires and `cat-file` subprocesses) to arrive at the same
    /// place, so one anonymous request becomes nine and the token makes the spin look like
    /// progress.
    ///
    /// The STATUS is asserted, not just the missing token. The documented precedence is
    /// truncation 503 over throttle 429 over the definitive 404, and a dropped seal must
    /// leave the truncation tail standing rather than fall through to either lower one.
    ///
    /// MUTATION (RED): drop the strictly-ahead filter at the mint site, and the shed
    /// carries a continuation that opens to the identical position that was sent.
    #[sqlx::test]
    async fn get_by_cid_visit_starved_resume_does_not_echo_the_callers_own_token(
        pool: sqlx::PgPool,
    ) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        // Probes must NOT bind: the visit budget, spent before the scan starts, is what
        // stops this request.
        state.ipfs_max_legacy_probes = 1024;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repo_visits = 2;
        state.config = std::sync::Arc::new(cfg);

        // Four root-readable rows. The first two double as the candidate's recorded pin
        // sources: each passes the root gate, so each is charged a visit, and the pair
        // spends the ceiling before the scan fetches its first page.
        seed_ladder_filler(&state, &pool, "visitstarve", 4, 0).await;
        let oid = absent_oid();
        let cid = seed_legacy_pin(&state, &oid).await;
        for i in 0..2 {
            state
                .db
                .record_pin_source(&oid, &format!("z6readablevisitstarve/visitstarve-{i:04}"))
                .await
                .unwrap();
        }
        // A non-empty source set only reaches the scan when it may be INCOMPLETE, and the
        // scan is what this rung has to be starved out of.
        state
            .db
            .mark_pin_sources_incomplete(&oid, "")
            .await
            .unwrap();

        let key = state.ipfs_scan_token_key.clone();
        let start = (
            scan_order_stamp(0).to_rfc3339(),
            "z6readablevisitstarve/visitstarve-0000".to_string(),
        );
        let token = minted(&key, &cid, &oid, (start.0.as_str(), start.1.as_str()));
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.177:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the search was cut short, so the truncation 503 stands; dropping the seal \
             must not let the tail fall through to the throttle or the definitive 404: \
             {body}"
        );
        // Rendered as the position rather than the opaque token so a failure NAMES the
        // defect: the echoed triple is byte for byte the one the request carried in.
        let echoed = continuation_of(&body).map(|t| {
            let pos = opened(&key, &cid, &t);
            (pos.sha256_hex, pos.created_at_key, pos.id)
        });
        assert_eq!(
            echoed, None,
            "this rung reached no row the caller had not already been given, so it owes \
             no continuation; echoing {start:?} back under {oid} spins the ladder for \
             another eight amplified requests and calls it progress"
        );
    }

    /// The filter drops a seal that stood still, never one that moved.
    ///
    /// Two properties in one fixture, because they are the two halves of "does not
    /// over-drop". Rung 1 is FRONT-STARTED, where the request's start is before every row,
    /// so its seal must pass the filter untouched; rung 2 resumes from it, walks two more
    /// rows, and its seal must pass because it is strictly ahead.
    ///
    /// MUTATION (RED): compare the proposal against the start with `>=` instead of `>`
    /// and rung 2 keeps its token, so this stays green; compare with `<` and both rungs
    /// lose theirs. The filter's job is the middle case, and this fixture is what keeps
    /// it from swallowing the other two.
    #[sqlx::test]
    async fn get_by_cid_a_rung_that_advances_a_row_still_mints(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "advances", 4, 0).await;
        let oid = absent_oid();
        let cid = seed_legacy_pin(&state, &oid).await;

        let key = state.ipfs_scan_token_key.clone();
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.178:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let rung1 = continuation_of(&body).expect(
            "a front-started request starts before every row, so its probe-ceiling seal \
             is strictly ahead by construction and must still mint",
        );
        let first = opened(&key, &cid, &rung1);

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&rung1)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let rung2 = continuation_of(&body)
            .expect("the resumed rung walked two more rows, so it has somewhere to seal");
        let second = opened(&key, &cid, &rung2);
        assert_eq!(
            (second.sha256_hex.as_str(), first.sha256_hex.as_str()),
            (oid.as_str(), oid.as_str()),
            "one candidate, so both rungs name it"
        );
        assert!(
            (second.created_at_key.clone(), second.id.clone())
                > (first.created_at_key.clone(), first.id.clone()),
            "a rung that reached rows the caller had not seen must seal one of them: \
             {first:?} then {second:?}"
        );
    }

    /// The advance to the next candidate is not "backwards", and the filter must know it.
    ///
    /// The advance seals the front-of-table sentinel, an empty row pair that sorts BELOW
    /// every real key. A filter that compared only the row would read the ladder's one real
    /// forward step as a step back and drop it, ending every multi-candidate ladder at the
    /// rung that was about to hand over. What makes it forward is the candidate: a
    /// different hex can only come from the finished-candidate advance, which is ahead by
    /// construction.
    ///
    /// MUTATION (RED): compare rows without first comparing the candidate, and the
    /// handover token disappears.
    #[sqlx::test]
    async fn get_by_cid_the_advance_to_the_next_candidate_survives_the_filter(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 1024;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_denying_repos(&state, "advfilter", 2, 0).await;
        let first = "00".repeat(32);
        let second = "11".repeat(32);
        let cid = seed_legacy_pin(&state, &first).await;
        state
            .db
            .record_pinned_cid(&second, &cid, None)
            .await
            .unwrap();

        let key = state.ipfs_scan_token_key.clone();
        // Resumed at the LAST row of the table, so the first candidate's keyset fetch comes
        // back empty, it wraps, and the rung's whole job is the handover.
        let token = minted(
            &key,
            &cid,
            &first,
            (&scan_order_stamp(1).to_rfc3339(), "advfilter-0001"),
        );
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.179:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let handover = continuation_of(&body).expect(
            "the finished candidate hands the ladder on, and the sentinel it seals is \
             ahead by candidate even though the row pair sorts below the start",
        );
        let pos = opened(&key, &cid, &handover);
        assert_eq!(
            (
                pos.sha256_hex.as_str(),
                pos.created_at_key.as_str(),
                pos.id.as_str()
            ),
            (second.as_str(), "", ""),
            "the next candidate, at the front of the table"
        );
    }

    /// A ceiling that stops mid-page seals the last row it SETTLED, which is progress.
    ///
    /// This is the arm the tokenless shed must not swallow. A resumed scan only ever walks
    /// rows past its start cursor, so any row it settled is strictly ahead, and the rung
    /// that settles two rows before a ceiling refuses the third owes the caller the second
    /// one. Only a rung that settled NOTHING sheds tokenless, because there the spender is
    /// the provenance phase, which runs identically on every retry.
    ///
    /// MUTATION (RED): seal the request's start instead of the settled row, and the filter
    /// (correctly) drops it, so this ladder loses its token and stalls.
    #[sqlx::test]
    async fn get_by_cid_resumed_ceiling_seals_the_last_row_it_settled(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // A page wide enough that the probe ceiling binds INSIDE the row loop rather than
        // at the top of it: that is the arm whose position is the last settled row.
        state.ipfs_legacy_scan_page_rows = 4;
        state.ipfs_max_legacy_scan_rows = 1024;
        state.ipfs_max_legacy_probes = 2;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_ladder_filler(&state, &pool, "settled", 5, 0).await;
        let oid = absent_oid();
        let cid = seed_legacy_pin(&state, &oid).await;

        let key = state.ipfs_scan_token_key.clone();
        let start = (
            scan_order_stamp(0).to_rfc3339(),
            "z6readablesettled/settled-0000".to_string(),
        );
        let token = minted(&key, &cid, &oid, (start.0.as_str(), start.1.as_str()));
        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.180:5000".parse().unwrap();

        let (status, body) = status_and_body(
            router
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        let pos = opened(
            &key,
            &cid,
            &continuation_of(&body).expect(
                "the rung settled two rows before the ceiling refused the third, so it \
                 has real progress to seal",
            ),
        );
        assert_eq!(
            (pos.created_at_key.as_str(), pos.id.as_str()),
            (
                scan_order_stamp(2).to_rfc3339().as_str(),
                "z6readablesettled/settled-0002"
            ),
            "the seal is the last row the ceiling let this rung settle, not the row it \
             refused and not the caller's own start"
        );
        assert!(
            (pos.created_at_key.clone(), pos.id.clone()) > start,
            "and it is strictly ahead of the position the request came in with"
        );
    }

    /// The VISIT ceiling must advance the ladder too, for the same reason as the probe
    /// ceiling: it is the sibling arm, it fires on the same root-readable inventory, and
    /// a tokenless shed there strands everything behind it just as permanently.
    ///
    /// MUTATION (RED): drop the continuation from the visit-ceiling arm.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_visit_ceiling_ladders_to_a_holder_past_it(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1024;
        // Probes must NOT bind: the visit ceiling is the one under test.
        state.ipfs_max_legacy_probes = 1024;
        let mut cfg = (*state.config).clone();
        cfg.ipfs_max_repo_visits = 2;
        state.config = std::sync::Arc::new(cfg);
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1024, std::time::Duration::from_secs(3600));

        seed_root_readable_repos(&state, "visit", 6).await;
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6visit",
            "holder",
            b"past the visits\n",
        )
        .await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.153:5000".parse().unwrap();
        let bound = 6usize.div_ceil(2) + 1;

        let mut token: Option<String> = None;
        let mut served_at = None;
        for step in 1..=bound {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::OK {
                served_at = Some(step);
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "an intermediate rung is the retryable 503 (step {step}): {body}"
            );
            token = Some(continuation_of(&body).unwrap_or_else(|| {
                panic!(
                    "the visit-ceiling shed at step {step} must carry a continuation: \
                     {body}"
                )
            }));
        }
        assert!(
            served_at.is_some(),
            "a holder past the visit ceiling must be reached within {bound} \
             token-echoing requests, not stranded forever"
        );
    }

    /// Scenario 6: the page toll accumulates ACROSS requests.
    ///
    /// Every page the scan buys is charged to the caller's per-IP work bucket, so a
    /// denial-only inventory cannot be re-paged for free by re-requesting. A bucket
    /// sized to 4 pages admits four requests' worth of paging and then sheds the fifth
    /// with 429, buying NO page (the `preload_queries()` count stalls) and carrying NO
    /// token. The caller's PREVIOUS token still resumes them once the bucket refills.
    ///
    /// MUTATION D (RED): drop the page toll and the pages are free again, so the fifth
    /// request buys its page and never 429s.
    #[sqlx::test]
    async fn get_by_cid_denial_only_requests_throttle_across_requests(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 2;
        // Four pages of allowance: above the derived floor's page term for this fixture
        // and still small enough that a handful of requests exhausts it.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(4, std::time::Duration::from_secs(3600));
        seed_root_denying_repos(&state, "toll", 20, 0).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let router = ipfs_router(state.clone());
        let peer: SocketAddr = "203.0.113.145:5000".parse().unwrap();

        crate::api::ipfs::reset_preload_queries();
        let mut last_token = None;
        for step in 1..=4 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), None))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "request {step} is within the bucket and must buy its page: {body}"
            );
            last_token = continuation_of(&body);
        }
        let last_token = last_token.expect("a tolled-but-admitted request still emits a token");
        let pages_before = crate::api::ipfs::preload_queries();

        let (status, body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "a spent work bucket must brake the next denial-only request with 429 \
             rather than sell it another page: {body}"
        );
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            pages_before,
            "and the braked request must buy NO page; a 429 that still paged would \
             leave the amplification exactly where it was"
        );
        assert!(
            continuation_of(&body).is_none(),
            "the 429 carries no token: the caller's own bucket, not the node's search, \
             stopped them, and their previous token is still valid: {body}"
        );

        // Bucket refilled (a fresh limiter is the window elapsing). The token the caller
        // already holds still resumes them: the throttle cost them a page, not their
        // place in the ladder.
        let mut refilled = state.clone();
        refilled.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(4, std::time::Duration::from_secs(3600));
        crate::api::ipfs::reset_scan_rows();
        let (status, body) = status_and_body(
            ipfs_router(refilled)
                .oneshot(get_cid_scan(&cid, Some(peer), Some(&last_token)))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the previously issued token must still resume after a refill: {body}"
        );
        assert_eq!(
            crate::api::ipfs::scan_rows(),
            2,
            "and it must resume at the sealed position, one ceiling's worth of rows \
             read, not a restart at the front"
        );
    }

    /// Scenario 7: the RULES ceiling. The row ceiling bounds the row count but not the
    /// memory each row drags in: the pager retains every fetched page's rules for the
    /// whole request. A window of rule-heavy repos must taint at the rules ceiling with
    /// the row count still well under the row ceiling, on the same 503-with-token
    /// contract.
    #[sqlx::test]
    async fn get_by_cid_rules_ceiling_stops_scan_with_token(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        // Rows are NOT the binding ceiling here.
        state.ipfs_max_legacy_scan_rows = 1000;
        state.ipfs_max_legacy_scan_rule_bytes = 3;
        seed_root_denying_repos(&state, "rules", 8, 2).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let peer: SocketAddr = "203.0.113.146:5000".parse().unwrap();
        crate::api::ipfs::reset_scan_rows();
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a rules-ceiling truncation sheds the same retryable 503: {body}"
        );
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("rules-ceiling"),
            "the shed must name the rules ceiling so an operator can tell it from a row \
             truncation: {body}"
        );
        let rows = crate::api::ipfs::scan_rows();
        assert!(
            rows < 1000,
            "the rules ceiling must fire with rows still under the row ceiling, or it is \
             not the guard being exercised; read {rows} rows"
        );
        assert!(
            continuation_of(&body).is_some(),
            "a rules truncation carries a continuation too: {body}"
        );
    }

    /// A SINGLE page whose rules exceed the ceiling truncates the request that bought
    /// it.
    ///
    /// The ceiling bounds retained MEMORY, and the thing it has to bound is bytes: there
    /// is no per-repo cap on `visibility_rules`, and an owner controls both how many
    /// rules their repos carry and how long each `reader_dids` list is. Counted in rules
    /// and checked only between pages, one page could carry arbitrarily many bytes and
    /// the guard would not notice until it was asked for the NEXT page, which on a scan
    /// that ends there is never.
    ///
    /// The fixture is calibrated so page one alone clears the byte ceiling while its
    /// four rules are far under any plausible rule COUNT, which is what makes the unit
    /// the thing under test.
    ///
    /// MUTATION (RED): move the check back between pages and the request that bought the
    /// oversized page runs on to a clean 404.
    #[sqlx::test]
    async fn get_by_cid_one_oversized_page_truncates_its_own_request(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        // Neither rows nor probes may bind: this is the rule-bytes guard alone.
        state.ipfs_max_legacy_scan_rows = 1000;
        // Under the byte ceiling one page (2 rows x 2 rules, each rule carrying its repo
        // id, its glob and a reader DID) is already over. Under a RULE count of 200 that
        // same page is four.
        state.ipfs_max_legacy_scan_rule_bytes = 200;
        seed_root_denying_repos(&state, "bytes", 6, 2).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let peer: SocketAddr = "203.0.113.152:5000".parse().unwrap();
        crate::api::ipfs::reset_scan_rows();
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "the page that blew the retained-byte ceiling must truncate its OWN request, \
             not run on to a 404: {body}"
        );
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("rules-ceiling"),
            "the shed names the rule-bytes ceiling: {body}"
        );
        assert_eq!(
            crate::api::ipfs::scan_rows(),
            2,
            "and it stops on the page that bought the bytes, not a page later"
        );
        assert!(
            continuation_of(&body).is_some(),
            "a rule-bytes truncation carries a continuation like every other ceiling: \
             {body}"
        );
    }

    /// The rule-bytes ceiling must be enforced by the QUERY, not by summing the page
    /// after it has been transferred and allocated.
    ///
    /// A repo owner controls how many rules their repos carry and how long each
    /// `reader_dids` list is, so a post-fetch sum truncates the REQUEST while leaving the
    /// WORK unbounded: the oversized page is already in memory by the time the guard
    /// fires. INV-10 bounds work done, never results measured afterwards, and the caller
    /// here is an anonymous `/ipfs/{legacy-cid}` request holding one of the scarce walk
    /// permits.
    ///
    /// The assertion is on the number of rule ROWS the query actually returned, not on
    /// the status: the status is identical either way, which is exactly why the old shape
    /// looked correct.
    ///
    /// MUTATION (RED): drop the query bound and sum the rules after the fetch, and the
    /// whole page's rules are materialized (16 rows here against a budget that admits
    /// one repo's two).
    #[sqlx::test]
    async fn get_by_cid_rule_bytes_bounded_in_the_query_not_after_the_page(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // One page holds every seeded repo, so nothing but the rule budget can bind.
        state.ipfs_legacy_scan_page_rows = 8;
        state.ipfs_max_legacy_scan_rows = 1000;
        // Under this budget a single repo's pair of rules is already over, so at most one
        // repo may be loaded and the page's remaining seven must never leave the database.
        state.ipfs_max_legacy_scan_rule_bytes = 200;
        seed_root_denying_repos(&state, "querybound", 8, 2).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let peer: SocketAddr = "203.0.113.171:5000".parse().unwrap();
        crate::api::ipfs::reset_scan_rule_rows();
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;

        let rule_rows = crate::api::ipfs::scan_rule_rows();
        assert!(
            rule_rows <= 4,
            "the byte budget must bound the QUERY: at most one repo's rules may be \
             materialized under a 200-byte budget, but {rule_rows} rule rows were pulled \
             (the whole page is 16)"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "reaching the query bound is the ceiling condition and sheds the retryable \
             503, exactly as the post-fetch sum did: {body}"
        );
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("rules-ceiling"),
            "the shed still names the rule-bytes ceiling: {body}"
        );
        assert!(
            continuation_of(&body).is_some(),
            "and it still mints a continuation, or the repos behind the cut are \
             unreachable: {body}"
        );
    }

    /// The property the old `!exhausted` condition protected, restated for the query
    /// bound: a scan that genuinely covered the table must answer 404, never a permanent
    /// 503.
    ///
    /// Under the query bound the taint no longer keys on "the page was short" but on
    /// "the query left repos unloaded". A short final page whose rules all fit leaves
    /// nothing unloaded, so it stays a complete scan and the absent object is a clean
    /// 404. The budget here is finite and set by the fixture, so this is the guard being
    /// exercised rather than the 4 MiB default never coming near.
    #[sqlx::test]
    async fn get_by_cid_short_final_page_under_the_rule_budget_still_404s(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 8;
        state.ipfs_max_legacy_scan_rows = 1000;
        // Roomy enough for all four repos' rules together, so no cut is possible.
        state.ipfs_max_legacy_scan_rule_bytes = 64 * 1024;
        seed_root_denying_repos(&state, "shortfit", 4, 1).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let peer: SocketAddr = "203.0.113.172:5000".parse().unwrap();
        let (status, body) = status_and_body(
            ipfs_router(state)
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a complete scan of an absent object is a verdict; turning it into a 503 \
             would make the object permanently unresolvable: {body}"
        );
    }

    /// The ladder MAKES PROGRESS under the query bound: every rung consumes at least one
    /// repo, so the continuation always advances and the scan terminates.
    ///
    /// This is the failure mode the query bound could have introduced. If a page whose
    /// FIRST repo alone exceeds the remaining budget loaded nothing, the cut would sit at
    /// the cursor, the next request would reproduce it exactly, and the caller would be
    /// wedged on a 503 forever for an object the node could otherwise settle. The bound
    /// therefore always admits the first rule-carrying repo of a page whatever its size.
    ///
    /// The ladder ends on the tokenless shed, which is the design's "your ladder is
    /// over" answer for a RESUMED scan (absence was only ever proven over
    /// `[token, end)`), not on a 404.
    #[sqlx::test]
    async fn get_by_cid_rule_bytes_ladder_advances_to_a_tokenless_shed(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 1000;
        // Every repo's rules alone clear the budget, so every page is cut at its first
        // repo: the worst case for progress.
        state.ipfs_max_legacy_scan_rule_bytes = 1;
        let repos = 8usize;
        seed_root_denying_repos(&state, "ladder", repos, 2).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let peer: SocketAddr = "203.0.113.173:5000".parse().unwrap();
        let router = ipfs_router(state);
        let mut token: Option<String> = None;
        let mut rungs = 0usize;
        let bound = repos + 2;
        loop {
            rungs += 1;
            assert!(
                rungs <= bound,
                "the ladder must consume at least one repo per rung and terminate within \
                 {bound} rungs; a rung that loaded nothing would repeat forever"
            );
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            if status == StatusCode::NOT_FOUND {
                break;
            }
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "rung {rungs} must be the retryable 503: {body}"
            );
            let next = continuation_of(&body);
            if next.is_none() {
                break;
            }
            assert_ne!(
                next, token,
                "rung {rungs} handed back the SAME continuation it was given, so the scan \
                 made no progress and the caller is wedged: {body}"
            );
            token = next;
        }
    }

    /// Scenario 8: interleaved callers stay isolated. Two source keys alternate
    /// token-echoing ladders against the same denial-heavy inventory with the holder
    /// past the ceiling; each must reach its own 200 within its own bound.
    ///
    /// Isolation is STRUCTURAL under this design (each ladder's entire state rides in
    /// its own tokens and the node holds none), so this is the executed confirmation
    /// rather than a mutant target. It is what rules out the rejected designs: a
    /// node-global persisted cursor lets these two advance each other's window, and a
    /// per-caller server-side map lets one evict the other.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_interleaved_callers_each_reach_their_holder(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 4;
        // The production toll, generous enough that neither caller's ladder is braked;
        // this scenario is about isolation, not the toll.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(600, std::time::Duration::from_secs(3600));

        seed_root_denying_repos(&state, "interleave", 10, 0).await;
        let (_, oid) = seed_repo_with_blob(
            &state,
            tmp.path(),
            "z6interleave",
            "holder",
            b"shared holder\n",
        )
        .await;
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        let router = ipfs_router(state);
        let peers: [SocketAddr; 2] = [
            "203.0.113.147:5000".parse().unwrap(),
            "203.0.113.148:5000".parse().unwrap(),
        ];
        let bound = 10usize.div_ceil(4) + 1;
        let mut tokens: [Option<String>; 2] = [None, None];
        let mut served = [None, None];

        for step in 1..=bound {
            for (i, peer) in peers.iter().enumerate() {
                if served[i].is_some() {
                    continue;
                }
                let (status, body) = status_and_body(
                    router
                        .clone()
                        .oneshot(get_cid_scan(&cid, Some(*peer), tokens[i].as_deref()))
                        .await
                        .unwrap(),
                )
                .await;
                if status == StatusCode::OK {
                    served[i] = Some(step);
                    continue;
                }
                assert_eq!(
                    status,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "caller {i} rung {step} must be the retryable 503: {body}"
                );
                tokens[i] = Some(
                    continuation_of(&body)
                        .unwrap_or_else(|| panic!("caller {i} rung {step} needs a token: {body}")),
                );
            }
        }

        assert!(
            served[0].is_some() && served[1].is_some(),
            "both interleaved callers must reach the holder within their own bound of \
             {bound}; got {served:?}. A shared server-side cursor would let one caller's \
             progress skip the other's coverage"
        );
    }

    /// Seed `n` PRIVATE repos whose id, owner DID, and `created_at` are all
    /// high-entropy MARKERS, so a substring search over an emitted token is a real
    /// test. Returns the markers in scan order.
    async fn seed_marked_withheld_repos(
        state: &crate::state::AppState,
        n: usize,
    ) -> Vec<(String, String, String)> {
        const OWNER: &str = "did:key:z6MkWithheldOwnerMarkerQQQQQQQQQQQQQQQQ";
        let mut out = Vec::new();
        for i in 0..n {
            let at = scan_order_stamp(i);
            let id = format!("marker-repo-XZXZ{i:04}");
            // Every other row is a quarantined mirror instead of a private repo, so
            // both withholding classes sit in the window the token is minted from.
            if i % 2 == 1 {
                state
                    .db
                    .upsert_mirror_repo(OWNER, &id, &format!("/nonexistent/{id}"), None, true)
                    .await
                    .expect("seed a quarantined marker row");
                // `upsert_mirror_repo` stamps `now` and derives its own id, so re-read
                // the row the scan will actually see.
                let rec = state
                    .db
                    .get_repo(OWNER, &id)
                    .await
                    .unwrap()
                    .expect("the quarantined marker row exists");
                out.push((rec.id, OWNER.to_string(), rec.created_at.to_rfc3339()));
                continue;
            }
            state
                .db
                .create_repo(&crate::db::RepoRecord {
                    id: id.clone(),
                    name: id.clone(),
                    owner_did: OWNER.to_string(),
                    description: None,
                    is_public: false,
                    default_branch: "main".to_string(),
                    created_at: at,
                    updated_at: at,
                    disk_path: format!("/nonexistent/{id}"),
                    forked_from: None,
                    machine_id: None,
                })
                .await
                .expect("seed a private marker row");
            out.push((id, OWNER.to_string(), at.to_rfc3339()));
        }
        out
    }

    /// Scenario 9, the INV-13 guard: the emitted continuation leaks no withheld field.
    ///
    /// A denial-only scan fetches nothing BUT withheld rows, so the row its token seals
    /// is by construction a private or quarantined repo the caller may not read. Its
    /// `created_at` leaks a hidden repo's creation time and its `id` carries the owner's
    /// DID. Base64 is transport, not confidentiality (this is the exact shape #134
    /// shipped and INV-13 records), so the token must be AEAD-SEALED.
    ///
    /// The fixture is arranged so the row at the truncation boundary (the row the token
    /// seals) IS one of the poisoned withheld repos. Stated because it is load-bearing:
    /// a future edit seeding a READABLE repo at the boundary would leave mutation E
    /// green and this guard would silently stop proving anything.
    ///
    /// The last assertion is the one the substring checks structurally cannot make.
    /// AEAD ciphertext is plaintext-length plus the tag, and both halves of a scan
    /// position vary in length, so without fixed-width padding the token LENGTH is a
    /// side channel for the sealed row.
    ///
    /// MUTATION E (RED): seal by base64-of-plaintext and the markers decode straight out.
    /// MUTATION G (RED): drop the fixed-width padding and the two lengths diverge.
    ///
    /// Like the two token guards below it, this has no pre-fix RED: its assertions call
    /// `seal_scan_token` / `open_scan_token`, which do not exist on the pre-fix head, so
    /// the only failure available there is a compile error. Mutations E and G are its
    /// REDs, and each injects precisely the encoding INV-13 forbids rather than merely
    /// removing the code, which is the stronger observation.
    #[sqlx::test]
    async fn scan_token_leaks_no_withheld_fields(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 2;
        let markers = seed_marked_withheld_repos(&state, 6).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let key = state.ipfs_scan_token_key.clone();

        let peer: SocketAddr = "203.0.113.150:5000".parse().unwrap();
        let resp = ipfs_router(state)
            .oneshot(get_cid_scan(&cid, Some(peer), None))
            .await
            .unwrap();
        let raw_body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        let body_text = String::from_utf8_lossy(&raw_body).to_string();
        let body: serde_json::Value = serde_json::from_slice(&raw_body).expect("json body");
        let token = continuation_of(&body).expect("the truncation must emit a token");

        // Fixture precondition, on the FIXTURE rather than on the token: every seeded
        // row is withheld (private or quarantined) and the scan stopped after exactly
        // one ceiling's worth, so the row the token seals is a withheld row. Stated
        // without opening the token so the leak assertions below are what fires when the
        // seal is replaced by an encoding, rather than a precondition panic.
        assert_eq!(
            crate::api::ipfs::scan_rows(),
            2,
            "the truncation boundary must sit inside the seeded withheld window"
        );

        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            token.as_bytes(),
        )
        .expect("the token is base64url");
        let decoded_text = String::from_utf8_lossy(&decoded).to_string();

        for (id, owner, created) in &markers {
            for (what, marker) in [
                ("repo id", id),
                ("owner did", owner),
                ("created_at", created),
            ] {
                assert!(
                    !body_text.contains(marker.as_str()),
                    "the response body must not carry a withheld repo's {what} ({marker}): \
                     {body_text}"
                );
                assert!(
                    !decoded_text.contains(marker.as_str()),
                    "the token's DECODED bytes must not carry a withheld repo's {what} \
                     ({marker}); base64 is transport, not confidentiality (INV-13)"
                );
                assert!(
                    decoded
                        .windows(marker.len())
                        .all(|w| w != marker.as_bytes()),
                    "the token's raw bytes must not carry a withheld repo's {what} ({marker})"
                );
            }
        }

        // And the row it actually seals IS one of the poisoned withheld rows, checked
        // after the leak assertions so a broken seal is reported as a leak, not as a
        // fixture failure. Load-bearing: seeding a READABLE repo at the boundary would
        // leave mutation E green and this whole guard would stop proving anything.
        let sealed = gitlawb_core::scan_token::open_scan_token(
            &key,
            &cid,
            &token,
            chrono::Utc::now().timestamp(),
        )
        .expect("the node's own key opens its own token");
        assert!(
            markers
                .iter()
                .any(|(id, _, created)| *id == sealed.id && *created == sealed.created_at_key),
            "the row at the truncation boundary must be one of the poisoned withheld \
             repos; sealed {sealed:?}"
        );

        // A different key must not open it: the seal, not an encoding, is what withholds.
        let other = gitlawb_core::scan_token::new_key();
        assert!(
            gitlawb_core::scan_token::open_scan_token(
                &other,
                &cid,
                &token,
                chrono::Utc::now().timestamp()
            )
            .is_none(),
            "a token that opens under any key but the node's own is not sealed"
        );

        // Token LENGTH must not vary with the sealed row.
        let now = chrono::Utc::now().timestamp();
        let short = gitlawb_core::scan_token::seal_scan_token(
            &key,
            &cid,
            &gitlawb_core::scan_token::ScanPosition {
                created_at_key: "2020-01-01T00:00:00+00:00".into(),
                id: "a/b".into(),
                sha256_hex: absent_oid(),
            },
            now + 60,
        )
        .unwrap();
        let long = gitlawb_core::scan_token::seal_scan_token(
            &key,
            &cid,
            &gitlawb_core::scan_token::ScanPosition {
                created_at_key: "2020-01-01T00:00:00+00:00".into(),
                id: format!("did:key:z6MkAVeryLongOwnerKeyIdentifier/{}", "n".repeat(48)),
                sha256_hex: absent_oid(),
            },
            now + 60,
        )
        .unwrap();
        assert_eq!(
            short.len(),
            long.len(),
            "tokens sealing rows of very different id lengths must be byte-identical in \
             length, or the length is a side channel for the withheld row, which the \
             substring assertions above structurally cannot see"
        );
    }

    /// Scenario 10: tampered, foreign-CID, and expired tokens are ABSENT, uniformly.
    ///
    /// Each of the three failure classes must produce exactly the front-started response
    /// a tokenless request gets: same status, same body shape, and (the decisive part)
    /// an emitted continuation sealing the FRONT window's last row, not the row the
    /// rejected token named. Never an error, never a resumed position, and no way to
    /// tell the three classes apart.
    ///
    /// The "front-started" half is asserted by opening the EMITTED token and checking
    /// which row it seals, which looks over-elaborate until you try the obvious thing.
    /// `scan_rows()` cannot separate the two states: a front start reads rows 1-2 and a
    /// resume from the rejected position reads rows 3-4, so the counter says 2 either
    /// way. The sealed position is the only thing that differs, and without checking it
    /// the foreign-CID leg passes under mutation F.
    ///
    /// No pre-fix RED, for the same reason as the guard above: the probes are minted
    /// with `seal_scan_token`, which does not exist pre-fix. Mutation F is its RED.
    ///
    /// MUTATION F (RED): drop the CID from the associated data and the foreign-CID leg's
    /// token is honoured, so the scan resumes at the foreign position.
    #[sqlx::test]
    async fn scan_token_invalid_variants_start_at_front(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 2;
        seed_root_denying_repos(&state, "front", 6, 0).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;
        let key = state.ipfs_scan_token_key.clone();
        let now = chrono::Utc::now().timestamp();

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.151:5000".parse().unwrap();

        // Baseline: a tokenless request reads the front window and seals row 2.
        let (base_status, base_body) = status_and_body(
            router
                .clone()
                .oneshot(get_cid_scan(&cid, Some(peer), None))
                .await
                .unwrap(),
        )
        .await;
        let base_token = continuation_of(&base_body).expect("baseline emits a token");
        let front = gitlawb_core::scan_token::open_scan_token(&key, &cid, &base_token, now)
            .expect("baseline token opens");
        assert_eq!(
            front.id, "front-0001",
            "fixture precondition: the front window ends at the second seeded row"
        );

        // Probe 1: a byte-flipped token.
        let mut bytes: Vec<u8> = base_token.bytes().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();

        // Probe 2: a well-formed token minted for a DIFFERENT CID, at a position deep
        // in the table so honouring it would be unmistakable.
        let elsewhere = cid_for_oid(&"f4".repeat(32));
        let foreign = gitlawb_core::scan_token::seal_scan_token(
            &key,
            &elsewhere,
            &gitlawb_core::scan_token::ScanPosition {
                created_at_key: scan_order_stamp(3).to_rfc3339(),
                id: "front-0003".into(),
                sha256_hex: absent_oid(),
            },
            now + 3600,
        )
        .unwrap();

        // Probe 3: a token for this CID whose expiry is already past.
        let expired = gitlawb_core::scan_token::seal_scan_token(
            &key,
            &cid,
            &gitlawb_core::scan_token::ScanPosition {
                created_at_key: scan_order_stamp(3).to_rfc3339(),
                id: "front-0003".into(),
                sha256_hex: absent_oid(),
            },
            now - 1,
        )
        .unwrap();

        for (what, probe) in [
            ("tampered", tampered),
            ("foreign-CID", foreign),
            ("expired", expired),
        ] {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), Some(&probe)))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                status, base_status,
                "a {what} token must answer exactly as a tokenless request does, never \
                 an error and never a distinguishable status: {body}"
            );
            assert_eq!(
                body["error"], base_body["error"],
                "a {what} token must not change the body shape: {body}"
            );
            assert_eq!(
                body["message"], base_body["message"],
                "a {what} token must not change the message: {body}"
            );
            let token = continuation_of(&body)
                .unwrap_or_else(|| panic!("the {what} probe answers like a front start: {body}"));
            let pos = gitlawb_core::scan_token::open_scan_token(&key, &cid, &token, now)
                .expect("the emitted token opens");
            assert_eq!(
                pos.id, front.id,
                "a {what} token must be treated as ABSENT and the scan must start at the \
                 FRONT; resuming from it would honour a position the caller was never \
                 handed for this CID"
            );
        }
    }

    /// Scenario 11: every seal draws a FRESH nonce.
    ///
    /// This is the property the whole confidentiality claim rests on and the one the
    /// other two token guards cannot see: both of them pass unchanged under a constant
    /// nonce. Under a stream cipher a repeated nonce repeats the keystream, so two
    /// tokens sealed under one nonce XOR to the difference of their plaintexts, and an
    /// attacker who can force the node to seal a position they know then recovers a
    /// withheld row's fields in full. That is strictly worse than the base64 defect
    /// INV-13 records.
    ///
    /// No pre-fix RED, like the two guards above: it seals through an API that does not
    /// exist on the pre-fix head. Mutation H is its RED, and H reddens nothing else,
    /// which is the same fact stated from the other side.
    ///
    /// MUTATION H (RED): fix the nonce to a constant and the two tokens are identical.
    #[test]
    fn scan_token_seals_are_nonce_fresh() {
        let key = gitlawb_core::scan_token::new_key();
        let pos = gitlawb_core::scan_token::ScanPosition {
            created_at_key: "2020-01-01T00:00:07+00:00".into(),
            id: "did:key:z6MkHiddenOwner/withheld-repo".into(),
            sha256_hex: "f2".repeat(32),
        };
        let expires = chrono::Utc::now().timestamp() + 3600;
        let first =
            gitlawb_core::scan_token::seal_scan_token(&key, "bafkcid", &pos, expires).unwrap();
        let second =
            gitlawb_core::scan_token::seal_scan_token(&key, "bafkcid", &pos, expires).unwrap();

        assert_ne!(
            first, second,
            "sealing the same position twice must produce different bytes; identical \
             tokens mean a reused nonce, and a reused nonce under a stream cipher leaks \
             the withheld plaintext to anyone holding two tokens"
        );
        let now = chrono::Utc::now().timestamp();
        for token in [&first, &second] {
            let opened = gitlawb_core::scan_token::open_scan_token(&key, "bafkcid", token, now)
                .expect("both tokens must still open");
            assert_eq!(
                opened, pos,
                "nonce freshness must not cost correctness: both seals open to the same \
                 position"
            );
        }
    }

    /// Scenario 12: the degenerate ZERO-ROW resume never 404s.
    ///
    /// A row count that is an EXACT multiple of the ceiling is the shape whose last
    /// emitted token points AT the final row, so the next resume fetches an empty page.
    /// The wrap taint is evaluated on `pager.exhausted`, not at any particular break
    /// site, so this is covered by construction: an implementation that keys the taint
    /// on having fetched a page passes every other scenario here and converts an
    /// incomplete search into a false 404 exactly here.
    #[sqlx::test]
    async fn scan_token_at_table_end_wraps_not_404(pool: sqlx::PgPool) {
        let mut state = crate::test_support::test_state(pool).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.ipfs_legacy_scan_page_rows = 2;
        state.ipfs_max_legacy_scan_rows = 2;
        // 4 rows at ceiling 2: the second rung's token points at the last row.
        seed_root_denying_repos(&state, "endstop", 4, 0).await;
        let cid = seed_legacy_pin(&state, &absent_oid()).await;

        let router = ipfs_router(state);
        let peer: SocketAddr = "203.0.113.149:5000".parse().unwrap();

        let mut token: Option<String> = None;
        let mut last = None;
        for step in 1..=4 {
            let (status, body) = status_and_body(
                router
                    .clone()
                    .oneshot(get_cid_scan(&cid, Some(peer), token.as_deref()))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "no rung of this ladder may 404, least of all the zero-row one \
                 (step {step}): {body}"
            );
            match continuation_of(&body) {
                Some(next) => token = Some(next),
                None => {
                    last = Some(body);
                    break;
                }
            }
        }
        let last = last.expect("the ladder must terminate at the table end");
        assert_eq!(last["error"], "search_incomplete", "{last}");
        assert!(
            last["message"]
                .as_str()
                .unwrap_or_default()
                .contains("scan-wrapped"),
            "a resume landing on or past the last row fetches an empty page, which sets \
             `exhausted` and must taint scan-wrapped: {last}"
        );
        assert!(
            continuation_of(&last).is_none(),
            "a wrapped scan emits no token: {last}"
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

    /// F4 (#174 round 13): the pre-walk resolve carries its OWN short budget. The
    /// clamp above proves `oids_for_cid` cannot run unbounded, but its deadline is the
    /// 600s request budget, and a CID with no `pinned_cids` row does zero probe and
    /// zero walk work. Under a stalled pool such a request held the scarce walk slot
    /// for that whole window while nothing walked, so requests from enough distinct
    /// source keys capacity-503'd every real `/ipfs` retrieval at admission.
    ///
    /// The request budget is left at its 600s DEFAULT here on purpose: that is the
    /// whole point of the scenario, since the short resolve budget, not the long
    /// request budget, is what must end this request.
    ///
    /// Load-bearing: without the resolve clamp the stalled lookup runs to the 600s
    /// request budget and blows past the 10s wrap (RED). MUTATION (RED): revert the
    /// clamp to `remaining()` only, the pre-fix shape.
    #[sqlx::test]
    async fn get_by_cid_stalled_resolve_frees_walk_permit_within_resolve_budget(
        pool: sqlx::PgPool,
    ) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        // Global walk pool of 1 so the held/freed permit is directly observable;
        // per-source cap permissive so only the global pool matters.
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);
        let mut cfg = (*state.config).clone();
        cfg.ipfs_resolve_budget_secs = 1;
        assert_eq!(
            cfg.ipfs_request_budget_secs, 600,
            "the request budget stays at its default: this scenario proves the SHORT \
             budget is what sheds"
        );
        state.config = Arc::new(cfg);

        let sem = state.git_ipfs_walk_semaphore.clone();
        // A well-formed CID with no `pinned_cids` row: an anonymous caller's request
        // that will do no admitted work at all once the lookup answers.
        let cid = cid_for_oid(&absent_oid());
        let router = ipfs_router(state);

        let mut lock_conn = pool.acquire().await.unwrap();
        sqlx::raw_sql("BEGIN; LOCK TABLE pinned_cids IN ACCESS EXCLUSIVE MODE;")
            .execute(&mut *lock_conn)
            .await
            .unwrap();

        let peer: SocketAddr = "203.0.113.85:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            router.clone().oneshot(get_cid(&cid, Some(peer))),
        )
        .await
        .expect(
            "the resolve clamp must return within the SHORT budget; on the request budget \
             alone the stalled lookup holds for 600s",
        )
        .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a resolve blocked past the resolve budget must shed a retryable 503"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the clamp must end the request at ~the resolve budget (1s); got {elapsed:?} \
             (on the request budget alone it runs for 600s)"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        // INV-24: the knob an operator can turn must be the one the shed names. The two
        // budgets are separately settable, so a body naming the request budget here
        // would point at a knob that did nothing.
        assert!(
            body.contains("resolve budget"),
            "the shed must name the RESOLVE budget so it maps to \
             GITLAWB_IPFS_RESOLVE_BUDGET_SECS; got: {body}"
        );
        assert!(
            !body.contains("request budget"),
            "the resolve shed must not name the request budget, which is untouched at \
             600s here and would send an operator to the wrong knob; got: {body}"
        );
        assert_eq!(
            sem.available_permits(),
            1,
            "the walk permit must be freed on the resolve-budget shed path, not held \
             for the stall"
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

    /// F4 must-not (#174 round 13): the short resolve budget bounds the RESOLVE and
    /// nothing else. A request whose resolve answers promptly and then spends real time
    /// in an admitted visibility walk is PROGRESSING, and shedding it would convert a
    /// slow-but-correct retrieval into a 503 on a box that is merely loaded.
    ///
    /// The resolve budget is 1s while the walk sleeps ~2s per `rev-list`, so any
    /// deadline that reaches past `oids_for_cid` ends this request before it can serve.
    /// The shim execs the REAL git after sleeping, so the allowed-set the walk produces
    /// is the repo's genuine one and the 200 is a real serve, not an artifact.
    ///
    /// MUTATION (RED): anchor the region's `remaining()` on the resolve deadline (the
    /// plausible over-wide re-implementation: one short admission-anchored clock for
    /// the whole permit-held region) and this 200 becomes a budget 503.
    #[cfg(unix)]
    #[sqlx::test]
    async fn get_by_cid_slow_walk_not_shed_by_resolve_budget(pool: sqlx::PgPool) {
        let tmp = tempfile::TempDir::new().unwrap();
        let repos_dir = tmp.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state.repo_store = crate::git::repo_store::RepoStore::for_testing(repos_dir, pool);
        state.git_ipfs_walk_semaphore = Arc::new(Semaphore::new(1));
        state.git_ipfs_walk_per_caller = crate::rate_limit::PerCallerConcurrency::new(1000, 1000);

        let content = b"slow but progressing\n";
        let (repo_id, oid) =
            seed_repo_with_blob(&state, tmp.path(), "z6slowwalk", "holder", content).await;
        // Path-scoped, so serving costs a real reachability walk: the rule withholds a
        // path the seeded blob is NOT under (it lives at `src/secret.txt`), so anon is
        // allowed and the request must reach a 200 the slow way.
        state
            .db
            .set_visibility_rule(
                &repo_id,
                "withheld/**",
                crate::db::VisibilityMode::B,
                &["did:key:z6MkU3IpfsReaderDDDDDDDDDDDDDDDDDDDDDDDD".to_string()],
                "z6slowwalk",
            )
            .await
            .unwrap();
        let cid = seed_legacy_pin_for_oid(&state, &oid).await;

        // Sleep only on the reachability walk, then exec the real git, so the delay
        // lands inside the admitted region and after the resolve has already answered.
        let shim = tmp.path().join("slowwalkgit");
        std::fs::write(
            &shim,
            "#!/bin/sh\n\
             case \"$1\" in\n\
               rev-list) sleep 2 ;;\n\
             esac\n\
             exec git \"$@\"\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&shim).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&shim, perm).unwrap();
        }
        state.git_bin = shim.to_str().unwrap().to_string();

        let mut cfg = (*state.config).clone();
        cfg.ipfs_resolve_budget_secs = 1;
        state.config = Arc::new(cfg);

        let peer: SocketAddr = "203.0.113.86:5000".parse().unwrap();
        let started = std::time::Instant::now();
        let resp = ipfs_router(state)
            .oneshot(get_cid(&cid, Some(peer)))
            .await
            .unwrap();
        let elapsed = started.elapsed();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "a walk that outlives the SHORT resolve budget must still serve: the resolve \
             budget bounds the pre-walk lookup, never admitted walk work. Got: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            &body[..],
            content.as_slice(),
            "the served bytes must be the seeded object's"
        );
        // Anti-vacuity: without a walk that genuinely outlives the 1s resolve budget,
        // the 200 above would prove nothing about the boundary.
        assert!(
            elapsed >= std::time::Duration::from_secs(2),
            "the request must actually have spent longer than the 1s resolve budget in \
             the walk; got {elapsed:?}, so the shim's sleep never ran"
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
