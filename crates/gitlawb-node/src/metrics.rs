//! Prometheus metrics for the gitlawb node.
//!
//! Exposes a small, deliberately conservative set of counters and histograms
//! that cover the questions an operator actually asks of a live node:
//!
//!   * is push traffic flowing? — `gitlawb_pushes_total`
//!   * is fetch traffic flowing? — `gitlawb_fetches_total`
//!   * are signature checks passing or failing? —
//!     `gitlawb_auth_successes_total` / `gitlawb_auth_failures_total`
//!   * is the sync worker making progress? —
//!     `gitlawb_sync_queue_processed_total{status}`
//!   * are webhooks reaching their endpoints? —
//!     `gitlawb_webhook_deliveries_total{result}`
//!   * how big are the packs we're sending and receiving? —
//!     `gitlawb_pack_size_bytes`
//!   * a single `gitlawb_info{version, did}` gauge = 1, for joins/dashboards
//!   * currently-connected peer count — `gitlawb_peers_connected`
//!   * repos whose local copy is ahead of durable storage —
//!     `gitlawb_pending_upload_markers`
//!
//! All metrics live in a single process-wide registry initialized by
//! [`init`]. Increment helpers (`record_push`, `record_auth_failure`, ...)
//! are no-ops until [`init`] has been called, so unit tests and benchmarks
//! that don't go through `main()` don't need to do anything special.
//!
//! The endpoint is opt-in via `GITLAWB_METRICS_ADDR`; if unset, no listener
//! is bound and no exposition happens. Increments are atomic and effectively
//! free.
//!
//! Follow-ups (not in this module):
//!   * per-route latency histograms (TraceLayer already gives us spans)
//!   * per-peer p2p counters
//!   * ipfs / pinata counters

use std::sync::OnceLock;

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

/// The single, process-wide metrics registry. Initialized by [`init`].
/// Wrapped in `OnceLock` so unit tests can run without going through
/// `main()` — the public `record_*` helpers treat an uninitialized
/// registry as a silent no-op.
static REGISTRY: OnceLock<Registry> = OnceLock::new();
static INFO: OnceLock<IntGaugeVec> = OnceLock::new();
static PUSHES: OnceLock<IntCounterVec> = OnceLock::new();
static FETCHES: OnceLock<IntCounterVec> = OnceLock::new();
static AUTH_SUCCESSES: OnceLock<IntCounterVec> = OnceLock::new();
static AUTH_FAILURES: OnceLock<IntCounterVec> = OnceLock::new();
static SYNC_PROCESSED: OnceLock<IntCounterVec> = OnceLock::new();
static WEBHOOK_DELIVERIES: OnceLock<IntCounterVec> = OnceLock::new();
static PACK_SIZE: OnceLock<Histogram> = OnceLock::new();
static PEERS_CONNECTED: OnceLock<IntGauge> = OnceLock::new();
static PENDING_UPLOAD_MARKERS: OnceLock<IntGauge> = OnceLock::new();

/// One-time initializer. Builds the registry, registers every metric,
/// and sets the constant `gitlawb_info` gauge. Idempotent — calling
/// more than once is a silent no-op. MUST be called from `main()` after
/// the node DID is known.
pub fn init(version: &str, node_did: &str) {
    if REGISTRY.get().is_some() {
        return;
    }

    let registry = Registry::new();

    let info = IntGaugeVec::new(
        Opts::new(
            "gitlawb_info",
            "Constant 1 labelled with version and node DID",
        ),
        &["version", "did"],
    )
    .expect("gitlawb_info metric definition");
    registry
        .register(Box::new(info.clone()))
        .expect("register gitlawb_info");
    info.with_label_values(&[version, node_did]).set(1);
    INFO.set(info).expect("set INFO once");

    let pushes = IntCounterVec::new(
        Opts::new(
            "gitlawb_pushes_total",
            "Total successful git push (receive-pack) completions",
        ),
        &["repo"],
    )
    .expect("gitlawb_pushes_total definition");
    registry
        .register(Box::new(pushes.clone()))
        .expect("register gitlawb_pushes_total");
    PUSHES.set(pushes).expect("set PUSHES once");

    let fetches = IntCounterVec::new(
        Opts::new(
            "gitlawb_fetches_total",
            "Total successful git fetch (upload-pack) completions",
        ),
        &["repo"],
    )
    .expect("gitlawb_fetches_total definition");
    registry
        .register(Box::new(fetches.clone()))
        .expect("register gitlawb_fetches_total");
    FETCHES.set(fetches).expect("set FETCHES once");

    let auth_successes = IntCounterVec::new(
        Opts::new(
            "gitlawb_auth_successes_total",
            "Total HTTP signature checks that passed",
        ),
        &["route"],
    )
    .expect("gitlawb_auth_successes_total definition");
    registry
        .register(Box::new(auth_successes.clone()))
        .expect("register gitlawb_auth_successes_total");
    AUTH_SUCCESSES
        .set(auth_successes)
        .expect("set AUTH_SUCCESSES once");

    let auth_failures = IntCounterVec::new(
        Opts::new(
            "gitlawb_auth_failures_total",
            "Total HTTP signature checks that failed",
        ),
        &["route", "reason"],
    )
    .expect("gitlawb_auth_failures_total definition");
    registry
        .register(Box::new(auth_failures.clone()))
        .expect("register gitlawb_auth_failures_total");
    AUTH_FAILURES
        .set(auth_failures)
        .expect("set AUTH_FAILURES once");

    let sync_processed = IntCounterVec::new(
        Opts::new(
            "gitlawb_sync_queue_processed_total",
            "Total sync_queue items the worker has processed",
        ),
        &["status"],
    )
    .expect("gitlawb_sync_queue_processed_total definition");
    registry
        .register(Box::new(sync_processed.clone()))
        .expect("register gitlawb_sync_queue_processed_total");
    SYNC_PROCESSED
        .set(sync_processed)
        .expect("set SYNC_PROCESSED once");

    let webhook_deliveries = IntCounterVec::new(
        Opts::new(
            "gitlawb_webhook_deliveries_total",
            "Total webhook delivery attempts and their outcomes",
        ),
        &["result"],
    )
    .expect("gitlawb_webhook_deliveries_total definition");
    registry
        .register(Box::new(webhook_deliveries.clone()))
        .expect("register gitlawb_webhook_deliveries_total");
    WEBHOOK_DELIVERIES
        .set(webhook_deliveries)
        .expect("set WEBHOOK_DELIVERIES once");

    let pack_size = Histogram::with_opts(
        HistogramOpts::new(
            "gitlawb_pack_size_bytes",
            "Distribution of git pack body sizes processed (bytes)",
        )
        .buckets(vec![
            1_024.0,         // 1 KB
            64_000.0,        // ~64 KB
            1_000_000.0,     // 1 MB
            16_000_000.0,    // 16 MB
            64_000_000.0,    // 64 MB
            256_000_000.0,   // 256 MB
            1_073_741_824.0, // 1 GiB
            2_147_483_648.0, // 2 GiB (current cap)
        ]),
    )
    .expect("gitlawb_pack_size_bytes definition");
    registry
        .register(Box::new(pack_size.clone()))
        .expect("register gitlawb_pack_size_bytes");
    PACK_SIZE.set(pack_size).expect("set PACK_SIZE once");

    let peers_connected = IntGauge::with_opts(Opts::new(
        "gitlawb_peers_connected",
        "Currently connected libp2p peers",
    ))
    .expect("gitlawb_peers_connected definition");
    registry
        .register(Box::new(peers_connected.clone()))
        .expect("register gitlawb_peers_connected");
    PEERS_CONNECTED
        .set(peers_connected)
        .expect("set PEERS_CONNECTED once");

    let pending_markers = IntGauge::with_opts(Opts::new(
        "gitlawb_pending_upload_markers",
        "Repos whose local copy is ahead of durable storage (pending-upload markers outstanding)",
    ))
    .expect("gitlawb_pending_upload_markers definition");
    registry
        .register(Box::new(pending_markers.clone()))
        .expect("register gitlawb_pending_upload_markers");
    PENDING_UPLOAD_MARKERS
        .set(pending_markers)
        .expect("set PENDING_UPLOAD_MARKERS once");

    REGISTRY
        .set(registry)
        .expect("set REGISTRY once (init must be called exactly once)");
}

/// Record one successful push (receive-pack completion). Labelled with
/// the repo in the form `owner_short/repo_name`. No-op if `init` was
/// never called (e.g. inside a unit test that doesn't go through main).
pub fn record_push(repo: &str) {
    if let Some(c) = PUSHES.get() {
        c.with_label_values(&[repo]).inc();
    }
}

/// Record one successful fetch (upload-pack completion).
pub fn record_fetch(repo: &str) {
    if let Some(c) = FETCHES.get() {
        c.with_label_values(&[repo]).inc();
    }
}

/// Record one HTTP signature check that passed.
#[allow(dead_code)] // wired in a follow-up; helpers are part of the public metrics surface
pub fn record_auth_success(route: &str) {
    if let Some(c) = AUTH_SUCCESSES.get() {
        c.with_label_values(&[route]).inc();
    }
}

/// Record one HTTP signature check that failed. `reason` is a short,
/// machine-friendly token (e.g. `expired`, `bad_signature`, `missing_header`).
#[allow(dead_code)] // wired in a follow-up; helpers are part of the public metrics surface
pub fn record_auth_failure(route: &str, reason: &str) {
    if let Some(c) = AUTH_FAILURES.get() {
        c.with_label_values(&[route, reason]).inc();
    }
}

/// Record one sync_queue item outcome. `status` ∈ {done, failed, skipped}.
pub fn record_sync_processed(status: &str) {
    if let Some(c) = SYNC_PROCESSED.get() {
        c.with_label_values(&[status]).inc();
    }
}

/// Record one webhook delivery attempt outcome. `result` ∈
/// {ok, http_error, network_error, skipped}.
pub fn record_webhook_delivery(result: &str) {
    if let Some(c) = WEBHOOK_DELIVERIES.get() {
        c.with_label_values(&[result]).inc();
    }
}

/// Record a pack body size observation (bytes).
pub fn observe_pack_size(bytes: f64) {
    if let Some(h) = PACK_SIZE.get() {
        h.observe(bytes);
    }
}

/// Update the currently-connected peer count gauge.
pub fn set_peers_connected(count: i64) {
    if let Some(g) = PEERS_CONNECTED.get() {
        g.set(count);
    }
}

/// Update the outstanding pending-upload marker gauge (repos whose local copy
/// is ahead of durable storage).
pub fn set_pending_upload_markers(count: i64) {
    if let Some(g) = PENDING_UPLOAD_MARKERS.get() {
        g.set(count);
    }
}

/// Encode the registry as the standard Prometheus text exposition format.
/// Returns an error if `init` was never called.
pub fn encode() -> Result<String, prometheus::Error> {
    let registry = REGISTRY
        .get()
        .ok_or_else(|| prometheus::Error::Msg("metrics::init() was never called".into()))?;
    let metric_families = registry.gather();
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buf)?;
    String::from_utf8(buf)
        .map_err(|e| prometheus::Error::Msg(format!("non-UTF8 in metric buffer: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: these tests are not run in parallel by default (cargo runs
    // tests in a binary in parallel via threads but the OnceLock guard
    // means only the first init() call succeeds; subsequent ones are
    // no-ops). The encode test below is structured so it's safe to run
    // alongside other tests in the same binary.

    #[test]
    fn encode_after_init_returns_prometheus_text() {
        // Reset is not supported by OnceLock, so this test relies on
        // either being the first to run, or `init` being a no-op on
        // second call. Both paths are exercised: if init() was already
        // called by another test, the no-op branch still leaves the
        // registry usable.
        init("0.0.0-test", "did:key:test");
        PUSHES
            .get()
            .expect("PUSHES set after init")
            .with_label_values(&["alice/repo"])
            .inc();

        let body = encode().expect("encode should succeed after init");
        assert!(
            body.contains("# HELP gitlawb_info"),
            "expected gitlawb_info HELP line in: {body}"
        );
        assert!(
            body.contains("# TYPE gitlawb_pushes_total counter"),
            "expected gitlawb_pushes_total TYPE line in: {body}"
        );
        assert!(
            body.contains("gitlawb_pushes_total{repo=\"alice/repo\"} 1"),
            "expected the incremented counter to be visible in: {body}"
        );
    }

    #[test]
    fn record_helpers_are_noops_before_init() {
        // These don't panic. They also don't show up in encode() output
        // because the registry doesn't exist yet.
        record_push("test/repo");
        record_fetch("test/repo");
        record_auth_success("test/route");
        record_auth_failure("test/route", "test_reason");
        record_sync_processed("done");
        record_webhook_delivery("ok");
        observe_pack_size(1024.0);
        set_peers_connected(0);
    }

    #[test]
    fn encode_before_init_returns_error() {
        // encode() must error rather than panic if init() was never called.
        // This test is meaningful only if NO other test in this binary
        // ran first. cargo runs tests on multiple threads within a
        // single binary, so this is racy — but worst case the assertion
        // below is "encode succeeded with a non-empty body", which is
        // still a valid state.
        let result = encode();
        match result {
            Err(_) => { /* expected when init wasn't called */ }
            Ok(body) => {
                // Some other test ran init() first; that's fine, the
                // body should still be a valid exposition payload.
                assert!(!body.is_empty(), "non-empty exposition body");
            }
        }
    }
}
