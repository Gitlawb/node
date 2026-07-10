use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Mutex;

use crate::auth::AuthenticatedDid;

/// Default ceiling on the number of distinct keys a limiter tracks. Bounds the
/// limiter's own memory so a caller that can vary the key (many DIDs, or a
/// spoofable IP header) cannot grow the map without limit.
const DEFAULT_MAX_KEYS: usize = 100_000;

#[derive(Clone)]
struct Window {
    timestamps: Vec<Instant>,
}

#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<Mutex<HashMap<String, Window>>>,
    max_requests: usize,
    window: Duration,
    /// Hard cap on tracked keys. When full, expired keys are evicted (at most
    /// once per [`sweep_interval`](Self::sweep_interval), see below); if still
    /// full, a request under a *new* key is rejected rather than inserted — so
    /// the map can never exceed this bound and a rejected request never
    /// allocates a new entry.
    max_keys: usize,
    /// Timestamp of the last inline capacity sweep. The eviction scan is
    /// O(max_keys), so under a distinct-key flood (when the map sits at the
    /// cap) running it on every miss would serialize all traffic behind a full
    /// scan. Gating it to at most once per interval amortizes that cost; the
    /// background [`cleanup`](Self::cleanup) loop still reclaims on its own.
    last_sweep: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    // Retained for tests and callers that don't need a tight key bound;
    // production limiters use `new_bounded`.
    #[allow(dead_code)]
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self::new_bounded(max_requests, window, DEFAULT_MAX_KEYS)
    }

    /// Like [`new`] but with an explicit cap on the number of distinct keys.
    /// Production limiters keyed on client-influenced values (per-DID, per-IP)
    /// set this so the limiter's own state cannot be turned into a
    /// memory-exhaustion vector.
    pub fn new_bounded(max_requests: usize, window: Duration, max_keys: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
            max_keys: max_keys.max(1),
            last_sweep: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// How often the inline capacity sweep may run: at most once per second, or
    /// once per window when the window is shorter. Bounds post-flood staleness
    /// (a full map self-heals within one interval) without paying the O(max_keys)
    /// scan on every capacity miss.
    fn sweep_interval(&self) -> Duration {
        self.window.min(Duration::from_secs(1))
    }

    pub(crate) async fn check(&self, key: &str) -> bool {
        // max_requests == 0 means the limiter is disabled, not "block all".
        if self.max_requests == 0 {
            return true;
        }
        let now = Instant::now();
        let mut state = self.state.lock().await;

        // Fast path: an already-tracked key never allocates and never grows the
        // map, so it is unaffected by the key cap.
        if let Some(window) = state.get_mut(key) {
            window
                .timestamps
                .retain(|t| now.duration_since(*t) < self.window);
            if window.timestamps.len() >= self.max_requests {
                return false;
            }
            window.timestamps.push(now);
            return true;
        }

        // New key. Enforce the cap BEFORE inserting so a flood of distinct keys
        // cannot grow the map, and a rejected request never allocates an entry.
        if state.len() >= self.max_keys {
            // Reclaim expired keys, but at most once per sweep interval — the
            // scan is O(max_keys) and the map sits at the cap precisely during a
            // distinct-key flood, so sweeping per miss would serialize traffic
            // behind a full scan. Between sweeps a new key is simply rejected.
            let mut last_sweep = self.last_sweep.lock().await;
            if now.duration_since(*last_sweep) >= self.sweep_interval() {
                state.retain(|_, w| {
                    w.timestamps
                        .retain(|t| now.duration_since(*t) < self.window);
                    !w.timestamps.is_empty()
                });
                *last_sweep = now;
            }
            drop(last_sweep);
            if state.len() >= self.max_keys {
                return false;
            }
        }
        state.insert(
            key.to_string(),
            Window {
                timestamps: vec![now],
            },
        );
        true
    }

    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut state = self.state.lock().await;
        state.retain(|_, w| {
            w.timestamps
                .retain(|t| now.duration_since(*t) < self.window);
            !w.timestamps.is_empty()
        });
    }
}

/// A bounded per-caller CONCURRENCY limiter — distinct from [`RateLimiter`], which
/// caps request RATE. Each caller key may hold at most `per_caller` in-flight
/// permits at once; beyond that [`try_acquire`](Self::try_acquire) returns `None`
/// and the caller sheds. Used to stop one caller (a single anonymous source-IP or
/// DID) monopolizing the served-git read pool (#174).
///
/// The key map is self-bounding: a key is removed the instant its in-flight count
/// reaches zero, so it never holds more keys than there are concurrently-active
/// callers (itself bounded by the read semaphore). A `max_keys` reject-before-insert
/// backstop guarantees a key farm can never grow the map even if that invariant
/// weakened — a NEW key at the cap is rejected WITHOUT allocating an entry (INV-15).
///
/// Uses a `std::sync::Mutex` (not the file's `tokio::sync::Mutex`) because the
/// permit's `Drop` must release synchronously; the critical section holds no await.
#[derive(Clone)]
pub struct PerCallerConcurrency {
    state: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    per_caller: usize,
    max_keys: usize,
}

/// RAII permit from [`PerCallerConcurrency::try_acquire`]. On drop it decrements
/// the caller's in-flight count and removes the key when it reaches zero.
pub struct PerCallerPermit {
    state: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    key: String,
}

impl PerCallerConcurrency {
    pub fn new(per_caller: usize, max_keys: usize) -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(HashMap::new())),
            per_caller: per_caller.max(1),
            max_keys: max_keys.max(1),
        }
    }

    /// Convenience constructor with the default key bound.
    pub fn with_default_max_keys(per_caller: usize) -> Self {
        Self::new(per_caller, DEFAULT_MAX_KEYS)
    }

    /// `Some(permit)` when the caller is under its cap and the map has room;
    /// `None` (shed) otherwise. Reject-before-insert: a new key at `max_keys` is
    /// rejected without allocating.
    pub fn try_acquire(&self, key: &str) -> Option<PerCallerPermit> {
        // Recover from a poisoned lock rather than panicking: the critical section
        // is pure counter arithmetic and cannot itself panic, so a poisoned mutex
        // would only ever come from an unrelated abort, and a slightly-off count
        // self-heals as permits drop. A panic here would instead brick the limiter
        // for every caller (each subsequent lock re-panics).
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match map.get_mut(key) {
            Some(count) => {
                if *count >= self.per_caller {
                    return None;
                }
                *count += 1;
            }
            None => {
                if map.len() >= self.max_keys {
                    return None;
                }
                map.insert(key.to_string(), 1);
            }
        }
        Some(PerCallerPermit {
            state: self.state.clone(),
            key: key.to_string(),
        })
    }

    #[cfg(test)]
    pub fn tracked_keys(&self) -> usize {
        self.state.lock().unwrap().len()
    }
}

impl Drop for PerCallerPermit {
    fn drop(&mut self) {
        let mut map = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.key);
            }
        }
    }
}

pub async fn rate_limit_by_did(request: Request, next: Next) -> Response {
    let limiter = request.extensions().get::<RateLimiter>().cloned();

    let did = request
        .extensions()
        .get::<AuthenticatedDid>()
        .map(|a| a.0.clone());

    if let (Some(limiter), Some(did)) = (limiter, did) {
        if !limiter.check(&did).await {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "60")],
                "rate limit exceeded — try again later",
            )
                .into_response();
        }
    }

    next.run(request).await
}

/// Which forwarded header (if any) the operator's edge is trusted to set. Only
/// a proxy the operator controls may be believed; a raw client can put any
/// value in `Fly-Client-IP` / `X-Forwarded-For`, so trusting them unconditionally
/// lets a flooder rotate the header and never fill a bucket. Configured via
/// `GITLAWB_TRUSTED_PROXY`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrustedProxy {
    /// No trusted proxy: ignore forwarded headers, key on the socket peer IP.
    /// Safe default for direct/self-hosted nodes.
    None,
    /// Behind Fly's edge, which sets (and overwrites any client-supplied)
    /// `Fly-Client-IP`.
    Fly,
    /// Behind a single reverse proxy (e.g. Caddy on the AWS image) that appends
    /// the real client as the rightmost `X-Forwarded-For` hop.
    XForwardedFor,
}

impl TrustedProxy {
    /// Parse `GITLAWB_TRUSTED_PROXY`. Unknown/empty → `None` (trust nothing).
    pub fn from_env_value(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "fly" | "fly-client-ip" => TrustedProxy::Fly,
            "xff" | "x-forwarded-for" | "caddy" => TrustedProxy::XForwardedFor,
            _ => TrustedProxy::None,
        }
    }
}

fn trimmed_nonempty(v: &str) -> Option<String> {
    let t = v.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Resolve the rate-limit key for a request. In a trusted-proxy mode the
/// operator's edge header is preferred; when that header is missing or empty we
/// fall back to the socket peer address rather than skipping the limiter (a
/// malformed header must never disable the brake). With no trusted proxy the
/// socket peer is always used and forwarded headers are ignored entirely.
/// Returns `None` only when neither a trusted header nor a peer address is
/// available (e.g. a synthetic test request with no `ConnectInfo`).
pub fn client_key(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trust: TrustedProxy,
) -> Option<String> {
    let from_header = match trust {
        TrustedProxy::None => None,
        TrustedProxy::Fly => headers
            .get("fly-client-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(trimmed_nonempty),
        // Rightmost hop = the value appended by the immediately-upstream trusted
        // proxy. The leftmost hop is client-controlled and must not be trusted.
        TrustedProxy::XForwardedFor => headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(trimmed_nonempty),
    };
    from_header.or_else(|| peer.map(|p| p.ip().to_string()))
}

/// Per-client-IP limiter for the git push path, carrying the trusted-proxy
/// policy. A newtype so it can live in request extensions (keyed by type)
/// alongside the per-DID [`RateLimiter`]. Per-DID limits are useless against a
/// push flood from a DID farm (one throwaway DID per repo), so the push path
/// throttles on the resolved client IP instead.
#[derive(Clone)]
pub struct IpRateLimiter {
    pub limiter: RateLimiter,
    pub trust: TrustedProxy,
}

/// Infallible extractor for the socket peer address from `ConnectInfo`. Yields
/// `None` when the server was started without connect-info (e.g. `oneshot` in
/// tests), so a handler never 500s on its absence — the limiter simply falls
/// back per [`client_key`].
pub struct PeerAddr(pub Option<SocketAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0),
        ))
    }
}

/// The shared 429 response for the per-IP flood brakes. Route-agnostic: this
/// middleware now serves the push path AND the peer-sync routes, so the message
/// stays generic (the offending path is recorded in the warn log below).
pub fn too_many_requests() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", "60")],
        "rate limit exceeded — try again later",
    )
        .into_response()
}

/// Throttle the git push path by resolved client IP. The socket peer address is
/// read from `ConnectInfo` (see `into_make_service_with_connect_info` in
/// `main`). Only skips the limiter when no key can be resolved at all.
pub async fn rate_limit_by_ip(request: Request, next: Next) -> Response {
    let limiter = request.extensions().get::<IpRateLimiter>().cloned();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);

    if let Some(limiter) = limiter {
        if let Some(key) = client_key(request.headers(), peer, limiter.trust) {
            if !limiter.limiter.check(&key).await {
                tracing::warn!(key = %key, path = %request.uri().path(), "per-IP rate limit exceeded");
                return too_many_requests();
            }
        }
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_caller_concurrency_caps_one_caller_and_frees_on_drop() {
        let lim = PerCallerConcurrency::new(2, 100);
        let p1 = lim.try_acquire("did:key:zA").expect("first under cap");
        let p2 = lim.try_acquire("did:key:zA").expect("second under cap");
        assert!(
            lim.try_acquire("did:key:zA").is_none(),
            "a third in-flight op for the same caller sheds (over the per-caller cap)"
        );
        // A DIFFERENT caller is unaffected — the cap is per-caller, not global.
        let _other = lim
            .try_acquire("did:key:zB")
            .expect("a different caller has its own budget");
        drop(p1);
        assert!(
            lim.try_acquire("did:key:zA").is_some(),
            "freeing one in-flight slot lets the same caller back in"
        );
        drop(p2);
    }

    #[test]
    fn per_caller_concurrency_map_is_self_bounding_and_reject_before_insert() {
        // Self-bounding: acquire+drop many distinct keys — the map never grows
        // because a key is removed the instant its in-flight count hits zero.
        let lim = PerCallerConcurrency::new(4, 3);
        for i in 0..50 {
            let _p = lim.try_acquire(&format!("k{i}"));
        }
        assert_eq!(
            lim.tracked_keys(),
            0,
            "keys with zero in-flight ops are removed, so an acquire+drop flood leaves the map empty"
        );
        // Reject-before-insert: HOLD max_keys distinct keys, then a new key sheds
        // WITHOUT growing the map past the cap (INV-15 — a rejected request never
        // allocates an entry).
        let held: Vec<_> = (0..3)
            .map(|i| lim.try_acquire(&format!("h{i}")).unwrap())
            .collect();
        assert_eq!(
            lim.tracked_keys(),
            3,
            "three distinct callers held concurrently"
        );
        assert!(
            lim.try_acquire("h3").is_none(),
            "a new key at max_keys is rejected"
        );
        assert_eq!(
            lim.tracked_keys(),
            3,
            "the rejected new key did not allocate an entry (reject-before-insert)"
        );
        drop(held);
    }

    #[tokio::test]
    async fn allows_within_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check("did:key:test1").await);
        assert!(limiter.check("did:key:test1").await);
        assert!(limiter.check("did:key:test1").await);
    }

    #[tokio::test]
    async fn blocks_over_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check("did:key:test2").await);
        assert!(limiter.check("did:key:test2").await);
        assert!(!limiter.check("did:key:test2").await);
    }

    #[tokio::test]
    async fn separate_keys_independent() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("did:key:alice").await);
        assert!(limiter.check("did:key:bob").await);
        assert!(!limiter.check("did:key:alice").await);
    }

    #[tokio::test]
    async fn window_expires() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.check("did:key:test3").await);
        assert!(!limiter.check("did:key:test3").await);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(limiter.check("did:key:test3").await);
    }

    #[tokio::test]
    async fn cleanup_removes_expired() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        limiter.check("did:key:stale").await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        limiter.cleanup().await;
        let state = limiter.state.lock().await;
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn zero_limit_disables() {
        let limiter = RateLimiter::new(0, Duration::from_secs(60));
        for _ in 0..1000 {
            assert!(limiter.check("k").await);
        }
    }

    // ── key-cap / memory-bound (P2) ──────────────────────────────────────

    #[tokio::test]
    async fn caps_tracked_keys_and_rejects_new_ones_when_full() {
        // Cap of 2 distinct keys; generous request budget so rejection is due to
        // the key cap, not the per-key limit.
        let limiter = RateLimiter::new_bounded(100, Duration::from_secs(60), 2);
        assert!(limiter.check("a").await);
        assert!(limiter.check("b").await);
        // Third distinct key would grow the map past the cap → rejected.
        assert!(!limiter.check("c").await);
        // The map never exceeded the cap, and the rejected key was NOT inserted.
        let state = limiter.state.lock().await;
        assert_eq!(state.len(), 2);
        assert!(!state.contains_key("c"));
    }

    #[tokio::test]
    async fn known_key_unaffected_by_cap() {
        let limiter = RateLimiter::new_bounded(100, Duration::from_secs(60), 1);
        assert!(limiter.check("a").await); // fills the single slot
        assert!(limiter.check("a").await); // same key still served
        assert!(!limiter.check("b").await); // new key rejected — cap full
    }

    #[tokio::test]
    async fn expired_keys_evicted_to_admit_new_when_full() {
        let limiter = RateLimiter::new_bounded(100, Duration::from_millis(40), 1);
        assert!(limiter.check("old").await);
        tokio::time::sleep(Duration::from_millis(55)).await;
        // "old" is now expired; a new key triggers inline eviction and is admitted.
        assert!(limiter.check("new").await);
        let state = limiter.state.lock().await;
        assert!(state.contains_key("new"));
        assert!(!state.contains_key("old"));
    }

    #[tokio::test]
    async fn capacity_sweep_is_amortized_within_interval() {
        // The O(max_keys) eviction scan must not run on every capacity miss.
        // With a 1s sweep interval, the resident (unexpired) key is never
        // evicted by a burst of misses, so repeated new keys are all rejected
        // without disturbing existing state.
        let limiter = RateLimiter::new_bounded(100, Duration::from_secs(1), 1);
        assert!(limiter.check("resident").await);
        for i in 0..100 {
            assert!(
                !limiter.check(&format!("flood-{i}")).await,
                "new key must be rejected while the single slot is held"
            );
        }
        let state = limiter.state.lock().await;
        assert_eq!(state.len(), 1, "no flood key was ever inserted");
        assert!(state.contains_key("resident"));
    }

    // ── client_key / trusted-proxy resolution (P1 + P2) ─────────────────

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn peer(s: &str) -> Option<SocketAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn none_mode_ignores_headers_and_uses_peer() {
        // Even a well-formed Fly header is ignored without a trusted proxy.
        let h = headers(&[("fly-client-ip", "203.0.113.7")]);
        assert_eq!(
            client_key(&h, peer("198.51.100.9:4000"), TrustedProxy::None).as_deref(),
            Some("198.51.100.9")
        );
    }

    #[test]
    fn fly_mode_trusts_fly_header() {
        let h = headers(&[
            ("fly-client-ip", "203.0.113.7"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        assert_eq!(
            client_key(&h, peer("10.0.0.1:1"), TrustedProxy::Fly).as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn fly_mode_empty_header_falls_back_to_peer_not_skip() {
        // Empty Fly-Client-IP must NOT collapse traffic onto Some("") nor skip
        // the limiter — it falls back to the real peer.
        let h = headers(&[("fly-client-ip", "")]);
        assert_eq!(
            client_key(&h, peer("198.51.100.9:4000"), TrustedProxy::Fly).as_deref(),
            Some("198.51.100.9")
        );
    }

    #[test]
    fn xff_mode_uses_rightmost_hop_not_client_controlled_first() {
        // Client prepends spoofed hops; only the rightmost (proxy-appended) is trusted.
        let h = headers(&[("x-forwarded-for", "9.9.9.9, 8.8.8.8, 198.51.100.9")]);
        assert_eq!(
            client_key(&h, peer("10.0.0.1:1"), TrustedProxy::XForwardedFor).as_deref(),
            Some("198.51.100.9")
        );
    }

    #[test]
    fn xff_mode_empty_leading_hop_does_not_disable_brake() {
        // "X-Forwarded-For: ,1.2.3.4" — rightmost hop is used; never None-skips.
        let h = headers(&[("x-forwarded-for", ",1.2.3.4")]);
        assert_eq!(
            client_key(&h, peer("10.0.0.1:1"), TrustedProxy::XForwardedFor).as_deref(),
            Some("1.2.3.4")
        );
    }

    #[test]
    fn malformed_xff_falls_back_to_peer() {
        let h = headers(&[("x-forwarded-for", " , ")]);
        assert_eq!(
            client_key(&h, peer("198.51.100.9:4000"), TrustedProxy::XForwardedFor).as_deref(),
            Some("198.51.100.9")
        );
    }

    #[test]
    fn trusted_proxy_parsing() {
        assert_eq!(TrustedProxy::from_env_value("fly"), TrustedProxy::Fly);
        assert_eq!(
            TrustedProxy::from_env_value("X-Forwarded-For"),
            TrustedProxy::XForwardedFor
        );
        assert_eq!(
            TrustedProxy::from_env_value("caddy"),
            TrustedProxy::XForwardedFor
        );
        assert_eq!(TrustedProxy::from_env_value(""), TrustedProxy::None);
        assert_eq!(TrustedProxy::from_env_value("garbage"), TrustedProxy::None);
    }

    // ── middleware 429 path ─────────────────────────────────────────────

    /// A minimal router with the push limiter layered over an OK handler,
    /// driven via `oneshot`. `ConnectInfo` is attached to each request directly
    /// (as the production make-service does) so the middleware resolves a peer.
    fn ip_limited_router(limiter: IpRateLimiter) -> axum::Router {
        axum::Router::new()
            .route(
                "/o/r/git-receive-pack",
                axum::routing::post(|| async { StatusCode::OK }),
            )
            .layer(axum::middleware::from_fn(rate_limit_by_ip))
            .layer(axum::Extension(limiter))
    }

    async fn post_from(router: &axum::Router, peer: SocketAddr) -> StatusCode {
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/o/r/git-receive-pack")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        router.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn middleware_returns_429_over_limit() {
        let router = ip_limited_router(IpRateLimiter {
            limiter: RateLimiter::new(2, Duration::from_secs(60)),
            trust: TrustedProxy::None,
        });
        let peer: SocketAddr = "203.0.113.7:5000".parse().unwrap();
        // Two requests inside the budget, the third over it (shared Arc state).
        assert_eq!(post_from(&router, peer).await, StatusCode::OK);
        assert_eq!(post_from(&router, peer).await, StatusCode::OK);
        assert_eq!(
            post_from(&router, peer).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn middleware_isolates_distinct_peers() {
        let router = ip_limited_router(IpRateLimiter {
            limiter: RateLimiter::new(1, Duration::from_secs(60)),
            trust: TrustedProxy::None,
        });
        let a: SocketAddr = "203.0.113.1:1".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:1".parse().unwrap();
        assert_eq!(post_from(&router, a).await, StatusCode::OK);
        assert_eq!(post_from(&router, b).await, StatusCode::OK); // independent bucket
        assert_eq!(post_from(&router, a).await, StatusCode::TOO_MANY_REQUESTS);
    }

    // ── creation-route layering: IP brake runs BEFORE auth ──────────────

    /// A minimal stand-in for the creation route group: an inner "auth" layer
    /// that rejects every request with 401 (as signature verification would for
    /// an unsigned caller), wrapped by the per-IP creation limiter as the
    /// outermost layer — exactly the ordering `server::build_router` applies to
    /// `/api/v1/repos` et al. Lets us assert the security-relevant property
    /// (flood traffic is braked before auth burns CPU) without a database, which
    /// the full `#[sqlx::test]` route test in `api::repos` cannot cover in the
    /// plain unit-test pass.
    fn ip_limited_over_auth_router(limiter: IpRateLimiter) -> axum::Router {
        async fn always_unauthorized(_req: Request, _next: Next) -> Response {
            StatusCode::UNAUTHORIZED.into_response()
        }
        axum::Router::new()
            .route(
                "/api/v1/repos",
                axum::routing::post(|| async { StatusCode::CREATED }),
            )
            .layer(axum::middleware::from_fn(always_unauthorized))
            .layer(axum::middleware::from_fn(rate_limit_by_ip))
            .layer(axum::Extension(limiter))
    }

    async fn post_repos_from(router: &axum::Router, peer: SocketAddr) -> StatusCode {
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/v1/repos")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        router.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn creation_ip_brake_rejects_before_auth() {
        // A DID farm mints a fresh signature per repo, so the per-DID limiter
        // never trips; the per-IP brake is what stops the flood. It must run
        // outermost, ahead of auth, so a flood is rejected with 429 before
        // signature verification — otherwise every request would reach (and pay
        // for) auth and merely 401.
        let router = ip_limited_over_auth_router(IpRateLimiter {
            limiter: RateLimiter::new(1, Duration::from_secs(60)),
            trust: TrustedProxy::None,
        });
        let peer: SocketAddr = "203.0.113.42:7000".parse().unwrap();

        // First request passes the IP brake and reaches the (failing) auth layer.
        assert_eq!(
            post_repos_from(&router, peer).await,
            StatusCode::UNAUTHORIZED
        );
        // Budget now exhausted: the IP brake short-circuits with 429 *before*
        // auth — proving the limiter is the outermost layer.
        assert_eq!(
            post_repos_from(&router, peer).await,
            StatusCode::TOO_MANY_REQUESTS,
            "an exhausted IP must be braked with 429 before auth runs, not leak to 401"
        );
    }
}
