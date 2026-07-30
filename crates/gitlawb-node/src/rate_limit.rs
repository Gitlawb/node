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

    /// Returns `true` if the request is allowed. Thin wrapper over
    /// [`check_retry`](Self::check_retry) for callers that only need the
    /// allow/deny decision, not the rejection's Retry-After delay. Test-only now:
    /// production 429 sites use `check_retry` so they can advertise Retry-After.
    #[cfg(test)]
    pub(crate) async fn check(&self, key: &str) -> bool {
        self.check_retry(key).await.is_none()
    }

    /// Record a request against `key`. Returns `None` when it is allowed, or
    /// `Some(retry_after)` when it is rejected — the delay a client should wait
    /// before retrying, so a 429 can advertise a value consistent with the
    /// actual window instead of a constant.
    pub(crate) async fn check_retry(&self, key: &str) -> Option<Duration> {
        // max_requests == 0 means the limiter is disabled, not "block all".
        if self.max_requests == 0 {
            return None;
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
                // Insertion order is preserved, so after the retain the first
                // element is the oldest live request. It ages out (freeing a
                // slot) one window after it landed, so that remaining time is
                // the delay to advertise. Clamp to >= 1 so a 429 never tells a
                // client to retry immediately.
                let retry = window
                    .timestamps
                    .first()
                    .map(|oldest| {
                        self.window
                            .as_secs()
                            .saturating_sub(now.duration_since(*oldest).as_secs())
                    })
                    .unwrap_or(0)
                    .max(1);
                return Some(Duration::from_secs(retry));
            }
            window.timestamps.push(now);
            return None;
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
                // The key is untracked (never inserted), so there is no oldest
                // entry to derive a delay from. Advertise the full window as a
                // conservative bound: capacity frees as other keys expire, at
                // the latest one window from now.
                return Some(self.window.max(Duration::from_secs(1)));
            }
        }
        state.insert(
            key.to_string(),
            Window {
                timestamps: vec![now],
            },
        );
        None
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

    /// Test-only: insert a fully-expired entry (no live timestamps) that the next
    /// `cleanup()` must reclaim. Models a key whose window has aged out, without
    /// depending on wall-clock sleeps or a short window. Used cross-module by the
    /// AppState cleanup guard test (H2).
    #[cfg(test)]
    pub(crate) async fn insert_reclaimable_for_test(&self, key: &str) {
        self.state
            .lock()
            .await
            .insert(key.to_string(), Window { timestamps: vec![] });
    }

    /// Test-only: number of distinct keys currently tracked.
    #[cfg(test)]
    pub(crate) async fn tracked_keys(&self) -> usize {
        self.state.lock().await.len()
    }

    /// Test-only: seed a key's bucket with entries of the given ages (how long
    /// ago each request landed), so a test can drive the Retry-After computation
    /// off a controlled oldest-entry age without wall-clock sleeps. Ages that
    /// would underflow the monotonic clock collapse to `now`.
    #[cfg(test)]
    pub(crate) async fn seed_aged_entry_for_test(&self, key: &str, ages: &[Duration]) {
        let now = Instant::now();
        let timestamps = ages
            .iter()
            .map(|a| now.checked_sub(*a).unwrap_or(now))
            .collect();
        self.state
            .lock()
            .await
            .insert(key.to_string(), Window { timestamps });
    }
}

pub async fn rate_limit_by_did(request: Request, next: Next) -> Response {
    let limiter = request.extensions().get::<RateLimiter>().cloned();

    let did = request
        .extensions()
        .get::<AuthenticatedDid>()
        .map(|a| a.0.clone());

    if let (Some(limiter), Some(did)) = (limiter, did) {
        if let Some(retry_after) = limiter.check_retry(&did).await {
            return too_many_requests(retry_after);
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

/// The shared 429 response for the rate-limit middlewares (per-DID and per-IP
/// alike). Route-agnostic: the message stays generic (the offending path, when
/// logged, is recorded at the call site).
pub fn too_many_requests(retry_after: Duration) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", retry_after.as_secs().to_string())],
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
            if let Some(retry_after) = limiter.limiter.check_retry(&key).await {
                tracing::warn!(key = %key, path = %request.uri().path(), "per-IP rate limit exceeded");
                return too_many_requests(retry_after);
            }
        }
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ── Adversarial TrustedProxy verification through the middleware (U5) ──
    // These complement the client_key unit tests above by driving hostile
    // headers through rate_limit_by_ip on a real router: the property under test
    // is that the *bucket key* cannot be rotated by a spoofer.

    async fn post_with(
        router: &axum::Router,
        peer: SocketAddr,
        hdrs: &[(&str, &str)],
    ) -> StatusCode {
        use tower::ServiceExt;
        let mut b = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/v1/repos");
        for (k, v) in hdrs {
            b = b.header(*k, *v);
        }
        let mut req = b.body(axum::body::Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        router.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn xff_spoofed_leftmost_hop_cannot_rotate_bucket() {
        // XForwardedFor mode, budget 1. A spoofer varies the client-controlled
        // leftmost hop every request but the trusted proxy always appends the
        // same rightmost hop. All requests must key to the rightmost hop, so the
        // second is braked despite a fresh leftmost value.
        let router = ip_limited_over_auth_router(IpRateLimiter {
            limiter: RateLimiter::new(1, Duration::from_secs(60)),
            trust: TrustedProxy::XForwardedFor,
        });
        let p1: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let p2: SocketAddr = "10.0.0.2:1".parse().unwrap();
        // First request passes the brake, reaches (failing) auth.
        assert_eq!(
            post_with(&router, p1, &[("x-forwarded-for", "9.9.9.1, 203.0.113.5")]).await,
            StatusCode::UNAUTHORIZED
        );
        // Different leftmost + different socket peer, SAME rightmost trusted hop:
        // braked, because the key is the rightmost hop, not the spoofed value.
        assert_eq!(
            post_with(&router, p2, &[("x-forwarded-for", "9.9.9.2, 203.0.113.5")]).await,
            StatusCode::TOO_MANY_REQUESTS,
            "a spoofer varying the leftmost XFF hop must not rotate its bucket key"
        );
    }

    #[tokio::test]
    async fn xff_distinct_real_clients_get_distinct_buckets() {
        // Distinct trusted (rightmost) hops are distinct clients: neither throttles
        // the other, so a busy legitimate client cannot starve a different one.
        let router = ip_limited_over_auth_router(IpRateLimiter {
            limiter: RateLimiter::new(1, Duration::from_secs(60)),
            trust: TrustedProxy::XForwardedFor,
        });
        let peer: SocketAddr = "10.0.0.9:1".parse().unwrap();
        assert_eq!(
            post_with(
                &router,
                peer,
                &[("x-forwarded-for", "1.1.1.1, 203.0.113.5")]
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_with(
                &router,
                peer,
                &[("x-forwarded-for", "1.1.1.1, 203.0.113.6")]
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "a different trusted client hop must get its own bucket"
        );
    }

    #[tokio::test]
    async fn absent_trusted_header_collapses_to_socket_peer() {
        // The documented fallback: in a trusted-proxy mode, a request with no
        // forwarded header keys on the socket peer. Behind a real edge every
        // request shares the proxy's socket, so they collapse onto one bucket —
        // asserted here by name so any change to this behavior is deliberate.
        let router = ip_limited_over_auth_router(IpRateLimiter {
            limiter: RateLimiter::new(1, Duration::from_secs(60)),
            trust: TrustedProxy::XForwardedFor,
        });
        let proxy: SocketAddr = "172.16.0.1:1".parse().unwrap();
        assert_eq!(
            post_with(&router, proxy, &[]).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post_with(&router, proxy, &[]).await,
            StatusCode::TOO_MANY_REQUESTS,
            "with no trusted header, requests fall back to the socket peer key (collapse)"
        );
    }

    // ── Retry-After derived from the window, not a constant 60 (U5) ───────
    // A 429 must advertise the delay until the oldest live request ages out of
    // the limiter's window, so the value tracks the real window instead of the
    // hardcoded 60 that contradicted every limiter's 3600s window.

    async fn resp_from(router: &axum::Router, peer: SocketAddr) -> Response {
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/o/r/git-receive-pack")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        router.clone().oneshot(req).await.unwrap()
    }

    fn retry_after_secs(resp: &Response) -> u64 {
        resp.headers()
            .get("retry-after")
            .expect("429 must carry a retry-after header")
            .to_str()
            .unwrap()
            .parse()
            .expect("retry-after must be an integer number of seconds")
    }

    #[tokio::test]
    async fn retry_after_reflects_full_window_for_freshly_filled_bucket() {
        // A just-filled bucket's oldest entry is ~now, so the advertised delay
        // must be close to the whole window (100s), NOT the old constant 60.
        let router = ip_limited_router(IpRateLimiter {
            limiter: RateLimiter::new(1, Duration::from_secs(100)),
            trust: TrustedProxy::None,
        });
        let peer: SocketAddr = "203.0.113.50:6000".parse().unwrap();
        assert_eq!(resp_from(&router, peer).await.status(), StatusCode::OK);
        let resp = resp_from(&router, peer).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry = retry_after_secs(&resp);
        assert!(
            (95..=100).contains(&retry),
            "freshly-filled bucket must advertise ~window (95..=100s), got {retry} (constant-60 bug if 60)"
        );
    }

    #[tokio::test]
    async fn retry_after_shrinks_as_oldest_entry_ages() {
        // Seed the sole slot with an entry already 95s into a 100s window: the
        // next request is rejected and must advertise only the ~5s remaining,
        // not 60.
        let limiter = RateLimiter::new(1, Duration::from_secs(100));
        let peer: SocketAddr = "203.0.113.51:6000".parse().unwrap();
        limiter
            .seed_aged_entry_for_test(&peer.ip().to_string(), &[Duration::from_secs(95)])
            .await;
        let router = ip_limited_router(IpRateLimiter {
            limiter,
            trust: TrustedProxy::None,
        });
        let resp = resp_from(&router, peer).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry = retry_after_secs(&resp);
        assert!(
            (1..=10).contains(&retry),
            "an aged bucket must advertise the small remaining delay (1..=10s), got {retry}"
        );
    }

    #[tokio::test]
    async fn retry_after_clamps_to_at_least_one_second() {
        // Oldest entry is 99s into a 100s window: the raw remainder rounds toward
        // 1s and must never be advertised as 0 (a 0/blank retry lets a rejected
        // client hammer immediately).
        let limiter = RateLimiter::new(1, Duration::from_secs(100));
        let peer: SocketAddr = "203.0.113.52:6000".parse().unwrap();
        limiter
            .seed_aged_entry_for_test(&peer.ip().to_string(), &[Duration::from_secs(99)])
            .await;
        let router = ip_limited_router(IpRateLimiter {
            limiter,
            trust: TrustedProxy::None,
        });
        let resp = resp_from(&router, peer).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry = retry_after_secs(&resp);
        assert!(retry >= 1, "retry-after must clamp to >= 1, got {retry}");
        assert!(
            retry <= 2,
            "with 99s of a 100s window elapsed, the remaining delay is ~1s, got {retry}"
        );
    }
}
