use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Mutex;

use crate::auth::AuthenticatedDid;

#[derive(Clone)]
struct Window {
    timestamps: Vec<Instant>,
}

#[derive(Clone)]
pub struct RateLimiter {
    state: Arc<Mutex<HashMap<String, Window>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    async fn check(&self, key: &str) -> bool {
        // max_requests == 0 means the limiter is disabled, not "block all".
        if self.max_requests == 0 {
            return true;
        }
        let now = Instant::now();
        let mut state = self.state.lock().await;
        // Look up before inserting so the common case (key already tracked)
        // doesn't allocate a String per request.
        if !state.contains_key(key) {
            state.insert(
                key.to_string(),
                Window {
                    timestamps: Vec::new(),
                },
            );
        }
        let window = state.get_mut(key).expect("window just ensured");
        window
            .timestamps
            .retain(|t| now.duration_since(*t) < self.window);
        if window.timestamps.len() >= self.max_requests {
            return false;
        }
        window.timestamps.push(now);
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

/// Per-client-IP limiter for the git push path. A newtype so it can coexist
/// with the per-DID [`RateLimiter`] in request extensions (which are keyed by
/// type). Per-DID limits are useless against the push-flood pattern — the June
/// 2026 attack held one throwaway DID per repo, so every DID stayed under any
/// per-identity threshold while the node absorbed several pushes per second.
#[derive(Clone)]
pub struct IpRateLimiter(pub RateLimiter);

/// Client IP as reported by the fronting proxy. Fly sets `Fly-Client-IP`;
/// generic reverse proxies set `X-Forwarded-For` (first hop). Both are only
/// trustworthy when a proxy the operator controls sets them, which is the
/// deployment shape this node documents (Fly, or Caddy on the AWS image).
fn client_ip(request: &Request) -> Option<String> {
    let headers = request.headers();
    if let Some(ip) = headers.get("fly-client-ip").and_then(|v| v.to_str().ok()) {
        return Some(ip.trim().to_string());
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|ip| ip.trim().to_string())
        .filter(|ip| !ip.is_empty())
}

/// Throttle by client IP. Fail-open when no IP header is present (direct
/// connections without a fronting proxy) — the limiter is a flood brake, not
/// an auth boundary, and rejecting proxy-less deployments outright would break
/// self-hosted nodes.
pub async fn rate_limit_by_ip(request: Request, next: Next) -> Response {
    let limiter = request.extensions().get::<IpRateLimiter>().cloned();

    if let (Some(limiter), Some(ip)) = (limiter, client_ip(&request)) {
        if !limiter.0.check(&ip).await {
            tracing::warn!(ip = %ip, path = %request.uri().path(), "push rate limit exceeded");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "60")],
                "push rate limit exceeded — try again later",
            )
                .into_response();
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

    fn request_with_headers(pairs: &[(&str, &str)]) -> Request {
        let mut builder = axum::http::Request::builder().uri("/x/y/git-receive-pack");
        for (k, v) in pairs {
            builder = builder.header(*k, *v);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn client_ip_prefers_fly_header() {
        let req = request_with_headers(&[
            ("fly-client-ip", "203.0.113.7"),
            ("x-forwarded-for", "198.51.100.1, 10.0.0.1"),
        ]);
        assert_eq!(client_ip(&req).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn client_ip_falls_back_to_first_forwarded_hop() {
        let req = request_with_headers(&[("x-forwarded-for", " 198.51.100.1 , 10.0.0.1")]);
        assert_eq!(client_ip(&req).as_deref(), Some("198.51.100.1"));
    }

    #[test]
    fn client_ip_none_without_proxy_headers() {
        assert_eq!(client_ip(&request_with_headers(&[])), None);
    }
}
