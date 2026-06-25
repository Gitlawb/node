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
}
