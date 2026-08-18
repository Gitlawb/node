use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("repo not found: {0}")]
    RepoNotFound(String),

    #[error("repo already exists: {0}")]
    RepoExists(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    #[allow(dead_code)]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    #[allow(dead_code)]
    Forbidden(String),

    #[error("icaptcha proof required: {message}")]
    IcaptchaProofRequired {
        message: String,
        /// iCaptcha service base URL the client should solve against.
        url: String,
        /// Minimum proof level this node requires.
        level: u32,
    },

    #[error("invalid request: {0}")]
    BadRequest(String),

    /// A DID was well-formed enough to carry to a resolver but no verifying key
    /// could be derived from it. Its own code rather than plain `bad_request`
    /// because the auth middleware already answers `unresolvable_did` for the
    /// same failure on a request's keyid, and a client should not have to
    /// substring-match a message to tell this apart from the other validation
    /// failures on the same route.
    #[error("unresolvable did: {0}")]
    UnresolvableDid(String),

    #[error("too many requests: {0}")]
    TooManyRequests(String),

    #[error("incomplete: {0}")]
    Incomplete(String),

    /// A bounded search that could not complete. `continuation`, when present, is the
    /// sealed scan position the caller echoes as `?scan=` to resume where the search
    /// stopped (#173 round 13, F2). It is AEAD-sealed at the mint site, never plaintext:
    /// the row it names is by construction one the caller was denied (INV-13).
    #[error("search incomplete: {message}")]
    SearchIncomplete {
        message: String,
        continuation: Option<String>,
    },

    #[error("git error: {0}")]
    Git(String),

    #[error("git service timed out: {0}")]
    Timeout(String),

    #[error("server overloaded: {0}")]
    Overloaded(String),

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(anyhow::Error),
}

/// Shared error code/message for "the database is unreachable", also used by
/// the degraded startup server (main.rs) and the readiness probe (server.rs)
/// so clients see one vocabulary for the condition.
pub const DB_UNAVAILABLE_CODE: &str = "db_unavailable";
pub const DB_UNAVAILABLE_MESSAGE: &str = "database is temporarily unavailable";

/// Generic client-facing message for `AppError::Internal`. The real error is
/// logged server-side; never put sqlx/anyhow detail in the HTTP body (#226).
pub const INTERNAL_ERROR_MESSAGE: &str = "an internal error occurred";

/// Generic client-facing message for non-unavailable `AppError::Db`. Query /
/// schema errors stay in logs; the HTTP body must not leak them (#226).
pub const DB_ERROR_MESSAGE: &str = "a database error occurred";

/// Connection-level sqlx failures that mean the database is unreachable right
/// now (retryable, 503), as opposed to server-reported query errors.
fn db_unavailable(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
    )
}

/// The db layer returns `anyhow::Result`, so sqlx errors reach handlers inside
/// anyhow chains. Downcast them back out so the status mapping below can see
/// them — without this, every database outage surfaces as a 500 instead of a
/// 503. anyhow preserves downcastability through `.context()` layers.
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast::<sqlx::Error>() {
            Ok(sql) => AppError::Db(sql),
            Err(err) => AppError::Internal(err),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // iCaptcha challenges carry structured discovery so clients don't have to
        // scrape the message: the service URL and required level are returned as
        // both JSON fields and `x-icaptcha-url` / `x-icaptcha-level` headers
        // (mirroring the header-bearing `human_detected` response in auth/mod.rs).
        if let AppError::IcaptchaProofRequired {
            message,
            url,
            level,
        } = &self
        {
            use axum::http::HeaderValue;
            let body = Json(json!({
                "error": "icaptcha_proof_required",
                "message": message,
                "icaptcha_url": url,
                "required_level": level,
            }));
            let mut resp = (StatusCode::FORBIDDEN, body).into_response();
            let headers = resp.headers_mut();
            if let Ok(v) = HeaderValue::from_str(url) {
                headers.insert("x-icaptcha-url", v);
            }
            if let Ok(v) = HeaderValue::from_str(&level.to_string()) {
                headers.insert("x-icaptcha-level", v);
            }
            return resp;
        }

        let (status, code, message) = match &self {
            AppError::RepoNotFound(r) => (
                StatusCode::NOT_FOUND,
                "repo_not_found",
                format!("repository '{r}' not found"),
            ),
            AppError::RepoExists(r) => (
                StatusCode::CONFLICT,
                "repo_exists",
                format!("repository '{r}' already exists"),
            ),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "not_an_agent", msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            // IcaptchaProofRequired is handled above (it carries extra headers/fields).
            AppError::IcaptchaProofRequired { .. } => unreachable!("handled before this match"),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            AppError::UnresolvableDid(msg) => {
                (StatusCode::BAD_REQUEST, "unresolvable_did", msg.clone())
            }
            AppError::TooManyRequests(msg) => {
                (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg.clone())
            }
            AppError::Incomplete(msg) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "incomplete", msg.clone())
            }
            // A bounded search that could not complete (the CID resolver hit its
            // legacy-probe or walk ceiling), distinct from the 404 that asserts a
            // definitive not-found: absence was NOT proven, so the caller should
            // retry rather than treat it as gone (#173, F2). 503, retryable.
            AppError::SearchIncomplete { message, .. } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "search_incomplete",
                message.clone(),
            ),
            AppError::Git(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "git_error", msg.clone()),
            // 504, distinct from the 500 git_error and from the read-gate's 404 /
            // the auth 401, so the client can tell a deadline from a failure.
            AppError::Timeout(msg) => (StatusCode::GATEWAY_TIMEOUT, "git_timeout", msg.clone()),
            AppError::Db(e) if db_unavailable(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                DB_UNAVAILABLE_CODE,
                DB_UNAVAILABLE_MESSAGE.into(),
            ),
            // 503 with a Retry-After (attached after this match — the shared tail
            // can't carry per-variant headers). This is the single place Overloaded
            // becomes a response, so it can never ship a 503 without the retry hint.
            AppError::Overloaded(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, "overloaded", msg.clone())
            }
            // Opaque body + server log: bare `?` on sqlx paths becomes `AppError::Db`
            // via `From`, so this arm (not `Internal`) is the common leak for open
            // routes like GET /api/v1/repos and GET /api/v1/peers (#226).
            AppError::Db(e) => {
                tracing::error!(error = %e, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "db_error",
                    DB_ERROR_MESSAGE.into(),
                )
            }
            // Opaque body: handlers that map with `.map_err(AppError::Internal)`
            // (e.g. GET /ipfs/{cid}) land here; other DB failures usually hit `Db`.
            // Log `{e:#}` so context-wrapped anyhow chains keep the leaf cause
            // (Display alone is only the outermost layer; see api/repos.rs).
            AppError::Internal(e) => {
                tracing::error!(error = %format!("{e:#}"), "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    INTERNAL_ERROR_MESSAGE.into(),
                )
            }
        };

        let mut body = json!({
            "error": code,
            "message": message,
        });
        // A truncated CID search may carry the sealed position the caller echoes as
        // `?scan=` to resume. Rendered as a third body field, present only when the
        // shed actually left something to resume: a wrapped scan and a throttled
        // request both omit it, and its ABSENCE is what tells a caller the ladder is
        // over. It is opaque ciphertext; see `gitlawb_core::scan_token`.
        if let AppError::SearchIncomplete {
            continuation: Some(token),
            ..
        } = &self
        {
            body["continuation"] = json!(token);
        }

        let mut resp = (status, Json(body)).into_response();
        // Both retryable 503s advertise when to retry: Overloaded (capacity shed) and
        // SearchIncomplete (a bounded CID search cut short by a cap — retry may complete
        // it). They ride the shared tail above for body/status, so the header is attached
        // here rather than in bespoke early returns, keeping each variant handled once.
        if matches!(
            self,
            AppError::Overloaded(_) | AppError::SearchIncomplete { .. }
        ) {
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("1"),
            );
        }
        resp
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_maps_to_409() {
        assert_eq!(
            AppError::Conflict("task not claimable".into())
                .into_response()
                .status(),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn timeout_maps_to_504_distinct_from_git_500() {
        assert_eq!(
            AppError::Timeout("x".into()).into_response().status(),
            StatusCode::GATEWAY_TIMEOUT
        );
        // Guard against a swap with the generic git failure (500).
        assert_eq!(
            AppError::Git("x".into()).into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn overloaded_maps_to_503_with_retry_after() {
        let resp = AppError::Overloaded("x".into()).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get("retry-after").unwrap().to_str().unwrap(),
            "1"
        );
    }

    /// #226: raw sqlx/DB detail must never appear in the Internal 500 body.
    #[tokio::test]
    async fn internal_error_body_is_opaque() {
        use serde_json::{json, Value};

        let leak = "error returned from database: relation \"repos\" does not exist";
        let resp = AppError::Internal(anyhow::anyhow!("{leak}")).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        // Exact object: a new `detail` field with different sensitive text must
        // also fail, not only a repeat of the original error string.
        assert_eq!(
            v,
            json!({
                "error": "internal_error",
                "message": INTERNAL_ERROR_MESSAGE,
            })
        );
    }

    /// #226: `AppError::Db` query errors (the common `?` path) must also be opaque.
    #[tokio::test]
    async fn db_error_body_is_opaque() {
        use serde_json::{json, Value};

        let resp = AppError::Db(sqlx::Error::Protocol(
            "error returned from database: column \"is_public\" does not exist".into(),
        ))
        .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v,
            json!({
                "error": "db_error",
                "message": DB_ERROR_MESSAGE,
            })
        );
    }

    /// Connection-level failures must stay 503 `db_unavailable`, not collapse
    /// into the opaque 500 `db_error` arm if `db_unavailable` loses a variant.
    #[tokio::test]
    async fn db_pool_timeout_stays_503_unavailable() {
        use serde_json::{json, Value};

        let resp = AppError::Db(sqlx::Error::PoolTimedOut).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v,
            json!({
                "error": DB_UNAVAILABLE_CODE,
                "message": DB_UNAVAILABLE_MESSAGE,
            })
        );
    }

    /// #251: bare `?` on anyhow-wrapped sqlx relies on this downcast so a
    /// closed pool becomes 503 `db_unavailable`, not 500 `internal_error`.
    #[test]
    fn pool_closed_via_anyhow_from_is_503_db_unavailable() {
        let err: AppError = anyhow::Error::from(sqlx::Error::PoolClosed).into();
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
