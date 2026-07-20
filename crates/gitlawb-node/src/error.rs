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

    #[error("incomplete: {0}")]
    Incomplete(String),

    #[error("git error: {0}")]
    Git(String),

    #[error("git service timed out: {0}")]
    Timeout(String),

    #[error("service unavailable: {0}")]
    Unavailable(String),

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
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "not_an_agent", msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            // IcaptchaProofRequired is handled above (it carries extra headers/fields).
            AppError::IcaptchaProofRequired { .. } => unreachable!("handled before this match"),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            AppError::Incomplete(msg) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "incomplete", msg.clone())
            }
            AppError::Git(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "git_error", msg.clone()),
            // 504, distinct from the 500 git_error and from the read-gate's 404 /
            // the auth 401, so the client can tell a deadline from a failure.
            AppError::Timeout(msg) => (StatusCode::GATEWAY_TIMEOUT, "git_timeout", msg.clone()),
            // 503, retryable: a transient resource contention (e.g. the repo lock
            // pool is pinned by a write burst or a purge holds the key), distinct
            // from the 500 git_error so the client knows to back off and retry.
            AppError::Unavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                msg.clone(),
            ),
            AppError::Db(e) if db_unavailable(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                DB_UNAVAILABLE_CODE,
                DB_UNAVAILABLE_MESSAGE.into(),
            ),
            AppError::Db(e) => (StatusCode::INTERNAL_SERVER_ERROR, "db_error", e.to_string()),
            AppError::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                e.to_string(),
            ),
        };

        let body = Json(json!({
            "error": code,
            "message": message,
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

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
    fn unavailable_maps_to_503_distinct_from_git_500() {
        // The create-repo lock-acquire failure returns Unavailable so a client sees
        // a retryable 503, not a terminal 500 git_error.
        assert_eq!(
            AppError::Unavailable("lock pool pinned".into())
                .into_response()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AppError::Git("x".into()).into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
