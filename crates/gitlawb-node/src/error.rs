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

    #[error("too many requests: {0}")]
    TooManyRequests(String),

    #[error("incomplete: {0}")]
    Incomplete(String),

    #[error("git error: {0}")]
    Git(String),

    #[error("git service timed out: {0}")]
    Timeout(String),

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
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
            AppError::TooManyRequests(msg) => {
                (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg.clone())
            }
            AppError::Incomplete(msg) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "incomplete", msg.clone())
            }
            AppError::Git(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "git_error", msg.clone()),
            // 504, distinct from the 500 git_error and from the read-gate's 404 /
            // the auth 401, so the client can tell a deadline from a failure.
            AppError::Timeout(msg) => (StatusCode::GATEWAY_TIMEOUT, "git_timeout", msg.clone()),
            AppError::Db(sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "db_unavailable",
                "database is temporarily unavailable".into(),
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
}
