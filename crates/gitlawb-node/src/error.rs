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

    #[error("icaptcha proof required: {0}")]
    IcaptchaProofRequired(String),

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("too many requests: {0}")]
    TooManyRequests(String),

    #[error("git error: {0}")]
    Git(String),

    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
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
            // 403, not 401: the caller IS an authenticated agent (credentials are
            // valid) but is forbidden from this action without a valid, fresh
            // iCaptcha proof. The distinct `icaptcha_proof_required` code — which
            // clients branch on — keeps it separable from a plain `forbidden`.
            AppError::IcaptchaProofRequired(msg) => (
                StatusCode::FORBIDDEN,
                "icaptcha_proof_required",
                msg.clone(),
            ),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            AppError::TooManyRequests(msg) => {
                (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg.clone())
            }
            AppError::Git(msg) => (StatusCode::INTERNAL_SERVER_ERROR, "git_error", msg.clone()),
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
