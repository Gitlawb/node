//! Pull request API handlers.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::{PullRequest, PrComment, PrReview};
use crate::error::{AppError, Result};
use crate::git::store;
use crate::state::AppState;
use crate::webhooks;

#[derive(Deserialize)]
pub struct CreatePrRequest {
    pub title: String,
    pub body: Option<String>,
    pub source_branch: String,
    pub target_branch: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateReviewRequest {
    pub body: Option<String>,
    pub status: String, // "approved" | "changes_requested" | "comment"
}

#[derive(Deserialize)]
pub struct CreateCommentRequest {
    pub body: String,
}

/// POST /api/v1/repos/:owner/:repo/pulls
pub async fn create_pr(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CreatePrRequest>,
) -> Result<(StatusCode, Json<PullRequest>)> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let author_did = auth.0;
    let target_branch = req.target_branch.unwrap_or_else(|| record.default_branch.clone());
    let number = state.db.next_pr_number(&record.id).await?;
    let now = Utc::now().to_rfc3339();

    let pr = PullRequest {
        id: Uuid::new_v4().to_string(),
        repo_id: record.id.clone(),
        number,
        title: req.title,
        body: req.body,
        author_did,
        source_branch: req.source_branch,
        target_branch,
        status: "open".to_string(),
        merged_by_did: None,
        merged_at: None,
        created_at: now.clone(),
        updated_at: now,
    };

    state.db.create_pr(&pr).await?;

    // Bump trust score for the PR author — increment current score by 0.05
    // (avoids the push_count=0 stuck-at-0.05 bug for agents who only open PRs)
    let current = state.db.get_trust_score(&pr.author_did).await.unwrap_or(0.05);
    let new_score = (current + 0.05).min(1.0);
    let _ = state.db.update_trust_score(&pr.author_did, new_score).await;

    webhooks::fire_event(
        std::sync::Arc::clone(&state.db),
        std::sync::Arc::clone(&state.http_client),
        &record.id,
        "pull_request.opened",
        serde_json::json!({
            "event": "pull_request.opened",
            "repository": { "id": record.id, "name": record.name, "owner_did": record.owner_did },
            "pull_request": &pr,
            "sender_did": &pr.author_did,
        }),
    );

    Ok((StatusCode::CREATED, Json(pr)))
}

/// GET /api/v1/repos/:owner/:repo/pulls
pub async fn list_prs(
    State(state): State<AppState>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let prs = state.db.list_prs(&record.id).await?;
    Ok(Json(serde_json::json!({ "pulls": prs, "count": prs.len() })))
}

/// GET /api/v1/repos/:owner/:repo/pulls/:number
pub async fn get_pr(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Json<PullRequest>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    Ok(Json(pr))
}

/// GET /api/v1/repos/:owner/:repo/pulls/:number/diff
pub async fn get_pr_diff(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let disk_path = state.repo_store.acquire(&record.owner_did, &record.name).await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let diff = store::branch_diff(&disk_path, &pr.target_branch, &pr.source_branch)
        .map_err(|e| AppError::Git(e.to_string()))?;

    Ok(Json(serde_json::json!({
        "diff": diff,
        "source_branch": pr.source_branch,
        "target_branch": pr.target_branch,
    })))
}

/// POST /api/v1/repos/:owner/:repo/pulls/:number/merge
pub async fn merge_pr(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    if pr.status != "open" {
        return Err(AppError::BadRequest(format!("PR is already {}", pr.status)));
    }

    let guard = state.repo_store.acquire_write(&record.owner_did, &record.name).await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let disk_path = guard.path().to_path_buf();
    let merger_did = auth.0;
    let merge_result = store::merge_branch(&disk_path, &pr.target_branch, &pr.source_branch, &merger_did, &pr.title);

    // Always release the advisory lock — even on error
    guard.release().await;

    let merge_sha = merge_result.map_err(|e| AppError::Git(e.to_string()))?;

    state.db.merge_pr(&pr.id, &merger_did).await?;
    let _ = state.db.touch_repo(&record.id).await;

    webhooks::fire_event(
        std::sync::Arc::clone(&state.db),
        std::sync::Arc::clone(&state.http_client),
        &record.id,
        "pull_request.merged",
        serde_json::json!({
            "event": "pull_request.merged",
            "repository": { "id": record.id, "name": record.name, "owner_did": record.owner_did },
            "pull_request": { "id": pr.id, "number": pr.number, "title": pr.title,
                              "source_branch": pr.source_branch, "target_branch": pr.target_branch },
            "merge_sha": merge_sha,
            "merged_by": merger_did,
        }),
    );

    Ok(Json(serde_json::json!({
        "status": "merged",
        "merge_sha": merge_sha,
        "merged_by": merger_did,
    })))
}

/// POST /api/v1/repos/:owner/:repo/pulls/:number/close
pub async fn close_pr(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    state.db.close_pr(&pr.id).await?;

    webhooks::fire_event(
        std::sync::Arc::clone(&state.db),
        std::sync::Arc::clone(&state.http_client),
        &record.id,
        "pull_request.closed",
        serde_json::json!({
            "event": "pull_request.closed",
            "repository": { "id": record.id, "name": record.name, "owner_did": record.owner_did },
            "pull_request": { "id": pr.id, "number": pr.number, "title": pr.title },
        }),
    );

    Ok(Json(serde_json::json!({ "status": "closed" })))
}

/// POST /api/v1/repos/:owner/:repo/pulls/:number/reviews
pub async fn create_review(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Json(req): Json<CreateReviewRequest>,
) -> Result<(StatusCode, Json<PrReview>)> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let valid_statuses = ["approved", "changes_requested", "comment"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return Err(AppError::BadRequest("status must be approved, changes_requested, or comment".into()));
    }

    let review = PrReview {
        id: Uuid::new_v4().to_string(),
        pr_id: pr.id,
        reviewer_did: auth.0,
        body: req.body,
        status: req.status,
        created_at: Utc::now().to_rfc3339(),
    };

    state.db.create_pr_review(&review).await?;

    webhooks::fire_event(
        std::sync::Arc::clone(&state.db),
        std::sync::Arc::clone(&state.http_client),
        &record.id,
        "pull_request.reviewed",
        serde_json::json!({
            "event": "pull_request.reviewed",
            "repository": { "id": record.id, "name": record.name, "owner_did": record.owner_did },
            "pull_request": { "number": pr.number, "title": pr.title },
            "review": &review,
        }),
    );

    Ok((StatusCode::CREATED, Json(review)))
}

/// GET /api/v1/repos/:owner/:repo/pulls/:number/reviews
pub async fn list_reviews(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let reviews = state.db.list_pr_reviews(&pr.id).await?;
    Ok(Json(serde_json::json!({ "reviews": reviews })))
}

/// POST /api/v1/repos/:owner/:repo/pulls/:number/comments
pub async fn create_comment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Json(req): Json<CreateCommentRequest>,
) -> Result<(StatusCode, Json<PrComment>)> {
    if req.body.trim().is_empty() {
        return Err(AppError::BadRequest("comment body must not be empty".into()));
    }

    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let comment = PrComment {
        id: Uuid::new_v4().to_string(),
        pr_id: pr.id,
        author_did: auth.0,
        body: req.body,
        created_at: Utc::now().to_rfc3339(),
    };

    state.db.create_pr_comment(&comment).await?;

    Ok((StatusCode::CREATED, Json(comment)))
}

/// GET /api/v1/repos/:owner/:repo/pulls/:number/comments
pub async fn list_comments(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &name).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state.db.get_pr(&record.id, number).await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let comments = state.db.list_pr_comments(&pr.id).await?;
    Ok(Json(serde_json::json!({ "comments": comments })))
}
