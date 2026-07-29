//! Issue API endpoints — issues stored as git refs.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::IssueComment;
use crate::error::{AppError, Result};
use crate::git::issues as git_issues;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateIssueRequest {
    pub title: String,
    pub body: Option<String>,
    /// Signed JSON payload (optional — if provided, stored as-is for verification)
    pub signed_payload: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IssueRecord {
    pub id: String,
    pub title: String,
    pub body: Option<String>,
    pub author: Option<String>,
    pub created_at: String,
    pub status: String,
    pub signed_payload: Option<serde_json::Value>,
}

/// POST /api/v1/repos/{owner}/{repo}/issues
pub async fn create_issue(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo)): Path<(String, String)>,
    Json(req): Json<CreateIssueRequest>,
) -> Result<(StatusCode, Json<IssueRecord>)> {
    // Authorize the caller as a reader before accepting an issue: a non-reader
    // must not be able to file an issue against a private repo they cannot read.
    // Mirrors create_issue_comment / create_review / create_bounty.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, Some(auth.0.as_str()), "/").await?;

    let issue_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let issue = IssueRecord {
        id: issue_id.clone(),
        title: req.title.clone(),
        body: req.body.clone(),
        author: Some(auth.0),
        created_at: now,
        status: "open".to_string(),
        signed_payload: req.signed_payload.clone(),
    };

    let json_str = serde_json::to_string(&issue)
        .map_err(|e| AppError::BadRequest(format!("serialization error: {e}")))?;

    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let disk_path = guard.path().to_path_buf();

    let create_result = git_issues::create_issue(&disk_path, &issue_id, &json_str);

    // Always release the advisory lock — even on error; upload to Tigris only on success.
    guard.release(create_result.is_ok()).await;

    create_result.map_err(|e| AppError::Git(e.to_string()))?;

    // Bump trust score for the issue author — increment current score by 0.05
    // (avoids the push_count=0 stuck-at-0.05 bug for agents who only file issues)
    if let Some(ref author_did) = issue.author {
        let current = state.db.get_trust_score(author_did).await.unwrap_or(0.05);
        let new_score = (current + 0.05).min(1.0);
        let _ = state.db.update_trust_score(author_did, new_score).await;
    }

    Ok((StatusCode::CREATED, Json(issue)))
}

/// GET /api/v1/repos/{owner}/{repo}/issues
pub async fn list_issues(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

    let raw_issues =
        git_issues::list_issues(&disk_path).map_err(|e| AppError::Git(e.to_string()))?;

    let mut issues: Vec<serde_json::Value> = Vec::new();
    for raw in raw_issues {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            issues.push(v);
        }
    }

    Ok(Json(serde_json::json!({ "issues": issues })))
}

/// GET /api/v1/repos/{owner}/{repo}/issues/{id}
pub async fn get_issue(
    State(state): State<AppState>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

    let raw = git_issues::get_issue(&disk_path, &issue_id)
        .map_err(|e| AppError::Git(e.to_string()))?
        .ok_or_else(|| AppError::RepoNotFound(format!("issue {issue_id} not found")))?;

    let issue: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| AppError::BadRequest(format!("invalid issue data: {e}")))?;

    Ok(Json(issue))
}

#[derive(Debug, Deserialize)]
pub struct CreateIssueCommentRequest {
    pub body: String,
}

/// POST /api/v1/repos/{owner}/{repo}/issues/{id}/comments
pub async fn create_issue_comment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
    Json(req): Json<CreateIssueCommentRequest>,
) -> Result<(StatusCode, Json<IssueComment>)> {
    if req.body.trim().is_empty() {
        return Err(AppError::BadRequest(
            "comment body must not be empty".into(),
        ));
    }

    // Read-gate: a commenter must be able to read the repo, but need not own it.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, Some(auth.0.as_str()), "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    // Verify issue exists
    crate::git::issues::get_issue(&disk_path, &issue_id)
        .map_err(|e| AppError::Git(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("issue {issue_id} not found")))?;

    let comment = IssueComment {
        id: Uuid::new_v4().to_string(),
        issue_id: issue_id.clone(),
        author_did: auth.0,
        body: req.body,
        created_at: Utc::now().to_rfc3339(),
    };

    state.db.create_issue_comment(&comment).await?;
    Ok((StatusCode::CREATED, Json(comment)))
}

/// GET /api/v1/repos/{owner}/{repo}/issues/{id}/comments
pub async fn list_issue_comments(
    State(state): State<AppState>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    // Resolve the full issue ID (accepts 8-char prefix) so the DB fetch
    // below uses the same canonical id as the git ref.
    let full_id = match git_issues::resolve_issue_id(&disk_path, &issue_id)
        .map_err(|e| AppError::Git(e.to_string()))?
    {
        Some(id) => id,
        None => {
            return Err(AppError::RepoNotFound(format!(
                "issue {issue_id} not found"
            )))
        }
    };

    let comments = state.db.list_issue_comments(&full_id).await?;
    Ok(Json(serde_json::json!({ "comments": comments })))
}

/// POST /api/v1/repos/{owner}/{repo}/issues/{id}/close
pub async fn close_issue(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, repo, issue_id)): Path<(String, String, String)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &repo)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    // AUTHORIZE BEFORE ACQUIRING. The per-repo advisory lock genuinely excludes
    // now, so taking it first would hand any caller with read access a way to hold
    // that lock on demand and be refused afterwards, while a legitimate writer
    // burned its retry budget against it. On a public repo that is every
    // permissionless identity. The lock must not be reachable by a caller who is
    // about to be refused the write.
    let is_owner = crate::api::require_repo_owner(&record, &auth.0).is_ok();
    if !is_owner {
        // Not the owner, so the author fallback decides it, and the author lives in
        // the issue's git-JSON blob rather than a DB column. Read it WITHOUT the
        // write lock: an issue's author is set at creation and never changes, so
        // reading it outside the lock races nothing. `acquire` ensures the repo is
        // on disk without taking the lock.
        let disk_path = state
            .repo_store
            .acquire(&record.owner_did, &record.name)
            .await
            .map_err(|e| AppError::Git(e.to_string()))?;
        let author_did: Option<String> = match git_issues::get_issue(&disk_path, &issue_id) {
            Ok(Some(raw)) => serde_json::from_str::<IssueRecord>(&raw)
                .ok()
                .and_then(|i| i.author),
            // Cannot establish authorship, so fail closed. Deliberately 403 rather
            // than 404 for a non-owner: a caller who is not authorized to write
            // should not learn from this route whether the issue exists.
            Ok(None) | Err(_) => None,
        };
        let is_author = author_did
            .as_deref()
            .is_some_and(|a| crate::api::did_matches(&auth.0, a));
        if !is_author {
            return Err(AppError::Forbidden(
                "only the repo owner or the issue author can close this issue".into(),
            ));
        }
    }

    // Authorized. Only now is the lock taken.
    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let disk_path = guard.path().to_path_buf();

    // Re-read under the guard so the mutation acts on current state, and keep the
    // owner's existing 404-for-a-missing-issue behavior.
    match git_issues::get_issue(&disk_path, &issue_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            guard.release(false).await;
            return Err(AppError::NotFound(format!("issue {issue_id} not found")));
        }
        Err(e) => {
            guard.release(false).await;
            return Err(AppError::Git(e.to_string()));
        }
    }

    let close_result = git_issues::close_issue(&disk_path, &issue_id);

    // Always release the advisory lock — even on error; upload to Tigris only on success.
    guard.release(close_result.is_ok()).await;

    let updated = close_result
        .map_err(|e| AppError::Git(e.to_string()))?
        .ok_or_else(|| AppError::RepoNotFound(format!("issue {issue_id} not found")))?;

    let issue: serde_json::Value = serde_json::from_str(&updated)
        .map_err(|e| AppError::BadRequest(format!("invalid issue data: {e}")))?;

    tracing::info!(repo = %repo, issue = %issue_id, "issue closed");

    Ok(Json(issue))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    /// U7: once the advisory lock actually excludes, taking it BEFORE authorizing
    /// turns close_issue into a wedge primitive. Any caller with repo read access
    /// (on a public repo, any permissionless identity) could take the per-repo
    /// write lock on demand and be refused the write afterwards, while the owner's
    /// push burned its retry budget against a lock held by someone with no write
    /// authorization.
    ///
    /// The observable: hold the lock from an independent session, then call the
    /// handler as a stranger. If it authorizes first it refuses immediately; if it
    /// acquires first it sits in the 60-attempt retry loop and the deadline fires.
    #[sqlx::test]
    async fn stranger_is_refused_without_waiting_on_the_write_lock(pool: PgPool) {
        use sqlx::Connection;
        let opts = (*pool.connect_options()).clone();
        let state = crate::test_support::test_state(pool.clone()).await;

        let owner = "did:key:z6MkU7Owner";
        state
            .db
            .upsert_mirror_repo("z6MkU7Owner", "u7repo", "/tmp/u7repo", None, true)
            .await
            .expect("seed repo");
        let record = state
            .db
            .get_repo("z6MkU7Owner", "u7repo")
            .await
            .expect("get_repo")
            .expect("repo exists");

        // An independent session holds the repo's write lock for the whole call.
        let key = crate::git::repo_store::advisory_lock_key_for_test(
            &record.owner_did.replace([':', '/'], "_"),
            &record.name,
        );
        let mut holder = sqlx::PgConnection::connect_with(&opts).await.unwrap();
        let held: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut holder)
            .await
            .unwrap();
        assert!(
            held.0,
            "the test must hold the lock for this to mean anything"
        );
        let _ = owner;

        let stranger = crate::auth::AuthenticatedDid("did:key:z6MkU7Stranger".to_string());
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            close_issue(
                axum::extract::State(state.clone()),
                axum::Extension(stranger),
                axum::extract::Path((
                    "z6MkU7Owner".to_string(),
                    "u7repo".to_string(),
                    "1".to_string(),
                )),
            ),
        )
        .await;

        let refused = outcome.expect(
            "a caller with no write authorization must be refused WITHOUT waiting on the \
             write lock; hitting this deadline means the handler tried to acquire first, \
             which is the wedge primitive",
        );
        assert!(
            matches!(refused, Err(AppError::Forbidden(_))),
            "expected 403 Forbidden for a stranger, got {:?}",
            refused.err().map(|e| format!("{e:?}"))
        );
    }
}
