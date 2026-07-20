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

    // Always release the advisory lock, even on error; upload to Tigris only on
    // success. A false return means the durable upload failed/timed out: the
    // issue ref applied to local disk but never reached object storage, so the
    // next acquire_write would revert it from the stale archive. Report 5xx so
    // the client retries rather than trusting an issue that never landed durably,
    // and skip the trust bump below. (Same P1 data-loss guard as receive-pack.)
    let upload_ok = guard.release(create_result.is_ok()).await;

    create_result.map_err(|e| AppError::Git(e.to_string()))?;

    if !upload_ok {
        tracing::error!(repo = %record.name,
            "durable upload failed after issue create; reporting failure so the client retries");
        return Err(AppError::Git(format!(
            "durable storage upload failed for {}",
            record.name
        )));
    }

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

    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let disk_path = guard.path().to_path_buf();

    // Owner OR issue author may close. The author lives in the issue's git-JSON
    // blob (not a DB column); a None author (legacy issues) falls back to
    // owner-only. Read it under the write guard, before mutating.
    let author_did: Option<String> = match git_issues::get_issue(&disk_path, &issue_id) {
        Ok(Some(raw)) => serde_json::from_str::<IssueRecord>(&raw)
            .ok()
            .and_then(|i| i.author),
        Ok(None) => {
            // release(false): no upload attempted, so the bool is always true
            // (nothing to fail on). Ignore it on this pre-write error path.
            let _ = guard.release(false).await;
            return Err(AppError::NotFound(format!("issue {issue_id} not found")));
        }
        Err(e) => {
            // release(false): no upload attempted, nothing to fail on.
            let _ = guard.release(false).await;
            return Err(AppError::Git(e.to_string()));
        }
    };
    let is_owner = crate::api::require_repo_owner(&record, &auth.0).is_ok();
    let is_author = author_did
        .as_deref()
        .is_some_and(|a| crate::api::did_matches(&auth.0, a));
    if !is_owner && !is_author {
        // release(false): no upload attempted, nothing to fail on.
        let _ = guard.release(false).await;
        return Err(AppError::Forbidden(
            "only the repo owner or the issue author can close this issue".into(),
        ));
    }

    let close_result = git_issues::close_issue(&disk_path, &issue_id);

    // Always release the advisory lock, even on error; upload to Tigris only on
    // success. A false return means the durable upload failed: the close applied
    // to local disk but never reached object storage, so a later acquire_write
    // reverts it. Report 5xx so the client retries. (P1 data-loss guard.)
    let upload_ok = guard.release(close_result.is_ok()).await;

    let updated = close_result
        .map_err(|e| AppError::Git(e.to_string()))?
        .ok_or_else(|| AppError::RepoNotFound(format!("issue {issue_id} not found")))?;

    if !upload_ok {
        tracing::error!(repo = %repo,
            "durable upload failed after issue close; reporting failure so the client retries");
        return Err(AppError::Git(format!(
            "durable storage upload failed for {}",
            record.name
        )));
    }

    let issue: serde_json::Value = serde_json::from_str(&updated)
        .map_err(|e| AppError::BadRequest(format!("invalid issue data: {e}")))?;

    tracing::info!(repo = %repo, issue = %issue_id, "issue closed");

    Ok(Json(issue))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path as AxPath, State};
    use axum::Extension;
    use std::path::Path as StdPath;
    use std::time::Duration;

    // Object store whose upload() parks forever, so release()'s bounded timeout
    // is the only thing that completes it, modeling a stalled durable PUT. exists()
    // is false so acquire_write never downloads over the fresh local bare repo.
    struct StallStore;
    #[async_trait::async_trait]
    impl crate::git::tigris::ObjectStore for StallStore {
        async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
        async fn upload(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
            std::future::pending::<()>().await;
            Ok(())
        }
        async fn download(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete(&self, _o: &str, _r: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    // P1-class data-loss regression, issue-create path. create_issue writes the
    // issue ref to local disk, then release(true) uploads the repo to durable
    // storage. When that upload times out the local write is NOT persisted, so
    // the next acquire_write reverts it from the stale archive. The pre-fix
    // handler ignored release()'s bool and still returned 201 AND bumped the
    // author's trust score, so the client trusted an issue that never landed
    // durably. The fix surfaces a failed/timed-out upload as a 5xx and skips the
    // success tail (the trust bump). Stall the upload past a tiny release timeout
    // and assert (a) the handler returns 5xx and (b) the trust bump did not run.
    // RED pre-fix: 201 + trust score bumped to 0.05.
    #[sqlx::test]
    async fn issue_create_durable_upload_timeout_fails_and_skips_side_effects(pool: sqlx::PgPool) {
        use axum::response::IntoResponse;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(StallStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));

        let owner = "z6issueownerdurablefail";
        let name = "issuedurablefail";
        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        // Public mirror repo so the owner clears authorize_repo_read, and a real
        // agent row so the post-write trust bump is an observable durable side
        // effect (register_agent seeds trust_score = 0.0).
        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();
        state.db.register_agent(owner, &[]).await.unwrap();

        std::fs::create_dir_all(&bare).unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "--bare", "-q", &bare.to_string_lossy()])
            .output()
            .unwrap();
        assert!(out.status.success(), "git init --bare failed");

        // acquire_write → git_issues::create_issue (writes the ref) → release
        // (upload stalls, times out after 200ms). The client MUST see a failure.
        let resp = super::create_issue(
            State(state.clone()),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            AxPath((owner.to_string(), name.to_string())),
            axum::Json(CreateIssueRequest {
                title: "t".into(),
                body: None,
                signed_payload: None,
            }),
        )
        .await;
        let status = match resp {
            Ok((code, _)) => code,
            Err(e) => e.into_response().status(),
        };
        assert!(
            status.is_server_error(),
            "a timed-out durable upload on issue-create must fail (5xx) so the \
             client retries (got {status}), which the client trusts as a landed \
             issue that a later acquire_write would silently revert"
        );

        // The success tail (trust bump) must NOT have run: the issue was never
        // durably accepted. register_agent seeded 0.0; a bump would make it 0.05.
        let score = state.db.get_trust_score(owner).await.unwrap();
        assert_eq!(
            score, 0.0,
            "the trust bump must NOT run when the durable upload failed; the \
             issue was not durably accepted (score bumped to {score})"
        );
    }
}
