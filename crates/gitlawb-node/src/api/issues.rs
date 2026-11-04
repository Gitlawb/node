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

    // Shed 503 + Retry-After on an exhausted write-lock POOL instead of a generic
    // git 500 (#173 F1). This path holds no admission permit, so it reaches the pool
    // unthrottled; reuse the push handler's mapping so the two cannot drift.
    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await
        .map_err(|e| crate::api::repos::acquire_write_app_error(&e, &repo))?;
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

    // Same capacity shed as create_issue above (#173 F1): an exhausted write-lock
    // pool is a 503 + Retry-After, not a 500 git error.
    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await
        .map_err(|e| crate::api::repos::acquire_write_app_error(&e, &repo))?;
    let disk_path = guard.path().to_path_buf();

    // Owner OR issue author may close. The author lives in the issue's git-JSON
    // blob (not a DB column); a None author (legacy issues) falls back to
    // owner-only. Read it under the write guard, before mutating.
    let author_did: Option<String> = match git_issues::get_issue(&disk_path, &issue_id) {
        Ok(Some(raw)) => serde_json::from_str::<IssueRecord>(&raw)
            .ok()
            .and_then(|i| i.author),
        Ok(None) => {
            guard.release(false).await;
            return Err(AppError::NotFound(format!("issue {issue_id} not found")));
        }
        Err(e) => {
            guard.release(false).await;
            return Err(AppError::Git(e.to_string()));
        }
    };
    let is_owner = crate::api::require_repo_owner(&record, &auth.0).is_ok();
    let is_author = author_did
        .as_deref()
        .is_some_and(|a| crate::api::did_matches(&auth.0, a));
    if !is_owner && !is_author {
        guard.release(false).await;
        return Err(AppError::Forbidden(
            "only the repo owner or the issue author can close this issue".into(),
        ));
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

/// #173 F1 follow-up: the two issue write paths reach `acquire_write` holding NO
/// admission permit (unlike the push handler, which is capped by the git-push
/// semaphore), so they are the callers most likely to meet an exhausted write-lock
/// POOL under load. An exhausted pool is a capacity signal, so both must shed
/// 503 + Retry-After (`AppError::Overloaded`) the way the push handler does, not
/// report the generic 500 git error that says nothing about retrying.
#[cfg(test)]
mod lock_pool_shed_tests {
    use super::*;
    use axum::response::IntoResponse;
    use sqlx::PgPool;

    fn seed_repo(owner_did: &str, name: &str) -> crate::db::RepoRecord {
        let now = Utc::now();
        crate::db::RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{name}"),
            forked_from: None,
            machine_id: None,
        }
    }

    /// State whose repo store draws write locks from a ONE-connection pool with a
    /// short checkout timeout, so a single held guard exhausts it promptly rather
    /// than at the pool default.
    async fn one_connection_lock_pool_state(pool: &PgPool) -> AppState {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            std::path::PathBuf::from("/tmp/gitlawb-issues-lockpool"),
            None,
            crate::git::repo_store::build_lock_pool(pool, 1, std::time::Duration::from_secs(1)),
        );
        state
    }

    /// The shed must be a real 503 carrying Retry-After, not just an internal enum
    /// variant: assert on the rendered response so a remapping of `Overloaded` is
    /// caught here too.
    fn assert_sheds_503_with_retry_after(err: AppError, what: &str) {
        let resp = err.into_response();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{what}: an exhausted write-lock pool must shed 503, not a 500 git error"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap()),
            Some("1"),
            "{what}: a capacity shed must tell the client when to retry"
        );
    }

    /// RED-before/GREEN-after for `create_issue`. Both directions: the shed while the
    /// only lock-pool connection is held by a guard on a DIFFERENT repo (so this is
    /// pool capacity, not advisory-lock contention on this repo), and the must-not
    /// case once that connection is back.
    #[sqlx::test]
    async fn create_issue_lock_pool_exhaustion_sheds_503_not_500(pool: PgPool) {
        let owner = "did:key:zISSUECREATELOCKPOOLAAAAAAAAAAAAAAAAAAAA";
        let state = one_connection_lock_pool_state(&pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "lp-create"))
            .await
            .expect("seed repo");

        let held = state
            .repo_store
            .acquire_write(owner, "other-repo")
            .await
            .expect("the first write takes the only lock-pool connection");

        let shed = create_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), "lp-create".to_string())),
            Json(CreateIssueRequest {
                title: "t".to_string(),
                body: None,
                signed_payload: None,
            }),
        )
        .await;
        let err = shed.expect_err("an exhausted lock pool must fail the call");
        assert_sheds_503_with_retry_after(err, "create_issue");

        // MUST-NOT: with the pool free again the call is not shed as capacity (it
        // fails later on the nonexistent on-disk repo, which is a git 500).
        held.release(false).await;
        let admitted = create_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), "lp-create".to_string())),
            Json(CreateIssueRequest {
                title: "t".to_string(),
                body: None,
                signed_payload: None,
            }),
        )
        .await;
        assert!(
            !matches!(admitted, Err(AppError::Overloaded(_))),
            "with the lock pool free, create_issue must not be shed as capacity; got {:?}",
            admitted.err()
        );
    }

    /// RED-before/GREEN-after for `close_issue`, same two directions.
    #[sqlx::test]
    async fn close_issue_lock_pool_exhaustion_sheds_503_not_500(pool: PgPool) {
        let owner = "did:key:zISSUECLOSELOCKPOOLBBBBBBBBBBBBBBBBBBBBB";
        let state = one_connection_lock_pool_state(&pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "lp-close"))
            .await
            .expect("seed repo");

        let held = state
            .repo_store
            .acquire_write(owner, "other-repo")
            .await
            .expect("the first write takes the only lock-pool connection");

        let shed = close_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((
                owner.to_string(),
                "lp-close".to_string(),
                "deadbeef".to_string(),
            )),
        )
        .await;
        let err = shed.expect_err("an exhausted lock pool must fail the call");
        assert_sheds_503_with_retry_after(err, "close_issue");

        held.release(false).await;
        let admitted = close_issue(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((
                owner.to_string(),
                "lp-close".to_string(),
                "deadbeef".to_string(),
            )),
        )
        .await;
        assert!(
            !matches!(admitted, Err(AppError::Overloaded(_))),
            "with the lock pool free, close_issue must not be shed as capacity; got {:?}",
            admitted.err()
        );
    }
}

/// #426: end-to-end at the handler seam. A corrupt object store behind a
/// resolving issue ref used to look identical to an absent issue: get returned
/// a fake 404, close returned a fake 404 after releasing the write guard, and
/// list silently under-reported. All three must now surface a git error.
#[cfg(test)]
mod corrupt_store_tests {
    use super::*;
    use axum::response::IntoResponse;
    use sqlx::PgPool;
    use tempfile::TempDir;

    fn seed_repo(owner_did: &str, name: &str) -> crate::db::RepoRecord {
        let now = Utc::now();
        crate::db::RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{name}"),
            forked_from: None,
            machine_id: None,
        }
    }

    /// A state whose repo store roots in `repos_dir`, so the test can lay down
    /// a real repo and then corrupt it without touching /tmp.
    async fn state_with_repos_dir(pool: &PgPool, repos_dir: &std::path::Path) -> AppState {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.repo_store =
            crate::git::repo_store::RepoStore::for_testing(repos_dir.to_path_buf(), pool.clone());
        state
    }

    /// Bare repo at the store's expected path, holding one issue ref.
    fn bare_repo_with_issue(
        repos_dir: &std::path::Path,
        owner: &str,
        name: &str,
    ) -> (std::path::PathBuf, String) {
        let repo_path = repos_dir
            .join(owner.replace([':', '/'], "_"))
            .join(format!("{name}.git"));
        std::fs::create_dir_all(&repo_path).unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "--bare"])
            .arg(&repo_path)
            .output()
            .unwrap();
        assert!(out.status.success());
        let issue_id = "aaaabbbb-0000-0000-0000-000000000000".to_string();
        git_issues::create_issue(
            &repo_path,
            &issue_id,
            &serde_json::json!({
                "id": issue_id,
                "title": "t",
                "status": "open",
            })
            .to_string(),
        )
        .unwrap();
        (repo_path, issue_id)
    }

    /// Delete the blob object behind the issue ref and put garbage in its
    /// place: `cat-file` fails while `rev-parse` still resolves the ref.
    fn corrupt_issue_object(repo_path: &std::path::Path, issue_id: &str) {
        let out = std::process::Command::new("git")
            .args(["rev-parse", &format!("refs/gitlawb/issues/{issue_id}")])
            .current_dir(repo_path)
            .output()
            .unwrap();
        let oid = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let obj = repo_path.join("objects").join(&oid[..2]).join(&oid[2..]);
        std::fs::remove_file(&obj).unwrap();
        std::fs::write(&obj, b"garbage").unwrap();
    }

    /// The regression: closing over a corrupt store used to return a fake 404
    /// (or panic deeper in). It must reach the caller as a git 500, and the
    /// handler must return rather than unwind.
    #[sqlx::test]
    async fn close_issue_on_corrupt_store_returns_git_error_not_panic(pool: PgPool) {
        let owner = "did:key:zISSUECORRUPTCCCCCCCCCCCCCCCCCCCCCCCCC";
        let dir = TempDir::new().unwrap();
        let state = state_with_repos_dir(&pool, dir.path()).await;
        state
            .db
            .create_repo(&seed_repo(owner, "corrupt-close"))
            .await
            .expect("seed repo");
        let (repo_path, issue_id) = bare_repo_with_issue(dir.path(), owner, "corrupt-close");
        corrupt_issue_object(&repo_path, &issue_id);

        let err = close_issue(
            State(state),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), "corrupt-close".to_string(), issue_id)),
        )
        .await
        .expect_err("a corrupt store must error, not panic or 404");
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a read failure is a git 500, not a fake not-found"
        );
    }

    /// get on a corrupt store: 500, not the 404 the fold used to produce.
    #[sqlx::test]
    async fn get_issue_on_corrupt_store_returns_500_not_404(pool: PgPool) {
        let owner = "did:key:zISSUECORRUPTGETDDDDDDDDDDDDDDDDDDDDDDD";
        let dir = TempDir::new().unwrap();
        let state = state_with_repos_dir(&pool, dir.path()).await;
        state
            .db
            .create_repo(&seed_repo(owner, "corrupt-get"))
            .await
            .expect("seed repo");
        let (repo_path, issue_id) = bare_repo_with_issue(dir.path(), owner, "corrupt-get");
        corrupt_issue_object(&repo_path, &issue_id);

        let err = get_issue(
            State(state),
            Path((owner.to_string(), "corrupt-get".to_string(), issue_id)),
            None,
        )
        .await
        .expect_err("a corrupt store must error, not 404");
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    /// list on a corrupt store must fail outright; a 200 that silently drops
    /// the unreadable issue is the other half of the fold.
    #[sqlx::test]
    async fn list_issues_on_corrupt_store_returns_git_error(pool: PgPool) {
        let owner = "did:key:zISSUECORRUPTLISTEEEEEEEEEEEEEEEEEEEEEE";
        let dir = TempDir::new().unwrap();
        let state = state_with_repos_dir(&pool, dir.path()).await;
        state
            .db
            .create_repo(&seed_repo(owner, "corrupt-list"))
            .await
            .expect("seed repo");
        let (repo_path, issue_id) = bare_repo_with_issue(dir.path(), owner, "corrupt-list");
        corrupt_issue_object(&repo_path, &issue_id);

        let err = list_issues(
            State(state),
            Path((owner.to_string(), "corrupt-list".to_string())),
            None,
        )
        .await
        .expect_err("a corrupt store must error, not under-report");
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    /// Must-not direction: a genuinely absent issue still gets the 404.
    #[sqlx::test]
    async fn get_issue_on_absent_ref_still_returns_404(pool: PgPool) {
        let owner = "did:key:zISSUEABSENTFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let dir = TempDir::new().unwrap();
        let state = state_with_repos_dir(&pool, dir.path()).await;
        state
            .db
            .create_repo(&seed_repo(owner, "absent-get"))
            .await
            .expect("seed repo");
        bare_repo_with_issue(dir.path(), owner, "absent-get");

        let err = get_issue(
            State(state),
            Path((
                owner.to_string(),
                "absent-get".to_string(),
                "ffffffff-0000-0000-0000-000000000000".to_string(),
            )),
            None,
        )
        .await
        .expect_err("a missing issue is still not-found");
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }
}
