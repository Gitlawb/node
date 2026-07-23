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
    // On that failure, roll back the local ref BEFORE the lock releases — an
    // orphan ref would make the retry a duplicate, and in an unlock-to-delete
    // window a concurrent same-repo write could upload an archive still
    // carrying it. Best-effort: a failed delete logs and the 5xx still returns.
    let upload_ok = guard
        .release_with_failure_cleanup(create_result.is_ok(), |path| {
            if let Err(e) = git_issues::delete_issue_ref(path, &issue_id) {
                tracing::warn!(issue = %issue_id, err = %e,
                    "failed to roll back local issue ref after failed durable upload; \
                     a retry may duplicate this issue");
            }
        })
        .await;

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

    // Snapshot the issue ref's pre-close OID so a failed durable upload can roll
    // the close back on local disk, mirroring create_issue. Best-effort: if the
    // snapshot read fails we proceed without a rollback closure (the close still
    // applies and a failed upload still surfaces as a 5xx below).
    let prior_ref = git_issues::issue_ref_oid(&disk_path, &issue_id)
        .ok()
        .flatten();

    let close_result = git_issues::close_issue(&disk_path, &issue_id);

    // Always release the advisory lock, even on error; upload to Tigris only on
    // success. A false return means the durable upload failed: the close applied
    // to local disk but never reached object storage, so a later acquire_write
    // reverts it. Report 5xx so the client retries. (P1 data-loss guard.)
    // On that failure, roll the local close BACK to the captured open ref BEFORE
    // the lock releases — otherwise the local fast path in RepoStore::acquire
    // serves the "closed" state until a later write refreshes the archive, even
    // though the client got a 5xx. The cleanup runs only when an upload was
    // attempted and failed, while the advisory lock is still held.
    let upload_ok = guard
        .release_with_failure_cleanup(close_result.is_ok(), |path| {
            if let Some((full_id, oid)) = &prior_ref {
                if let Err(e) = git_issues::restore_issue_ref(path, full_id, oid) {
                    tracing::warn!(issue = %issue_id, err = %e,
                        "failed to roll back local issue close after failed durable upload; \
                         a local-fast-path read may serve a stale closed state");
                }
            }
        })
        .await;

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

    // Object store whose upload succeeds immediately. exists() is false so
    // acquire_write never performs a reverting refresh over the local dir —
    // the retry test below pins that contract explicitly.
    struct OkStore;
    #[async_trait::async_trait]
    impl crate::git::tigris::ObjectStore for OkStore {
        async fn exists(&self, _o: &str, _r: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
        async fn upload(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
            Ok(())
        }
        async fn download(&self, _o: &str, _r: &str, _p: &StdPath) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete(&self, _o: &str, _r: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    // Shared setup for the failed-upload rollback tests: a state whose repo
    // store stalls uploads (200ms release timeout), a public repo row for
    // `owner/name`, and an initialized bare repo at the returned path.
    async fn stall_state_with_repo(
        pool: sqlx::PgPool,
        repos_dir: &tempfile::TempDir,
        owner: &str,
        name: &str,
    ) -> (crate::state::AppState, std::path::PathBuf) {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(StallStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));

        let owner_slug = owner.replace([':', '/'], "_");
        let bare = repos_dir
            .path()
            .join(&owner_slug)
            .join(format!("{name}.git"));

        state
            .db
            .upsert_mirror_repo(owner, name, &bare.to_string_lossy(), None, false)
            .await
            .unwrap();

        std::fs::create_dir_all(&bare).unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "--bare", "-q", &bare.to_string_lossy()])
            .output()
            .unwrap();
        assert!(out.status.success(), "git init --bare failed");

        (state, bare)
    }

    async fn create_issue_status(
        state: &crate::state::AppState,
        owner: &str,
        name: &str,
    ) -> axum::http::StatusCode {
        use axum::response::IntoResponse;
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
        match resp {
            Ok((code, _)) => code,
            Err(e) => e.into_response().status(),
        }
    }

    async fn close_issue_status(
        state: &crate::state::AppState,
        owner: &str,
        name: &str,
        issue_id: &str,
    ) -> axum::http::StatusCode {
        use axum::response::IntoResponse;
        let resp = super::close_issue(
            State(state.clone()),
            Extension(crate::auth::AuthenticatedDid(owner.to_string())),
            AxPath((owner.to_string(), name.to_string(), issue_id.to_string())),
        )
        .await;
        match resp {
            Ok(_) => axum::http::StatusCode::OK,
            Err(e) => e.into_response().status(),
        }
    }

    // Seed an OPEN issue directly on local disk, bypassing the (stalling) upload
    // path so the close test starts from a durably-consistent open issue.
    fn seed_open_issue(bare: &StdPath, owner: &str, issue_id: &str) {
        let issue = IssueRecord {
            id: issue_id.to_string(),
            title: "t".into(),
            body: None,
            author: Some(owner.to_string()),
            created_at: Utc::now().to_rfc3339(),
            status: "open".to_string(),
            signed_payload: None,
        };
        let json = serde_json::to_string(&issue).unwrap();
        git_issues::create_issue(bare, issue_id, &json).unwrap();
    }

    fn issue_status(bare: &StdPath, issue_id: &str) -> String {
        let raw = git_issues::get_issue(bare, issue_id).unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["status"].as_str().unwrap().to_string()
    }

    // U2 [F2, P1] — the failed-upload rollback on the close path. close_issue
    // applies the "closed" ref to LOCAL disk, then release() uploads to durable
    // storage. When that upload times out the local close is NOT persisted, so a
    // later acquire_write reverts it from the stale archive — but until then, a
    // local-fast-path read via RepoStore::acquire serves the stale "closed"
    // state even though the client got a 5xx. The fix rolls the close back to the
    // captured open ref while the advisory lock is held. RED with the cleanup
    // closure reverted to `|_| {}`: the read sees "closed".
    #[sqlx::test]
    async fn issue_close_failed_upload_rolls_back_to_open(pool: sqlx::PgPool) {
        let repos_dir = tempfile::TempDir::new().unwrap();
        let owner = "z6issuecloserollbackowner";
        let name = "issuecloserollback";
        let (state, bare) = stall_state_with_repo(pool, &repos_dir, owner, name).await;

        let issue_id = "aaaa1111-0000-0000-0000-000000000000";
        seed_open_issue(&bare, owner, issue_id);
        assert_eq!(issue_status(&bare, issue_id), "open", "seed must be open");

        // Close via the handler — the durable upload stalls and times out (5xx).
        let status = close_issue_status(&state, owner, name, issue_id).await;
        assert!(
            status.is_server_error(),
            "a stalled durable upload on issue-close must 500, got {status}"
        );

        // The local fast path must still see the issue OPEN: the failed upload
        // rolled the close back while the lock was held.
        assert_eq!(
            issue_status(&bare, issue_id),
            "open",
            "a failed durable upload must roll the local close back to open; a \
             local-fast-path read served the stale closed state"
        );
    }

    // Success path: a working store closes the issue (2xx) and the read reflects
    // the close. Confirms the rollback wiring does not fire on success.
    #[sqlx::test]
    async fn issue_close_success_persists_close(pool: sqlx::PgPool) {
        let repos_dir = tempfile::TempDir::new().unwrap();
        let owner = "z6issueclosesuccessowner";
        let name = "issueclosesuccess";
        let (mut state, bare) = stall_state_with_repo(pool.clone(), &repos_dir, owner, name).await;
        // Swap the stalling store for one whose upload succeeds immediately.
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(OkStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));

        let issue_id = "bbbb2222-0000-0000-0000-000000000000";
        seed_open_issue(&bare, owner, issue_id);

        let status = close_issue_status(&state, owner, name, issue_id).await;
        assert_eq!(status, StatusCode::OK, "working store must close (200)");
        assert_eq!(
            issue_status(&bare, issue_id),
            "closed",
            "a successful close must persist as closed"
        );
    }

    // Pre-write error path: closing a nonexistent issue returns 404 and never
    // attempts an upload (release(false)), so the stalling store cannot hang it.
    #[sqlx::test]
    async fn issue_close_not_found_releases_without_upload(pool: sqlx::PgPool) {
        let repos_dir = tempfile::TempDir::new().unwrap();
        let owner = "z6issueclosemissingowner";
        let name = "issueclosemissing";
        let (state, _bare) = stall_state_with_repo(pool, &repos_dir, owner, name).await;

        let status =
            close_issue_status(&state, owner, name, "cccc3333-0000-0000-0000-000000000000").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "closing a missing issue must 404 without attempting an upload"
        );
    }

    fn issue_refs(bare: &StdPath) -> Vec<String> {
        let out = std::process::Command::new("git")
            .args([
                "for-each-ref",
                "--format=%(refname)",
                "refs/gitlawb/issues/",
            ])
            .current_dir(bare)
            .output()
            .unwrap();
        assert!(out.status.success(), "git for-each-ref failed");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .collect()
    }

    // Rollback half of the #196 round-four issue-create fix. When the durable
    // upload fails/times out, the handler 500s (covered below) — but the issue
    // ref it wrote to LOCAL disk must also be rolled back, while the advisory
    // lock is still held. An orphan ref makes the 500 dishonest: a retry
    // re-creates the issue under a new uuid while the orphan is still listed,
    // and a concurrent same-repo write can upload an archive carrying it.
    // RED pre-fix: the orphan ref survives the failed create.
    #[sqlx::test]
    async fn issue_create_failed_upload_rolls_back_local_ref(pool: sqlx::PgPool) {
        let repos_dir = tempfile::TempDir::new().unwrap();
        let owner = "z6issuerollbackowner";
        let name = "issuerollback";
        let (state, bare) = stall_state_with_repo(pool, &repos_dir, owner, name).await;

        let status = create_issue_status(&state, owner, name).await;
        assert!(
            status.is_server_error(),
            "stalled upload must 500, got {status}"
        );

        let refs = issue_refs(&bare);
        assert!(
            refs.is_empty(),
            "a failed durable upload must roll back the local issue ref while \
             the advisory lock is held; orphan ref(s) survived: {refs:?}"
        );
    }

    // Retry half: after the failed-upload 500, a retry with a WORKING store
    // must yield exactly one issue. Pre-fix the orphan ref from the failed
    // attempt makes the retry a duplicate (two issues in list_issues).
    #[sqlx::test]
    async fn issue_create_failed_upload_retry_does_not_duplicate(pool: sqlx::PgPool) {
        use crate::git::tigris::ObjectStore as _;

        let repos_dir = tempfile::TempDir::new().unwrap();
        let owner = "z6issueretryowner";
        let name = "issueretry";
        let (state, bare) = stall_state_with_repo(pool.clone(), &repos_dir, owner, name).await;

        let status = create_issue_status(&state, owner, name).await;
        assert!(
            status.is_server_error(),
            "stalled upload must 500, got {status}"
        );

        // PIN the double's contract: exists() stays false after the failed
        // upload, so the retry's acquire_write performs no reverting refresh
        // from a stale archive. Without this pin, a download could revert the
        // orphan ref and the assertion below would pass without the rollback
        // fix — it must rest on the rollback, not a stale-archive revert.
        let owner_slug = owner.replace([':', '/'], "_");
        assert!(
            !OkStore.exists(&owner_slug, name).await.unwrap(),
            "test double contract broken: exists() must stay false"
        );

        // Retry with a store whose upload succeeds.
        let mut retry_state = state.clone();
        retry_state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(OkStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));

        let status = create_issue_status(&retry_state, owner, name).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "retry with working store must 201"
        );

        let issues = crate::git::issues::list_issues(&bare).unwrap();
        assert_eq!(
            issues.len(),
            1,
            "retry after a failed-upload 500 must yield exactly ONE issue; the \
             failed attempt's orphan ref duplicated it (got {} issues)",
            issues.len()
        );
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
