//! Pull request API handlers.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::{PrComment, PrReview, PullRequest};
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
    // Authorize the caller as a reader before accepting a PR: a non-reader must
    // not be able to open a PR (and fire its webhooks) against a private repo
    // they cannot read. Mirrors create_review / create_comment / create_bounty.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;

    let author_did = auth.0;
    let target_branch = req
        .target_branch
        .unwrap_or_else(|| record.default_branch.clone());
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
    let current = state
        .db
        .get_trust_score(&pr.author_did)
        .await
        .unwrap_or(0.05);
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
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let prs = state.db.list_prs(&record.id).await?;
    Ok(Json(
        serde_json::json!({ "pulls": prs, "count": prs.len() }),
    ))
}

/// GET /api/v1/repos/:owner/:repo/pulls/:number
pub async fn get_pr(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<PullRequest>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    Ok(Json(pr))
}

/// GET /api/v1/repos/:owner/:repo/pulls/:number/diff
pub async fn get_pr_diff(
    State(state): State<AppState>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;

    // Withhold the entire diff if it touches a path the caller cannot read, so a
    // PR diff cannot leak private-subtree content of an otherwise-public repo.
    let touched = store::branch_diff_names(&disk_path, &pr.target_branch, &pr.source_branch)
        .map_err(|e| AppError::Git(e.to_string()))?;
    for p in &touched {
        let gate = format!("/{}", p.trim_start_matches('/'));
        if crate::visibility::visibility_check(
            &rules,
            record.is_public,
            &record.owner_did,
            caller,
            &gate,
        ) == crate::visibility::Decision::Deny
        {
            return Err(AppError::NotFound(format!("PR #{number} not found")));
        }
    }

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
    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    // Owner-only merge (N7). Merging writes the served tree, so this is the same
    // trust boundary as owner-only push; it subsumes branch protection (a
    // non-owner cannot merge to any branch, protected or not).
    crate::api::require_repo_owner(&record, &auth.0)?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    if pr.status != "open" {
        return Err(AppError::BadRequest(format!("PR is already {}", pr.status)));
    }

    let guard = state
        .repo_store
        .acquire_write(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let disk_path = guard.path().to_path_buf();
    let merger_did = auth.0;

    // Snapshot the target branch's pre-merge tip so a failed durable upload can
    // roll the merge commit back on local disk (mirrors create_issue). Without
    // this the local fast path in RepoStore::acquire serves the merged tree until
    // a later write refreshes the archive, even though the client got a 5xx.
    let target_ref = format!("refs/heads/{}", pr.target_branch);
    let prior_target = store::ref_oid(&disk_path, &target_ref).ok().flatten();

    let merge_result = store::merge_branch(
        &disk_path,
        &pr.target_branch,
        &pr.source_branch,
        &merger_did,
        &pr.title,
    );

    // Always release the advisory lock, even on error; upload to Tigris only on
    // success. A false return means the durable upload failed/timed out: the merge
    // commit applied to local disk but never reached object storage, so the next
    // acquire_write reverts it from the stale archive. Report 5xx so the client
    // retries rather than marking the PR merged in the DB while the merged tree
    // was silently lost. Fail BEFORE merge_pr / touch_repo / webhooks. (P1
    // data-loss guard, same as receive-pack.) On that failure, roll the local
    // merge back to the captured tip BEFORE the lock releases.
    let upload_ok = guard
        .release_with_failure_cleanup(merge_result.is_ok(), |path| {
            if let Some(oid) = &prior_target {
                if let Err(e) = store::set_ref(path, &target_ref, oid) {
                    tracing::warn!(repo = %record.name, err = %e,
                        "failed to roll back local merge commit after failed durable upload; \
                         a local-fast-path read may serve the un-uploaded merged tree");
                }
            }
        })
        .await;

    let merge_sha = merge_result.map_err(|e| AppError::Git(e.to_string()))?;

    if !upload_ok {
        tracing::error!(repo = %record.name,
            "durable upload failed after merge; reporting failure so the client retries");
        return Err(AppError::Git(format!(
            "durable storage upload failed for {}",
            record.name
        )));
    }

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
    Extension(auth): Extension<AuthenticatedDid>,
    Path((owner, name, number)): Path<(String, String, i64)>,
) -> Result<Json<serde_json::Value>> {
    let record = state
        .db
        .get_repo(&owner, &name)
        .await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    // Owner OR author may close (forge norm).
    let is_owner = crate::api::require_repo_owner(&record, &auth.0).is_ok();
    let is_author = crate::api::did_matches(&auth.0, &pr.author_did);
    if !is_owner && !is_author {
        return Err(AppError::Forbidden(
            "only the repo owner or the PR author can close this PR".into(),
        ));
    }

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
    // Read-gate: a reviewer must be able to read the repo, but need not own it.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let valid_statuses = ["approved", "changes_requested", "comment"];
    if !valid_statuses.contains(&req.status.as_str()) {
        return Err(AppError::BadRequest(
            "status must be approved, changes_requested, or comment".into(),
        ));
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
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
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
        return Err(AppError::BadRequest(
            "comment body must not be empty".into(),
        ));
    }

    // Read-gate: a commenter must be able to read the repo, but need not own it.
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
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
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, caller, "/").await?;

    let pr = state
        .db
        .get_pr(&record.id, number)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("PR #{number} not found")))?;

    let comments = state.db.list_pr_comments(&pr.id).await?;
    Ok(Json(serde_json::json!({ "comments": comments })))
}

#[cfg(test)]
mod tests {
    // super::* brings in the handler plus the axum Extension/Path/State
    // extractors and the Utc/Uuid/PullRequest types the seed uses.
    use super::*;
    use std::path::Path as StdPath;
    use std::time::Duration;

    // Object store whose upload() parks forever, so release()'s bounded timeout
    // is the only thing that completes it, modeling a stalled durable PUT.
    // exists() is false so acquire_write never downloads over the local bare repo.
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

    // The failed-upload rollback on the merge path. merge_pr writes the merge
    // commit to LOCAL disk, then release() uploads to durable storage. When
    // that upload times out the handler must 5xx (before merge_pr/webhooks)
    // AND roll the target branch back to its pre-merge tip while the advisory
    // lock is held, so a local-fast-path read never serves the un-uploaded
    // merged tree. RED with the cleanup closure at ~pulls.rs:244 reverted to
    // `|_| {}`: main stays at the merge commit.
    #[sqlx::test]
    async fn merge_failed_upload_rolls_back_target_ref(pool: sqlx::PgPool) {
        use axum::response::IntoResponse;
        use std::process::Command;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        let repos_dir = tempfile::TempDir::new().unwrap();
        state.repo_store = crate::git::repo_store::RepoStore::new(
            repos_dir.path().to_path_buf(),
            Some(std::sync::Arc::new(StallStore)),
            pool.clone(),
        )
        .with_release_upload_timeout(Duration::from_millis(200));

        let owner = "z6mergerollbackowner";
        let name = "mergerollback";
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

        fn git(args: &[&str], dir: &StdPath) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        // Scratch repo: c1 on main, c2 on feature; the bare clone carries both
        // branches, so the merge of feature into main has real work to do.
        let work = tempfile::TempDir::new().unwrap();
        git(&["init", "-q", "-b", "main", "."], work.path());
        git(&["config", "user.email", "t@t"], work.path());
        git(&["config", "user.name", "t"], work.path());
        std::fs::write(work.path().join("f.txt"), "one").unwrap();
        git(&["add", "f.txt"], work.path());
        git(&["commit", "-q", "-m", "c1"], work.path());
        git(&["checkout", "-q", "-b", "feature"], work.path());
        std::fs::write(work.path().join("g.txt"), "two").unwrap();
        git(&["add", "g.txt"], work.path());
        git(&["commit", "-q", "-m", "c2"], work.path());

        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "clone --bare failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let pre_merge_tip = store::ref_oid(&bare, "refs/heads/main")
            .unwrap()
            .expect("main exists before the merge");

        // Seed the open PR row the handler looks up.
        let record = state.db.get_repo(owner, name).await.unwrap().unwrap();
        let now = Utc::now().to_rfc3339();
        state
            .db
            .create_pr(&PullRequest {
                id: Uuid::new_v4().to_string(),
                repo_id: record.id.clone(),
                number: 1,
                title: "t".into(),
                body: None,
                author_did: owner.to_string(),
                source_branch: "feature".into(),
                target_branch: "main".into(),
                status: "open".to_string(),
                merged_by_did: None,
                merged_at: None,
                created_at: now.clone(),
                updated_at: now,
            })
            .await
            .unwrap();

        // Merge as the owner: the merge commit applies locally, the durable
        // upload stalls and times out, and the handler must report 5xx.
        let resp = super::merge_pr(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), name.to_string(), 1)),
        )
        .await;
        let status = match resp {
            Ok(_) => StatusCode::OK,
            Err(e) => e.into_response().status(),
        };
        assert!(
            status.is_server_error(),
            "a stalled durable upload on merge must 5xx, got {status}"
        );

        // The target branch must still point at the pre-merge tip: the failed
        // upload rolled the merge commit back while the lock was held.
        let tip = store::ref_oid(&bare, "refs/heads/main")
            .unwrap()
            .expect("main still exists after the rollback");
        assert_eq!(
            tip, pre_merge_tip,
            "a failed durable upload must roll the target branch back to its \
             pre-merge tip; a local-fast-path read served the un-uploaded merge"
        );
    }
}
