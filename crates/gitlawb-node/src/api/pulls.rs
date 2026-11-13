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

    // Validate both refs before they are stored, since both are later
    // interpolated into git argv (git diff / worktree add / merge). Validate the
    // RESOLVED target, not just a caller-supplied one: create_repo also gates
    // default_branch, but validating here as well means a PR can never feed the
    // git sink an unchecked ref even if a default was poisoned by an older row
    // or a future path that skips create_repo's gate.
    crate::api::validate_git_ref_with_git(&state.git_bin, &req.source_branch)
        .map_err(crate::api::map_git_ref_validation_error)?;
    crate::api::validate_git_ref_with_git(&state.git_bin, &target_branch)
        .map_err(crate::api::map_git_ref_validation_error)?;
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
        std::sync::Arc::clone(&state.webhook_secret_key),
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
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;

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
        .map_err(|e| crate::api::repos::acquire_write_app_error(&e, &name))?;
    let disk_path = guard.path().to_path_buf();
    let merger_did = auth.0;

    // Snapshot the target ref's pre-merge OID so a refused durable upload can
    // rewind the local merge, mirroring the close_issue / create_issue
    // compensating pattern. A read failure or an absent ref (a first-commit
    // merge onto an unborn branch) yields no rollback closure: the merge still
    // applies and a refused publish still surfaces as 5xx.
    let target_ref = format!("refs/heads/{}", pr.target_branch);
    let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
    let prior_tip = store::read_ref_bounded(&state.git_bin, &disk_path, &target_ref, git_timeout)
        .await
        .ok()
        .flatten();

    let merge_result = store::merge_branch(
        &disk_path,
        &pr.target_branch,
        &pr.source_branch,
        &merger_did,
        &pr.title,
    );

    // Always release the advisory lock — even on error; upload to Tigris only on success.
    // Short-circuit on a refused publish before the PR is marked merged and
    // before the webhook fires. Both are irreversible announcements of a merge
    // commit that only exists on this node's disk.
    let release_result = match (merge_result.is_ok(), prior_tip) {
        (true, Some(tip)) => {
            let git_bin = state.git_bin.clone();
            let deadline = std::time::Instant::now() + git_timeout;
            guard
                .release_compensating(true, move |path| {
                    crate::git::visibility_pack::run_bounded_git(
                        &git_bin,
                        &["update-ref", &target_ref, &tip],
                        path,
                        b"",
                        deadline,
                    )
                    .map(|_| ())
                })
                .await
                .into_result()
        }
        _ => guard.release(merge_result.is_ok()).await.into_result(),
    };
    release_result?;

    let merge_sha = merge_result.map_err(|e| AppError::Git(e.to_string()))?;

    state.db.merge_pr(&pr.id, &merger_did).await?;
    let _ = state.db.touch_repo(&record.id).await;

    webhooks::fire_event(
        std::sync::Arc::clone(&state.db),
        std::sync::Arc::clone(&state.http_client),
        std::sync::Arc::clone(&state.webhook_secret_key),
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
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &name, Some(auth.0.as_str()), "/").await?;

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
        std::sync::Arc::clone(&state.webhook_secret_key),
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
        std::sync::Arc::clone(&state.webhook_secret_key),
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
mod merge_rollback_tests {
    use super::*;
    use axum::response::IntoResponse;
    use sqlx::PgPool;

    fn git(dir: &std::path::Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .args(["-C", &*dir.to_string_lossy()])
            .args([
                "-c",
                "user.name=merge-rollback-test",
                "-c",
                "user.email=merge-rollback-test@example.com",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Build a bare repo whose `main` and `feature` refs diverge: one root
    /// commit on main, one commit on feature, so merge_branch creates a real
    /// merge commit that a refused publish must rewind.
    fn seeded_merge_repo(dir: &std::path::Path) -> (String, String) {
        crate::git::store::init_bare(dir).expect("bare repo");
        let empty_tree = git(dir, &["mktree"]);
        let root = git(dir, &["commit-tree", &empty_tree, "-m", "root"]);
        git(dir, &["update-ref", "refs/heads/main", &root]);
        let tip2 = git(
            dir,
            &["commit-tree", &empty_tree, "-m", "feature", "-p", &root],
        );
        git(dir, &["update-ref", "refs/heads/feature", &tip2]);
        (root, tip2)
    }

    /// On a definite publish refusal, the local merge commit must be rewound:
    /// the client got a 5xx, so the repo cannot show a merge the mirror never
    /// learned about (same contract create_issue's rollback enforces).
    #[sqlx::test]
    async fn merge_pr_rewinds_local_merge_when_publish_refuses(pool: PgPool) {
        // Endpoint that answers HEAD with an etag but refuses every write.
        let app = axum::Router::new().route(
            "/{*key}",
            axum::routing::any(|method: axum::http::Method| async move {
                if method == axum::http::Method::HEAD {
                    let mut resp = axum::http::StatusCode::OK.into_response();
                    resp.headers_mut()
                        .insert("etag", axum::http::HeaderValue::from_static("\"gen-1\""));
                    resp
                } else {
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let owner = "did:key:zMERGEROLLBACKAAAAAAAAAAAAAAAAAAAAAAAA";
        let repo_name = "rollback-merge";
        let mut state = crate::test_support::test_state(pool.clone()).await;
        let disk = tempfile::TempDir::new().unwrap();
        let repo_path = disk.path().join("repo.git");
        let (main_tip, _feature_tip) = seeded_merge_repo(&repo_path);

        let mut seeded = crate::db::RepoRecord {
            id: Uuid::new_v4().to_string(),
            name: repo_name.to_string(),
            owner_did: owner.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: String::new(),
            forked_from: None,
            machine_id: None,
        };
        seeded.disk_path = repo_path.to_string_lossy().to_string();
        let repo_id = seeded.id.clone();
        state.db.create_repo(&seeded).await.expect("seed repo");
        let now = Utc::now().to_rfc3339();
        state
            .db
            .create_pr(&PullRequest {
                id: Uuid::new_v4().to_string(),
                repo_id,
                number: 1,
                title: "rb".to_string(),
                body: None,
                author_did: owner.to_string(),
                source_branch: "feature".to_string(),
                target_branch: "main".to_string(),
                status: "open".to_string(),
                merged_by_did: None,
                merged_at: None,
                created_at: now.clone(),
                updated_at: now,
            })
            .await
            .expect("seed PR");
        state.repo_store = crate::git::repo_store::RepoStore::for_testing_with_tigris(
            disk.path().to_path_buf(),
            crate::git::repo_store::build_lock_pool(&pool, 2, std::time::Duration::from_secs(1)),
            crate::git::tigris::TigrisClient::for_testing_with_endpoint("test-bucket", &endpoint),
        );

        let res = merge_pr(
            State(state),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), repo_name.to_string(), 1)),
        )
        .await;
        assert!(res.is_err(), "a refused publish must surface an error");

        let tip_after = git(&repo_path, &["rev-parse", "refs/heads/main"]);
        assert_eq!(
            tip_after, main_tip,
            "a refused publish must rewind the local merge to the pre-merge tip"
        );
    }
}

/// #173 F1 follow-up: merge holds no admission permit, so an exhausted write-lock
/// pool must shed 503 + Retry-After.
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

    #[sqlx::test]
    async fn merge_pr_lock_pool_exhaustion_sheds_503_not_500(pool: PgPool) {
        let owner = "did:key:zMERGELOCKPOOLOWNERAAAAAAAAAAAAAAAAAAAAA";
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.repo_store = crate::git::repo_store::RepoStore::new(
            std::path::PathBuf::from("/tmp/gitlawb-pulls-lockpool"),
            None,
            crate::git::repo_store::build_lock_pool(&pool, 1, std::time::Duration::from_secs(1)),
            std::time::Duration::from_secs(300),
        );

        let repo = seed_repo(owner, "lp-merge");
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.expect("seed repo");
        let now = Utc::now().to_rfc3339();
        state
            .db
            .create_pr(&PullRequest {
                id: Uuid::new_v4().to_string(),
                repo_id: repo_id.clone(),
                number: 1,
                title: "lp".to_string(),
                body: None,
                author_did: owner.to_string(),
                source_branch: "feature".to_string(),
                target_branch: "main".to_string(),
                status: "open".to_string(),
                merged_by_did: None,
                merged_at: None,
                created_at: now.clone(),
                updated_at: now,
            })
            .await
            .expect("seed open PR");

        let held = state
            .repo_store
            .acquire_write(owner, "other-repo")
            .await
            .expect("the first write takes the only lock-pool connection");

        let shed = merge_pr(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), "lp-merge".to_string(), 1)),
        )
        .await;
        let err = shed.expect_err("an exhausted lock pool must fail the call");
        let resp = err.into_response();
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "merge_pr: an exhausted write-lock pool must shed 503, not a 500 git error"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap()),
            Some("1"),
            "merge_pr: a capacity shed must tell the client when to retry"
        );

        let _ = held.release(false).await;
        let admitted = merge_pr(
            State(state.clone()),
            Extension(AuthenticatedDid(owner.to_string())),
            Path((owner.to_string(), "lp-merge".to_string(), 1)),
        )
        .await;
        assert!(
            !matches!(admitted, Err(AppError::Overloaded(_))),
            "with the lock pool free, merge_pr must not be shed as capacity; got {:?}",
            admitted.err()
        );
    }
}
