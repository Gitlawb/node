//! Changelog endpoint — unified timeline of commits, merged PRs, and closed issues.

use axum::extract::{Extension, Path, Query, State};
use axum::Json;
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::git::store;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ChangelogQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

/// GET /api/v1/repos/:owner/:repo/changelog[?limit=N]
///
/// Returns a unified, time-sorted list of recent events:
///   - git commits (type: "commit")
///   - merged pull requests (type: "pr_merged")
pub async fn get_changelog(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<ChangelogQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (record, _rules) =
        crate::api::authorize_repo_read(&state, &owner, &repo, caller, "/").await?;

    let limit = query.limit.min(100);

    // ── Commits from git log ─────────────────────────────────────────────
    let disk_path = state
        .repo_store
        .acquire(&record.owner_did, &record.name)
        .await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let head_ref = store::resolve_head(&disk_path, &record.default_branch);
    // A read failure is not an empty history: returning a bare 200 with no
    // events makes a degraded repo look identical to a brand-new one (#400).
    let commits =
        store::log(&disk_path, &head_ref, limit).map_err(|e| AppError::Git(e.to_string()))?;

    let mut events: Vec<serde_json::Value> = commits
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "type": "commit",
                "sha": c.hash,
                "message": c.subject,
                "author": c.author_name,
                "timestamp": c.timestamp,
                "branch": record.default_branch,
            })
        })
        .collect();

    // ── Merged PRs ───────────────────────────────────────────────────────
    // Same for the DB half: an outage must surface as an error (503 when the
    // pool is unreachable), not an empty timeline (#400).
    let prs = state.db.list_prs(&record.id).await?;
    for pr in prs.iter().filter(|p| p.status == "merged") {
        events.push(serde_json::json!({
            "type": "pr_merged",
            "number": pr.number,
            "title": pr.title,
            "author": pr.author_did,
            "merged_by": pr.merged_by_did,
            "timestamp": pr.merged_at.as_deref().unwrap_or(&pr.updated_at),
            "source_branch": pr.source_branch,
            "target_branch": pr.target_branch,
        }));
    }

    // ── Sort by timestamp descending, take limit ─────────────────────────
    events.sort_by(|a, b| {
        let ta = a["timestamp"].as_str().unwrap_or("");
        let tb = b["timestamp"].as_str().unwrap_or("");
        tb.cmp(ta)
    });
    events.truncate(limit);

    Ok(Json(serde_json::json!({
        "repo": format!("{owner}/{repo}"),
        "events": events,
        "count": events.len(),
    })))
}

/// #400: endpoint-level proof that a degraded store or DB reaches the caller
/// as an error, not a 200 with an empty timeline.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::Router;
    use sqlx::PgPool;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn seed_repo(owner_did: &str, name: &str) -> crate::db::RepoRecord {
        let now = chrono::Utc::now();
        crate::db::RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
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

    /// A state whose repo store roots in `repos_dir` so the test controls the
    /// on-disk repo, with the repo record already inserted.
    async fn seeded_state(
        pool: &PgPool,
        repos_dir: &std::path::Path,
        owner: &str,
        name: &str,
    ) -> AppState {
        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.repo_store =
            crate::git::repo_store::RepoStore::for_testing(repos_dir.to_path_buf(), pool.clone());
        state
            .db
            .create_repo(&seed_repo(owner, name))
            .await
            .expect("seed repo");
        state
    }

    fn repo_disk_path(repos_dir: &std::path::Path, owner: &str, name: &str) -> std::path::PathBuf {
        repos_dir
            .join(owner.replace([':', '/'], "_"))
            .join(format!("{name}.git"))
    }

    fn init_bare(path: &std::path::Path) {
        std::fs::create_dir_all(path).unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "--bare"])
            .arg(path)
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    /// A bare repo with one real commit on HEAD.
    fn bare_repo_with_commit(
        repos_dir: &std::path::Path,
        owner: &str,
        name: &str,
    ) -> std::path::PathBuf {
        let scratch = repos_dir.join(format!("scratch-{name}"));
        let out = std::process::Command::new("git")
            .args(["init"])
            .arg(&scratch)
            .output()
            .unwrap();
        assert!(out.status.success());
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "--allow-empty",
                "-m",
                "initial",
            ])
            .current_dir(&scratch)
            .output()
            .unwrap();
        assert!(out.status.success());
        let repo_path = repo_disk_path(repos_dir, owner, name);
        std::fs::create_dir_all(repo_path.parent().unwrap()).unwrap();
        let out = std::process::Command::new("git")
            .args(["clone", "--bare"])
            .arg(&scratch)
            .arg(&repo_path)
            .output()
            .unwrap();
        assert!(out.status.success());
        repo_path
    }

    /// Delete the object behind HEAD and leave garbage: `git log` fails while
    /// `rev-parse` still resolves the ref.
    fn corrupt_head_object(repo_path: &std::path::Path) {
        let out = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        let oid = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let obj = repo_path.join("objects").join(&oid[..2]).join(&oid[2..]);
        std::fs::remove_file(&obj).unwrap();
        std::fs::write(&obj, b"garbage").unwrap();
    }

    async fn oneshot_changelog(
        state: AppState,
        owner: &str,
        name: &str,
    ) -> axum::response::Response {
        Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/changelog",
                axum::routing::get(get_changelog),
            )
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/repos/{owner}/{name}/changelog"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// The git half of the fold: a repo whose HEAD resolves but whose object
    /// store is corrupt must be a 500, not a 200 with zero events.
    #[sqlx::test]
    async fn changelog_on_corrupt_object_store_returns_500_not_empty_200(pool: PgPool) {
        let owner = "did:key:zCHANGELOGCORRUPTAAAAAAAAAAAAAAAAAAAA";
        let dir = TempDir::new().unwrap();
        let state = seeded_state(&pool, dir.path(), owner, "corrupt-log").await;
        let repo_path = bare_repo_with_commit(dir.path(), owner, "corrupt-log");
        corrupt_head_object(&repo_path);

        let resp = oneshot_changelog(state, owner, "corrupt-log").await;
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a resolving ref whose objects cannot be read is a git error"
        );
    }

    /// The DB half of the fold: with the pull_requests table gone, list_prs
    /// fails and the endpoint must surface it (503) rather than answering a
    /// 200 with only the git-derived events.
    #[sqlx::test]
    async fn changelog_on_pr_table_failure_returns_error_not_empty_200(pool: PgPool) {
        let owner = "did:key:zCHANGELOGDBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let dir = TempDir::new().unwrap();
        let state = seeded_state(&pool, dir.path(), owner, "db-fail").await;
        init_bare(&repo_disk_path(dir.path(), owner, "db-fail"));
        sqlx::query("DROP TABLE pull_requests")
            .execute(&pool)
            .await
            .unwrap();

        let resp = oneshot_changelog(state, owner, "db-fail").await;
        assert!(
            resp.status().is_server_error(),
            "a DB failure must not answer a 200 empty timeline; got {}",
            resp.status()
        );
    }

    /// Must-not direction: a healthy repo with a commit still returns the
    /// event; an empty repo is still a valid empty timeline.
    #[sqlx::test]
    async fn changelog_still_serves_commit_and_empty_repo(pool: PgPool) {
        let owner = "did:key:zCHANGELOGOKCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let dir = TempDir::new().unwrap();
        let state = seeded_state(&pool, dir.path(), owner, "with-commit").await;
        bare_repo_with_commit(dir.path(), owner, "with-commit");

        let resp = oneshot_changelog(state, owner, "with-commit").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["count"], 1, "the seeded commit must appear");
        assert_eq!(v["events"][0]["type"], "commit");

        let state = seeded_state(&pool, dir.path(), owner, "empty-repo").await;
        init_bare(&repo_disk_path(dir.path(), owner, "empty-repo"));
        let resp = oneshot_changelog(state, owner, "empty-repo").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["count"], 0, "a genuinely empty repo is still 200/empty");
    }
}
