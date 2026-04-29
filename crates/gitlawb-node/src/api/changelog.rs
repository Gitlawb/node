//! Changelog endpoint — unified timeline of commits, merged PRs, and closed issues.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

use crate::error::{AppError, Result};
use crate::git::store;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ChangelogQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize { 20 }

/// GET /api/v1/repos/:owner/:repo/changelog[?limit=N]
///
/// Returns a unified, time-sorted list of recent events:
///   - git commits (type: "commit")
///   - merged pull requests (type: "pr_merged")
pub async fn get_changelog(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<ChangelogQuery>,
) -> Result<Json<serde_json::Value>> {
    let record = state.db.get_repo(&owner, &repo).await?
        .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{repo}")))?;

    let limit = query.limit.min(100);

    // ── Commits from git log ─────────────────────────────────────────────
    let disk_path = state.repo_store.acquire(&record.owner_did, &record.name).await
        .map_err(|e| AppError::Git(e.to_string()))?;
    let head_ref = store::resolve_head(&disk_path, &record.default_branch);
    let commits = store::log(&disk_path, &head_ref, limit).unwrap_or_default();

    let mut events: Vec<serde_json::Value> = commits.into_iter().map(|c| {
        serde_json::json!({
            "type": "commit",
            "sha": c.hash,
            "message": c.subject,
            "author": c.author_name,
            "timestamp": c.timestamp,
            "branch": record.default_branch,
        })
    }).collect();

    // ── Merged PRs ───────────────────────────────────────────────────────
    let prs = state.db.list_prs(&record.id).await.unwrap_or_default();
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
