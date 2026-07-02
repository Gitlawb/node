//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::visibility::{visibility_check, Decision};

#[derive(Debug, Deserialize)]
pub struct ListAnchorsQuery {
    pub repo: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

/// GET /api/v1/arweave/anchors
///
/// Returns Arweave ref-update anchors. When `?repo=<owner>/<name>` is provided,
/// the response is gated on the caller's read visibility for that repo (deny ->
/// 404). Without a `?repo=` filter, the global listing filters each row on
/// current visibility to prevent metadata disclosure when repos are made private
/// after push (#136).
pub async fn list_anchors(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Query(q): Query<ListAnchorsQuery>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());

    // Global listings (no ?repo=) are restricted to authenticated callers: an
    // anonymous request against the full-node index would disclose metadata for
    // every repo ever pushed here. Per-repo requests are gated by
    // authorize_repo_read which applies the per-repo visibility rules.
    if q.repo.is_none() && caller.is_none() {
        return Err(AppError::Unauthorized(
            "authentication required for global anchor listing".into(),
        ));
    }

    let normalized_repo = if let Some(ref repo) = q.repo {
        // Gate on per-repo visibility.
        let parts: Vec<&str> = repo.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(AppError::NotFound("repo not found".into()));
        }
        let (owner, name) = (parts[0], parts[1]);
        let (record, _rules) =
            crate::api::authorize_repo_read(&state, owner, name, caller, "/").await?;

        // Normalize to short-form slug that matches what's written to the table.
        let owner_short = record
            .owner_did
            .split(':')
            .next_back()
            .unwrap_or(&record.owner_did);
        Some(format!("{}/{}", owner_short, record.name))
    } else {
        None
    };

    let limit = q.limit.clamp(0, 200);

    let anchors = if let Some(ref slug) = normalized_repo {
        // Per-repo: filter at the DB level and return directly.
        state
            .db
            .list_arweave_anchors(Some(slug), limit)
            .await
            .map_err(AppError::Internal)?
    } else {
        // Global listing: fetch all anchors, filter by current visibility
        // against the deduped repo view (so mirror rows never bypass canonical
        // visibility), then take limit.
        let all_anchors = state
            .db
            .list_arweave_anchors(None, i64::MAX)
            .await
            .map_err(AppError::Internal)?;

        // Build a set of readable repo short-form slugs from the deduped list.
        let repos = state
            .db
            .list_all_repos_deduped()
            .await
            .map_err(AppError::Internal)?;
        let repo_ids: Vec<String> = repos.iter().map(|r| r.id.clone()).collect();
        let rules_by_repo = state
            .db
            .list_visibility_rules_for_repos(&repo_ids)
            .await
            .map_err(AppError::Internal)?;

        let readable: std::collections::HashSet<String> = repos
            .iter()
            .filter(|r| {
                let rules = rules_by_repo.get(&r.id).map(Vec::as_slice).unwrap_or(&[]);
                visibility_check(rules, r.is_public, &r.owner_did, caller, "/") != Decision::Deny
            })
            .map(|r| {
                let short = r.owner_did.split(':').next_back().unwrap_or(&r.owner_did);
                format!("{}/{}", short, r.name)
            })
            .collect();

        all_anchors
            .into_iter()
            .filter(|a| readable.contains(&a.repo))
            .take(limit as usize)
            .collect()
    };

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}
