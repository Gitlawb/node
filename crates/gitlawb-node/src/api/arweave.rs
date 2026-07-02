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
///
/// Both paths resolve visibility against the deduped repo view so mirror rows
/// never bypass the canonical repo's rules.
pub async fn list_anchors(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Query(q): Query<ListAnchorsQuery>,
) -> Result<Json<serde_json::Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let limit = q.limit.clamp(0, 200);

    // Global listings (no ?repo=) are restricted to authenticated callers.
    if q.repo.is_none() && caller.is_none() {
        return Err(AppError::Unauthorized(
            "authentication required for global anchor listing".into(),
        ));
    }

    let anchors = if let Some(ref repo) = q.repo {
        // ── Per-repo path ──
        // Resolve against the deduped repo view so mirror rows never bypass
        // the canonical repo's visibility rules. Use did_matches to handle
        // both full DID and bare short-form owner in the URL.
        let parts: Vec<&str> = repo.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(AppError::NotFound("repo not found".into()));
        }
        let (owner, name) = (parts[0], parts[1]);

        // Fetch the deduped list (mirror rows collapsed, quarantined excluded).
        let repos = state
            .db
            .list_all_repos_deduped()
            .await
            .map_err(AppError::Internal)?;

        let record = repos
            .into_iter()
            .find(|r| crate::api::did_matches(owner, &r.owner_did) && r.name == name)
            .ok_or_else(|| AppError::RepoNotFound(format!("{owner}/{name}")))?;

        // Quarantine gate (belt-and-suspenders — deduped already filters).
        if state.db.is_repo_quarantined(&record.id).await? {
            return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
        }

        // Visibility gate against the canonical survivor's rules.
        let rules = state.db.list_visibility_rules(&record.id).await?;
        if visibility_check(&rules, record.is_public, &record.owner_did, caller, "/")
            == Decision::Deny
        {
            return Err(AppError::RepoNotFound(format!("{owner}/{name}")));
        }

        // Normalize to short-form slug matching the anchor table.
        let owner_short = record
            .owner_did
            .split(':')
            .next_back()
            .unwrap_or(&record.owner_did);
        let slug = Some(format!("{}/{}", owner_short, record.name));

        state
            .db
            .list_arweave_anchors(slug.as_deref(), limit)
            .await
            .map_err(AppError::Internal)?
    } else {
        // ── Global listing ──
        // Build the set of readable repo slugs from the deduped repo view
        // (mirror rows already collapsed, quarantined excluded), then query
        // anchors bounded in SQL via WHERE repo = ANY(...).
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

        let readable: Vec<String> = repos
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

        if readable.is_empty() {
            Vec::new()
        } else {
            state
                .db
                .list_arweave_anchors_for_repos(&readable, limit)
                .await
                .map_err(AppError::Internal)?
        }
    };

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}
