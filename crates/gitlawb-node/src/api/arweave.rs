//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use serde::Deserialize;

use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};
use crate::state::AppState;

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

    let limit = q.limit.min(200);
    let raw_anchors = state
        .db
        .list_arweave_anchors(normalized_repo.as_deref(), limit)
        .await
        .map_err(AppError::Internal)?;

    // For global listings (no ?repo=), filter each anchor on current visibility.
    let anchors = if normalized_repo.is_none() {
        let mut filtered = Vec::new();
        for anchor in raw_anchors {
            // Parse repo slug to resolve current visibility.
            let parts: Vec<&str> = anchor.repo.splitn(2, '/').collect();
            if parts.len() != 2 {
                continue;
            }
            let (owner, name) = (parts[0], parts[1]);
            // Skip anchors for repos the caller cannot currently read.
            if crate::api::authorize_repo_read(&state, owner, name, caller, "/")
                .await
                .is_ok()
            {
                filtered.push(anchor);
            }
        }
        filtered
    } else {
        raw_anchors
    };

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}
