//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;

use crate::error::Result;
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
pub async fn list_anchors(
    State(state): State<AppState>,
    Query(q): Query<ListAnchorsQuery>,
) -> Result<Json<serde_json::Value>> {
    let limit = q.limit.min(200);
    let anchors = state
        .db
        .list_arweave_anchors(q.repo.as_deref(), limit)
        .await
        .map_err(crate::error::AppError::Internal)?;

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}
