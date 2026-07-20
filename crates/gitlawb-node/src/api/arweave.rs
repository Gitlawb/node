//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use crate::error::Result;
use crate::state::AppState;

/// GET /api/v1/arweave/verify/:tx_id
///
/// Fetch the anchor from Arweave via the configured gateway, extract the embedded
/// certificate, and verify:
///   1. The node's Ed25519 signature on the certificate payload
///   2. The `prev` hash chains correctly against the most recent local cert
///   3. The `pusher_sig` can be verified (optional, informational)
pub async fn verify_anchor_endpoint(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let gateway = &state.config.arweave_gateway;
    let result = crate::arweave::verify_anchor(&state.http_client, gateway, &tx_id, &state.db)
        .await
        .map_err(crate::error::AppError::Internal)?;

    Ok(Json(serde_json::json!({
        "valid": result.valid,
        "errors": result.errors,
        "certificate": result.certificate,
    })))
}

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
