//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use crate::error::{AppError, Result};
use crate::state::AppState;

/// Validate an Arweave transaction ID: 43-character base64url string.
fn is_valid_tx_id(tx_id: &str) -> bool {
    if tx_id.len() != 43 {
        return false;
    }
    tx_id
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

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
    if !is_valid_tx_id(&tx_id) {
        return Err(AppError::BadRequest(
            "invalid transaction ID: expected 43-character base64url".to_string(),
        ));
    }
    let gateway = &state.config.arweave_gateway;
    let node_did = state.node_did.to_string();
    let result =
        crate::arweave::verify_anchor(&state.http_client, gateway, &tx_id, &state.db, &node_did)
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
    // Bare `?` so connection-class sqlx failures downcast to `AppError::Db` and
    // map to 503 `db_unavailable` (not 500 via `.map_err(AppError::Internal)`) (#251).
    let anchors = state
        .db
        .list_arweave_anchors(q.repo.as_deref(), limit)
        .await?;

    let gateway = state.config.arweave_gateway.trim_end_matches('/');
    let anchors: Vec<crate::db::ArweaveAnchor> = anchors
        .into_iter()
        .map(|mut a| {
            a.irys_tx_id = Some(a.arweave_tx_id.clone());
            a.arweave_url = Some(format!("{}/{}", gateway, a.arweave_tx_id));
            a
        })
        .collect();

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}

#[cfg(test)]
mod closed_pool_tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use serde_json::Value;
    use sqlx::PgPool;
    use tower::ServiceExt;

    /// #251: a closed pool on /api/v1/arweave/anchors must be 503 db_unavailable.
    #[sqlx::test]
    async fn list_anchors_closed_pool_returns_503_db_unavailable(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        pool.close().await;

        let resp = Router::new()
            .route("/api/v1/arweave/anchors", axum::routing::get(list_anchors))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/arweave/anchors")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "closed-pool outage must be retryable 503, not 500"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v,
            serde_json::json!({
                "error": crate::error::DB_UNAVAILABLE_CODE,
                "message": crate::error::DB_UNAVAILABLE_MESSAGE,
            })
        );
    }
}
