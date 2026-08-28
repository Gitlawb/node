//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.
//! GET /api/v1/arweave/anchors/verify/{item_id} — verify an anchor
//! against the gateway.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use gitlawb_core::did::Did;
use serde::Deserialize;
use std::str::FromStr;

use crate::arweave_v2;
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

    Ok(Json(serde_json::json!({
        "anchors": anchors,
        "count": anchors.len(),
    })))
}

/// GET /api/v1/arweave/anchors/verify/{item_id}
///
/// Public verification endpoint. Fetches the data item from the
/// configured Arweave gateway, parses it as ANS-104, verifies the
/// Ed25519 signature against the persisted `node_did`, and returns
/// the decoded data payload. The handler is a thin wrapper over
/// `arweave_v2::verify_anchor`; the three-outcome probe model and
/// the verify logic live there.
///
/// This endpoint is the public, in-band way for a third party to
/// confirm that a pushed ref-cert was permanently anchored by the
/// claimed node. The reviewer demanded that the embedded cert only
/// be trusted after the envelope signature is verified; this
/// endpoint is the surface for that verification.
pub async fn verify_anchor(
    State(state): State<AppState>,
    Path(item_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // 1. Look up the anchor row to get the persisted node_did.
    let row = state
        .db
        .get_arweave_anchor_by_item_id(&item_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("no anchor with item_id {item_id}")))?;

    // 2. Resolve the node_did to the raw Ed25519 public key bytes
    //    so verify_data_item can do the signature check.
    let did = Did::from_str(&row.node_did)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bad node_did: {e}")))?;
    let verifying_key = did
        .to_verifying_key()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("node_did not a did:key: {e}")))?;
    let expected_pk = verifying_key.to_bytes();

    // 3. Run the verify path. This is exhaustive: Present, Definitively
    //    Absent, or Indeterminate. The HTTP layer surfaces all three.
    let result = arweave_v2::verify_anchor(
        &state.http_client,
        &item_id,
        &expected_pk,
        &state.config.arweave_gateway_url,
    )
    .await
    .map_err(AppError::Internal)?;

    let status = if result.verified {
        "verified"
    } else if result
        .error
        .as_deref()
        .map(|e| e.contains("never served"))
        .unwrap_or(false)
    {
        "definitively_absent"
    } else {
        "indeterminate"
    };

    let body = serde_json::json!({
        "item_id": result.item_id,
        "status": status,
        "verified": result.verified,
        "owner_did": result.owner_did,
        "data_payload": result.data_payload,
        "error": result.error,
    });
    Ok(Json(body))
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

#[cfg(test)]
mod verify_anchor_tests {
    use super::*;
    use crate::ans104::DataItem;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use gitlawb_core::identity::Keypair;
    use serde_json::Value;
    use sqlx::PgPool;
    use tower::ServiceExt;

    /// Pre-seed a row in `arweave_anchors` with a specific node_did
    /// and item_id. Returns the item_id.
    async fn seed_anchor(pool: &PgPool, node_did: &str, item_id: &str) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        sqlx::query(
            r#"INSERT INTO arweave_anchors
               (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(item_id) // PK
        .bind("alice/r")
        .bind("did:key:z6owner")
        .bind("refs/heads/main")
        .bind("0".repeat(40))
        .bind("1".repeat(40))
        .bind(Option::<String>::None)
        .bind(item_id)
        .bind(format!("https://arweave.net/{item_id}"))
        .bind(node_did)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    }

    fn did_of(kp: &Keypair) -> String {
        Did::from_verifying_key(&kp.verifying_key()).to_string()
    }

    /// The public verify endpoint reports `verified: true` for a
    /// well-signed item, and decodes the embedded payload.
    #[sqlx::test]
    async fn verify_endpoint_reports_verified_on_signed_item(pool: PgPool) {
        let kp = Keypair::generate();
        let node_did = did_of(&kp);
        let item_id = "item_signed_001";
        seed_anchor(&pool, &node_did, item_id).await;

        let data = br#"{"repo":"alice/r","ref":"refs/heads/main","old":"0000","new":"1111"}"#;
        let mut item = DataItem::new_unsigned(
            &kp.verifying_key().to_bytes(),
            "",
            "",
            vec![(b"App-Name", b"gitlawb")],
            data.to_vec(),
        );
        crate::ans104::sign_data_item(&mut item, &kp).unwrap();
        let body = serde_json::to_string(&item).unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let mut state = crate::test_support::test_state(pool).await;
        state.config = std::sync::Arc::new({
            let mut c = (*state.config).clone();
            c.arweave_gateway_url = server.url();
            c
        });

        let resp = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/arweave/anchors/verify/{item_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "verified");
        assert_eq!(v["verified"], true);
        assert_eq!(v["data_payload"]["new"], "1111");
    }

    /// The public verify endpoint reports `definitively_absent`
    /// when the gateway returns a 404 with a known JSON body shape.
    #[sqlx::test]
    async fn verify_endpoint_reports_definitively_absent_on_404(pool: PgPool) {
        let kp = Keypair::generate();
        let node_did = did_of(&kp);
        let item_id = "item_absent_001";
        seed_anchor(&pool, &node_did, item_id).await;

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_body(r#"{"status":"not found"}"#)
            .create_async()
            .await;

        let mut state = crate::test_support::test_state(pool).await;
        state.config = std::sync::Arc::new({
            let mut c = (*state.config).clone();
            c.arweave_gateway_url = server.url();
            c
        });

        let resp = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/arweave/anchors/verify/{item_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "definitively_absent");
        assert_eq!(v["verified"], false);
    }

    /// A 400 from the gateway surfaces as `indeterminate` — the
    /// reviewer's named bug, surfaced at the public verify surface.
    #[sqlx::test]
    async fn verify_endpoint_reports_indeterminate_on_400(pool: PgPool) {
        let kp = Keypair::generate();
        let node_did = did_of(&kp);
        let item_id = "item_400_001";
        seed_anchor(&pool, &node_did, item_id).await;

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(400)
            .with_body("bad request")
            .create_async()
            .await;

        let mut state = crate::test_support::test_state(pool).await;
        state.config = std::sync::Arc::new({
            let mut c = (*state.config).clone();
            c.arweave_gateway_url = server.url();
            c
        });

        let resp = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/arweave/anchors/verify/{item_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "indeterminate");
        assert_eq!(v["verified"], false);
    }
}
