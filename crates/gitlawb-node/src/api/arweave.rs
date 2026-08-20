//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use crate::error::{AppError, Result};
use crate::state::AppState;

/// GET /api/v1/arweave/verify/:tx_id
///
/// Fetch the anchor from Arweave via the configured gateway, extract the embedded
/// certificate, and verify:
///   1. The node's Ed25519 signature on the certificate payload (with a
///      7-field legacy fallback when the proof fields are absent)
///   2. Chain continuity: `prev` hashes against the predecessor cert (seq > 1)
///      and, on the legacy path, the stored row is corroborated
///   3. The RFC 9421 `pusher_sig` — REQUIRED (not optional) whenever the
///      signature context fields are present
///
/// The verdict only ever covers fields the certificate actually signed; the
/// outer repo/owner_did are corroborated against the node's own record.
pub async fn verify_anchor_endpoint(
    State(state): State<AppState>,
    Path(tx_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    if !crate::arweave::is_valid_tx_id(&tx_id) {
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

    // The gateway config may carry credentials (e.g. an Irys user:pass). Those
    // must never leak into a public listing, so only the credential-free origin
    // is embedded in each anchor's URL. A node with NO gateway configured emits
    // no presentation URL at all: the recorded tx id stays durable and listable
    // (it is the anchor's identity), but a `/tx_id`-shaped relative string would
    // resolve against the node's own origin and mislead clients (#224 review).
    let gateway =
        crate::server::mask_credential_url(state.config.arweave_gateway.trim_end_matches('/'));
    let anchors: Vec<crate::db::ArweaveAnchor> = anchors
        .into_iter()
        .map(|mut a| {
            a.irys_tx_id = Some(a.arweave_tx_id.clone());
            if !gateway.is_empty() {
                a.arweave_url = Some(format!("{}/{}", gateway, a.arweave_tx_id));
            }
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

    /// A credentialed gateway (user:pass in the URL) must not leak into the
    /// public anchors listing — every `arweave_url` is built from the masked
    /// origin, never the raw config.
    #[sqlx::test]
    async fn list_anchors_does_not_leak_gateway_credentials(pool: PgPool) {
        use clap::Parser as _;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.config = std::sync::Arc::new(crate::config::Config::parse_from([
            "gitlawb-node",
            "--arweave-gateway",
            "https://user:supersecret@arweave.net",
        ]));

        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInputV2 {
                repo: "alice/myrepo",
                owner_did: "did:key:zAlice",
                ref_name: "refs/heads/main",
                old_sha: &"a".repeat(40),
                new_sha: &"b".repeat(40),
                cid: Some("bafy1test"),
                arweave_tx_id: &"f".repeat(43),
                node_did: "did:key:zNode",
                cert_id: None,
            })
            .await
            .unwrap();

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

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body: String = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        assert!(
            !body.contains("supersecret"),
            "anchors listing must not disclose gateway credentials"
        );
        assert!(
            body.contains("https://arweave.net/"),
            "arweave_url should carry the credential-free origin"
        );
        let v: Value = serde_json::from_str(&body).expect("json body");
        assert_eq!(v["count"], 1);
    }

    /// Query and fragment credentials on a gateway with a path prefix must not
    /// leak into the public listing, and the safe path prefix must survive so
    /// the returned arweave_url still routes to the intended gateway.
    #[sqlx::test]
    async fn list_anchors_drops_query_and_fragment_credentials(pool: PgPool) {
        use clap::Parser as _;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.config = std::sync::Arc::new(crate::config::Config::parse_from([
            "gitlawb-node",
            "--arweave-gateway",
            "https://user:supersecret@gateway.example/data?token=SECRET#frag",
        ]));

        let tx_id = "f".repeat(43);
        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInputV2 {
                repo: "alice/myrepo",
                owner_did: "did:key:zAlice",
                ref_name: "refs/heads/main",
                old_sha: &"a".repeat(40),
                new_sha: &"b".repeat(40),
                cid: Some("bafy1test"),
                arweave_tx_id: &tx_id,
                node_did: "did:key:zNode",
                cert_id: None,
            })
            .await
            .unwrap();

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

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body: String = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        for secret in ["supersecret", "SECRET"] {
            assert!(
                !body.contains(secret),
                "anchors listing must not disclose {secret}"
            );
        }
        // Path prefix preserved, query/fragment gone, tx_id appended cleanly.
        assert!(
            body.contains(&format!("https://gateway.example/data/{tx_id}")),
            "arweave_url should carry the safe origin plus path prefix, got: {body}"
        );
    }

    /// #224 review, P2: a node with recorded anchors but NO gateway configured
    /// must not emit a relative `/tx_id` string as `arweave_url` — it would
    /// resolve against the node's own origin and mislead clients. The recorded
    /// tx id stays durable and listable (it is the anchor's identity); the
    /// presentation URL is simply omitted.
    #[sqlx::test]
    async fn list_anchors_without_gateway_omits_arweave_url(pool: PgPool) {
        // test_state's default config has no gateway configured.
        let state = crate::test_support::test_state(pool.clone()).await;

        state
            .db
            .record_arweave_anchor(&crate::db::RecordAnchorInputV2 {
                repo: "alice/myrepo",
                owner_did: "did:key:zAlice",
                ref_name: "refs/heads/main",
                old_sha: &"a".repeat(40),
                new_sha: &"b".repeat(40),
                cid: Some("bafy1test"),
                arweave_tx_id: &"f".repeat(43),
                node_did: "did:key:zNode",
                cert_id: None,
            })
            .await
            .unwrap();

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

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        let anchor = v["anchors"][0].clone();
        assert_eq!(
            anchor["arweave_tx_id"],
            "f".repeat(43),
            "the durable tx id must still be listable"
        );
        assert!(
            anchor["arweave_url"].is_null(),
            "with no gateway the arweave_url must be omitted, got: {}",
            anchor["arweave_url"]
        );
    }

    /// #224 review: `?limit=0` must behave like the parameter being absent
    /// (the serde default of 50), not like `?limit=1`. The old
    /// `q.limit.clamp(1, 200)` collapsed 0 to 1, silently narrowing the
    /// listing; the fix routes sub-1 values through `default_limit()`.
    #[sqlx::test]
    async fn list_anchors_limit_zero_uses_default_limit(pool: PgPool) {
        use clap::Parser as _;

        let mut state = crate::test_support::test_state(pool.clone()).await;
        state.config = std::sync::Arc::new(crate::config::Config::parse_from([
            "gitlawb-node",
            "--arweave-gateway",
            "https://arweave.net",
        ]));

        // Seed three distinct transitions.
        for (ref_name, old_sha, new_sha) in [
            ("refs/heads/main", "a".repeat(40), "b".repeat(40)),
            ("refs/heads/dev", "c".repeat(40), "d".repeat(40)),
            ("refs/tags/v1", "e".repeat(40), "f".repeat(40)),
        ] {
            state
                .db
                .record_arweave_anchor(&crate::db::RecordAnchorInputV2 {
                    repo: "alice/myrepo",
                    owner_did: "did:key:zAlice",
                    ref_name,
                    old_sha: &old_sha,
                    new_sha: &new_sha,
                    cid: Some("bafy1test"),
                    arweave_tx_id: &"f".repeat(43),
                    node_did: "did:key:zNode",
                    cert_id: None,
                })
                .await
                .unwrap();
        }

        let resp = Router::new()
            .route("/api/v1/arweave/anchors", axum::routing::get(list_anchors))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/arweave/anchors?limit=0")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let v: Value = serde_json::from_slice(&bytes).expect("json body");
        assert_eq!(
            v["count"], 3,
            "limit=0 must fall back to the default limit, not clamp to 1"
        );
    }
}
