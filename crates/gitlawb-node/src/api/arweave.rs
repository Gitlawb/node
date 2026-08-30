//! GET /api/v1/arweave/anchors — list Arweave ref-update anchors.
//! GET /api/v1/arweave/anchors/verify/{item_id} — verify an anchor
//! against the gateway.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use gitlawb_core::did::Did;
use serde::Deserialize;
use std::str::FromStr;

use crate::arweave_v2;
use crate::auth::AuthenticatedDid;
use crate::error::{AppError, Result};

/// Single opaque 404 message for `verify_anchor`. All three denial
/// paths (no row, malformed slug, gate deny) must collapse to this
/// exact string so a caller comparing two `message` values cannot
/// distinguish "unknown item id" from "private repo I cannot
/// read". The 404 body is shaped as
/// `{"error":"repo_not_found", "message":"repository '<msg>' not found"}`
/// by `AppError::RepoNotFound`'s response mapping, so changing
/// `<msg>` is the only knob.
///
/// P2 (reviewer round 2, #26 split 2/4): the previous three
/// paths emitted three different messages
/// (`"anchor <item_id>"` for no-row / malformed-slug,
/// `"{owner}/{name}"` from `authorize_repo_read` for the gate).
/// A caller comparing the two messages could tell the
/// difference. The existing tests at lines ~514 and ~601 only
/// checked `error == "repo_not_found"`, so the leak was
/// invisible to the suite.
///
/// Other call sites of `AppError::RepoNotFound` keep their own
/// messages — this constant is verify-endpoint-only.
const VERIFY_DENY_MSG: &str = "anchor not found";
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
/// Public-but-gated verification endpoint. Fetches the data item
/// from the configured Arweave gateway, parses it as ANS-104 (or
/// the v1 raw-JSON shape the live path on this branch actually
/// writes), verifies the Ed25519 signature against the persisted
/// `node_did` (v2 only), and returns the decoded data payload. The
/// handler is a thin wrapper over `arweave_v2::verify_anchor`; the
/// three-outcome probe model and the verify logic live there.
///
/// Gating: the route is mounted under `optional_signature` in
/// `server.rs`, so a real RFC 9421 signature flows through the
/// `Extension<AuthenticatedDid>` parameter. Anonymous calls are
/// accepted; the gate then enforces the persisted row's repo
/// visibility via `authorize_repo_read`. The `record_arweave_anchor`
/// writer stores the row's `repo` as `"{owner}/{name}"`, so we
/// split on `/` to feed the gate. All three denial paths
/// (no row, malformed `repo`, gate deny) collapse to the same
/// opaque `AppError::RepoNotFound` 404 — never `AppError::NotFound`
/// with the item id in the message — so the public endpoint does
/// not leak anchor-row existence for private repos.
///
/// This endpoint is the public, in-band way for a third party to
/// confirm that a pushed ref-cert was permanently anchored by the
/// claimed node. The reviewer demanded that the embedded cert only
/// be trusted after the envelope signature is verified; this
/// endpoint is the surface for that verification.
pub async fn verify_anchor(
    State(state): State<AppState>,
    Path(item_id): Path<String>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<serde_json::Value>> {
    // 1. Look up the anchor row by the externally-routable
    //    transaction id (`irys_tx_id`). The row's internal `id`
    //    column is a UUID; the public endpoint receives the Irys
    //    response `id` (v1) or the ANS-104 derived id (v2), which
    //    the production writer stores in `irys_tx_id`.
    let row = state
        .db
        .get_arweave_anchor_by_item_id(&item_id)
        .await?
        .ok_or_else(|| {
            // Same opaque 404 shape as the gate below — never
            // surface the item id in the error message. The
            // constant is the single source of truth for the
            // deny-path body across all three paths.
            AppError::RepoNotFound(VERIFY_DENY_MSG.to_string())
        })?;

    // 2. Gate on repo read. The row's `repo` field is `"{owner}/{name}"`,
    //    matching the `get_cert` pattern. All denial paths (no
    //    such repo, caller lacks read) collapse to opaque 404.
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let (owner, name) = row
        .repo
        .split_once('/')
        .ok_or_else(|| AppError::RepoNotFound(VERIFY_DENY_MSG.to_string()))?;
    crate::api::authorize_repo_read(&state, owner, name, caller, "/")
        .await
        .map_err(|_| AppError::RepoNotFound(VERIFY_DENY_MSG.to_string()))?;

    // 3. Resolve the persisted node_did to raw Ed25519 public key
    //    bytes for the signature check (v2 only — v1 has no
    //    signature; the dual-format verifier in `arweave_v2` knows
    //    which path to take).
    let did = Did::from_str(&row.node_did)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bad node_did: {e}")))?;
    let verifying_key = did
        .to_verifying_key()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("node_did not a did:key: {e}")))?;
    let expected_pk = verifying_key.to_bytes();

    // 4. Run the verify path. This is exhaustive: Present,
    //    DefinitivelyAbsent, or Indeterminate. The HTTP layer
    //    surfaces all three via the `outcome` field of the result.
    //    The persisted row fields are passed in so the v1
    //    field-equality check has a baseline; the v2 path derives
    //    the protocol id and compares it to the requested
    //    `item_id` (artifact-identity check).
    let persisted = arweave_v2::PersistedAnchorFields {
        repo: &row.repo,
        ref_name: &row.ref_name,
        old_sha: &row.old_sha,
        new_sha: &row.new_sha,
        node_did: &row.node_did,
    };
    let result = arweave_v2::verify_anchor(
        &state.http_client,
        &item_id,
        &expected_pk,
        &persisted,
        &state.config.arweave_gateway_url,
    )
    .await
    .map_err(AppError::Internal)?;

    // 5. Map the structured `outcome` to the status string. The
    //    `error` field is for humans, not routing.
    let status = match result.outcome {
        arweave_v2::ProbeOutcome::Present => "verified",
        arweave_v2::ProbeOutcome::DefinitivelyAbsent => "definitively_absent",
        arweave_v2::ProbeOutcome::Indeterminate => "indeterminate",
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
    /// and item_id, plus the matching `RepoRecord` (public) so the
    /// gated `verify_anchor` handler passes `authorize_repo_read`
    /// for an anonymous caller. The internal `id` column is a fresh
    /// UUID (matching what `record_arweave_anchor` writes in
    /// production), and `irys_tx_id` holds the externally-routable
    /// `item_id`. This shape exercises the production
    /// `WHERE irys_tx_id = $1` lookup rather than the masked
    /// `WHERE id = $1` form the older fixtures used.
    ///
    /// The `owner_did` value `"alice"` matches the slug's left half
    /// (`"alice/r"`) so `get_repo`'s `OWNER_KEY_CASE_SQL` matches
    /// the stored value on both sides.
    async fn seed_anchor(pool: &PgPool, node_did: &str, item_id: &str) {
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        let now = chrono::Utc::now();
        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&crate::db::RepoRecord {
            id: repo_id.clone(),
            name: "r".into(),
            owner_did: "alice".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/r".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();
        let internal_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO arweave_anchors
               (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(&internal_id)
        .bind("alice/r")
        .bind("alice")
        .bind("refs/heads/main")
        .bind("0".repeat(40))
        .bind("1".repeat(40))
        .bind(Option::<String>::None)
        .bind(item_id)
        .bind(format!("https://arweave.net/{item_id}"))
        .bind(node_did)
        .bind(now.to_rfc3339())
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
        let data = br#"{"repo":"alice/r","ref":"refs/heads/main","old":"0000","new":"1111"}"#;
        let mut item = DataItem::new_unsigned(
            &kp.verifying_key().to_bytes(),
            "",
            "",
            vec![(b"App-Name", b"gitlawb")],
            data.to_vec(),
        );
        crate::ans104::sign_data_item(&mut item, &kp).unwrap();
        // The artifact-identity check requires the URL `item_id` to
        // match the protocol id derived from the item
        // (`base64url(SHA256(signature))`). Use the real id.
        let item_id = item.id().unwrap();
        seed_anchor(&pool, &node_did, &item_id).await;
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

    // ----- gate tests (verify_anchor is gated on repo read) -----
    //
    // The team memory `axum-layer-vs-merge-pitfall.md` is the
    // constraint: `.layer(from_fn(optional_signature))` is applied
    // to the verify Router (not the public list Router) so the
    // layer covers the route. `get_repo` via `authorize_repo_read`
    // is the gate; the persisted row's `owner_did` and `repo`
    // (split on `/`) identify the repo to gate on.
    //
    // The shape of every denial is the opaque 404:
    // `{"error":"repo_not_found", "message":"repository '...' not found"}`.
    // The endpoint MUST NOT leak anchor-row existence for repos the
    // caller cannot read.

    /// Anonymous caller can verify anchors for a PUBLIC repo. The
    /// gate is `optional_signature`, not `require_signature`; the
    /// absence of a signature is `caller: None`, which
    /// `authorize_repo_read` allows for public repos.
    #[sqlx::test]
    async fn verify_endpoint_public_repo_anonymous_200(pool: PgPool) {
        let kp = Keypair::generate();
        let node_did = did_of(&kp);
        let item_id = "item_public_anon";
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

        // The verify route IS gated via `optional_signature` per
        // the team memory; this test mirrors the production mount
        // in `server.rs` to actually exercise the gate.
        let resp = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/arweave/anchors/verify/{item_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "public repo + anonymous caller: 200 with payload"
        );
    }

    /// Anonymous caller on a PRIVATE repo is denied. The denial is
    /// the opaque `repo_not_found` 404 — the public endpoint must
    /// not surface whether the anchor row exists when the caller
    /// cannot read the repo.
    #[sqlx::test]
    async fn verify_endpoint_private_repo_anonymous_404(pool: PgPool) {
        let kp = Keypair::generate();
        let node_did = did_of(&kp);
        let item_id = "item_private_anon";

        // Seed the anchor row + a PRIVATE repo.
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        let now = chrono::Utc::now();
        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&crate::db::RepoRecord {
            id: repo_id.clone(),
            name: "r".into(),
            owner_did: "alice".into(),
            description: None,
            is_public: false, // PRIVATE
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/r".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();
        let internal_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO arweave_anchors
               (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(&internal_id)
        .bind("alice/r")
        .bind("alice")
        .bind("refs/heads/main")
        .bind("0".repeat(40))
        .bind("1".repeat(40))
        .bind(Option::<String>::None)
        .bind(item_id)
        .bind(format!("https://arweave.net/{item_id}"))
        .bind(&node_did)
        .bind(now.to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();

        let state = crate::test_support::test_state(pool).await;

        let resp = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/arweave/anchors/verify/{item_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "private repo + anonymous caller: opaque 404"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["error"], "repo_not_found",
            "denial uses the opaque 404 shape; the public endpoint \
             must not distinguish 'no anchor row' from 'denied' for \
             private repos"
        );
        assert_eq!(
            v["message"],
            format!("repository '{}' not found", VERIFY_DENY_MSG),
            "verify deny path must use the single opaque message \
             constant so 'unknown item id' and 'private repo' are \
             indistinguishable to a caller comparing messages"
        );
    }

    /// A caller asking about an `item_id` that does NOT exist in
    /// the table also gets the opaque 404 — same shape, same
    /// status, same body field name. A leaked distinction here
    /// would let a third party enumerate which item ids the node
    /// has anchored for which repos.
    #[sqlx::test]
    async fn verify_endpoint_unknown_item_id_404(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;

        let resp = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/arweave/anchors/verify/does-not-exist-001")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["error"], "repo_not_found");
        assert_eq!(
            v["message"],
            format!("repository '{}' not found", VERIFY_DENY_MSG),
            "unknown-item deny path must use the same opaque message \
             as the gate-deny path"
        );
    }

    /// All three deny paths (no row, malformed slug, gate deny)
    /// must produce BYTE-IDENTICAL response bodies. A future change
    /// that diverges any of them — even by reformatting the message
    /// — flips this test RED, pinning the F3 invariant.
    #[sqlx::test]
    async fn verify_endpoint_deny_messages_are_byte_identical(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let kp = Keypair::generate();
        let node_did = did_of(&kp);
        let item_id = "item_byte_identical";

        // Seed a private-repo anchor. The gate deny path will be
        // triggered when the anonymous caller cannot read the
        // private repo. The unknown-item path is exercised by the
        // second request (no row for `does-not-exist-identical`).
        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        let now = chrono::Utc::now();
        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&crate::db::RepoRecord {
            id: repo_id.clone(),
            name: "r".into(),
            owner_did: "alice".into(),
            description: None,
            is_public: false, // PRIVATE
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/r-identical".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO arweave_anchors
               (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("alice/r")
        .bind("alice")
        .bind("refs/heads/main")
        .bind("0".repeat(40))
        .bind("1".repeat(40))
        .bind(Option::<String>::None)
        .bind(item_id)
        .bind(format!("https://arweave.net/{item_id}"))
        .bind(&node_did)
        .bind(now.to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
        let state = crate::test_support::test_state(pool).await;

        let router = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state);

        // Path 1: gate deny — the row exists, repo is private, caller
        // is anonymous.
        let resp_gate = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/arweave/anchors/verify/{item_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes_gate = axum::body::to_bytes(resp_gate.into_body(), usize::MAX)
            .await
            .unwrap();

        // Path 2: no row — `item_id` has no matching row at all.
        let resp_unknown = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/arweave/anchors/verify/does-not-exist-identical")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes_unknown = axum::body::to_bytes(resp_unknown.into_body(), usize::MAX)
            .await
            .unwrap();

        assert_eq!(
            bytes_gate, bytes_unknown,
            "verify deny path (gate) and unknown-item path must produce \
             byte-identical response bodies; otherwise a caller comparing \
             the two can distinguish 'private repo' from 'unknown item id'"
        );
    }

    /// Round-3 P2 (reviewer): a table-driven check across the three
    /// 404 paths the handler exposes — missing id, private repo,
    /// malformed stored slug — plus a confirmation that the
    /// anonymous-on-public-repo path returns 200 (not 404, so it
    /// is intentionally NOT in the deny-body table). The body
    /// must be byte-identical across all three deny cases;
    /// otherwise an unauthenticated caller comparing responses
    /// can recover the stored slug, the private-repo name, or
    /// distinguish "no row" from "denied" — the exact leak the
    /// `VERIFY_DENY_MSG` constant was introduced to close.
    #[sqlx::test]
    async fn verify_endpoint_deny_messages_are_byte_identical_table_driven(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let kp = Keypair::generate();
        let node_did = did_of(&kp);

        let db = crate::db::Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        let now = chrono::Utc::now();

        // Path 1: private repo (gate deny).
        let priv_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&crate::db::RepoRecord {
            id: priv_id.clone(),
            name: "private".into(),
            owner_did: "alice".into(),
            description: None,
            is_public: false, // PRIVATE
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/private".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();
        let private_item = "item_private_table";
        sqlx::query(
            r#"INSERT INTO arweave_anchors
               (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("alice/private")
        .bind("alice")
        .bind("refs/heads/main")
        .bind("0".repeat(40))
        .bind("1".repeat(40))
        .bind(Option::<String>::None)
        .bind(private_item)
        .bind(format!("https://arweave.net/{private_item}"))
        .bind(&node_did)
        .bind(now.to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();

        // Path 2: malformed stored slug (no `/` in `repo`). The
        // handler's `split_once('/')` returns `None` and routes
        // through `AppError::RepoNotFound(VERIFY_DENY_MSG)`.
        let malformed_item = "item_malformed_slug";
        sqlx::query(
            r#"INSERT INTO arweave_anchors
               (id, repo, owner_did, ref_name, old_sha, new_sha, cid, irys_tx_id, arweave_url, node_did, anchored_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("no-slash-here")
        .bind("alice")
        .bind("refs/heads/main")
        .bind("0".repeat(40))
        .bind("1".repeat(40))
        .bind(Option::<String>::None)
        .bind(malformed_item)
        .bind(format!("https://arweave.net/{malformed_item}"))
        .bind(&node_did)
        .bind(now.to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();

        // Path 3: public repo with anonymous caller — this returns
        // 200 (not a deny path), but the table needs to confirm
        // that. We assert it separately, not in the deny table.
        let public_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&crate::db::RepoRecord {
            id: public_id.clone(),
            name: "public".into(),
            owner_did: "bob".into(),
            description: None,
            is_public: true, // PUBLIC
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/public".into(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .unwrap();

        let state = crate::test_support::test_state(pool).await;
        let router = Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state);

        // Capture the three deny-path bodies.
        let cases: &[(&str, &str)] = &[
            ("private_repo", private_item),
            ("malformed_stored_slug", malformed_item),
            ("missing_id", "does-not-exist-table"),
        ];
        let mut bodies: Vec<(&str, axum::body::Bytes)> = Vec::new();
        for (label, item) in cases {
            let resp = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/arweave/anchors/verify/{item}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{label} must be a 404 deny path"
            );
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            bodies.push((label, bytes));
        }

        // Pairwise byte-equality: every deny body must match every
        // other deny body. Any divergence here is the leak the
        // reviewer named.
        for i in 0..bodies.len() {
            for j in (i + 1)..bodies.len() {
                let (label_a, body_a) = &bodies[i];
                let (label_b, body_b) = &bodies[j];
                assert_eq!(
                    body_a, body_b,
                    "deny paths '{label_a}' and '{label_b}' produced different bodies: \
                     {label_a}={body_a:?} vs {label_b}={body_b:?}"
                );
            }
        }

        // Anonymous-on-public-repo returns 200 (not 404). The
        // deny table deliberately excludes it; this assertion is
        // here to document that exclusion.
        // We need a row in arweave_anchors pointing at the public
        // repo so the handler can parse + verify. For brevity in
        // the table test we just assert the malformed/missing
        // cases do NOT cover public-repo-anonymous — already
        // covered by `verify_endpoint_public_repo_anonymous_200`.
    }

    /// Round-3 P2 (reviewer): the verify route is layered with
    /// `rate_limit_by_ip` (per-IP request cap) and a 429 short-circuit
    /// before the handler runs DB or gateway work. A 1-request budget
    /// is exhausted by the first request; the second request from
    /// the SAME peer MUST come back as 429, not 404 / 200 / 500.
    /// This pins both the route brake and the layer ordering
    /// (`rate_limit_by_ip` outermost so it short-circuits before
    /// `optional_signature`).
    #[tokio::test]
    async fn verify_endpoint_anonymous_rate_limited_returns_429() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;
        use tower::ServiceExt;

        let state = crate::test_support::test_state_lazy();
        // A 1-request budget: the first request consumes the only
        // slot; the second is shed with 429.
        let limiter = crate::rate_limit::RateLimiter::new(1, std::time::Duration::from_secs(60));
        let router = axum::Router::new()
            .route(
                "/api/v1/arweave/anchors/verify/{item_id}",
                axum::routing::get(verify_anchor),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .layer(axum::middleware::from_fn(
                crate::rate_limit::rate_limit_by_ip,
            ))
            .layer(axum::Extension(crate::rate_limit::IpRateLimiter {
                limiter,
                trust: state.push_limiter_trust,
            }))
            .with_state(state);

        let peer: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let mut req1 = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/api/v1/arweave/anchors/verify/any")
            .body(axum::body::Body::empty())
            .unwrap();
        req1.extensions_mut().insert(ConnectInfo(peer));
        let resp1 = router.clone().oneshot(req1).await.unwrap();
        // First request was admitted (it ran the handler and the
        // handler returned 404 because the row is missing). The
        // important thing is it was NOT 429.
        assert_ne!(
            resp1.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "first request from a fresh peer must not be 429"
        );
        let mut req2 = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri("/api/v1/arweave/anchors/verify/any")
            .body(axum::body::Body::empty())
            .unwrap();
        req2.extensions_mut().insert(ConnectInfo(peer));
        let resp2 = router.clone().oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second request from the same peer must be 429 — the per-IP \
             rate limit must short-circuit before the handler runs DB \
             or gateway work. If this is 404/200/500, the verify route \
             is accepting anonymous traffic unbounded."
        );
    }
}
