//! Shared `#[cfg(test)]` HTTP-API integration-test harness.
//!
//! Provides a migrated [`AppState`] over a real `#[sqlx::test]` Postgres pool
//! ([`test_state`]), a DB-free variant for middleware tests that never query
//! ([`test_state_lazy`]), the assembled router ([`app`]), and a request builder
//! that injects an already-verified [`AuthenticatedDid`] without producing real
//! RFC-9421 signatures ([`signed_request_as`]).
//!
//! NOTE on auth: the production router wraps mutation routes in `add_auth_layers`
//! (`require_signature` then `require_ucan_chain`). `require_signature` rejects a
//! request that carries only an injected `AuthenticatedDid` (no real signature),
//! so [`app`] is for tests of *open* routes or no-auth-rejection paths. To test a
//! handler's own authorization (e.g. `require_owner`), mount the handler directly
//! with the state and inject the DID — see the `tests` module below, which
//! mirrors the pattern in `auth/mod.rs`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request};
use axum::Router;
use sqlx::PgPool;

use gitlawb_core::identity::Keypair;

use crate::auth::AuthenticatedDid;
use crate::state::AppState;

/// Build an [`AppState`] over a real, migrated Postgres pool (from `#[sqlx::test]`).
/// Runs the schema migrations first, because the per-test database starts empty.
///
/// **The config here is parsed from the process environment.** `Config` sources 47
/// fields from `GITLAWB_*` variables, so a developer or CI environment that sets one
/// silently changes what this state does. Never assert a behaviour that a config
/// field controls on top of this state — use [`test_state_with`] and set the field,
/// so the test states the configuration it is about instead of inheriting it.
pub(crate) async fn test_state(pool: PgPool) -> AppState {
    let db = Arc::new(crate::db::Db::for_testing(pool.clone()));
    db.run_migrations()
        .await
        .expect("test schema migrations should apply");
    build_state(db, pool)
}

/// [`test_state`] with an explicit config override, so a test that depends on a
/// setting pins it rather than inheriting whatever the environment supplies.
///
/// The shipped default is proved separately and env-independently by
/// `config::tests::enforce_owner_push_is_declared_true_independent_of_the_environment`,
/// which reads the declaration off the parser. Splitting the two keeps a parser
/// question and an authorization question from sharing one failure mode.
pub(crate) async fn test_state_with(
    pool: PgPool,
    configure: impl FnOnce(&mut crate::config::Config),
) -> AppState {
    let mut state = test_state(pool).await;
    let mut cfg = (*state.config).clone();
    configure(&mut cfg);
    state.config = Arc::new(cfg);
    state
}

/// DB-free [`AppState`] for middleware/auth tests that return before any query.
/// The pool is lazy and never connects — do NOT use for tests that hit the DB.
// Harness API consumed by the plan-002/003 middleware and no-auth-rejection tests.
#[allow(dead_code)]
pub(crate) fn test_state_lazy() -> AppState {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/gitlawb_test_placeholder")
        .expect("lazy pool creation should not fail");
    let db = Arc::new(crate::db::Db::for_testing(pool.clone()));
    build_state(db, pool)
}

fn build_state(db: Arc<crate::db::Db>, pool: PgPool) -> AppState {
    use crate::{config::Config, graphql, rate_limit::RateLimiter};
    use clap::Parser;

    let keypair = Keypair::generate();
    let scan_token_key = crate::state::AppState::derive_scan_token_key(&keypair);
    let node_did = keypair.did();
    let (ref_tx, _) = tokio::sync::broadcast::channel(1);
    let (task_tx, _) = tokio::sync::broadcast::channel(1);
    let schema = Arc::new(graphql::build_schema(
        db.clone(),
        ref_tx.clone(),
        task_tx.clone(),
    ));
    AppState {
        config: Arc::new(Config::parse_from(["gitlawb-node"])),
        db,
        node_did,
        node_keypair: Arc::new(keypair),
        p2p: None,
        http_client: Arc::new(reqwest::Client::new()),
        ref_update_tx: ref_tx,
        task_event_tx: task_tx,
        graphql_schema: schema,
        machine_id: None,
        repo_store: crate::git::repo_store::RepoStore::for_testing(PathBuf::from("/tmp"), pool),
        rate_limiter: RateLimiter::new(100, Duration::from_secs(60)),
        create_ip_rate_limiter: RateLimiter::new(1000, Duration::from_secs(3600)),
        push_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
        ipfs_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
        ipfs_work_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
        ipfs_max_history_walks: crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST,
        ipfs_max_legacy_probes: crate::api::ipfs::MAX_LEGACY_PROBES_PER_REQUEST,
        ipfs_legacy_scan_page_rows: crate::api::ipfs::LEGACY_SCAN_PAGE_ROWS,
        ipfs_max_legacy_scan_rows: crate::api::ipfs::MAX_LEGACY_SCAN_ROWS_PER_REQUEST,
        ipfs_max_legacy_scan_rule_bytes: crate::api::ipfs::MAX_LEGACY_SCAN_RULE_BYTES_PER_REQUEST,
        ipfs_scan_token_key: Arc::new(scan_token_key),
        ipfs_max_served_object_bytes: crate::api::ipfs::MAX_SERVED_OBJECT_BYTES,
        push_limiter_trust: crate::rate_limit::TrustedProxy::None,
        sync_trigger_rate_limiter: RateLimiter::new(60, Duration::from_secs(3600)),
        peer_write_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
        shutdown_tx: tokio::sync::watch::channel(false).0,
        // Generous — no test drives the handler-level shed (git_permit is unit-tested).
        git_read_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        git_write_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        git_push_advert_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        git_encrypt_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        pin_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        encrypt_inflight: crate::state::EncryptInflight::new(),
        repo_write_leases: crate::state::RepoWriteLeases::new(8),
        git_read_per_caller: crate::rate_limit::PerCallerConcurrency::with_default_max_keys(16),
        git_push_advert_per_caller: crate::rate_limit::PerCallerConcurrency::with_default_max_keys(
            8,
        ),
        git_write_per_caller: crate::rate_limit::PerCallerConcurrency::with_default_max_keys(8),
        // Generous — a test that drives the /ipfs walk shed overrides these directly.
        git_ipfs_walk_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        git_ipfs_walk_per_caller: crate::rate_limit::PerCallerConcurrency::with_default_max_keys(
            16,
        ),
        git_bin: "git".to_string(),
    }
}

/// The full production router over a migrated test state. See the module note:
/// requests through this router must carry a real signature, so it suits open
/// routes and no-auth-rejection tests, not injected-DID authorization tests.
// Harness API consumed by plan-003's no-auth GraphQL test and open-route tests.
#[allow(dead_code)]
pub(crate) async fn app(pool: PgPool) -> Router {
    crate::server::build_router(test_state(pool).await)
}

/// Build a request carrying an already-verified [`AuthenticatedDid`] extension,
/// so a handler mounted without `require_signature` sees the caller identity.
/// Sets `Content-Type: application/json` — the API is JSON throughout, and
/// without it axum's `Json` extractor returns 415 before the handler runs
/// (which would make any JSON-body authz assertion a false pass).
pub(crate) fn signed_request_as(did: &str, method: Method, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .extension(AuthenticatedDid(did.to_string()))
        .body(body)
        .expect("request builder")
}

/// A local endpoint whose TCP accept succeeds instantly but that never writes an
/// HTTP response, so any request against it stalls deterministically until the
/// caller's own timeout. (A non-routable address hangs only if the network
/// blackholes the SYN — a fast RST would end the stall early and make a timeout
/// test pass for the wrong reason.) The accepted sockets are parked in the
/// spawned task, which dies with the test's runtime, so the peer never sees a
/// close mid-test.
pub(crate) async fn silent_http_endpoint() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    endpoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AgentTask, RepoRecord};
    use axum::http::StatusCode;
    use chrono::Utc;
    use tower::ServiceExt;

    fn seed_repo(owner_did: &str, name: &str) -> RepoRecord {
        let now = Utc::now();
        RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner_did.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{name}"),
            forked_from: None,
            machine_id: None,
        }
    }

    /// Proves the harness end to end: a migrated DB, a seeded repo, and the
    /// owner gate on an ALREADY-gated endpoint (`PUT /visibility`, gated by
    /// `require_owner`). Non-owner is rejected; owner succeeds. Mounts the
    /// handler directly (not via `app`) because `require_signature` would
    /// reject the injected-DID request — see the module note.
    #[sqlx::test]
    async fn visibility_set_is_owner_gated(pool: PgPool) {
        let owner = "did:key:zHARNESSOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zHARNESSSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBB";

        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "harness-repo"))
            .await
            .expect("seed repo");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/visibility",
                    axum::routing::put(crate::api::visibility::set_visibility),
                )
                .with_state(state.clone())
        };
        let uri = format!("/api/v1/repos/{owner}/harness-repo/visibility");
        let body = || Body::from(r#"{"path_glob":"/","reader_dids":[]}"#);

        // Non-owner → rejected by require_owner with 403 Forbidden. Asserting the
        // exact code proves the rejection came from the owner gate, not an
        // incidental 404/415.
        let resp = router()
            .oneshot(signed_request_as(stranger, Method::PUT, &uri, body()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "non-owner must be rejected by the owner gate"
        );

        // Owner → accepted (2xx).
        let resp = router()
            .oneshot(signed_request_as(owner, Method::PUT, &uri, body()))
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "owner should be allowed to set visibility, got {}",
            resp.status()
        );
    }

    /// PR3 (#62): the served-git concurrency cap sheds at the HTTP layer before the
    /// DB. The held `git_permit` acquire now sits after the per-source cap, so the
    /// cheap early shed is carried by an explicit `available_permits() == 0` check at
    /// the top of the handler (the held permit remains the authoritative bound further
    /// down). That check is a permit-less snapshot: it spares a request's DB work once
    /// the pool is ALREADY saturated, which is the case this test drives, and it does
    /// not bound the DB window in general. DB-free here because an exhausted semaphore
    /// sheds before any DB/disk access, so a lazy state works. Remove the early-shed block
    /// from git_info_refs and this goes red (the request falls through to the DB and
    /// returns something other than 503).
    #[tokio::test]
    async fn git_info_refs_sheds_with_503_when_semaphore_exhausted() {
        let mut state = test_state_lazy();
        state.git_read_semaphore = Arc::new(tokio::sync::Semaphore::new(0));

        let router = Router::new()
            .route(
                "/{owner}/{repo}/info/refs",
                axum::routing::get(crate::api::repos::git_info_refs),
            )
            .with_state(state);
        let resp = router
            .oneshot(anon_get(
                "/alice/repo.git/info/refs?service=git-upload-pack",
            ))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exhausted git semaphore must shed info/refs with 503 before touching the DB"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the 503 shed must carry Retry-After"
        );
    }

    /// PR3 (#62) sibling of the info/refs shed test: git-upload-pack carries the same
    /// explicit `available_permits() == 0` early check at the top, so an ALREADY
    /// exhausted semaphore must shed the request with a 503 before its DB/disk work.
    /// That is the case the permit-less snapshot does deliver; it is not an admission
    /// bound on the DB window. Anonymous-reachable, so no auth injection is needed.
    /// Remove the early-shed block from git_upload_pack and this goes red.
    #[tokio::test]
    async fn git_upload_pack_sheds_with_503_when_semaphore_exhausted() {
        let mut state = test_state_lazy();
        state.git_read_semaphore = Arc::new(tokio::sync::Semaphore::new(0));

        let router = Router::new()
            .route(
                "/{owner}/{repo}/git-upload-pack",
                axum::routing::post(crate::api::repos::git_upload_pack),
            )
            .with_state(state);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/alice/repo.git/git-upload-pack")
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exhausted git semaphore must shed git-upload-pack with 503 before touching the DB"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the 503 shed must carry Retry-After"
        );
    }

    /// PR3 (#62) receive-pack sibling of the info/refs shed test: the early shed
    /// selects the dedicated ADVERT pool for a git-receive-pack advertisement (#174),
    /// so an ALREADY exhausted advert pool sheds the advert with 503 before its DB/disk
    /// work (the case the permit-less snapshot delivers, not an admission bound on the
    /// DB window), while the write pool (reserved for authenticated POSTs) is left
    /// free here.
    /// Flip the pool selection back to the write pool, or remove the early-shed
    /// block, and this goes red.
    #[tokio::test]
    async fn git_info_refs_receive_pack_sheds_with_503_when_advert_pool_exhausted() {
        let mut state = test_state_lazy();
        state.git_push_advert_semaphore = Arc::new(tokio::sync::Semaphore::new(0));

        let router = Router::new()
            .route(
                "/{owner}/{repo}/info/refs",
                axum::routing::get(crate::api::repos::git_info_refs),
            )
            .with_state(state);
        let resp = router
            .oneshot(anon_get(
                "/alice/repo.git/info/refs?service=git-receive-pack",
            ))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exhausted ADVERT pool must shed the receive-pack advertisement with 503 before touching the DB"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the 503 shed must carry Retry-After"
        );
    }

    /// PR3 (#62) sibling for the push path: git-receive-pack requires an
    /// AuthenticatedDid extension (production: require_signature injects it), so the
    /// request carries one via signed_request_as — without it the Extension
    /// extractor 500s before the handler body reaches the shed. What sits at the top of
    /// the handler is a permit-less `available_permits() == 0` peek, NOT the permit
    /// itself: the authoritative held acquire is taken after the per-repo lease, so a
    /// lease-blocked waiter pins no write slot. An ALREADY exhausted pool is the case
    /// the peek delivers, so the request sheds 503 before its DB work here. Remove the
    /// early-shed block from git_receive_pack and this goes red.
    #[tokio::test]
    async fn git_receive_pack_sheds_with_503_when_semaphore_exhausted() {
        let mut state = test_state_lazy();
        state.git_write_semaphore = Arc::new(tokio::sync::Semaphore::new(0));

        let router = Router::new()
            .route(
                "/{owner}/{repo}/git-receive-pack",
                axum::routing::post(crate::api::repos::git_receive_pack),
            )
            .with_state(state);
        let owner = "did:key:zRECVSHEDOWNERAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let resp = router
            .oneshot(signed_request_as(
                owner,
                Method::POST,
                "/alice/repo.git/git-receive-pack",
                Body::from(&b"0000"[..]),
            ))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exhausted write pool must shed git-receive-pack with 503 before touching the DB"
        );
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok()),
            Some("1"),
            "the 503 shed must carry Retry-After"
        );
    }

    /// #174 (SC1, load-bearing): a saturated READ pool must NOT shed an
    /// authenticated push — the write pool is a separate budget. Read pool at zero,
    /// write pool with capacity: the push proceeds PAST admission (it then errors on
    /// the placeholder DB, but crucially it is not a 503). Route git-receive-pack
    /// back to the read pool and this goes red — that is the isolation proof.
    #[tokio::test]
    async fn git_receive_pack_not_shed_by_exhausted_read_pool() {
        let mut state = test_state_lazy();
        // Read pool exhausted as if a flood of anonymous clones held every slot.
        state.git_read_semaphore = Arc::new(tokio::sync::Semaphore::new(0));
        // Write pool keeps its default capacity from test_state_lazy.

        let router = Router::new()
            .route(
                "/{owner}/{repo}/git-receive-pack",
                axum::routing::post(crate::api::repos::git_receive_pack),
            )
            .with_state(state);
        let owner = "did:key:zRECVCROSSBOUNDARYAAAAAAAAAAAAAAAAAAAAA";
        let resp = router
            .oneshot(signed_request_as(
                owner,
                Method::POST,
                "/alice/repo.git/git-receive-pack",
                Body::from(&b"0000"[..]),
            ))
            .await
            .unwrap();

        assert_ne!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "an exhausted READ pool must not shed a push — the write pool is a separate budget (#174)"
        );
    }

    /// N7: merge_pr is owner-only. A non-owner is rejected by require_repo_owner
    /// before any git work (so no on-disk repo is needed for the rejection).
    #[sqlx::test]
    async fn merge_pr_rejects_non_owner(pool: PgPool) {
        let owner = "did:key:zMERGEOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zMERGESTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "merge-repo"))
            .await
            .expect("seed repo");

        let router = Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/pulls/{number}/merge",
                axum::routing::post(crate::api::pulls::merge_pr),
            )
            .with_state(state);
        let uri = format!("/api/v1/repos/{owner}/merge-repo/pulls/1/merge");
        let resp = router
            .oneshot(signed_request_as(
                stranger,
                Method::POST,
                &uri,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a non-owner must not be able to merge"
        );
    }

    /// #98: forking a repo with a path-scoped subtree the caller cannot read is
    /// refused with 404, before any clone. A public repo with a `/secret/**` rule
    /// that excludes the stranger lets the stranger pass the `/` read gate but not
    /// fork the full mirror. Pins the wiring (rules bound, gate before the clone);
    /// a regression to `_rules` or moving the gate past `repo_store.acquire` fails
    /// here. No on-disk source repo is needed — the refusal precedes acquire.
    #[sqlx::test]
    async fn fork_rejects_non_owner_with_withheld_subtree(pool: PgPool) {
        let owner = "did:key:zFORKOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zFORKSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;
        let repo = seed_repo(owner, "fork-repo");
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.expect("seed repo");
        state
            .db
            .set_visibility_rule(
                &repo_id,
                "/secret/**",
                crate::db::VisibilityMode::B,
                &[],
                owner,
            )
            .await
            .expect("seed visibility rule");

        let router = Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/fork",
                axum::routing::post(crate::api::repos::fork_repo),
            )
            .with_state(state.clone());
        let uri = format!("/api/v1/repos/{owner}/fork-repo/fork");
        let resp = router
            .oneshot(signed_request_as(
                stranger,
                Method::POST,
                &uri,
                Body::from("{}"),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "fork of a repo with a withheld subtree must be refused with 404"
        );

        // The fork must not have been created under the stranger's ownership.
        let stranger_short = stranger.split(':').next_back().unwrap();
        assert!(
            state
                .db
                .get_repo(stranger_short, "fork-repo")
                .await
                .expect("get_repo")
                .is_none(),
            "no fork row may be created for a refused fork"
        );
    }

    /// N13: the task handlers bind the acting DID to the signer. A caller signed
    /// as B claiming delegator_did A is rejected before any DB write (DB-free).
    #[sqlx::test]
    async fn create_task_binds_delegator_to_signer(pool: PgPool) {
        let signer = "did:key:zSIGNERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let claimed = "did:key:zCLAIMEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;

        let router = Router::new()
            .route(
                "/api/v1/tasks",
                axum::routing::post(crate::api::tasks::create_task),
            )
            .with_state(state);
        let body = Body::from(format!(
            r#"{{"kind":"build","capability":"repo:write","delegator_did":"{claimed}"}}"#
        ));
        let resp = router
            .oneshot(signed_request_as(
                signer,
                Method::POST,
                "/api/v1/tasks",
                body,
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "delegator_did must be bound to the signer"
        );
    }

    /// N3: get_tree gates on the REQUESTED subtree, not the repo root. A caller
    /// denied a withheld subtree is rejected there (404) but passes the gate on a
    /// non-withheld path (so the rejection is path-scoped, not repo-wide).
    #[sqlx::test]
    async fn get_tree_gate_is_path_scoped(pool: PgPool) {
        use crate::db::VisibilityMode;
        let owner = "did:key:zTREEOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zTREESTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;
        let repo = seed_repo(owner, "tree-repo");
        state.db.create_repo(&repo).await.expect("seed repo");
        // Withhold /secret/** from everyone but the owner.
        state
            .db
            .set_visibility_rule(&repo.id, "/secret/**", VisibilityMode::B, &[], owner)
            .await
            .expect("set rule");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/tree/{*path}",
                    axum::routing::get(crate::api::repos::get_tree),
                )
                .with_state(state.clone())
        };

        // Withheld subtree → denied at the gate (opaque 404), before any disk access.
        let resp = router()
            .oneshot(signed_request_as(
                stranger,
                Method::GET,
                &format!("/api/v1/repos/{owner}/tree-repo/tree/secret"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "withheld subtree must be denied"
        );

        // Non-withheld path → passes the gate (whatever the disk layer then returns,
        // it is NOT the gate's 404). Proves the gate keyed off the path, not the repo.
        let resp = router()
            .oneshot(signed_request_as(
                stranger,
                Method::GET,
                &format!("/api/v1/repos/{owner}/tree-repo/tree/public"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a non-withheld path must pass the path-scoped gate (exact 200, so a \
             future upstream 4xx/5xx cannot masquerade as gate-pass)"
        );
    }

    fn seed_task(id: &str, delegator: &str) -> AgentTask {
        let now = Utc::now().to_rfc3339();
        AgentTask {
            id: id.to_string(),
            repo_id: None,
            kind: "build".to_string(),
            status: "pending".to_string(),
            delegator_did: delegator.to_string(),
            assignee_did: None,
            capability: "repo:write".to_string(),
            ucan_token: None,
            payload: None,
            result: None,
            created_at: now.clone(),
            updated_at: now,
            deadline: None,
        }
    }

    /// Adversarial-review GATE-1: complete_task authorizes the assignee, not just
    /// the claimed identity. A stranger (even with an empty body, which used to
    /// skip the signer binding entirely) is rejected; the assignee succeeds; and a
    /// task that is no longer `claimed` cannot transition again.
    #[sqlx::test]
    async fn complete_task_authorizes_assignee_only(pool: PgPool) {
        let delegator = "did:key:zTASKDELEGATORAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let assignee = "did:key:zTASKASSIGNEEBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let stranger = "did:key:zTASKSTRANGERCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let state = test_state(pool).await;
        state
            .db
            .create_task(&seed_task("task-1", delegator))
            .await
            .expect("seed task");
        // Assignee claims it: pending -> claimed, assignee_did = assignee.
        state
            .db
            .claim_task("task-1", assignee)
            .await
            .expect("claim");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/tasks/{id}/complete",
                    axum::routing::post(crate::api::tasks::complete_task),
                )
                .with_state(state.clone())
        };
        let uri = "/api/v1/tasks/task-1/complete";
        let body = || Body::from("{}");

        // Stranger (not the assignee) is rejected by the authorization gate, even
        // with the empty body that previously bypassed the binding. Exact 403.
        let resp = router()
            .oneshot(signed_request_as(stranger, Method::POST, uri, body()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a non-assignee must not complete the task"
        );

        // The assignee completes successfully.
        let resp = router()
            .oneshot(signed_request_as(assignee, Method::POST, uri, body()))
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "the assignee should complete the task, got {}",
            resp.status()
        );

        // The task is now `completed`, not `claimed`; the status predicate in
        // finish_task rejects a second transition (proves only a claimed task moves).
        let resp = router()
            .oneshot(signed_request_as(assignee, Method::POST, uri, body()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "a task that is no longer claimed must not transition again"
        );
    }

    /// Adversarial-review GATE-2 (create_pr): opening a PR requires read access.
    /// A non-reader is denied on a private repo before any PR is created; the
    /// owner is allowed.
    #[sqlx::test]
    async fn create_pr_denies_non_reader_on_private_repo(pool: PgPool) {
        let owner = "did:key:zPROWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zPRSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;
        let mut repo = seed_repo(owner, "priv-pr-repo");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed repo");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/pulls",
                    axum::routing::post(crate::api::pulls::create_pr),
                )
                .with_state(state.clone())
        };
        let uri = format!("/api/v1/repos/{owner}/priv-pr-repo/pulls");
        let body = || Body::from(r#"{"title":"x","source_branch":"feature"}"#);

        // Non-reader on a private repo: opaque 404 (RepoNotFound), no PR created.
        let resp = router()
            .oneshot(signed_request_as(stranger, Method::POST, &uri, body()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a non-reader must not open a PR against a private repo"
        );

        // Owner is a reader, so the gate admits them (create_pr does no disk I/O).
        let resp = router()
            .oneshot(signed_request_as(owner, Method::POST, &uri, body()))
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "the owner should be able to open a PR, got {}",
            resp.status()
        );
    }

    /// Adversarial-review GATE-2 (create_issue): filing an issue requires read
    /// access. A non-reader is denied on a private repo before any git work.
    #[sqlx::test]
    async fn create_issue_denies_non_reader_on_private_repo(pool: PgPool) {
        let owner = "did:key:zISOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zISSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;
        let mut repo = seed_repo(owner, "priv-issue-repo");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed repo");

        let router = Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/issues",
                axum::routing::post(crate::api::issues::create_issue),
            )
            .with_state(state);
        let uri = format!("/api/v1/repos/{owner}/priv-issue-repo/issues");
        let resp = router
            .oneshot(signed_request_as(
                stranger,
                Method::POST,
                &uri,
                Body::from(r#"{"title":"x","body":"y"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a non-reader must not file an issue against a private repo"
        );
    }

    /// Adversarial-review D3-1: register binds the registered DID to the signer.
    /// A caller signed as A cannot register a different DID B (no spoofed
    /// registration or trust row under a victim DID). Rejected before any write.
    #[sqlx::test]
    async fn register_binds_did_to_signer(pool: PgPool) {
        let signer = "did:key:zREGSIGNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let other = "did:key:zREGOTHERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;
        let router = Router::new()
            .route(
                "/api/register",
                axum::routing::post(crate::api::register::register),
            )
            .with_state(state);
        let resp = router
            .oneshot(signed_request_as(
                signer,
                Method::POST,
                "/api/register",
                Body::from(format!(r#"{{"did":"{other}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "register must reject a DID other than the signer"
        );
    }

    /// Issue #6 / jatmn finding 1: the GraphQL `repos` query renders one logical
    /// repo per mirror+canonical pair. Seeds a canonical `did:key:` repo plus its
    /// short-owner mirror row and a distinct standalone repo, then asserts the
    /// query returns two entries (not three) and the shared repo appears once as
    /// the canonical owner.
    #[sqlx::test]
    async fn graphql_repos_is_deduped(pool: PgPool) {
        let short = "zGRAPHQLDEDUPAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(&format!("did:key:{short}"), "shared"))
            .await
            .expect("seed canonical");
        state
            .db
            .upsert_mirror_repo(short, "shared", "/tmp/mirror", None, false)
            .await
            .expect("seed mirror");
        state
            .db
            .create_repo(&seed_repo(
                "did:key:zGQLOTHERBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "solo",
            ))
            .await
            .expect("seed standalone");

        let resp = state
            .graphql_schema
            .execute(async_graphql::Request::new("{ repos { name ownerDid } }"))
            .await;
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        let data = resp.data.into_json().expect("graphql data to json");
        let repos = data["repos"].as_array().expect("repos array");
        assert_eq!(
            repos.len(),
            2,
            "mirror+canonical collapse to one logical repo, plus the standalone"
        );
        let shared: Vec<_> = repos.iter().filter(|r| r["name"] == "shared").collect();
        assert_eq!(shared.len(), 1, "the shared repo must not be double-listed");
        assert_eq!(
            shared[0]["ownerDid"],
            serde_json::json!(format!("did:key:{short}")),
            "the canonical did:key row is the survivor"
        );
    }

    /// #94: list_webhooks is gated read-visibility THEN owner. Webhook callback
    /// URLs are owner-secret, so the listing must hide a private repo's existence
    /// (404, uniform with the read-visibility siblings) and 403 a non-owner of a
    /// public repo, while a headerless caller gets 401 (no anonymous form). Mounts
    /// the handler directly (it sits on `optional_signature`, so the handler does
    /// its own check) and seeds a real webhook so a leak would surface in the body.
    #[sqlx::test]
    async fn list_webhooks_is_owner_gated(pool: PgPool) {
        let owner = "did:key:zHOOKOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zHOOKSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;

        let pub_repo = seed_repo(owner, "hook-pub");
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public repo");
        let mut priv_repo = seed_repo(owner, "hook-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");

        let secret_url = "https://hooks.example.com/sekret-endpoint";
        for repo in [&pub_repo, &priv_repo] {
            state
                .db
                .create_webhook(&crate::db::Webhook {
                    id: uuid::Uuid::new_v4().to_string(),
                    repo_id: repo.id.clone(),
                    url: secret_url.to_string(),
                    secret: Some("topsecret".to_string()),
                    events: vec!["*".to_string()],
                    created_by_did: owner.to_string(),
                    created_at: Utc::now().to_rfc3339(),
                    active: true,
                })
                .await
                .expect("seed webhook");
        }

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/hooks",
                    axum::routing::get(crate::api::webhooks::list_webhooks),
                )
                .with_state(state.clone())
        };
        let body_text = |resp_body: &[u8]| String::from_utf8_lossy(resp_body).to_string();

        // Owner on the public repo → 200, hook listed, secret redacted, url present.
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{owner}/hook-pub/hooks"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "owner must read its own hooks"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let txt = body_text(&bytes);
        assert!(
            txt.contains(secret_url),
            "owner response must include the url"
        );
        assert!(txt.contains("***"), "secret must stay redacted");
        assert!(
            !txt.contains("topsecret"),
            "the real secret must never appear"
        );

        // Non-owner of a PUBLIC repo → 403 (repo is public, existence not secret).
        let resp = router()
            .oneshot(signed_request_as(
                stranger,
                Method::GET,
                &format!("/api/v1/repos/{owner}/hook-pub/hooks"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a non-owner of a public repo must be forbidden, not served"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body_text(&bytes).contains(secret_url),
            "403 must not leak the url"
        );

        // Non-owner of a PRIVATE repo → 404 (existence hidden, uniform with siblings).
        let resp = router()
            .oneshot(signed_request_as(
                stranger,
                Method::GET,
                &format!("/api/v1/repos/{owner}/hook-priv/hooks"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a non-reader of a private repo must get 404, not 403/200"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body_text(&bytes).contains(secret_url),
            "404 must not leak the url"
        );

        // Owner of a PRIVATE repo → 200 (both guards pass: read-visibility admits
        // the owner, then require_repo_owner admits the owner). Exercises the
        // both-pass branch the public/owner case does not, and confirms redaction.
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{owner}/hook-priv/hooks"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the owner must read its own private repo's hooks"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let txt = body_text(&bytes);
        assert!(
            txt.contains(secret_url),
            "owner of private repo sees the url"
        );
        assert!(
            txt.contains("***"),
            "secret stays redacted on the private repo"
        );

        // Headerless (no AuthenticatedDid) → 401: a webhook listing has no anon form.
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/repos/{owner}/hook-pub/hooks"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a headerless caller must get 401"
        );

        // Absent repo → 404.
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{owner}/does-not-exist/hooks"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "absent repo → 404");
    }

    /// #94: a visibility READER who is not the owner passes the read gate but is
    /// still refused the webhook list (the require_repo_owner half), and the
    /// headerless 401 fires before any lookup so it cannot be an existence oracle
    /// (headerless on an existing private repo and on an absent repo both 401).
    #[sqlx::test]
    async fn list_webhooks_reader_403_and_no_existence_oracle(pool: PgPool) {
        use crate::db::VisibilityMode;
        let owner = "did:key:zHKRDROWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let reader = "did:key:zHKRDRREADERBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;

        let mut repo = seed_repo(owner, "hook-reader");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed repo");
        // Root allow-list rule: `reader` may read the repo at "/", but is not the owner.
        state
            .db
            .set_visibility_rule(
                &repo.id,
                "/",
                VisibilityMode::B,
                &[reader.to_string()],
                owner,
            )
            .await
            .expect("seed reader rule");
        let secret_url = "https://hooks.example.com/reader-case";
        state
            .db
            .create_webhook(&crate::db::Webhook {
                id: uuid::Uuid::new_v4().to_string(),
                repo_id: repo.id.clone(),
                url: secret_url.to_string(),
                secret: None,
                events: vec!["*".to_string()],
                created_by_did: owner.to_string(),
                created_at: Utc::now().to_rfc3339(),
                active: true,
            })
            .await
            .expect("seed webhook");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/hooks",
                    axum::routing::get(crate::api::webhooks::list_webhooks),
                )
                .with_state(state.clone())
        };

        // A listed reader passes authorize_repo_read but is not the owner → 403,
        // and the webhook url does not leak.
        let resp = router()
            .oneshot(signed_request_as(
                reader,
                Method::GET,
                &format!("/api/v1/repos/{owner}/hook-reader/hooks"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a non-owner reader passes the read gate but is refused the webhook list"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(secret_url),
            "403 must not leak the url to a reader"
        );

        // Existence-oracle check: headerless on the existing private repo → 401,
        // headerless on an absent repo → 401. Indistinguishable ⇒ no oracle.
        let headerless = |uri: String| {
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        };
        let resp = router()
            .oneshot(headerless(format!(
                "/api/v1/repos/{owner}/hook-reader/hooks"
            )))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "headerless on an existing private repo → 401 (before any lookup)"
        );
        let resp = router()
            .oneshot(headerless(format!(
                "/api/v1/repos/{owner}/no-such-repo/hooks"
            )))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "headerless on an absent repo → 401 too, so existence does not leak"
        );
    }

    /// #94: the read-visibility surfaces admit a listed reader who is NOT the
    /// owner (the allow-list branch of visibility_check). Pins that a private
    /// repo's reader — not just its owner — can read replicas and protected
    /// branches, while a non-reader stranger still 404s.
    #[sqlx::test]
    async fn read_visibility_admits_listed_reader(pool: PgPool) {
        use crate::db::VisibilityMode;
        let owner = "did:key:zRDRDOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let reader = "did:key:zRDRDREADERBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let stranger = "did:key:zRDRDSTRGRCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let state = test_state(pool).await;

        let mut repo = seed_repo(owner, "rdr-repo");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed repo");
        state
            .db
            .set_visibility_rule(
                &repo.id,
                "/",
                VisibilityMode::B,
                &[reader.to_string()],
                owner,
            )
            .await
            .expect("seed reader rule");
        state
            .db
            .register_replica(&repo.id, stranger, "https://replica.example.com/x")
            .await
            .expect("seed replica");
        state
            .db
            .protect_branch(&repo.id, "main", owner)
            .await
            .expect("seed protected branch");

        let call = |handler_router: Router, did: Option<&str>, uri: String| {
            let req = match did {
                Some(d) => signed_request_as(d, Method::GET, &uri, Body::empty()),
                None => Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            };
            handler_router.oneshot(req)
        };

        let replicas_router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/replicas",
                    axum::routing::get(crate::api::replicas::list_replicas),
                )
                .with_state(state.clone())
        };
        let protect_router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/branches/protected",
                    axum::routing::get(crate::api::protect::list_protected_branches),
                )
                .with_state(state.clone())
        };

        // Listed reader (non-owner) → 200 on both surfaces.
        for (router, path) in [
            (replicas_router(), "replicas"),
            (protect_router(), "branches/protected"),
        ] {
            let resp = call(
                router,
                Some(reader),
                format!("/api/v1/repos/{owner}/rdr-repo/{path}"),
            )
            .await
            .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "a listed reader must read {path}"
            );
        }

        // A non-reader stranger → 404 on both (deny path).
        for (router, path) in [
            (replicas_router(), "replicas"),
            (protect_router(), "branches/protected"),
        ] {
            let resp = call(
                router,
                Some(stranger),
                format!("/api/v1/repos/{owner}/rdr-repo/{path}"),
            )
            .await
            .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "a non-reader stranger must be denied {path}"
            );
        }
    }

    /// #94 sibling: list_replicas is read-visibility-gated. Replica lists are a
    /// documented public mirror-discovery surface, so a PUBLIC repo stays
    /// anonymously listable, but a PRIVATE repo must not leak its replica URLs.
    /// register_replica registers NON-owner DIDs (it rejects the owner), and a
    /// replica operator is not a visibility reader, so a non-owner replica
    /// operator of a private repo gets 404 — the intended contract, pinned here.
    #[sqlx::test]
    async fn list_replicas_is_read_visibility_gated(pool: PgPool) {
        let owner = "did:key:zREPLOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let replica_op = "did:key:zREPLOPERATORBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;

        let pub_repo = seed_repo(owner, "repl-pub");
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public repo");
        let mut priv_repo = seed_repo(owner, "repl-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");

        let replica_url = "https://replica.example.com/mirror-endpoint";
        for repo in [&pub_repo, &priv_repo] {
            state
                .db
                .register_replica(&repo.id, replica_op, replica_url)
                .await
                .expect("seed replica");
        }

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/replicas",
                    axum::routing::get(crate::api::replicas::list_replicas),
                )
                .with_state(state.clone())
        };
        let leaks = |bytes: &[u8]| String::from_utf8_lossy(bytes).contains(replica_url);
        let anon = |uri: String| {
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        };

        // Public repo, anonymous → 200, replicas listed (mirror-discovery preserved).
        let resp = router()
            .oneshot(anon(format!("/api/v1/repos/{owner}/repl-pub/replicas")))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "public replica list stays anonymous"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            leaks(&bytes),
            "public response must include the replica url"
        );

        // Private repo, anonymous → 404, no replica URL leaked.
        let resp = router()
            .oneshot(anon(format!("/api/v1/repos/{owner}/repl-priv/replicas")))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "private replica list is hidden from anon"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!leaks(&bytes), "404 must not leak the replica url");

        // Private repo, owner → 200.
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{owner}/repl-priv/replicas"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "owner reads its private replica list"
        );

        // Private repo, the non-owner replica operator → 404 (intended contract:
        // a replica operator is not a visibility reader).
        let resp = router()
            .oneshot(signed_request_as(
                replica_op,
                Method::GET,
                &format!("/api/v1/repos/{owner}/repl-priv/replicas"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a non-owner replica operator of a private repo is not a reader"
        );

        // Absent repo → 404.
        let resp = router()
            .oneshot(anon(format!("/api/v1/repos/{owner}/no-such-repo/replicas")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "absent repo → 404");
    }

    /// #94 sibling: list_labels is read-visibility-gated. A public repo's labels
    /// stay anonymously listable; a private repo's label names must not leak to a
    /// non-reader (404). A listed reader of the private repo reads the label; the
    /// owner reads it; a non-reader stranger 404s.
    #[sqlx::test]
    async fn list_labels_is_read_visibility_gated(pool: PgPool) {
        use crate::db::VisibilityMode;
        let owner = "did:key:zLBLOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let reader = "did:key:zLBLREADERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let stranger = "did:key:zLBLSTRGRCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let state = test_state(pool).await;

        let mut repo = seed_repo(owner, "lbl-priv");
        repo.is_public = false;
        state
            .db
            .create_repo(&repo)
            .await
            .expect("seed private repo");
        state
            .db
            .set_visibility_rule(
                &repo.id,
                "/",
                VisibilityMode::B,
                &[reader.to_string()],
                owner,
            )
            .await
            .expect("seed reader rule");
        state
            .db
            .add_label(&repo.id, "bug")
            .await
            .expect("seed label");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/labels",
                    axum::routing::get(crate::api::labels::list_labels),
                )
                .with_state(state.clone())
        };
        let leaks = |bytes: &[u8]| String::from_utf8_lossy(bytes).contains("bug");
        let uri = format!("/api/v1/repos/{owner}/lbl-priv/labels");

        // Owner (signed) → 200, sees the label.
        let resp = router()
            .oneshot(signed_request_as(owner, Method::GET, &uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "owner reads its private labels"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(leaks(&bytes), "owner response must include the label");

        // Listed reader (signed, non-owner) → 200, sees the label.
        let resp = router()
            .oneshot(signed_request_as(reader, Method::GET, &uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a listed reader reads the labels"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            leaks(&bytes),
            "listed reader response must include the label"
        );

        // Non-reader stranger (signed) → 404, no label leaked.
        let resp = router()
            .oneshot(signed_request_as(
                stranger,
                Method::GET,
                &uri,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a non-reader stranger is denied the private labels"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!leaks(&bytes), "404 must not leak the label name");

        // Anonymous on the private repo → 404.
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "anon is denied the private labels"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!leaks(&bytes), "anon 404 must not leak the label name");

        // Public repo, anonymous → 200, label visible. The gate must not break
        // the existing anonymous read path for public repos.
        let pub_repo = seed_repo(owner, "lbl-pub");
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public repo");
        state
            .db
            .add_label(&pub_repo.id, "pubtag")
            .await
            .expect("seed public label");
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/repos/{owner}/lbl-pub/labels"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a public repo's labels stay anonymously listable"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&bytes).contains("pubtag"),
            "public anon response must include the label"
        );

        // Absent repo → 404 (uniform with the non-reader denial; no 500).
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/repos/{owner}/no-such-repo/labels"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "absent repo → 404");
    }

    /// #94 sibling: list_protected_branches is read-visibility-gated. A public
    /// repo's protected-branch listing stays anonymous; a private repo must not
    /// leak its branch names to a non-reader (404, uniform no-existence-oracle).
    #[sqlx::test]
    async fn list_protected_branches_is_read_visibility_gated(pool: PgPool) {
        let owner = "did:key:zPROTOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;

        let pub_repo = seed_repo(owner, "prot-pub");
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public repo");
        let mut priv_repo = seed_repo(owner, "prot-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");

        let secret_branch = "release-embargoed";
        for repo in [&pub_repo, &priv_repo] {
            state
                .db
                .protect_branch(&repo.id, secret_branch, owner)
                .await
                .expect("seed protected branch");
        }

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/branches/protected",
                    axum::routing::get(crate::api::protect::list_protected_branches),
                )
                .with_state(state.clone())
        };
        let leaks = |bytes: &[u8]| String::from_utf8_lossy(bytes).contains(secret_branch);
        let anon = |uri: String| {
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        };

        // Public repo, anonymous → 200, branch listed.
        let resp = router()
            .oneshot(anon(format!(
                "/api/v1/repos/{owner}/prot-pub/branches/protected"
            )))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "public protected-branch list stays anonymous"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            leaks(&bytes),
            "public response must include the branch name"
        );

        // Private repo, anonymous → 404, no branch name leaked.
        let resp = router()
            .oneshot(anon(format!(
                "/api/v1/repos/{owner}/prot-priv/branches/protected"
            )))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "private branch list hidden from anon"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!leaks(&bytes), "404 must not leak the branch name");

        // Private repo, owner → 200, branch listed.
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{owner}/prot-priv/branches/protected"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "owner reads its private protected branches"
        );

        // Absent repo → 404.
        let resp = router()
            .oneshot(anon(format!(
                "/api/v1/repos/{owner}/no-such-repo/branches/protected"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "absent repo → 404");
    }

    /// #113: the events read-gate admits a listed reader (the allow-list branch
    /// of visibility_check), not just the owner — parity with the replica and
    /// protected-branch surfaces covered by `read_visibility_admits_listed_reader`.
    /// A non-reader stranger still 404s with no leak.
    #[sqlx::test]
    async fn list_repo_events_admits_listed_reader(pool: PgPool) {
        use crate::db::{RefCertificate, VisibilityMode};
        let owner = "did:key:zEVTRDROWNERAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let reader = "did:key:zEVTRDRREADERBBBBBBBBBBBBBBBBBBBBBBBB";
        let stranger = "did:key:zEVTRDRSTRGRCCCCCCCCCCCCCCCCCCCCCCCC";
        let state = test_state(pool).await;

        let mut repo = seed_repo(owner, "evt-rdr");
        repo.is_public = false;
        state
            .db
            .create_repo(&repo)
            .await
            .expect("seed private repo");
        state
            .db
            .set_visibility_rule(
                &repo.id,
                "/",
                VisibilityMode::B,
                &[reader.to_string()],
                owner,
            )
            .await
            .expect("seed reader rule");
        state
            .db
            .insert_ref_certificate(&RefCertificate {
                id: uuid::Uuid::new_v4().to_string(),
                repo_id: repo.id.clone(),
                ref_name: "refs/heads/embargo-rdr".to_string(),
                old_sha: "0".repeat(40),
                new_sha: "rdrsha00".to_string(),
                pusher_did: owner.to_string(),
                node_did: owner.to_string(),
                signature: "sig".to_string(),
                issued_at: Utc::now().to_rfc3339(),
                seq: next_cert_seq(),
                prev: "0".repeat(64),
                pusher_sig: None,
                signature_input: None,
                content_digest: None,
                request_path: None,
            })
            .await
            .expect("seed private cert");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/events",
                    axum::routing::get(crate::api::events::list_repo_events),
                )
                .with_state(state.clone())
        };
        let uri = format!("/api/v1/repos/{owner}/evt-rdr/events");
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).to_string();

        // Listed reader (non-owner) → 200, the private cert is served.
        let resp = router()
            .oneshot(signed_request_as(reader, Method::GET, &uri, Body::empty()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a listed reader (non-owner) must read events"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            text(&bytes).contains("embargo-rdr"),
            "listed reader sees the private cert"
        );

        // A non-reader stranger → 404, and the cert ref does not leak.
        let resp = router()
            .oneshot(signed_request_as(
                stranger,
                Method::GET,
                &uri,
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a non-reader stranger must 404"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !text(&bytes).contains("embargo-rdr"),
            "404 must not leak the cert ref"
        );
        assert!(
            !text(&bytes).contains("rdrsha00"),
            "404 must not leak the cert sha"
        );
    }

    /// #113 fail-closed: when the repo lookup ERRORS (not a clean Ok(None)), the
    /// visibility gate must not be skipped. The buggy `.ok().flatten()` collapsed an
    /// Err into None, so a transient DB failure during the lookup dropped the gate
    /// and the handler served the private repo's gossip ref-updates via the
    /// ungated None branch (slug taken from the URL owner segment). We force a
    /// deterministic get_repo error by dropping the column its SELECT reads, then
    /// require the handler to fail closed (500, no secret) instead of 200-with-secret.
    #[sqlx::test]
    async fn list_repo_events_fails_closed_when_repo_lookup_errors(pool: PgPool) {
        use crate::db::ReceivedRefUpdate;
        let owner = "did:key:zEVTERRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        // Caller addresses the repo by the full key part (the slug gossip rows use),
        // so the buggy None-branch fallback slug matches the seeded private update.
        let keypart = owner.split(':').next_back().unwrap();
        let state = test_state(pool.clone()).await;

        let mut priv_repo = seed_repo(owner, "evt-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");

        state
            .db
            .insert_ref_update(&ReceivedRefUpdate {
                id: uuid::Uuid::new_v4().to_string(),
                node_did: owner.to_string(),
                pusher_did: owner.to_string(),
                repo: format!("{keypart}/evt-priv"),
                ref_name: "refs/heads/embargo-gossip".to_string(),
                old_sha: "0".repeat(40),
                new_sha: "gossipSEKRET".to_string(),
                timestamp: Utc::now().to_rfc3339(),
                cert_id: None,
                received_at: Utc::now().to_rfc3339(),
                from_peer: "peer".to_string(),
                owner_did: None,
            })
            .await
            .expect("seed private gossip update");

        // Force get_repo's SELECT (which reads machine_id, db/mod.rs) to error,
        // simulating a transient DB failure during the visibility lookup. The repo
        // row and the gossip update both remain present.
        // Precondition: the lookup must succeed before we break it, otherwise the
        // injection proves nothing.
        state
            .db
            .get_repo(keypart, "evt-priv")
            .await
            .expect("pre-drop lookup must succeed")
            .expect("private repo row must be present pre-drop");
        sqlx::query("ALTER TABLE repos DROP COLUMN machine_id")
            .execute(&pool)
            .await
            .expect("drop column to force a get_repo error");
        // Guard the injection: if a future refactor drops machine_id from get_repo's
        // SELECT, this assertion fails loudly instead of letting the test pass
        // vacuously (get_repo would return Ok and the gate, not the error path,
        // would drive the response).
        assert!(
            state.db.get_repo(keypart, "evt-priv").await.is_err(),
            "dropping machine_id must make get_repo error, else this test no longer exercises the Err path"
        );

        let router = Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/events",
                axum::routing::get(crate::api::events::list_repo_events),
            )
            .with_state(state.clone());
        let resp = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/v1/repos/{keypart}/evt-priv/events"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Fail closed: a lookup error must surface as 500, never a 200 that serves
        // the private repo's ref metadata through the ungated branch.
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a repo-lookup error must fail closed, not skip the gate"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes).to_string();
        assert!(
            !body.contains("gossipSEKRET"),
            "fail-closed response must not leak the gossip secret"
        );
    }

    /// #94 end-to-end seam: a REAL RFC-9421 signature produced exactly as the gl
    /// client's get_signed does (gitlawb_core::http_sig::sign_request over GET +
    /// empty body) is accepted by the node's actual optional_signature middleware,
    /// which verifies it and injects AuthenticatedDid, so the owner's signed
    /// `gl webhook list` resolves to 200. This stitches the gl signing side and
    /// the node verifying side in one test (not mockito on one end and a unit
    /// verify on the other).
    #[sqlx::test]
    async fn list_webhooks_accepts_a_real_gl_signature_e2e(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let owner_did = kp.did().to_string();
        // Short owner form in the URL path: no colons (so the signed @path and the
        // node's path_and_query() match byte-for-byte), and get_repo's owner LIKE
        // match + did_matches still authorize the full-DID signer as the owner.
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;
        let repo = seed_repo(&owner_did, "real-sig-repo");
        state.db.create_repo(&repo).await.expect("seed repo");
        let url = "https://hooks.example.com/e2e";
        state
            .db
            .create_webhook(&crate::db::Webhook {
                id: uuid::Uuid::new_v4().to_string(),
                repo_id: repo.id.clone(),
                url: url.to_string(),
                secret: None,
                events: vec!["*".to_string()],
                created_by_did: owner_did.clone(),
                created_at: Utc::now().to_rfc3339(),
                active: true,
            })
            .await
            .expect("seed webhook");

        let path = format!("/api/v1/repos/{short}/real-sig-repo/hooks");
        let signed = sign_request(&kp, "GET", &path, b"");
        let req = Request::builder()
            .method(Method::GET)
            .uri(&path)
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::empty())
            .unwrap();

        // Mount the handler UNDER the production optional_signature middleware so
        // the node actually verifies the signature (not the injected-DID shortcut).
        let router = Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/hooks",
                axum::routing::get(crate::api::webhooks::list_webhooks),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state);

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the node must verify a real gl-style signature and authorize the owner"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&bytes).contains(url),
            "the verified owner sees the webhook list"
        );
    }

    /// A signed request body reused by the request-target trio below. Non-empty so
    /// the content-digest the signature covers is a real hash rather than the
    /// empty-body constant, which keeps `@path` the only component under test.
    const TARGET_PIN_BODY: &[u8] = br#"{"task_type":"noop","payload":{}}"#;

    /// Send `body` to `uri` carrying a signature made over `signed_over`, through
    /// the PRODUCTION router (`app`, which goes through `server::build_router`, where
    /// `add_auth_layers` installs `require_signature` on the write routes). Returns
    /// the status and the parsed JSON body (`Null` when the response is not JSON, as
    /// a handler response past the middleware may be). Going through `app` rather
    /// than a hand-mounted `Router::new().route(...)` probe is the point: a bare
    /// router answers whether the middleware rejects the request, not whether that
    /// is how a caller is actually gated.
    async fn signed_over_then_sent(
        pool: PgPool,
        signed_over: &str,
        uri: &str,
    ) -> (StatusCode, serde_json::Value) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let signed = sign_request(&kp, "POST", signed_over, TARGET_PIN_BODY);
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::from(TARGET_PIN_BODY))
            .unwrap();

        let resp = app(pool).await.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// The server half of the redirect finding: `require_signature` rebuilds `@path`
    /// from the URI of the request it actually received, so a signature minted over
    /// `/api/v1/repos` and presented at `POST /api/v1/tasks` verifies against the
    /// wrong request-target and is refused 401 `invalid_signature`. Both routes sit
    /// behind `add_auth_layers` in `build_router`, so the request really does reach
    /// the middleware instead of 404ing at the fallback. This is the node-side proof
    /// that a client which lets a redirect rewrite the target gets a 401, which is
    /// what the production report showed.
    ///
    /// No pre-fix RED is obtainable here: the verifier already gates on `@path` (that
    /// is precisely why the client bug surfaced as a 401 rather than as a silently
    /// accepted request), so there is no broken state to observe first. The test is a
    /// must-not guard, green by design, and its RED proof is by mutation of the
    /// reconstruction it pins.
    #[sqlx::test]
    async fn require_signature_refuses_a_stale_request_target_path(pool: PgPool) {
        let (status, json) = signed_over_then_sent(pool, "/api/v1/repos", "/api/v1/tasks").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a signature minted over one route path must not verify when replayed on another"
        );
        assert_eq!(
            json["error"], "invalid_signature",
            "the refusal must come from the signature check, not from a handler or a later gate"
        );
    }

    /// The query half of the same reconstruction: `@path` is path-and-query, not path
    /// alone, so a signature minted over `/api/v1/tasks` and sent to
    /// `/api/v1/tasks?x=1` is refused 401 `invalid_signature` too. Without this case a
    /// reconstruction narrowed to `parts.uri.path()` would keep the sibling test above
    /// green while admitting every query rewrite, so both components of the received
    /// target are pinned rather than just the first.
    ///
    /// No pre-fix RED is obtainable here either, for the reason given on the sibling
    /// above: the verifier already covers the query, so this is a green-by-design
    /// must-not guard whose RED proof is by mutation.
    #[sqlx::test]
    async fn require_signature_refuses_a_stale_request_target_query(pool: PgPool) {
        let (status, json) =
            signed_over_then_sent(pool, "/api/v1/tasks", "/api/v1/tasks?x=1").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a signature minted over the bare task path \
             must not verify on a request that carries a query"
        );
        assert_eq!(
            json["error"], "invalid_signature",
            "the query refusal must come from the signature check, \
             not from a handler rejecting the unknown parameter"
        );
    }

    /// The paired positive control the two refusals need to mean anything: signed and
    /// sent over the identical target `/api/v1/tasks?x=1`, the request clears
    /// `require_signature`. Without it a reconstruction that produced garbage for
    /// every request would satisfy both refusals above and look like coverage. The
    /// request carries no `x-ucan` header, so `require_ucan_chain` passes it through
    /// and whatever status arrives past the auth pair is the handler's own; the
    /// assertion is therefore that the response is NOT the 401 `invalid_signature` the
    /// mismatch cases get, not a pin on some particular handler outcome.
    ///
    /// Green by design like its siblings, and for the same reason: the verifier
    /// already reconstructs the received target, so there is no pre-fix RED to
    /// observe and the proof that this assertion is load-bearing comes from degrading
    /// the reconstruction under mutation.
    #[sqlx::test]
    async fn require_signature_admits_the_exact_request_target(pool: PgPool) {
        let (status, json) =
            signed_over_then_sent(pool, "/api/v1/tasks?x=1", "/api/v1/tasks?x=1").await;
        assert!(
            !(status == StatusCode::UNAUTHORIZED && json["error"] == "invalid_signature"),
            "an identically signed and sent request-target must clear require_signature, \
             so this control must not draw the same refusal as the mismatch cases; got {status}"
        );
    }

    /// Issue #6 / jatmn finding 2: `/api/v1/stats` counts logical repos, not raw
    /// rows. With a mirror+canonical pair and a standalone repo present, the
    /// `repos` count is 2.
    #[sqlx::test]
    async fn stats_repo_count_is_deduped(pool: PgPool) {
        let short = "zSTATSDEDUPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(&format!("did:key:{short}"), "shared"))
            .await
            .expect("seed canonical");
        state
            .db
            .upsert_mirror_repo(short, "shared", "/tmp/mirror", None, false)
            .await
            .expect("seed mirror");
        state
            .db
            .create_repo(&seed_repo(
                "did:key:zSTATSOTHERBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "solo",
            ))
            .await
            .expect("seed standalone");

        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["repos"], 2,
            "stats must count logical repos (mirror+canonical collapsed)"
        );
    }

    // ── #119: git-info-refs advertisement gate + client signing ──────────────

    /// A1 read-gate bypass + its client remedy. `git_info_refs` serves BOTH the
    /// `git-upload-pack` (clone/fetch) and `git-receive-pack` (push) ref
    /// advertisement off one route, but the visibility gate was wrapped in
    /// `if service == "git-upload-pack"`, so a private repo's ref advertisement
    /// (branch/tag names + commit tips) leaked to any anonymous caller who asked
    /// for `?service=git-receive-pack`. The fix gates the advertisement for both
    /// services. Because the gate now denies an *unauthenticated* advertisement
    /// of a private repo for both services, `git-remote-gitlawb` signs its
    /// Phase-1 advertisement GET (over path_and_query) so the owner can still
    /// fetch and push; this test exercises that exact request with a REAL
    /// RFC-9421 signature through the production `optional_signature` middleware.
    ///
    /// Denied → 404 (`RepoNotFound`, existence-hiding) at the gate, before disk
    /// access. Allowed → the handler clears the gate and falls through to
    /// `acquire` + real `git ... --advertise-refs` against a repo absent from the
    /// test disk, returning 500; that 500 (anything but 404) is the signal the
    /// caller cleared the gate.
    #[sqlx::test]
    async fn git_info_refs_gates_advertisement_for_both_services(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let owner_did = kp.did().to_string();
        // Short owner form in the URL so the signed @path and the node's
        // path_and_query() match byte-for-byte; get_repo's owner LIKE + did_matches
        // still authorize the full-DID signer as the owner.
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let mut priv_repo = seed_repo(&owner_did, "ir-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");
        // A public repo to guard against the unconditional gate accidentally
        // denying public, anonymous clones.
        state
            .db
            .create_repo(&seed_repo(&owner_did, "ir-pub"))
            .await
            .expect("seed public repo");

        // Production-shaped router: the real optional_signature middleware, so a
        // signed request is genuinely verified (not the injected-DID shortcut).
        let router = || {
            Router::new()
                .route(
                    "/{owner}/{repo}/info/refs",
                    axum::routing::get(crate::api::repos::git_info_refs),
                )
                .layer(axum::middleware::from_fn(crate::auth::optional_signature))
                .with_state(state.clone())
        };
        let path = |service: &str| format!("/{short}/ir-priv.git/info/refs?service={service}");
        let anon = |service: &str| {
            Request::builder()
                .method(Method::GET)
                .uri(path(service))
                .body(Body::empty())
                .unwrap()
        };
        // The advertisement GET exactly as git-remote-gitlawb now builds it: a
        // real signature over the path_and_query, empty body.
        let signed = |service: &str| {
            let p = path(service);
            let s = sign_request(&kp, "GET", &p, b"");
            Request::builder()
                .method(Method::GET)
                .uri(&p)
                .header("content-digest", s.content_digest)
                .header("signature-input", s.signature_input)
                .header("signature", s.signature)
                .body(Body::empty())
                .unwrap()
        };

        // Leak fix: anonymous advertisement of a private repo is denied (404) for
        // BOTH services. Pre-fix the receive-pack case returned 500 (gate skipped).
        for service in ["git-upload-pack", "git-receive-pack"] {
            let resp = router().oneshot(anon(service)).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "anonymous {service} advertisement of a private repo must be denied"
            );
        }

        // No-regression: a PUBLIC repo's advertisement stays anonymous for BOTH
        // services. The gate admits the anonymous caller, so the handler clears it
        // and 500s on the missing test-disk repo; anything but 404 (a gate denial)
        // proves the unconditional gate did not accidentally lock out public reads.
        for service in ["git-upload-pack", "git-receive-pack"] {
            let req = Request::builder()
                .method(Method::GET)
                .uri(format!("/{short}/ir-pub.git/info/refs?service={service}"))
                .body(Body::empty())
                .unwrap();
            let resp = router().oneshot(req).await.unwrap();
            // 500 (not just non-404): the gate admits the public anonymous caller,
            // so the handler reaches acquire + git advertise-refs on the missing
            // test-disk repo. Pinning the exact 500 rules out a 401/403 regression
            // masquerading as "not gated".
            assert_eq!(
                resp.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "anonymous {service} advertisement of a PUBLIC repo must not be gated"
            );
        }

        // Client remedy: the owner's SIGNED advertisement GET clears the gate for
        // BOTH services (so fetch and push of a private repo keep working). It
        // 500s on the missing test-disk repo; anything but 404 means cleared.
        for service in ["git-upload-pack", "git-receive-pack"] {
            let resp = router().oneshot(signed(service)).await.unwrap();
            // INTERNAL_SERVER_ERROR specifically: the signature VERIFIED (passed
            // require_signature, not 401/403) and the owner cleared the read gate
            // (not 404), so the handler proceeded to acquire + git on a repo absent
            // from the test disk. Asserting the exact 500 (rather than merely
            // "not 404") proves the request got PAST auth, not rejected by it.
            assert_eq!(
                resp.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "the owner's signed {service} advertisement must verify and clear the gate"
            );
        }
    }

    /// Push is signature-gated, not merely owner-gated: an UNSIGNED
    /// git-receive-pack POST is rejected by `require_signature` (401) before
    /// reaching `git_receive_pack`. 401 (not the handler's 404/500) is the
    /// discriminator that proves the request never reached the handler.
    #[sqlx::test]
    async fn unsigned_receive_pack_post_is_rejected(pool: PgPool) {
        let state = test_state(pool).await;
        let owner_did = Keypair::generate().did().to_string();
        let short = owner_did.split(':').next_back().unwrap().to_string();
        state
            .db
            .create_repo(&seed_repo(&owner_did, "rp-repo"))
            .await
            .expect("seed repo");

        // Production wiring: the receive-pack POST sits behind require_signature
        // (server.rs add_auth_layers); apply that same layer here.
        let router = Router::new()
            .route(
                "/{owner}/{repo}/git-receive-pack",
                axum::routing::post(crate::api::repos::git_receive_pack),
            )
            .layer(axum::middleware::from_fn(crate::auth::require_signature))
            .with_state(state);

        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{short}/rp-repo.git/git-receive-pack"))
            .body(Body::from(&b"0000"[..]))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an unsigned receive-pack POST must be rejected by require_signature, \
             not reach the handler"
        );
    }

    /// The handler wiring: with the gate on, a signed non-owner push is refused.
    ///
    /// The gate's own unit tests pass `enforce` as a literal and never exercise the
    /// handler, so this is what proves the flag is actually consulted on the request
    /// path. It sets the field EXPLICITLY rather than leaning on the default: on a
    /// host exporting `GITLAWB_ENFORCE_OWNER_PUSH=false` — which is exactly what the
    /// rolling-upgrade guidance tells operators to set — an ambient config would
    /// build a disabled state, let the push through to git, and fail this test for a
    /// reason that has nothing to do with the code under test.
    ///
    /// The shipped default is proved env-independently in `config::tests`, off the
    /// parser declaration. Authorization behaviour and parser defaults are separate
    /// questions and get separate tests.
    ///
    /// 403 rather than 401 is the discriminator: the request carries a real RFC 9421
    /// signature and passes `require_signature`, so it is authenticated and refused on
    /// authorization — which is the whole distinction the change rests on.
    #[sqlx::test]
    async fn enforced_owner_push_refuses_a_signed_non_owner(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let stranger = Keypair::generate();
        let owner_did = owner.did().to_string();
        let short = owner_did.split(':').next_back().unwrap().to_string();

        let state = test_state_with(pool, |cfg| cfg.enforce_owner_push = true).await;
        state
            .db
            .create_repo(&seed_repo(&owner_did, "defrepo"))
            .await
            .expect("seed repo");

        let router = Router::new()
            .route(
                "/{owner}/{repo}/git-receive-pack",
                axum::routing::post(crate::api::repos::git_receive_pack),
            )
            .layer(axum::middleware::from_fn(crate::auth::require_signature))
            .with_state(state);

        let path = format!("/{short}/defrepo.git/git-receive-pack");
        let body = b"0000".to_vec();
        let signed = sign_request(&stranger, "POST", &path, &body);
        let req = Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header("content-type", "application/x-git-receive-pack-request")
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::from(body))
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "with the gate enabled, a signed push from a non-owner must be refused: \
             a did:key is self-certifying, so authentication alone is not \
             authorization"
        );
    }

    /// A1 Phase-2 contract: the `git-upload-pack` POST (the actual fetch, after
    /// the advertisement) is itself read-visibility gated. An ANONYMOUS upload-pack
    /// POST against a private repo is denied (404), so signing only the Phase-1
    /// advertisement GET is NOT enough; `git-remote-gitlawb` must also sign this
    /// POST, or an owner's fetch of their own private repo clears the advertisement
    /// and then dies on the pack POST. A real owner signature clears the gate
    /// (non-404; the missing test-disk repo then errors downstream).
    #[sqlx::test]
    async fn git_upload_pack_post_is_read_gated_on_private_repo(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;

        let kp = Keypair::generate();
        let owner_did = kp.did().to_string();
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let mut priv_repo = seed_repo(&owner_did, "up-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");

        let router = || {
            Router::new()
                .route(
                    "/{owner}/{repo}/git-upload-pack",
                    axum::routing::post(crate::api::repos::git_upload_pack),
                )
                .layer(axum::middleware::from_fn(crate::auth::optional_signature))
                .with_state(state.clone())
        };
        // A non-empty body (git-remote-gitlawb skips the POST when the body is empty).
        let body = b"0032want 0000000000000000000000000000000000000000\n".to_vec();
        let path = format!("/{short}/up-priv.git/git-upload-pack");

        // Anonymous Phase-2 fetch of a private repo: denied at the gate (404). This
        // is exactly the request git-remote-gitlawb sends today for upload-pack
        // (the unsigned POST), which is why fetch breaks for the owner.
        let anon = Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header("content-type", "application/x-git-upload-pack-request")
            .body(Body::from(body.clone()))
            .unwrap();
        let resp = router().oneshot(anon).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "an anonymous upload-pack POST against a private repo must be denied"
        );

        // The same POST signed by the owner clears the read gate (non-404). This is
        // the request the client must send once it signs the upload-pack POST.
        let signed = sign_request(&kp, "POST", &path, &body);
        let signed_req = Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header("content-type", "application/x-git-upload-pack-request")
            .header("content-digest", signed.content_digest)
            .header("signature-input", signed.signature_input)
            .header("signature", signed.signature)
            .body(Body::from(body))
            .unwrap();
        let resp = router().oneshot(signed_req).await.unwrap();
        // 500 (not merely non-404): the signature VERIFIED (passed require_signature,
        // not 401/403) AND the owner cleared the read gate (not 404), so the handler
        // reached git on the missing test-disk repo. Pinning 500 proves the request
        // got past auth; a 401 regression would slip through a bare `!= 404`.
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "the owner's signed upload-pack POST must verify and clear the read gate"
        );
    }

    /// Served-content seam: with a REAL on-disk bare repo (branch
    /// `topsecret-branch`), the advertisement serves the actual ref names to
    /// authorized callers and withholds them from denied ones, proving real
    /// content egress + withholding, not just the gate decision (the other tests
    /// land on a 500 from a missing-disk repo). Asserts the branch name appears for
    /// allowed callers and never appears in a denied 404 body.
    #[sqlx::test]
    async fn advertisement_serves_real_refs_only_to_authorized_callers(pool: PgPool) {
        use gitlawb_core::http_sig::sign_request;
        use gitlawb_core::identity::Keypair;
        use std::process::Command;

        // repo_store::for_testing fixes the on-disk layout (/tmp/<slug>/<name>.git
        // and /tmp/gl-seam-src-<short>), so tempfile::TempDir's random paths don't
        // fit. Wrap each known path in a Drop guard so the dirs are removed even if
        // an assertion below panics.
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let kp = Keypair::generate();
        let owner_did = kp.did().to_string();
        let short = owner_did.split(':').next_back().unwrap().to_string();
        // repo_store::for_testing uses /tmp; local_path = /tmp/<slug>/<name>.git
        // with slug = owner_did with ':' and '/' replaced by '_'.
        let slug = owner_did.replace([':', '/'], "_");
        let state = test_state(pool).await;

        let run = |args: &[&str], cwd: &std::path::Path| {
            let out = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .expect("git runs");
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };

        // Source repo with a recognizable branch + one commit.
        let src = std::env::temp_dir().join(format!("gl-seam-src-{short}"));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(&src).unwrap();
        let _src_guard = DirGuard(src.clone());
        run(&["init", "-q", "-b", "topsecret-branch"], &src);
        run(&["config", "user.email", "t@t"], &src);
        run(&["config", "user.name", "t"], &src);
        std::fs::write(src.join("f.txt"), b"hi").unwrap();
        run(&["add", "f.txt"], &src);
        run(&["commit", "-q", "-m", "seed"], &src);

        // Bare-clone into the exact path repo_store.acquire() will read.
        let bare_for = |name: &str| {
            let dir = std::path::PathBuf::from("/tmp")
                .join(&slug)
                .join(format!("{name}.git"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
            let out = Command::new("git")
                .args([
                    "clone",
                    "--bare",
                    "-q",
                    src.to_str().unwrap(),
                    dir.to_str().unwrap(),
                ])
                .output()
                .expect("git clone runs");
            assert!(
                out.status.success(),
                "bare clone failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            dir
        };
        let pub_dir = bare_for("served-pub");
        let _pub_guard = DirGuard(pub_dir.clone());
        let priv_dir = bare_for("served-priv");
        let _priv_guard = DirGuard(priv_dir.clone());

        state
            .db
            .create_repo(&seed_repo(&owner_did, "served-pub"))
            .await
            .expect("seed public repo");
        let mut priv_repo = seed_repo(&owner_did, "served-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");

        let router = || {
            Router::new()
                .route(
                    "/{owner}/{repo}/info/refs",
                    axum::routing::get(crate::api::repos::git_info_refs),
                )
                .layer(axum::middleware::from_fn(crate::auth::optional_signature))
                .with_state(state.clone())
        };
        async fn body_of(resp: axum::response::Response) -> String {
            let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            String::from_utf8_lossy(&b).to_string()
        }

        // Public repo, anonymous → 200 and the real ref name is served.
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/{short}/served-pub.git/info/refs?service=git-upload-pack"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            body_of(resp).await.contains("topsecret-branch"),
            "public advertisement must serve the real ref name"
        );

        // Private repo, anonymous → 404 and the ref name is withheld.
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/{short}/served-priv.git/info/refs?service=git-upload-pack"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            !body_of(resp).await.contains("topsecret-branch"),
            "a denied 404 must not leak the real ref name"
        );

        // Private repo, owner's REAL signature → 200 and the real ref is served.
        let path = format!("/{short}/served-priv.git/info/refs?service=git-upload-pack");
        let s = sign_request(&kp, "GET", &path, b"");
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&path)
                    .header("content-digest", s.content_digest)
                    .header("signature-input", s.signature_input)
                    .header("signature", s.signature)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the owner's signed request reads the private advertisement"
        );
        assert!(
            body_of(resp).await.contains("topsecret-branch"),
            "the verified owner gets the real ref name"
        );

        // Cleanup runs via the DirGuard Drop impls above, on success or panic.
    }

    // ── #97: repo-listing surfaces are visibility-gated ──────────────────────

    fn seed_private_repo(owner_did: &str, name: &str) -> RepoRecord {
        RepoRecord {
            is_public: false,
            ..seed_repo(owner_did, name)
        }
    }

    fn anon_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .expect("request builder")
    }

    async fn json_body(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn names_in(v: &serde_json::Value) -> Vec<String> {
        v.as_array()
            .expect("array body")
            .iter()
            .filter_map(|r| r["name"].as_str().map(str::to_string))
            .collect()
    }

    fn list_repos_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/repos",
                axum::routing::get(crate::api::repos::list_repos),
            )
            .with_state(state)
    }

    #[sqlx::test]
    async fn list_repos_hides_private_repo_and_count_from_anonymous(pool: PgPool) {
        let owner = "did:key:zLISTOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-repo"))
            .await
            .expect("seed public");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let resp = list_repos_router(state)
            .oneshot(anon_get("/api/v1/repos"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let total = resp
            .headers()
            .get("X-Total-Count")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let names = names_in(&json_body(resp).await);
        assert!(
            names.contains(&"pub-repo".to_string()),
            "public repo listed"
        );
        assert!(
            !names.contains(&"priv-repo".to_string()),
            "private repo must not be enumerable anonymously (#97)"
        );
        assert_eq!(
            total.as_deref(),
            Some("1"),
            "X-Total-Count must not leak the private repo's existence"
        );
    }

    #[sqlx::test]
    async fn list_repos_shows_owner_their_private_repo(pool: PgPool) {
        let owner = "did:key:zLISTOWNER2BBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-repo"))
            .await
            .expect("seed public");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let resp = list_repos_router(state)
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                "/api/v1/repos",
                Body::empty(),
            ))
            .await
            .unwrap();
        let names = names_in(&json_body(resp).await);
        assert!(
            names.contains(&"priv-repo".to_string()) && names.contains(&"pub-repo".to_string()),
            "owner sees their own private repo, got {names:?}"
        );
    }

    #[sqlx::test]
    async fn list_repos_shows_private_repo_to_authorized_root_reader(pool: PgPool) {
        // Proves the gate is visibility_check, not a bare is_public filter: an
        // is_public=false repo with a root rule granting a reader DID is listable
        // to that reader (and not to a stranger).
        let owner = "did:key:zLISTOWNER3CCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let reader = "did:key:zLISTREADERDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
        let stranger = "did:key:zLISTSTRANGEREEEEEEEEEEEEEEEEEEEEEEEEEE";
        let state = test_state(pool).await;
        let rec = seed_private_repo(owner, "priv-repo");
        state.db.create_repo(&rec).await.expect("seed private");
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/",
                crate::db::VisibilityMode::A,
                &[reader.to_string()],
                owner,
            )
            .await
            .expect("grant root reader");

        let names_for = |did: &'static str, st: AppState| async move {
            let resp = list_repos_router(st)
                .oneshot(signed_request_as(
                    did,
                    Method::GET,
                    "/api/v1/repos",
                    Body::empty(),
                ))
                .await
                .unwrap();
            names_in(&json_body(resp).await)
        };

        assert!(
            names_for(reader, state.clone())
                .await
                .contains(&"priv-repo".to_string()),
            "authorized root reader must see the private repo"
        );
        assert!(
            !names_for(stranger, state)
                .await
                .contains(&"priv-repo".to_string()),
            "an unlisted stranger must not see it"
        );
    }

    #[sqlx::test]
    async fn list_federated_repos_hides_private_from_anonymous(pool: PgPool) {
        let owner = "did:key:zFEDOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-repo"))
            .await
            .expect("seed public");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let router = Router::new()
            .route(
                "/api/v1/repos/federated",
                axum::routing::get(crate::api::repos::list_federated_repos),
            )
            .with_state(state);
        let resp = router
            .oneshot(anon_get("/api/v1/repos/federated"))
            .await
            .unwrap();
        let body = json_body(resp).await;
        let names = names_in(&body["repos"]);
        assert_eq!(
            body["count"].as_u64(),
            Some(1),
            "federated count must reflect only the visible repos, not the pre-filter total (#97)"
        );
        assert!(
            names.contains(&"pub-repo".to_string()),
            "public repo federated"
        );
        assert!(
            !names.contains(&"priv-repo".to_string()),
            "private repo must not be federated to anonymous callers (#97)"
        );
    }

    #[sqlx::test]
    async fn graphql_repos_hides_private_from_anonymous(pool: PgPool) {
        // The GraphQL repos query is the third listing surface; an anonymous
        // query must not enumerate a private repo (#97).
        let owner = "did:key:zGQLOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-repo"))
            .await
            .expect("seed public");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let resp = state
            .graphql_schema
            .execute(async_graphql::Request::new("{ repos { name } }"))
            .await;
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        let names = names_in(&resp.data.into_json().expect("graphql json")["repos"]);
        assert!(
            names.contains(&"pub-repo".to_string()),
            "public repo listed"
        );
        assert!(
            !names.contains(&"priv-repo".to_string()),
            "private repo must not be enumerable via anonymous GraphQL (#97)"
        );
    }

    #[sqlx::test]
    async fn graphql_repos_shows_authorized_caller_their_private_repo(pool: PgPool) {
        // Positive path: the resolver pulls the caller DID from GraphQL request
        // data, so the authenticated context must still surface a private repo its
        // owner may read. Guards an auth-context regression on the GraphQL surface
        // that the anonymous-only test would miss (#97).
        let owner = "did:key:zGQLAUTHOWNERAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let resp = state
            .graphql_schema
            .execute(
                async_graphql::Request::new("{ repos { name } }")
                    .data(AuthenticatedDid(owner.to_string())),
            )
            .await;
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        let names = names_in(&resp.data.into_json().expect("graphql json")["repos"]);
        assert!(
            names.contains(&"priv-repo".to_string()),
            "owner must see their own private repo via authenticated GraphQL (#97)"
        );
    }

    #[sqlx::test]
    async fn list_repos_paged_count_excludes_private(pool: PgPool) {
        // The paged path (limit set) is the KTD2 exploit shape: a pre-cut page +
        // SQL total would leak the private-repo count. Assert X-Total-Count is the
        // visible count and the page is not short (#97).
        let owner = "did:key:zPAGEOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-a"))
            .await
            .expect("seed public a");
        state
            .db
            .create_repo(&seed_repo(owner, "pub-b"))
            .await
            .expect("seed public b");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let resp = list_repos_router(state)
            .oneshot(anon_get("/api/v1/repos?limit=10"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let total = resp
            .headers()
            .get("X-Total-Count")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let names = names_in(&json_body(resp).await);
        assert_eq!(
            total.as_deref(),
            Some("2"),
            "paged X-Total-Count must reflect only the 2 visible repos, not leak the private count"
        );
        assert_eq!(
            names.len(),
            2,
            "page must not be short: both public repos present"
        );
        assert!(!names.contains(&"priv-repo".to_string()));
    }

    #[sqlx::test]
    async fn list_repos_hides_public_repo_under_root_deny(pool: PgPool) {
        // Proves the gate is visibility_check, not a bare is_public filter, in the
        // negative direction: an is_public=true repo with a root deny rule (mode B,
        // no readers) is NOT listable to anonymous, while a plain public repo is.
        let owner = "did:key:zDENYOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "open-repo"))
            .await
            .expect("seed open");
        let denied = seed_repo(owner, "deny-repo"); // is_public = true
        state.db.create_repo(&denied).await.expect("seed denied");
        state
            .db
            .set_visibility_rule(&denied.id, "/", crate::db::VisibilityMode::B, &[], owner)
            .await
            .expect("root deny rule");

        let resp = list_repos_router(state)
            .oneshot(anon_get("/api/v1/repos"))
            .await
            .unwrap();
        let names = names_in(&json_body(resp).await);
        assert!(
            names.contains(&"open-repo".to_string()),
            "plain public repo listed"
        );
        assert!(
            !names.contains(&"deny-repo".to_string()),
            "is_public=true repo with a root deny must NOT be listed (proves visibility_check, not is_public)"
        );
    }

    #[sqlx::test]
    async fn list_repos_owner_filter_excludes_private_from_anonymous(pool: PgPool) {
        // The owner-filtered path (?owner=, SQL $1 bind) must still apply the Rust
        // "/" visibility gate: an anonymous caller filtering by an owner sees that
        // owner's public repos but never their private ones, and the count does
        // not leak (#97). This is a distinct SQL branch from the unfiltered path.
        let short = "zOWNERFILTERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let owner = format!("did:key:{short}");
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(&owner, "pub-repo"))
            .await
            .expect("seed public");
        state
            .db
            .create_repo(&seed_private_repo(&owner, "priv-repo"))
            .await
            .expect("seed private");

        let resp = list_repos_router(state)
            .oneshot(anon_get(&format!("/api/v1/repos?owner={short}&limit=10")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let total = resp
            .headers()
            .get("X-Total-Count")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let names = names_in(&json_body(resp).await);
        assert!(
            names.contains(&"pub-repo".to_string()),
            "owner's public repo listed"
        );
        assert!(
            !names.contains(&"priv-repo".to_string()),
            "owner's private repo hidden from anonymous even when owner-filtered (#97)"
        );
        assert_eq!(
            total.as_deref(),
            Some("1"),
            "owner-filtered X-Total-Count must exclude the private repo"
        );
    }

    #[sqlx::test]
    async fn list_repos_owner_filter_full_did_matches_bare_mirror(pool: PgPool) {
        // A mirror-only repo (known via gossip, no local canonical row) stores the
        // bare owner key `z...`. Filtering by the full `did:key:z...` form must
        // still return it, matching crate::api::did_matches — the behavior the
        // no-limit `gl repo list --owner` path relied on before #97 routed owner
        // filtering through SQL (jatmn P2 on #111). Both owner forms must match.
        let short = "zMIRRORONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .upsert_mirror_repo(short, "mirror-repo", "/tmp/mirror", None, false)
            .await
            .expect("seed mirror-only row");

        // full did:key: form must match the bare-owner mirror row
        let resp = list_repos_router(state.clone())
            .oneshot(anon_get(&format!("/api/v1/repos?owner=did:key:{short}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let names = names_in(&json_body(resp).await);
        assert!(
            names.contains(&"mirror-repo".to_string()),
            "full did:key: owner filter must match a bare-owner mirror row (jatmn #111)"
        );

        // short bare form must still match
        let resp = list_repos_router(state)
            .oneshot(anon_get(&format!("/api/v1/repos?owner={short}")))
            .await
            .unwrap();
        let names = names_in(&json_body(resp).await);
        assert!(
            names.contains(&"mirror-repo".to_string()),
            "short-form owner filter must still match the mirror row"
        );
    }

    #[sqlx::test]
    async fn list_repos_pagination_offset_past_end_keeps_total(pool: PgPool) {
        // Pagination edge: an offset past the visible set returns an empty page,
        // but X-Total-Count still reflects the full visible count -- so paging can
        // neither short the page nor leak a different total (#97). Guards against a
        // refactor that derives the total from the cut page instead of the set.
        let owner = "did:key:zOFFSETOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-a"))
            .await
            .expect("seed public a");
        state
            .db
            .create_repo(&seed_repo(owner, "pub-b"))
            .await
            .expect("seed public b");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let resp = list_repos_router(state)
            .oneshot(anon_get("/api/v1/repos?limit=5&offset=100"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let total = resp
            .headers()
            .get("X-Total-Count")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let names = names_in(&json_body(resp).await);
        assert!(names.is_empty(), "offset past the end yields an empty page");
        assert_eq!(
            total.as_deref(),
            Some("2"),
            "X-Total-Count stays the full visible total regardless of offset"
        );
    }

    #[sqlx::test]
    async fn list_repos_hides_canonical_under_root_deny_even_with_mirror(pool: PgPool) {
        // Regression guard for the dedup-survivor + visibility-rule seam. A logical
        // repo present as BOTH a canonical row (carrying a root-deny rule) and a
        // gossip mirror row: the DEDUP_CTE must pick the canonical survivor so the
        // batch rule lookup (keyed by the survivor's id) finds the deny and
        // withholds it. If dedup ever picked the mirror (slash-form id, no rule),
        // the gate would fall back to is_public=true and leak the repo. is_public
        // is true here, so the rule is the only thing hiding it.
        let short = "zMIRRORDENYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let owner = format!("did:key:{short}");
        let state = test_state(pool).await;
        let canonical = seed_repo(&owner, "secret"); // is_public = true
        state
            .db
            .create_repo(&canonical)
            .await
            .expect("seed canonical");
        state
            .db
            .set_visibility_rule(
                &canonical.id,
                "/",
                crate::db::VisibilityMode::B,
                &[],
                &owner,
            )
            .await
            .expect("root deny rule on canonical");
        state
            .db
            .upsert_mirror_repo(short, "secret", "/tmp/mirror", None, false)
            .await
            .expect("seed mirror");
        state
            .db
            .create_repo(&seed_repo(&owner, "open"))
            .await
            .expect("seed public sibling");

        let resp = list_repos_router(state)
            .oneshot(anon_get("/api/v1/repos"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let total = resp
            .headers()
            .get("X-Total-Count")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let names = names_in(&json_body(resp).await);
        assert!(names.contains(&"open".to_string()), "public sibling listed");
        assert!(
            !names.contains(&"secret".to_string()),
            "canonical repo with a root deny must stay hidden even when a mirror row exists (#97 dedup-survivor/rule seam)"
        );
        assert_eq!(
            total.as_deref(),
            Some("1"),
            "X-Total-Count counts only the visible sibling, not the mirror+canonical pair"
        );
    }

    // ── /api/v1/stats count oracle (#104) ──────────────────────────────────
    // The stats endpoint lives in meta_routes (no auth layer), so the caller is
    // always anonymous (None). Its `repos` count must withhold private/mode-A
    // repos exactly as the listing surfaces do, or it is a count oracle.

    fn stats_router(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/stats", axum::routing::get(crate::server::stats))
            .with_state(state)
    }

    async fn stats_repos_count(state: AppState) -> i64 {
        let resp = stats_router(state)
            .oneshot(anon_get("/api/v1/stats"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        json_body(resp).await["repos"]
            .as_i64()
            .expect("stats.repos is an integer")
    }

    #[sqlx::test]
    async fn stats_repos_count_excludes_bare_private(pool: PgPool) {
        // No-rule branch: an is_public=false repo with no visibility rule is
        // denied to anonymous, so stats.repos counts only the public repo.
        let owner = "did:key:zSTATSPRIVAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-repo"))
            .await
            .expect("seed public");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        assert_eq!(
            stats_repos_count(state).await,
            1,
            "stats.repos must not count the private repo (#104 count oracle)"
        );
    }

    #[sqlx::test]
    async fn stats_repos_count_excludes_hide_existence_repo(pool: PgPool) {
        // Some(rule) branch — the #104 subject. Both repos are is_public=true, so
        // the only reason the second is withheld is its root rule with empty
        // reader_dids (anonymous excluded). Proves the count goes through
        // listable_at_root, not a bare is_public predicate.
        let owner = "did:key:zSTATSHIDEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "open-repo"))
            .await
            .expect("seed open");
        let hidden = seed_repo(owner, "hidden-repo"); // is_public = true
        state.db.create_repo(&hidden).await.expect("seed hidden");
        state
            .db
            .set_visibility_rule(&hidden.id, "/", crate::db::VisibilityMode::A, &[], owner)
            .await
            .expect("root hide-existence rule");

        assert_eq!(
            stats_repos_count(state).await,
            1,
            "stats.repos must not count a hide-existence (mode-A, empty readers) repo (#104)"
        );
    }

    #[sqlx::test]
    async fn stats_repos_count_excludes_public_under_root_deny(pool: PgPool) {
        // Inverse the seam was built for: an is_public=true repo with a root deny
        // (mode B, no readers) must not be counted — is_public alone would count it.
        let owner = "did:key:zSTATSDENYAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "open-repo"))
            .await
            .expect("seed open");
        let denied = seed_repo(owner, "deny-repo"); // is_public = true
        state.db.create_repo(&denied).await.expect("seed denied");
        state
            .db
            .set_visibility_rule(&denied.id, "/", crate::db::VisibilityMode::B, &[], owner)
            .await
            .expect("root deny rule");

        assert_eq!(
            stats_repos_count(state).await,
            1,
            "stats.repos must not count an is_public=true repo under a root deny (#104)"
        );
    }

    #[sqlx::test]
    async fn stats_repos_count_matches_list_total(pool: PgPool) {
        // R2 parity: stats.repos == anonymous GET /api/v1/repos X-Total-Count.
        let owner = "did:key:zSTATSPARITYAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "pub-repo"))
            .await
            .expect("seed public");
        state
            .db
            .create_repo(&seed_private_repo(owner, "priv-repo"))
            .await
            .expect("seed private");

        let list_total = {
            let resp = list_repos_router(state.clone())
                .oneshot(anon_get("/api/v1/repos"))
                .await
                .unwrap();
            resp.headers()
                .get("X-Total-Count")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok())
                .expect("X-Total-Count header")
        };

        assert_eq!(
            stats_repos_count(state).await,
            list_total,
            "stats.repos must equal the anonymous list X-Total-Count (R2 parity)"
        );
        assert_eq!(list_total, 1, "sanity: only the public repo is visible");
    }

    #[sqlx::test]
    async fn stats_preserves_sibling_fields(pool: PgPool) {
        // R4: the rewrite must not drop agents/pushes/version.
        let state = test_state(pool).await;
        let resp = stats_router(state)
            .oneshot(anon_get("/api/v1/stats"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        for key in ["repos", "agents", "pushes", "version"] {
            assert!(body.get(key).is_some(), "stats must still carry `{key}`");
        }
    }

    #[sqlx::test]
    async fn stats_repos_count_empty_db_is_zero(pool: PgPool) {
        let state = test_state(pool).await;
        assert_eq!(
            stats_repos_count(state).await,
            0,
            "empty DB yields repos == 0 without error"
        );
    }

    // ---- #110: GET /ipfs/{cid} per-caller visibility gate ----

    /// Seed a SHA-256 source repo (public/a.txt + secret/b.txt), bare-clone it
    /// into each `/tmp/<slug>/<name>.git` path, and return guards + oids.
    /// SHA-256 object format matches production (`--object-format=sha256`) so the
    /// oids are 64-hex. A real CID digests the raw object CONTENT (not the git
    /// oid), so tests build the request CID with `pin_cid_for` — mirroring the pin
    /// path — and `get_by_cid` maps it back to the oid via `pinned_cids` (#173).
    struct CidFixture {
        _guards: Vec<std::path::PathBuf>,
        secret_oid: String,
        public_oid: String,
        secret_tree_oid: String,
        public_tree_oid: String,
        root_tree_oid: String,
        commit_oid: String,
        tag_oid: String,
    }
    impl Drop for CidFixture {
        fn drop(&mut self) {
            for p in &self._guards {
                let _ = std::fs::remove_dir_all(p);
            }
        }
    }
    fn seed_cid_repos(slug: &str, tag: &str, bare_names: &[&str]) -> CidFixture {
        use std::process::Command;
        let run = |args: &[&str], cwd: &std::path::Path| {
            let out = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .expect("git runs");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let src = std::env::temp_dir().join(format!("gl-cid-src-{tag}"));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("public")).unwrap();
        std::fs::create_dir_all(src.join("secret")).unwrap();
        std::fs::write(src.join("public/a.txt"), b"public bytes\n").unwrap();
        std::fs::write(src.join("secret/b.txt"), b"TOP SECRET\n").unwrap();
        run(&["init", "-q", "--object-format=sha256"], &src);
        run(&["config", "user.email", "t@t"], &src);
        run(&["config", "user.name", "t"], &src);
        run(&["add", "."], &src);
        run(&["commit", "-qm", "seed"], &src);
        // Annotated tag of the commit — exercises the "tags stay served" guard.
        run(&["tag", "-a", "-m", "annotated", "v1", "HEAD"], &src);
        let oid = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&src)
                .output()
                .unwrap();
            assert!(out.status.success(), "rev-parse {rev}");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let secret_oid = oid("HEAD:secret/b.txt");
        let public_oid = oid("HEAD:public/a.txt");
        let secret_tree_oid = oid("HEAD:secret");
        let public_tree_oid = oid("HEAD:public");
        let root_tree_oid = oid("HEAD^{tree}");
        let commit_oid = oid("HEAD");
        let tag_oid = oid("refs/tags/v1");
        let mut guards = vec![src.clone()];
        for name in bare_names {
            let bare = std::path::PathBuf::from("/tmp")
                .join(slug)
                .join(format!("{name}.git"));
            let _ = std::fs::remove_dir_all(&bare);
            std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
            run(
                &[
                    "clone",
                    "--bare",
                    "-q",
                    src.to_str().unwrap(),
                    bare.to_str().unwrap(),
                ],
                &src,
            );
            // `git clone --bare` does NOT copy the source repo's local identity, so
            // fixtures that create objects directly in the bare repo (`commit-tree`,
            // `git tag -a`) abort with "identity unknown" on a CI runner that has no
            // ambient/global git identity. Set it explicitly so the suite is portable.
            run(&["config", "user.email", "t@t"], &bare);
            run(&["config", "user.name", "t"], &bare);
        }
        // One guard for the whole /tmp/<slug> tree covers every bare clone.
        guards.push(std::path::PathBuf::from("/tmp").join(slug));
        CidFixture {
            _guards: guards,
            secret_oid,
            public_oid,
            secret_tree_oid,
            public_tree_oid,
            root_tree_oid,
            commit_oid,
            tag_oid,
        }
    }

    /// Record a pin exactly as the production pin path does — read the object's
    /// raw bytes (`git cat-file <type>`, no framing), CID them with
    /// `Cid::from_git_object_bytes`, and store the `(oid, cid)` row — then return
    /// the CID string the node advertises (`gl ipfs list`) and a client sends to
    /// `GET /ipfs/{cid}`. Building the CID from the oid instead (the old
    /// `cid_for_oid`) produced an identifier that never occurs in production and
    /// made the gate assertions vacuous: a real pin CID digests the raw content,
    /// not the git oid, so `get_by_cid` resolves it through `pinned_cids` (#173).
    async fn pin_cid_for(bare_repo: &std::path::Path, oid: &str, db: &crate::db::Db) -> String {
        let (_ty, raw) = crate::git::store::read_object(bare_repo, oid)
            .expect("read object bytes")
            .expect("object exists in repo");
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(&raw).to_string();
        // Legacy-style pin (no provenance) so existing CID tests exercise the
        // resolver's scan fallback; provenance-path tests pin via `pin_cid_for_repo`.
        db.record_pinned_cid(oid, &cid, None)
            .await
            .expect("record pinned cid");
        cid
    }

    /// Like [`pin_cid_for`] but records the pin's provenance (`repo_id`), so the
    /// resolver resolves the CID straight to `repo_id` instead of scanning (#173).
    #[allow(dead_code)] // used by the provenance-path resolver tests (P-U3)
    async fn pin_cid_for_repo(
        bare_repo: &std::path::Path,
        oid: &str,
        db: &crate::db::Db,
        repo_id: &str,
    ) -> String {
        let (_ty, raw) = crate::git::store::read_object(bare_repo, oid)
            .expect("read object bytes")
            .expect("object exists in repo");
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(&raw).to_string();
        db.record_pinned_cid(oid, &cid, Some(repo_id))
            .await
            .expect("record pinned cid with provenance");
        cid
    }

    /// INV-7 upgrade path for the pin-provenance column (#173, jatmn round 2): a node
    /// already past v11 gets `pinned_cids.repo_id` from the NEW v19 migration, and a
    /// legacy pin recorded before the column existed survives with NULL provenance (so
    /// it falls back to the repo scan). Simulate the pre-v19 node by dropping the
    /// column and un-applying v12, seed a legacy row, then re-migrate. RED before the
    /// v19 migration exists (the column is never re-added → the SELECT errors); GREEN
    /// after.
    #[sqlx::test]
    async fn pinned_cids_repo_provenance_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        // Pre-v19 shape: drop the provenance column and forget v19 was applied.
        sqlx::query("ALTER TABLE pinned_cids DROP COLUMN IF EXISTS repo_id")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 19")
            .execute(&pool)
            .await
            .unwrap();

        // A legacy pin recorded before provenance existed.
        sqlx::query("INSERT INTO pinned_cids (sha256_hex, cid, pinned_at) VALUES ($1, $2, $3)")
            .bind("legacyoid")
            .bind("legacycid")
            .bind("2020-01-01T00:00:00Z")
            .execute(&pool)
            .await
            .unwrap();

        // Upgrade: re-run migrations → v19 re-adds the column.
        state.db.run_migrations().await.expect("migrate to v12");

        // The legacy pin survives with NULL provenance.
        let legacy: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM pinned_cids WHERE sha256_hex = 'legacyoid'")
                .fetch_one(&pool)
                .await
                .expect("legacy pin row survives the upgrade");
        assert!(
            legacy.is_none(),
            "a pin recorded before v19 must keep NULL provenance (it falls back to the scan)"
        );

        // A new pin can carry provenance.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) VALUES ($1, $2, $3, $4)",
        )
        .bind("newoid")
        .bind("newcid")
        .bind("2026-01-01T00:00:00Z")
        .bind("repo-abc")
        .execute(&pool)
        .await
        .unwrap();
        let prov: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM pinned_cids WHERE sha256_hex = 'newoid'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            prov.as_deref(),
            Some("repo-abc"),
            "a pin recorded after v19 carries its source repo_id"
        );
    }

    /// #173: a pin records the repository it came from; `provenance_for_oid` reads it
    /// back; a legacy pin (no repo) reads back None; and first-pinner-owns holds — a
    /// second push of the same oid does NOT rewrite provenance (ON CONFLICT DO
    /// NOTHING). This is what lets the resolver gate a CID against its ONE source repo.
    #[sqlx::test]
    async fn record_pinned_cid_stores_and_reads_provenance(pool: PgPool) {
        let state = test_state(pool).await;

        state
            .db
            .record_pinned_cid("oidA", "cidA", Some("repo-xyz"))
            .await
            .unwrap();
        assert_eq!(
            state
                .db
                .provenance_for_oid("oidA")
                .await
                .unwrap()
                .as_deref(),
            Some("repo-xyz"),
            "a provenanced pin reads back its source repo_id"
        );

        state
            .db
            .record_pinned_cid("oidB", "cidB", None)
            .await
            .unwrap();
        assert_eq!(
            state.db.provenance_for_oid("oidB").await.unwrap(),
            None,
            "a legacy pin (no repo) has NULL provenance"
        );

        // First-pinner-owns: a later push of the same oid must not rewrite provenance.
        state
            .db
            .record_pinned_cid("oidA", "cidA", Some("repo-OTHER"))
            .await
            .unwrap();
        assert_eq!(
            state
                .db
                .provenance_for_oid("oidA")
                .await
                .unwrap()
                .as_deref(),
            Some("repo-xyz"),
            "ON CONFLICT DO NOTHING keeps the first repo's provenance"
        );

        // An unpinned oid has no provenance.
        assert_eq!(
            state.db.provenance_for_oid("never-pinned").await.unwrap(),
            None
        );
    }

    /// #173 (provenance, happy path): a CID pinned with provenance resolves straight
    /// to its ONE source repo and serves an authorized reader — no repo scan.
    #[sqlx::test]
    async fn ipfs_cid_provenance_serves_from_pinning_repo(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let _fx = seed_cid_repos(&slug, &short, &["provserve"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("provserve.git");
        let fx = &_fx;

        // Build the repo FIRST so the pin can carry its id as provenance.
        let repo = seed_repo(&owner_did, "provserve"); // public
        state.db.create_repo(&repo).await.expect("seed repo");
        let cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo.id).await;

        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a provenanced public CID serves its content"
        );
        assert!(
            body.contains("public bytes"),
            "the pinning repo's object is served"
        );
    }

    /// #173 (provenance, THE load-bearing one — #124 flip + bounded fan-out): a CID
    /// pinned from a PRIVATE repo must gate against that pinning repo (404), NOT serve
    /// from a byte-identical PUBLIC copy in another repo. Provenance is strictly more
    /// restrictive than the old scan (which served the public copy). RED before the
    /// rework (the scan serves the public copy → 200 + leaks the secret bytes); GREEN
    /// after (provenance → the private repo → 404, no leak).
    #[sqlx::test]
    async fn ipfs_cid_provenance_private_denies_despite_public_copy(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["privsrc", "pubcopy"]);
        let priv_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("privsrc.git");

        // Private source repo, built first so the pin carries its id as provenance.
        let mut priv_repo = seed_repo(&owner_did, "privsrc");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");
        let cid = pin_cid_for_repo(&priv_bare, &fx.secret_oid, &state.db, &priv_repo.id).await;

        // A PUBLIC repo holds the SAME object (the old scan would serve it).
        let pub_repo = seed_repo(&owner_did, "pubcopy"); // public, no rule
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public copy");

        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "a provenanced private CID must 404, not serve from a public copy elsewhere (#124 flip)"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "the 404 body must not leak the withheld object"
        );
    }

    /// #173 (jatmn round 8, F1 — load-bearing): a shared object first pinned from a
    /// PRIVATE repo, then pushed again from a PUBLIC repo through the real pin path,
    /// must serve by CID to an anonymous caller from the public source. First-pinner-
    /// only provenance 404s it (only the private source is known); recording EVERY
    /// pin-path source fixes it. The second push hits the already-pinned skip branch,
    /// so this proves the skip-branch source insert fires (and does NOT re-pin: /add
    /// expect(0)). RED before U1 (anon 404); GREEN after.
    #[sqlx::test]
    async fn ipfs_cid_multi_source_serves_from_later_public_pinner(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["privfirst", "pubsecond"]);
        let priv_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("privfirst.git");
        let pub_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("pubsecond.git");

        // Private repo pins the object FIRST — it owns the first-pinner provenance.
        let mut priv_repo = seed_repo(&owner_did, "privfirst");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private first-pinner");
        let cid = pin_cid_for_repo(&priv_bare, &fx.public_oid, &state.db, &priv_repo.id).await;

        // A PUBLIC repo pushes the SAME object through the real pin path. The object is
        // already pinned, so this hits the already-pinned skip branch, which must record
        // the public repo as an additional source without re-pinning (/add expect 0).
        let pub_repo = seed_repo(&owner_did, "pubsecond"); // public, no rule
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public second-pinner");
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"bafyshouldnothappen"}"#)
            .expect(0)
            .create_async()
            .await;
        crate::ipfs_pin::pin_new_objects(
            &server.url(),
            &pub_bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![fx.public_oid.clone()],
            &state.db,
            &pub_repo.id,
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await; // asserts /add was NOT called (already pinned)

        // Anonymous CID fetch: the private first source denies, the public second
        // source serves → 200. Before F1 only the private source is known → 404.
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a shared object must serve by CID from a later public pin-path source (F1)"
        );
        assert!(
            body.contains("public bytes"),
            "the served body is the public object's bytes"
        );
    }

    /// U1 (grok round-4 P1): `pin_sources_at_cap` flips exactly at `MAX_PIN_SOURCES`.
    /// It is the signal `get_by_cid` uses to decide a provenance miss may be hiding a
    /// dropped servable source and must fall back to the bounded scan.
    #[sqlx::test]
    async fn pin_sources_at_cap_flips_at_max(pool: PgPool) {
        let state = test_state(pool).await;
        let cap = crate::db::MAX_PIN_SOURCES;
        assert!(
            !state.db.pin_sources_at_cap("atcapoid").await.unwrap(),
            "an oid with no pin_repo_sources rows is not at cap"
        );
        for i in 0..(cap - 1) {
            state
                .db
                .record_pin_source("atcapoid", &format!("r-{i:02}"))
                .await
                .unwrap();
        }
        assert!(
            !state.db.pin_sources_at_cap("atcapoid").await.unwrap(),
            "one below MAX_PIN_SOURCES is not at cap"
        );
        state
            .db
            .record_pin_source("atcapoid", "r-last")
            .await
            .unwrap();
        assert!(
            state.db.pin_sources_at_cap("atcapoid").await.unwrap(),
            "exactly MAX_PIN_SOURCES rows is at cap"
        );
    }

    /// U2 (grok round-4 P1, load-bearing): the pin-source GRIEFING hole. A private
    /// first-pinner denies anon; an attacker fills the whole `MAX_PIN_SOURCES` source
    /// window with deny-anon sources BEFORE a legitimate public repo pins the same
    /// object, so the public repo's `record_pin_source` no-ops (cap full) and it is
    /// buried — present in NO provenance record. The resolver's provenance set is then
    /// {private + 16 attacker}, all deny anon. Because the set is at_cap (may hide a
    /// dropped source), the handler falls back to the bounded legacy scan, which gates
    /// every repo through the real gate and finds the buried PUBLIC copy → 200.
    /// MUTATION (RED): remove the `at_cap` fallback edge in `get_by_cid` and the buried
    /// public object 404s forever.
    #[sqlx::test]
    async fn ipfs_cid_buried_public_source_still_serves_via_scan_fallback(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["privfirst", "pubburied"]);
        let priv_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("privfirst.git");
        let pub_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("pubburied.git");

        // Private repo pins FIRST — owns the first-pinner provenance, denies anon.
        let mut priv_repo = seed_repo(&owner_did, "privfirst");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private first-pinner");
        let cid = pin_cid_for_repo(&priv_bare, &fx.public_oid, &state.db, &priv_repo.id).await;

        // Attacker fills the ENTIRE MAX_PIN_SOURCES window with deny-anon (non-existent)
        // sources BEFORE the public repo registers, so the cap is full.
        let cap = crate::db::MAX_PIN_SOURCES;
        for i in 0..cap {
            state
                .db
                .record_pin_source(&fx.public_oid, &format!("00-attacker-{i:02}"))
                .await
                .expect("attacker source");
        }

        // A PUBLIC repo pushes the SAME object through the real pin path. Already pinned
        // (skip branch), so it only tries record_pin_source — which NO-OPS because the
        // cap is full. The public repo is thus buried: not the first-pinner, not in
        // pin_repo_sources.
        let pub_repo = seed_repo(&owner_did, "pubburied"); // public, no rule
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public buried source");
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"bafyshouldnothappen"}"#)
            .expect(0)
            .create_async()
            .await;
        crate::ipfs_pin::pin_new_objects(
            &server.url(),
            &pub_bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![fx.public_oid.clone()],
            &state.db,
            &pub_repo.id,
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await; // /add NOT called (already pinned)

        // The buried public object must STILL serve: the provenance set is at_cap and
        // all-deny, so the handler falls back to the bounded scan, which finds pubburied.
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a public source buried by a full attacker source window must still serve via the bounded scan fallback (F1)"
        );
        assert!(
            body.contains("public bytes"),
            "the served body is the buried public object's bytes"
        );
    }

    /// #173 (jatmn round 8, F1 — bound, R2): the per-object source set is capped at
    /// `MAX_PIN_SOURCES` so an adversary pushing one object from many repos cannot make
    /// resolution O(repos). Recording the same oid from `MAX_PIN_SOURCES + 3` distinct
    /// repos leaves exactly `MAX_PIN_SOURCES` rows.
    #[sqlx::test]
    async fn ipfs_cid_pin_sources_capped_at_max(pool: PgPool) {
        let state = test_state(pool).await;
        let cap = crate::db::MAX_PIN_SOURCES;
        for i in 0..(cap + 3) {
            state
                .db
                .record_pin_source("capoid", &format!("repo-{i}"))
                .await
                .expect("record source");
        }
        let sources = state.db.pin_sources_for_oid("capoid").await.unwrap();
        assert_eq!(
            sources.len() as i64,
            cap,
            "the per-object source set is capped at MAX_PIN_SOURCES"
        );
    }

    /// #173 (jatmn round 8, F1 — availability, grok-4.5 adversarial catch): the resolver's
    /// per-object source cap must NEVER evict the first-pinner. A legacy public pin keeps
    /// its source in `pinned_cids.repo_id` but not in `pin_repo_sources` (pre-v20 pins, or
    /// a pin whose best-effort `record_pin_source` missed). If the cap `LIMIT` were applied
    /// to the whole union with a lexicographic order, an attacker could push the same
    /// object from `MAX_PIN_SOURCES` repos whose grindable ids sort before the public
    /// source and evict it from the window — turning a public CID that served 200 into a
    /// 404. This drives exactly that: a legacy public first-pinner plus `MAX_PIN_SOURCES`
    /// lower-sorting attacker sources must STILL serve the public object. RED with a
    /// whole-union LIMIT (the first-pinner is dropped → 404); GREEN once the first-pinner
    /// is always included and the LIMIT caps only the additional sources.
    #[sqlx::test]
    async fn ipfs_cid_first_pinner_never_evicted_by_lower_sorting_sources(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["pubfirst"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("pubfirst.git");
        // Public repo whose id sorts AFTER every attacker id below. Legacy shape: the
        // source lives in pinned_cids.repo_id only (pin_cid_for_repo records no
        // pin_repo_sources row), exactly like a pin from before v13.
        let mut pub_repo = seed_repo(&owner_did, "pubfirst"); // public, no rule
        pub_repo.id = "zzzzzzzz-pubfirst".to_string();
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public first-pinner");
        let cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &pub_repo.id).await;

        // Attacker fills the whole MAX_PIN_SOURCES window with lower-sorting source ids
        // (non-existent repos — their mere presence would evict the first-pinner under a
        // whole-union LIMIT).
        let cap = crate::db::MAX_PIN_SOURCES;
        for i in 0..cap {
            state
                .db
                .record_pin_source(&fx.public_oid, &format!("00-attacker-{i:02}"))
                .await
                .expect("attacker source");
        }

        // The public first-pinner must still serve — never evicted by the cap window.
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "the first-pinner public source must never be evicted by lower-sorting attacker sources (F1 availability)"
        );
        assert!(
            body.contains("public bytes"),
            "the public object is served from the first-pinner"
        );
    }

    /// INV-7 upgrade path for the F1 `pin_repo_sources` table (#173, jatmn round 8): a
    /// node already past v19 gets the table from the NEW v20 migration. Simulate the
    /// pre-v20 node by dropping the table and un-applying v13, then re-migrate and
    /// assert a source row round-trips. RED before the v20 migration exists.
    #[sqlx::test]
    async fn pin_repo_sources_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        sqlx::query("DROP TABLE IF EXISTS pin_repo_sources")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 20")
            .execute(&pool)
            .await
            .unwrap();
        state.db.run_migrations().await.expect("re-migrate");
        state
            .db
            .record_pin_source("upgradeoid", "repo-upg")
            .await
            .expect("record after re-migrate");
        assert_eq!(
            state.db.pin_sources_for_oid("upgradeoid").await.unwrap(),
            vec!["repo-upg".to_string()],
            "the v20 pin_repo_sources table is present after upgrade"
        );
    }

    // ── U3 (#173): durable pin-source incompleteness marker ──────────────────
    //
    // `record_pin_source` is best effort at every call site, so a non-empty,
    // below-cap source set is NOT proof of completeness: an object first pinned
    // from a PRIVATE repo and later pushed from a PUBLIC repo whose record failed
    // has a set that names only the private source. The resolver used to treat
    // that set as complete and 404 an object the public repo would serve. The
    // pinned_cids.pin_sources_incomplete marker records the miss durably so the
    // bounded scan fallback still runs. These tests drive both arms: the marker
    // set (fallback runs, object serves, denial still denies) and the marker
    // clear (ordinary denials stay off the O(repos) path, INV-10).

    /// Make `record_pin_source` fail for the duration of `body` by moving the
    /// `pin_repo_sources` table out from under it, the closest honest stand-in for
    /// the transient DB error the retry wrapper is there to absorb. Every other
    /// pin-path query keeps working, so only the source record (and its retries)
    /// fails, which is exactly the partial-record shape the finding turns on.
    async fn with_pin_sources_broken<F, Fut, T>(pool: &PgPool, body: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        sqlx::query("ALTER TABLE pin_repo_sources RENAME TO pin_repo_sources_hidden")
            .execute(pool)
            .await
            .expect("hide pin_repo_sources");
        let out = body().await;
        sqlx::query("ALTER TABLE pin_repo_sources_hidden RENAME TO pin_repo_sources")
            .execute(pool)
            .await
            .expect("restore pin_repo_sources");
        out
    }

    /// Pin `oid` from `repo_id` through the real ipfs_pin path with a mock Kubo that
    /// must NOT be called (the object is already pinned, so this drives the
    /// skip-branch `record_pin_source` and nothing else).
    async fn repin_via_skip_branch(
        state: &AppState,
        bare: &std::path::Path,
        oid: &str,
        repo_id: &str,
    ) {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"bafyshouldnothappen"}"#)
            .expect(0)
            .create_async()
            .await;
        crate::ipfs_pin::pin_new_objects(
            &server.url(),
            bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![oid.to_string()],
            &state.db,
            repo_id,
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await;
    }

    /// U3 scenario 1 (#173, the finding's exact case): an object first pinned from a
    /// PRIVATE repo, then pushed from a PUBLIC repo whose `record_pin_source`
    /// exhausts its retries. The source set is non-empty and below cap, so the old
    /// gate called it COMPLETE and 404'd an object the public repo would happily
    /// serve. With the durable marker the bounded scan fallback still runs and the
    /// public copy serves. RED before the marker (404); GREEN after (200).
    #[sqlx::test]
    async fn ipfs_cid_incomplete_source_set_falls_back_to_scan(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3priv", "u3pub"]);
        let priv_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3priv.git");
        let pub_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3pub.git");

        // Private first-pinner owns the only recorded source.
        let mut priv_repo = seed_repo(&owner_did, "u3priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private");
        let cid = pin_cid_for_repo(&priv_bare, &fx.public_oid, &state.db, &priv_repo.id).await;

        // The PUBLIC repo holds the same object, but its source record never lands.
        let pub_repo = seed_repo(&owner_did, "u3pub"); // public, no rule
        state.db.create_repo(&pub_repo).await.expect("seed public");
        with_pin_sources_broken(&pool, || {
            repin_via_skip_branch(&state, &pub_bare, &fx.public_oid, &pub_repo.id)
        })
        .await;

        // The recorded set still names only the private repo, and it is below cap.
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![priv_repo.id.clone()],
            "the public source really did fail to record"
        );
        assert!(
            !state.db.pin_sources_at_cap(&fx.public_oid).await.unwrap(),
            "the set is below cap, so at_cap cannot be what triggers the fallback"
        );

        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a KNOWN-incomplete source set must keep the scan fallback so the public copy serves"
        );
        assert!(
            body.contains("public bytes"),
            "the served body is the public object's bytes"
        );
    }

    /// U3 scenario 2 (#173, INV-10 guard): the marker must not turn ORDINARY denials
    /// into an O(repos) fan-out. With the marker false, a non-empty below-cap source
    /// set and a provenance miss, the request must 404 WITHOUT the scan preload ever
    /// running. The preload counter is the both-ways proof: forcing the marker true
    /// unconditionally turns this red (count 1), which is what keeps the assertion
    /// from being vacuous.
    #[sqlx::test]
    async fn ipfs_cid_complete_source_set_never_preloads(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["u3only"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3only.git");

        // One PRIVATE source, recorded cleanly: the set is complete and below cap.
        let mut priv_repo = seed_repo(&owner_did, "u3only");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private");
        let cid = pin_cid_for_repo(&bare, &fx.secret_oid, &state.db, &priv_repo.id).await;
        state
            .db
            .record_pin_source(&fx.secret_oid, &priv_repo.id)
            .await
            .expect("record source");
        assert!(
            !state
                .db
                .pin_sources_incomplete(&fx.secret_oid)
                .await
                .unwrap(),
            "a clean record leaves the set marked complete"
        );
        assert!(
            !state.db.pin_sources_at_cap(&fx.secret_oid).await.unwrap(),
            "the set is below cap, so at_cap cannot be what drives the gate"
        );

        crate::api::ipfs::reset_preload_queries();
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "an anonymous caller denied by the only recorded source gets the opaque 404"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "the 404 body must not leak the withheld object"
        );
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            0,
            "an ordinary denial against a COMPLETE source set must never run the O(repos) preload (INV-10)"
        );
    }

    /// U3 scenario 3 (#173): the marker is not permanent. Once a later
    /// `record_pin_source` for the object succeeds, nothing is missing, so the marker
    /// clears and the scan stops being triggered. BOTH sources here are private, so the
    /// provenance walk MISSES and the request actually reaches the `needs_scan` gate:
    /// with a marker left stuck the gate arms the O(repos) preload for an ordinary
    /// denial forever. Drop the clear and both halves go red (marker still true, preload
    /// 1). A public second source would make the preload half vacuous, because the
    /// provenance path serves and returns before the gate is ever evaluated.
    #[sqlx::test]
    async fn ipfs_cid_marker_clears_on_a_later_successful_record(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3cfirst", "u3csecond"]);
        let first_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3cfirst.git");
        let second_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3csecond.git");

        let mut first_repo = seed_repo(&owner_did, "u3cfirst");
        first_repo.is_public = false;
        state.db.create_repo(&first_repo).await.expect("seed first");
        let cid = pin_cid_for_repo(&first_bare, &fx.secret_oid, &state.db, &first_repo.id).await;
        let mut second_repo = seed_repo(&owner_did, "u3csecond");
        second_repo.is_public = false;
        state
            .db
            .create_repo(&second_repo)
            .await
            .expect("seed second");

        // First push from the second repo: the source record fails, so the set is marked.
        with_pin_sources_broken(&pool, || {
            repin_via_skip_branch(&state, &second_bare, &fx.secret_oid, &second_repo.id)
        })
        .await;
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.secret_oid)
                .await
                .unwrap(),
            "the exhausted record marked the set incomplete"
        );

        // A later push from the same repo records cleanly, so nothing is missing.
        repin_via_skip_branch(&state, &second_bare, &fx.secret_oid, &second_repo.id).await;
        assert!(
            !state
                .db
                .pin_sources_incomplete(&fx.secret_oid)
                .await
                .unwrap(),
            "a successful record clears the marker"
        );
        assert_eq!(
            state
                .db
                .pin_sources_for_oid(&fx.secret_oid)
                .await
                .unwrap()
                .len(),
            2,
            "the repaired set really does name both sources"
        );

        crate::api::ipfs::reset_preload_queries();
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "both sources are private, so the anonymous caller is denied"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "the 404 body must not leak the withheld object"
        );
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            0,
            "a repaired source set stops triggering the scan: the denial is back off the O(repos) path"
        );
    }

    /// F5 (#173 round 11): the work-budget peek sheds an already-throttled caller BEFORE
    /// the two marker queries, so a spent-budget source stops paying two lookups per
    /// request for a scan it will never be allowed to run. The source set here is
    /// non-empty and complete, which is the case that used to reach the queries anyway.
    /// The counter is the both-ways guard: moving the peek back below the pair reads 1.
    #[sqlx::test]
    async fn ipfs_cid_throttled_caller_sheds_before_the_marker_queries(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        // One PRIVATE source, recorded cleanly: the set is non-empty, below cap and
        // unmarked, so nothing but the peek can keep the request off the queries.
        let fx = seed_cid_repos(&slug, &short, &["f5only"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("f5only.git");
        let mut repo = seed_repo(&owner_did, "f5only");
        repo.is_public = false;
        state.db.create_repo(&repo).await.expect("seed private");
        let cid = pin_cid_for_repo(&bare, &fx.secret_oid, &state.db, &repo.id).await;
        state
            .db
            .record_pin_source(&fx.secret_oid, &repo.id)
            .await
            .expect("record source");

        // Spend the caller's whole work budget before the request.
        assert!(
            state.ipfs_work_rate_limiter.check("9.9.9.9").await,
            "the budget starts with room"
        );

        crate::api::ipfs::reset_marker_queries();
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon_xff(&cid, "9.9.9.9"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::TOO_MANY_REQUESTS,
            "a spent-budget caller is shed at the peek"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "the shed response must not leak the withheld object"
        );
        assert_eq!(
            crate::api::ipfs::marker_queries(),
            0,
            "a shed caller pays neither marker query"
        );
    }

    /// U3 scenario 6 (#173, regression): a record that inserts NOTHING must not clear
    /// the marker. `record_pin_source` is called for EVERY already-pinned object on the
    /// skip path, and on a requeue pass that is the whole-repo enumeration, so the next
    /// coalesced push from a repo ALREADY in the source set re-runs the insert as a
    /// no-op. Clearing on that no-op re-hides the hole a different repo's failed record
    /// recorded: the public copy stops being scanned for and 404s again. The assertion
    /// is the SERVE outcome, not the column, so it still bites if the resolver ever
    /// stops consulting the marker. RED before the rows_affected gate (404); GREEN after.
    #[sqlx::test]
    async fn ipfs_cid_noop_record_must_not_clear_the_marker(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3npriv", "u3npub"]);
        let priv_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3npriv.git");
        let pub_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3npub.git");

        // Repo A (private) is the first pinner AND is already recorded as a source, so a
        // later record from A is a pure no-op insert.
        let mut priv_repo = seed_repo(&owner_did, "u3npriv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private");
        let cid = pin_cid_for_repo(&priv_bare, &fx.public_oid, &state.db, &priv_repo.id).await;
        state
            .db
            .record_pin_source(&fx.public_oid, &priv_repo.id)
            .await
            .expect("record the first pinner as a source");

        // Repo B (public) holds the same object, but its source record never lands, so
        // the node marks the set known-incomplete.
        let pub_repo = seed_repo(&owner_did, "u3npub");
        state.db.create_repo(&pub_repo).await.expect("seed public");
        with_pin_sources_broken(&pool, || {
            repin_via_skip_branch(&state, &pub_bare, &fx.public_oid, &pub_repo.id)
        })
        .await;
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "the exhausted record marked the set incomplete"
        );

        // A pushes again. The insert affects zero rows (A is already a source), so it
        // recorded nothing and must not claim the set is complete.
        repin_via_skip_branch(&state, &priv_bare, &fx.public_oid, &priv_repo.id).await;
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![priv_repo.id.clone()],
            "the re-push really did add no source"
        );

        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a no-op record must not clear the marker: the public copy still has to serve"
        );
        assert!(
            body.contains("public bytes"),
            "the served body is the public object's bytes"
        );
    }

    /// U3 residual, CLOSED (#173 round 12): the incompleteness marker is per
    /// `(object, repo)`, so a GENUINE record from a third repo C no longer clears the
    /// marker repo B's FAILED record set, and the resolver keeps the scan fallback that
    /// finds B's unrecorded public copy.
    ///
    /// This test asserted the opposite until the marker moved to `pin_source_failures`.
    /// It was written as a deliberate pin on an accepted cost of the single boolean, with
    /// a note saying that implementing the per-(oid, repo) marker should turn it red and
    /// that it should then be updated rather than deleted. That is what happened, so the
    /// assertions are inverted here and the fixture is unchanged.
    ///
    /// The BEFORE request is what makes the AFTER assertion mean anything: it proves the
    /// unrecorded public holder IS reachable while the marker stands, so an AFTER 404
    /// would be caused by the clear and by nothing else in the fixture. The window this
    /// covers is exactly `1 <= sources < MAX_PIN_SOURCES`: an empty set always scans, and
    /// at cap the insert is a no-op so the marker survives regardless.
    #[sqlx::test]
    async fn ipfs_cid_third_repo_record_keeps_the_marker_and_still_serves_an_unrecorded_holder(
        pool: PgPool,
    ) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3ta", "u3tb", "u3tc"]);
        let a_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3ta.git");
        let b_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3tb.git");
        let c_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3tc.git");

        // Repo A (private) is the first pinner and the only recorded source.
        let mut a_repo = seed_repo(&owner_did, "u3ta");
        a_repo.is_public = false;
        state.db.create_repo(&a_repo).await.expect("seed A private");
        let cid = pin_cid_for_repo(&a_bare, &fx.public_oid, &state.db, &a_repo.id).await;
        state
            .db
            .record_pin_source(&fx.public_oid, &a_repo.id)
            .await
            .expect("record the first pinner as a source");

        // Repo B (public) genuinely holds the object, but its source record never lands,
        // so the node marks the set known-incomplete.
        let b_repo = seed_repo(&owner_did, "u3tb"); // public, no rule
        state.db.create_repo(&b_repo).await.expect("seed B public");
        with_pin_sources_broken(&pool, || {
            repin_via_skip_branch(&state, &b_bare, &fx.public_oid, &b_repo.id)
        })
        .await;
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "B's exhausted record marked the set incomplete"
        );

        // BEFORE: while the marker stands, the scan fallback finds B and serves.
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "with the marker set, the unrecorded public holder is reachable"
        );
        assert!(
            body.contains("public bytes"),
            "the served body is the public object's bytes"
        );

        // Repo C (private) pushes the same object. Its record is a GENUINE insert (C is
        // not yet a source), and it must NOT clear the marker B set, because B is still
        // missing and C's record says nothing about B.
        let mut c_repo = seed_repo(&owner_did, "u3tc");
        c_repo.is_public = false;
        state.db.create_repo(&c_repo).await.expect("seed C private");
        repin_via_skip_branch(&state, &c_bare, &fx.public_oid, &c_repo.id).await;

        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "a third repo's record clears only its own pair, so B's marker survives"
        );
        assert!(
            !state.db.pin_sources_at_cap(&fx.public_oid).await.unwrap(),
            "the set is below cap, so at_cap is not what drives the gate here"
        );
        let sources = state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap();
        assert_eq!(sources.len(), 2, "the set names A and C only: {sources:?}");
        assert!(
            !sources.contains(&b_repo.id),
            "B is still missing from the set it was marked for: {sources:?}"
        );

        // AFTER: the identical request still serves B's copy, because the surviving
        // marker keeps the fallback armed. The scan is asserted to have RUN, so the 200
        // is the fallback finding B and not the provenance loop reaching it some other way.
        crate::api::ipfs::reset_preload_queries();
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "B's marker survived C's record, so the unrecorded public holder is still reachable"
        );
        assert!(
            body.contains("public bytes"),
            "the served body is the public object's bytes"
        );
        assert!(
            crate::api::ipfs::preload_queries() > 0,
            "the fallback scan ran, so the 200 came from the armed fallback"
        );
    }

    /// U3 scenario 4 (#173): the marker tracks the record's OUTCOME, not the attempt.
    /// An exhausted retry sets it; a first-attempt success never does. Without the
    /// second arm the first could be satisfied by marking unconditionally.
    #[sqlx::test]
    async fn pin_sources_incomplete_marks_only_exhausted_records(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3mark"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3mark.git");
        let repo = seed_repo(&owner_did, "u3mark");
        state.db.create_repo(&repo).await.expect("seed repo");
        let _ = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo.id).await;

        // Arm A: a first-attempt success must leave the marker alone.
        repin_via_skip_branch(&state, &bare, &fx.public_oid, &repo.id).await;
        assert!(
            !state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "a record that lands on the first attempt never marks the set incomplete"
        );

        // Arm B: an exhausted retry marks it.
        with_pin_sources_broken(&pool, || {
            repin_via_skip_branch(&state, &bare, &fx.public_oid, &repo.id)
        })
        .await;
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "an exhausted record marks the set incomplete"
        );

        // An unpinned oid has no row and must read as complete, never as missing.
        assert!(
            !state
                .db
                .pin_sources_incomplete(&"f".repeat(64))
                .await
                .unwrap(),
            "an unpinned oid reads complete, so an unknown CID cannot arm the fallback"
        );
    }

    /// #173 round 12 (jatmn): the incompleteness marker is per `(object, repo)`, so a
    /// record from an UNRELATED repo does not clear a marker a different repo's failed
    /// record set. It was one boolean per object, and the resolver reads a cleared marker
    /// as "every source is recorded", drops the scan fallback, and 404s an anonymous
    /// caller whose only servable copy is the unrecorded public one.
    ///
    /// Both directions, because the precision is the point: an unrelated repo must NOT
    /// clear, and the repo that actually failed MUST clear, or every transient DB blip
    /// would strand an object on the scan path forever.
    #[sqlx::test]
    async fn pin_source_failure_is_cleared_only_by_the_repo_that_failed(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3perrepo"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3perrepo.git");
        let repo_a = seed_repo(&owner_did, "u3perrepo");
        state.db.create_repo(&repo_a).await.expect("seed repo A");
        let repo_b = seed_repo(&owner_did, "u3perrepo-b");
        state.db.create_repo(&repo_b).await.expect("seed repo B");
        let repo_c = seed_repo(&owner_did, "u3perrepo-c");
        state.db.create_repo(&repo_c).await.expect("seed repo C");
        let _ = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo_a.id).await;

        // Repo B's record fails: the object is now known to be missing B as a source.
        state
            .db
            .mark_pin_sources_incomplete(&fx.public_oid, &repo_b.id)
            .await
            .expect("mark B's failure");
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "B's failed record marks the set incomplete"
        );

        // A genuine record from an UNRELATED repo C. B is still missing.
        state
            .db
            .record_pin_source(&fx.public_oid, &repo_c.id)
            .await
            .expect("record C");
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "a record from an unrelated repo must not clear a marker another repo set: \
             the resolver would drop the scan fallback while B's copy is still unrecorded"
        );

        // The repo that actually failed lands its record: now the set is complete.
        state
            .db
            .record_pin_source(&fx.public_oid, &repo_b.id)
            .await
            .expect("record B");
        assert!(
            !state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "the repo whose record failed clears its own marker once it lands"
        );
    }

    /// U3 scenario 5 (#173): the Pinata pin path had BARE `record_pin_source` calls, so
    /// one transient DB error dropped a source permanently. It now shares the ipfs_pin
    /// retry helper and marks/clears the same marker. The elapsed-time assertion is the
    /// retry proof: a bare call returns immediately, whereas the wrapper sleeps
    /// `PIN_RECORD_BACKOFF` between each of `PIN_RECORD_ATTEMPTS` tries.
    #[sqlx::test]
    async fn pinata_pin_path_retries_and_marks_incomplete(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3pinata"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3pinata.git");
        let repo = seed_repo(&owner_did, "u3pinata");
        state.db.create_repo(&repo).await.expect("seed repo");

        // Already carries a pinata_cid, so pin_new_objects takes the skip branch and the
        // only DB write under test is the source record.
        let (_ty, raw) = crate::git::store::read_object(&bare, &fx.public_oid)
            .unwrap()
            .expect("object readable");
        let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(&raw).to_string();
        state
            .db
            .record_pinata_cid(&fx.public_oid, &raw_cid, "QmProvider", Some(&repo.id))
            .await
            .expect("seed pinata pin");

        let client = reqwest::Client::new();
        let run = |db_broken: bool| {
            let client = client.clone();
            let bare = bare.clone();
            let oid = fx.public_oid.clone();
            let repo_id = repo.id.clone();
            let state = &state;
            async move {
                let mut server = mockito::Server::new_async().await;
                let m = server
                    .mock("POST", mockito::Matcher::Any)
                    .with_status(200)
                    .with_body(r#"{"data":{"cid":"QmShouldNotHappen"}}"#)
                    .expect(0)
                    .create_async()
                    .await;
                let started = std::time::Instant::now();
                crate::pinata::pin_new_objects(
                    &client,
                    &server.url(),
                    "test-jwt",
                    &bare,
                    "git",
                    // Generous: this test measures the record retry backoff, not the
                    // read bound, so the git_timeout must never be what fires.
                    std::time::Duration::from_secs(60),
                    vec![oid],
                    &state.db,
                    &repo_id,
                    // Far above the ~150ms the retry ladder spends, so the batch gate
                    // never truncates the one object under test: what is being measured
                    // is the retry backoff, not the budget.
                    std::time::Duration::from_secs(60),
                )
                .await;
                m.assert_async().await; // the upload is skipped: DB-only path
                let _ = db_broken;
                started.elapsed()
            }
        };

        // Failing arm: retried (so it sleeps the full backoff horizon) and marked.
        let elapsed = with_pin_sources_broken(&pool, || run(true)).await;
        assert!(
            elapsed >= std::time::Duration::from_millis(100),
            "the pinata source record now RETRIES (bare call returns at once, got {elapsed:?})"
        );
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "an exhausted pinata record marks the set incomplete, same as the ipfs_pin path"
        );

        // Recovery arm: a later successful pinata record clears it, same as ipfs_pin.
        run(false).await;
        assert!(
            !state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "a successful pinata record clears the marker"
        );
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![repo.id.clone()],
            "the recovered record actually landed the source row"
        );
    }

    /// A Pinata upload mock that must never fire, for the skip-branch tests below: an
    /// object already carrying a `pinata_cid` is skipped before the upload, so a call
    /// here means the branch under test was not the one taken.
    async fn pinata_upload_mock_never(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"data":{"cid":"QmShouldNotHappen"}}"#)
            .expect(0)
            .create_async()
            .await
    }

    /// The raw-content resolver key for an object in a bare repo, computed the way the
    /// pin path computes it.
    fn raw_key_for(bare: &std::path::Path, oid: &str) -> String {
        gitlawb_core::cid::Cid::from_git_object_bytes(
            &crate::git::store::read_object(bare, oid)
                .expect("read object bytes")
                .expect("object exists")
                .1,
        )
        .to_string()
    }

    /// Seed a `pinned_cids` row by hand: the production helpers always store the raw
    /// key, so a legacy provider-CID row can only be written with raw SQL.
    async fn seed_pinned_row(
        pool: &PgPool,
        oid: &str,
        cid: &str,
        pinata_cid: Option<&str>,
        repo_id: &str,
    ) {
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pinata_cid, repo_id)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(oid)
        .bind(cid)
        .bind("2020-01-01T00:00:00Z")
        .bind(pinata_cid)
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("seed pinned_cids row");
    }

    /// The stored resolver key and the stashed old provider value for a pinned object.
    async fn stored_key_and_stash(pool: &PgPool, oid: &str) -> (String, Option<String>) {
        sqlx::query_as("SELECT cid, legacy_provider_cid FROM pinned_cids WHERE sha256_hex = $1")
            .bind(oid)
            .fetch_one(pool)
            .await
            .expect("the pinned row exists")
    }

    /// The skip-branch repair runs while the caller holds a `pin_semaphore` permit, so it
    /// must be bounded by the BATCH deadline and not by `git_timeout` alone.
    /// `repair_legacy_provider_cid` builds its own deadline, and at shipped defaults that
    /// is `git_service_timeout_secs` (600s) against a `PIN_BATCH_BUDGET` of 120s: one
    /// legacy row whose `cat-file` wedges would hold a GLOBAL pin slot for five times the
    /// budget the batch is supposed to cost, starving every other repo's pin work. The
    /// loop's own budget gate cannot help, since it only runs at the top of the NEXT
    /// iteration and cannot preempt a call already in flight.
    ///
    /// A wedged `cat-file`, a generous 60s `git_timeout`, and a 2s batch budget: the call
    /// must return on the batch order. Both pin-permit-holding callers of the repair share
    /// this clamp; the boot sweep keeps the plain `git_timeout`, since it holds no permit
    /// and has no batch to overrun.
    ///
    /// REVERT PROOF (RED): pass `Instant::now() + git_timeout` to the repair instead of the
    /// batch-clamped deadline and the wedged child runs the full 60s, blowing the outer
    /// timeout below.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pinata_skip_branch_repair_is_bounded_by_the_batch_deadline(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let fx = seed_cid_repos("pinatabound", "pb", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("pinatabound")
            .join("pinsrc.git");

        // Resolve the real key with the real git BEFORE the fake is wired in, so the row
        // is genuinely legacy-shaped and the repair has real work to attempt.
        let raw_cid = raw_key_for(&bare, &fx.public_oid);
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        seed_pinned_row(
            &pool,
            &fx.public_oid,
            &provider_cid,
            Some("QmPinataProvider"),
            "repoPinataBound",
        )
        .await;

        // `cat-file` never answers and ignores SIGTERM, so only the watchdog's group
        // SIGKILL at the deadline can end it. Which deadline that is, is the whole test.
        let tmp = tempfile::TempDir::new().unwrap();
        let fake = tmp.path().join("wedged-git");
        std::fs::write(
            &fake,
            "#!/bin/sh\ntrap '' TERM\ncase \"$1\" in\n  cat-file) sleep 60 ;;\n  *) : ;;\nesac\nexit 0\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&fake).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&fake, perm).unwrap();
        }

        let mut server = mockito::Server::new_async().await;
        let m = pinata_upload_mock_never(&mut server).await;
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_secs(25),
            crate::pinata::pin_new_objects(
                &client,
                &server.url(),
                "test-jwt",
                &bare,
                fake.to_str().unwrap(),
                // Generous: if the call ends on time it ended on the batch deadline.
                std::time::Duration::from_secs(60),
                vec![fx.public_oid.clone()],
                &state.db,
                "repoPinataBound",
                // The bound under test.
                std::time::Duration::from_secs(2),
            ),
        )
        .await
        .expect(
            "a wedged skip-branch repair must be reaped on the batch deadline, not held for \
             the whole git_timeout while it pins a global pin permit",
        );
        m.assert_async().await;

        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "elapsed {elapsed:?} must stay in the 2s batch-budget order (plus one watchdog \
             teardown), not the 60s git_timeout order"
        );
    }

    /// The ipfs_pin twin of the clamp above, and the one that has been shipping: the Kubo
    /// skip branch has always called the repair with a bare `git_timeout` while holding the
    /// pin permit. Same wedged `cat-file`, same 60s `git_timeout` against a 2s batch
    /// budget, same requirement that the call return on the batch order.
    ///
    /// REVERT PROOF (RED): drop the `min(deadline, ...)` clamp at the ipfs_pin skip-branch
    /// call and this blows its outer timeout.
    #[cfg(unix)]
    #[sqlx::test]
    async fn kubo_skip_branch_repair_is_bounded_by_the_batch_deadline(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let fx = seed_cid_repos("kubobound", "kb", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("kubobound")
            .join("pinsrc.git");

        let raw_cid = raw_key_for(&bare, &fx.public_oid);
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        // A row in pinned_cids makes `is_pinned` true, so the Kubo loop takes the skip
        // branch and reaches the repair without ever attempting an add.
        seed_pinned_row(&pool, &fx.public_oid, &provider_cid, None, "repoKuboBound").await;

        let tmp = tempfile::TempDir::new().unwrap();
        let fake = tmp.path().join("wedged-git");
        std::fs::write(
            &fake,
            "#!/bin/sh\ntrap '' TERM\ncase \"$1\" in\n  cat-file) sleep 60 ;;\n  *) : ;;\nesac\nexit 0\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&fake).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&fake, perm).unwrap();
        }

        let started = std::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_secs(25),
            crate::ipfs_pin::pin_new_objects(
                // Empty endpoint would return before the loop, so point at a closed port:
                // the skip branch is reached and no add is ever attempted anyway.
                "http://127.0.0.1:9",
                &bare,
                fake.to_str().unwrap(),
                std::time::Duration::from_secs(60),
                vec![fx.public_oid.clone()],
                &state.db,
                "repoKuboBound",
                std::time::Duration::from_secs(2),
            ),
        )
        .await
        .expect(
            "a wedged skip-branch repair must be reaped on the batch deadline, not held for \
             the whole git_timeout while it pins a global pin permit",
        );

        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "elapsed {elapsed:?} must stay in the 2s batch-budget order, not the 60s \
             git_timeout order"
        );
    }

    /// U3 scenario 1 (#173, Finding 2 lockstep): the PINATA skip branch runs the same
    /// opportunistic legacy provider-CID repair the ipfs_pin skip branch runs. A row keyed
    /// on a legacy provider CID that already carries a `pinata_cid` (so `has_pinata_cid`
    /// answers true and the skip branch is taken) is rewritten to the raw-content resolver
    /// key, stashing the old provider value in `legacy_provider_cid`.
    ///
    /// This drives `pinata::pin_new_objects`, never the ipfs_pin twin: the repair call
    /// being PRESENT in `pinata.rs` proves nothing, only its execution through this lane
    /// does. RED before the skip-branch call lands (the key stays the provider CID).
    #[sqlx::test]
    async fn pinata_skip_branch_repairs_legacy_provider_cid(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let fx = seed_cid_repos("pinatarepair", "pr", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("pinatarepair")
            .join("pinsrc.git");

        let raw_cid = raw_key_for(&bare, &fx.public_oid);
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        assert_ne!(
            provider_cid, raw_cid,
            "the provider CID differs from the raw resolver key"
        );
        seed_pinned_row(
            &pool,
            &fx.public_oid,
            &provider_cid,
            Some("QmPinataProvider"),
            "repoPinataRepair",
        )
        .await;

        let mut server = mockito::Server::new_async().await;
        let m = pinata_upload_mock_never(&mut server).await;
        let client = reqwest::Client::new();
        crate::pinata::pin_new_objects(
            &client,
            &server.url(),
            "test-jwt",
            &bare,
            "git",
            std::time::Duration::from_secs(60),
            vec![fx.public_oid.clone()],
            &state.db,
            "repoPinataRepair",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await;

        let (stored_cid, stashed) = stored_key_and_stash(&pool, &fx.public_oid).await;
        assert_eq!(
            stored_cid, raw_cid,
            "the pinata skip branch repairs the key to the raw-content CID"
        );
        assert_eq!(
            stashed.as_deref(),
            Some(provider_cid.as_str()),
            "the old provider CID is stashed in legacy_provider_cid"
        );
    }

    /// U3 scenario 2 (#173, cost gate): a canonical raw-CIDv1 row on the pinata skip
    /// branch reads NO object bytes. Candidacy is decided from the stored key's codec
    /// alone, so the steady-state skip cost stays DB-only on this lane too. The counter
    /// lives inside `repair_legacy_provider_cid`, so it counts for whichever lane calls
    /// it; this is the both-ways guard (removing the codec gate reads the raw row).
    #[sqlx::test]
    async fn pinata_skip_branch_repair_codec_gate_skips_raw_row(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let fx = seed_cid_repos("pinatagate", "pg", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("pinatagate")
            .join("pinsrc.git");

        let raw_cid = raw_key_for(&bare, &fx.public_oid);
        assert!(
            gitlawb_core::cid::is_raw_cidv1(&raw_cid),
            "the steady-state key is a CIDv1/raw key"
        );
        seed_pinned_row(
            &pool,
            &fx.public_oid,
            &raw_cid,
            Some("QmPinataProvider"),
            "repoPinataGate",
        )
        .await;

        let mut server = mockito::Server::new_async().await;
        let m = pinata_upload_mock_never(&mut server).await;
        let client = reqwest::Client::new();
        crate::ipfs_pin::reset_legacy_repair_reads();
        crate::pinata::pin_new_objects(
            &client,
            &server.url(),
            "test-jwt",
            &bare,
            "git",
            std::time::Duration::from_secs(60),
            vec![fx.public_oid.clone()],
            &state.db,
            "repoPinataGate",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await;

        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "a CIDv1/raw row triggers no object read on the pinata skip path (cost gate)"
        );
        assert_eq!(
            state
                .db
                .cid_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .as_deref(),
            Some(raw_cid.as_str()),
            "the raw row is left as-is"
        );
    }

    /// U3 scenario 3 (#173): a repair that cannot complete is warn-only. It neither
    /// aborts the batch nor loses the pin. The first object is a legacy row whose bytes
    /// are NOT in the repo, so the read verifies an absence and the row stays withheld
    /// rather than being destructively rewritten; the skip branch's own source record
    /// still lands for it, and the SECOND object's legacy row is still repaired, which is
    /// what proves the batch ran past the failure.
    #[sqlx::test]
    async fn pinata_skip_branch_repair_failure_is_warn_only(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let fx = seed_cid_repos("pinatawarn", "pw", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("pinatawarn")
            .join("pinsrc.git");

        // Object A: bytes absent from this repo, so its repair cannot complete.
        let absent_oid = "a".repeat(64);
        let absent_provider = legacy_dagpb_cid(&raw_key_for(&bare, &fx.secret_oid));
        seed_pinned_row(
            &pool,
            &absent_oid,
            &absent_provider,
            Some("QmPinataProviderA"),
            "repoPinataWarn",
        )
        .await;
        // Object B: a repairable legacy row, queued behind A.
        let raw_cid = raw_key_for(&bare, &fx.public_oid);
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        seed_pinned_row(
            &pool,
            &fx.public_oid,
            &provider_cid,
            Some("QmPinataProviderB"),
            "repoPinataWarn",
        )
        .await;

        let mut server = mockito::Server::new_async().await;
        let m = pinata_upload_mock_never(&mut server).await;
        let client = reqwest::Client::new();
        crate::pinata::pin_new_objects(
            &client,
            &server.url(),
            "test-jwt",
            &bare,
            "git",
            std::time::Duration::from_secs(60),
            vec![absent_oid.clone(), fx.public_oid.clone()],
            &state.db,
            "repoPinataWarn",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await;

        let (a_cid, a_stash) = stored_key_and_stash(&pool, &absent_oid).await;
        assert_eq!(
            a_cid, absent_provider,
            "an unrepairable row is never destructively rewritten"
        );
        assert_eq!(a_stash, None, "nothing is stashed for an unrepaired row");
        assert_eq!(
            state.db.pin_sources_for_oid(&absent_oid).await.unwrap(),
            vec!["repoPinataWarn".to_string()],
            "the skip branch's source record still lands: a failed repair loses no pin"
        );

        let (b_cid, b_stash) = stored_key_and_stash(&pool, &fx.public_oid).await;
        assert_eq!(
            b_cid, raw_cid,
            "the batch ran past the failed repair and repaired the later object"
        );
        assert_eq!(b_stash.as_deref(), Some(provider_cid.as_str()));
    }

    /// U3 scenario 4 (#173, the must-not case): the repair is inside the `has_pinata_cid`
    /// skip branch and nowhere else. An object with NO `pinata_cid` takes the upload path,
    /// so it must run NO repair read and its (legacy-shaped) key must be left exactly as
    /// stored, even though the row would be a repair candidate on the skip branch. Moving
    /// the call out of the `Ok(true)` arm reads bytes here and trips the counter.
    #[sqlx::test]
    async fn pinata_upload_path_never_runs_the_legacy_repair(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let fx = seed_cid_repos("pinatanoskip", "pn", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("pinatanoskip")
            .join("pinsrc.git");

        // Legacy-shaped row with NO pinata_cid: `has_pinata_cid` is false, so the skip
        // branch is not taken and the object goes to the upload path.
        let raw_cid = raw_key_for(&bare, &fx.public_oid);
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        seed_pinned_row(
            &pool,
            &fx.public_oid,
            &provider_cid,
            None,
            "repoPinataNoSkip",
        )
        .await;

        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"{"data":{"cid":"QmPinataUploaded"}}"#)
            .expect(1)
            .create_async()
            .await;
        let client = reqwest::Client::new();
        crate::ipfs_pin::reset_legacy_repair_reads();
        let pinned = crate::pinata::pin_new_objects(
            &client,
            &server.url(),
            "test-jwt",
            &bare,
            "git",
            std::time::Duration::from_secs(60),
            vec![fx.public_oid.clone()],
            &state.db,
            "repoPinataNoSkip",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await;

        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "the upload path must never run the skip-branch repair"
        );
        let (stored_cid, stashed) = stored_key_and_stash(&pool, &fx.public_oid).await;
        assert_eq!(
            stored_cid, provider_cid,
            "an object that never reached the skip branch keeps its stored key untouched"
        );
        assert_eq!(stashed, None, "and nothing is stashed for it");
        assert_eq!(
            pinned,
            vec![(fx.public_oid.clone(), "QmPinataUploaded".to_string())],
            "the pinata return still carries the provider CID for the announcement cid_map"
        );
    }

    /// U3 scenario 6 (#173, authorization): the marker arms a FALLBACK, never a bypass.
    /// With the set marked incomplete and the object living only in a repo the caller
    /// may not read, the scan gates every repo through the same per-caller gate, so the
    /// caller is still denied and no bytes leak.
    #[sqlx::test]
    async fn ipfs_cid_marked_incomplete_still_denies_unauthorized_caller(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["u3deny"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("u3deny.git");
        let mut priv_repo = seed_repo(&owner_did, "u3deny");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private");
        let cid = pin_cid_for_repo(&bare, &fx.secret_oid, &state.db, &priv_repo.id).await;

        // The set is marked incomplete, so the fallback scan definitely runs.
        with_pin_sources_broken(&pool, || {
            repin_via_skip_branch(&state, &bare, &fx.secret_oid, &priv_repo.id)
        })
        .await;
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.secret_oid)
                .await
                .unwrap(),
            "the marker is set, so the scan fallback is armed for this object"
        );

        crate::api::ipfs::reset_preload_queries();
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            1,
            "the fallback really did run (otherwise the denial below proves nothing)"
        );
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "the fallback scan gates every repo, so an unauthorized caller is still denied"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "the denial must not leak the withheld object's bytes"
        );
    }

    /// U3 scenario 7 (#173, INV-7 upgrade path): a node already past v21 gets
    /// `pinned_cids.pin_sources_incomplete` from the NEW v22 migration, re-running the
    /// migrations is idempotent, and a row written before the column existed reads as
    /// COMPLETE (so an upgrade cannot arm the O(repos) fallback for every legacy pin).
    #[sqlx::test]
    async fn pinned_cids_sources_incomplete_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        // Pre-v22 shape: drop the column and forget v22 was applied.
        sqlx::query("ALTER TABLE pinned_cids DROP COLUMN IF EXISTS pin_sources_incomplete")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 22")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO pinned_cids (sha256_hex, cid, pinned_at) VALUES ($1, $2, $3)")
            .bind("preu3oid")
            .bind("preu3cid")
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&pool)
            .await
            .unwrap();

        state.db.run_migrations().await.expect("re-migrate");
        state
            .db
            .run_migrations()
            .await
            .expect("migrations are idempotent: a second run succeeds");

        assert!(
            !state.db.pin_sources_incomplete("preu3oid").await.unwrap(),
            "a row predating the column reads COMPLETE, so the upgrade arms no fallback"
        );
        state
            .db
            .mark_pin_sources_incomplete("preu3oid", "somerepo")
            .await
            .expect("mark after upgrade");
        assert!(
            state.db.pin_sources_incomplete("preu3oid").await.unwrap(),
            "the marker store is present and writable after the upgrade"
        );
    }

    /// #173 round 12 (INV-7 upgrade path for v24): a node already carrying v22 markers
    /// keeps them across the move to per-`(oid, repo)` state. Which repo failed was never
    /// recorded, so a carried marker takes the empty sentinel and no real record clears
    /// it, which is strictly safer than the v22 behavior it replaces (there, the next
    /// unrelated record cleared it). Also asserts the re-migration is idempotent and that
    /// an object with no marker still reads complete.
    #[sqlx::test]
    async fn pin_source_failures_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        // Pre-v24 shape: drop the new table, forget v24, and leave a v22-style marker.
        sqlx::query("DROP TABLE IF EXISTS pin_source_failures")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 24")
            .execute(&pool)
            .await
            .unwrap();
        for (oid, marked) in [("carriedoid", true), ("cleanoid", false)] {
            sqlx::query(
                "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, pin_sources_incomplete) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(oid)
            .bind(format!("{oid}cid"))
            .bind(chrono::Utc::now().to_rfc3339())
            .bind(marked)
            .execute(&pool)
            .await
            .unwrap();
        }

        state.db.run_migrations().await.expect("re-migrate");
        state
            .db
            .run_migrations()
            .await
            .expect("migrations are idempotent: a second run succeeds");

        assert!(
            state.db.pin_sources_incomplete("carriedoid").await.unwrap(),
            "a v22 marker survives the upgrade instead of being silently dropped"
        );
        assert!(
            !state.db.pin_sources_incomplete("cleanoid").await.unwrap(),
            "an unmarked row stays complete, so the upgrade arms no new fallback"
        );

        // A real record cannot clear a carried marker: the failing repo is unknown, so
        // the sentinel it carries matches no repo id.
        state
            .db
            .record_pin_source("carriedoid", "anyrepo")
            .await
            .expect("record a source");
        assert!(
            state.db.pin_sources_incomplete("carriedoid").await.unwrap(),
            "a carried marker names no repo, so nothing clears it by accident"
        );
    }

    /// #173 (jatmn round 8, F2 — load-bearing): a legacy `pinned_cids` row keyed on a
    /// PROVIDER CID (Pinata/Kubo dag-pb — every release before this branch stored the
    /// provider CID as the resolver key, not the raw-content CID) must NOT serve raw git
    /// bytes that do not hash to the requested CID. `get_by_cid` recomputes the CID over
    /// the served bytes and refuses to serve on mismatch. Seeded with a RAW SQL INSERT
    /// because the current helpers store the raw CID, so a helper-seeded row is already
    /// correct-shape and the RED assertion would be vacuous (INV-21). RED before U2
    /// (serves the git bytes → 200); GREEN after (not served, no bytes egress).
    #[sqlx::test]
    async fn ipfs_cid_legacy_provider_cid_row_not_served(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["provsrc"]);
        let repo = seed_repo(&owner_did, "provsrc"); // public, no rule
        state.db.create_repo(&repo).await.expect("seed repo");

        // A valid sha2-256 CID whose digest is NOT the object's raw-content digest —
        // stands in for a Pinata/Kubo dag-pb provider CID (the legacy resolver key).
        let provider_cid = gitlawb_core::cid::Cid::from_git_object_bytes(
            b"a decoy object whose CID is not the served object's CID",
        )
        .to_string();

        // Legacy-shape row: cid = the PROVIDER CID (raw SQL — the helpers now store the
        // raw CID and cannot reproduce this shape). The object itself is public+servable.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(&fx.public_oid)
        .bind(&provider_cid)
        .bind("2020-01-01T00:00:00Z")
        .bind(&repo.id)
        .execute(&pool)
        .await
        .unwrap();

        // Requesting the provider CID resolves the row and passes the repo gate, but the
        // served bytes hash to a DIFFERENT CID, so the integrity check must withhold them.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&provider_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_ne!(
            st,
            StatusCode::OK,
            "a provider-CID legacy row must not serve raw git bytes (F2)"
        );
        assert!(
            !body.contains("public bytes"),
            "the mismatched bytes must not egress"
        );
    }

    /// #173 (jatmn round 8, F6 — INV-10 cost guard): the serve path buffers the object via
    /// a blocking `cat-file`; an object larger than `ipfs_max_served_object_bytes` must be
    /// WITHHELD (rejected by the size precheck, never buffered), with zero body bytes
    /// egressed. Under the cap it serves unchanged. The oversize-reject counter guards it
    /// both ways: a removed size precheck serves the object and leaves the counter at 0.
    #[sqlx::test]
    async fn ipfs_cid_f6_oversized_object_withheld(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["big"]);
        let bare = std::path::PathBuf::from("/tmp").join(&slug).join("big.git");
        let repo = seed_repo(&owner_did, "big"); // public, no rule
        state.db.create_repo(&repo).await.expect("seed repo");
        let cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo.id).await;

        // Cap below the object size ("public bytes\n" = 13 bytes) → withheld.
        state.ipfs_max_served_object_bytes = 5;
        crate::api::ipfs::reset_oversize_rejects();
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_ne!(
            st,
            StatusCode::OK,
            "an object over the size cap must not serve (F6)"
        );
        assert!(
            !body.contains("public bytes"),
            "no object bytes egress for an over-cap object"
        );
        assert_eq!(
            crate::api::ipfs::oversize_rejects(),
            1,
            "the oversized object was rejected by the size precheck"
        );

        // Control: raise the cap above the object size → serves unchanged.
        state.ipfs_max_served_object_bytes = crate::api::ipfs::MAX_SERVED_OBJECT_BYTES;
        crate::api::ipfs::reset_oversize_rejects();
        let (st2, body2) =
            cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st2,
            StatusCode::OK,
            "under the cap the object serves normally"
        );
        assert!(
            body2.contains("public bytes"),
            "the served body is the object's bytes"
        );
        assert_eq!(
            crate::api::ipfs::oversize_rejects(),
            0,
            "no oversize reject under the cap"
        );
    }

    /// #173 (provenance, INV-11): a quarantined pinning repo must 404 by CID even for
    /// its own owner — quarantine hard-drops before the visibility gate on the
    /// provenance path too. The owner-signed 404 is the load-bearing negative (a
    /// visibility-only gate would Allow the owner).
    #[sqlx::test]
    async fn ipfs_cid_provenance_quarantined_repo_404_even_owner(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["quarsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("quarsrc.git");
        let repo = seed_repo(&owner_did, "quarsrc"); // public
        state.db.create_repo(&repo).await.expect("seed repo");
        let cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo.id).await;

        // Baseline: before quarantine the provenanced CID serves (proves the path works).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed(&owner, &cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "provenanced CID serves before quarantine"
        );

        state
            .db
            .set_repo_quarantine(&repo.id, true)
            .await
            .expect("quarantine");

        for req in [cid_anon(&cid), cid_signed(&owner, &cid)] {
            let (st, body) = cid_parts(cid_router(&state).oneshot(req).await.unwrap()).await;
            assert_eq!(
                st,
                StatusCode::NOT_FOUND,
                "a quarantined pinning repo must 404 by CID (anon + owner)"
            );
            assert!(
                !body.contains("public bytes"),
                "the 404 body must not leak quarantined content"
            );
        }
    }

    /// #173 (provenance, bounded — must NOT fall back to the scan): a CID whose
    /// provenance points at a repo that no longer exists must 404 rather than scan
    /// every repo and serve a byte-identical public copy. Falling back to the scan
    /// would reopen the O(repos) anonymous fan-out the provenance rework closes. RED
    /// before the rework (the scan serves the public copy → 200); GREEN after.
    #[sqlx::test]
    async fn ipfs_cid_provenance_missing_repo_404_no_scan_fallback(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["gonesrc", "pubcopy2"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("gonesrc.git");

        // Pin with provenance = a repo_id that is never created (deleted/absent).
        let cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, "nonexistent-repo-id").await;

        // A public repo holds the SAME object (the old scan would serve it).
        let pub_repo = seed_repo(&owner_did, "pubcopy2");
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public copy");

        let (st, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "a provenance pointing at a missing repo must 404, not fall back to the scan"
        );
    }

    /// #173 (provenance, path-scoped WALK gate): the #135/#173 per-object gates must
    /// run on the NEW provenance path, not only the legacy scan. A provenanced pin from
    /// a repo under a `/secret/**` rule runs `allowed_blob_set_for_caller` via the shared
    /// gate: a withheld secret blob 404s to anon (no byte leak); the allowed reader gets
    /// it. Exercises the walk gate on the provenance path in BOTH directions.
    #[sqlx::test]
    async fn ipfs_cid_provenance_path_scoped_walk_gates_withheld_blob(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let reader = Keypair::generate();
        let reader_did = reader.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["provwalk"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("provwalk.git");
        let repo = seed_repo(&owner_did, "provwalk"); // public at "/"
        state.db.create_repo(&repo).await.expect("seed repo");
        // /secret/** Mode B with the reader allowed → the secret blob walk gates by caller.
        state
            .db
            .set_visibility_rule(
                &repo.id,
                "/secret/**",
                VisibilityMode::B,
                std::slice::from_ref(&reader_did),
                &owner_did,
            )
            .await
            .expect("path rule");
        let cid = pin_cid_for_repo(&bare, &fx.secret_oid, &state.db, &repo.id).await;

        // Anon: the walk denies the secret blob → 404, no leak.
        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "a withheld secret blob 404s to anon on the provenance path (walk gate runs)"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "the 404 body must not leak the withheld blob"
        );

        // Allowed reader: the walk includes the secret blob → 200 with content.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed(&reader, &cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "an allowed reader gets the secret blob via the provenance walk gate"
        );
        assert!(
            body.contains("TOP SECRET"),
            "the allowed reader receives the content"
        );
    }

    /// #173: the pinata pin path stores the locally-computed raw CID in the
    /// resolver-key `cid` column and the provider CID in `pinata_cid`, and its ON
    /// CONFLICT COALESCE fills a NULL provenance without overwriting an existing one
    /// (first-pinner-owns). On conflict `cid` is left untouched so a prior local pin's
    /// raw CID is never clobbered by a provider CID.
    #[sqlx::test]
    async fn record_pinata_cid_stores_and_coalesces_provenance(pool: PgPool) {
        let state = test_state(pool).await;

        // Real raw-CIDv1 resolver keys, as the pin paths write them: `list_pinned_cids`
        // withholds any row keyed on a non-raw (legacy provider) value (U4, #173), so a
        // placeholder string here would be filtered out and make the assertions vacuous.
        let raw1 = gitlawb_core::cid::Cid::from_git_object_bytes(b"pinata raw 1").to_string();
        let local2 = gitlawb_core::cid::Cid::from_git_object_bytes(b"local raw 2").to_string();

        // A new row created via the pinata path carries provenance, and stores the
        // raw CID in `cid` with the provider CID in `pinata_cid`.
        state
            .db
            .record_pinata_cid("po1", &raw1, "pcid1", Some("repoA"))
            .await
            .unwrap();
        assert_eq!(
            state.db.provenance_for_oid("po1").await.unwrap().as_deref(),
            Some("repoA")
        );
        let po1 = state
            .db
            .list_pinned_cids()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.sha256_hex == "po1")
            .expect("po1 row exists");
        assert_eq!(po1.cid, raw1, "resolver-key cid is the raw CID");
        assert_eq!(
            po1.pinata_cid.as_deref(),
            Some("pcid1"),
            "the provider CID is kept in pinata_cid"
        );

        // An existing NULL-provenance row: the pinata COALESCE fills it, and the
        // prior local pin's `cid` is left untouched (not overwritten by the raw arg).
        state
            .db
            .record_pinned_cid("po2", &local2, None)
            .await
            .unwrap();
        state
            .db
            .record_pinata_cid("po2", "rawcid2", "pcid2", Some("repoB"))
            .await
            .unwrap();
        assert_eq!(
            state.db.provenance_for_oid("po2").await.unwrap().as_deref(),
            Some("repoB"),
            "pinata fills a NULL provenance"
        );
        let po2 = state
            .db
            .list_pinned_cids()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.sha256_hex == "po2")
            .expect("po2 row exists");
        assert_eq!(
            po2.cid, local2,
            "on conflict the prior local pin's cid is left untouched"
        );

        // An existing provenance: the pinata COALESCE must NOT overwrite it.
        state
            .db
            .record_pinned_cid("po3", "cid3", Some("repoX"))
            .await
            .unwrap();
        state
            .db
            .record_pinata_cid("po3", "rawcid3", "pcid3", Some("repoY"))
            .await
            .unwrap();
        assert_eq!(
            state.db.provenance_for_oid("po3").await.unwrap().as_deref(),
            Some("repoX"),
            "pinata COALESCE keeps the first-pinner's provenance"
        );
    }

    /// #173 (jatmn, F4, load-bearing security): a Pinata-first pin (no prior local pin)
    /// must make the resolver key (`pinned_cids.cid`) the locally-computed raw CID, NOT
    /// the provider CID. Pinata wraps the bytes in dag-pb/UnixFS, so its returned CID
    /// does not hash the raw content; if it became the resolver key, `/ipfs/{provider_cid}`
    /// would serve raw git bytes that do not hash to it, breaking raw content-addressing.
    /// Assert `oids_for_cid(raw_cid)` finds the sha AND `oids_for_cid(provider_cid)` does NOT.
    #[sqlx::test]
    async fn record_pinata_cid_resolver_key_is_raw_not_provider(pool: PgPool) {
        let state = test_state(pool).await;

        let bytes = b"raw git object content for pinata-first pin";
        let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(bytes).to_string();
        // A distinct provider CID (a dag-pb wrapper CID Pinata would return).
        let provider_cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG";
        assert_ne!(
            raw_cid, provider_cid,
            "the provider CID must differ from the raw CID for this test to be meaningful"
        );

        // Pinata-first: no prior local pin, so this INSERT creates the row.
        state
            .db
            .record_pinata_cid("pfsha", &raw_cid, provider_cid, Some("repoP"))
            .await
            .unwrap();

        // The raw CID resolves to the sha.
        assert_eq!(
            state.db.oids_for_cid(&raw_cid).await.unwrap(),
            vec!["pfsha".to_string()],
            "the locally-computed raw CID is the resolver key"
        );
        // The provider (dag-pb) CID must NOT resolve raw bytes.
        assert!(
            state
                .db
                .oids_for_cid(provider_cid)
                .await
                .unwrap()
                .is_empty(),
            "the provider dag-pb CID must never resolve raw git bytes"
        );
    }

    /// #173 (end-to-end pin wiring): `pin_new_objects` records the repo_id it is given
    /// as the pin's provenance. Drives the real pin path against a mocked IPFS `/add`
    /// endpoint (so `pin_git_object` succeeds) and asserts `provenance_for_oid` returns
    /// the repo — closing the gap between the push handler's threading and the DB write.
    #[sqlx::test]
    async fn pin_new_objects_records_provenance(pool: PgPool) {
        let state = test_state(pool).await;

        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"bafyprovtest"}"#)
            .expect_at_least(1)
            .create_async()
            .await;

        let fx = seed_cid_repos("provpin_e2e", "ppe2e", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("provpin_e2e")
            .join("pinsrc.git");

        let pinned = crate::ipfs_pin::pin_new_objects(
            &server.url(),
            &bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![fx.public_oid.clone()],
            &state.db,
            "repoZ",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        assert!(
            !pinned.is_empty(),
            "the object was pinned via the real pin path"
        );
        m.assert_async().await;
        assert_eq!(
            state
                .db
                .provenance_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .as_deref(),
            Some("repoZ"),
            "pin_new_objects records the repo_id it was given as the pin's provenance"
        );
    }

    /// U4 (#173, finding 5): a pin whose DB record exhausts its retries must NOT appear
    /// in the returned vector. Kubo really is holding the bytes (the `/add` mock is hit),
    /// but with no `pinned_cids` row the resolver cannot serve that CID, so reporting it
    /// as pinned overclaims. The Kubo return is log-only (`api/repos.rs` counts the pairs
    /// and logs each one), which is what makes omitting the row safe here; the pinata
    /// twin's return feeds the announcement `cid_map` and keeps its own contract.
    ///
    /// Two objects, because `with_pin_sources_broken` hides the table process-wide and
    /// the harness cannot express per-object DB breakage. Both records fail, and the
    /// `/add` mock being hit exactly twice is the batch-survival proof: the first
    /// failure warns and continues instead of breaking out of the loop. The healthy
    /// direction (a successful record IS returned) is already covered by
    /// `pin_new_objects_records_provenance` directly above, so the two together cover
    /// both sides without new harness machinery.
    #[sqlx::test]
    async fn pin_new_objects_omits_objects_whose_db_record_failed(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"bafyproviderhash"}"#)
            .expect(2)
            .create_async()
            .await;

        let fx = seed_cid_repos("provpin_u4", "ppu4", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("provpin_u4")
            .join("pinsrc.git");

        let pinned = with_pin_sources_broken(&pool, || async {
            crate::ipfs_pin::pin_new_objects(
                &server.url(),
                &bare,
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                vec![fx.public_oid.clone(), fx.secret_oid.clone()],
                &state.db,
                "repoU4",
                // Far above the ~150ms per object the retry ladder spends
                // (PIN_RECORD_ATTEMPTS x PIN_RECORD_BACKOFF), so the batch budget gate
                // is never what truncates this run.
                std::time::Duration::from_secs(60),
            )
            .await
        })
        .await;

        assert!(
            pinned.is_empty(),
            "a pin with no durable index row must not be reported as pinned, got {pinned:?}"
        );
        // Exactly two adds: the first record failure did not break the batch.
        m.assert_async().await;
        for oid in [&fx.public_oid, &fx.secret_oid] {
            assert_eq!(
                state.db.provenance_for_oid(oid).await.unwrap(),
                None,
                "the record really did fail, so there is no row to report"
            );
        }
    }

    /// #173 (grok F2): the post-push pin read is BOUNDED, so a wedged/D-state
    /// `git cat-file` (stuck NFS/Tigris backend) is reaped at `git_timeout` and
    /// `pin_new_objects` RETURNS — reaching `requeue_or_release` in production —
    /// instead of hanging forever and pinning the per-repo coalescing key until
    /// process death. A fake `git` whose `cat-file` records its pid then sleeps far
    /// past a SHORT 1s timeout stands in for the wedged backend; the `run_bounded_git`
    /// watchdog (SIGTERM -> grace -> SIGKILL of the process group) must reap it well
    /// before its 8s natural exit, and the call must return with nothing pinned.
    ///
    /// REVERT PROOF (RED): swap `read_object_bounded` back to the bare
    /// `store::read_object` at the pin read and the wedged child is STILL RUNNING at
    /// the mid-flight liveness poll below (unbounded `Command::output` cannot be
    /// reaped at the deadline) — the reap assertion fails.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_reaps_wedged_read_at_deadline(pool: PgPool) {
        use std::time::Duration;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        // Fake `git`: `cat-file` records its own pid then sleeps 8s (>> the 1s
        // deadline) so the read is genuinely wedged; the watchdog is what must end it.
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("catfile.pid");
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               cat-file) echo $$ > \"{}\"; sleep 8 ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            pidfile.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }
        let repo = tmp.path().to_path_buf();
        let git = git_path.to_str().unwrap().to_string();
        // A never-pinned OID so the call reaches the object-read stage (not the
        // already-pinned skip path).
        let oid = "f".repeat(64);
        // Non-empty ipfs_api so `pin_new_objects` does not early-return; the wedged
        // read is reaped and the OID skipped before any `/add`, so this URL is unused.
        let ipfs_api = "http://127.0.0.1:1".to_string();

        // `pin_new_objects` must run on THIS runtime so its `is_pinned` DB call keeps
        // the sqlx pool on its home runtime. The bounded read is a synchronous blocking
        // call, so the reap poll runs on a separate OS thread (independent of tokio): it
        // captures the wedged child's pid, waits past the deadline, records whether it
        // was reaped, then SIGKILLs defensively so even a true infinite hang cannot leak
        // an orphan or stall the awaited call.
        let pidfile_poll = pidfile.clone();
        let poll = std::thread::spawn(move || -> (Option<i32>, bool) {
            let alive = |pid: i32| unsafe { libc::kill(pid, 0) == 0 };
            let mut pid = None;
            for _ in 0..500 {
                if let Some(p) = std::fs::read_to_string(&pidfile_poll)
                    .ok()
                    .and_then(|s| s.trim().parse::<i32>().ok())
                {
                    pid = Some(p);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let pid = match pid {
                Some(p) => p,
                None => return (None, false),
            };
            // Past the 1s deadline + SIGTERM grace but well before the 8s natural exit:
            // the bounded read must already have reaped the wedged group. The unbounded
            // `store::read_object` leaves it running here — the load-bearing RED.
            std::thread::sleep(Duration::from_secs(3));
            let reaped = !alive(pid);
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            (Some(pid), reaped)
        });

        // The call must RETURN — reaching `requeue_or_release` in production — rather
        // than hang on the 8s sleep. The poll thread's defensive SIGKILL guarantees the
        // read completes even in the unbounded RED case, so this observes a bounded
        // return either way; the reap assertion below is what separates RED from GREEN.
        let pinned = tokio::time::timeout(
            Duration::from_secs(6),
            crate::ipfs_pin::pin_new_objects(
                &ipfs_api,
                &repo,
                &git,
                Duration::from_secs(1),
                vec![oid],
                &db,
                "repoWedge",
                crate::ipfs_pin::PIN_BATCH_BUDGET,
            ),
        )
        .await
        .expect("pin_new_objects must return within the bound, not hang on the wedged read");

        let (pid, reaped) = poll.join().expect("poll thread joins");
        pid.expect("the fake cat-file must have spawned and recorded its pid");
        assert!(
            reaped,
            "the post-push pin read must reap the wedged cat-file child at the deadline, \
             not leave it running (which would pin the coalescing key until process death)"
        );
        assert!(
            pinned.is_empty(),
            "a wedged read pins nothing this pass; a later pass/push retries"
        );
    }

    /// #173 (jatmn, F2): a legacy pin with NULL provenance backfills its source
    /// via `backfill_pin_provenance`, and the `AND repo_id IS NULL` guard preserves
    /// first-pinner-owns (a non-NULL provenance is left untouched).
    #[sqlx::test]
    async fn backfill_pin_provenance_fills_null_keeps_existing(pool: PgPool) {
        let state = test_state(pool).await;

        // A legacy pin: no provenance recorded.
        state
            .db
            .record_pinned_cid("legacy_oid", "legacy_cid", None)
            .await
            .unwrap();
        assert_eq!(
            state.db.provenance_for_oid("legacy_oid").await.unwrap(),
            None,
            "a legacy pin starts with NULL provenance"
        );

        // Backfill sets the NULL provenance.
        state
            .db
            .backfill_pin_provenance("legacy_oid", "repo-src")
            .await
            .unwrap();
        assert_eq!(
            state
                .db
                .provenance_for_oid("legacy_oid")
                .await
                .unwrap()
                .as_deref(),
            Some("repo-src"),
            "backfill fills a NULL provenance from the known source"
        );

        // A pin that already has provenance: backfill must NOT overwrite it.
        state
            .db
            .record_pinned_cid("owned_oid", "owned_cid", Some("repo-first"))
            .await
            .unwrap();
        state
            .db
            .backfill_pin_provenance("owned_oid", "repo-second")
            .await
            .unwrap();
        assert_eq!(
            state
                .db
                .provenance_for_oid("owned_oid")
                .await
                .unwrap()
                .as_deref(),
            Some("repo-first"),
            "the AND repo_id IS NULL guard keeps the first-pinner's provenance"
        );
    }

    /// #173 (jatmn, F2, load-bearing): an object already pinned with NULL provenance
    /// (a pre-provenance legacy pin) acquires its source when `pin_new_objects` sees
    /// it again. The already-pinned skip path must backfill rather than leave the
    /// object stuck on the O(repos) scan fallback — and it must NOT re-pin the bytes
    /// (no IPFS `/add` call, the object is already on IPFS).
    #[sqlx::test]
    async fn pin_new_objects_backfills_legacy_null_provenance(pool: PgPool) {
        let state = test_state(pool).await;

        let fx = seed_cid_repos("provpin_backfill", "ppbf", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("provpin_backfill")
            .join("pinsrc.git");
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(
            &crate::git::store::read_object(&bare, &fx.public_oid)
                .expect("read object bytes")
                .expect("object exists")
                .1,
        )
        .to_string();

        // Legacy pin: the object is already recorded with NULL provenance.
        state
            .db
            .record_pinned_cid(&fx.public_oid, &cid, None)
            .await
            .unwrap();
        assert_eq!(
            state.db.provenance_for_oid(&fx.public_oid).await.unwrap(),
            None,
            "the object starts as a legacy pin with NULL provenance"
        );

        // Mock IPFS `/add` and require it is NOT called: the already-pinned object
        // must be backfilled, never re-pinned.
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"bafyshouldnothappen"}"#)
            .expect(0)
            .create_async()
            .await;

        let pinned = crate::ipfs_pin::pin_new_objects(
            &server.url(),
            &bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![fx.public_oid.clone()],
            &state.db,
            "repoBF",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;

        assert!(
            pinned.is_empty(),
            "an already-pinned object is not re-pinned (no bytes returned)"
        );
        m.assert_async().await; // asserts /add was called 0 times
        assert_eq!(
            state
                .db
                .provenance_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .as_deref(),
            Some("repoBF"),
            "pin_new_objects backfills the legacy pin's NULL provenance"
        );
    }

    /// Build a legacy provider CID (CIDv1 dag-pb — the Kubo above-block-size root
    /// shape, and codec-equivalent to the Pinata CIDv0 legacy key for the cost
    /// gate) over the object's own multihash. Non-raw codec, so `is_raw_cidv1`
    /// flags it a repair candidate, and a different string from the raw key, so a
    /// repair rewrites it. The existing `ipfs_cid_legacy_provider_cid_row_not_served`
    /// fixture seeds a raw-codec decoy (an integrity negative the cost gate treats
    /// as non-legacy on purpose); this produces the genuine dag-pb legacy shape the
    /// repair path targets. Uses only the `cid` crate (already a node dep).
    fn legacy_dagpb_cid(raw_cid: &str) -> String {
        const DAG_PB: u64 = 0x70;
        let parsed = raw_cid
            .parse::<cid::CidGeneric<64>>()
            .expect("the raw CID parses");
        cid::CidGeneric::<64>::new_v1(DAG_PB, *parsed.hash()).to_string()
    }

    /// #173 R8 (jatmn round 10, U7 — load-bearing): a legacy row keyed on a PROVIDER
    /// CID (Kubo dag-pb / Pinata) is opportunistically rewritten to the raw-content
    /// key on a re-push whose pack carries the object, stashing the old value in
    /// `legacy_provider_cid`. The advertised key 404s while the row is legacy (the
    /// resolver recomputes the raw CID and the stored key does not match) and serves
    /// after repair. RED before the skip-branch repair lands (the raw key 404s post
    /// pin). Also asserts the repair leaves `pinata_cid` NULL (scenario 3) and that
    /// the retired provider CID still refuses to serve (scenario 6, integrity).
    #[sqlx::test]
    async fn ipfs_cid_legacy_provider_cid_repaired_on_repush(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["provsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("provsrc.git");
        let repo = seed_repo(&owner_did, "provsrc"); // public, no rule
        state.db.create_repo(&repo).await.expect("seed repo");

        // The canonical raw key the resolver accepts once the row is repaired.
        let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(
            &crate::git::store::read_object(&bare, &fx.public_oid)
                .unwrap()
                .unwrap()
                .1,
        )
        .to_string();
        // The key stored today: a genuine legacy dag-pb provider CID.
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        assert_ne!(
            provider_cid, raw_cid,
            "the provider CID differs from the raw resolver key"
        );

        // Legacy-shape row: cid = the PROVIDER CID (raw SQL — the helpers store the
        // raw CID). The object itself is public and servable.
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(&fx.public_oid)
        .bind(&provider_cid)
        .bind("2020-01-01T00:00:00Z")
        .bind(&repo.id)
        .execute(&pool)
        .await
        .unwrap();

        // RED baseline: the raw key a correct client sends 404s while the row is legacy.
        let (st_before, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_ne!(
            st_before,
            StatusCode::OK,
            "the raw key 404s while the row is keyed on the provider CID"
        );

        // Re-push carries the object again: `pin_new_objects` hits the already-pinned
        // skip branch and repairs the row. The `/add` mock must NOT fire — the object
        // is already on IPFS, never re-pinned.
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"bafyshouldnothappen"}"#)
            .expect(0)
            .create_async()
            .await;
        crate::ipfs_pin::pin_new_objects(
            &server.url(),
            &bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![fx.public_oid.clone()],
            &state.db,
            &repo.id,
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await;

        // GREEN: the key is repaired to the raw CID and the old value is stashed.
        let (stored_cid, stashed): (String, Option<String>) = sqlx::query_as(
            "SELECT cid, legacy_provider_cid FROM pinned_cids WHERE sha256_hex = $1",
        )
        .bind(&fx.public_oid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            stored_cid, raw_cid,
            "the key is repaired to the raw-content CID"
        );
        assert_eq!(
            stashed.as_deref(),
            Some(provider_cid.as_str()),
            "the old provider CID is stashed in legacy_provider_cid"
        );

        // The advertised (raw) key now serves 200.
        let (st_after, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st_after,
            StatusCode::OK,
            "the repaired raw key serves after the re-push"
        );
        assert!(body.contains("public bytes"), "the object's bytes serve");

        // Scenario 3: repair never wrote `pinata_cid`, so the Pinata pin-skip gate
        // (`has_pinata_cid`) is untouched and Pinata still pins the object.
        assert!(
            !state.db.has_pinata_cid(&fx.public_oid).await.unwrap(),
            "repair leaves pinata_cid NULL"
        );

        // Scenario 6 (integrity negative): the retired provider CID still 404s — no
        // serve-path alias for a CID the bytes do not hash to.
        let (st_old, body_old) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&provider_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_ne!(
            st_old,
            StatusCode::OK,
            "the retired provider CID must not serve after repair"
        );
        assert!(
            !body_old.contains("public bytes"),
            "no bytes egress under the retired provider CID"
        );
    }

    /// #173 R8 (U7 cost gate): a well-formed CIDv1/raw already-pinned row triggers NO
    /// object read on the skip path — the codec check decides candidacy from the
    /// stored string alone, so a non-legacy row keeps the DB-only skip cost. Also
    /// covers the small-object equivalence: a small legacy object Kubo pins under the
    /// raw key (raw-leaves) is already CIDv1/raw and needs no repair. The read counter
    /// is the both-ways guard: removing the codec gate reads the raw row and trips it.
    #[sqlx::test]
    async fn ipfs_cid_repair_codec_gate_skips_raw_row(pool: PgPool) {
        let state = test_state(pool).await;
        let fx = seed_cid_repos("codecgate", "cg", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("codecgate")
            .join("pinsrc.git");

        // A correct raw-CID row (steady state), recorded via the production helper.
        let raw_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;
        assert!(
            gitlawb_core::cid::is_raw_cidv1(&raw_cid),
            "the helper records a CIDv1/raw key"
        );

        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"x"}"#)
            .expect(0)
            .create_async()
            .await;

        crate::ipfs_pin::reset_legacy_repair_reads();
        crate::ipfs_pin::pin_new_objects(
            &server.url(),
            &bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![fx.public_oid.clone()],
            &state.db,
            "repoCG",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;
        m.assert_async().await;

        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "a CIDv1/raw row triggers no object read on the skip path (cost gate)"
        );
        assert_eq!(
            state
                .db
                .cid_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .as_deref(),
            Some(raw_cid.as_str()),
            "the raw row is left as-is"
        );
    }

    /// #173 R8 (U7): a legacy row whose object bytes are gone stays withheld — the
    /// repair never destructively rewrites it, so the row is preserved for a future
    /// re-push or the deferred one-shot sweep.
    #[sqlx::test]
    async fn ipfs_cid_repair_unrepairable_row_stays_withheld(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        let _fx = seed_cid_repos("unrep", "ur", &["pinsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join("unrep")
            .join("pinsrc.git");

        // A legacy dag-pb row for an oid whose bytes are NOT in this bare repo.
        let phantom_oid = "b".repeat(64);
        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"bytes that live nowhere").to_string();
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        sqlx::query("INSERT INTO pinned_cids (sha256_hex, cid, pinned_at) VALUES ($1, $2, $3)")
            .bind(&phantom_oid)
            .bind(&provider_cid)
            .bind("2020-01-01T00:00:00Z")
            .execute(&pool)
            .await
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
            .with_status(200)
            .with_body(r#"{"Hash":"x"}"#)
            .expect(0)
            .create_async()
            .await;

        // Skip-branch runs (is_pinned true) but read_object returns None (bytes gone),
        // so the repair returns without touching the row.
        crate::ipfs_pin::pin_new_objects(
            &server.url(),
            &bare,
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            vec![phantom_oid.clone()],
            &state.db,
            "repoUR",
            crate::ipfs_pin::PIN_BATCH_BUDGET,
        )
        .await;

        let (stored, stashed): (String, Option<String>) = sqlx::query_as(
            "SELECT cid, legacy_provider_cid FROM pinned_cids WHERE sha256_hex = $1",
        )
        .bind(&phantom_oid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            stored, provider_cid,
            "an unrepairable row keeps its provider CID (no destructive rewrite)"
        );
        assert_eq!(
            stashed, None,
            "no legacy_provider_cid is stashed when the bytes are gone"
        );
    }

    /// #173 R8 (U7, INV-7 upgrade path): a node already at the prior-max schema (v13)
    /// gets `pinned_cids.legacy_provider_cid` from the NEW v21 migration. Simulate the
    /// pre-v21 node by dropping the column and un-applying v14, then re-migrate and
    /// assert a repair round-trips through the column. RED before the v21 migration
    /// exists (the column is never re-added → the repair UPDATE errors).
    #[sqlx::test]
    async fn pinned_cids_legacy_provider_cid_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        // Pre-v21 shape: drop the column and forget v21 was applied.
        sqlx::query("ALTER TABLE pinned_cids DROP COLUMN IF EXISTS legacy_provider_cid")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 21")
            .execute(&pool)
            .await
            .unwrap();

        // Upgrade: re-run migrations → v21 re-adds the column.
        state.db.run_migrations().await.expect("migrate to v14");

        // A repair round-trips through the v21 column.
        state
            .db
            .record_pinned_cid("upg_oid", "QmProviderLegacy", None)
            .await
            .unwrap();
        state
            .db
            .repair_legacy_provider_cid("upg_oid", "bRawContentKey", "QmProviderLegacy")
            .await
            .unwrap();
        let (cid, stashed): (String, Option<String>) = sqlx::query_as(
            "SELECT cid, legacy_provider_cid FROM pinned_cids WHERE sha256_hex = 'upg_oid'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(cid, "bRawContentKey", "v21 lets the repair rewrite the key");
        assert_eq!(
            stashed.as_deref(),
            Some("QmProviderLegacy"),
            "the v21 legacy_provider_cid column is present after upgrade"
        );
    }

    // ---- #173 U4: legacy provider-CID migration sweep ----

    /// Seed a legacy PROVIDER-CID `pinned_cids` row for `oid` (the pre-branch shape:
    /// `cid` holds the Kubo dag-pb / Pinata key, not the raw-content resolver key).
    /// Returns `(raw_cid, provider_cid)`. Raw SQL because every production helper
    /// stores the already-correct raw key.
    async fn seed_legacy_pin(
        pool: &PgPool,
        bare: &std::path::Path,
        oid: &str,
        repo_id: Option<&str>,
    ) -> (String, String) {
        let (_ty, bytes) = crate::git::store::read_object(bare, oid)
            .expect("read object bytes")
            .expect("object exists in the bare repo");
        let raw = gitlawb_core::cid::Cid::from_git_object_bytes(&bytes).to_string();
        let provider = legacy_dagpb_cid(&raw);
        assert_ne!(provider, raw, "the legacy key differs from the raw key");
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(oid)
        .bind(&provider)
        .bind("2020-01-01T00:00:00Z")
        .bind(repo_id)
        .execute(pool)
        .await
        .unwrap();
        (raw, provider)
    }

    /// The `pinned_cids.cid` currently stored for an oid, unfiltered (unlike
    /// `list_pinned_cids`, which withholds unrepaired legacy rows).
    async fn stored_pin(pool: &PgPool, oid: &str) -> (String, Option<String>) {
        sqlx::query_as("SELECT cid, legacy_provider_cid FROM pinned_cids WHERE sha256_hex = $1")
            .bind(oid)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// U4 (#173, INV-7 upgrade path): a node already at the prior-max schema (v15) gets
    /// the `pin_repair_sweep` cursor table from the NEW v23 migration. Simulate the
    /// pre-v23 node by dropping the table and un-applying v16, then re-migrate and
    /// assert the cursor round-trips. RED before the v23 migration exists (the table is
    /// never recreated, so the cursor read errors).
    #[sqlx::test]
    async fn pin_repair_sweep_cursor_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        // Pre-v23 shape: drop the table and forget v23 was applied.
        sqlx::query("DROP TABLE IF EXISTS pin_repair_sweep")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 23")
            .execute(&pool)
            .await
            .unwrap();

        state.db.run_migrations().await.expect("migrate to v16");

        // Absent row reads as the "never swept" start, and a write round-trips.
        assert_eq!(
            state.db.pin_repair_cursor().await.unwrap(),
            "",
            "a node that has never swept starts at the beginning of the table"
        );
        state.db.set_pin_repair_cursor("abc").await.unwrap();
        state.db.set_pin_repair_cursor("def").await.unwrap();
        assert_eq!(
            state.db.pin_repair_cursor().await.unwrap(),
            "def",
            "the v23 cursor table persists the walk position across writes"
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM pin_repair_sweep")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "the cursor is a single row, not an append log");
    }

    /// U4 scenario 1 (#173): a legacy provider-CID row with intact object bytes is
    /// repaired to the raw-content resolver key by the SWEEP alone, with the old value
    /// stashed in `legacy_provider_cid`. No push, no re-pin: this is the whole point of
    /// U4, because normal git negotiation omits objects the node already has, so the
    /// skip-branch repair's re-push trigger generally never fires on an upgraded node.
    /// RED before the sweep is implemented (the row keeps its provider key).
    #[sqlx::test]
    async fn sweep_repairs_legacy_row_without_a_push(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["swsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("swsrc.git");
        let repo = seed_repo(&owner_did, "swsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        let (raw_cid, provider_cid) =
            seed_legacy_pin(&pool, &bare, &fx.public_oid, Some(&repo.id)).await;

        let stats = crate::ipfs_pin::sweep_legacy_provider_cids(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            16,
            std::time::Duration::ZERO,
            &state.db,
            &mut Default::default(),
        )
        .await;
        assert_eq!(stats.repaired, 1, "the sweep repairs the one legacy row");

        let (stored, stashed) = stored_pin(&pool, &fx.public_oid).await;
        assert_eq!(
            stored, raw_cid,
            "the key is rewritten to the raw-content CID"
        );
        assert_eq!(
            stashed.as_deref(),
            Some(provider_cid.as_str()),
            "the old provider CID is stashed in legacy_provider_cid"
        );

        // End to end: the repaired key is now advertised AND serves.
        assert!(
            state
                .db
                .list_pinned_cids()
                .await
                .unwrap()
                .iter()
                .any(|r| r.cid == raw_cid),
            "the repaired row is advertised"
        );
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "the repaired raw key serves");
        assert!(body.contains("public bytes"), "the object's bytes serve");
    }

    /// One transient database fault must not permanently disable the sweep.
    ///
    /// The wrapper was made periodic so coverage is wall-clock rather than a reboot
    /// count. Returning for good on the first failed pass query undoes exactly that: a
    /// single deadlock or connection reset disables legacy-CID repair for the whole
    /// process lifetime, `main` never joins the handle, so nothing observes it past one
    /// warn, and the node keeps withholding every unrepaired row until someone reboots
    /// it.
    ///
    /// The fixture renames `pinned_cids` out of the way so every pass query fails, waits
    /// for the loop to have gone round more than once (which a terminal return cannot
    /// do), then renames the table back and asserts the still-running loop picks the
    /// repair up.
    ///
    /// MUTATION (RED): restore the terminal `return` on `PassFailed` and the loop exits
    /// on the first failure, so the row is never repaired.
    #[sqlx::test]
    async fn sweep_rearms_after_a_failed_pass(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let _serialized = crate::ipfs_pin::sweep_run_lock().lock().await;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["rearmsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("rearmsrc.git");
        let repo = seed_repo(&owner_did, "rearmsrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        let (raw_cid, _provider) =
            seed_legacy_pin(&pool, &bare, &fx.public_oid, Some(&repo.id)).await;

        // Every pass query now fails, exactly as a broken database makes them fail.
        sqlx::query("ALTER TABLE pinned_cids RENAME TO pinned_cids_hidden")
            .execute(&pool)
            .await
            .unwrap();

        crate::ipfs_pin::reset_sweep_runs();
        let db = state.db.clone();
        let git_bin = state.git_bin.clone();
        // Short rather than literally zero: the loop is spinning against a real
        // Postgres, and the property under test is that it goes round again at all. The
        // failure and idle intervals are multiples of this base, so they shrink with it.
        let handle = tokio::spawn(async move {
            crate::ipfs_pin::run_sweep_rearmed(
                std::path::Path::new("/tmp"),
                &git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                std::time::Duration::from_millis(10),
                &db,
            )
            .await
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while crate::ipfs_pin::sweep_runs() < 2 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            crate::ipfs_pin::sweep_runs() >= 2,
            "a failed pass must re-arm: the sweep completed {} run(s) and stopped, which \
             is one transient database fault disabling legacy-CID repair for the life of \
             the process",
            crate::ipfs_pin::sweep_runs()
        );
        assert!(
            !handle.is_finished(),
            "the re-arm loop must never return; shutdown preempts it from the outside"
        );

        // The database comes back. The loop is still there to notice.
        sqlx::query("ALTER TABLE pinned_cids_hidden RENAME TO pinned_cids")
            .execute(&pool)
            .await
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut repaired = false;
        while std::time::Instant::now() < deadline {
            if stored_pin(&pool, &fx.public_oid).await.0 == raw_cid {
                repaired = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        handle.abort();
        assert!(
            repaired,
            "once the database recovers the still-running sweep must repair the row; a \
             wrapper that returned on the first failure never gets here"
        );
    }

    /// A run that repairs nothing backs off; a run that repairs keeps the base interval.
    ///
    /// The base interval is priced against a settled table. It is not priced against the
    /// table that never settles: source-less rows whose bytes are permanently gone cost
    /// up to `MAX_DEAD_ROW_READS_PER_RUN` object reads per run and repair nothing, every
    /// base interval, forever. Backing off on a fruitless run is what stops paying that;
    /// resetting on a productive one is what keeps a table that is still yielding
    /// repairs being walked often.
    ///
    /// Both directions, on the wall clock, off the run counter the wrapper exposes:
    /// leg 1 is an empty table, where a run repairs nothing and the next run must NOT
    /// arrive within a window several base intervals wide; leg 2 seeds a repairable row,
    /// so the first run repairs and the second must arrive one BASE interval later.
    ///
    /// MUTATION (RED): drop the idle branch and leg 1 completes many runs in its window.
    #[sqlx::test]
    async fn sweep_backs_off_after_a_run_that_repairs_nothing(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let _serialized = crate::ipfs_pin::sweep_run_lock().lock().await;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        // Scaled down from production by a constant factor: the idle interval is a
        // multiple of this base, so the ratio under test is the production ratio.
        let base = std::time::Duration::from_millis(200);
        let window = std::time::Duration::from_millis(800);

        let spawn_loop = |db: std::sync::Arc<crate::db::Db>, git_bin: String| {
            tokio::spawn(async move {
                crate::ipfs_pin::run_sweep_rearmed(
                    std::path::Path::new("/tmp"),
                    &git_bin,
                    git_timeout,
                    16,
                    std::time::Duration::ZERO,
                    base,
                    &db,
                )
                .await
            })
        };
        let await_first_run = || async {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while crate::ipfs_pin::sweep_runs() < 1 && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(
                crate::ipfs_pin::sweep_runs() >= 1,
                "fixture precondition: the sweep completes a first run"
            );
        };

        // Leg 1: nothing to repair. The next run must not arrive inside a window four
        // base intervals wide.
        crate::ipfs_pin::reset_sweep_runs();
        let idle_loop = spawn_loop(state.db.clone(), state.git_bin.clone());
        await_first_run().await;
        tokio::time::sleep(window).await;
        let idle_runs = crate::ipfs_pin::sweep_runs();
        idle_loop.abort();
        assert_eq!(
            idle_runs,
            1,
            "a run that repaired nothing must back off to the longer idle interval; at \
             the base interval this window fits about {} runs, each of which pays up to \
             MAX_DEAD_ROW_READS_PER_RUN fruitless object reads against a table that will \
             never repair",
            window.as_millis() / base.as_millis()
        );

        // Leg 2: a repairable row. The run that repairs it must be followed by the BASE
        // interval, so a second run lands well inside the same window.
        let fx = seed_cid_repos(&slug, &short, &["idlesrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("idlesrc.git");
        let repo = seed_repo(&owner_did, "idlesrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        let (raw_cid, _provider) =
            seed_legacy_pin(&pool, &bare, &fx.public_oid, Some(&repo.id)).await;

        crate::ipfs_pin::reset_sweep_runs();
        let busy_loop = spawn_loop(state.db.clone(), state.git_bin.clone());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while crate::ipfs_pin::sweep_runs() < 2 && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let busy_runs = crate::ipfs_pin::sweep_runs();
        busy_loop.abort();
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "fixture precondition: the first run repairs the row"
        );
        assert!(
            busy_runs >= 2,
            "a run that repaired something must keep the BASE interval; backing off \
             after a productive run would stall a table that is still yielding repairs \
             (saw {busy_runs} run(s))"
        );
    }

    /// U4 scenario 2 (#173): a legacy row whose object bytes are gone is left exactly
    /// as it is by the sweep: never rewritten, never deleted. The row stays withheld
    /// until the bytes come back, which is the non-destructive contract the skip-branch
    /// repair already holds.
    #[sqlx::test]
    async fn sweep_leaves_a_bytes_gone_row_untouched(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let _fx = seed_cid_repos(&slug, &short, &["gonesrc"]);
        let repo = seed_repo(&owner_did, "gonesrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        // An oid whose bytes are NOT in the repo, but whose provenance resolves fine.
        let phantom_oid = "d".repeat(64);
        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"bytes that live nowhere").to_string();
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(&phantom_oid)
        .bind(&provider_cid)
        .bind("2020-01-01T00:00:00Z")
        .bind(&repo.id)
        .execute(&pool)
        .await
        .unwrap();

        let stats = crate::ipfs_pin::sweep_legacy_provider_cids(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            16,
            std::time::Duration::ZERO,
            &state.db,
            &mut Default::default(),
        )
        .await;
        assert_eq!(stats.repaired, 0, "an unrepairable row is not repaired");

        let (stored, stashed) = stored_pin(&pool, &phantom_oid).await;
        assert_eq!(
            stored, provider_cid,
            "the bytes-gone row keeps its provider CID (no destructive rewrite)"
        );
        assert_eq!(stashed, None, "nothing is stashed when the bytes are gone");
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM pinned_cids")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "the row is not deleted");
    }

    /// U4 scenario 3 (#173): the sweep inherits `repair_legacy_provider_cid`'s cost
    /// gate, so a row already keyed on a raw CIDv1 is NEVER read for bytes. The
    /// test-only `legacy_repair_reads` counter is the both-ways guard: dropping the
    /// codec gate reads the raw row and trips it off zero.
    #[sqlx::test]
    async fn sweep_never_reads_bytes_for_a_raw_cidv1_row(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["rawsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("rawsrc.git");
        let repo = seed_repo(&owner_did, "rawsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        let raw_cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo.id).await;
        assert!(
            gitlawb_core::cid::is_raw_cidv1(&raw_cid),
            "the seeded row is already the canonical resolver key"
        );

        crate::ipfs_pin::reset_legacy_repair_reads();
        let stats = crate::ipfs_pin::sweep_legacy_provider_cids(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            16,
            std::time::Duration::ZERO,
            &state.db,
            &mut Default::default(),
        )
        .await;
        assert_eq!(stats.scanned, 1, "the sweep walked the row");
        assert_eq!(stats.repaired, 0, "a raw row needs no repair");
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "a raw-CIDv1 row is never read for bytes (cost gate)"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the raw row is left as-is"
        );
    }

    /// U4 scenario 4 (#173, BOUND): one pass reads at most `batch` rows, so it repairs
    /// at most `batch` of them. The exact count is asserted, so raising or removing the
    /// bound fails. This is what keeps the sweep from monopolizing the DB on a node
    /// with a large `pinned_cids` table.
    #[sqlx::test]
    async fn sweep_one_pass_is_bounded_by_the_batch_size(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["batchsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("batchsrc.git");
        let repo = seed_repo(&owner_did, "batchsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        // Five legacy rows, batch of two.
        for oid in [
            &fx.public_oid,
            &fx.secret_oid,
            &fx.public_tree_oid,
            &fx.secret_tree_oid,
            &fx.commit_oid,
        ] {
            seed_legacy_pin(&pool, &bare, oid, Some(&repo.id)).await;
        }

        let stats = crate::ipfs_pin::sweep_legacy_provider_cids_once(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            2,
            &state.db,
            &mut Default::default(),
        )
        .await
        .expect("one pass runs");
        assert_eq!(stats.scanned, 2, "one pass reads exactly the batch size");
        assert_eq!(stats.repaired, 2, "one pass repairs at most the batch size");

        let repaired: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pinned_cids WHERE legacy_provider_cid IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(repaired, 2, "exactly two of the five rows were rewritten");
    }

    /// U4 scenario 5 (#173, RESUMPTION): the walk cursor persists, so a sweep
    /// interrupted mid-table continues from where it stopped instead of restarting.
    /// Two bounded passes are driven by hand (the restart), and the second pass is
    /// asserted to repair the NEXT two rows in cursor order, not the first two again.
    /// The read counter proves the already-repaired rows are not re-read.
    #[sqlx::test]
    async fn sweep_resumes_from_the_persisted_cursor(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["resumesrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("resumesrc.git");
        let repo = seed_repo(&owner_did, "resumesrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        let mut oids = vec![
            fx.public_oid.clone(),
            fx.secret_oid.clone(),
            fx.public_tree_oid.clone(),
            fx.secret_tree_oid.clone(),
        ];
        for oid in &oids {
            seed_legacy_pin(&pool, &bare, oid, Some(&repo.id)).await;
        }
        // The cursor is an ordered walk over the `pinned_cids` primary key.
        oids.sort();

        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let pass1 = crate::ipfs_pin::sweep_legacy_provider_cids_once(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            git_timeout,
            2,
            &state.db,
            &mut Default::default(),
        )
        .await
        .expect("pass 1 runs");
        assert_eq!(pass1.repaired, 2, "pass 1 repairs the first two rows");

        // The restart: a second pass over the SAME state must continue, not rewind.
        crate::ipfs_pin::reset_legacy_repair_reads();
        let pass2 = crate::ipfs_pin::sweep_legacy_provider_cids_once(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            git_timeout,
            2,
            &state.db,
            &mut Default::default(),
        )
        .await
        .expect("pass 2 runs");
        assert_eq!(pass2.repaired, 2, "pass 2 repairs the NEXT two rows");
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            2,
            "pass 2 reads bytes only for the two rows it repaired; the already-repaired \
             rows are not re-read"
        );
        for oid in &oids {
            let (_cid, stashed) = stored_pin(&pool, oid).await;
            assert!(
                stashed.is_some(),
                "every row is repaired after two resumed passes"
            );
        }
    }

    /// U4 scenario 7 (#173, cursor liveness): a row that cannot be repaired (NULL
    /// provenance, or a provenance whose repo row is gone) is skipped AND the cursor
    /// still advances past it. With `batch = 1` the two unrepairable rows sort first,
    /// so a cursor that failed to advance would re-read the same row forever and never
    /// reach the repairable row behind them. The outer timeout turns that into a
    /// FAILURE rather than a hung suite.
    #[sqlx::test]
    async fn sweep_advances_past_unrepairable_rows(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["skipsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("skipsrc.git");
        let repo = seed_repo(&owner_did, "skipsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        // Two blockers that sort ahead of any real 64-hex oid: one with NULL
        // provenance, one naming a repo row that no longer exists.
        let null_prov_oid = "0".repeat(64);
        let ghost_repo_oid = format!("{}1", "0".repeat(63));
        seed_legacy_pin(&pool, &bare, &fx.public_oid, Some(&repo.id)).await;
        for (oid, prov) in [
            (&null_prov_oid, None),
            (&ghost_repo_oid, Some("repo-that-is-gone")),
        ] {
            let raw = gitlawb_core::cid::Cid::from_git_object_bytes(oid.as_bytes()).to_string();
            sqlx::query(
                "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(oid)
            .bind(legacy_dagpb_cid(&raw))
            .bind("2020-01-01T00:00:00Z")
            .bind(prov)
            .execute(&pool)
            .await
            .unwrap();
        }
        assert!(
            null_prov_oid < fx.public_oid && ghost_repo_oid < fx.public_oid,
            "the blockers really do sort ahead of the repairable row"
        );

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                1,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates instead of looping on an unrepairable row");

        assert_eq!(
            stats.repaired, 1,
            "the sweep advanced past both blockers and repaired the row behind them"
        );
        assert!(
            stored_pin(&pool, &fx.public_oid).await.1.is_some(),
            "the row behind the blockers is the one that got repaired"
        );
        for oid in [&null_prov_oid, &ghost_repo_oid] {
            assert_eq!(
                stored_pin(&pool, oid).await.1,
                None,
                "an unrepairable row is left untouched"
            );
        }
    }

    /// U4 scenario 9 (#173, regression): a row skipped for a TRANSIENT reason is
    /// retried by a later run. The sweep never pulls a cold repo back from remote
    /// storage, so on a Tigris-backed node a repo that is not on local disk at boot
    /// contributes nothing to the pass. With the cursor parked at the end of the table
    /// that row was skipped FOREVER: every later boot read zero rows and the row stayed
    /// unadvertised and unresolvable with nothing left to repair it. Here the repo is
    /// off disk for the first run and back for the second, so only a re-walk repairs it.
    /// RED before the transient-skip cursor reset (the second run scans nothing).
    #[sqlx::test]
    async fn sweep_rewalks_after_a_transient_skip(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["coldsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("coldsrc.git");
        let repo = seed_repo(&owner_did, "coldsrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        let (raw_cid, _provider) =
            seed_legacy_pin(&pool, &bare, &fx.public_oid, Some(&repo.id)).await;

        // The repo is COLD: its provenance resolves, but the bytes are not on this
        // node's disk right now, exactly the state the sweep refuses to fix by pulling.
        let stashed_away = bare.with_extension("git.away");
        let _ = std::fs::remove_dir_all(&stashed_away);
        std::fs::rename(&bare, &stashed_away).expect("take the repo off local disk");

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first run terminates");
        assert_eq!(
            (first.scanned, first.repaired),
            (1, 0),
            "the cold repo's row is walked but cannot be repaired yet"
        );

        // The repo is warm again (a later boot, a fetch, an operator restore).
        std::fs::rename(&stashed_away, &bare).expect("put the repo back on local disk");

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second run terminates");
        assert_eq!(
            second.repaired, 1,
            "a later run re-walks the transiently skipped row and repairs it"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the row now carries the raw-content resolver key"
        );
        assert!(
            state
                .db
                .list_pinned_cids()
                .await
                .unwrap()
                .iter()
                .any(|r| r.cid == raw_cid),
            "the repaired row is advertised again"
        );
    }

    /// U4 scenario 10 (#173, the other arm of scenario 9): a PERMANENTLY unrepairable
    /// row must not cost anything on a later run. Bytes that are genuinely gone stay
    /// gone, so a re-walk must not read object bytes for that row, must not repair it,
    /// and must not spin: both runs are timeout-bounded, so a hot loop FAILS here.
    ///
    /// The assertion is about BOUNDED cost, not about the row going unread (jatmn
    /// round 12). It asserted `scanned == 0` while the cursor parked at the table
    /// maximum on a clean run; that parking is what let a row written below the cursor
    /// by another node go unswept forever, so the run now always rewinds on clean
    /// completion. The terminal row is therefore re-walked once per run, and its
    /// repair is re-attempted once: the object read is attempted before the bytes are
    /// found missing. That cost is real and it is the price of D. What must stay true
    /// is that it is exactly ONE attempt per run and never repairs, so a regression
    /// that retries the dead row within a run fails here.
    #[sqlx::test]
    async fn sweep_does_not_rewalk_for_a_terminal_skip(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        // The repo IS on local disk; the object's bytes are not in it and never will be.
        let _fx = seed_cid_repos(&slug, &short, &["termsrc"]);
        let repo = seed_repo(&owner_did, "termsrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        let phantom_oid = "e".repeat(64);
        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"bytes that live nowhere").to_string();
        sqlx::query(
            "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(&phantom_oid)
        .bind(legacy_dagpb_cid(&raw_cid))
        .bind("2020-01-01T00:00:00Z")
        .bind(&repo.id)
        .execute(&pool)
        .await
        .unwrap();

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first run terminates");
        assert_eq!(
            (first.scanned, first.repaired),
            (1, 0),
            "the row is walked and cannot be repaired"
        );

        crate::ipfs_pin::reset_legacy_repair_reads();
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second run terminates");
        assert_eq!(
            (second.repaired, second.passes),
            (0, 1),
            "the terminal row is still unrepairable and the run does not spin"
        );
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            1,
            "the dead row costs exactly one repair attempt per run, never a retry loop"
        );
    }

    /// U4 (#173, jatmn round 12): a row inserted BELOW a parked cursor must still be
    /// swept. A clean run (no retryable skips) leaves the cursor at the table's maximum
    /// `sha256_hex` and every later pass reads only `> cursor`, so a provider-CID row
    /// written afterwards by an older node mid-rolling-upgrade whose oid sorts below
    /// that maximum is never revisited. The resolver withholds its advertised key, so
    /// the object stays unretrievable with nothing left to fix it. The rewind added for
    /// the transient-skip case does not cover this: it is gated on `retryable_skips > 0`
    /// and a clean pass reports zero.
    #[sqlx::test]
    async fn sweep_revisits_a_row_written_below_a_parked_cursor(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["rollsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("rollsrc.git");
        let repo = seed_repo(&owner_did, "rollsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        // Two objects from the fixture, ordered by the column the walk is keyed on.
        let mut oids = [fx.public_oid.clone(), fx.secret_oid.clone()];
        oids.sort();
        let (low_oid, high_oid) = (oids[0].clone(), oids[1].clone());

        // First boot: one legacy row, repaired, nothing retryable. Under round 11 this
        // is exactly the run that parked the cursor at that row's oid, the table
        // maximum, because a clean run reported no retryable skip to rewind for.
        seed_legacy_pin(&pool, &bare, &high_oid, Some(&repo.id)).await;
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first run terminates");
        assert_eq!(
            (first.repaired, first.retryable_skips),
            (1, 0),
            "the first run is a clean completion: nothing retryable to rewind for"
        );
        assert_eq!(
            state.db.pin_repair_cursor().await.unwrap(),
            "",
            "a completed run rewinds instead of parking at the table maximum"
        );

        // An older node in the rolling upgrade writes a provider-CID row that sorts
        // below where the walk finished, which is where round 11 left the cursor.
        let (low_raw, low_provider) = seed_legacy_pin(&pool, &bare, &low_oid, Some(&repo.id)).await;

        // Next boot.
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second run terminates");

        let (stored, stashed) = stored_pin(&pool, &low_oid).await;
        assert_eq!(
            stored, low_raw,
            "the row written below the cursor is repaired to the raw-content key \
             (stored {stored}, provider key {low_provider}, second run scanned \
             {} repaired {})",
            second.scanned, second.repaired
        );
        assert_eq!(
            stashed.as_deref(),
            Some(low_provider.as_str()),
            "its old provider CID is stashed"
        );
        assert!(
            state
                .db
                .list_pinned_cids()
                .await
                .unwrap()
                .iter()
                .any(|r| r.cid == low_raw),
            "the repaired row is advertised again"
        );
    }

    /// U4 (#173, round 12, second-model pass): the fruitless reads a run spends on rows
    /// whose bytes are permanently gone are bounded per run. The rewind means every
    /// later run re-attempts each of them, so without a bound a node that accumulated
    /// dead pins (a deleted repo, a force-pushed history) pays `O(dead rows)` git
    /// invocations on every boot, forever. The run stops early instead and keeps its
    /// cursor, so the next boot resumes past what it already walked.
    #[sqlx::test]
    async fn sweep_bounds_fruitless_reads_per_run(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_DEAD_ROW_READS_PER_RUN;
        let batch: i64 = 16;

        // A real repo on disk, so every row gets as far as spending an object read, and
        // objects that were never in it, so every one of those reads is wasted.
        let _fx = seed_cid_repos(&slug, &short, &["deadsrc"]);
        let repo = seed_repo(&owner_did, "deadsrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"bytes that live nowhere").to_string();
        let dead_rows = cap + 2 * batch as usize;
        for i in 0..dead_rows {
            let phantom_oid = format!("{:064x}", i);
            sqlx::query(
                "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&phantom_oid)
            .bind(legacy_dagpb_cid(&raw_cid))
            .bind("2020-01-01T00:00:00Z")
            .bind(&repo.id)
            .execute(&pool)
            .await
            .unwrap();
        }

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                batch,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the run terminates");

        assert!(
            stats.dead_row_reads >= cap,
            "the run spends its budget before stopping (spent {})",
            stats.dead_row_reads
        );
        assert!(
            stats.dead_row_reads < cap + batch as usize,
            "the run overshoots its budget by at most one batch (spent {}, cap {cap})",
            stats.dead_row_reads
        );
        assert!(
            stats.scanned < dead_rows,
            "the run stops short of the table (scanned {} of {dead_rows})",
            stats.scanned
        );

        // Not a completed walk, so the cursor is kept and the next run carries on from
        // it rather than re-reading the rows this one already paid for.
        let cursor = state.db.pin_repair_cursor().await.unwrap();
        assert_ne!(cursor, "", "a run that stops on its budget keeps its place");
        let resumed = state.db.pinned_cids_after(&cursor, batch).await.unwrap();
        assert_eq!(
            resumed.first().map(|(sha, _)| sha.as_str()),
            Some(format!("{:064x}", stats.scanned).as_str()),
            "the next run starts at the row after the last one walked"
        );
    }

    /// U4 (#173, round 12, the other side of the unconditional rewind): a run that stops
    /// on a pass ERROR keeps its mid-table cursor. The rewind is what a COMPLETED walk
    /// does; applying it to a failed one would restart from the beginning of the table
    /// on every boot of a node whose DB fails part-way through, and such a node would
    /// never reach the rows behind the failure point. The error is induced by renaming
    /// `pinned_cids` out from under the walk during the inter-batch sleep.
    #[sqlx::test]
    async fn sweep_keeps_its_cursor_when_a_pass_fails(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["failsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("failsrc.git");
        let repo = seed_repo(&owner_did, "failsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        let mut oids = [fx.public_oid.clone(), fx.secret_oid.clone()];
        oids.sort();
        for oid in &oids {
            seed_legacy_pin(&pool, &bare, oid, Some(&repo.id)).await;
        }

        // A batch of one means the first pass is full, so the run sleeps and comes back
        // for a second pass. The table is gone by then.
        //
        // The killer WAITS for the first pass to finish rather than racing a fixed sleep
        // against it: the pass writes its cursor as its last act, so a non-empty cursor
        // is the signal that the run is now in its inter-batch sleep. A fixed delay here
        // fails on a runner slow enough that the rename lands during the first pass's
        // own query, which reports `scanned = 0` and asserts something else entirely.
        let killer = {
            let pool = pool.clone();
            let db = state.db.clone();
            tokio::spawn(async move {
                loop {
                    if !db.pin_repair_cursor().await.unwrap().is_empty() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                sqlx::query("ALTER TABLE pinned_cids RENAME TO pinned_cids_gone")
                    .execute(&pool)
                    .await
                    .expect("rename the table out from under the walk");
            })
        };

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                1,
                std::time::Duration::from_millis(300),
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the run terminates on the failed pass");
        killer.await.expect("the killer task completes");

        assert_eq!(
            stats.scanned, 1,
            "the first pass read its one row before the table went away"
        );
        assert_eq!(
            state.db.pin_repair_cursor().await.unwrap(),
            oids[0],
            "a failed run keeps the position it reached instead of rewinding"
        );
    }

    /// U4 scenario 11 (#173, path barrier): the sweep resolves a source repo's disk path
    /// through the SAME validated logic the repo store uses, so a repo row whose name
    /// carries `..` reads nothing. Names are validated at creation today, so this is a
    /// defence-in-depth barrier on a second caller of the raw path helper rather than a
    /// live exploit. The escapee repo really does hold the object's bytes, so before the
    /// barrier the sweep happily read them from outside `repos_dir` and repaired the row.
    /// RED before routing through the validated path (repaired 1).
    #[sqlx::test]
    async fn sweep_refuses_a_source_path_that_escapes_repos_dir(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        // The bytes live at /tmp/{slug}/escapee.git, OUTSIDE the repos_dir below.
        let fx = seed_cid_repos(&slug, &short, &["escapee"]);
        let escapee_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("escapee.git");
        let repos_dir = std::path::PathBuf::from("/tmp").join(&slug).join("root");
        std::fs::create_dir_all(repos_dir.join(&slug)).expect("create the repos_dir tree");

        // A repo row whose name walks back out of repos_dir: repos_dir/{slug}/../../escapee.git
        let mut repo = seed_repo(&owner_did, "../../escapee");
        repo.disk_path = escapee_bare.display().to_string();
        state.db.create_repo(&repo).await.expect("seed repo");
        let (_raw_cid, provider_cid) =
            seed_legacy_pin(&pool, &escapee_bare, &fx.public_oid, Some(&repo.id)).await;
        assert!(
            crate::git::store::repo_disk_path(&repos_dir, &owner_did, &repo.name).exists(),
            "the unvalidated helper really does resolve to the escapee repo"
        );

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                &repos_dir,
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");

        assert_eq!(
            stats.repaired, 0,
            "a repo path that escapes repos_dir must never be read"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            provider_cid,
            "the row is untouched because its bytes were never read"
        );
    }

    /// U4 scenario 12 (#173, F4): the repair's object read is SYNCHRONOUS `git cat-file`,
    /// so running it inline parks the async worker for as long as git takes, up to the
    /// whole `git_service_timeout_secs` budget on a wedged read, and the sweep does this
    /// per legacy row starting at boot. A slow git stand-in makes that observable: a
    /// concurrent 20ms ticker cannot tick at all while the only worker thread is blocked,
    /// and ticks freely once the read is on the blocking pool. RED before the
    /// `spawn_blocking` (0 ticks).
    #[sqlx::test]
    async fn repair_object_read_does_not_block_the_async_worker(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["slowsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("slowsrc.git");
        let repo = seed_repo(&owner_did, "slowsrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        seed_legacy_pin(&pool, &bare, &fx.public_oid, Some(&repo.id)).await;

        // A git that takes 300ms per invocation (the read makes two: type, then content).
        let slow_git = std::env::temp_dir().join(format!("gl-slow-git-{short}"));
        std::fs::write(&slow_git, "#!/bin/sh\nsleep 0.3\nexec git \"$@\"\n").expect("write shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&slow_git, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        let ticks = std::sync::Arc::new(AtomicUsize::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };

        let stats = crate::ipfs_pin::sweep_legacy_provider_cids(
            std::path::Path::new("/tmp"),
            slow_git.to_str().unwrap(),
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            16,
            std::time::Duration::ZERO,
            &state.db,
            &mut Default::default(),
        )
        .await;
        ticker.abort();

        assert_eq!(stats.repaired, 1, "the slow git still repairs the row");
        assert!(
            ticks.load(Ordering::Relaxed) >= 5,
            "the runtime kept running other tasks during the blocking git read (ticks: {})",
            ticks.load(Ordering::Relaxed)
        );
    }

    /// U4 scenario 8 (#173, degenerate states): an empty `pinned_cids` table and a
    /// table with zero legacy rows both complete cleanly, with no repair and no read.
    #[sqlx::test]
    async fn sweep_completes_on_degenerate_tables(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        // Empty table.
        crate::ipfs_pin::reset_legacy_repair_reads();
        let empty = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                4,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates on an empty table");
        assert_eq!(
            (empty.scanned, empty.repaired),
            (0, 0),
            "an empty table is a clean no-op"
        );

        // Zero legacy rows: every row already carries the canonical raw key.
        let fx = seed_cid_repos(&slug, &short, &["degensrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("degensrc.git");
        let repo = seed_repo(&owner_did, "degensrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        for oid in [&fx.public_oid, &fx.secret_oid, &fx.commit_oid] {
            pin_cid_for_repo(&bare, oid, &state.db, &repo.id).await;
        }

        let clean = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                4,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates on a table with no legacy rows");
        assert_eq!(clean.scanned, 3, "every row is walked");
        assert_eq!(clean.repaired, 0, "nothing needs repair");
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "no object bytes are read when no row is legacy"
        );
    }

    /// U4 (#173, BOUND): the inter-batch delay is real, observed by wall clock. Five
    /// rows at a batch of two means two full batches and a trailing partial one, so the
    /// run sleeps twice. Without the sleep the whole run is sub-millisecond DB work and
    /// a node's `pinned_cids` table gets walked as fast as Postgres will answer.
    #[sqlx::test]
    async fn sweep_sleeps_between_batches(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["delaysrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("delaysrc.git");
        let repo = seed_repo(&owner_did, "delaysrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        for oid in [
            &fx.public_oid,
            &fx.secret_oid,
            &fx.public_tree_oid,
            &fx.secret_tree_oid,
            &fx.commit_oid,
        ] {
            pin_cid_for_repo(&bare, oid, &state.db, &repo.id).await;
        }

        let delay = std::time::Duration::from_millis(150);
        let started = std::time::Instant::now();
        let stats = crate::ipfs_pin::sweep_legacy_provider_cids(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            2,
            delay,
            &state.db,
            &mut Default::default(),
        )
        .await;
        let elapsed = started.elapsed();

        assert_eq!(
            stats.passes, 3,
            "five rows at a batch of two is three passes"
        );
        assert!(
            elapsed >= delay * 2,
            "the run sleeps once between each pair of full batches: {elapsed:?} < {:?}",
            delay * 2
        );
    }

    // ---- F1: bounded additive discovery for source-less legacy rows ----

    /// An empty bare repo at `path`, used as a warm discovery candidate that does not
    /// hold the object. sha256 so a 64-hex oid probe is a clean "absent" rather than a
    /// format error.
    fn init_empty_bare(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().unwrap()).expect("create the owner dir");
        let out = std::process::Command::new("git")
            .args([
                "init",
                "-q",
                "--bare",
                "--object-format=sha256",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git init --bare: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    async fn set_quarantined(pool: &PgPool, repo_id: &str) {
        sqlx::query("UPDATE repos SET quarantined = TRUE WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn pinned_repo_id(pool: &PgPool, oid: &str) -> Option<String> {
        sqlx::query_scalar("SELECT repo_id FROM pinned_cids WHERE sha256_hex = $1")
            .bind(oid)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// F1 scenario 1 (#173): a pre-provenance row (`repo_id` NULL, no `pin_repo_sources`
    /// entry) is repaired by probing warm local repos for the object, and the discovered
    /// repo is recorded ADDITIVELY. The must-not half is the last assertion: reading
    /// identical bytes proves the repo HOLDS the object, never that it is the FIRST
    /// pinner (forks, a shared LICENSE blob and the empty tree all collide), and
    /// `backfill_pin_provenance`'s `AND repo_id IS NULL` guard would make a guessed
    /// exclusive claim permanent, so `pinned_cids.repo_id` must stay NULL. RED before
    /// discovery exists: the source set is empty, the row is skipped, and the cursor
    /// advances past it for good.
    #[sqlx::test]
    async fn sweep_discovery_repairs_sourceless_legacy_row(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["discsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("discsrc.git");
        let repo = seed_repo(&owner_did, "discsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        // The pre-provenance shape: NULL repo_id and no pin_repo_sources row.
        let (raw_cid, provider_cid) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;
        assert!(
            state
                .db
                .pin_sources_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .is_empty(),
            "the seeded row really has no recorded source"
        );

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");
        assert_eq!(stats.repaired, 1, "discovery repairs the source-less row");

        let (stored, stashed) = stored_pin(&pool, &fx.public_oid).await;
        assert_eq!(
            stored, raw_cid,
            "the key is rewritten to the raw-content CID from locally verified bytes"
        );
        assert_eq!(
            stashed.as_deref(),
            Some(provider_cid.as_str()),
            "the old provider CID is stashed"
        );
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![repo.id.clone()],
            "the discovered repo is recorded as an additive source"
        );
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "one discovered holder never proves the set complete, so the marker is set \
             and the resolver's fallback scan stays available"
        );
        assert_eq!(
            pinned_repo_id(&pool, &fx.public_oid).await,
            None,
            "discovery makes no exclusive first-pinner claim: repo_id stays NULL"
        );
    }

    /// F1 scenario 2 (#173): once discovery has repaired the row it is raw-CIDv1, so a
    /// later pass takes the cost gate's cheap path and reads no bytes at all. The cursor
    /// is rewound by hand so the second pass really re-walks the row rather than reading
    /// nothing because it is behind the cursor.
    #[sqlx::test]
    async fn sweep_discovery_repaired_row_is_cheap_on_later_passes(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["cheapsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("cheapsrc.git");
        let repo = seed_repo(&owner_did, "cheapsrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        let (raw_cid, _provider) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first run terminates");
        assert_eq!(first.repaired, 1, "the first run repairs by discovery");

        // Re-walk the same row: the cost gate must spare it every byte read.
        state.db.set_pin_repair_cursor("").await.unwrap();
        crate::ipfs_pin::reset_legacy_repair_reads();
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second run terminates");
        assert_eq!(second.scanned, 1, "the second run really re-walks the row");
        assert_eq!(second.repaired, 0, "there is nothing left to repair");
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "a repaired row is raw-CIDv1, so no later pass reads bytes for it"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the repaired key survives the second pass"
        );
    }

    /// F1 scenario 3 (#173, MUST-NOT): a quarantined repo is hidden from every reader,
    /// so it must not become a discovery source either. The only holder here is warm and
    /// quarantined, and the filter drops it at candidate-load time, before any probe: the
    /// row is left exactly as it is and no bytes are read.
    #[sqlx::test]
    async fn sweep_discovery_skips_quarantined_holder(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["quarsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("quarsrc.git");
        let repo = seed_repo(&owner_did, "quarsrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        set_quarantined(&pool, &repo.id).await;
        let (_raw_cid, provider_cid) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        crate::ipfs_pin::reset_legacy_repair_reads();
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");

        assert_eq!(
            stats.repaired, 0,
            "a quarantined repo never serves as a discovery source"
        );
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "the quarantine filter drops the candidate before any probe reads bytes"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            provider_cid,
            "the row keeps its provider key"
        );
        assert_eq!(
            state
                .db
                .pin_sources_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .len(),
            0,
            "no source is recorded from a quarantined repo"
        );
    }

    /// F1 scenario 4 (#173, MUST-NOT): a candidate that is not on local disk is COLD.
    /// Discovery must not pull it back from remote storage (the sweep is opportunistic
    /// background maintenance, not a bulk restore), and it must not mark the row
    /// retryable either.
    ///
    /// The retryable half was originally about the cursor: a cold-candidate retryable
    /// would rewind it, and the second run's `scanned` proved it had not. Round 12 made
    /// the rewind unconditional on reaching the end of the table, so every completed run
    /// rewinds and the second run re-reads the row whatever this one does. What still
    /// holds, and what is asserted below, is the COST: a cold candidate is filtered at
    /// load, so re-walking the row reads no object bytes and restores nothing. The
    /// retryable-skip assertion also still stands on its own terms, since a cold
    /// candidate is not evidence about the row.
    ///
    /// The no-fetch half is asserted here on the EFFECT rather than on the call: the
    /// cold candidate's disk path must still not exist after two full runs, which is
    /// what any restore (through the repo store, through Tigris, through anything else)
    /// would have changed. The control that keeps that assertion from being vacuous is
    /// the read from `stashed_away`: the bytes really are still on this node and really
    /// would have repaired the row, so declining them is a choice and not an absence.
    /// The call-shape half is `sweep_module_never_calls_a_remote_fetch`.
    #[sqlx::test]
    async fn sweep_discovery_cold_candidates_do_not_rewind(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["coldcand"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("coldcand.git");
        let repo = seed_repo(&owner_did, "coldcand");
        state.db.create_repo(&repo).await.expect("seed repo");
        let (raw_cid, provider_cid) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        // The only holder goes cold: its row stays in the DB, its bytes leave the disk.
        let stashed_away = bare.with_extension("git.away");
        let _ = std::fs::remove_dir_all(&stashed_away);
        std::fs::rename(&bare, &stashed_away).expect("take the repo off local disk");

        crate::ipfs_pin::reset_legacy_repair_reads();
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first run terminates");
        assert_eq!(
            (first.scanned, first.repaired),
            (1, 0),
            "the row is walked and no cold candidate can repair it"
        );
        // The effect a restore would have left behind. Nothing put the repo back.
        assert!(
            !bare.exists(),
            "the sweep must never materialize a cold candidate on local disk: a repair \
             pass over every pinned row on the node would become a bulk restore"
        );
        // Anti-vacuity for the assertion above: the bytes are still reachable on this
        // node and still recompute to the raw key, so a fetch would have succeeded and
        // repaired the row. The sweep declined an available copy rather than finding
        // nothing to take.
        let (_ty, stashed_bytes) = crate::git::store::read_object(&stashed_away, &fx.public_oid)
            .expect("the stashed copy is readable")
            .expect("the stashed copy still holds the object");
        assert_eq!(
            gitlawb_core::cid::Cid::from_git_object_bytes(&stashed_bytes).to_string(),
            raw_cid,
            "the withheld copy is exactly the one that would have repaired the row"
        );
        assert_eq!(
            first.retryable_skips, 0,
            "a cold candidate is not evidence about the row, so it never marks the row \
             retryable and never drives a cursor rewind"
        );
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "a cold candidate is filtered at load, so nothing is read and nothing is pulled"
        );

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second run terminates");
        assert_eq!(
            second.retryable_skips, 0,
            "the re-walk still finds nothing retryable about the row"
        );
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "the re-walk costs no object read either: the cold candidate is filtered at \
             load on every run, so an unconditional rewind does not turn into repeated \
             discovery reads for this row"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            provider_cid,
            "the row keeps its provider key"
        );
        assert!(
            !bare.exists(),
            "no later pass materialized the cold candidate either"
        );
    }

    /// #173 round 12 (rebase interaction): discovery's probes count against the per-run
    /// fruitless-read budget, PER PROBE rather than per row.
    ///
    /// The two changes met badly. Round 12 made the cursor rewind unconditional on
    /// reaching the end of the table, so every completed run re-walks every row; the
    /// budget is what stops a node from paying `O(dead rows)` object reads on every boot.
    /// But `row_read_attempted` was only ever set in the provenance loop, so a
    /// source-less row, the one shape discovery exists for, spent up to
    /// `MAX_LEGACY_DISCOVERY_PROBES` reads and contributed nothing to the budget. The
    /// per-row cap bounds one row; nothing bounded the run.
    ///
    /// Counting per row instead of per probe would not do: at 16 probes a row the budget
    /// would admit 16 times the reads it names. Several warm candidates here are what
    /// distinguishes the two, since the run must stop after far fewer ROWS than the
    /// budget's own number.
    #[sqlx::test]
    async fn sweep_discovery_probes_count_against_the_fruitless_read_budget(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_DEAD_ROW_READS_PER_RUN;
        let batch: i64 = 8;

        // Three warm repos, none of which holds the objects below, so every probe reads
        // and finds nothing: three fruitless reads per source-less row.
        let names = ["u3bdga", "u3bdgb", "u3bdgc"];
        let _fx = seed_cid_repos(&slug, &short, &names);
        for n in names {
            let repo = seed_repo(&owner_did, n);
            state.db.create_repo(&repo).await.expect("seed repo");
        }
        let probes_per_row = names.len();

        // Source-less legacy rows (no repo_id, no pin_repo_sources) for objects that live
        // in none of the repos, which is the shape discovery probes and cannot repair.
        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"bytes that live nowhere").to_string();
        let rows = cap; // more than the budget allows once each row costs three probes
        for i in 0..rows {
            sqlx::query("INSERT INTO pinned_cids (sha256_hex, cid, pinned_at) VALUES ($1, $2, $3)")
                .bind(format!("{:064x}", i))
                .bind(legacy_dagpb_cid(&raw_cid))
                .bind("2020-01-01T00:00:00Z")
                .execute(&pool)
                .await
                .unwrap();
        }

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(180),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                batch,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the run terminates");

        assert!(
            stats.dead_row_reads >= cap,
            "discovery's fruitless probes reach the budget (spent {})",
            stats.dead_row_reads
        );
        // Per PROBE, not per row: at three probes a row the run must stop after roughly a
        // third of the budget's worth of rows, plus at most one batch of overshoot.
        // Asserted BEFORE the coarser bound below so that a per-row implementation
        // reddens on the property this test is named for. The fixture deliberately holds
        // exactly `cap` rows, so per-row counting walks the whole table and would
        // otherwise trip the coarse assertion first, reporting the wrong reason.
        assert!(
            stats.scanned <= cap / probes_per_row + batch as usize,
            "the budget counts probes, not rows: scanned {} with a cap of {cap} at \
             {probes_per_row} probes per row",
            stats.scanned
        );
        assert!(
            stats.scanned < rows,
            "the run stops short of the table instead of walking all {rows} rows \
             (scanned {})",
            stats.scanned
        );
        assert_ne!(
            state.db.pin_repair_cursor().await.unwrap(),
            "",
            "a run that stops on its budget keeps its place for the next one"
        );
    }

    /// #173 round 12: the RETRYABLE arm of discovery is charged to the budget too, which
    /// is the half that differs from the provenance loop and the half an attacker can
    /// steer.
    ///
    /// The cap-reached outcome is retryable BY DESIGN, so that a grindable repo id cannot
    /// bury the true holder past the cap permanently. That same design makes it the arm a
    /// hostile registrant can hold a row in: register more than the cap's worth of warm
    /// repos and every source-less row costs a full cap of reads, on every boot, forever.
    /// Charging only the settled arm would leave exactly that uncharged.
    #[sqlx::test]
    async fn sweep_discovery_charges_a_retryable_cap_reached_row(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let probe_cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        // One more warm repo than the probe cap, so the walk stops with candidates left
        // and classifies the row RETRYABLE rather than settled. None holds the object.
        let names: Vec<String> = (0..probe_cap + 1).map(|i| format!("u3ret{i}")).collect();
        let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let _fx = seed_cid_repos(&slug, &short, &name_refs);
        for n in &names {
            let repo = seed_repo(&owner_did, n);
            state.db.create_repo(&repo).await.expect("seed repo");
        }

        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"bytes that live nowhere").to_string();
        sqlx::query("INSERT INTO pinned_cids (sha256_hex, cid, pinned_at) VALUES ($1, $2, $3)")
            .bind("a".repeat(64))
            .bind(legacy_dagpb_cid(&raw_cid))
            .bind("2020-01-01T00:00:00Z")
            .execute(&pool)
            .await
            .unwrap();

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the run terminates");

        assert_eq!(
            stats.retryable_skips, 1,
            "the cap was reached with candidates left, so the row is retryable"
        );
        assert_eq!(
            stats.repaired, 0,
            "no candidate holds the object, so nothing is repaired"
        );
        assert_eq!(
            stats.dead_row_reads, probe_cap,
            "a retryable cap-reached row is charged its full cap of probes, not zero"
        );
    }

    /// F1 scenario 5 (#173, BOUND plus anti-burial): the probe cap counts the expensive
    /// unit, a bounded object read from a warm repo, so a row costs at most
    /// `MAX_LEGACY_DISCOVERY_PROBES` reads however many candidates the node holds. With
    /// candidates left over the row is classified RETRYABLE, not terminal: `repo_id`
    /// derives from the owner DID, which anyone can grind, so a first-N-wins cap over a
    /// sorted set would otherwise let an attacker bury the true holder permanently.
    #[sqlx::test]
    async fn sweep_discovery_read_probes_are_capped(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        // The bytes live in a bare repo with NO repos row, so it is never a candidate.
        let fx = seed_cid_repos(&slug, &short, &["capsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("capsrc.git");
        let (_raw_cid, provider_cid) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        // More warm candidates than the cap, none of them holding the object.
        let candidates = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES + 4;
        for i in 0..candidates {
            let name = format!("capcand{i}");
            init_empty_bare(
                &std::path::PathBuf::from("/tmp")
                    .join(&slug)
                    .join(format!("{name}.git")),
            );
            let repo = seed_repo(&owner_did, &name);
            state.db.create_repo(&repo).await.expect("seed candidate");
        }

        crate::ipfs_pin::reset_legacy_repair_reads();
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");

        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES,
            "one row costs at most the probe cap in object reads, whatever the candidate count"
        );
        assert_eq!(stats.repaired, 0, "no candidate holds the object");
        assert_eq!(
            stats.retryable_skips, 1,
            "cap exhaustion with candidates remaining is RETRYABLE, so a buried holder \
             is re-walked by a later run instead of written off"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            provider_cid,
            "the row is untouched"
        );
    }

    /// Write an executable `git` stand-in and return its path.
    fn write_git_shim(name: &str, script: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, script).expect("write the git shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod the git shim");
        }
        path
    }

    /// F6 scenario 1 (#173 round 13): one hung candidate must not starve the rows behind
    /// it in the same pass. `DiscoveryCtx` is loaded once per pass, so before the per-row
    /// slice every source-less row in a pass shared ONE deadline: the first row's wedged
    /// `cat-file` spent the whole budget, and every later row reached
    /// `repair_legacy_provider_cid` with it already gone, came back retryable without a
    /// meaningful probe, and (because `sha256_hex` order is stable) starved on the same
    /// row on every boot.
    ///
    /// Two source-less legacy rows, one warm candidate holding both objects, and a `git`
    /// stand-in that wedges on the FIRST row's object and answers the second's for real.
    /// With `git_timeout` at 4s the row slice is 1s, so the wedged row costs a quarter of
    /// the pass budget and the second row still probes with a live deadline. RED before
    /// the slice: the first row burns all 4s and the second is never repaired.
    #[sqlx::test]
    async fn sweep_discovery_hung_candidate_does_not_starve_later_rows(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["hungsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("hungsrc.git");
        let repo = seed_repo(&owner_did, "hungsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        // The walk is ordered by `sha256_hex`, so the row that is reached FIRST is the
        // lexicographically smaller oid. That is the one the stand-in wedges on.
        let mut oids = [fx.public_oid.clone(), fx.secret_oid.clone()];
        oids.sort();
        let (hung_oid, live_oid) = (oids[0].clone(), oids[1].clone());
        let (_hung_raw, hung_provider) = seed_legacy_pin(&pool, &bare, &hung_oid, None).await;
        let (live_raw, live_provider) = seed_legacy_pin(&pool, &bare, &live_oid, None).await;

        // The type stage feeds the oid on STDIN (`cat-file --batch-check`) and the
        // content stage puts it in argv, so the stand-in has to look in both places.
        let git_bin = write_git_shim(
            &format!("gl-hung-git-{short}"),
            &format!(
                "#!/bin/sh\n\
                 if [ \"$2\" = \"--batch-check\" ]; then\n\
                 \x20 oid=$(cat)\n\
                 \x20 case \"$oid\" in\n\
                 \x20   {hung_oid}) sleep 30; exit 1 ;;\n\
                 \x20 esac\n\
                 \x20 printf '%s\\n' \"$oid\" | git \"$@\"\n\
                 \x20 exit $?\n\
                 fi\n\
                 case \"$*\" in\n\
                 \x20 *{hung_oid}*) sleep 30; exit 1 ;;\n\
                 esac\n\
                 exec git \"$@\"\n"
            ),
        );

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            crate::ipfs_pin::sweep_legacy_provider_cids_once(
                std::path::Path::new("/tmp"),
                git_bin.to_str().unwrap(),
                std::time::Duration::from_secs(4),
                16,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the pass terminates")
        .expect("the pass succeeds");

        assert_eq!(stats.scanned, 2, "both rows are walked in the one pass");
        assert_eq!(
            stored_pin(&pool, &live_oid).await.0,
            live_raw,
            "the second row still probes with a LIVE deadline and is repaired in the \
             same pass; a hung first row must not spend the whole pass budget"
        );
        assert_eq!(stats.repaired, 1, "exactly the second row is repaired");
        assert_eq!(
            stored_pin(&pool, &hung_oid).await.0,
            hung_provider,
            "the wedged row keeps its provider key"
        );
        assert_eq!(
            stats.retryable_skips, 1,
            "the wedged row is retryable, so a later run walks it again"
        );
        assert_ne!(
            live_raw, live_provider,
            "control: the repaired key really differs from the seeded legacy one"
        );
    }

    /// F6 scenario 2 (#173 round 13, MUST-NOT): once a pass's whole discovery budget is
    /// spent, the rows it has not reached are skipped CHEAPLY and visibly, never folded
    /// into ordinary retryable accounting. A row charged for a probe it never meaningfully
    /// made burns `MAX_DEAD_ROW_READS_PER_RUN` on nothing, which pauses the run early and
    /// (once the discovery continuation lands) would let it advance over windows nobody
    /// probed.
    ///
    /// Seven source-less legacy rows, one warm candidate, and a `git` that wedges on
    /// everything. With `git_timeout` at 4s each row slice is 1s, so about four rows spend
    /// the pass budget between them and the rest start with it already gone: those charge
    /// ZERO reads and the pass reports that it ran out. RED before the skip arm: every row
    /// past the first reaches the probe with a dead deadline and is charged a read for it,
    /// so `dead_row_reads` equals the row count.
    #[sqlx::test]
    async fn sweep_discovery_spent_pass_budget_skips_cheaply(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["spentsrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("spentsrc.git");
        let repo = seed_repo(&owner_did, "spentsrc");
        state.db.create_repo(&repo).await.expect("seed repo");

        let oids = [
            fx.public_oid.clone(),
            fx.secret_oid.clone(),
            fx.public_tree_oid.clone(),
            fx.secret_tree_oid.clone(),
            fx.root_tree_oid.clone(),
            fx.commit_oid.clone(),
            fx.tag_oid.clone(),
        ];
        for oid in &oids {
            seed_legacy_pin(&pool, &bare, oid, None).await;
        }

        // Wedges on every invocation, so no row can ever be repaired and the only
        // question left is what each one COSTS.
        let git_bin = write_git_shim(
            &format!("gl-spent-git-{short}"),
            "#!/bin/sh\nsleep 30\nexit 1\n",
        );

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            crate::ipfs_pin::sweep_legacy_provider_cids_once(
                std::path::Path::new("/tmp"),
                git_bin.to_str().unwrap(),
                std::time::Duration::from_secs(4),
                16,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the pass terminates")
        .expect("the pass succeeds");

        assert_eq!(stats.scanned, oids.len(), "every row is walked");
        assert_eq!(stats.repaired, 0, "a wedged candidate repairs nothing");
        assert!(
            stats.dead_row_reads < stats.scanned,
            "a row reached after the pass budget is spent must be skipped free, not \
             charged for a probe it cannot make: {} reads charged over {} rows",
            stats.dead_row_reads,
            stats.scanned
        );
        assert!(
            stats.dead_row_reads <= 5,
            "the pass budget is four row slices wide, so at most the rows that really \
             probed are charged (plus at most one on the boundary); got {}",
            stats.dead_row_reads
        );
        assert!(
            stats.discovery_budget_spent,
            "a pass that ran out of discovery budget must SAY so rather than starving \
             its remaining rows silently"
        );
        assert_eq!(
            stats.retryable_skips,
            oids.len(),
            "no row is settled: the wedged ones and the unprobed ones are all worth \
             walking again"
        );
    }

    // ---- #173 round 13, F5: the per-traversal discovery window continuation ----

    /// A repo row at a chosen point in the sweep's `(created_at, id)` candidate order,
    /// `pos` seconds past a fixed base so the order is the fixture's to set rather than
    /// the clock's. Negative positions sort BELOW the base, which is how a fixture models
    /// a candidate entering the warm list underneath an already-persisted continuation.
    fn seed_repo_at(owner_did: &str, name: &str, pos: i64) -> RepoRecord {
        let created_at = chrono::DateTime::parse_from_rfc3339("2020-01-01T12:00:00Z")
            .expect("the fixture base parses")
            .with_timezone(&Utc)
            + chrono::Duration::seconds(pos);
        RepoRecord {
            created_at,
            updated_at: created_at,
            ..seed_repo(owner_did, name)
        }
    }

    /// The keyset key the sweep stores for a candidate: the RAW `created_at` text as
    /// `create_repo` wrote it, plus the repo id.
    fn candidate_key(repo: &RepoRecord) -> (String, String) {
        (repo.created_at.to_rfc3339(), repo.id.clone())
    }

    /// Seed `n` warm candidates in candidate order (position 1 is the oldest). The one at
    /// 1-based `holder` is the already-cloned bare named there and really holds the
    /// fixture's objects; every other position is an empty bare that holds nothing, so a
    /// probe against it costs a real object read and finds nothing.
    async fn seed_candidate_ladder(
        db: &crate::db::Db,
        owner_did: &str,
        slug: &str,
        prefix: &str,
        n: usize,
        holder: Option<(usize, &str)>,
    ) -> Vec<RepoRecord> {
        let mut rows = Vec::new();
        for pos in 1..=n {
            let name = match holder {
                Some((hp, hn)) if hp == pos => hn.to_string(),
                _ => {
                    let name = format!("{prefix}{pos}");
                    init_empty_bare(
                        &std::path::PathBuf::from("/tmp")
                            .join(slug)
                            .join(format!("{name}.git")),
                    );
                    name
                }
            };
            let repo = seed_repo_at(owner_did, &name, pos as i64);
            db.create_repo(&repo).await.expect("seed candidate");
            rows.push(repo);
        }
        rows
    }

    /// Copy ONE blob between SHA-256 bares, preserving its oid. A bare clone carries
    /// every object in the fixture, and the cross-batch scenario needs a candidate that
    /// holds exactly one of them.
    fn copy_blob_into_bare(src: &std::path::Path, dst: &std::path::Path, oid: &str) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let blob = Command::new("git")
            .args(["cat-file", "blob", oid])
            .current_dir(src)
            .output()
            .expect("git runs");
        assert!(blob.status.success(), "cat-file blob {oid}");
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "-t", "blob", "--stdin"])
            .current_dir(dst)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("git runs");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(&blob.stdout)
            .expect("feed the blob");
        let out = child.wait_with_output().expect("hash-object finishes");
        assert!(out.status.success(), "hash-object -w");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            oid,
            "the copied blob keeps its oid, or the fixture is not the object the row names"
        );
    }

    /// Poll `f` until it yields a value or `limit` runs out. Several scenarios drive the
    /// re-arm wrapper, which on a healthy table never returns, so the assertion has to be
    /// on DB state observed while it runs.
    async fn poll_until<T, F, Fut>(limit: std::time::Duration, mut f: F) -> Option<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        let deadline = std::time::Instant::now() + limit;
        loop {
            if let Some(v) = f().await {
                return Some(v);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// The discovery load is bounded to ONE probe window, not to the whole repo table.
    ///
    /// The exhaustive load was justified as "background maintenance on a timer" whose
    /// "paging cost is paid once". That was written when the sweep ran once per boot.
    /// The sweep now re-arms on a timer, so a node carrying a single unrepairable
    /// source-less row paid a full-table paging pass plus a stat of every warm repo on
    /// every re-armed run, forever, to choose sixteen candidates. The idle backoff makes
    /// that hourly rather than every five minutes, which is a smaller bill for the same
    /// unbounded work.
    ///
    /// The window itself is unchanged, which is why the assertion is on the PAGING and
    /// not on the outcome: an exhaustive load and a bounded one pick the same sixteen
    /// candidates and reach the same verdict, so nothing about the result can go red on
    /// the difference. The fixture puts more than one window of warm candidates at the
    /// front of the `(created_at, id)` order and enough cold rows behind them to push the
    /// table past a single page.
    ///
    /// MUTATION (RED): page to exhaustion and the load buys a second page it has no use
    /// for.
    #[sqlx::test]
    async fn sweep_discovery_load_stops_once_the_window_is_full(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        // The bytes live in a bare with no `repos` row, so no candidate ever holds them
        // and the row stays source-less: the pass runs a full window of probes.
        let fx = seed_cid_repos(&slug, &short, &["boundsrc"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("boundsrc.git");
        let _warm = seed_candidate_ladder(
            &state.db,
            &owner_did,
            &slug,
            "boundwarm",
            crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES + 4,
            None,
        )
        .await;
        // Cold rows: a `repos` row with nothing on disk. They cost a page each but can
        // never fill a window slot, so they are what an exhaustive load pages through.
        let page_rows = crate::api::ipfs::LEGACY_SCAN_PAGE_ROWS;
        for pos in 100..(100 + page_rows) {
            let repo = seed_repo_at(&owner_did, &format!("boundcold{pos}"), pos as i64);
            state.db.create_repo(&repo).await.expect("seed a cold row");
        }
        seed_legacy_pin(&pool, &src, &fx.public_oid, None).await;

        crate::ipfs_pin::reset_discovery_paging();
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the traversal terminates");

        let pages = crate::ipfs_pin::discovery_repo_pages();
        let rows = crate::ipfs_pin::discovery_repo_rows();
        assert_eq!(
            pages, 1,
            "the window fills inside the first page, so the load must stop there; it \
             bought {pages} pages carrying {rows} rows"
        );
        assert!(
            rows <= page_rows,
            "a bounded load reads at most the pages it needs; it read {rows} rows out of \
             a table of {}",
            crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES + 4 + page_rows
        );
        assert_eq!(
            stats.dead_row_reads,
            crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES,
            "and the window it picked is still a FULL one: bounding the load must not \
             shrink the number of candidates the row actually probes"
        );
    }

    /// F5 scenario 1 (#173 round 13): a holder past the probe cap is REACHED.
    ///
    /// `discover_legacy_row` probes the first `MAX_LEGACY_DISCOVERY_PROBES` of a list
    /// ordered `(created_at, id)`. That order is stable and the list was rebuilt from
    /// scratch every run, so before the continuation every traversal on every node probed
    /// the same oldest sixteen and a holder at position seventeen was unreachable by
    /// anything: not a later pass, not a later run, not a reboot. Seventeen warm
    /// candidates with only the newest holding the object; the first traversal must
    /// repair nothing and persist where it got to, the second must start after that and
    /// repair the row, and neither may exceed the probe cap.
    ///
    /// RED before the rotation: both traversals probe the same first sixteen and the row
    /// keeps its provider key forever.
    #[sqlx::test]
    async fn sweep_discovery_rotation_reaches_later_candidates(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        // `rotsrc` carries the bytes but has NO repos row, so it is never a candidate;
        // `rotheld` is the candidate that really holds them.
        let fx = seed_cid_repos(&slug, &short, &["rotsrc", "rotheld"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("rotsrc.git");
        let candidates = seed_candidate_ladder(
            &state.db,
            &owner_did,
            &slug,
            "rotcand",
            crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES + 1,
            Some((crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES + 1, "rotheld")),
        )
        .await;
        let (raw_cid, provider_cid) = seed_legacy_pin(&pool, &src, &fx.public_oid, None).await;

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first traversal terminates");

        assert_eq!(
            first.repaired, 0,
            "the holder sits past the probe cap, so the first window cannot reach it"
        );
        assert_eq!(
            first.dead_row_reads,
            crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES,
            "the first traversal spends exactly one window of probes on the row"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            provider_cid,
            "the row still carries its legacy provider key after the first traversal"
        );
        assert_eq!(
            state.db.discovery_continuation().await.unwrap(),
            candidate_key(&candidates[crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES - 1]),
            "a completed traversal that ran out of window persists the last candidate it \
             actually read, so the next one starts after it instead of repeating it"
        );

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second traversal terminates");

        assert_eq!(
            second.repaired, 1,
            "the second traversal's window starts at the seventeenth candidate and \
             repairs the row"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the key is rewritten to the raw-content CID"
        );
        assert!(
            second.dead_row_reads <= crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES,
            "the rotation moves the window, it does not widen it: {} reads in one \
             traversal",
            second.dead_row_reads
        );
        assert_ne!(raw_cid, provider_cid, "control: the two keys really differ");
    }

    /// F5 scenario 2 (#173 round 13, MUST-NOT, the steerability negative): candidates
    /// appearing between traversals must not move the window off the holder.
    ///
    /// The continuation is a keyset KEY, not an offset, and this is the difference.
    /// Freshly registered repos sort LAST under `created_at` and cannot be backdated, so
    /// they can only ever land behind the window. Candidates can also enter BELOW the
    /// continuation without any mint at all: a cold repo warms on a Tigris-backed node,
    /// an operator restores an archived one. Every one of those silently renumbers an
    /// offset, and sixteen of them slide an offset window clean off the candidate it was
    /// about to reach, while a key names the boundary itself and does not care what
    /// appeared underneath it.
    ///
    /// RED under an offset continuation: the second traversal's window starts sixteen
    /// entries into a list that grew underneath it and never reaches the holder.
    #[sqlx::test]
    async fn sweep_discovery_rotation_survives_minted_candidates(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["mintsrc", "mintheld"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("mintsrc.git");
        let candidates = seed_candidate_ladder(
            &state.db,
            &owner_did,
            &slug,
            "mintcand",
            cap + 1,
            Some((cap + 1, "mintheld")),
        )
        .await;
        let (raw_cid, provider_cid) = seed_legacy_pin(&pool, &src, &fx.public_oid, None).await;

        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first traversal terminates");
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            provider_cid,
            "precondition: the first window does not reach the holder"
        );
        let boundary = state.db.discovery_continuation().await.unwrap();
        assert_eq!(
            boundary,
            candidate_key(&candidates[cap - 1]),
            "precondition: the window boundary is the sixteenth candidate"
        );

        // The mint: several brand-new repos. They sort last and are the only thing an
        // attacker who can grind owner DIDs actually gets to do.
        for i in 0..5 {
            let name = format!("minted{i}");
            init_empty_bare(
                &std::path::PathBuf::from("/tmp")
                    .join(&slug)
                    .join(format!("{name}.git")),
            );
            state
                .db
                .create_repo(&seed_repo_at(&owner_did, &name, 100 + i))
                .await
                .expect("seed a minted candidate");
        }
        // And a whole window's worth entering BELOW the boundary, which is what an
        // offset silently mistakes for a move of the boundary itself.
        for i in 0..cap {
            let name = format!("warmed{i}");
            init_empty_bare(
                &std::path::PathBuf::from("/tmp")
                    .join(&slug)
                    .join(format!("{name}.git")),
            );
            state
                .db
                .create_repo(&seed_repo_at(&owner_did, &name, -(i as i64) - 1))
                .await
                .expect("seed a candidate below the boundary");
        }

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second traversal terminates");

        assert_eq!(
            second.repaired, 1,
            "the window boundary is a key, so twenty-one candidates arriving between \
             traversals leave it exactly where the first traversal put it and the holder \
             is still the next thing read"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the holder's row is repaired despite the churn"
        );
    }

    /// F5 scenario 3 (#173 round 13): a candidate list that has shrunk below one window
    /// RESETS the continuation instead of stranding it past the end of the list.
    ///
    /// The migration's own success shrinks the list (repos go cold, get deleted), and a
    /// continuation left pointing past everything would rotate each later traversal to an
    /// empty tail and then wrap to the same prefix forever. Once the whole warm list fits
    /// in one window there is no next window to advance to, so the traversal resets.
    #[sqlx::test]
    async fn sweep_discovery_shrunken_list_resets_the_continuation(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["shrinksrc"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("shrinksrc.git");
        // Nothing warm holds the object, so the row stays unrepaired and every traversal
        // spends a full window on it.
        let candidates =
            seed_candidate_ladder(&state.db, &owner_did, &slug, "shrinkcand", cap + 1, None).await;
        seed_legacy_pin(&pool, &src, &fx.public_oid, None).await;

        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first traversal terminates");
        assert_eq!(
            state.db.discovery_continuation().await.unwrap(),
            candidate_key(&candidates[cap - 1]),
            "precondition: the traversal parked the continuation past the head"
        );

        // The list shrinks to two: everything but the two oldest goes away.
        for repo in candidates.iter().skip(2) {
            sqlx::query("DELETE FROM repos WHERE id = $1")
                .bind(&repo.id)
                .execute(&pool)
                .await
                .unwrap();
        }

        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second traversal terminates");

        assert_eq!(
            state.db.discovery_continuation().await.unwrap(),
            (String::new(), String::new()),
            "once the whole warm list fits in one window there is no next window, so the \
             continuation resets rather than pointing past the end of a shrunken list"
        );
    }

    /// F5 scenario 5 (#173 round 13, MUST-NOT): a traversal may only advance over
    /// candidates it really READ, never over the ones it merely walked past with a dead
    /// deadline.
    ///
    /// U3 gives each source-less row a slice of the pass budget and skips a row reached
    /// with the pass budget already gone. What it does NOT skip is the candidates behind
    /// a wedged one INSIDE a row: those still enter the probe loop, still get charged a
    /// read, and still come back retryable, but `db_bounded` returns on the spent
    /// deadline without touching the repo. Advancing over them would burn a window nobody
    /// looked in, which is the same hole the continuation exists to close.
    ///
    /// Twenty warm candidates, seven source-less rows, and a `git` that wedges on
    /// everything. With `git_timeout` at 4s each row slice is 1s, so each row that probes
    /// at all spends its whole slice on candidate ONE and walks the other fifteen with a
    /// dead deadline. The traversal may advance to candidate one and no further.
    #[sqlx::test]
    async fn sweep_discovery_starved_traversal_advances_only_over_live_probes(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["starvesrc"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("starvesrc.git");
        let candidates =
            seed_candidate_ladder(&state.db, &owner_did, &slug, "starvecand", cap + 4, None).await;
        for oid in [
            &fx.public_oid,
            &fx.secret_oid,
            &fx.public_tree_oid,
            &fx.secret_tree_oid,
            &fx.root_tree_oid,
            &fx.commit_oid,
            &fx.tag_oid,
        ] {
            seed_legacy_pin(&pool, &src, oid, None).await;
        }

        let git_bin = write_git_shim(
            &format!("gl-starve-git-{short}"),
            "#!/bin/sh\nsleep 30\nexit 1\n",
        );

        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::ipfs_pin::sweep_legacy_provider_cids_once(
                std::path::Path::new("/tmp"),
                git_bin.to_str().unwrap(),
                std::time::Duration::from_secs(4),
                16,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the traversal terminates")
        .expect("the traversal succeeds");

        let seen = state.db.discovery_continuation().await.unwrap();
        assert_eq!(
            seen,
            candidate_key(&candidates[0]),
            "the only candidate any row read with a live deadline is the first, so that \
             is exactly how far the traversal may advance"
        );
        assert_ne!(
            seen,
            candidate_key(&candidates[cap - 1]),
            "advancing to the end of the window would skip fifteen candidates that were \
             charged a read but never actually looked at"
        );
    }

    /// F5 scenario 6 (#173 round 13, MUST-NOT): a candidate that wedges MID-window must
    /// not carry the continuation past the candidates behind it.
    ///
    /// The sharp version of the live-budget rule, and the one a window's-end advance gets
    /// wrong while looking correct. Twenty-four warm candidates, the holder at position
    /// twelve, and a `git` that wedges only in the repo at position nine. Positions one
    /// to eight are read for real, nine eats the row's whole slice, and ten through
    /// sixteen are charged a read apiece against a dead deadline without the repo ever
    /// being opened. The continuation may advance to nine and no further, or the holder
    /// at twelve is skipped by a traversal that never looked at it.
    #[sqlx::test]
    async fn sweep_discovery_hung_mid_window_does_not_skip_unread_candidates(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["midsrc", "midheld"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("midsrc.git");
        let candidates = seed_candidate_ladder(
            &state.db,
            &owner_did,
            &slug,
            "midcand",
            cap + 8,
            Some((12, "midheld")),
        )
        .await;
        let (raw_cid, provider_cid) = seed_legacy_pin(&pool, &src, &fx.public_oid, None).await;

        // Wedges only inside the position-nine repo, which the sweep enters by cwd.
        let git_bin = write_git_shim(
            &format!("gl-mid-git-{short}"),
            "#!/bin/sh\ncase \"$(pwd)\" in\n  */midcand9.git) sleep 30; exit 1 ;;\nesac\nexec git \"$@\"\n",
        );

        let first = tokio::time::timeout(
            std::time::Duration::from_secs(180),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                git_bin.to_str().unwrap(),
                std::time::Duration::from_secs(16),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the first traversal terminates");

        assert_eq!(
            first.repaired, 0,
            "the wedged candidate spends the row's slice, so the holder behind it is \
             charged a read but never actually read"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            provider_cid,
            "precondition: the first traversal leaves the row on its provider key"
        );
        assert_eq!(
            state.db.discovery_continuation().await.unwrap(),
            candidate_key(&candidates[8]),
            "the last candidate read with a live deadline is the wedged one at position \
             nine, so that is the boundary; anything further skips unread candidates"
        );

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(180),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                git_bin.to_str().unwrap(),
                std::time::Duration::from_secs(16),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the second traversal terminates");

        assert_eq!(
            second.repaired, 1,
            "the next traversal starts at position ten and reaches the holder at twelve"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the row is repaired from the candidate the hang had hidden"
        );
    }

    /// F5 scenario 7 (#173 round 13): the continuation survives the future being DROPPED.
    ///
    /// `spawn_legacy_cid_sweep` runs the sweep inside a `tokio::select!` against the
    /// shutdown watcher, so on shutdown the sweep future is dropped wherever it happens
    /// to be. The re-arm wrapper never returns on a healthy node, so a persist written on
    /// the way out of the wrapper would never be written at all. Persisting inside the
    /// traversal-ending pass is what makes a shutdown cost at most a repeated window.
    #[sqlx::test]
    async fn sweep_continuation_survives_dropped_sweep_future(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["dropsrc"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("dropsrc.git");
        let candidates =
            seed_candidate_ladder(&state.db, &owner_did, &slug, "dropcand", cap + 1, None).await;
        seed_legacy_pin(&pool, &src, &fx.public_oid, None).await;

        // The wrapper completes a traversal and then parks on its re-arm sleep, which is
        // exactly where a shutdown drops it in production.
        let expected = candidate_key(&candidates[cap - 1]);
        let observed = tokio::select! {
            _ = crate::ipfs_pin::run_sweep_rearmed(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                16,
                std::time::Duration::ZERO,
                std::time::Duration::from_secs(3600),
                &state.db,
            ) => None,
            v = poll_until(std::time::Duration::from_secs(120), || async {
                let c = state.db.discovery_continuation().await.unwrap();
                (c != (String::new(), String::new())).then_some(c)
            }) => v,
        };

        assert_eq!(
            observed,
            Some(expected),
            "the traversal-ending pass persists the continuation, so dropping the sweep \
             future afterwards keeps the advance the traversal earned"
        );
    }

    /// F5 scenario 8 (#173 round 13, MUST-NOT, the aliasing negative): two source-less
    /// rows in DIFFERENT passes of the same traversal share one window.
    ///
    /// The continuation advances once per TRAVERSAL, not once per pass. Per pass, a row's
    /// window index across traversals is `(t*m + j) mod W` for `m` rows and `W` windows,
    /// so with `m` and `W` sharing a factor a given row only ever visits `W / gcd(m, W)`
    /// of the windows and orbits a strict subset forever. Two rows, two windows: under
    /// per-pass advancement the first row is pinned to window one for the life of the
    /// node and its holder in window two is unreachable.
    ///
    /// Thirty-two warm candidates, `batch = 1` so the two rows land in different passes,
    /// the first row's holder at position twenty, the second row's object nowhere at all.
    #[sqlx::test]
    async fn sweep_discovery_rows_in_different_batches_share_windows(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["alisrc"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("alisrc.git");
        // The walk is ordered by `sha256_hex`, so the smaller oid is the row read first.
        let mut oids = [fx.public_oid.clone(), fx.secret_oid.clone()];
        oids.sort();
        let (first_row, second_row) = (oids[0].clone(), oids[1].clone());

        let candidates =
            seed_candidate_ladder(&state.db, &owner_did, &slug, "alicand", 2 * cap, None).await;
        // Position twenty holds ONLY the first row's blob: a bare clone would carry both
        // and the second row would stop being the unrepairable control.
        copy_blob_into_bare(
            &src,
            &std::path::PathBuf::from("/tmp")
                .join(&slug)
                .join("alicand20.git"),
            &first_row,
        );
        let (first_raw, first_provider) = seed_legacy_pin(&pool, &src, &first_row, None).await;
        seed_legacy_pin(&pool, &src, &second_row, None).await;

        let log = std::env::temp_dir().join(format!("gl-ali-log-{short}"));
        let _ = std::fs::remove_file(&log);
        let git_bin = write_git_shim(
            &format!("gl-ali-git-{short}"),
            &format!(
                "#!/bin/sh\n\
                 if [ \"$2\" = \"--batch-check\" ]; then\n\
                 \x20 oid=$(cat)\n\
                 \x20 printf '%s %s\\n' \"$oid\" \"$(basename $(pwd))\" >> {log}\n\
                 \x20 printf '%s\\n' \"$oid\" | git \"$@\"\n\
                 \x20 exit $?\n\
                 fi\n\
                 exec git \"$@\"\n",
                log = log.display()
            ),
        );

        let mut traversal = crate::ipfs_pin::DiscoveryTraversalState::default();
        for _ in 0..2 {
            tokio::time::timeout(
                std::time::Duration::from_secs(180),
                crate::ipfs_pin::sweep_legacy_provider_cids(
                    std::path::Path::new("/tmp"),
                    git_bin.to_str().unwrap(),
                    git_timeout,
                    1,
                    std::time::Duration::ZERO,
                    &state.db,
                    &mut traversal,
                ),
            )
            .await
            .expect("the traversal terminates");
        }

        assert_eq!(
            stored_pin(&pool, &first_row).await.0,
            first_raw,
            "the first row's holder is in the second window, which it only reaches if \
             both rows moved through the windows together"
        );
        assert_ne!(
            first_raw, first_provider,
            "control: the repaired key really differs from the seeded legacy one"
        );

        // The invocation log proves the shared window rather than inferring it: inside
        // one traversal both oids must have been probed against the same repos.
        let text = std::fs::read_to_string(&log).expect("the shim logged its probes");
        let _ = std::fs::remove_file(&log);
        let repos_for = |oid: &str| -> Vec<String> {
            let mut v: Vec<String> = text
                .lines()
                .filter_map(|l| l.split_once(' '))
                .filter(|(o, _)| *o == oid)
                .map(|(_, r)| r.to_string())
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let first_probed = repos_for(&first_row);
        let second_probed = repos_for(&second_row);
        assert!(
            first_probed.len() >= cap && second_probed.len() >= cap,
            "precondition: both rows really probed a full window ({} and {})",
            first_probed.len(),
            second_probed.len()
        );
        let window_one: Vec<String> = {
            let mut v: Vec<String> = candidates[..cap]
                .iter()
                .map(|r| format!("{}.git", r.name))
                .collect();
            v.sort();
            v
        };
        for repo in &window_one {
            assert!(
                first_probed.contains(repo) && second_probed.contains(repo),
                "both rows must have probed {repo} in the first traversal; per-pass \
                 advancement would have handed the second row a different window"
            );
        }
    }

    /// F5 scenario 9 (#173 round 13): the dead-read cap PAUSES a run, and the re-arm is
    /// what keeps coverage moving afterwards.
    ///
    /// Before the wrapper the sweep ran exactly once per boot, so the window advanced
    /// once per boot too and a node that never reboots never advanced past its first
    /// window. Five unrepairable source-less rows at a full window of probes each blow
    /// through `MAX_DEAD_ROW_READS_PER_RUN` inside one run; the holder sits in the second
    /// window, so it is reachable only across re-arms.
    #[sqlx::test]
    async fn sweep_rearm_advances_past_dead_read_cap(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["rearmsrc", "rearmheld"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("rearmsrc.git");
        seed_candidate_ladder(
            &state.db,
            &owner_did,
            &slug,
            "rearmcand",
            cap + 4,
            Some((cap + 2, "rearmheld")),
        )
        .await;
        let mut oids = [
            fx.public_oid.clone(),
            fx.secret_oid.clone(),
            fx.public_tree_oid.clone(),
            fx.secret_tree_oid.clone(),
            fx.root_tree_oid.clone(),
        ];
        oids.sort();
        for oid in &oids {
            seed_legacy_pin(&pool, &src, oid, None).await;
        }
        let target = oids.last().unwrap().clone();
        let target_raw = {
            let (_ty, bytes) = crate::git::store::read_object(&src, &target)
                .expect("read the object")
                .expect("the object exists");
            gitlawb_core::cid::Cid::from_git_object_bytes(&bytes).to_string()
        };

        // One run, driven directly: five rows at a full window each is more fruitless
        // reading than one run will do, so it PAUSES rather than completing.
        let mut traversal = crate::ipfs_pin::DiscoveryTraversalState::default();
        let run = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                1,
                std::time::Duration::ZERO,
                &state.db,
                &mut traversal,
            ),
        )
        .await
        .expect("the run terminates");
        assert_eq!(
            run.stop,
            crate::ipfs_pin::SweepStop::PausedOnDeadReadCap,
            "one run cannot walk this table: it stops on the dead-read cap with the \
             cursor mid-table"
        );
        assert_eq!(run.repaired, 0, "the holder is past the first window");

        let repaired = tokio::select! {
            _ = crate::ipfs_pin::run_sweep_rearmed(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                1,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                &state.db,
            ) => false,
            v = poll_until(std::time::Duration::from_secs(300), || async {
                (stored_pin(&pool, &target).await.0 == target_raw).then_some(())
            }) => v.is_some(),
        };
        assert!(
            repaired,
            "a run that pauses on the dead-read cap is re-armed, so traversals keep \
             completing and the window keeps advancing until the holder is reached"
        );
    }

    /// F5 scenario 10 (#173 round 13, MUST-NOT): a cap pause AFTER the traversal's last
    /// source-less row must not lose the advance that traversal earned.
    ///
    /// The traversal accumulator is scoped to the TRAVERSAL, not the run, and this is the
    /// case that separates the two. The run that probes the window is paused by the
    /// dead-read cap before it reaches the end of the table; a LATER run reads the short
    /// batch and is the one that applies the advance. Rebuild the accumulator per run and
    /// that later run sees nothing recorded, applies the hold arm, and the window never
    /// moves however many times the sweep re-arms.
    ///
    /// One source-less row against twenty warm candidates (a full window of probes),
    /// then enough bytes-gone rows behind it to trip the cap before the short batch.
    #[sqlx::test]
    async fn sweep_cap_pause_after_last_discovery_row_still_advances(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);
        let cap = crate::ipfs_pin::MAX_LEGACY_DISCOVERY_PROBES;

        let fx = seed_cid_repos(&slug, &short, &["pausesrc"]);
        let src = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("pausesrc.git");
        let candidates =
            seed_candidate_ladder(&state.db, &owner_did, &slug, "pausecand", cap + 4, None).await;
        let (_raw, provider) = seed_legacy_pin(&pool, &src, &fx.public_oid, None).await;
        assert!(
            !fx.public_oid.starts_with("ff"),
            "precondition: the discovery row sorts before the synthetic bytes-gone rows"
        );

        // Bytes-gone rows: real provenance pointing at a warm repo that does not hold
        // them, so each costs exactly one fruitless read. Enough of them that the run
        // trips the cap with the end of the table still ahead of it.
        let ghost = &candidates[0];
        let needed = crate::ipfs_pin::MAX_DEAD_ROW_READS_PER_RUN - cap;
        for i in 0..needed {
            let oid = format!("ff{:062x}", i);
            sqlx::query(
                "INSERT INTO pinned_cids (sha256_hex, cid, pinned_at, repo_id)
                 VALUES ($1, $2, $3, NULL)",
            )
            .bind(&oid)
            .bind(&provider)
            .bind("2020-01-01T00:00:00Z")
            .execute(&pool)
            .await
            .unwrap();
            state
                .db
                .record_pin_source(&oid, &ghost.id)
                .await
                .expect("record the ghost source");
        }

        let expected = candidate_key(&candidates[cap - 1]);
        let observed = tokio::select! {
            _ = crate::ipfs_pin::run_sweep_rearmed(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                git_timeout,
                1,
                std::time::Duration::ZERO,
                std::time::Duration::ZERO,
                &state.db,
            ) => None,
            v = poll_until(std::time::Duration::from_secs(300), || async {
                let c = state.db.discovery_continuation().await.unwrap();
                (c != (String::new(), String::new())).then_some(c)
            }) => v,
        };

        assert_eq!(
            observed,
            Some(expected),
            "the run that probed the window was paused by the dead-read cap, so a LATER \
             run ends the traversal; the advance it applies has to come from the \
             traversal's accumulator, not that run's"
        );
    }

    /// F1 scenario 6 (#173, the collision case): two warm repos hold identical bytes,
    /// which is the shape (forks, a shared LICENSE blob, the empty tree) that makes an
    /// exclusive first-pinner claim wrong. Discovery records ONE additive source and
    /// sets the incomplete marker, and the marker is what keeps `needs_scan` true so a
    /// caller who can only read the OTHER holder is still served. Under an exclusive
    /// claim `needs_scan` would be false and that caller would get a 404 for a public
    /// object.
    #[sqlx::test]
    async fn sweep_discovery_multi_holder_serves_both_readers(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["holda", "holdb"]);
        let bare_a = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("holda.git");

        // A is older, so the oldest-first probe order selects it; it is PRIVATE, so it
        // denies the anonymous caller. B is public and holds the same bytes.
        let mut repo_a = seed_repo(&owner_did, "holda");
        repo_a.is_public = false;
        repo_a.created_at = Utc::now() - chrono::Duration::days(2);
        let repo_b = seed_repo(&owner_did, "holdb");
        state.db.create_repo(&repo_a).await.expect("seed repo a");
        state.db.create_repo(&repo_b).await.expect("seed repo b");

        let (raw_cid, _provider) = seed_legacy_pin(&pool, &bare_a, &fx.public_oid, None).await;

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");
        assert_eq!(
            stats.repaired, 1,
            "the row is repaired from the first holder"
        );
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![repo_a.id.clone()],
            "exactly one additive source is recorded, the oldest-first selection"
        );
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "the marker records that discovery does not know the full source set"
        );
        assert_eq!(
            pinned_repo_id(&pool, &fx.public_oid).await,
            None,
            "no exclusive claim is written for either holder"
        );

        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a caller who can read only the NON-selected holder is still served"
        );
        assert!(body.contains("public bytes"), "the object's bytes serve");
    }

    /// U5 (#173, F7): the discovered-source row and the fallback-arming sentinel commit
    /// together or not at all, so discovery can never leave a row in the one state the
    /// resolver reads as complete while it is not: a nonempty, below-cap, UNMARKED
    /// source set.
    ///
    /// Same shape as the multi-holder test above (older private holder selected, newer
    /// public holder unrecorded), plus a fault that fails ONLY the marker insert: a
    /// `BEFORE INSERT` trigger on `pin_source_failures` that raises. Under the pre-fix
    /// two-call shape the source insert commits (its own transaction's second statement
    /// is a DELETE, which an insert trigger does not fire) and the separate marker insert
    /// then fails, leaving the source set holding the private holder alone with no
    /// marker; `needs_scan` is `sources.is_empty() || at_cap || incomplete`, so all three
    /// signals are off, the resolver drops its fallback scan, and the public duplicate is
    /// permanently 404'd for the anonymous caller. One transaction makes that state
    /// unreachable: the marker's failure rolls the source row back with it, the set stays
    /// EMPTY, and the empty-set signal routes the request to the fallback scan.
    #[sqlx::test]
    async fn sweep_discovery_failed_marker_does_not_strand_public_copy(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["stranda", "strandb"]);
        let bare_a = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("stranda.git");

        // A is older, so the oldest-first probe order selects it; it is PRIVATE, so it
        // denies the anonymous caller. B is public and holds the same bytes.
        let mut repo_a = seed_repo(&owner_did, "stranda");
        repo_a.is_public = false;
        repo_a.created_at = Utc::now() - chrono::Duration::days(2);
        let repo_b = seed_repo(&owner_did, "strandb");
        state.db.create_repo(&repo_a).await.expect("seed repo a");
        state.db.create_repo(&repo_b).await.expect("seed repo b");

        let (raw_cid, _provider) = seed_legacy_pin(&pool, &bare_a, &fx.public_oid, None).await;

        // The fault, installed AFTER migrations: every insert into `pin_source_failures`
        // raises. Postgres triggers cannot raise inline, hence the plpgsql function.
        // Deliberately NOT a `DROP TABLE`: the source-record transaction's own DELETE on
        // this table would then error too, that transaction would roll back, and the
        // pre-fix run would land the same empty set as the post-fix one, so the test
        // would pass for the wrong reason.
        sqlx::query(
            "CREATE FUNCTION fail_pin_source_failure_insert() RETURNS trigger AS $$
             BEGIN RAISE EXCEPTION 'injected pin_source_failures insert failure'; END;
             $$ LANGUAGE plpgsql",
        )
        .execute(&pool)
        .await
        .expect("install the fault function");
        sqlx::query(
            "CREATE TRIGGER fail_pin_source_failure_insert
                 BEFORE INSERT ON pin_source_failures
                 FOR EACH ROW EXECUTE FUNCTION fail_pin_source_failure_insert()",
        )
        .execute(&pool)
        .await
        .expect("install the fault trigger");

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");
        assert_eq!(
            stats.repaired, 1,
            "the row is still repaired to its raw key; only the source record is at risk"
        );

        // Gathered before the assertions so the RED output carries the half-state.
        let sources = state
            .db
            .pin_sources_for_oid(&fx.public_oid)
            .await
            .expect("read the source set");
        let marker_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pin_source_failures WHERE sha256_hex = $1")
                .bind(&fx.public_oid)
                .fetch_one(&pool)
                .await
                .expect("read the marker table");

        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            (st, body.contains("public bytes")),
            (StatusCode::OK, true),
            "the anonymous caller must be served the PUBLIC holder's copy through the \
             fallback scan; got {st} with source set {sources:?} and {marker_rows} marker \
             row(s), the nonempty-and-unmarked half-state the resolver reads as complete"
        );
        assert!(
            sources.is_empty(),
            "the failed marker must roll the source row back with it; got {sources:?}"
        );
        assert_eq!(
            marker_rows, 0,
            "the marker insert is what failed, so no marker row can exist"
        );
    }

    /// U5 (#173, F7, the healthy direction): one discovery hit writes BOTH rows, asserted
    /// against the tables directly rather than through the boolean helper. The sentinel
    /// is unconditional because one discovered holder out of a bounded warm-only
    /// candidate set never proves the source set complete, and it is written against the
    /// empty-string UNKNOWN-repo sentinel so no later real record clears it.
    #[sqlx::test]
    async fn sweep_discovery_records_source_and_sentinel_in_one_commit(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["bothrows"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("bothrows.git");
        let repo = seed_repo(&owner_did, "bothrows");
        state.db.create_repo(&repo).await.expect("seed repo");

        seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");
        assert_eq!(stats.repaired, 1, "the discovered row is repaired");

        let source_rows: Vec<String> = sqlx::query_scalar(
            "SELECT repo_id FROM pin_repo_sources WHERE sha256_hex = $1 ORDER BY repo_id",
        )
        .bind(&fx.public_oid)
        .fetch_all(&pool)
        .await
        .expect("read pin_repo_sources");
        assert_eq!(
            source_rows,
            vec![repo.id.clone()],
            "the discovered holder is recorded additively"
        );

        let marker_repos: Vec<String> = sqlx::query_scalar(
            "SELECT repo_id FROM pin_source_failures WHERE sha256_hex = $1 ORDER BY repo_id",
        )
        .bind(&fx.public_oid)
        .fetch_all(&pool)
        .await
        .expect("read pin_source_failures");
        assert_eq!(
            marker_repos,
            vec![String::new()],
            "the same commit writes the unknown-repo sentinel: one discovered holder never \
             proves the set complete, so the resolver must keep its fallback scan"
        );
    }

    /// F1 scenario 7 (#173, degenerate state): the cost gate at the top of the row loop
    /// fires before the sources query, so a source-less row that is ALREADY raw-CIDv1
    /// never enters discovery and reads nothing.
    #[sqlx::test]
    async fn sweep_discovery_never_runs_for_a_raw_cidv1_sourceless_row(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["rawnosrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("rawnosrc.git");
        let repo = seed_repo(&owner_did, "rawnosrc");
        state.db.create_repo(&repo).await.expect("seed repo");
        // No provenance recorded: `pin_cid_for` stores the raw key with a NULL repo_id.
        let raw_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;

        crate::ipfs_pin::reset_legacy_repair_reads();
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");

        assert_eq!(stats.scanned, 1, "the row is walked");
        assert_eq!(stats.repaired, 0, "a raw-CIDv1 row needs no repair");
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            0,
            "the cost gate spares a raw row every byte read, discovery included"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the raw row is left as-is"
        );
    }

    /// F1 scenario 8 (#173, the negative direction of the new branch): a row WITH a
    /// recorded source resolves through the existing source loop only. An older warm
    /// decoy repo holds identical bytes, so if discovery ran it would record the decoy
    /// and set the incomplete marker; neither happens.
    #[sqlx::test]
    async fn sweep_discovery_is_not_used_for_a_provenanced_row(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["provsrc", "decoysrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("provsrc.git");

        let mut decoy = seed_repo(&owner_did, "decoysrc");
        decoy.created_at = Utc::now() - chrono::Duration::days(2);
        let repo = seed_repo(&owner_did, "provsrc");
        state.db.create_repo(&decoy).await.expect("seed decoy");
        state.db.create_repo(&repo).await.expect("seed repo");

        let (raw_cid, _provider) =
            seed_legacy_pin(&pool, &bare, &fx.public_oid, Some(&repo.id)).await;

        crate::ipfs_pin::reset_legacy_repair_reads();
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");

        assert_eq!(stats.repaired, 1, "the provenanced row repairs as before");
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the key is rewritten from the recorded source"
        );
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            1,
            "exactly one read, from the recorded source: discovery never probes"
        );
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![repo.id.clone()],
            "the decoy is never recorded as a source"
        );
        assert!(
            !state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "a provenanced row's source set is not marked incomplete"
        );
    }

    /// F1 scenario 9 (#173, the degradation posture, by execution): if the additive
    /// `record_pin_source` fails after the key rewrite lands, the row is raw-CIDv1 with
    /// an empty source set. Nothing in the sweep revisits it (the cost gate skips a raw
    /// row free on every later pass), so the source record is best-effort and the
    /// resolver's own fallback is the healing path, not a retry. This is that state,
    /// driven end to end: an empty source set makes `needs_scan` true and the bounded
    /// legacy scan still serves the object.
    #[sqlx::test]
    async fn sweep_repaired_row_without_source_record_still_served(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["nosrcrec"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("nosrcrec.git");
        let repo = seed_repo(&owner_did, "nosrcrec");
        state.db.create_repo(&repo).await.expect("seed repo");

        // The post-repair state a failed source record leaves behind: raw key, no
        // provenance row, no pin_repo_sources row.
        let raw_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;
        assert!(
            state
                .db
                .pin_sources_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .is_empty(),
            "the row really has no recorded source"
        );

        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "an empty source set routes the resolver to its bounded legacy scan, so a \
             repaired row whose source record failed still serves"
        );
        assert!(body.contains("public bytes"), "the object's bytes serve");
    }

    /// U2 (#173, F1 proved by execution): a genuinely PRE-PROVENANCE `pinned_cids` row,
    /// one written while `pinned_cids.repo_id` and `pin_repo_sources` do not exist, is
    /// repaired by the sweep and then served end to end by `GET /ipfs/{cid}`.
    ///
    /// The fixture un-applies v19 and v20 before the insert on purpose. A source-less
    /// row written through the modern schema is a shortcut: it shows the sweep copes
    /// with an empty source set, not that it copes with the row shape an upgraded node
    /// actually carries. With the column absent, a provenance-carrying insert is
    /// impossible, so the row cannot be anything but the real upgrade case.
    ///
    /// F1 was that the sweep SKIPPED exactly this row. An empty `pin_sources_for_oid`
    /// left the `for repo_id in sources` body unentered while the cursor had already
    /// advanced past it, so the row kept its provider key and stayed unresolvable with
    /// nothing left to fix it. The pre-sweep assertion below brackets the repair, so
    /// the serve at the end cannot pass vacuously on a row that was already fine.
    #[sqlx::test]
    async fn sweep_repairs_pre_provenance_upgrade_row_and_serves(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["preprov"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("preprov.git");
        let repo = seed_repo(&owner_did, "preprov"); // public, no rule
        state.db.create_repo(&repo).await.expect("seed repo");

        // Un-apply the provenance schema: the node is back at the shape it had before
        // v19 and v20, where a pin could not carry provenance at all.
        sqlx::query("DROP TABLE IF EXISTS pin_repo_sources")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE pinned_cids DROP COLUMN IF EXISTS repo_id")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version IN (19, 20)")
            .execute(&pool)
            .await
            .unwrap();

        // The legacy row, INSERTed naming only the columns that exist at this schema.
        // `seed_legacy_pin` cannot be reused here: it binds `repo_id`, which is the one
        // thing this fixture is proving the row never had.
        let (_ty, bytes) = crate::git::store::read_object(&bare, &fx.public_oid)
            .expect("read object bytes")
            .expect("object exists in the bare repo");
        let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(&bytes).to_string();
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        assert_ne!(
            provider_cid, raw_cid,
            "the legacy key differs from the raw resolver key"
        );
        sqlx::query("INSERT INTO pinned_cids (sha256_hex, cid, pinned_at) VALUES ($1, $2, $3)")
            .bind(&fx.public_oid)
            .bind(&provider_cid)
            .bind("2020-01-01T00:00:00Z")
            .execute(&pool)
            .await
            .unwrap();

        // Upgrade forward. The row now reads as the exact F1 shape: no first-pinner, no
        // source rows, and no incompleteness signal either, so emptiness is the only
        // thing the sweep has to go on.
        state
            .db
            .run_migrations()
            .await
            .expect("re-apply the provenance migrations");
        let first_pinner: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM pinned_cids WHERE sha256_hex = $1")
                .bind(&fx.public_oid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            first_pinner.is_none(),
            "the upgraded row carries no first-pinner: the column did not exist when it \
             was written"
        );
        assert!(
            state
                .db
                .pin_sources_for_oid(&fx.public_oid)
                .await
                .unwrap()
                .is_empty(),
            "the upgraded row has no recorded source of any kind"
        );
        assert!(
            !state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "and no incompleteness marker either: an upgrade row is indistinguishable \
             from a healthy one except by being empty"
        );

        // The bracket: while the row is unrepaired the resolver withholds it, so the
        // raw key a correct client sends does not serve.
        let (st_before, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_ne!(
            st_before,
            StatusCode::OK,
            "the raw key does not serve while the row is still keyed on the provider CID"
        );

        let stats = crate::ipfs_pin::sweep_legacy_provider_cids(
            std::path::Path::new("/tmp"),
            &state.git_bin,
            std::time::Duration::from_secs(state.config.git_service_timeout_secs),
            16,
            std::time::Duration::ZERO,
            &state.db,
            &mut Default::default(),
        )
        .await;
        assert_eq!(
            stats.repaired, 1,
            "the sweep repairs the pre-provenance upgrade row"
        );

        let (stored, stashed) = stored_pin(&pool, &fx.public_oid).await;
        assert_eq!(
            stored, raw_cid,
            "the key is rewritten to the raw-content resolver key"
        );
        assert_eq!(
            stashed.as_deref(),
            Some(provider_cid.as_str()),
            "the old provider CID is stashed rather than dropped"
        );
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![repo.id.clone()],
            "the repo discovery read the bytes from is recorded as a source"
        );
        let claimed: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM pinned_cids WHERE sha256_hex = $1")
                .bind(&fx.public_oid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            claimed.is_none(),
            "discovery records the holder ADDITIVELY: reading identical bytes proves \
             the repo holds the object, never that it pinned it first, so the exclusive \
             first-pinner column stays NULL"
        );
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "one discovered holder out of a bounded candidate set never proves the set \
             complete, so the resolver keeps its scan fallback for this row"
        );
        let marker: Vec<String> =
            sqlx::query_scalar("SELECT repo_id FROM pin_source_failures WHERE sha256_hex = $1")
                .bind(&fx.public_oid)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            marker,
            vec![String::new()],
            "the marker is against the UNKNOWN-repo sentinel, not the repo just \
             recorded: no real record can clear it"
        );

        // End to end: the repaired key serves the object's raw bytes to an anonymous
        // caller, which is the whole point of repairing it.
        let (st, body) = cid_bytes(
            cid_router(&state)
                .oneshot(cid_anon(&raw_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "the repaired raw key serves");
        assert_eq!(
            body, bytes,
            "the served body is the object's raw content, byte for byte"
        );
    }

    /// F1 scenario 10 (#173, the unsafe-path arm of the candidate load): a `repos` row
    /// whose name cannot be turned into a validated disk path is dropped when the
    /// candidate list is built, and the drop is both TERMINAL and NON-FATAL.
    ///
    /// Terminal: nothing a later pass does makes an unsafe name safe, so the rejection
    /// must not mark the row retryable and must not consume a probe against
    /// `MAX_LEGACY_DISCOVERY_PROBES`.
    ///
    /// Non-fatal is the half that matters most. `load_discovery_ctx` builds ONE list for
    /// the whole pass, so a rejection that propagated instead of warning would fail the
    /// load, `discover_legacy_row` would return Retryable for every source-less row in
    /// the pass, and a single unsafe `repos` row anywhere on the node would strand every
    /// legacy row behind it on every future run. Here the unsafe row sorts first (the
    /// candidate order is oldest-first by `(created_at, id)`), so the pass has to survive
    /// it before it can reach the warm holder that actually repairs the row.
    #[sqlx::test]
    async fn sweep_discovery_drops_unsafe_candidate_and_keeps_going(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["safesrc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("safesrc.git");

        // `validate_repo_name` bails on a '..' sequence, so this name can never resolve
        // to a disk path. Asserted against the validator itself rather than assumed, so
        // the fixture cannot quietly become a safe name and turn the test vacuous.
        let bad_name = "../escape";
        assert!(
            crate::git::repo_store::validated_repo_disk_path(
                std::path::Path::new("/tmp"),
                &owner_did,
                bad_name,
            )
            .is_err(),
            "the fixture name is genuinely refused by the validated resolver"
        );

        let mut unsafe_repo = seed_repo(&owner_did, bad_name);
        unsafe_repo.created_at = Utc::now() - chrono::Duration::days(2);
        let holder = seed_repo(&owner_did, "safesrc");
        state
            .db
            .create_repo(&unsafe_repo)
            .await
            .expect("seed the unsafe repos row");
        state
            .db
            .create_repo(&holder)
            .await
            .expect("seed the warm holder");

        // The pre-provenance shape: NULL repo_id and no pin_repo_sources row.
        let (raw_cid, _provider) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        crate::ipfs_pin::reset_legacy_repair_reads();
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("an unsafe candidate never wedges the pass");

        assert_eq!(
            stats.repaired, 1,
            "the rejection is non-fatal: a later safe candidate in the same list still \
             repairs the row"
        );
        assert_eq!(
            crate::ipfs_pin::legacy_repair_reads(),
            1,
            "the unsafe candidate is dropped before any probe, so the only object read \
             is the warm holder's"
        );
        assert_eq!(
            stats.retryable_skips, 0,
            "an unsafe name is not a condition a later pass clears, so the drop is \
             terminal and drives no cursor rewind"
        );
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the key is rewritten from the safe candidate's verified bytes"
        );
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![holder.id.clone()],
            "only the safe candidate is recorded as a source"
        );
    }

    /// Strip Rust line comments, block comments and double-quoted string literals,
    /// leaving code. Used by the source scan below, which must not fire on the prose
    /// that DESCRIBES the forbidden call (`ipfs_pin.rs` names `repo_store.acquire` in
    /// two comments) and must still fire on the call itself.
    fn code_only(src: &str) -> String {
        let mut out = String::with_capacity(src.len());
        let b: Vec<char> = src.chars().collect();
        let mut i = 0;
        while i < b.len() {
            if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
            } else if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
                i += 2;
                while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            } else if b[i] == '"' {
                i += 1;
                while i < b.len() && b[i] != '"' {
                    if b[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    /// The call-shape half of the sweep's no-remote-fetch guarantee, and a STRUCTURAL
    /// guard, not a behavioral one. Say what that means before trusting it.
    ///
    /// The sweep must never pull a cold repo back from remote storage: it is
    /// opportunistic background maintenance over every pinned row on the node, so a
    /// fetch would turn a repair pass into a bulk restore. A behavioral test that made
    /// the candidate cold, made it fetchable from a live remote, and counted zero fetch
    /// attempts cannot be built here, and the reason is worth stating rather than
    /// working around: `sweep_pass` takes a `repos_dir`, a `git_bin` and a `&Db`, and
    /// holds no `RepoStore` and no `TigrisClient`. A download counter armed on a store
    /// the TEST builds could never move no matter what the sweep did, so a zero from it
    /// would be vacuous by construction rather than evidence.
    ///
    /// So the guarantee is asserted from two sides instead. The effect side lives in
    /// `sweep_discovery_cold_candidates_do_not_rewind`, which proves the bytes were
    /// still available and the cold candidate's path was still absent after two full
    /// runs. This is the call side: the module's production code contains none of the
    /// fetch-capable call shapes.
    ///
    /// What it does NOT cover: a fetch reached indirectly through a helper this module
    /// calls (`git::store`, `db`) whose own source is not scanned, and git's own lazy
    /// fetch if a bare repo on disk were ever configured as a partial clone with a
    /// promisor remote. Neither shape exists today; neither is detected here.
    #[test]
    fn sweep_module_never_calls_a_remote_fetch() {
        const SRC: &str = include_str!("ipfs_pin.rs");
        // Scan the PRODUCTION half only. The module's own test module legitimately
        // calls `pool.acquire()`, which shares a needle with the store's fetch entry
        // points and would otherwise force the needle set to be weakened.
        let marker = "\n#[cfg(test)]\nmod tests {";
        let cut = SRC
            .find(marker)
            .expect("ipfs_pin.rs still opens its test module the usual way");
        let production = &SRC[..cut];
        let code = code_only(production);

        // Anti-vacuity, three ways: a scan that read nothing, a stripper that ate the
        // code, or a stripper that left the comments in would each let this pass while
        // proving nothing.
        assert!(
            code.len() > 10_000,
            "the scan kept only {} chars of production code, so a clean result proves \
             nothing",
            code.len()
        );
        assert!(
            code.contains("validated_repo_disk_path"),
            "the stripper removed real code: the sweep's own path resolver is gone from \
             what was scanned"
        );
        assert!(
            production.contains("repo_store.acquire"),
            "the module no longer names the forbidden call in prose, so this scan is no \
             longer exercising the comment-vs-code distinction it exists to make"
        );
        assert!(
            !code.contains("bulk restore"),
            "the stripper left comments in, so every needle below would fire on the \
             prose that describes it rather than on a call"
        );

        // Every way this crate reaches remote storage. `repo_store::` alone is not a
        // needle: the sweep legitimately calls `repo_store::validated_repo_disk_path`,
        // the non-fetching path resolver.
        for shape in [
            ".acquire(",
            "acquire_fresh",
            "acquire_write",
            "RepoStore",
            "TigrisClient",
            ".download(",
            "tigris",
        ] {
            assert!(
                !code.contains(shape),
                "the sweep's production code reaches remote storage through `{shape}`. \
                 A repair pass over every pinned row on the node must never pull a cold \
                 repo back: that is a bulk restore, not maintenance"
            );
        }
    }

    /// Poll until some backend in THIS test's database is blocked on a lock, so a test
    /// that means to drive an interleaving cannot silently degrade into two calls that
    /// simply ran one after the other. Returns false if nothing ever blocked.
    async fn wait_for_lock_wait(pool: &PgPool) -> bool {
        for _ in 0..600 {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                  WHERE datname = current_database() AND wait_event_type = 'Lock'",
            )
            .fetch_one(pool)
            .await
            .unwrap_or(0);
            if waiting > 0 {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    /// GAP 2: discovery's `record_pin_source` then `mark_pin_sources_incomplete` pair
    /// under a REAL concurrent writer on the same row, not a reasoned ordering.
    ///
    /// The order is load-bearing because a `record_pin_source` that actually inserts
    /// CLEARS the marker in its own transaction (`rows_affected > 0`), so marking first
    /// would have discovery wipe its own marker. The resolver's `needs_scan` is
    /// `sources.is_empty() || at_cap || incomplete`, so a non-empty, below-cap, unmarked
    /// set is what tells it to stop scanning. Discovery's knowledge is never complete
    /// (it stops at the first hit, and its candidate list is capped), so that
    /// combination is exactly the state the row must not end in.
    ///
    /// The interleaving driven here is the one that threatens the pair: a second writer
    /// recording a DIFFERENT source for the same oid lands while discovery is mid-row.
    /// A row lock parks the sweep inside `repair_legacy_provider_cid`, which is after
    /// the source set was read as empty and before either of discovery's own writes, and
    /// `wait_for_lock_wait` proves the sweep really is parked rather than already done.
    /// The end state must still be a marked row.
    #[sqlx::test]
    async fn sweep_discovery_marker_survives_a_concurrent_source_record(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["concwarm"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("concwarm.git");
        let holder = seed_repo(&owner_did, "concwarm");
        state.db.create_repo(&holder).await.expect("seed holder");
        // The concurrent writer's repo has no directory on disk, so it is filtered out
        // of the candidate list and the only thing it contributes to the row is its own
        // `record_pin_source`.
        let other = seed_repo(&owner_did, "conccold");
        state.db.create_repo(&other).await.expect("seed other");

        let (raw_cid, _provider) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        let mut blocker = pool.begin().await.expect("open the blocking transaction");
        sqlx::query("SELECT sha256_hex FROM pinned_cids WHERE sha256_hex = $1 FOR UPDATE")
            .bind(&fx.public_oid)
            .execute(&mut *blocker)
            .await
            .expect("hold the row lock");

        let driver = async {
            let parked = wait_for_lock_wait(&pool).await;
            state
                .db
                .record_pin_source(&fx.public_oid, &other.id)
                .await
                .expect("the concurrent record lands");
            blocker.commit().await.expect("release the row lock");
            parked
        };
        let mut traversal = Default::default();
        let (stats, parked) = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::join!(
                crate::ipfs_pin::sweep_legacy_provider_cids(
                    std::path::Path::new("/tmp"),
                    &state.git_bin,
                    git_timeout,
                    16,
                    std::time::Duration::ZERO,
                    &state.db,
                    &mut traversal,
                ),
                driver
            )
        })
        .await
        .expect("the interleaved run terminates");

        assert!(
            parked,
            "nothing ever blocked, so the two writers did not actually interleave and \
             this test proved nothing about ordering"
        );
        assert_eq!(stats.repaired, 1, "discovery still repairs the row");
        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the key is rewritten to the raw-content CID"
        );
        let mut sources = state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap();
        sources.sort();
        let mut expected = vec![holder.id.clone(), other.id.clone()];
        expected.sort();
        assert_eq!(
            sources, expected,
            "both writers' sources are present: the record is additive, so neither \
             writer erases the other"
        );
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "the marker survives a concurrent record landing inside discovery's window: \
             a non-empty, below-cap, unmarked set would tell the resolver to stop \
             scanning while discovery's knowledge of the set is still incomplete"
        );
        assert_eq!(
            pinned_repo_id(&pool, &fx.public_oid).await,
            None,
            "no exclusive first-pinner claim is made under concurrency either"
        );
    }

    /// GAP 2, the other interleaving: two sweep passes over the same source-less row at
    /// the same time. Whichever order the two passes' `repair_legacy_provider_cid`,
    /// `record_pin_source` and `mark_pin_sources_incomplete` calls land in, the end
    /// state the resolver reads must be the same one a single pass leaves: the raw key,
    /// exactly one recorded source, no exclusive claim, and a marked row.
    ///
    /// The second pass cannot double-record: `record_pin_source` is
    /// `ON CONFLICT DO NOTHING` on `(oid, repo)`, so its insert affects no rows, its
    /// marker clear is gated on `rows_affected > 0` and does not run, and its own
    /// `mark_pin_sources_incomplete` is idempotent.
    #[sqlx::test]
    async fn sweep_discovery_two_concurrent_passes_leave_one_marked_source(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;
        let git_timeout = std::time::Duration::from_secs(state.config.git_service_timeout_secs);

        let fx = seed_cid_repos(&slug, &short, &["twopass"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("twopass.git");
        let holder = seed_repo(&owner_did, "twopass");
        state.db.create_repo(&holder).await.expect("seed holder");
        let (raw_cid, _provider) = seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        let (mut ta, mut tb) = (Default::default(), Default::default());
        let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::join!(
                crate::ipfs_pin::sweep_legacy_provider_cids_once(
                    std::path::Path::new("/tmp"),
                    &state.git_bin,
                    git_timeout,
                    16,
                    &state.db,
                    &mut ta,
                ),
                crate::ipfs_pin::sweep_legacy_provider_cids_once(
                    std::path::Path::new("/tmp"),
                    &state.git_bin,
                    git_timeout,
                    16,
                    &state.db,
                    &mut tb,
                )
            )
        })
        .await
        .expect("both passes terminate");
        let a = a.expect("the first pass succeeds");
        let b = b.expect("the second pass succeeds");
        assert!(
            a.repaired + b.repaired >= 1,
            "at least one of the two concurrent passes repairs the row"
        );

        assert_eq!(
            stored_pin(&pool, &fx.public_oid).await.0,
            raw_cid,
            "the key is the raw-content CID whichever pass got there first"
        );
        assert_eq!(
            state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap(),
            vec![holder.id.clone()],
            "the holder is recorded exactly once: the second pass's insert conflicts and \
             affects no rows"
        );
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "two concurrent passes still leave the row marked, so the resolver keeps its \
             fallback scan"
        );
        assert_eq!(
            pinned_repo_id(&pool, &fx.public_oid).await,
            None,
            "neither pass makes an exclusive first-pinner claim"
        );
    }

    /// GAP 2, CLOSED (#173 round 12), kept as the regression that proves it stays closed.
    ///
    /// This documented a residual: `pin_sources_incomplete` was one boolean per OBJECT, so
    /// any later inserting `record_pin_source` cleared it, including one from a repo with
    /// nothing to do with discovery, leaving a non-empty source set and no marker, which
    /// is the combination that stops the resolver's fallback scan. The marker is now per
    /// `(object, repo)` and a record clears only its own pair, so a later writer cannot
    /// clear what discovery set.
    ///
    /// Discovery marks against the unknown-repo sentinel rather than a real repo id,
    /// because what it knows is that its bounded warm-only probe may have missed a holder,
    /// not that any particular repo failed to record. No real record equals that sentinel,
    /// which is what makes the marker survive here.
    #[sqlx::test]
    async fn sweep_discovery_marker_survives_a_later_record_from_another_repo(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool.clone()).await;

        let fx = seed_cid_repos(&slug, &short, &["latewarm"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("latewarm.git");
        let holder = seed_repo(&owner_did, "latewarm");
        state.db.create_repo(&holder).await.expect("seed holder");
        let other = seed_repo(&owner_did, "latecold");
        state.db.create_repo(&other).await.expect("seed other");
        seed_legacy_pin(&pool, &bare, &fx.public_oid, None).await;

        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            crate::ipfs_pin::sweep_legacy_provider_cids(
                std::path::Path::new("/tmp"),
                &state.git_bin,
                std::time::Duration::from_secs(state.config.git_service_timeout_secs),
                16,
                std::time::Duration::ZERO,
                &state.db,
                &mut Default::default(),
            ),
        )
        .await
        .expect("the sweep terminates");
        assert_eq!(stats.repaired, 1, "discovery repairs the row");
        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "discovery leaves the row marked"
        );

        // A genuine later pusher of the same object from a different repo.
        state
            .db
            .record_pin_source(&fx.public_oid, &other.id)
            .await
            .expect("the later record lands");

        assert!(
            state
                .db
                .pin_sources_incomplete(&fx.public_oid)
                .await
                .unwrap(),
            "a later record from another repo clears only its own pair, so discovery's \
             marker survives and the resolver keeps its fallback"
        );
        let mut sources = state.db.pin_sources_for_oid(&fx.public_oid).await.unwrap();
        sources.sort();
        let mut expected = vec![holder.id.clone(), other.id.clone()];
        expected.sort();
        assert_eq!(
            sources, expected,
            "the bound on that residual: every source left in the set is a repo that \
             really holds the object, so the row stays servable through them"
        );
    }

    /// U4 scenario 6 (#173): `list_pinned_cids` never advertises a key the `/ipfs`
    /// resolver would withhold. The resolver recomputes the raw CIDv1 from the object
    /// bytes and 404s any row keyed on a legacy PROVIDER CID, so advertising that key
    /// hands clients a CID this node deliberately refuses. Both states of ONE row are
    /// asserted (omitted while legacy, present once repaired) so the test cannot pass
    /// by accident. RED before the `is_raw_cidv1` filter lands: the legacy row is
    /// advertised.
    #[sqlx::test]
    async fn list_pinned_cids_omits_unrepaired_legacy_row(pool: PgPool) {
        let state = test_state(pool).await;

        let raw_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"u4 advertise bytes").to_string();
        let provider_cid = legacy_dagpb_cid(&raw_cid);
        let oid = "c".repeat(64);
        state
            .db
            .record_pinned_cid(&oid, &provider_cid, None)
            .await
            .unwrap();

        let listed = state.db.list_pinned_cids().await.unwrap();
        assert!(
            !listed.iter().any(|r| r.sha256_hex == oid),
            "an unrepaired legacy provider-CID row is not advertised"
        );

        // Same row, repaired: it comes back, keyed on the raw CID the resolver serves.
        state
            .db
            .repair_legacy_provider_cid(&oid, &raw_cid, &provider_cid)
            .await
            .unwrap();
        let listed = state.db.list_pinned_cids().await.unwrap();
        let rec = listed
            .iter()
            .find(|r| r.sha256_hex == oid)
            .expect("the repaired row is advertised again");
        assert_eq!(
            rec.cid, raw_cid,
            "the advertised key is the raw-content resolver key"
        );
    }

    /// #173 (provenance-path throttle): a walk-requiring provenanced candidate whose
    /// per-IP walk quota is spent returns 429 (the provenance arm's Throttled outcome,
    /// then the fall-through). quota=1, keyed on XFF. The first reader request runs the
    /// walk and spends the token; the second from the same IP is throttled → 429.
    #[sqlx::test]
    async fn ipfs_cid_provenance_walk_throttle_returns_429(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let reader = Keypair::generate();
        let reader_did = reader.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        let fx = seed_cid_repos(&slug, &short, &["provthrottle"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("provthrottle.git");
        let repo = seed_repo(&owner_did, "provthrottle");
        state.db.create_repo(&repo).await.expect("seed repo");
        state
            .db
            .set_visibility_rule(
                &repo.id,
                "/secret/**",
                VisibilityMode::B,
                std::slice::from_ref(&reader_did),
                &owner_did,
            )
            .await
            .expect("path rule");
        let cid = pin_cid_for_repo(&bare, &fx.secret_oid, &state.db, &repo.id).await;

        // 1st reader request runs the walk (reader is allowed) and spends the token.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed_xff(&reader, &cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "1st provenance walk from the IP serves");

        // 2nd request from the same IP: the walk is throttled → 429 (provenance path).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed_xff(&reader, &cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::TOO_MANY_REQUESTS,
            "a throttled provenance walk returns 429"
        );
    }

    /// #173 (multi-oid dispatch, mixed provenance + legacy): one CID mapping to a
    /// provenanced-then-denied oid AND a legacy (NULL-provenance) oid must still resolve
    /// to the legacy-servable copy — the provenance arm's skip does not abort the loop.
    #[sqlx::test]
    async fn ipfs_cid_mixed_provenance_and_legacy_serves_legacy(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["mixpriv", "mixpub"]);

        // Private repo holds secret_oid, pinned with provenance = itself (denies anon).
        let mut priv_repo = seed_repo(&owner_did, "mixpriv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private");
        // Public repo holds public_oid, legacy pin (NULL provenance -> scan serves it).
        let pub_repo = seed_repo(&owner_did, "mixpub");
        state.db.create_repo(&pub_repo).await.expect("seed public");

        // One REAL CID (the non-unique cid index) maps to BOTH oids: the public oid as a
        // legacy (NULL) pin, and the secret oid provenanced to the private repo.
        let pub_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("mixpub.git");
        let shared_cid = pin_cid_for(&pub_bare, &fx.public_oid, &state.db).await;
        state
            .db
            .record_pinned_cid(&fx.secret_oid, &shared_cid, Some(&priv_repo.id))
            .await
            .unwrap();

        // Anon: secret_oid (provenance -> private -> denied), public_oid (legacy -> scan
        // -> public -> served). Resolves to the public copy regardless of oid order.
        let resp = cid_router(&state)
            .oneshot(cid_anon(&shared_cid))
            .await
            .unwrap();
        let served = resp
            .headers()
            .get("x-git-hash")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (st, body) = cid_parts(resp).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a CID mixing a provenanced-denied oid and a legacy-servable oid resolves"
        );
        assert_eq!(
            served.as_deref(),
            Some(fx.public_oid.as_str()),
            "the served object is the legacy public oid"
        );
        assert!(
            body.contains("public bytes"),
            "the public content is served"
        );
    }

    // ---- #173 round 3: legacy (NULL-provenance) scan bound + 503-on-truncation ----
    // The provenance path targets one repo and is already bounded. These cover the
    // legacy scan fallback, where an anonymous request could otherwise fan out to
    // O(repos) `acquire` + `cat-file` probes (F1) and a walk-cap truncation could
    // false-404 an object that may be readable (F2). The bound is a per-request probe
    // BUDGET, not a per-IP brake: a walk-free public fetch stays un-rate-limited
    // (ipfs_walk_rate_limited_per_source), while the expensive walk keeps its IP brake.

    /// #173 round 12 (jatmn): a failure of the SIZE stage must reach the client as the
    /// retryable 503, never as a definitive 404. `object_size_bounded` mapped every
    /// non-timeout failure to `Ok(None)`, which `gate_and_serve` read as a verified
    /// absence and did not taint the search for, so a corrupt object or a failed spawn
    /// 404'd an authorized caller on an object the type probe had just reported present.
    ///
    /// The failure is induced between the two stages with a test seam, because the size
    /// read uses the real `git` rather than `state.git_bin` and no shim can be injected
    /// there. The BEFORE request is what makes the AFTER assertion mean anything: it
    /// proves this fixture serves 200 when the size read succeeds, so the 503 is caused
    /// by the broken size probe and nothing else.
    #[sqlx::test]
    async fn ipfs_cid_size_probe_failure_is_retryable_not_a_404(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["sizefault"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("sizefault.git");
        let repo = seed_repo(&owner_did, "sizefault"); // public, no rule
        state.db.create_repo(&repo).await.expect("seed repo");
        let cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo.id).await;

        let (before, body) =
            cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            before,
            StatusCode::OK,
            "the fixture serves this object when the size read succeeds"
        );
        assert!(body.contains("public bytes"), "and serves the real content");

        // The object vanishes between the type probe and the size probe. Armed on THIS
        // repo's path: fixture oids are shared across tests, so an oid-only key would
        // reach into another test's repo.
        crate::api::ipfs::break_size_probe_for(&bare, &fx.public_oid);
        let (after, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            after,
            StatusCode::SERVICE_UNAVAILABLE,
            "a size-stage fault taints the search and tails to a retryable 503; a 404 here \
             would tell an authorized caller the object does not exist"
        );
    }

    /// T1 (F1): the probe budget gates BEFORE `acquire`/`cat-file`, so it genuinely
    /// bounds the fan-out — a repo past the budget is never probed, even one that
    /// WOULD serve. With the budget at 0, a PUBLIC legacy copy that would otherwise
    /// serve 200 is not probed at all → 503 truncated (absence unproven). RED before
    /// the budget check (the repo is probed and serves 200).
    #[sqlx::test]
    async fn ipfs_cid_legacy_probe_budget_gates_before_serving(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_max_legacy_probes = 0; // probe nothing → any legacy candidate truncates

        let fx = seed_cid_repos(&slug, &short, &["pubprobe"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("pubprobe.git");
        let repo = seed_repo(&owner_did, "pubprobe"); // public, no path rule → would serve
        state.db.create_repo(&repo).await.expect("seed repo");
        // Legacy pin (NULL provenance) → resolver takes the scan fallback.
        let cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;

        let (st, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "the probe budget gates before the probe: a servable copy past the budget is not reached → 503"
        );
    }

    /// T7 (F1/F3 pre-limit): EVERY legacy probe is braked on the source IP from the
    /// FIRST one, so a hostile caller cannot repeatedly force the whole-node `acquire`
    /// fan-out across requests (each cold `acquire` is a Tigris round-trip, INV-10).
    /// Since #173-F3 (jatmn) there is no free budget: a single-repo legacy scan is
    /// itself charged. quota=1 keyed on XFF, one PUBLIC legacy copy that serves
    /// walk-free (never touches the walk brake), so the second same-IP request can only
    /// be shed by the probe brake: req1 serves and spends the token, req2 → 429. RED
    /// before the probe brake (req2 serves 200). The cross-request bound this proves is
    /// exactly the amplification F3 closes.
    #[sqlx::test]
    async fn ipfs_cid_legacy_fanout_braked_on_ip_past_free_budget(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        // Budget = one full scan of the single seeded repo: 1 page + 1 probe. The page
        // is charged because the legacy scan's DB-facing pages draw on this same bucket
        // (#173 round 13, F2). Without that charge a denial-only inventory could be
        // re-paged for free by re-requesting. Production never sees a bucket this small:
        // `AppState::ipfs_work_budget` floors it at probes + pages, so only a fixture
        // that sets the limiter by hand has to do the arithmetic itself.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(2, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        let fx = seed_cid_repos(&slug, &short, &["fanout"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("fanout.git");
        let repo = seed_repo(&owner_did, "fanout"); // public, no path rule → walk-free serve
        state.db.create_repo(&repo).await.expect("seed repo");
        let cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await; // legacy pin

        let (st1, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon_xff(&cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st1,
            StatusCode::OK,
            "1st legacy fan-out probe from the IP serves"
        );

        let (st2, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon_xff(&cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st2,
            StatusCode::TOO_MANY_REQUESTS,
            "with no free budget, a repeat fan-out from the same IP is braked at the first probe"
        );
    }

    /// F3 (jatmn, across-request amplification): the pre-fix free-probe budget was
    /// PER REQUEST, so a caller could repeat a known NULL-provenance CID and force a
    /// fresh batch of `acquire` + `cat-file` probes every request with zero limiter
    /// contact, unbounded anonymous amplification against Tigris. Charging every
    /// legacy probe from the first one makes those probes accumulate against the
    /// per-IP `ipfs_work_rate_limiter` ACROSS requests. Four repos, none holding the CID,
    /// so a full scan probes all four; the per-IP budget is sized to exactly ONE such
    /// scan (4 tokens). req1 (a genuine absence) fully scans and 404s, spending the
    /// budget; req2 from the SAME IP is shed at the first probe → 429 (it never
    /// re-runs the four `acquire` probes). RED with the old free carve-out restored:
    /// req2 re-scans un-braked and 404s again (the amplification stays open). This is
    /// the load-bearing across-request bound F3 asks for.
    #[sqlx::test]
    async fn ipfs_cid_legacy_fanout_bounded_across_requests(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        // Budget = one full scan of the four seeded repos: 1 page + 4 probes. A repeat
        // scan from the same IP then finds it spent. Keyed on XFF so `oneshot` can
        // choose the source IP. The page term is there because the scan's DB-facing
        // pages draw on this same bucket (#173 round 13, F2), so re-requesting cannot
        // buy the inventory again for free; all four repos fit in one 128-row page, so
        // one page covers the whole scan. Production is floored at probes + pages by
        // `AppState::ipfs_work_budget`; only a hand-set limiter does this arithmetic.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(5, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        let names = ["a0", "a1", "a2", "a3"];
        let _fx = seed_cid_repos(&slug, &short, &names);
        for n in names {
            let repo = seed_repo(&owner_did, n);
            state.db.create_repo(&repo).await.expect("seed repo");
        }
        // A legacy pin whose oid is absent from every repo → each probed repo misses,
        // so req1 scans all four (spending the four-token budget) and 404s cleanly.
        let bogus_oid = "0".repeat(64);
        let cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"absent-across-requests").to_string();
        state
            .db
            .record_pinned_cid(&bogus_oid, &cid, None)
            .await
            .expect("record legacy pin");

        let (st1, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon_xff(&cid, "9.9.9.9"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st1,
            StatusCode::NOT_FOUND,
            "1st scan completes under budget: a genuine absence is a definitive 404"
        );

        let (st2, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon_xff(&cid, "9.9.9.9"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st2,
            StatusCode::TOO_MANY_REQUESTS,
            "2nd same-IP scan is shed at the first probe (429), not re-run un-braked: the across-request amplification is closed"
        );
    }

    /// #173 (jatmn round 8, F3 — INV-10 cost guard): an already-throttled source's
    /// legacy NULL-provenance request must be shed by the non-consuming admission peek
    /// BEFORE the O(repos) `scan_ctx` preload runs — not after, where the per-probe
    /// brake sits. The preload-query counter proves it both ways: 0 for the throttled
    /// replay, 1 for an unthrottled source. RED if the peek is removed (the preload runs
    /// while throttled → count 1). The two existing `_fanout_` tests confirm the per-
    /// probe consuming charge is untouched (no double-charge, no under-charge).
    #[sqlx::test]
    async fn ipfs_cid_f3_throttled_source_skips_preload(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        // Budget 1, keyed on XFF so `oneshot` can choose the source IP.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        let _fx = seed_cid_repos(&slug, &short, &["r0"]);
        state
            .db
            .create_repo(&seed_repo(&owner_did, "r0"))
            .await
            .expect("seed repo");
        // A legacy pin absent from every repo → the scan probes and 404s (spending the
        // one token on the first probe).
        let bogus_oid = "0".repeat(64);
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(b"f3-absent").to_string();
        state
            .db
            .record_pinned_cid(&bogus_oid, &cid, None)
            .await
            .expect("legacy pin");

        // Req1 from 9.9.9.9 spends the one token (and runs the preload once).
        let _ = cid_router(&state)
            .oneshot(cid_anon_xff(&cid, "9.9.9.9"))
            .await
            .unwrap();

        // Measure the throttled replay: the peek must shed it before the preload runs.
        crate::api::ipfs::reset_preload_queries();
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon_xff(&cid, "9.9.9.9"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::TOO_MANY_REQUESTS,
            "an already-throttled legacy replay is 429"
        );
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            0,
            "a throttled source must NOT run the O(repos) preload (F3): shed before scan_ctx"
        );

        // Control: an unthrottled source (a different IP) still runs the preload once —
        // the peek must not over-block.
        crate::api::ipfs::reset_preload_queries();
        let _ = cid_router(&state)
            .oneshot(cid_anon_xff(&cid, "8.8.8.8"))
            .await
            .unwrap();
        assert_eq!(
            crate::api::ipfs::preload_queries(),
            1,
            "an unthrottled source runs the preload once (the peek must not over-block)"
        );
    }

    /// T2 (F1): the legacy scan is bounded per request. With the probe ceiling shrunk
    /// to 2 and 3 candidate repos none of which hold the object, the 3rd repo is never
    /// probed and the search is reported truncated → 503, not an unbounded fan-out.
    /// RED before the probe cap (all 3 probe, none serve, definitive 404).
    #[sqlx::test]
    async fn ipfs_cid_legacy_scan_probe_cap_truncates_to_503(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_max_legacy_probes = 2;

        let _fx = seed_cid_repos(&slug, &short, &["r0", "r1", "r2"]);
        for n in ["r0", "r1", "r2"] {
            let repo = seed_repo(&owner_did, n);
            state.db.create_repo(&repo).await.expect("seed repo");
        }
        // A legacy pin whose oid is absent from every repo: each probed repo misses,
        // so the cap (not a hit) decides the outcome.
        let bogus_oid = "0".repeat(64);
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(b"absent-marker-t2").to_string();
        state
            .db
            .record_pinned_cid(&bogus_oid, &cid, None)
            .await
            .expect("record legacy pin");

        let (st, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "a scan truncated by the probe cap is a retryable 503, not a definitive 404"
        );
    }

    /// T2b (R5, KTD5): the `GITLAWB_IPFS_MAX_REPOS_WALKED` knob drives the legacy-probe
    /// budget end to end. With the knob at 1 (fed through the same production helper the
    /// state seeding uses) and two candidate repos that miss, the first repo spends the
    /// single probe and the second is skipped at the cap → truncated → 503. If the knob
    /// budget were not honoured (unbounded), both would probe, both miss, and the request
    /// would be a definitive 404. Proves the wired knob=1 → exactly one probe path.
    #[sqlx::test]
    async fn ipfs_cid_repos_walked_knob_caps_legacy_probes(pool: PgPool) {
        use clap::Parser;
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        // Seed the legacy-probe budget the way production does: from the operator knob.
        // The legacy-probe budget knob, renamed in the merge: #174 already owned
        // `--ipfs-max-repos-walked` for its expensive-walk cap, so #173's identically
        // named knob became `--ipfs-max-legacy-probes`.
        let cfg =
            crate::config::Config::parse_from(["gitlawb-node", "--ipfs-max-legacy-probes", "1"]);
        state.ipfs_max_legacy_probes = AppState::ipfs_legacy_probe_budget(&cfg);
        assert_eq!(state.ipfs_max_legacy_probes, 1, "knob=1 → one-probe budget");
        // The knob must not touch the history-walk ceiling (must stay MAX_PIN_SOURCES + 1).
        assert_eq!(
            state.ipfs_max_history_walks,
            crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST,
            "the repos-walked knob leaves the history-walk ceiling untouched"
        );

        let _fx = seed_cid_repos(&slug, &short, &["k0", "k1"]);
        for n in ["k0", "k1"] {
            let repo = seed_repo(&owner_did, n);
            state.db.create_repo(&repo).await.expect("seed repo");
        }
        // A legacy pin whose oid is absent from every repo: the cap, not a hit, decides.
        let bogus_oid = "0".repeat(64);
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(b"absent-marker-knob").to_string();
        state
            .db
            .record_pinned_cid(&bogus_oid, &cid, None)
            .await
            .expect("record legacy pin");

        let (st, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "knob=1 caps the scan at one probe → incomplete search → retryable 503"
        );
    }

    /// T3 (F2): a walk-cap truncation must not false-404. Walk ceiling shrunk to 1;
    /// two public repos each carry a path-scoped rule over the object and deny anon.
    /// The 1st spends the single walk (deny), the 2nd is skipped at the cap — the
    /// resolver did NOT prove the object unreadable everywhere, so 503, not 404.
    /// RED before the walk-cap `truncated` flag (returns the opaque 404).
    #[sqlx::test]
    async fn ipfs_cid_legacy_walk_cap_truncates_to_503(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let reader = Keypair::generate();
        let reader_did = reader.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_max_history_walks = 1;

        let fx = seed_cid_repos(&slug, &short, &["wa", "wb"]);
        for n in ["wa", "wb"] {
            let repo = seed_repo(&owner_did, n);
            state.db.create_repo(&repo).await.expect("seed repo");
            state
                .db
                .set_visibility_rule(
                    &repo.id,
                    "/secret/**",
                    VisibilityMode::B,
                    std::slice::from_ref(&reader_did),
                    &owner_did,
                )
                .await
                .expect("path rule");
        }
        // Legacy pin of the path-scoped secret blob (present in both repos, denies anon).
        let bare_wa = std::path::PathBuf::from("/tmp").join(&slug).join("wa.git");
        let cid = pin_cid_for(&bare_wa, &fx.secret_oid, &state.db).await;

        let (st, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "the walk cap truncated the scan, so absence is unproven → 503, not a false 404"
        );
    }

    /// T4 (must-not over-fire): a legacy CID genuinely absent from every repo on a
    /// node UNDER the probe cap still returns the definitive 404 — the 503 fires only
    /// on real truncation, never as a blanket replacement for not-found.
    #[sqlx::test]
    async fn ipfs_cid_legacy_true_absence_stays_404(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_max_legacy_probes = 8; // well above the single repo → no truncation

        let _fx = seed_cid_repos(&slug, &short, &["only"]);
        let repo = seed_repo(&owner_did, "only");
        state.db.create_repo(&repo).await.expect("seed repo");
        let bogus_oid = "0".repeat(64);
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(b"absent-marker-t4").to_string();
        state
            .db
            .record_pinned_cid(&bogus_oid, &cid, None)
            .await
            .expect("record legacy pin");

        let (st, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "a fully-scanned genuine absence is a definitive 404, not a 503"
        );
    }

    /// T5 (provenance path untouched): the probe cap governs ONLY the legacy scan.
    /// With the cap set to 0 (which would truncate any legacy probe immediately) a
    /// PROVENANCED pin still resolves to its one repo and serves 200 — proving the
    /// `legacy_scan=false` guard exempts the provenance path. RED if the guard were
    /// dropped (provenance would truncate to 503).
    #[sqlx::test]
    async fn ipfs_cid_provenance_serves_despite_zero_probe_cap(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_max_legacy_probes = 0; // would truncate every LEGACY probe

        let fx = seed_cid_repos(&slug, &short, &["provonly"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("provonly.git");
        let repo = seed_repo(&owner_did, "provonly"); // public, no path rule
        state.db.create_repo(&repo).await.expect("seed repo");
        let cid = pin_cid_for_repo(&bare, &fx.public_oid, &state.db, &repo.id).await;

        let (st, _) = cid_parts(cid_router(&state).oneshot(cid_anon(&cid)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "the provenance path ignores the legacy probe cap and serves"
        );
    }

    fn cid_router(state: &AppState) -> Router {
        Router::new()
            .route(
                "/ipfs/{cid}",
                axum::routing::get(crate::api::ipfs::get_by_cid),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state.clone())
    }
    async fn cid_parts(resp: axum::response::Response) -> (StatusCode, String) {
        let st = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (st, String::from_utf8_lossy(&b).to_string())
    }
    /// Raw body bytes (NOT lossy-decoded). A git tree body stores each child oid
    /// as 32 RAW bytes that `from_utf8_lossy` mangles to U+FFFD, so a hex
    /// `contains` check on `cid_parts`'s String is vacuous. #135 deny tests must
    /// witness the leak on these raw bytes.
    async fn cid_bytes(resp: axum::response::Response) -> (StatusCode, Vec<u8>) {
        let st = resp.status();
        let b = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (st, b.to_vec())
    }
    /// True if `needle` appears as a contiguous byte subsequence of `haystack`.
    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }
    fn cid_anon(cid: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/ipfs/{cid}"))
            .body(Body::empty())
            .unwrap()
    }
    /// Anonymous CID request carrying `x-forwarded-for: <ip>` — an anon caller with a
    /// resolvable source IP, so the per-IP walk brake keys on it (the walk still
    /// denies anon at a path rule).
    fn cid_anon_xff(cid: &str, xff_ip: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/ipfs/{cid}"))
            .header("x-forwarded-for", xff_ip)
            .body(Body::empty())
            .unwrap()
    }
    fn cid_signed(kp: &gitlawb_core::identity::Keypair, cid: &str) -> Request<Body> {
        let path = format!("/ipfs/{cid}");
        let s = gitlawb_core::http_sig::sign_request(kp, "GET", &path, b"");
        Request::builder()
            .method(Method::GET)
            .uri(&path)
            .header("content-digest", s.content_digest)
            .header("signature-input", s.signature_input)
            .header("signature", s.signature)
            .body(Body::empty())
            .unwrap()
    }
    /// Signed CID request carrying `x-forwarded-for: <ip>`. Used by the walk
    /// rate-limit test to key the per-IP limiter off a chosen source under
    /// `TrustedProxy::XForwardedFor` (the request goes through `oneshot`, which
    /// leaves no socket peer, so the header is the only key source).
    fn cid_signed_xff(
        kp: &gitlawb_core::identity::Keypair,
        cid: &str,
        xff_ip: &str,
    ) -> Request<Body> {
        let path = format!("/ipfs/{cid}");
        let s = gitlawb_core::http_sig::sign_request(kp, "GET", &path, b"");
        Request::builder()
            .method(Method::GET)
            .uri(&path)
            .header("content-digest", s.content_digest)
            .header("signature-input", s.signature_input)
            .header("signature", s.signature)
            .header("x-forwarded-for", xff_ip)
            .body(Body::empty())
            .unwrap()
    }

    /// #110: `GET /ipfs/{cid}` must gate a withheld blob by per-caller visibility.
    /// RED before U2 (the current handler serves the secret to anon).
    #[sqlx::test]
    async fn ipfs_cid_gate_withholds_blob_from_unauthorized(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let reader = Keypair::generate();
        let reader_did = reader.did().to_string();
        let stranger = Keypair::generate();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["withhold"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("withhold.git");
        // Request CIDs are the production pin CIDs (content-hash), recorded in
        // pinned_cids so get_by_cid resolves each back to its oid (#173).
        let secret_cid = pin_cid_for(&bare, &fx.secret_oid, &state.db).await;
        let tree_cid = pin_cid_for(&bare, &fx.secret_tree_oid, &state.db).await;
        let public_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;
        let root_tree_cid = pin_cid_for(&bare, &fx.root_tree_oid, &state.db).await;
        let public_tree_cid = pin_cid_for(&bare, &fx.public_tree_oid, &state.db).await;
        let commit_cid = pin_cid_for(&bare, &fx.commit_oid, &state.db).await;
        let tag_cid = pin_cid_for(&bare, &fx.tag_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "withhold"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "withhold")
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/secret/**",
                VisibilityMode::B,
                std::slice::from_ref(&reader_did),
                &owner_did,
            )
            .await
            .expect("deny rule");

        // anon → withheld blob: must 404, must not leak content. (RED on current handler.)
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&secret_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "anon must not read the withheld blob"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "404 body must not leak the secret"
        );

        // signed non-reader → 404.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed(&stranger, &secret_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "non-reader must not read the withheld blob"
        );
        assert!(!body.contains("TOP SECRET"));

        // owner (signed) → 200 + secret bytes.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed(&owner, &secret_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "owner reads the withheld blob");
        assert!(body.contains("TOP SECRET"), "owner gets the content");

        // listed reader (signed) → 200.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed(&reader, &secret_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "listed reader reads the blob");
        assert!(body.contains("TOP SECRET"));

        // #135: anon tree CID under withheld /secret → 404. The 404 body is an opaque
        // error string (never the object), so status is the load-bearing deny check;
        // the real leak witness is the CONTRAST with the reader below, who DOES get a
        // 200 carrying the child structure that anon is denied.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&tree_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "withheld subtree tree must not be served to anon (#135)"
        );

        // Over-denial guard + positive leak witness: the listed reader (signed) DOES
        // read the withheld subtree's tree, and its body carries the exact child
        // structure anon was denied — the child filename plus the child oid as the 32
        // RAW bytes a git tree stores (witnessed on raw bytes, since cid_parts's lossy
        // decode would mangle them). This proves b.txt / secret_raw are the real leak
        // markers and that the anon 404 above actually withheld them.
        let secret_raw = hex::decode(&fx.secret_oid).expect("hex oid");
        let (st, body) = cid_bytes(
            cid_router(&state)
                .oneshot(cid_signed(&reader, &tree_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "listed reader reads the withheld subtree tree"
        );
        assert!(
            bytes_contain(&body, b"b.txt") && bytes_contain(&body, &secret_raw),
            "reader's tree body carries the child filename and raw child oid"
        );

        // Root tree (path "/") stays served to anon who passes the "/" gate.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&root_tree_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "root tree stays served (must-serve)");

        // /public subtree tree stays served to anon (allowed path).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&public_tree_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "public subtree tree stays served");

        // Commit and annotated tag objects stay served (unchanged by #135).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&commit_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "commit object stays served");
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&tag_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "tag object stays served");

        // R3: public blob anon → 200 (non-withheld content not affected).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&public_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "public blob stays served");

        // R5: a genuine unknown CID also 404, uniform with the withheld 404. A
        // well-formed pin-style CID that was never recorded in pinned_cids, so the
        // oid_for_cid resolve misses (the production not-found path).
        let absent_cid =
            gitlawb_core::cid::Cid::from_git_object_bytes(b"never pinned to this node").to_string();
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&absent_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "absent CID 404 (uniform with withheld)"
        );

        // malformed CID → 400 (unchanged).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon("not-a-cid"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "malformed CID still 400");
    }

    /// R4: the same object withheld in one repo but public in another is still
    /// served from the public copy; the withholding repo is iterated first.
    #[sqlx::test]
    async fn ipfs_cid_served_from_public_copy_when_withheld_elsewhere(pool: PgPool) {
        use crate::db::VisibilityMode;
        use chrono::Utc;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["withhold", "pubcopy"]);
        // Same content in both clones -> same oid/CID; read from either.
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("withhold.git");
        let secret_cid = pin_cid_for(&bare, &fx.secret_oid, &state.db).await;

        // Withholding repo, iterated FIRST: the paged scan orders on the immutable
        // `(created_at, id)` ASC, so the OLDER created_at leads (#173, jatmn).
        let mut withhold = seed_repo(&owner_did, "withhold");
        withhold.created_at = Utc::now() - chrono::Duration::seconds(60);
        state
            .db
            .create_repo(&withhold)
            .await
            .expect("withhold repo");
        state
            .db
            .set_visibility_rule(
                &withhold.id,
                "/secret/**",
                VisibilityMode::B,
                &[],
                &owner_did,
            )
            .await
            .expect("deny rule");

        // Public copy, no rules, iterated AFTER (newer created_at).
        let mut pubcopy = seed_repo(&owner_did, "pubcopy");
        pubcopy.created_at = Utc::now();
        state.db.create_repo(&pubcopy).await.expect("pubcopy repo");

        // anon: denied at the withholding repo (continue), served from the public copy.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&secret_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "served from the public copy despite the other deny"
        );
        assert!(
            body.contains("TOP SECRET"),
            "the public copy serves the content"
        );
    }

    /// Repo-level "/" gate (KTD2a, first continue branch): a fully private repo
    /// (is_public=false, no rules) denies anon before any per-blob check; the
    /// owner still reads. The path-scoped tests pass the "/" gate and deny at the
    /// per-blob stage, so this exercises the coarser repo-level deny separately.
    #[sqlx::test]
    async fn ipfs_cid_private_repo_denies_anon_at_repo_gate(pool: PgPool) {
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["priv"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("priv.git");
        let blob_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;

        let mut rec = seed_repo(&owner_did, "priv");
        rec.is_public = false;
        state.db.create_repo(&rec).await.expect("private repo");

        // anon → repo-level deny → 404, no content leaked.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&blob_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "anon denied at a private repo's / gate"
        );
        assert!(!body.contains("public bytes"), "404 must not leak content");

        // owner-signed → 200.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed(&owner, &blob_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "owner reads their private repo's object"
        );
        assert!(body.contains("public bytes"), "owner gets the content");
    }

    /// Fail-closed walk-error arm: if `withheld_blob_oids` errors (here, a ref
    /// pointing at a non-tree-ish blob, which `git ls-tree -r` cannot traverse —
    /// the same induction as `visibility_pack::fails_closed_when_a_ref_cannot_be_traversed`),
    /// the handler skips the whole repo rather than serving. Asserts no leak of the
    /// withheld blob AND that even the *public* blob in that repo is withheld — the
    /// latter distinguishes fail-closed-skip from normal per-blob withholding and
    /// would serve 200 if the error arm wrongly proceeded. The skip carries no
    /// VERDICT (F2), so the response is the retryable truncation 503, not a 404
    /// claiming the object is absent — never-serve-unproven and never-404-unproven
    /// hold together.
    #[sqlx::test]
    async fn ipfs_cid_walk_error_fails_closed(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["withhold"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("withhold.git");
        // Recorded pins so get_by_cid resolves each CID to its oid and reaches the
        // walk; the 404s below are then the fail-closed skip, not a table miss.
        let secret_cid = pin_cid_for(&bare, &fx.secret_oid, &state.db).await;
        let public_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;

        // Force the withheld walk to fail closed: a ref pointing at a blob (not
        // tree-ish) makes `git ls-tree -r` error, which `withheld_blob_oids`
        // propagates as Err → the handler's `Ok(Err)` arm skips the repo.
        std::fs::write(
            bare.join("refs/heads/blobref"),
            format!("{}\n", fx.secret_oid),
        )
        .unwrap();

        state
            .db
            .create_repo(&seed_repo(&owner_did, "withhold"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "withhold")
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("deny rule");

        // Withheld secret CID under a walk error → the repo is skipped without a
        // verdict, so the scan is truncated (503), and nothing leaks.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&secret_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "walk error must not serve the withheld blob — the unproven skip sheds 503"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "walk-error 503 must not leak the secret"
        );

        // The PUBLIC blob in the same repo is also not served: the walk error fails
        // closed by skipping the whole repo. Without the fail-closed arm this would
        // serve 200, so this assertion is the load-bearing discriminator.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&public_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "walk error fails closed: repo skipped without a verdict, even the public \
             blob is not served and the scan sheds 503"
        );
    }

    /// #173 review (F2): the commit/tag reachability walk must FAIL CLOSED on a git
    /// error, exactly like the blob/tree walk. A ref pointing at a nonexistent object
    /// makes `rev-list --all` fail, so `reachable_commit_tag_oids` returns Err, which
    /// the handler's shared `Ok(Err) => continue` arm turns into a repo skip. The
    /// load-bearing discriminator is that the PUBLIC commit is ALSO 404: if the arm
    /// fail-OPENed (served on error) it would 200. Drives the commit/tag branch of
    /// the shared fail-closed arm specifically (the sibling test covers blob/tree).
    #[sqlx::test]
    async fn ipfs_cid_commit_tag_walk_error_fails_closed(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["cterr"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("cterr.git");
        // A reachable commit CID — would serve 200 if the walk succeeded.
        let commit_cid = pin_cid_for(&bare, &fx.commit_oid, &state.db).await;

        // A ref to a NONEXISTENT object: `git rev-list --all` fails ("bad object"),
        // so reachable_commit_tag_oids bails → the walk arm skips the repo.
        std::fs::write(
            bare.join("refs/heads/broken"),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
        )
        .unwrap();

        state
            .db
            .create_repo(&seed_repo(&owner_did, "cterr"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "cterr")
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("path rule");

        // Fail-closed: a walk error skips the repo, so even the otherwise-reachable
        // public commit is NOT served. A fail-OPEN arm would 200 here.
        //
        // The skip is a truncation, not an absence verdict (#174 F2): the walk failed,
        // so nothing was proven about whether this caller may read the object, and the
        // tail sheds a retryable 503 rather than the definitive 404 this asserted
        // before the merge. Withholding is the property under test either way; what
        // changed is that the response no longer claims the object is absent.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&commit_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "a commit/tag walk error must fail closed (repo skipped), never serve"
        );
    }

    /// #126: a dangling blob (written via `git hash-object -w`, never referenced
    /// by any commit/tree) must 404 through `GET /ipfs/{cid}` under path-scoped
    /// rules — for anon AND the owner. The pre-#126 deny-set was fail-open by
    /// construction: dangling oids were absent from the reachable enumeration
    /// and thus absent from the deny-set, so the handler served 200. The
    /// allowed-set is fail-closed: dangling oids are absent from the reachable
    /// allowed-set, so the handler 404s (per team memory: the owner shift to
    /// 404 is the accepted fail-closed default — owners can still
    /// `git cat-file` directly).
    #[sqlx::test]
    async fn ipfs_cid_dangling_blob_fails_closed_under_path_rules(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        // Seed a normal repo with `secret/b.txt` reachable from HEAD, so the
        // path-scoped rule has something to match — without this the rule has
        // no anchor and we'd be testing nothing.
        let _fx = seed_cid_repos(&slug, &short, &["dangling"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("dangling.git");

        // Write a dangling blob: `git hash-object -w --stdin` adds it to the
        // object DB but nothing references it, so the reachable walk never
        // enumerates it.
        let mut cmd = std::process::Command::new("git");
        cmd.args(["hash-object", "-w", "--stdin"])
            .current_dir(&bare)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let mut child = cmd.spawn().expect("spawn git hash-object");
        {
            use std::io::Write;
            let stdin = child.stdin.as_mut().expect("stdin");
            stdin.write_all(b"DANGLING SECRET\n").expect("write stdin");
        }
        let out = child.wait_with_output().expect("hash-object output");
        assert!(
            out.status.success(),
            "git hash-object: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let dangling_oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // Sanity: must be a 64-hex sha256 oid, since the repo is sha256-format.
        assert_eq!(
            dangling_oid.len(),
            64,
            "expected sha256 oid: {dangling_oid}"
        );
        // Record the pin so oid_for_cid resolves it — the 404 must then come from
        // the allowed-set gate excluding the dangling oid, not from a table miss.
        let dangling_cid = pin_cid_for(&bare, &dangling_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "dangling"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "dangling")
            .await
            .unwrap()
            .unwrap();
        // Path-scoped rule triggers the per-blob allowed-set gate (KTD4).
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("deny rule");

        // anon: the dangling blob is absent from the reachable allowed-set →
        // 404, no leak. Pre-#126 (deny-set) would serve 200.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&dangling_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "dangling blob must 404 under path-scoped rules"
        );
        assert!(
            !body.contains("DANGLING SECRET"),
            "404 body must not leak the dangling content"
        );

        // owner (signed): same 404. The dangling blob has no path, so it's
        // never visibility-checked → never in the allowed set, even for the
        // owner. This is the accepted fail-closed shift documented in the PR.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed(&owner, &dangling_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "owner also 404s on dangling blobs under path-scoped rules (fail-closed default)"
        );
        assert!(!body.contains("DANGLING SECRET"));
    }

    /// #135: a DANGLING tree (in the ODB, referenced by no commit) 404s under
    /// path-scoped rules for anon AND owner — the reachable-only allowed-tree-set
    /// never enumerates it. Handler-level companion to the helper test
    /// `allowed_tree_set_excludes_dangling_tree`, proving the `get_by_cid` tree arm
    /// (memo insert + `!in_allowed` continue) fails closed on the dangling case.
    #[sqlx::test]
    async fn ipfs_cid_dangling_tree_fails_closed_under_path_rules(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["dangtree"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("dangtree.git");

        // Dangling tree via `git mktree`: a UNIQUE entry name so its oid is
        // content-distinct from every reachable tree (a content-identical tree would
        // dedup to a reachable oid — that is T2, not danglingness).
        let mut child = std::process::Command::new("git")
            .args(["mktree"])
            .current_dir(&bare)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn git mktree");
        {
            use std::io::Write;
            writeln!(
                child.stdin.as_mut().unwrap(),
                "100644 blob {}\tdangling-only-unreferenced.txt",
                fx.secret_oid
            )
            .unwrap();
        }
        let out = child.wait_with_output().expect("mktree output");
        assert!(
            out.status.success(),
            "git mktree: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let dangling_tree_oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_eq!(dangling_tree_oid.len(), 64, "expected sha256 oid");
        // Record the pin so the 404 is the allowed-tree-set gate excluding the
        // dangling tree, not a table miss.
        let dangling_cid = pin_cid_for(&bare, &dangling_tree_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "dangtree"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "dangtree")
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("deny rule");

        for req in [cid_anon(&dangling_cid), cid_signed(&owner, &dangling_cid)] {
            let (st, _) = cid_parts(cid_router(&state).oneshot(req).await.unwrap()).await;
            assert_eq!(
                st,
                StatusCode::NOT_FOUND,
                "dangling tree must 404 under path-scoped rules (anon + owner)"
            );
        }
    }

    /// #173 (F1): a QUARANTINED repo must not serve a pinned object by CID, to anon
    /// OR to the mirror's own owner — quarantine is "hidden from serve/clone/listings,
    /// owner included" (authorize_repo_read / feed_quarantined_mirror_withheld_from_owner).
    /// The repo is PUBLIC with no path-scoped rule, so the "/" visibility gate ALLOWS
    /// it and quarantine is the sole possible denier: RED before the fix (the loop
    /// never checks quarantine → serves 200 + bytes), GREEN after the quarantine skip.
    /// The owner-signed 404 is the load-bearing negative — a visibility-only gate
    /// would Allow the owner and miss this.
    #[sqlx::test]
    async fn ipfs_cid_quarantined_repo_withheld_from_anon_and_owner(pool: PgPool) {
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["quar"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("quar.git");
        // Pin a ROOT-readable object (public/a.txt) — no path-scoped rule, so only
        // quarantine can deny it.
        let public_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "quar"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "quar")
            .await
            .unwrap()
            .unwrap();

        // Baseline: before quarantine the object serves 200 (proves the CID resolves
        // and the object is otherwise servable, so the 404 below is quarantine's doing).
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&public_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "public root object serves before quarantine"
        );
        assert!(body.contains("public bytes"), "baseline serves the content");

        // Quarantine it.
        state
            .db
            .set_repo_quarantine(&rec.id, true)
            .await
            .expect("quarantine");

        // anon AND owner-signed must both 404 with no content leak.
        for req in [cid_anon(&public_cid), cid_signed(&owner, &public_cid)] {
            let (st, body) = cid_parts(cid_router(&state).oneshot(req).await.unwrap()).await;
            assert_eq!(
                st,
                StatusCode::NOT_FOUND,
                "quarantined repo must not serve by CID (anon + owner)"
            );
            assert!(
                !body.contains("public bytes"),
                "404 body must not leak quarantined content"
            );
        }
    }

    /// #173 (F2): a DANGLING commit or annotated tag (in the ODB, referenced by no
    /// ref) must 404 under path-scoped rules for anon AND owner. The resolver proved
    /// reachability only for blobs/trees, so a dangling commit/tag fell through to
    /// serve, leaking its message/metadata. RED before the fix (serves 200 +
    /// sentinel), GREEN after (the reachable commit/tag set excludes them). The
    /// reachable-commit/tag serve path is covered by
    /// ipfs_cid_gate_withholds_blob_from_unauthorized (commit + annotated tag → 200).
    #[sqlx::test]
    async fn ipfs_cid_dangling_commit_and_tag_fail_closed_under_path_rules(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["dangct"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("dangct.git");

        // Run a git plumbing command that reads from stdin and prints an oid.
        let oid_from_stdin = |args: &[&str], input: &[u8]| -> String {
            use std::io::Write;
            let mut child = std::process::Command::new("git")
                .args(args)
                .current_dir(&bare)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn git");
            child.stdin.as_mut().unwrap().write_all(input).unwrap();
            let out = child.wait_with_output().expect("git output");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        // Dangling commit: commit-tree with a sentinel message, NO ref update.
        let dangling_commit_oid = oid_from_stdin(
            &["commit-tree", &fx.root_tree_oid],
            b"DANGLING COMMIT SECRET\n",
        );
        assert_eq!(dangling_commit_oid.len(), 64, "expected sha256 commit oid");
        // Dangling annotated tag: mktag of the dangling commit, NO ref.
        let tag_body = format!(
            "object {dangling_commit_oid}\ntype commit\ntag dang\ntagger t <t@t> 0 +0000\n\nDANGLING TAG SECRET\n"
        );
        let dangling_tag_oid = oid_from_stdin(&["mktag"], tag_body.as_bytes());
        assert_eq!(dangling_tag_oid.len(), 64, "expected sha256 tag oid");

        let commit_cid = pin_cid_for(&bare, &dangling_commit_oid, &state.db).await;
        let tag_cid = pin_cid_for(&bare, &dangling_tag_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "dangct"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "dangct")
            .await
            .unwrap()
            .unwrap();
        // Path-scoped rule triggers the per-object gate (KTD4).
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("deny rule");

        for (cid, sentinel) in [
            (&commit_cid, "DANGLING COMMIT SECRET"),
            (&tag_cid, "DANGLING TAG SECRET"),
        ] {
            for req in [cid_anon(cid), cid_signed(&owner, cid)] {
                let (st, body) = cid_parts(cid_router(&state).oneshot(req).await.unwrap()).await;
                assert_eq!(
                    st,
                    StatusCode::NOT_FOUND,
                    "dangling commit/tag must 404 under path-scoped rules (anon + owner)"
                );
                assert!(
                    !body.contains(sentinel),
                    "404 body must not leak the dangling message: {sentinel}"
                );
            }
        }
    }

    /// #173 review (F2 hardening): a REACHABLE commit must still serve under a
    /// path-scoped rule even when the repo carries a pushable non-commit ref (an
    /// annotated tag of a tree, accepted by receive-pack). `reachable_commit_tag_oids`
    /// must NOT route through `assert_all_refs_are_commits` (which bails on such a
    /// ref and would fail-closed 404 every reachable commit/tag CID in the repo).
    /// RED before the decoupling (the guard bails → 404), GREEN after.
    #[sqlx::test]
    async fn ipfs_cid_reachable_commit_served_despite_non_commit_ref(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["weirdref"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("weirdref.git");

        // A pushable non-commit ref: an annotated tag pointing at a TREE. `git tag -a`
        // in the bare repo creates refs/tags/treetag -> tag object -> tree, which
        // peels to a non-commit and makes assert_all_refs_are_commits bail.
        let out = std::process::Command::new("git")
            .args([
                "tag",
                "-a",
                "treetag",
                &fx.root_tree_oid,
                "-m",
                "tag of a tree",
            ])
            .current_dir(&bare)
            .output()
            .expect("git tag -a");
        assert!(
            out.status.success(),
            "git tag -a: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Pin the REACHABLE root commit.
        let commit_cid = pin_cid_for(&bare, &fx.commit_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "weirdref"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "weirdref")
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("path rule");

        // The reachable commit must still serve — the non-commit ref must not
        // fail-closed the whole repo's commit/tag CID retrieval.
        let resp = cid_router(&state)
            .oneshot(cid_anon(&commit_cid))
            .await
            .unwrap();
        let served_hash = resp
            .headers()
            .get("x-git-hash")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (st, _body) = cid_parts(resp).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a reachable commit must serve despite a pushable non-commit ref in the repo"
        );
        assert_eq!(
            served_hash.as_deref(),
            Some(fx.commit_oid.as_str()),
            "the served object is the reachable root commit"
        );
    }

    /// #173 review (F-F): an annotated tag pointing at a TREE is pushable through
    /// receive-pack, and the TREE allowed-set path
    /// (`allowed_tree_set_for_caller` -> `tree_paths` -> `reachable_commits`) runs
    /// `assert_all_refs_are_commits`, which bails on that ref and fail-closes the
    /// whole repo — 404-ing EVERY tree CID (root + public subtrees) for its owner
    /// and readers, not just the offending tag. The tree allowed-set feeds ONLY the
    /// CID gate (absence = fail-closed 404), so `tree_paths` uses the lenient
    /// reachable-commit enumeration: commit-reachable trees still serve, while a
    /// tree reachable only via such a tag stays excluded. `blob_paths` keeps the
    /// strict guard (it also feeds serve/replication, where a miss under-withholds).
    /// RED before the decoupling (whole-repo bail -> 404 on the root/public tree),
    /// GREEN after; the withheld-subtree 404 is the load-bearing must-not.
    #[sqlx::test]
    async fn ipfs_cid_tree_served_despite_non_commit_ref(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["treeweird"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("treeweird.git");

        // Pushable non-commit ref: an annotated tag pointing at the ROOT TREE.
        let out = std::process::Command::new("git")
            .args([
                "tag",
                "-a",
                "treetag",
                &fx.root_tree_oid,
                "-m",
                "tag of a tree",
            ])
            .current_dir(&bare)
            .output()
            .expect("git tag -a");
        assert!(
            out.status.success(),
            "git tag -a: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Pin the reachable root tree and public subtree (both at ALLOWED paths),
        // plus the secret subtree (a DENIED path — the fail-closed negative).
        let root_tree_cid = pin_cid_for(&bare, &fx.root_tree_oid, &state.db).await;
        let public_tree_cid = pin_cid_for(&bare, &fx.public_tree_oid, &state.db).await;
        let secret_tree_cid = pin_cid_for(&bare, &fx.secret_tree_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "treeweird"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "treeweird")
            .await
            .unwrap()
            .unwrap();
        // Path-scoped rule triggers the per-object tree gate (KTD4).
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("path rule");

        // Reachable trees at ALLOWED paths must still serve despite the tag-of-tree.
        for (cid, want_oid, label) in [
            (&root_tree_cid, &fx.root_tree_oid, "root tree"),
            (&public_tree_cid, &fx.public_tree_oid, "public subtree"),
        ] {
            let resp = cid_router(&state).oneshot(cid_anon(cid)).await.unwrap();
            let served = resp
                .headers()
                .get("x-git-hash")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let (st, _) = cid_parts(resp).await;
            assert_eq!(
                st,
                StatusCode::OK,
                "{label} CID must serve despite a pushable tag-of-tree in the repo"
            );
            assert_eq!(
                served.as_deref(),
                Some(want_oid.as_str()),
                "{label}: the served object is the reachable tree"
            );
        }

        // Fail-closed preserved: the DENIED subtree's CID is still withheld — the
        // lenient walk must not under-withhold a path the caller cannot read.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&secret_tree_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "a withheld subtree's tree CID stays 404 (lenient walk must not under-withhold)"
        );
    }

    /// #173 review (F2 hardening): the INNER tag object of a nested tag-of-a-tag is
    /// reachable (via the outer ref tag) and pinnable, so its CID must serve under a
    /// path rule. `reachable_commit_tag_oids` peels tag chains to include it. RED
    /// before the peel loop (the inner tag is not a ref tip and rev-list dereferences
    /// to the commit, so it is absent → 404), GREEN after.
    #[sqlx::test]
    async fn ipfs_cid_nested_tag_inner_object_served(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["nested"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("nested.git");

        let git_stdin = |args: &[&str], input: &[u8]| -> String {
            use std::io::Write;
            let mut child = std::process::Command::new("git")
                .args(args)
                .current_dir(&bare)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn git");
            child.stdin.as_mut().unwrap().write_all(input).unwrap();
            let out = child.wait_with_output().expect("git output");
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        // Inner annotated tag of the reachable commit (no ref of its own).
        let inner_body = format!(
            "object {}\ntype commit\ntag inner\ntagger t <t@t> 0 +0000\n\ninner\n",
            fx.commit_oid
        );
        let inner_tag_oid = git_stdin(&["mktag"], inner_body.as_bytes());
        // Outer annotated tag of the inner tag, then a ref to the outer tag. The
        // inner tag is reachable only THROUGH the outer, not as a ref tip.
        let outer_body = format!(
            "object {inner_tag_oid}\ntype tag\ntag outer\ntagger t <t@t> 0 +0000\n\nouter\n"
        );
        let outer_tag_oid = git_stdin(&["mktag"], outer_body.as_bytes());
        let out = std::process::Command::new("git")
            .args(["update-ref", "refs/tags/nested", &outer_tag_oid])
            .current_dir(&bare)
            .output()
            .expect("update-ref");
        assert!(
            out.status.success(),
            "update-ref: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let inner_cid = pin_cid_for(&bare, &inner_tag_oid, &state.db).await;

        state
            .db
            .create_repo(&seed_repo(&owner_did, "nested"))
            .await
            .expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "nested")
            .await
            .unwrap()
            .unwrap();
        state
            .db
            .set_visibility_rule(&rec.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("path rule");

        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&inner_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "the inner tag of a nested tag-of-a-tag is reachable and must serve"
        );
    }

    /// #135: with NO path-scoped rule the per-object gate is skipped, so a tree CID
    /// is served (the `"/"` gate is the whole story). Guards against over-gating
    /// trees — the tree analog of the blob skip-walk branch.
    #[sqlx::test]
    async fn ipfs_cid_tree_served_when_no_path_scoped_rule(pool: PgPool) {
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["nopathrule"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("nopathrule.git");
        let tree_cid = pin_cid_for(&bare, &fx.secret_tree_oid, &state.db).await;

        // Public repo, no visibility rules → has_path_scoped_rule is false.
        state
            .db
            .create_repo(&seed_repo(&owner_did, "nopathrule"))
            .await
            .expect("seed repo");

        let (st, body) = cid_bytes(
            cid_router(&state)
                .oneshot(cid_anon(&tree_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "tree served to anon when no path-scoped rule exists"
        );
        assert!(
            bytes_contain(&body, b"b.txt"),
            "served tree carries its child structure"
        );
    }

    /// #173 (Fix 1): the pinned_cids lookup must use the canonical base32 CID, not
    /// the raw request spelling. A pin is stored under `cid.to_string()` (canonical
    /// base32); a request carrying the SAME CID re-encoded to a different multibase
    /// (base58btc) parses and passes the sha2-256 check but, on the pre-fix handler,
    /// misses the lookup key → false 404. Public repo, no path-scoped rule, so no
    /// walk — this isolates the lookup-key canonicalization.
    #[sqlx::test]
    async fn ipfs_alt_encoding_cid_resolves(pool: PgPool) {
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["altenc"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("altenc.git");
        // Canonical base32 CID as stored by the pin path.
        let public_cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;

        // Public repo, no visibility rules (no path-scoped walk).
        state
            .db
            .create_repo(&seed_repo(&owner_did, "altenc"))
            .await
            .expect("seed repo");

        // Re-encode the SAME CID to base58btc — a different, equally-valid spelling
        // that is NOT the stored key. The `cid` crate re-exports `multibase`.
        let alt = public_cid
            .parse::<cid::CidGeneric<64>>()
            .unwrap()
            .to_string_of_base(cid::multibase::Base::Base58Btc)
            .unwrap();
        assert_ne!(alt, public_cid, "alt encoding must differ from canonical");

        let (st, body) = cid_parts(cid_router(&state).oneshot(cid_anon(&alt)).await.unwrap()).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "alt-multibase spelling of a pinned CID must resolve (canonicalized lookup)"
        );
        assert!(
            body.contains("public bytes"),
            "resolved object serves its content"
        );
    }

    /// #173 (Fix 2a, db-level): `oids_for_cid` returns EVERY oid recorded under a
    /// CID, not an arbitrary one. `record_pinned_cid` is unique on the git oid and
    /// non-unique on cid, so two distinct oids can share one content-CID. Old
    /// `oid_for_cid` did `LIMIT 1`; the new plural method must surface both.
    #[sqlx::test]
    async fn oids_for_cid_returns_all_duplicates(pool: PgPool) {
        let state = test_state(pool).await;
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(b"shared content cid").to_string();
        let oid_a = "a".repeat(64);
        let oid_b = "b".repeat(64);
        state
            .db
            .record_pinned_cid(&oid_a, &cid, None)
            .await
            .unwrap();
        state
            .db
            .record_pinned_cid(&oid_b, &cid, None)
            .await
            .unwrap();

        let mut oids = state.db.oids_for_cid(&cid).await.unwrap();
        oids.sort();
        assert_eq!(
            oids,
            vec![oid_a, oid_b],
            "oids_for_cid must return every oid recorded under the shared CID"
        );
    }

    /// #173 (Fix 2b, handler-level): when two oids collide on one CID and the
    /// first-recorded is absent from every repo while the second is a readable
    /// public object, the handler must try both and serve the readable one. The
    /// pre-fix handler resolved a single oid (LIMIT 1 → first-inserted for equal
    /// keys) and 404'd. Ordering caveat: this relies on `oids_for_cid` returning
    /// the absent oid before the readable one (heap/insert order for equal keys);
    /// if that ordering ever changes, `oids_for_cid_returns_all_duplicates` remains
    /// the load-bearing, deterministic driver for Fix 2.
    #[sqlx::test]
    async fn ipfs_cid_collision_serves_readable_duplicate(pool: PgPool) {
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let fx = seed_cid_repos(&slug, &short, &["collision"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("collision.git");

        // A GENUINE content collision: the shared CID is the readable object's REAL
        // content CID, and a second (absent) oid is recorded under the SAME cid. The
        // handler must try every oid and serve the one whose bytes hash to the CID.
        // (F2, #173: the served bytes must match the requested content address, so the
        // shared cid has to be the object's real cid — an arbitrary seed would now be
        // withheld by the integrity check as an unverifiable provider-CID-style row.)
        let (_ty, raw) = crate::git::store::read_object(&bare, &fx.public_oid)
            .unwrap()
            .unwrap();
        let shared_cid = gitlawb_core::cid::Cid::from_git_object_bytes(&raw).to_string();
        let absent_oid = "c".repeat(64);
        state
            .db
            .record_pinned_cid(&absent_oid, &shared_cid, None)
            .await
            .expect("record absent oid first");
        state
            .db
            .record_pinned_cid(&fx.public_oid, &shared_cid, None)
            .await
            .expect("record readable oid second");

        // Public repo, no rules → the readable public object is served if reached.
        state
            .db
            .create_repo(&seed_repo(&owner_did, "collision"))
            .await
            .expect("seed repo");

        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&shared_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "handler must try every oid under the CID and serve the readable duplicate"
        );
        assert!(
            body.contains("public bytes"),
            "the readable duplicate's content is served"
        );
    }

    /// #173 (Fix 3/F3, INV-10): the expensive legacy fan-out is rate-limited per
    /// source IP. A valid tree CID makes the object-type pre-check pass, so each
    /// repeat request pays a fresh walk (request-scoped memo only) — unbounded
    /// amplification. Since #173-F3 (jatmn) the source charge sits on the LEGACY
    /// PROBE (`acquire` + `cat-file`), which precedes the walk, so every legacy
    /// candidate is charged to the non-farmable source IP from the first probe; a
    /// second identical request from the same IP is shed with 429, but a targeted
    /// PROVENANCE fetch (no scan) and a request from a different IP are unaffected.
    /// The limiter is sized to admit one full scan of the two seeded repos (2 probes)
    /// so the first request serves; the repeat then finds the bucket spent.
    #[sqlx::test]
    async fn ipfs_walk_rate_limited_per_source(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let reader = Keypair::generate();
        let reader_did = reader.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();

        let mut state = test_state(pool).await;
        // The scan reads both seeded repos (walklimit + walkpublic) in one page and
        // probes each, so size the per-IP budget to admit exactly one full scan:
        // 1 page + 2 probes. A repeat scan from the same IP then finds the bucket spent.
        // Keyed on the rightmost X-Forwarded-For hop so the test can choose a source IP
        // under `oneshot`. The page is charged because the scan's DB-facing pages draw
        // on this same bucket (#173 round 13, F2). Production is floored at
        // probes + pages by `AppState::ipfs_work_budget`; a hand-set limiter is not.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(3, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        let fx = seed_cid_repos(&slug, &short, &["walklimit"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("walklimit.git");
        // The tree CID drives a path-scoped walk (the load-bearing amplification
        // surface). The reader is allowed under /secret so the walk returns 200.
        let secret_tree_cid = pin_cid_for(&bare, &fx.secret_tree_oid, &state.db).await;

        // NEWEST `created_at` → the paged scan (ORDER BY created_at, id ASC) probes
        // this serving repo LAST, so a scan deterministically charges the walk-free
        // `walkpublic` miss first then this serve: exactly 2 probes per scan.
        let mut walklimit = seed_repo(&owner_did, "walklimit");
        walklimit.created_at = chrono::Utc::now() + chrono::Duration::seconds(60);
        state.db.create_repo(&walklimit).await.expect("seed repo");
        let rec = state
            .db
            .get_repo(&owner_did, "walklimit")
            .await
            .unwrap()
            .unwrap();
        // Mode B path rule over /secret with the reader allowed → the reader's
        // secret-tree fetch runs the allowed-tree walk and returns 200.
        state
            .db
            .set_visibility_rule(
                &rec.id,
                "/secret/**",
                VisibilityMode::B,
                std::slice::from_ref(&reader_did),
                &owner_did,
            )
            .await
            .expect("path rule");

        // The MUST-NOT object must be a genuinely CHEAP fetch: an object served
        // from a repo with NO path-scoped rule takes the no-walk path, so the WALK
        // brake never rate-limits it. It has to live in a repo that carries no path
        // rule AND whose object graph does not overlap `walklimit` (a blob shared
        // with the path-scoped repo would still walk there), so we seed a second bare
        // repo with UNIQUE content. `acquire(owner, "walkpublic")` resolves to
        // `/tmp/<slug>/walkpublic.git`. This copy is PROVENANCED (`pin_cid_for_repo`)
        // so it resolves straight to its repo and skips the legacy probe brake: the
        // point here is the WALK brake, and post-#173-F3 a walk-free LEGACY fetch is
        // itself source-charged at the probe, so a legacy pin would (correctly) be
        // shed from the exhausted IP and no longer isolate the walk brake.
        let pub_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("walkpublic.git");
        {
            use std::process::Command;
            let run = |args: &[&str], cwd: &std::path::Path| {
                let out = Command::new("git")
                    .args(args)
                    .current_dir(cwd)
                    .output()
                    .expect("git runs");
                assert!(
                    out.status.success(),
                    "git {args:?}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            };
            let src = std::env::temp_dir().join(format!("gl-cid-pub-{short}"));
            let _ = std::fs::remove_dir_all(&src);
            std::fs::create_dir_all(&src).unwrap();
            std::fs::write(src.join("cheap.txt"), b"cheap public bytes\n").unwrap();
            run(&["init", "-q", "--object-format=sha256"], &src);
            run(&["config", "user.email", "t@t"], &src);
            run(&["config", "user.name", "t"], &src);
            run(&["add", "."], &src);
            run(&["commit", "-qm", "cheap"], &src);
            let _ = std::fs::remove_dir_all(&pub_bare);
            run(
                &[
                    "clone",
                    "--bare",
                    "-q",
                    src.to_str().unwrap(),
                    pub_bare.to_str().unwrap(),
                ],
                &src,
            );
            let _ = std::fs::remove_dir_all(&src);
        }
        let cheap_oid = {
            use std::process::Command;
            let out = Command::new("git")
                .args(["rev-parse", "HEAD:cheap.txt"])
                .current_dir(&pub_bare)
                .output()
                .unwrap();
            assert!(out.status.success(), "rev-parse cheap.txt");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        // Public repo, NO visibility rules → the cheap object takes the no-walk path.
        state
            .db
            .create_repo(&seed_repo(&owner_did, "walkpublic"))
            .await
            .expect("seed public repo");
        let pub_rec = state
            .db
            .get_repo(&owner_did, "walkpublic")
            .await
            .unwrap()
            .unwrap();
        let public_cid = pin_cid_for_repo(&pub_bare, &cheap_oid, &state.db, &pub_rec.id).await;

        // 1st legacy scan from 1.2.3.4 → 200 (its two probes fit the budget; the
        // walk ran, reader allowed).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed_xff(&reader, &secret_tree_cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "1st legacy scan from a source IP is served"
        );

        // 2nd identical scan from the SAME IP → 429 (per-IP probe budget spent).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed_xff(&reader, &secret_tree_cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::TOO_MANY_REQUESTS,
            "2nd legacy scan from the same source IP is shed with 429"
        );

        // MUST-NOT: a targeted PROVENANCE fetch (no scan, no probe brake) from the
        // SAME limited IP, even after the 429, is served: the brake is on the legacy
        // scan, not the route.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed_xff(&reader, &public_cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a provenance (non-scan) fetch is never rate-limited, even from the exhausted IP"
        );
        assert!(
            body.contains("cheap public bytes"),
            "the cheap fetch serves content"
        );

        // PER-SOURCE isolation: the same tree-CID scan from a DIFFERENT IP → 200.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed_xff(&reader, &secret_tree_cid, "5.6.7.8"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "one source's exhaustion must not shed another source's walk"
        );
    }

    /// #173 review (F-C): a SKIPPED legacy candidate (a walk-and-deny denier, OR a
    /// probe-throttled repo since #173-F3) must not end the whole request: the scan
    /// keeps going so a later walk-free copy still serves, and a spent probe budget is
    /// a clean 429, never a false 404/503. Otherwise a public CID would 404/429 solely
    /// because a path-scoped duplicate sorts ahead of a no-rule copy under the scan's
    /// `(created_at, id)` ASC order. Two same-oid legacy copies: a `/secret`-scoped
    /// denier iterated first and a no-rule public copy behind it.
    ///
    /// Two requests from the SAME IP, budget = 2 (one full scan of both copies):
    /// req1 probes the denier (charged), its allowed-blob walk denies anon → skip and
    /// keep scanning, then probes+serves the walk-free public copy → 200. That proves
    /// the denier skip is non-fatal (`continue`, not `break`). req2 from the same IP
    /// finds the probe budget spent, so the denier's probe throttles → skip-continue,
    /// the public copy's probe throttles too → nothing servable → a clean 429 (not a
    /// truncation 503 nor a false 404), proving the throttle is likewise non-fatal but
    /// correctly shed. RED before `continue` (a `break` on the skipped denier 404s
    /// req1 outright).
    #[sqlx::test]
    async fn ipfs_walk_quota_skips_denier_and_serves_public_copy(pool: PgPool) {
        use crate::db::VisibilityMode;
        use chrono::Utc;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        // Budget = one full two-repo scan: 1 page + 2 probes. Keyed on the rightmost XFF
        // hop so `oneshot` can choose a source IP (no socket peer). A repeat scan from
        // the same IP then finds the budget spent. The page is charged because the
        // scan's DB-facing pages draw on this same bucket (#173 round 13, F2); both
        // repos fit in one 128-row page. Production is floored at probes + pages by
        // `AppState::ipfs_work_budget`, so only a hand-set limiter counts this out.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(3, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        // Identical secret-blob content in both bare clones → one CID resolves to
        // `secret_oid` in each. A NEWER path-scoped denier (walk-and-deny anon) and an
        // OLDER no-rule public copy (walk-free serve).
        let fx = seed_cid_repos(&slug, &short, &["scopeddenier", "publiccopy"]);
        let denier_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("scopeddenier.git");
        let secret_cid = pin_cid_for(&denier_bare, &fx.secret_oid, &state.db).await;

        // First-iterated denier: public at "/", `/secret/**` Mode B empty readers → an
        // anon blob fetch clears "/", runs the allowed-blob walk, is denied → continue.
        // The paged scan orders on the immutable `(created_at, id)` ASC (#173, jatmn).
        let mut denier = seed_repo(&owner_did, "scopeddenier");
        denier.created_at = Utc::now() - chrono::Duration::seconds(60);
        state.db.create_repo(&denier).await.expect("seed denier");
        state
            .db
            .set_visibility_rule(&denier.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("path rule");

        // Public copy behind it — NO rule → the secret blob serves via the no-walk path.
        let mut public = seed_repo(&owner_did, "publiccopy");
        public.created_at = Utc::now();
        state
            .db
            .create_repo(&public)
            .await
            .expect("seed public copy");

        // req1 from 1.2.3.4: the denier is skipped (walk denies anon) and the scan
        // keeps going to serve the older walk-free public copy. Both probes fit the
        // budget, so this leaves the IP bucket spent.
        let resp = cid_router(&state)
            .oneshot(cid_anon_xff(&secret_cid, "1.2.3.4"))
            .await
            .unwrap();
        let served_hash = resp
            .headers()
            .get("x-git-hash")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (st, _body) = cid_parts(resp).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "a skipped walk-requiring denier must not end the scan: the later walk-free public copy still serves"
        );
        assert_eq!(
            served_hash.as_deref(),
            Some(fx.secret_oid.as_str()),
            "the served object is the secret blob from the no-rule public copy"
        );

        // req2 from the SAME exhausted IP: every legacy probe is now throttled. The
        // throttle is non-fatal (skip and keep scanning), but nothing is servable, so
        // it resolves to a clean 429, not a truncation 503, not a false 404.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon_xff(&secret_cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::TOO_MANY_REQUESTS,
            "with the probe budget spent, the repeat legacy scan is shed with a clean 429"
        );
    }

    /// INV-10 amplification bound: a single `GET /ipfs/{cid}` must not fan out an
    /// unbounded number of full-history walks. The route brake (`ipfs_rate_limiter`)
    /// fires once per request and the per-walk `ipfs_work_rate_limiter` charge bounds
    /// walk work across requests, but within ONE request the same object can exist under
    /// path-scoped rules in many repos, each paying its own walk.
    /// `MAX_HISTORY_WALKS_PER_REQUEST` caps that fan-out.
    ///
    /// Load-bearing witness (#173, F4): a readable public copy (no path rule →
    /// served via the no-walk path, exactly like
    /// `ipfs_cid_served_from_public_copy_when_withheld_elsewhere`) is given the
    /// NEWEST `created_at` so the paged scan (ORDER BY created_at, id ASC) iterates it
    /// LAST. Ahead of it sit `cap + 1` path-scoped deniers, each forcing an
    /// allowed-blob walk that denies anon. The cap bounds SPAWNED walks to `cap`, but
    /// hitting it must `continue` (skip only the walk-requiring denier), NOT `break`
    /// the whole repo loop: the walk-free public copy needs no walk, so it is still
    /// reached and served (200, `x-git-hash` = the blob oid). The old `break`
    /// wrongly 404'd this publicly-readable content. Reverting `continue`→`break`
    /// turns this 200 back into a 404: the RED proof that the loop keeps scanning for
    /// a cheap readable copy after the cap. The `cap` walk ceiling still holds — only
    /// `cap` walks are spawned across the deniers regardless (the amplification bound
    /// is proven separately by `ipfs_walk_cap_still_serves_walk_free_candidate`).
    #[sqlx::test]
    async fn ipfs_walk_fanout_capped_per_request(pool: PgPool) {
        use crate::db::VisibilityMode;
        use chrono::Utc;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let cap = crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST as usize;

        // `cap + 1` deniers guarantee the fan-out crosses the ceiling before the
        // readable copy (iterated last) is reached. All bare clones share identical
        // content, so the one secret-BLOB CID resolves to `secret_oid` in every repo.
        let denier_names: Vec<String> = (0..=cap).map(|i| format!("denier{i}")).collect();
        let mut names: Vec<&str> = vec!["readable"];
        names.extend(denier_names.iter().map(|s| s.as_str()));
        let fx = seed_cid_repos(&slug, &short, &names);

        let readable_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("readable.git");
        // The secret BLOB CID drives the path-scoped allowed-blob walk in every
        // denier (the amplification surface) and is served cheaply from the
        // no-rule public copy — the proven serve path.
        let secret_cid = pin_cid_for(&readable_bare, &fx.secret_oid, &state.db).await;

        // 1) Readable public copy — NEWEST created_at → iterated LAST under the paged
        //    `(created_at, id)` ASC order (#173, jatmn). Public with NO visibility
        //    rule, so the blob serves via the no-walk path. This is the copy an
        //    uncapped fan-out would eventually reach and serve.
        let mut readable = seed_repo(&owner_did, "readable");
        readable.created_at = Utc::now() + chrono::Duration::seconds(60);
        state
            .db
            .create_repo(&readable)
            .await
            .expect("seed readable copy");

        // 2) cap+1 deniers with OLDER created_at → iterated before the copy. Public
        //    at "/", but a `/secret/**` Mode B rule with an EMPTY reader list, so an
        //    anon blob fetch clears the "/" gate, runs the allowed-blob walk, and is
        //    denied (the secret blob is in no one's set) → continue. Each distinct
        //    repo.id is its own walk (the memo only dedups the same repo).
        for name in &denier_names {
            let mut denier = seed_repo(&owner_did, name);
            denier.created_at = Utc::now();
            state.db.create_repo(&denier).await.expect("seed denier");
            state
                .db
                .set_visibility_rule(&denier.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
                .await
                .expect("path rule");
        }

        // Anon (no peer, no XFF → the IP brake is skipped, so the walk cap is the
        // only thing in play). After the cap, `continue` skips only the
        // walk-requiring deniers and keeps scanning, reaching the walk-free public
        // copy (iterated last) → served 200. The served object is the secret blob
        // from the no-rule public copy, which is legitimately public THERE.
        let resp = cid_router(&state)
            .oneshot(cid_anon(&secret_cid))
            .await
            .unwrap();
        let served_hash = resp
            .headers()
            .get("x-git-hash")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let (st, _body) = cid_parts(resp).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "hitting the walk cap must skip only the walk-requiring candidate, not abandon the walk-free readable copy"
        );
        assert_eq!(
            served_hash.as_deref(),
            Some(fx.secret_oid.as_str()),
            "the served object is the blob from the no-rule public copy reached after the cap"
        );
    }

    /// Multi-oid companion to `ipfs_walk_fanout_capped_per_request`: exercises the
    /// outer oid loop and proves the per-request walk budget PERSISTS across oid
    /// candidates, so a commit/tag candidate cannot re-open the fan-out. Since #173
    /// (F2) a `commit`/`tag` under a path-scoped rule is itself walk-gated (its
    /// reachability is proven by a `rev-list` walk via `reachable_commit_tag_oids`),
    /// so it is NOT walk-free — it draws from the same budget as the blob/tree walks.
    ///
    /// One CID → TWO oids (the non-unique cid index, #173): a withheld `/secret`
    /// blob (walk-triggering, denied to anon in every denier) recorded FIRST so a
    /// seq scan tries it first and burns the whole walk budget across the deniers;
    /// the reachable root commit is second. Because the budget is already spent, the
    /// commit candidate's reachability walk is also capped in every denier, so the
    /// request 404s — proving commit/tag walks (F2) respect the fan-out ceiling and
    /// cannot be used to bypass it (R6/F3). A reachable commit served with budget to
    /// spare is covered by `ipfs_cid_gate_withholds_blob_from_unauthorized`. The
    /// withheld blob must not leak. Since #173 F2 a scan the walk cap truncated
    /// returns 503 (absence unproven), not the old opaque 404.
    #[sqlx::test]
    async fn ipfs_walk_commit_tag_candidate_respects_the_walk_cap(pool: PgPool) {
        use crate::db::VisibilityMode;
        use chrono::Utc;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let state = test_state(pool).await;

        let cap = crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST as usize;

        // cap+1 path-scoped deniers, all carrying identical content (same oids).
        let denier_names: Vec<String> = (0..=cap).map(|i| format!("m{i}")).collect();
        let names: Vec<&str> = denier_names.iter().map(|s| s.as_str()).collect();
        let fx = seed_cid_repos(&slug, &short, &names);
        let bare = std::path::PathBuf::from("/tmp").join(&slug).join("m0.git");

        // ONE cid → TWO oids. The withheld blob is recorded first (seq scan lists it
        // first → tried first → burns the budget); the reachable commit is second.
        let multi_cid = pin_cid_for(&bare, &fx.secret_oid, &state.db).await;
        state
            .db
            .record_pinned_cid(&fx.commit_oid, &multi_cid, None)
            .await
            .expect("co-locate the commit oid under the same cid");

        for name in &denier_names {
            let mut d = seed_repo(&owner_did, name);
            d.updated_at = Utc::now();
            state.db.create_repo(&d).await.expect("seed denier");
            state
                .db
                .set_visibility_rule(&d.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
                .await
                .expect("path rule");
        }

        // Anon: the blob candidate is denied in every denier (a walk each, spending
        // the budget); the commit candidate's reachability walk is then also capped
        // in every denier — so no candidate is served AND the walk cap truncated the
        // scan, leaving absence unproven → 503 (not the old false 404, #173 F2).
        // Either way commit/tag walks respect the ceiling and cannot re-open the
        // fan-out (R6/F3). The withheld blob must not leak in the body.
        let (st, body) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&multi_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::SERVICE_UNAVAILABLE,
            "a commit/tag reachability walk respects the per-request cap; a truncated scan is 503, not a false 404"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "the withheld blob must not leak in the truncation response"
        );
    }

    /// #173 (F3, INV-15): the per-IP quota debits ONE token per expensive legacy
    /// candidate, not once per request, so one IP cannot drive an unbounded fan-out.
    /// With quota=1 and two path-scoped deniers holding one CID, a SINGLE request is
    /// shed at 429: since #173-F3 (jatmn) each legacy PROBE (`acquire` + `cat-file`,
    /// which precedes the walk) debits, so the first denier probes+walks+denies on
    /// token 1 and the second denier's probe finds no token → 429. (Before F3 the
    /// debit sat on the walk; the outcome is unchanged, the charge point moved earlier
    /// to also bound walk-free probes.) Defeating the per-candidate debit let one IP
    /// drive up to MAX_HISTORY_WALKS_PER_REQUEST × quota expensive ops/hour.
    #[sqlx::test]
    async fn ipfs_walk_quota_debited_per_walk(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        // Signed but NOT a reader → cleared at "/", denied at /secret → forces a walk.
        let stranger = Keypair::generate();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();

        let mut state = test_state(pool).await;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        let fx = seed_cid_repos(&slug, &short, &["w0", "w1"]);
        let bare = std::path::PathBuf::from("/tmp").join(&slug).join("w0.git");
        // The secret BLOB CID forces a path-scoped allowed-blob walk in each denier.
        let secret_cid = pin_cid_for(&bare, &fx.secret_oid, &state.db).await;

        // Two path-scoped deniers (Mode B /secret, empty readers): each forces a
        // walk that denies the signed stranger, so ONE request spawns two walks.
        for name in ["w0", "w1"] {
            let d = seed_repo(&owner_did, name);
            state.db.create_repo(&d).await.expect("seed denier");
            state
                .db
                .set_visibility_rule(&d.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
                .await
                .expect("path rule");
        }

        // ONE request, quota 1: walk 1 debits the token, walk 2 has none → 429.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_signed_xff(&stranger, &secret_cid, "1.2.3.4"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::TOO_MANY_REQUESTS,
            "the second full-history walk in one request must be shed with 429 (per-walk debit)"
        );
    }

    /// The periodic cleanup task must sweep the ipfs walk limiter, not only its
    /// five siblings. Drives `AppState::sweep_rate_limiters` — the exact method the
    /// 300s loop calls — and asserts the ipfs limiter's expired entry is evicted.
    /// Dropping `ipfs_rate_limiter.cleanup()` from that method leaves the entry in
    /// place (`tracked_keys` stays 1): the RED proof that the sweep covers it.
    #[sqlx::test]
    async fn sweep_rate_limiters_includes_ipfs_limiter(pool: PgPool) {
        let mut state = test_state(pool).await;
        // Short window so a single recorded hit is already expired at sweep time.
        state.ipfs_rate_limiter = crate::rate_limit::RateLimiter::new(5, Duration::from_millis(50));

        assert!(
            state.ipfs_rate_limiter.check("1.2.3.4").await,
            "record a hit on the ipfs limiter"
        );
        assert_eq!(
            state.ipfs_rate_limiter.tracked_keys().await,
            1,
            "the source-IP key is tracked before the sweep"
        );

        // Expire the entry (still mapped — cleanup hasn't run), then sweep.
        tokio::time::sleep(Duration::from_millis(60)).await;
        state.sweep_rate_limiters().await;

        assert_eq!(
            state.ipfs_rate_limiter.tracked_keys().await,
            0,
            "the periodic sweep must evict the ipfs limiter's expired entries"
        );
    }

    /// U5 (R6, KTD6), the observed defect: the `/ipfs` route rate limit and the
    /// resolver's per-probe WORK budget are SEPARATE buckets, so a single request with
    /// one probe COMPLETES even at route limit = 1. Through the production router the
    /// `rate_limit_by_ip` middleware charges `ipfs_rate_limiter` once (its 1-slot bucket
    /// is now full); the handler's legacy pre-scan peek and per-probe charge then draw
    /// from `ipfs_work_rate_limiter`, a different bucket, so the walk-free public copy
    /// still serves 200. RED before the split (both charges on `ipfs_rate_limiter`): the
    /// middleware fills the one slot, the pre-scan peek reads it throttled, nothing is
    /// servable → 429 on the FIRST request. Trust None so the middleware and the handler
    /// resolve the same `ConnectInfo` peer IP.
    #[sqlx::test]
    async fn ipfs_route_limit_1_still_serves_one_probe(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_rate_limiter = crate::rate_limit::RateLimiter::new(1, Duration::from_secs(3600));
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(600, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        // Public, no-rule legacy pin (NULL provenance) → the resolver takes the scan
        // fallback and serves walk-free (exactly one probe).
        let fx = seed_cid_repos(&slug, &short, &["routeone"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("routeone.git");
        let repo = seed_repo(&owner_did, "routeone");
        state.db.create_repo(&repo).await.expect("seed repo");
        let cid = pin_cid_for(&bare, &fx.public_oid, &state.db).await;

        let router = crate::server::build_router(state);
        let peer: std::net::SocketAddr = "203.0.113.7:5000".parse().unwrap();
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(format!("/ipfs/{cid}"))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a single /ipfs request with one probe must serve even at route limit = 1 \
             (the route brake and the resolver's work budget are separate buckets)"
        );
    }

    /// U5 (R6): the two buckets are independent — the WORK budget can be exhausted
    /// (429) WITHOUT draining the ROUTE bucket. Through the production router, route
    /// generous (5) but work tight (1): one request drives two legacy probes, so the
    /// second probe finds the work bucket spent → 429 (the route middleware admitted it).
    /// The route bucket, charged once by the middleware, still has room afterward — the
    /// work charges never touched it, so it admits four more direct checks.
    #[sqlx::test]
    async fn ipfs_work_exhaustion_leaves_route_bucket_intact(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();
        let mut state = test_state(pool).await;
        state.ipfs_rate_limiter = crate::rate_limit::RateLimiter::new(5, Duration::from_secs(3600));
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;

        // A legacy pin absent from every repo so the scan probes both seeded repos: two
        // probes, work budget 1 → the second probe is shed → 429.
        let names = ["we0", "we1"];
        let _fx = seed_cid_repos(&slug, &short, &names);
        for n in names {
            state
                .db
                .create_repo(&seed_repo(&owner_did, n))
                .await
                .expect("seed repo");
        }
        let bogus_oid = "0".repeat(64);
        let cid = gitlawb_core::cid::Cid::from_git_object_bytes(b"work-exhaustion").to_string();
        state
            .db
            .record_pinned_cid(&bogus_oid, &cid, None)
            .await
            .expect("legacy pin");

        let route_bucket = state.ipfs_rate_limiter.clone();
        let peer_ip = "203.0.113.8";
        let peer: std::net::SocketAddr = format!("{peer_ip}:5000").parse().unwrap();
        let router = crate::server::build_router(state);
        let mut req = Request::builder()
            .method(Method::GET)
            .uri(format!("/ipfs/{cid}"))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a request whose probes exceed the work budget is shed 429 (work bucket), \
             not blocked at the route (route bucket generous)"
        );
        // The route bucket recorded only the single request the middleware charged; the
        // work charges did not drain it. Sized 5, one used by the request → four left.
        for i in 0..4 {
            assert!(
                route_bucket.check(peer_ip).await,
                "route check {i} must still admit — work charges never drained the route bucket"
            );
        }
    }

    /// U5 (R6): the periodic cleanup task sweeps the NEW work-budget limiter too, not
    /// only the route limiter and its siblings. Mirrors
    /// `sweep_rate_limiters_includes_ipfs_limiter`: drive `sweep_rate_limiters` and
    /// assert the work limiter's expired entry is evicted. Dropping the
    /// `ipfs_work_rate_limiter.cleanup()` call from that method leaves the entry in place
    /// (`tracked_keys` stays 1): the RED proof the sweep covers it.
    #[sqlx::test]
    async fn sweep_rate_limiters_includes_ipfs_work_limiter(pool: PgPool) {
        let mut state = test_state(pool).await;
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(5, Duration::from_millis(50));

        assert!(
            state.ipfs_work_rate_limiter.check("1.2.3.4").await,
            "record a hit on the work limiter"
        );
        assert_eq!(
            state.ipfs_work_rate_limiter.tracked_keys().await,
            1,
            "the source-IP key is tracked before the sweep"
        );

        tokio::time::sleep(Duration::from_millis(60)).await;
        state.sweep_rate_limiters().await;

        assert_eq!(
            state.ipfs_work_rate_limiter.tracked_keys().await,
            0,
            "the periodic sweep must evict the work limiter's expired entries"
        );
    }

    // ---------------------------------------------------------------------------
    // Issue #120 — repo-scoped read surfaces visibility gate
    // ---------------------------------------------------------------------------

    #[sqlx::test]
    async fn list_certs_gate_denies_anon_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zCERTSOWNER0000000000000000000000000000000";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs",
                    axum::routing::get(crate::api::certs::list_certs),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(anon_get(
                "/api/v1/repos/zCERTSOWNER0000000000000000000000000000000/secret-repo/certs",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn list_certs_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zCERTSOWNER1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs",
                    axum::routing::get(crate::api::certs::list_certs),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                "/api/v1/repos/zCERTSOWNER1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/secret-repo/certs",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn get_cert_gate_denies_anon_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zCERTGETOWN00000000000000000000000000000000";
        let repo = seed_private_repo(owner, "secret-repo");
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        let cert = crate::db::RefCertificate {
            id: "real-cert-120".into(),
            repo_id,
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "b".repeat(40),
            pusher_did: owner.into(),
            node_did: "did:key:zNode".into(),
            signature: "sig".into(),
            issued_at: "2026-01-01T00:00:00Z".into(),
            seq: 1,
            prev: "0".repeat(64),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        };
        state.db.insert_ref_certificate(&cert).await.unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs/{id}",
                    axum::routing::get(crate::api::certs::get_cert),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(anon_get("/api/v1/repos/zCERTGETOWN00000000000000000000000000000000/secret-repo/certs/real-cert-120"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn get_cert_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zCERTGETOWN1BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let repo = seed_private_repo(owner, "secret-repo");
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();
        let cert = crate::db::RefCertificate {
            id: "real-cert-120".into(),
            repo_id: repo_id.clone(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "b".repeat(40),
            pusher_did: owner.into(),
            node_did: "did:key:zNode".into(),
            signature: "sig".into(),
            issued_at: "2026-01-01T00:00:00Z".into(),
            seq: 1,
            prev: "0".repeat(64),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        };
        state.db.insert_ref_certificate(&cert).await.unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs/{id}",
                    axum::routing::get(crate::api::certs::get_cert),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                "/api/v1/repos/zCERTGETOWN1BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/secret-repo/certs/real-cert-120",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn list_issues_gate_denies_anon_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zISSOWNER0000000000000000000000000000000000";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/issues",
                    axum::routing::get(crate::api::issues::list_issues),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(anon_get(
                "/api/v1/repos/zISSOWNER0000000000000000000000000000000000/secret-repo/issues",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn list_issues_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zISSOWNER1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let slug = owner.replace([':', '/'], "_");
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let repo_dir = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("secret-repo.git");
        let _ = std::fs::remove_dir_all(&repo_dir);
        std::fs::create_dir_all(repo_dir.parent().unwrap()).unwrap();
        let _repo_guard = DirGuard(repo_dir.clone());
        crate::git::store::init_bare(&repo_dir).unwrap();
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/issues",
                    axum::routing::get(crate::api::issues::list_issues),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                "/api/v1/repos/zISSOWNER1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/secret-repo/issues",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn get_issue_gate_denies_anon_on_private(pool: PgPool) {
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let state = test_state(pool).await;
        let owner = "did:key:zISGETOWN0000000000000000000000000000000000";
        let slug = owner.replace([':', '/'], "_");
        let repo_dir = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("secret-repo.git");
        let _ = std::fs::remove_dir_all(&repo_dir);
        std::fs::create_dir_all(repo_dir.parent().unwrap()).unwrap();
        crate::git::store::init_bare(&repo_dir).unwrap();
        let _repo_guard = DirGuard(repo_dir.clone());
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let issue_id = "real-issue-120";
        let issue_json = serde_json::json!({
            "id": issue_id,
            "title": "Test Issue",
            "body": "test body",
            "author": owner,
            "created_at": "2026-01-01T00:00:00Z",
            "status": "open",
        });
        crate::git::issues::create_issue(&repo_dir, issue_id, &issue_json.to_string()).unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/issues/{id}",
                    axum::routing::get(crate::api::issues::get_issue),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(anon_get("/api/v1/repos/zISGETOWN0000000000000000000000000000000000/secret-repo/issues/real-issue-120"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn get_issue_gate_admits_owner_on_private(pool: PgPool) {
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let state = test_state(pool).await;
        let owner = "did:key:zISGETOWN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let slug = owner.replace([':', '/'], "_");
        let repo_dir = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("secret-repo.git");
        let _ = std::fs::remove_dir_all(&repo_dir);
        std::fs::create_dir_all(repo_dir.parent().unwrap()).unwrap();
        let _repo_guard = DirGuard(repo_dir.clone());
        crate::git::store::init_bare(&repo_dir).unwrap();
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let issue_id = "real-issue-120";
        let issue_json = serde_json::json!({
            "id": issue_id,
            "title": "Test Issue",
            "body": "test body",
            "author": owner,
            "created_at": "2026-01-01T00:00:00Z",
            "status": "open",
        });
        crate::git::issues::create_issue(&repo_dir, issue_id, &issue_json.to_string()).unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/issues/{id}",
                    axum::routing::get(crate::api::issues::get_issue),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{owner}/secret-repo/issues/{issue_id}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn list_issue_comments_gate_denies_anon_on_private(pool: PgPool) {
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let state = test_state(pool).await;
        let owner = "did:key:zISCMTOWN0000000000000000000000000000000000";
        let slug = owner.replace([':', '/'], "_");
        let repo_dir = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("secret-repo.git");
        let _ = std::fs::remove_dir_all(&repo_dir);
        std::fs::create_dir_all(repo_dir.parent().unwrap()).unwrap();
        crate::git::store::init_bare(&repo_dir).unwrap();
        let _repo_guard = DirGuard(repo_dir.clone());
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let issue_id = "real-issue-comment-120";
        let issue_json = serde_json::json!({
            "id": issue_id,
            "title": "Test Issue",
            "body": "test body",
            "author": owner,
            "created_at": "2026-01-01T00:00:00Z",
            "status": "open",
        });
        crate::git::issues::create_issue(&repo_dir, issue_id, &issue_json.to_string()).unwrap();
        let comment = crate::db::IssueComment {
            id: "real-comment-120".into(),
            issue_id: issue_id.into(),
            author_did: owner.into(),
            body: "a comment".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        state.db.create_issue_comment(&comment).await.unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/issues/{id}/comments",
                    axum::routing::get(crate::api::issues::list_issue_comments),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(anon_get("/api/v1/repos/zISCMTOWN0000000000000000000000000000000000/secret-repo/issues/real-issue-comment-120/comments"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn list_issue_comments_gate_admits_owner_on_private(pool: PgPool) {
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let state = test_state(pool).await;
        let owner = "did:key:zISCMTOWN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let short_key = "zISCMTOWN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let slug = owner.replace([':', '/'], "_");
        let repo_dir = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("secret-repo.git");
        let _ = std::fs::remove_dir_all(&repo_dir);
        std::fs::create_dir_all(repo_dir.parent().unwrap()).unwrap();
        let _repo_guard = DirGuard(repo_dir.clone());
        crate::git::store::init_bare(&repo_dir).unwrap();
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let issue_id = "real-issue-comment-120";
        let issue_json = serde_json::json!({
            "id": issue_id,
            "title": "Test Issue",
            "body": "test body",
            "author": owner,
            "created_at": "2026-01-01T00:00:00Z",
            "status": "open",
        });
        crate::git::issues::create_issue(&repo_dir, issue_id, &issue_json.to_string()).unwrap();
        let comment = crate::db::IssueComment {
            id: "real-comment-120".into(),
            issue_id: issue_id.into(),
            author_did: owner.into(),
            body: "a comment".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        state.db.create_issue_comment(&comment).await.unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/issues/{id}/comments",
                    axum::routing::get(crate::api::issues::list_issue_comments),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{short_key}/secret-repo/issues/{issue_id}/comments"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn list_labels_gate_denies_anon_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zLABELOWN00000000000000000000000000000000000";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/labels",
                    axum::routing::get(crate::api::labels::list_labels),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(anon_get(
                "/api/v1/repos/zLABELOWN00000000000000000000000000000000000/secret-repo/labels",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn list_labels_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zLABELOWN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/labels",
                    axum::routing::get(crate::api::labels::list_labels),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                "/api/v1/repos/zLABELOWN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/secret-repo/labels",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn list_repo_bounties_gate_denies_anon_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zBONOWNER00000000000000000000000000000000000";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(anon_get(
                "/api/v1/repos/zBONOWNER00000000000000000000000000000000000/secret-repo/bounties",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn get_star_status_gate_denies_anon_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zSTAROWN000000000000000000000000000000000000";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/star",
                    axum::routing::get(crate::api::stars::get_star_status),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(anon_get(
                "/api/v1/repos/zSTAROWN000000000000000000000000000000000000/secret-repo/star",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn get_star_status_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zSTAROWN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/star",
                    axum::routing::get(crate::api::stars::get_star_status),
                )
                .with_state(state.clone())
        };
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                "/api/v1/repos/zSTAROWN1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/secret-repo/star",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn list_repo_bounties_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let kp = gitlawb_core::identity::Keypair::generate();
        let owner = kp.did().to_string();
        let short = owner.split(':').next_back().unwrap();
        state
            .db
            .create_repo(&seed_private_repo(&owner, "secret-repo"))
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let uri = format!("/api/v1/repos/{short}/secret-repo/bounties");
        let sig = gitlawb_core::http_sig::sign_request(&kp, "GET", &uri, b"");
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("content-type", "application/json")
            .header("content-digest", sig.content_digest)
            .header("signature-input", sig.signature_input)
            .header("signature", sig.signature)
            .body(Body::empty())
            .unwrap();

        let resp = router.oneshot(req).await.unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn get_cert_rejects_cross_repo_idor(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zCERTIDOROWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let short = owner.split(':').next_back().unwrap();
        let repo_a = seed_private_repo(owner, "repo-a");
        state.db.create_repo(&repo_a).await.unwrap();

        let repo_b = seed_private_repo(owner, "repo-b");
        let repo_b_id = repo_b.id.clone();
        state.db.create_repo(&repo_b).await.unwrap();

        let cert = crate::db::RefCertificate {
            id: "cert-in-b".into(),
            repo_id: repo_b_id,
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "b".repeat(40),
            pusher_did: owner.into(),
            node_did: "did:key:zNode".into(),
            signature: "sig".into(),
            issued_at: "2026-01-01T00:00:00Z".into(),
            seq: 1,
            prev: "0".repeat(64),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        };
        state.db.insert_ref_certificate(&cert).await.unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs/{id}",
                    axum::routing::get(crate::api::certs::get_cert),
                )
                .with_state(state.clone())
        };

        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{short}/repo-a/certs/cert-in-b"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn list_issue_comments_rejects_cross_repo_idor(pool: PgPool) {
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let state = test_state(pool).await;
        let owner = "did:key:zISSCMTIDORAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let short = owner.split(':').next_back().unwrap();
        let slug = owner.replace([':', '/'], "_");

        let repo_dir_a = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("repo-a.git");
        let _ = std::fs::remove_dir_all(&repo_dir_a);
        std::fs::create_dir_all(repo_dir_a.parent().unwrap()).unwrap();
        crate::git::store::init_bare(&repo_dir_a).unwrap();
        let _guard_a = DirGuard(repo_dir_a.clone());
        state
            .db
            .create_repo(&seed_private_repo(owner, "repo-a"))
            .await
            .unwrap();

        let repo_dir_b = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("repo-b.git");
        let _ = std::fs::remove_dir_all(&repo_dir_b);
        std::fs::create_dir_all(repo_dir_b.parent().unwrap()).unwrap();
        crate::git::store::init_bare(&repo_dir_b).unwrap();
        let _guard_b = DirGuard(repo_dir_b.clone());
        state
            .db
            .create_repo(&seed_private_repo(owner, "repo-b"))
            .await
            .unwrap();

        let issue_id = "idor-issue-120";
        let issue_json = serde_json::json!({
            "id": issue_id,
            "title": "Test Issue",
            "body": "test body",
            "author": owner,
            "created_at": "2026-01-01T00:00:00Z",
            "status": "open",
        });
        crate::git::issues::create_issue(&repo_dir_b, issue_id, &issue_json.to_string()).unwrap();
        let comment = crate::db::IssueComment {
            id: "idor-comment-120".into(),
            issue_id: issue_id.into(),
            author_did: owner.into(),
            body: "a comment".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        state.db.create_issue_comment(&comment).await.unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/issues/{id}/comments",
                    axum::routing::get(crate::api::issues::list_issue_comments),
                )
                .with_state(state.clone())
        };

        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{short}/repo-a/issues/{issue_id}/comments"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn repo_gate_quarantined_repo_denied(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zQUARANTINEOWNERAAAAAAAAAAAAAAAAAAAAAAAAA";
        let short = owner.split(':').next_back().unwrap();
        let mut repo = seed_private_repo(owner, "quarantined-repo");
        repo.is_public = true; // Make it public to prove quarantine still denies it
        let repo_id = repo.id.clone();
        state.db.create_repo(&repo).await.unwrap();

        state.db.set_repo_quarantine(&repo_id, true).await.unwrap();

        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(anon_get(&format!(
                "/api/v1/repos/{short}/quarantined-repo/issues"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn repo_gate_public_repo_anon_read_admitted(pool: PgPool) {
        struct DirGuard(std::path::PathBuf);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let state = test_state(pool).await;
        let owner = "did:key:zPUBLICREPOOWNERAAAAAAAAAAAAAAAAAAAAAAAAA";
        let short = owner.split(':').next_back().unwrap();

        let slug = owner.replace([':', '/'], "_");
        let repo_dir = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("public-repo.git");
        let _ = std::fs::remove_dir_all(&repo_dir);
        std::fs::create_dir_all(repo_dir.parent().unwrap()).unwrap();
        crate::git::store::init_bare(&repo_dir).unwrap();
        let _repo_guard = DirGuard(repo_dir.clone());

        let mut repo = seed_private_repo(owner, "public-repo");
        repo.is_public = true;
        state.db.create_repo(&repo).await.unwrap();

        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(anon_get(&format!(
                "/api/v1/repos/{short}/public-repo/issues"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[sqlx::test]
    async fn get_bounty_gate_denies_anon_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zGNB0UNTYANONPRIVOWNERAAAAAAAAAAAAAAAAAAA";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();
        let bounty = crate::db::BountyRecord {
            id: "anon-private-bounty".into(),
            repo_owner: owner.into(),
            repo_name: "secret-repo".into(),
            issue_id: None,
            title: "Secret Bounty".into(),
            amount: 100,
            creator_did: owner.into(),
            claimant_did: None,
            claimant_wallet: None,
            pr_id: None,
            status: "open".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            claimed_at: None,
            submitted_at: None,
            completed_at: None,
            deadline_secs: 86400,
            tx_hash: None,
        };
        state.db.create_bounty(&bounty).await.unwrap();

        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(anon_get("/api/v1/bounties/anon-private-bounty"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn get_bounty_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let kp = gitlawb_core::identity::Keypair::generate();
        let owner = kp.did().to_string();
        state
            .db
            .create_repo(&seed_private_repo(&owner, "secret-repo"))
            .await
            .unwrap();
        let bounty = crate::db::BountyRecord {
            id: "owner-private-bounty".into(),
            repo_owner: owner.clone(),
            repo_name: "secret-repo".into(),
            issue_id: None,
            title: "Owner Bounty".into(),
            amount: 200,
            creator_did: owner.clone(),
            claimant_did: None,
            claimant_wallet: None,
            pr_id: None,
            status: "open".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            claimed_at: None,
            submitted_at: None,
            completed_at: None,
            deadline_secs: 86400,
            tx_hash: None,
        };
        state.db.create_bounty(&bounty).await.unwrap();

        let router = crate::server::build_router(state);
        let uri = "/api/v1/bounties/owner-private-bounty";
        let sig = gitlawb_core::http_sig::sign_request(&kp, "GET", uri, b"");
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("content-type", "application/json")
            .header("content-digest", sig.content_digest)
            .header("signature-input", sig.signature_input)
            .header("signature", sig.signature)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn list_all_bounties_filters_private_repos_for_anon(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zLSTALLBOUNTYOWNERAAAAAAAAAAAAAAAAAAAAAA";

        // Private repo with a bounty (should be filtered out)
        state
            .db
            .create_repo(&seed_private_repo(owner, "private-bounty-repo"))
            .await
            .unwrap();
        let private_bounty = crate::db::BountyRecord {
            id: "private-bounty-1".into(),
            repo_owner: owner.into(),
            repo_name: "private-bounty-repo".into(),
            issue_id: None,
            title: "Private Bounty".into(),
            amount: 100,
            creator_did: owner.into(),
            claimant_did: None,
            claimant_wallet: None,
            pr_id: None,
            status: "open".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            claimed_at: None,
            submitted_at: None,
            completed_at: None,
            deadline_secs: 86400,
            tx_hash: None,
        };
        state.db.create_bounty(&private_bounty).await.unwrap();

        // Public repo with a bounty (should be visible to anon)
        let mut public_repo = seed_private_repo(owner, "public-bounty-repo");
        public_repo.is_public = true;
        state.db.create_repo(&public_repo).await.unwrap();
        let public_bounty = crate::db::BountyRecord {
            id: "public-bounty-1".into(),
            repo_owner: owner.into(),
            repo_name: "public-bounty-repo".into(),
            issue_id: None,
            title: "Public Bounty".into(),
            amount: 200,
            creator_did: owner.into(),
            claimant_did: None,
            claimant_wallet: None,
            pr_id: None,
            status: "open".into(),
            created_at: "2026-01-02T00:00:00Z".into(),
            claimed_at: None,
            submitted_at: None,
            completed_at: None,
            deadline_secs: 86400,
            tx_hash: None,
        };
        state.db.create_bounty(&public_bounty).await.unwrap();

        let router = crate::server::build_router(state);
        let resp = router.oneshot(anon_get("/api/v1/bounties")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let bounties = body["bounties"].as_array().unwrap();
        assert_eq!(bounties.len(), 1, "anon should see only the public bounty");
        assert_eq!(bounties[0]["id"], "public-bounty-1");
    }

    #[sqlx::test]
    async fn list_all_bounties_same_private_repo_two_bounties_anon_sees_none(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zP1SAME2PRIVBOUNTYOWNERAAAAAAAAAAAAAAAAA";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        for id in ["private-bounty-a", "private-bounty-b"] {
            let b = crate::db::BountyRecord {
                id: id.into(),
                repo_owner: owner.into(),
                repo_name: "secret-repo".into(),
                issue_id: None,
                title: "Private Bounty".into(),
                amount: 100,
                creator_did: owner.into(),
                claimant_did: None,
                claimant_wallet: None,
                pr_id: None,
                status: "open".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                claimed_at: None,
                submitted_at: None,
                completed_at: None,
                deadline_secs: 86400,
                tx_hash: None,
            };
            state.db.create_bounty(&b).await.unwrap();
        }

        let router = crate::server::build_router(state);
        let resp = router.oneshot(anon_get("/api/v1/bounties")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let bounties = body["bounties"].as_array().unwrap();
        assert_eq!(
            bounties.len(),
            0,
            "anon should see 0 bounties from private repo even with 2 entries"
        );
    }

    // ── Ref-update events (issue #144: owner_did wire format) ─────────────────

    fn events_router(state: AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/events/ref-updates",
                axum::routing::get(crate::api::events::list_ref_updates),
            )
            .with_state(state)
    }

    #[sqlx::test]
    async fn events_returns_inserted_ref_updates(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zEVENTSOWNERAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Seed a local repo the wire owner_did is bound to. The stored wire
        // owner_did is untrusted; it is only surfaced when it matches the
        // canonical owner of the local repo the slug names.
        state
            .db
            .create_repo(&seed_repo(owner, "myrepo"))
            .await
            .unwrap();

        // Insert a gossip event with owner_did set
        state
            .db
            .insert_ref_update(&crate::db::ReceivedRefUpdate {
                id: uuid::Uuid::new_v4().to_string(),
                node_did: "did:key:zNode".into(),
                pusher_did: "did:key:zPusher".into(),
                repo: format!("{}/myrepo", owner.split(':').next_back().unwrap()),
                owner_did: Some(owner.into()),
                ref_name: "refs/heads/main".into(),
                old_sha: "0000000000000000000000000000000000000000".into(),
                new_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                timestamp: "2026-07-02T12:00:00Z".into(),
                cert_id: None,
                received_at: "2026-07-02T12:00:01Z".into(),
                from_peer: "12D3KooWTest".into(),
            })
            .await
            .unwrap();

        let resp = events_router(state)
            .oneshot(anon_get("/api/v1/events/ref-updates"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = json_body(resp).await;
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]["repo"],
            format!("{}/myrepo", owner.split(':').next_back().unwrap())
        );
        assert_eq!(events[0]["owner_did"], owner);
    }

    // P1: a peer-supplied owner_did that does NOT match the canonical owner of
    // the local repo the slug names must NOT be surfaced. Here zVictim asserts
    // ownership of alice's widget repo; the projection must drop it to null
    // rather than poisoning persisted event ownership.
    #[sqlx::test]
    async fn events_drop_forged_peer_owner_did(pool: PgPool) {
        let state = test_state(pool).await;
        let alice = "did:key:zALICEOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let victim = "did:key:zVICTIMOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        state
            .db
            .create_repo(&seed_repo(alice, "widget"))
            .await
            .unwrap();

        state
            .db
            .insert_ref_update(&crate::db::ReceivedRefUpdate {
                id: uuid::Uuid::new_v4().to_string(),
                node_did: "did:key:zNode".into(),
                pusher_did: "did:key:zPusher".into(),
                repo: format!("{}/widget", alice.split(':').next_back().unwrap()),
                owner_did: Some(victim.into()),
                ref_name: "refs/heads/main".into(),
                old_sha: "0000000000000000000000000000000000000000".into(),
                new_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                timestamp: "2026-07-02T12:00:00Z".into(),
                cert_id: None,
                received_at: "2026-07-02T12:00:01Z".into(),
                from_peer: "12D3KooWTest".into(),
            })
            .await
            .unwrap();

        let resp = events_router(state)
            .oneshot(anon_get("/api/v1/events/ref-updates"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        // Forged value dropped: owner_did is null, NOT zVictim.
        assert_eq!(events[0]["owner_did"], serde_json::Value::Null);
    }

    // P3: a legacy row stored with owner_did = None must be attributed only via
    // an exact, unique local match — never a loose prefix-tolerant collision.
    // alice/widget is owned by alice; a stray None row on a different repo whose
    // owner key shares a segment must not inherit alice's full DID.
    #[sqlx::test]
    async fn events_legacy_none_owner_uses_exact_local_match(pool: PgPool) {
        let state = test_state(pool).await;
        let alice = "did:key:zALICEOWNER2AAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let bob = "did:key:zBOBOWNER2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Alice owns "widget".
        state
            .db
            .create_repo(&seed_repo(alice, "widget"))
            .await
            .unwrap();
        // Bob owns a distinct "gadget" repo.
        state
            .db
            .create_repo(&seed_repo(bob, "gadget"))
            .await
            .unwrap();

        // Legacy None row claiming slug "bob/gadget" (matches bob exactly).
        state
            .db
            .insert_ref_update(&crate::db::ReceivedRefUpdate {
                id: uuid::Uuid::new_v4().to_string(),
                node_did: "did:key:zNode".into(),
                pusher_did: "did:key:zPusher".into(),
                repo: format!("{}/gadget", bob.split(':').next_back().unwrap()),
                owner_did: None,
                ref_name: "refs/heads/main".into(),
                old_sha: "0000000000000000000000000000000000000000".into(),
                new_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                timestamp: "2026-07-02T12:00:00Z".into(),
                cert_id: None,
                received_at: "2026-07-02T12:00:01Z".into(),
                from_peer: "12D3KooWTest".into(),
            })
            .await
            .unwrap();

        let resp = events_router(state)
            .oneshot(anon_get("/api/v1/events/ref-updates"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        // Attributed to the exact local owner (bob), not alice via collision.
        assert_eq!(
            events[0]["owner_did"],
            serde_json::Value::String(bob.to_string())
        );
    }

    #[sqlx::test]
    async fn list_all_bounties_past_private_window_finds_public(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zP2PASTPRIVWINDOWOWNERAAAAAAAAAAAAAAAAA";

        // Seed a private repo with 6 bounties (more than one page of page_size=5)
        state
            .db
            .create_repo(&seed_private_repo(owner, "private-repo"))
            .await
            .unwrap();
        for i in 0..6 {
            let b = crate::db::BountyRecord {
                id: format!("private-bounty-{i}"),
                repo_owner: owner.into(),
                repo_name: "private-repo".into(),
                issue_id: None,
                title: format!("Private Bounty {i}"),
                amount: 100,
                creator_did: owner.into(),
                claimant_did: None,
                claimant_wallet: None,
                pr_id: None,
                status: "open".into(),
                created_at: format!("2026-01-{:02}T00:00:00Z", 6 - i),
                claimed_at: None,
                submitted_at: None,
                completed_at: None,
                deadline_secs: 86400,
                tx_hash: None,
            };
            state.db.create_bounty(&b).await.unwrap();
        }

        // Public repo with a bounty created after the private ones
        let mut pub_repo = seed_private_repo(owner, "public-repo");
        pub_repo.is_public = true;
        state.db.create_repo(&pub_repo).await.unwrap();
        let pub_bounty = crate::db::BountyRecord {
            id: "public-bounty-past-window".into(),
            repo_owner: owner.into(),
            repo_name: "public-repo".into(),
            issue_id: None,
            title: "Public Bounty".into(),
            amount: 200,
            creator_did: owner.into(),
            claimant_did: None,
            claimant_wallet: None,
            pr_id: None,
            status: "open".into(),
            // This is older (earlier date) so it appears after the private ones in DESC order
            created_at: "2025-12-01T00:00:00Z".into(),
            claimed_at: None,
            submitted_at: None,
            completed_at: None,
            deadline_secs: 86400,
            tx_hash: None,
        };
        state.db.create_bounty(&pub_bounty).await.unwrap();

        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(anon_get("/api/v1/bounties?limit=1"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let bounties = body["bounties"].as_array().unwrap();
        assert_eq!(
            bounties.len(),
            1,
            "anon should find the public bounty past the private window"
        );
        assert_eq!(bounties[0]["id"], "public-bounty-past-window");
    }

    #[sqlx::test]
    async fn star_repo_gate_denies_non_reader_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zSTARGATEDENYOWNERAAAAAAAAAAAAAAAAAAAAA";
        let short = owner.split(':').next_back().unwrap();
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let non_owner_kp = gitlawb_core::identity::Keypair::generate();
        let uri = format!("/api/v1/repos/{short}/secret-repo/star");
        let sig = gitlawb_core::http_sig::sign_request(&non_owner_kp, "PUT", &uri, b"");
        let req = Request::builder()
            .method(Method::PUT)
            .uri(&uri)
            .header("content-type", "application/json")
            .header("content-digest", sig.content_digest)
            .header("signature-input", sig.signature_input)
            .header("signature", sig.signature)
            .body(Body::empty())
            .unwrap();

        let router = crate::server::build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn unstar_repo_gate_denies_non_reader_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zUNSTARGATEDENYOWNERAAAAAAAAAAAAAAAAAAA";
        let short = owner.split(':').next_back().unwrap();
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();

        let non_owner_kp = gitlawb_core::identity::Keypair::generate();
        let uri = format!("/api/v1/repos/{short}/secret-repo/star");
        let sig = gitlawb_core::http_sig::sign_request(&non_owner_kp, "DELETE", &uri, b"");
        let req = Request::builder()
            .method(Method::DELETE)
            .uri(&uri)
            .header("content-digest", sig.content_digest)
            .header("signature-input", sig.signature_input)
            .header("signature", sig.signature)
            .body(Body::empty())
            .unwrap();

        let router = crate::server::build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn repo_gate_owner_bare_key_vs_full_did(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zBAREKEYFULLDIDOWNERAAAAAAAAAAAAAAAAAA";
        let short = owner.split(':').next_back().unwrap();

        // Save repo with bare key as owner
        let repo = seed_private_repo(short, "bare-repo");
        state.db.create_repo(&repo).await.unwrap();

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs",
                    axum::routing::get(crate::api::certs::list_certs),
                )
                .with_state(state.clone())
        };

        // Caller is full DID, should match bare key in DB
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{short}/bare-repo/certs"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[sqlx::test]
    async fn events_limit_respects_limit_param(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zEVENTLIMITAAAAAAAAAAAAAAAAAAAAAAAA";

        for i in 0..5 {
            state
                .db
                .insert_ref_update(&crate::db::ReceivedRefUpdate {
                    id: uuid::Uuid::new_v4().to_string(),
                    node_did: "did:key:zNode".into(),
                    pusher_did: "did:key:zPusher".into(),
                    repo: format!("{}/r{i}", owner.split(':').next_back().unwrap()),
                    owner_did: Some(owner.into()),
                    ref_name: "refs/heads/main".into(),
                    old_sha: "0000000000000000000000000000000000000000".into(),
                    new_sha: format!("{i:040x}"),
                    timestamp: format!("2026-07-02T12:00:{i:02}Z"),
                    cert_id: None,
                    received_at: format!("2026-07-02T12:00:{i:02}Z"),
                    from_peer: "12D3KooWTest".into(),
                })
                .await
                .unwrap();
        }

        let resp = events_router(state)
            .oneshot(anon_get("/api/v1/events/ref-updates?limit=2"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["count"].as_i64(), Some(2));
        assert_eq!(body["events"].as_array().unwrap().len(), 2);
    }

    #[sqlx::test]
    async fn claim_bounty_gate_denies_non_reader_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let owner = "did:key:zCLAIMDENYOWNERRRRRRRRRRRRRRRRRRRRRRRRR";
        state
            .db
            .create_repo(&seed_private_repo(owner, "secret-repo"))
            .await
            .unwrap();
        let bounty = crate::db::BountyRecord {
            id: "claim-bounty-deny".into(),
            repo_owner: owner.into(),
            repo_name: "secret-repo".into(),
            issue_id: None,
            title: "Secret Claim Bounty".into(),
            amount: 100,
            creator_did: owner.into(),
            claimant_did: None,
            claimant_wallet: None,
            pr_id: None,
            status: "open".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            claimed_at: None,
            submitted_at: None,
            completed_at: None,
            deadline_secs: 86400,
            tx_hash: None,
        };
        state.db.create_bounty(&bounty).await.unwrap();

        // A stranger (not repo owner/reader) tries to claim the bounty
        let stranger_kp = gitlawb_core::identity::Keypair::generate();
        let uri = "/api/v1/bounties/claim-bounty-deny/claim";
        let body = b"{}";
        let sig = gitlawb_core::http_sig::sign_request(&stranger_kp, "POST", uri, body);
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .header("content-digest", sig.content_digest)
            .header("signature-input", sig.signature_input)
            .header("signature", sig.signature)
            .body(Body::from(body.to_vec()))
            .unwrap();

        let router = crate::server::build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn claim_bounty_gate_admits_owner_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let kp = gitlawb_core::identity::Keypair::generate();
        let owner = kp.did().to_string();
        state
            .db
            .create_repo(&seed_private_repo(&owner, "secret-repo"))
            .await
            .unwrap();
        let bounty = crate::db::BountyRecord {
            id: "claim-bounty-admit".into(),
            repo_owner: owner.clone(),
            repo_name: "secret-repo".into(),
            issue_id: None,
            title: "Owner Claim Bounty".into(),
            amount: 200,
            creator_did: owner.clone(),
            claimant_did: None,
            claimant_wallet: None,
            pr_id: None,
            status: "open".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            claimed_at: None,
            submitted_at: None,
            completed_at: None,
            deadline_secs: 86400,
            tx_hash: None,
        };
        state.db.create_bounty(&bounty).await.unwrap();

        // The owner claims their own bounty
        let uri = "/api/v1/bounties/claim-bounty-admit/claim";
        let body = b"{}";
        let sig = gitlawb_core::http_sig::sign_request(&kp, "POST", uri, body);
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/json")
            .header("content-digest", sig.content_digest)
            .header("signature-input", sig.signature_input)
            .header("signature", sig.signature)
            .body(Body::from(body.to_vec()))
            .unwrap();

        let router = crate::server::build_router(state);
        let resp = router.oneshot(req).await.unwrap();
        assert!(resp.status().is_success());
    }

    // ── #147: list_certs respects ?limit ──────────────────────────────────────

    use std::sync::atomic::{AtomicI64, Ordering};
    static NEXT_CERT_SEQ: AtomicI64 = AtomicI64::new(1);

    fn next_cert_seq() -> i64 {
        NEXT_CERT_SEQ.fetch_add(1, Ordering::Relaxed)
    }

    fn seed_cert(
        id: &str,
        repo_id: &str,
        ref_name: &str,
        issued_at: &str,
    ) -> crate::db::RefCertificate {
        crate::db::RefCertificate {
            id: id.to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: "0000".into(),
            new_sha: "1111".into(),
            pusher_did: "did:key:zPUSHER".into(),
            node_did: "did:key:zNODE".into(),
            signature: "sig".into(),
            issued_at: issued_at.to_string(),
            seq: next_cert_seq(),
            prev: "0".repeat(64),
            pusher_sig: None,
            signature_input: None,
            content_digest: None,
            request_path: None,
        }
    }

    #[sqlx::test]
    async fn list_certs_respects_limit_param(pool: PgPool) {
        let owner = "did:key:zCERTOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "cert-repo"))
            .await
            .expect("seed repo");
        let repo = state
            .db
            .get_repo(owner, "cert-repo")
            .await
            .unwrap()
            .expect("repo must exist");

        for i in 0..10u64 {
            state
                .db
                .insert_ref_certificate(&seed_cert(
                    &format!("cert-{i}"),
                    &repo.id,
                    &format!("refs/heads/feature-{i}"),
                    &format!("2026-07-03T20:{i:02}:00Z"),
                ))
                .await
                .unwrap();
        }

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs",
                    axum::routing::get(crate::api::certs::list_certs),
                )
                .with_state(state.clone())
        };

        // No limit param → default 50, returns all 10
        let resp = router()
            .oneshot(anon_get(&format!("/api/v1/repos/{owner}/cert-repo/certs")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["count"], 10, "default limit returns all rows");
        assert_eq!(
            body["certificates"].as_array().unwrap().len(),
            10,
            "all certs in response"
        );

        // limit=3 returns exactly 3
        let resp = router()
            .oneshot(anon_get(&format!(
                "/api/v1/repos/{owner}/cert-repo/certs?limit=3"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["count"], 3, "limit=3 returns 3 certs");
        let certs = body["certificates"].as_array().unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0]["id"], "cert-9", "most recent cert first");
        assert_eq!(certs[2]["id"], "cert-7", "third most recent cert");

        // limit=0 is clamped to min 1, returns 1 cert
        let resp = router()
            .oneshot(anon_get(&format!(
                "/api/v1/repos/{owner}/cert-repo/certs?limit=0"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["count"], 1, "limit=0 clamped to min 1");
        assert_eq!(
            body["certificates"].as_array().unwrap().len(),
            1,
            "one cert when limit=0"
        );
        assert_eq!(body["certificates"][0]["id"], "cert-9", "most recent");

        // limit=200+ is capped at 200
        let resp = router()
            .oneshot(anon_get(&format!(
                "/api/v1/repos/{owner}/cert-repo/certs?limit=300"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["count"], 10,
            "limit=300 capped to 200, still returns all 10"
        );
    }

    #[sqlx::test]
    async fn list_certs_returns_count_field(pool: PgPool) {
        let owner = "did:key:zCERTCOUNTAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "count-repo"))
            .await
            .expect("seed repo");
        let repo = state
            .db
            .get_repo(owner, "count-repo")
            .await
            .unwrap()
            .unwrap();

        state
            .db
            .insert_ref_certificate(&seed_cert(
                "cnt-1",
                &repo.id,
                "refs/heads/main",
                "2026-07-03T20:00:00Z",
            ))
            .await
            .unwrap();

        let router = Router::new()
            .route(
                "/api/v1/repos/{owner}/{repo}/certs",
                axum::routing::get(crate::api::certs::list_certs),
            )
            .with_state(state);

        let resp = router
            .oneshot(anon_get(&format!("/api/v1/repos/{owner}/count-repo/certs")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body.get("count").is_some(), "response must include `count`");
        assert_eq!(body["count"], 1);
        assert_eq!(
            body["certificates"].as_array().unwrap().len(),
            1,
            "certificates array length matches count"
        );
    }

    #[sqlx::test]
    async fn list_certs_prefix_resolves_deep_cert(pool: PgPool) {
        let owner = "did:key:zPREFIXDEEPTESTAAAAAAAAAAAAAAAAAAAAAAA";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&seed_repo(owner, "deep-repo"))
            .await
            .expect("seed repo");
        let repo = state
            .db
            .get_repo(owner, "deep-repo")
            .await
            .unwrap()
            .expect("repo must exist");

        // Insert 55 certs with distinct refs — only the newest 50 fit in a
        // default list_certs response, so a short-ID for cert #0 requires the
        // prefix query to reach it.
        for i in 0..55u64 {
            state
                .db
                .insert_ref_certificate(&seed_cert(
                    &format!("deep-{i:04}"),
                    &repo.id,
                    &format!("refs/heads/feature-{i}"),
                    &format!("2026-07-03T20:{i:02}:00Z"),
                ))
                .await
                .unwrap();
        }

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/certs",
                    axum::routing::get(crate::api::certs::list_certs),
                )
                .with_state(state.clone())
        };

        // Default list (no prefix) returns only the 50 newest — cert-0000 is absent.
        let body = json_body(
            router()
                .oneshot(anon_get(&format!("/api/v1/repos/{owner}/deep-repo/certs")))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["count"].as_u64().unwrap(), 50, "default limit 50");

        // Prefix lookup finds the deep cert by short prefix.
        let body = json_body(
            router()
                .oneshot(anon_get(&format!(
                    "/api/v1/repos/{owner}/deep-repo/certs?prefix=deep-0"
                )))
                .await
                .unwrap(),
        )
        .await;
        assert!(
            body["count"].as_u64().unwrap_or(0) >= 1,
            "prefix query returns at least one result"
        );
        let ids: Vec<&str> = body["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["id"].as_str())
            .collect();
        assert!(
            ids.iter().any(|id| id.starts_with("deep-0")),
            "result includes the deep cert matching the prefix"
        );
    }

    /// Coalesced-drain behavior of the detached post-push encrypt/pin task.
    ///
    /// A push arriving while a task is in flight does not spawn a second task; its
    /// (old_sha, new_sha) tip pairs are merged into the in-flight key's pending slot
    /// and the task loop-drains them before releasing the key. These tests drive the
    /// real task through `run_encrypt_pin_task_for_test` and assert on the WORK
    /// PERFORMED (what is pinned, what is sealed, whether the key is released), not
    /// on control flow. The drain re-reads repo state FRESH, so a rule tightened
    /// between the coalesced push and its drain must be honored, fail closed.
    mod u3_requeue {
        use super::*;
        use crate::db::VisibilityMode;
        use crate::state::{BeginOutcome, PendingWork};
        use std::path::{Path, PathBuf};
        use std::process::Command;

        fn git(args: &[&str], dir: &Path) {
            let ok = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?} failed");
        }
        fn oid(rev: &str, dir: &Path) -> String {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(out.status.success(), "rev-parse {rev}: {out:?}");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        struct Repo {
            _td: tempfile::TempDir,
            path: PathBuf,
        }
        fn init_repo() -> Repo {
            let td = tempfile::TempDir::new().unwrap();
            let path = td.path().to_path_buf();
            git(&["init", "-q"], &path);
            git(&["config", "user.email", "t@t"], &path);
            git(&["config", "user.name", "t"], &path);
            Repo { _td: td, path }
        }
        /// Commit `content` at `rel`, return the blob oid.
        fn commit(repo: &Path, rel: &str, content: &str) -> String {
            let full = repo.join(rel);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, content).unwrap();
            git(&["add", "."], repo);
            git(&["commit", "-qm", rel], repo);
            oid(&format!("HEAD:{rel}"), repo)
        }
        /// Write a loose, UNREACHABLE blob (dangling object).
        fn write_dangling_blob(repo: &Path, content: &str) -> String {
            let out = Command::new("git")
                .args(["hash-object", "-w", "--stdin"])
                .current_dir(repo)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            use std::io::Write;
            out.stdin
                .as_ref()
                .unwrap()
                .write_all(content.as_bytes())
                .unwrap();
            let o = out.wait_with_output().unwrap();
            assert!(o.status.success());
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        fn new_did() -> String {
            Keypair::generate().did().to_string()
        }
        /// Admit push A on the in-flight key, or fail the test.
        fn admit(state: &AppState, key: &str) -> crate::state::EncryptInflightGuard {
            match state.encrypt_inflight.try_begin(key, Vec::new()) {
                BeginOutcome::Admitted(g) => g,
                BeginOutcome::Coalesced => panic!("push A must be admitted, nothing is in flight"),
            }
        }
        /// Coalesce push B's tip pairs into the in-flight key, or fail the test.
        fn coalesce(state: &AppState, key: &str, pairs: Vec<(String, String)>) {
            match state.encrypt_inflight.try_begin(key, pairs) {
                BeginOutcome::Coalesced => {}
                BeginOutcome::Admitted(_) => {
                    panic!("push B must coalesce, a task is already in flight")
                }
            }
        }

        /// SCENARIO 2 + 5 (pin half, TAIL-PLACEMENT guard). A coalesced push on a PUBLIC
        /// repo with NO path-scoped rule must still drain its pin half: the second
        /// push's new object is pinned after the task. RED without the drain (the stale
        /// spawn object_list never lists obj2), and RED if the drain sits inside the
        /// `has_path_scoped_rule` block (a rules-free repo would never reach it).
        #[sqlx::test]
        async fn u3_rules_free_public_repo_requeues_pin_half(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let repo = seed_repo(&owner, "u3-pin");
            state.db.create_repo(&repo).await.expect("seed repo");
            let key = crate::state::repo_identity_key(&owner, &repo.name);
            let git_repo = init_repo();
            let obj1 = commit(&git_repo.path, "a.txt", "one\n");
            let tip_a = oid("HEAD", &git_repo.path);
            // The coalesced push B adds obj2 (present at drain time, NOT in the stale
            // push-A spawn object_list).
            let obj2 = commit(&git_repo.path, "b.txt", "two\n");
            let tip_b = oid("HEAD", &git_repo.path);

            let mut server = mockito::Server::new_async().await;
            let _m = server
                .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .with_status(200)
                .with_body(r#"{"Hash":"bafyprovider"}"#)
                .expect_at_least(1)
                .create_async()
                .await;

            // Push A admits (guard); push B coalesces its tip pair into the slot.
            let guard = admit(&state, &key);
            coalesce(&state, &key, vec![(tip_a, tip_b)]);

            // Spawn-time (push A) captures are STALE: object_list lists only obj1, no rule.
            crate::api::repos::run_encrypt_pin_task_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                owner.clone(),
                repo.name.clone(),
                server.url(),
                vec![obj1.clone()],
                Some(vec![]),
                true,
            )
            .await;

            assert!(
                state.db.is_pinned(&obj1).await.unwrap(),
                "push A's object is pinned on the first pass"
            );
            assert!(
                state.db.is_pinned(&obj2).await.unwrap(),
                "the coalesced push's new object is pinned by the DRAIN lap (RED without \
                 the drain, or if the drain sits inside the encrypt gate)"
            );
            assert!(
                state.encrypt_inflight.is_empty(),
                "the guard key is released once the task exits clean"
            );
        }

        /// SCENARIO 1 + 3 (encrypt half, FRESH re-read). A coalesced push adds a
        /// path-scoped rule withholding a blob. The task must re-read rules FRESH on
        /// the drain lap and seal the newly-withheld blob's recovery copy. RED without
        /// the fresh read (pass one's stale empty rule set seals nothing).
        #[sqlx::test]
        async fn u3_requeue_seals_blob_withheld_by_coalesced_rule_change(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let reader = new_did();
            let repo = seed_repo(&owner, "u3-enc");
            state.db.create_repo(&repo).await.expect("seed repo");
            let key = crate::state::repo_identity_key(&owner, &repo.name);
            let git_repo = init_repo();
            let _pub_oid = commit(&git_repo.path, "public/a.txt", "public\n");
            let tip_a = oid("HEAD", &git_repo.path);
            let secret_oid = commit(&git_repo.path, "secret/b.txt", "TOP SECRET\n");
            let tip_b = oid("HEAD", &git_repo.path);

            // Coalesced push B changes .gitlawb: withhold /secret/** from anon, grant reader.
            state
                .db
                .set_visibility_rule(&repo.id, "/secret/**", VisibilityMode::B, &[reader], &owner)
                .await
                .expect("set rule");

            let mut server = mockito::Server::new_async().await;
            let _m = server
                .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .with_status(200)
                .with_body(r#"{"Hash":"bafyprovider"}"#)
                .expect_at_least(1)
                .create_async()
                .await;

            let guard = admit(&state, &key);
            coalesce(&state, &key, vec![(tip_a, tip_b)]);

            // Push A captures are STALE: no rule, public repo.
            crate::api::repos::run_encrypt_pin_task_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                owner.clone(),
                repo.name.clone(),
                server.url(),
                vec![],
                Some(vec![]),
                true,
            )
            .await;

            assert!(
                state
                    .db
                    .encrypted_blob_recipients_tag(&repo.id, &secret_oid)
                    .await
                    .unwrap()
                    .is_some(),
                "the coalesced push's newly-withheld blob is sealed after the DRAIN re-read \
                 (RED without the fresh read: pass one's stale empty rules seal nothing)"
            );
            assert!(state.encrypt_inflight.is_empty(), "guard key released");
        }

        /// SCENARIO 4 (visibility-leak negative). The drain's full scan must feed
        /// `list_all_objects` through the fail-closed filter, never pin it bare: a
        /// withheld secret blob and a dangling blob must NOT land in the public pin set.
        ///
        /// The full scan is forced through the public API: one coalescing push carrying
        /// more than the pending tip-pair cap degrades the slot to `PendingWork::FullScan`,
        /// which is also the overflow path itself.
        #[sqlx::test]
        async fn u3_requeue_full_scan_does_not_publicly_pin_withheld_or_dangling(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let reader = new_did();
            let repo = seed_repo(&owner, "u3-leak");
            state.db.create_repo(&repo).await.expect("seed repo");
            let key = crate::state::repo_identity_key(&owner, &repo.name);
            let git_repo = init_repo();
            let pub_oid = commit(&git_repo.path, "public/a.txt", "public\n");
            let secret_oid = commit(&git_repo.path, "secret/b.txt", "TOP SECRET\n");
            state
                .db
                .set_visibility_rule(&repo.id, "/secret/**", VisibilityMode::B, &[reader], &owner)
                .await
                .expect("set rule");
            // Coalesced push adds a new public object and a dangling blob.
            let new_pub_oid = commit(&git_repo.path, "public/c.txt", "more public\n");
            let tip = oid("HEAD", &git_repo.path);
            let dangling_oid = write_dangling_blob(&git_repo.path, "orphan bytes\n");

            let mut server = mockito::Server::new_async().await;
            let _m = server
                .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .with_status(200)
                .with_body(r#"{"Hash":"bafyprovider"}"#)
                .expect_at_least(1)
                .create_async()
                .await;

            let rules = state.db.list_visibility_rules(&repo.id).await.unwrap();

            let guard = admit(&state, &key);
            // 1025 pairs is one past the pending cap, so the slot degrades to FullScan.
            coalesce(&state, &key, vec![(tip.clone(), tip.clone()); 1025]);
            assert_eq!(
                state.encrypt_inflight.pending_for(&key),
                Some(PendingWork::FullScan),
                "an overflowing coalesce degrades the pending slot to a forced full scan"
            );

            crate::api::repos::run_encrypt_pin_task_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                owner.clone(),
                repo.name.clone(),
                server.url(),
                vec![pub_oid.clone()],
                Some(rules),
                true,
            )
            .await;

            assert!(
                state.db.is_pinned(&new_pub_oid).await.unwrap(),
                "the coalesced push's new PUBLIC object is pinned by the drain full scan"
            );
            assert!(
                !state.db.is_pinned(&secret_oid).await.unwrap(),
                "a WITHHELD blob is never publicly pinned by the drain enumeration (leak guard)"
            );
            assert!(
                !state.db.is_pinned(&dangling_oid).await.unwrap(),
                "a DANGLING blob is never publicly pinned by the drain enumeration (leak guard)"
            );
            // The withheld blob still gets its ENCRYPTED recovery copy (not a public pin).
            assert!(
                state
                    .db
                    .encrypted_blob_recipients_tag(&repo.id, &secret_oid)
                    .await
                    .unwrap()
                    .is_some(),
                "withheld blob is sealed as an encrypted recovery copy, not pinned in the clear"
            );
        }

        /// SCENARIO 8 (no-coalesce happy path). A single push with no coalesced follower
        /// runs exactly one pass, pins its object, and releases the key. No drain lap.
        #[sqlx::test]
        async fn u3_no_coalesce_single_pass_pins_and_releases(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let repo = seed_repo(&owner, "u3-happy");
            state.db.create_repo(&repo).await.expect("seed repo");
            let key = crate::state::repo_identity_key(&owner, &repo.name);
            let git_repo = init_repo();
            let obj1 = commit(&git_repo.path, "a.txt", "one\n");

            let mut server = mockito::Server::new_async().await;
            let _m = server
                .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .with_status(200)
                .with_body(r#"{"Hash":"bafyprovider"}"#)
                .expect_at_least(1)
                .create_async()
                .await;

            // No second try_begin: nothing is ever merged into the pending slot.
            let guard = admit(&state, &key);
            assert_eq!(
                state.encrypt_inflight.pending_for(&key),
                Some(PendingWork::Tips(vec![])),
                "clean, no coalesce"
            );

            crate::api::repos::run_encrypt_pin_task_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                owner.clone(),
                repo.name.clone(),
                server.url(),
                vec![obj1.clone()],
                Some(vec![]),
                true,
            )
            .await;

            assert!(
                state.db.is_pinned(&obj1).await.unwrap(),
                "the single push's object is pinned"
            );
            assert!(
                state.encrypt_inflight.is_empty(),
                "the key is released after one pass"
            );
        }

        mod u2_reread_retry {
            use super::*;
            use crate::api::repos::drain_faults;

            /// Process-wide tracing capture so a test can assert the give-up is logged at
            /// ERROR. A global default subscriber can only be installed once per process,
            /// so it is shared by every test here and assertions filter on the repo id,
            /// which is a fresh uuid per test.
            mod logcap {
                use std::sync::{Arc, Mutex, OnceLock};
                use tracing::{Event, Level, Subscriber};
                use tracing_subscriber::layer::{Context, Layer};
                use tracing_subscriber::prelude::*;

                type Lines = Arc<Mutex<Vec<(Level, String)>>>;

                fn lines() -> &'static Lines {
                    static LINES: OnceLock<Lines> = OnceLock::new();
                    LINES.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
                }

                struct Capture;
                impl<S: Subscriber> Layer<S> for Capture {
                    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
                        struct V(String);
                        impl tracing::field::Visit for V {
                            fn record_debug(
                                &mut self,
                                field: &tracing::field::Field,
                                value: &dyn std::fmt::Debug,
                            ) {
                                self.0.push_str(&format!(" {}={:?}", field.name(), value));
                            }
                        }
                        let mut v = V(String::new());
                        event.record(&mut v);
                        lines()
                            .lock()
                            .unwrap()
                            .push((*event.metadata().level(), v.0));
                    }
                }

                pub(super) fn install() {
                    static ONCE: OnceLock<()> = OnceLock::new();
                    ONCE.get_or_init(|| {
                        let _ = tracing::subscriber::set_global_default(
                            tracing_subscriber::registry().with(Capture),
                        );
                    });
                }

                pub(super) fn errors_containing(needle: &str) -> Vec<String> {
                    lines()
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|(lvl, msg)| *lvl == Level::ERROR && msg.contains(needle))
                        .map(|(_, msg)| msg.clone())
                        .collect()
                }
            }

            /// SCENARIO 1. The repo re-read fails once, then succeeds: the drain lap
            /// must still RUN, under the refreshed state, and pin the coalesced push's
            /// object. RED before the fix (the single `Err` returned `None`, the lap
            /// pinned nothing, and `finish_or_take_pending` had already taken the
            /// pending work out of the slot, so it was gone for good).
            #[sqlx::test]
            async fn u2_transient_repo_reread_failure_is_retried_and_work_lands(pool: PgPool) {
                let state = test_state(pool).await;
                let owner = new_did();
                let repo = seed_repo(&owner, "u2-retry");
                state.db.create_repo(&repo).await.expect("seed repo");
                let key = crate::state::repo_identity_key(&owner, &repo.name);
                let git_repo = init_repo();
                let obj1 = commit(&git_repo.path, "a.txt", "one\n");
                let tip_a = oid("HEAD", &git_repo.path);
                // The coalesced push B adds obj2, absent from push A's spawn captures.
                let obj2 = commit(&git_repo.path, "b.txt", "two\n");
                let tip_b = oid("HEAD", &git_repo.path);

                let mut server = mockito::Server::new_async().await;
                let _m = server
                    .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                    .with_status(200)
                    .with_body(r#"{"Hash":"bafyprovider"}"#)
                    .expect_at_least(1)
                    .create_async()
                    .await;

                // One transient repo re-read failure, then the real DB answers.
                drain_faults::inject(&repo.id, 1, 0);

                let guard = admit(&state, &key);
                coalesce(&state, &key, vec![(tip_a, tip_b)]);

                crate::api::repos::run_encrypt_pin_task_for_test(
                    &state,
                    guard,
                    git_repo.path.clone(),
                    repo.id.clone(),
                    owner.clone(),
                    repo.name.clone(),
                    server.url(),
                    vec![obj1.clone()],
                    Some(vec![]),
                    true,
                )
                .await;

                assert!(
                    state.db.is_pinned(&obj2).await.unwrap(),
                    "the coalesced push's object is pinned after the retried re-read (RED \
                     before this unit: the Err arm dropped the lap and the work with it)"
                );
                let c = drain_faults::counters(&repo.id);
                assert_eq!(
                    c.repo_read_attempts, 2,
                    "the failed re-read is retried exactly once before it succeeds"
                );
                assert!(
                    state.encrypt_inflight.is_empty(),
                    "the guard key is released once the task exits"
                );
            }

            /// SCENARIO 2. Every re-read attempt fails: the loop must give up on a BOUND
            /// (asserted as a literal, so raising or removing the bound goes RED) and log
            /// the give-up at ERROR so the residual loss is observable rather than silent.
            #[sqlx::test]
            async fn u2_sustained_repo_reread_failure_is_bounded_and_logged(pool: PgPool) {
                logcap::install();
                let state = test_state(pool).await;
                let owner = new_did();
                let repo = seed_repo(&owner, "u2-bounded");
                state.db.create_repo(&repo).await.expect("seed repo");
                let key = crate::state::repo_identity_key(&owner, &repo.name);
                let git_repo = init_repo();
                let obj1 = commit(&git_repo.path, "a.txt", "one\n");
                let tip_a = oid("HEAD", &git_repo.path);
                let obj2 = commit(&git_repo.path, "b.txt", "two\n");
                let tip_b = oid("HEAD", &git_repo.path);

                let mut server = mockito::Server::new_async().await;
                let _m = server
                    .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                    .with_status(200)
                    .with_body(r#"{"Hash":"bafyprovider"}"#)
                    .expect_at_least(1)
                    .create_async()
                    .await;

                // Far more failures than the bound allows: the outage never clears.
                drain_faults::inject(&repo.id, 10_000, 0);

                let guard = admit(&state, &key);
                coalesce(&state, &key, vec![(tip_a, tip_b)]);

                crate::api::repos::run_encrypt_pin_task_for_test(
                    &state,
                    guard,
                    git_repo.path.clone(),
                    repo.id.clone(),
                    owner.clone(),
                    repo.name.clone(),
                    server.url(),
                    vec![obj1.clone()],
                    Some(vec![]),
                    true,
                )
                .await;

                let c = drain_faults::counters(&repo.id);
                assert_eq!(
                    c.repo_read_attempts, 3,
                    "the re-read is bounded at 3 attempts; unbounded retry or a raised \
                     bound must fail here"
                );
                assert!(
                    !state.db.is_pinned(&obj2).await.unwrap(),
                    "with the read never succeeding there is nothing fresh to act on"
                );
                let errs = logcap::errors_containing(&repo.id);
                assert!(
                    !errs.is_empty(),
                    "the exhausted drain re-read is logged at ERROR with the repo id, so \
                     the residual work loss is observable; captured: {errs:?}"
                );
                assert!(
                    state.encrypt_inflight.is_empty(),
                    "the guard key is still released on the give-up path"
                );
            }

            /// SCENARIO 3. `Ok(None)` (the repo was deleted during the in-flight window)
            /// is NOT a transient failure: it must release immediately without burning the
            /// retry budget. The repo row is never created, so the re-read legitimately
            /// returns `Ok(None)`.
            #[sqlx::test]
            async fn u2_repo_gone_releases_without_consuming_retries(pool: PgPool) {
                let state = test_state(pool).await;
                let owner = new_did();
                let missing_id = uuid::Uuid::new_v4().to_string();
                let missing_name = "u2-gone".to_string();
                let key = crate::state::repo_identity_key(&owner, &missing_name);
                let git_repo = init_repo();
                let _obj1 = commit(&git_repo.path, "a.txt", "one\n");
                let tip_a = oid("HEAD", &git_repo.path);
                let _obj2 = commit(&git_repo.path, "b.txt", "two\n");
                let tip_b = oid("HEAD", &git_repo.path);

                let server = mockito::Server::new_async().await;

                drain_faults::inject(&missing_id, 0, 0);

                let guard = admit(&state, &key);
                // A real pair, so a drain lap actually runs and reaches the re-read.
                coalesce(&state, &key, vec![(tip_a, tip_b)]);

                // Empty object list: pass one touches no pin rows for a repo that is gone.
                crate::api::repos::run_encrypt_pin_task_for_test(
                    &state,
                    guard,
                    git_repo.path.clone(),
                    missing_id.clone(),
                    owner.clone(),
                    missing_name.clone(),
                    server.url(),
                    vec![],
                    Some(vec![]),
                    true,
                )
                .await;

                let c = drain_faults::counters(&missing_id);
                assert_eq!(
                    c.repo_read_attempts, 1,
                    "a deleted repo is a terminal answer, never retried"
                );
                assert_eq!(
                    c.rules_read_attempts, 0,
                    "no rules read is attempted once the repo row is gone"
                );
                assert!(
                    state.encrypt_inflight.is_empty(),
                    "the guard key is released cleanly"
                );
            }

            /// SCENARIO 4. A failed visibility-rule read is transient, never an empty
            /// policy. RED before the fix, where `.ok()` made "the rules read failed" and
            /// "this repo has no rules" the same value: the withheld blob was then neither
            /// sealed nor covered, because a `None` rule set skips the entire lap.
            #[sqlx::test]
            async fn u2_transient_rules_read_failure_is_retried_not_read_as_empty(pool: PgPool) {
                let state = test_state(pool).await;
                let owner = new_did();
                let reader = new_did();
                let repo = seed_repo(&owner, "u2-rules");
                state.db.create_repo(&repo).await.expect("seed repo");
                let key = crate::state::repo_identity_key(&owner, &repo.name);
                let git_repo = init_repo();
                let pub_oid = commit(&git_repo.path, "public/a.txt", "public\n");
                let tip_a = oid("HEAD", &git_repo.path);
                let secret_oid = commit(&git_repo.path, "secret/b.txt", "TOP SECRET\n");
                let tip_b = oid("HEAD", &git_repo.path);

                // The coalesced push B is what added the path-scoped rule.
                state
                    .db
                    .set_visibility_rule(
                        &repo.id,
                        "/secret/**",
                        VisibilityMode::B,
                        &[reader],
                        &owner,
                    )
                    .await
                    .expect("set rule");

                let mut server = mockito::Server::new_async().await;
                let _m = server
                    .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                    .with_status(200)
                    .with_body(r#"{"Hash":"bafyprovider"}"#)
                    .expect_at_least(1)
                    .create_async()
                    .await;

                // The repo row reads fine; the RULES read is the one that blips.
                drain_faults::inject(&repo.id, 0, 1);

                let guard = admit(&state, &key);
                coalesce(&state, &key, vec![(tip_a, tip_b)]);

                // Push A's captures are stale: no rule, nothing withheld.
                crate::api::repos::run_encrypt_pin_task_for_test(
                    &state,
                    guard,
                    git_repo.path.clone(),
                    repo.id.clone(),
                    owner.clone(),
                    repo.name.clone(),
                    server.url(),
                    vec![pub_oid.clone()],
                    Some(vec![]),
                    true,
                )
                .await;

                assert!(
                    state
                        .db
                        .encrypted_blob_recipients_tag(&repo.id, &secret_oid)
                        .await
                        .unwrap()
                        .is_some(),
                    "the withheld blob is sealed under the RETRIED rule set (RED with \
                     list_visibility_rules(..).ok(): an empty policy seals nothing)"
                );
                let c = drain_faults::counters(&repo.id);
                assert_eq!(
                    c.rules_read_attempts, 2,
                    "the failed rules read is retried, not collapsed into an empty rule set"
                );
                assert!(
                    !state.db.is_pinned(&secret_oid).await.unwrap(),
                    "the withheld blob is never pinned in the clear by the drain"
                );
            }

            /// SCENARIO 5. The fault-free control for scenario 4: the rules applied by the
            /// drain are the COALESCED push's fresh ones, never the spawn-time capture,
            /// and the retry path does not perturb that (exactly one read of each).
            #[sqlx::test]
            async fn u2_requeue_applies_fresh_rules_not_spawn_captures(pool: PgPool) {
                let state = test_state(pool).await;
                let owner = new_did();
                let reader = new_did();
                let repo = seed_repo(&owner, "u2-fresh");
                state.db.create_repo(&repo).await.expect("seed repo");
                let key = crate::state::repo_identity_key(&owner, &repo.name);
                let git_repo = init_repo();
                let pub_oid = commit(&git_repo.path, "public/a.txt", "public\n");
                let tip_a = oid("HEAD", &git_repo.path);
                let secret_oid = commit(&git_repo.path, "secret/b.txt", "TOP SECRET\n");
                let tip_b = oid("HEAD", &git_repo.path);
                state
                    .db
                    .set_visibility_rule(
                        &repo.id,
                        "/secret/**",
                        VisibilityMode::B,
                        &[reader],
                        &owner,
                    )
                    .await
                    .expect("set rule");

                let mut server = mockito::Server::new_async().await;
                let _m = server
                    .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                    .with_status(200)
                    .with_body(r#"{"Hash":"bafyprovider"}"#)
                    .expect_at_least(1)
                    .create_async()
                    .await;

                drain_faults::inject(&repo.id, 0, 0);

                let guard = admit(&state, &key);
                coalesce(&state, &key, vec![(tip_a, tip_b)]);

                crate::api::repos::run_encrypt_pin_task_for_test(
                    &state,
                    guard,
                    git_repo.path.clone(),
                    repo.id.clone(),
                    owner.clone(),
                    repo.name.clone(),
                    server.url(),
                    vec![pub_oid.clone()],
                    Some(vec![]),
                    true,
                )
                .await;

                let c = drain_faults::counters(&repo.id);
                assert_eq!(
                    (c.repo_read_attempts, c.rules_read_attempts),
                    (1, 1),
                    "a healthy DB is read exactly once per drain lap"
                );
                assert!(
                    state.db.is_pinned(&pub_oid).await.unwrap(),
                    "the visible object is pinned under the fresh rules"
                );
                assert!(
                    !state.db.is_pinned(&secret_oid).await.unwrap(),
                    "the freshly-read rule withholds the secret blob (the spawn-time \
                     capture had no rules at all)"
                );
            }

            /// SCENARIO 6. Regression guard on the property the fix must not disturb: the
            /// finish-or-take critical section is atomic, so a push coalescing during it is
            /// still covered by exactly one more lap, and the key is released after.
            #[sqlx::test]
            async fn u2_coalesced_push_still_covered_by_exactly_one_requeue_pass(pool: PgPool) {
                let state = test_state(pool).await;
                let owner = new_did();
                let repo = seed_repo(&owner, "u2-coalesce");
                state.db.create_repo(&repo).await.expect("seed repo");
                let key = crate::state::repo_identity_key(&owner, &repo.name);
                let git_repo = init_repo();
                let obj1 = commit(&git_repo.path, "a.txt", "one\n");
                let tip_a = oid("HEAD", &git_repo.path);
                let obj2 = commit(&git_repo.path, "b.txt", "two\n");
                let tip_b = oid("HEAD", &git_repo.path);

                let mut server = mockito::Server::new_async().await;
                let _m = server
                    .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                    .with_status(200)
                    .with_body(r#"{"Hash":"bafyprovider"}"#)
                    .expect_at_least(1)
                    .create_async()
                    .await;

                drain_faults::inject(&repo.id, 0, 0);

                let guard = admit(&state, &key);
                // Push B lands during the in-flight window: its tip pair is merged.
                coalesce(&state, &key, vec![(tip_a.clone(), tip_b.clone())]);
                assert_eq!(
                    state.encrypt_inflight.pending_for(&key),
                    Some(PendingWork::Tips(vec![(tip_a, tip_b)])),
                    "the coalesced push recorded its work in the pending slot"
                );

                crate::api::repos::run_encrypt_pin_task_for_test(
                    &state,
                    guard,
                    git_repo.path.clone(),
                    repo.id.clone(),
                    owner.clone(),
                    repo.name.clone(),
                    server.url(),
                    vec![obj1.clone()],
                    Some(vec![]),
                    true,
                )
                .await;

                assert_eq!(
                    drain_faults::counters(&repo.id).repo_read_attempts,
                    1,
                    "one coalesced push means exactly one drain lap, no re-spin"
                );
                assert!(
                    state.db.is_pinned(&obj1).await.unwrap(),
                    "push A's object is pinned"
                );
                assert!(
                    state.db.is_pinned(&obj2).await.unwrap(),
                    "the coalesced push's object is covered by the drain lap"
                );
                assert!(
                    state.encrypt_inflight.is_empty(),
                    "the key is released once the task is clean"
                );
            }

            /// Wait for `finish_or_take_pending` to take the pending work out of the slot
            /// (`Tips(nonempty)` -> `Tips(empty)`), which is the exact instant the task
            /// enters `drain_refresh_state`'s retry window. Deterministic, so the
            /// coalescing push below lands INSIDE that window rather than on a sleep
            /// guess. `None` means the key is already gone (the task exited), which the
            /// caller reports as its own failure.
            async fn wait_for_drain_window(
                inflight: &crate::state::EncryptInflight,
                key: &str,
            ) -> bool {
                for _ in 0..5_000 {
                    match inflight.pending_for(key) {
                        Some(PendingWork::Tips(acc)) if acc.is_empty() => return true,
                        None => return false,
                        Some(_) => {}
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                false
            }

            /// SCENARIO 7 (RED-before/GREEN-after). A push that coalesces WHILE the
            /// re-read is retrying must not be thrown away when that re-read finally
            /// gives up. Breaking the drain loop on the give-up would let
            /// `EncryptInflightGuard::drop` remove the key with push C's work still
            /// recorded, and push C's lap would never run: a silent drop with no
            /// reconciliation sweep behind it.
            ///
            /// Exactly `DRAIN_REREAD_MAX_ATTEMPTS` injected repo-read faults, so the
            /// first refresh exhausts its budget and the DB is healthy for the next one.
            /// Push C coalesces inside that window.
            #[sqlx::test]
            async fn u2_failed_reread_keeps_a_push_that_coalesced_during_the_window(pool: PgPool) {
                let state = test_state(pool).await;
                let owner = new_did();
                let repo = seed_repo(&owner, "u2-window");
                state.db.create_repo(&repo).await.expect("seed repo");
                let key = crate::state::repo_identity_key(&owner, &repo.name);
                let git_repo = init_repo();
                let obj_a = commit(&git_repo.path, "a.txt", "one\n");
                let tip_a = oid("HEAD", &git_repo.path);
                let _obj_b = commit(&git_repo.path, "b.txt", "two\n");
                let tip_b = oid("HEAD", &git_repo.path);
                let obj_c = commit(&git_repo.path, "c.txt", "three\n");
                let tip_c = oid("HEAD", &git_repo.path);

                let mut server = mockito::Server::new_async().await;
                let _m = server
                    .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                    .with_status(200)
                    .with_body(r#"{"Hash":"bafyprovider"}"#)
                    .expect_at_least(1)
                    .create_async()
                    .await;

                // Exactly the bound: the FIRST refresh burns all three attempts and gives
                // up; every later refresh sees a healthy DB.
                drain_faults::inject(&repo.id, 3, 0);

                let guard = admit(&state, &key);
                coalesce(&state, &key, vec![(tip_a.clone(), tip_b.clone())]);

                // Push C lands during the retry window, after the loop already took push
                // B's pending work out of the slot. It MUST carry a real tip pair: an
                // empty merge leaves the slot empty and no extra lap runs at all.
                let inflight = state.encrypt_inflight.clone();
                let watch_key = key.clone();
                let coalesced = tokio::spawn(async move {
                    if !wait_for_drain_window(&inflight, &watch_key).await {
                        return false;
                    }
                    matches!(
                        inflight.try_begin(&watch_key, vec![(tip_b, tip_c)]),
                        BeginOutcome::Coalesced
                    )
                });

                crate::api::repos::run_encrypt_pin_task_for_test(
                    &state,
                    guard,
                    git_repo.path.clone(),
                    repo.id.clone(),
                    owner.clone(),
                    repo.name.clone(),
                    server.url(),
                    vec![obj_a.clone()],
                    Some(vec![]),
                    true,
                )
                .await;

                assert!(
                    coalesced.await.expect("coalescing task"),
                    "push C must have coalesced inside the retry window for this test to \
                     mean anything"
                );
                assert!(
                    state.db.is_pinned(&obj_c).await.unwrap(),
                    "the push that coalesced during the retry window must still get a lap \
                     once the DB recovers (RED if the give-up breaks the loop: the pending \
                     work was already taken, so the lap was dropped with nothing to \
                     re-derive it)"
                );
                assert!(
                    state.encrypt_inflight.is_empty(),
                    "the guard key is released once the task exits"
                );
            }

            /// SCENARIO 8 (the sustained-outage guard on the fall-through). Continuing the
            /// loop on a give-up means `finish_or_take_pending` runs again, so a DB that
            /// never recovers must still TERMINATE rather than spin. It does: an extra lap
            /// only happens when a push actually coalesced, and each lap pays a full
            /// bounded re-read (3 attempts with backoff). One coalescing push during the
            /// window buys exactly one extra lap: 6 repo-read attempts, then exit.
            #[sqlx::test]
            async fn u2_sustained_failure_with_a_coalesce_terminates_after_one_more_lap(
                pool: PgPool,
            ) {
                let state = test_state(pool).await;
                let owner = new_did();
                let repo = seed_repo(&owner, "u2-sustained-window");
                state.db.create_repo(&repo).await.expect("seed repo");
                let key = crate::state::repo_identity_key(&owner, &repo.name);
                let git_repo = init_repo();
                let obj_a = commit(&git_repo.path, "a.txt", "one\n");
                let tip_a = oid("HEAD", &git_repo.path);
                let _obj_b = commit(&git_repo.path, "b.txt", "two\n");
                let tip_b = oid("HEAD", &git_repo.path);
                let _obj_c = commit(&git_repo.path, "c.txt", "three\n");
                let tip_c = oid("HEAD", &git_repo.path);

                let mut server = mockito::Server::new_async().await;
                let _m = server
                    .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                    .with_status(200)
                    .with_body(r#"{"Hash":"bafyprovider"}"#)
                    .expect_at_least(1)
                    .create_async()
                    .await;

                // The outage never clears.
                drain_faults::inject(&repo.id, 10_000, 0);

                let guard = admit(&state, &key);
                coalesce(&state, &key, vec![(tip_a.clone(), tip_b.clone())]);

                let inflight = state.encrypt_inflight.clone();
                let watch_key = key.clone();
                let coalesced = tokio::spawn(async move {
                    if !wait_for_drain_window(&inflight, &watch_key).await {
                        return false;
                    }
                    matches!(
                        inflight.try_begin(&watch_key, vec![(tip_b, tip_c)]),
                        BeginOutcome::Coalesced
                    )
                });

                // The watchdog is the real assertion: a loop that re-spins without the
                // pending gate would never return here.
                tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    crate::api::repos::run_encrypt_pin_task_for_test(
                        &state,
                        guard,
                        git_repo.path.clone(),
                        repo.id.clone(),
                        owner.clone(),
                        repo.name.clone(),
                        server.url(),
                        vec![obj_a.clone()],
                        Some(vec![]),
                        true,
                    ),
                )
                .await
                .expect(
                    "the task must terminate under a sustained outage; a fall-through that \
                     does not gate on the pending slot spins forever",
                );

                assert!(
                    coalesced.await.expect("coalescing task"),
                    "push C must have coalesced inside the retry window"
                );
                assert_eq!(
                    drain_faults::counters(&repo.id).repo_read_attempts,
                    6,
                    "one coalescing push buys exactly one more bounded re-read lap \
                     (3 + 3 attempts), never an unbounded retry"
                );
                assert!(
                    state.encrypt_inflight.is_empty(),
                    "the guard key is released on the give-up path"
                );
            }
        }
    }
}
