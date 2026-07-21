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
pub(crate) async fn test_state(pool: PgPool) -> AppState {
    let db = Arc::new(crate::db::Db::for_testing(pool.clone()));
    db.run_migrations()
        .await
        .expect("test schema migrations should apply");
    build_state(db, pool)
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
        encrypt_inflight: crate::state::EncryptInflight::new(),
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
    /// shed-before-DB property is carried by an explicit `available_permits() == 0`
    /// early check at the top of the handler (the held permit remains the
    /// authoritative bound further down). DB-free: an exhausted semaphore sheds
    /// before any DB/disk access, so a lazy state works. Remove the early-shed block
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
    /// explicit `available_permits() == 0` early-shed check at the top, so an
    /// exhausted semaphore must shed it with a 503 before any DB/disk work.
    /// Anonymous-reachable, so no auth injection is needed. Remove the early-shed
    /// block from git_upload_pack and this goes red.
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
    /// so an exhausted advert pool sheds the advert with 503 before any DB/disk work
    /// — while the write pool (reserved for authenticated POSTs) is left free here.
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
    /// extractor 500s before the handler body reaches git_permit. The permit is the
    /// first statement, so an exhausted semaphore still sheds 503 before any DB
    /// work. Remove the permit line from git_receive_pack and this goes red.
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
    /// already past v11 gets `pinned_cids.repo_id` from the NEW v12 migration, and a
    /// legacy pin recorded before the column existed survives with NULL provenance (so
    /// it falls back to the repo scan). Simulate the pre-v12 node by dropping the
    /// column and un-applying v12, seed a legacy row, then re-migrate. RED before the
    /// v12 migration exists (the column is never re-added → the SELECT errors); GREEN
    /// after.
    #[sqlx::test]
    async fn pinned_cids_repo_provenance_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        // Pre-v12 shape: drop the provenance column and forget v12 was applied.
        sqlx::query("ALTER TABLE pinned_cids DROP COLUMN IF EXISTS repo_id")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 12")
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

        // Upgrade: re-run migrations → v12 re-adds the column.
        state.db.run_migrations().await.expect("migrate to v12");

        // The legacy pin survives with NULL provenance.
        let legacy: Option<String> =
            sqlx::query_scalar("SELECT repo_id FROM pinned_cids WHERE sha256_hex = 'legacyoid'")
                .fetch_one(&pool)
                .await
                .expect("legacy pin row survives the upgrade");
        assert!(
            legacy.is_none(),
            "a pin recorded before v12 must keep NULL provenance (it falls back to the scan)"
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
            "a pin recorded after v12 carries its source repo_id"
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
            vec![fx.public_oid.clone()],
            &state.db,
            &pub_repo.id,
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
            vec![fx.public_oid.clone()],
            &state.db,
            &pub_repo.id,
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
    /// its source in `pinned_cids.repo_id` but not in `pin_repo_sources` (pre-v13 pins, or
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
    /// node already past v12 gets the table from the NEW v13 migration. Simulate the
    /// pre-v13 node by dropping the table and un-applying v13, then re-migrate and
    /// assert a source row round-trips. RED before the v13 migration exists.
    #[sqlx::test]
    async fn pin_repo_sources_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        sqlx::query("DROP TABLE IF EXISTS pin_repo_sources")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 13")
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
            "the v13 pin_repo_sources table is present after upgrade"
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

        // A new row created via the pinata path carries provenance, and stores the
        // raw CID in `cid` with the provider CID in `pinata_cid`.
        state
            .db
            .record_pinata_cid("po1", "rawcid1", "pcid1", Some("repoA"))
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
        assert_eq!(po1.cid, "rawcid1", "resolver-key cid is the raw CID");
        assert_eq!(
            po1.pinata_cid.as_deref(),
            Some("pcid1"),
            "the provider CID is kept in pinata_cid"
        );

        // An existing NULL-provenance row: the pinata COALESCE fills it, and the
        // prior local pin's `cid` is left untouched (not overwritten by the raw arg).
        state
            .db
            .record_pinned_cid("po2", "localcid2", None)
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
            po2.cid, "localcid2",
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
            vec![fx.public_oid.clone()],
            &state.db,
            "repoZ",
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
            vec![fx.public_oid.clone()],
            &state.db,
            "repoBF",
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
            vec![fx.public_oid.clone()],
            &state.db,
            &repo.id,
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
            vec![fx.public_oid.clone()],
            &state.db,
            "repoCG",
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
            vec![phantom_oid.clone()],
            &state.db,
            "repoUR",
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
    /// gets `pinned_cids.legacy_provider_cid` from the NEW v14 migration. Simulate the
    /// pre-v14 node by dropping the column and un-applying v14, then re-migrate and
    /// assert a repair round-trips through the column. RED before the v14 migration
    /// exists (the column is never re-added → the repair UPDATE errors).
    #[sqlx::test]
    async fn pinned_cids_legacy_provider_cid_upgrade_path(pool: PgPool) {
        let state = test_state(pool.clone()).await;

        // Pre-v14 shape: drop the column and forget v14 was applied.
        sqlx::query("ALTER TABLE pinned_cids DROP COLUMN IF EXISTS legacy_provider_cid")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 14")
            .execute(&pool)
            .await
            .unwrap();

        // Upgrade: re-run migrations → v14 re-adds the column.
        state.db.run_migrations().await.expect("migrate to v14");

        // A repair round-trips through the v14 column.
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
        assert_eq!(cid, "bRawContentKey", "v14 lets the repair rewrite the key");
        assert_eq!(
            stashed.as_deref(),
            Some("QmProviderLegacy"),
            "the v14 legacy_provider_cid column is present after upgrade"
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
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(1, Duration::from_secs(3600));
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
        // Budget = one full scan of the four seeded repos. A repeat scan from the same
        // IP then finds it spent. Keyed on XFF so `oneshot` can choose the source IP.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(4, Duration::from_secs(3600));
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
        let cfg =
            crate::config::Config::parse_from(["gitlawb-node", "--ipfs-max-repos-walked", "1"]);
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

        // Withholding repo, iterated FIRST (later updated_at; list_all_repos is DESC).
        let mut withhold = seed_repo(&owner_did, "withhold");
        withhold.updated_at = Utc::now();
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

        // Public copy, no rules, iterated AFTER.
        let mut pubcopy = seed_repo(&owner_did, "pubcopy");
        pubcopy.updated_at = Utc::now() - chrono::Duration::seconds(60);
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
    /// would serve 200 if the error arm wrongly proceeded.
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

        // Withheld secret CID under a walk error → 404, no leak.
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
            "walk error must not serve the withheld blob"
        );
        assert!(
            !body.contains("TOP SECRET"),
            "walk-error 404 must not leak the secret"
        );

        // The PUBLIC blob in the same repo is also 404: the walk error fails closed
        // by skipping the whole repo, not by serving. Without the fail-closed arm
        // this would serve 200, so this assertion is the load-bearing discriminator.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&public_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
            "walk error fails closed: repo skipped, even the public blob is not served"
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
        // public commit is 404 (not served). A fail-OPEN arm would 200 here.
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&commit_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::NOT_FOUND,
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
        // The scan probes both seeded repos (walklimit + walkpublic) per request, so
        // size the per-IP budget to admit exactly one full scan (2 probes). A repeat
        // scan from the same IP then finds the bucket spent. Keyed on the rightmost
        // X-Forwarded-For hop so the test can choose a source IP under `oneshot`.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(2, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        let fx = seed_cid_repos(&slug, &short, &["walklimit"]);
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("walklimit.git");
        // The tree CID drives a path-scoped walk (the load-bearing amplification
        // surface). The reader is allowed under /secret so the walk returns 200.
        let secret_tree_cid = pin_cid_for(&bare, &fx.secret_tree_oid, &state.db).await;

        // Oldest `updated_at` → `list_all_repos` (ORDER BY updated_at DESC) probes
        // this serving repo LAST, so a scan deterministically charges the walk-free
        // `walkpublic` miss first then this serve: exactly 2 probes per scan.
        let mut walklimit = seed_repo(&owner_did, "walklimit");
        walklimit.updated_at = chrono::Utc::now() - chrono::Duration::seconds(60);
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
    /// because a newer path-scoped duplicate sorts ahead of an older no-rule copy under
    /// `updated_at DESC`. Two same-oid legacy copies: a NEWER `/secret`-scoped denier
    /// and an OLDER no-rule public copy.
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
        // Budget = one full two-repo scan (2 probes), keyed on the rightmost XFF hop
        // so `oneshot` can choose a source IP (no socket peer). A repeat scan from the
        // same IP then finds the budget spent.
        state.ipfs_work_rate_limiter =
            crate::rate_limit::RateLimiter::new(2, Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::XForwardedFor;

        // Identical secret-blob content in both bare clones → one CID resolves to
        // `secret_oid` in each. A NEWER path-scoped denier (walk-and-deny anon) and an
        // OLDER no-rule public copy (walk-free serve).
        let fx = seed_cid_repos(&slug, &short, &["scopeddenier", "publiccopy"]);
        let denier_bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("scopeddenier.git");
        let secret_cid = pin_cid_for(&denier_bare, &fx.secret_oid, &state.db).await;

        // Newer denier: public at "/", `/secret/**` Mode B empty readers → an anon
        // blob fetch clears "/", runs the allowed-blob walk, is denied → continue.
        let mut denier = seed_repo(&owner_did, "scopeddenier");
        denier.updated_at = Utc::now();
        state.db.create_repo(&denier).await.expect("seed denier");
        state
            .db
            .set_visibility_rule(&denier.id, "/secret/**", VisibilityMode::B, &[], &owner_did)
            .await
            .expect("path rule");

        // Older public copy — NO rule → the secret blob serves via the no-walk path.
        let mut public = seed_repo(&owner_did, "publiccopy");
        public.updated_at = Utc::now() - chrono::Duration::seconds(60);
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
    /// OLDEST `updated_at` so `list_all_repos` (ORDER BY updated_at DESC) iterates it
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

        // 1) Readable public copy — OLDEST updated_at → iterated LAST. Public with
        //    NO visibility rule, so the blob serves via the no-walk path. This is
        //    the copy an uncapped fan-out would eventually reach and serve.
        let mut readable = seed_repo(&owner_did, "readable");
        readable.updated_at = Utc::now() - chrono::Duration::seconds(60);
        state
            .db
            .create_repo(&readable)
            .await
            .expect("seed readable copy");

        // 2) cap+1 deniers with NEWER updated_at → iterated before the copy. Public
        //    at "/", but a `/secret/**` Mode B rule with an EMPTY reader list, so an
        //    anon blob fetch clears the "/" gate, runs the allowed-blob walk, and is
        //    denied (the secret blob is in no one's set) → continue. Each distinct
        //    repo.id is its own walk (the memo only dedups the same repo).
        for name in &denier_names {
            let mut denier = seed_repo(&owner_did, name);
            denier.updated_at = Utc::now();
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

    // ---- U3 (#173 F3): coalesced post-push work is REQUEUED, not dropped ----
    //
    // The seam mechanics (dirty flag, atomic check-and-clear, Drop backstop) are unit
    // tested next to the #174 coalescing tests in `api/repos.rs`. These drive the whole
    // detached task through a mock Kubo node and a real git repo, so the requeue's
    // fresh re-read (encrypt half) and fail-closed full-scan enumeration (pin half) are
    // proven end to end, with DB-observable effects. Each test models a push that
    // coalesced during the in-flight window by (a) marking the repo dirty via a second
    // `try_begin` and (b) making the repo/policy dynamic so the FIRST pass's spawn-time
    // captures are stale — a static-state test would pass vacuously over the gap.
    mod u3_requeue {
        use super::*;
        use crate::db::VisibilityMode;
        use std::collections::HashSet;
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

        /// SCENARIO 2 + 5 (pin half, TAIL-PLACEMENT guard). A coalesced push on a PUBLIC
        /// repo with NO path-scoped rule must still requeue its pin half: the second
        /// push's new object is pinned after the task. RED without the loop (stale spawn
        /// object_list never lists obj2), and RED if the check-and-clear sits inside the
        /// `has_path_scoped_rule` block (a rules-free repo would never reach it).
        #[sqlx::test]
        async fn u3_rules_free_public_repo_requeues_pin_half(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let repo = seed_repo(&owner, "u3-pin");
            state.db.create_repo(&repo).await.expect("seed repo");
            let git_repo = init_repo();
            let obj1 = commit(&git_repo.path, "a.txt", "one\n");
            // The coalesced push B adds obj2 (present at requeue time, NOT in the stale
            // push-A spawn object_list).
            let obj2 = commit(&git_repo.path, "b.txt", "two\n");

            let mut server = mockito::Server::new_async().await;
            let _m = server
                .mock("POST", mockito::Matcher::Regex(r"^/api/v0/add".to_string()))
                .with_status(200)
                .with_body(r#"{"Hash":"bafyprovider"}"#)
                .expect_at_least(1)
                .create_async()
                .await;

            // Push A admits (guard); push B coalesces (marks dirty).
            let guard = state
                .encrypt_inflight
                .try_begin(&repo.id)
                .expect("push A admits");
            assert!(
                state.encrypt_inflight.try_begin(&repo.id).is_none(),
                "push B coalesces while A is in flight"
            );

            // Spawn-time (push A) captures are STALE: object_list lists only obj1, no rule.
            crate::api::repos::run_post_push_replication_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                server.url(),
                true,
                owner.clone(),
                vec![obj1.clone()],
                Some(vec![]),
                HashSet::new(),
            )
            .await;

            assert!(
                state.db.is_pinned(&obj1).await.unwrap(),
                "push A's object is pinned on the first pass"
            );
            assert!(
                state.db.is_pinned(&obj2).await.unwrap(),
                "the coalesced push's new object is pinned by the REQUEUE full scan (RED \
                 without the loop, or if the check-and-clear sits inside the encrypt gate)"
            );
            assert!(
                state.encrypt_inflight.is_empty(),
                "the guard key is released once the task exits clean"
            );
        }

        /// SCENARIO 1 + 3 (encrypt half, FRESH re-read). A coalesced push adds a
        /// path-scoped rule withholding a blob. The task must re-read rules FRESH on
        /// requeue and seal the newly-withheld blob's recovery copy. RED without the loop
        /// (pass one's stale empty rule set seals nothing).
        #[sqlx::test]
        async fn u3_requeue_seals_blob_withheld_by_coalesced_rule_change(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let reader = new_did();
            let repo = seed_repo(&owner, "u3-enc");
            state.db.create_repo(&repo).await.expect("seed repo");
            let git_repo = init_repo();
            let _pub_oid = commit(&git_repo.path, "public/a.txt", "public\n");
            let secret_oid = commit(&git_repo.path, "secret/b.txt", "TOP SECRET\n");

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

            let guard = state
                .encrypt_inflight
                .try_begin(&repo.id)
                .expect("push A admits");
            assert!(
                state.encrypt_inflight.try_begin(&repo.id).is_none(),
                "push B coalesces"
            );

            // Push A captures are STALE: no rule, empty withheld set (public repo).
            crate::api::repos::run_post_push_replication_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                server.url(),
                true,
                owner.clone(),
                vec![],
                Some(vec![]),
                HashSet::new(),
            )
            .await;

            assert!(
                state
                    .db
                    .encrypted_blob_recipients_tag(&repo.id, &secret_oid)
                    .await
                    .unwrap()
                    .is_some(),
                "the coalesced push's newly-withheld blob is sealed after the REQUEUE re-read \
                 (RED without the loop: pass one's stale empty rules seal nothing)"
            );
            assert!(state.encrypt_inflight.is_empty(), "guard key released");
        }

        /// SCENARIO 4 (visibility-leak negative). The requeue full scan must feed
        /// `list_all_objects` through the fail-closed filter, never pin it bare: a
        /// withheld secret blob and a dangling blob must NOT land in the public pin set.
        #[sqlx::test]
        async fn u3_requeue_full_scan_does_not_publicly_pin_withheld_or_dangling(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let reader = new_did();
            let repo = seed_repo(&owner, "u3-leak");
            state.db.create_repo(&repo).await.expect("seed repo");
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
            let mut withheld = HashSet::new();
            withheld.insert(secret_oid.clone());

            let guard = state
                .encrypt_inflight
                .try_begin(&repo.id)
                .expect("push A admits");
            assert!(
                state.encrypt_inflight.try_begin(&repo.id).is_none(),
                "push B coalesces"
            );

            crate::api::repos::run_post_push_replication_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                server.url(),
                true,
                owner.clone(),
                vec![pub_oid.clone()],
                Some(rules),
                withheld,
            )
            .await;

            assert!(
                state.db.is_pinned(&new_pub_oid).await.unwrap(),
                "the coalesced push's new PUBLIC object is pinned by the requeue"
            );
            assert!(
                !state.db.is_pinned(&secret_oid).await.unwrap(),
                "a WITHHELD blob is never publicly pinned by the requeue enumeration (leak guard)"
            );
            assert!(
                !state.db.is_pinned(&dangling_oid).await.unwrap(),
                "a DANGLING blob is never publicly pinned by the requeue enumeration (leak guard)"
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
        /// runs exactly one pass, pins its object, and releases the key. No requeue.
        #[sqlx::test]
        async fn u3_no_coalesce_single_pass_pins_and_releases(pool: PgPool) {
            let state = test_state(pool).await;
            let owner = new_did();
            let repo = seed_repo(&owner, "u3-happy");
            state.db.create_repo(&repo).await.expect("seed repo");
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

            // No second try_begin: the repo is never marked dirty.
            let guard = state
                .encrypt_inflight
                .try_begin(&repo.id)
                .expect("push admits");
            assert_eq!(
                state.encrypt_inflight.dirty(&repo.id),
                Some(false),
                "clean, no coalesce"
            );

            crate::api::repos::run_post_push_replication_for_test(
                &state,
                guard,
                git_repo.path.clone(),
                repo.id.clone(),
                server.url(),
                true,
                owner.clone(),
                vec![obj1.clone()],
                Some(vec![]),
                HashSet::new(),
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
    }
}
