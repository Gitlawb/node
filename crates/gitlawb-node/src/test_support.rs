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
        shutdown_tx: tokio::sync::watch::channel(false).0,
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
            .upsert_mirror_repo(short, "shared", "/tmp/mirror", None)
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
            .upsert_mirror_repo(short, "shared", "/tmp/mirror", None)
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
}
