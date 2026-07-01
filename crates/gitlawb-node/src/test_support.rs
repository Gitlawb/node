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
    /// SHA-256 object format is required: `get_by_cid` resolves a CID whose
    /// multihash digest IS the git object id, which only matches in sha256 repos.
    struct CidFixture {
        _guards: Vec<std::path::PathBuf>,
        secret_oid: String,
        public_oid: String,
        secret_tree_oid: String,
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
        }
        // One guard for the whole /tmp/<slug> tree covers every bare clone.
        guards.push(std::path::PathBuf::from("/tmp").join(slug));
        CidFixture {
            _guards: guards,
            secret_oid,
            public_oid,
            secret_tree_oid,
        }
    }

    /// CID whose sha2-256 multihash digest equals the given 64-hex git oid, so
    /// `get_by_cid` decodes it back to that oid and `git cat-file`s it.
    fn cid_for_oid(oid_hex: &str) -> String {
        use gitlawb_core::cid::Cid;
        let bytes = hex::decode(oid_hex).expect("hex oid");
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("32-byte sha256 oid");
        Cid::from_sha256_bytes(&arr).to_string()
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
    fn cid_anon(cid: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(format!("/ipfs/{cid}"))
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
        let secret_cid = cid_for_oid(&fx.secret_oid);
        let tree_cid = cid_for_oid(&fx.secret_tree_oid);
        let public_cid = cid_for_oid(&fx.public_oid);

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

        // KTD3: anon tree CID under /secret → 200 (trees/commits are not withheld).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&tree_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "tree object is served to anon (KTD3)");

        // R3: public blob anon → 200 (non-withheld content not affected).
        let (st, _) = cid_parts(
            cid_router(&state)
                .oneshot(cid_anon(&public_cid))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "public blob stays served");

        // R5: a genuine unknown CID also 404, uniform with the withheld 404.
        let absent_cid = cid_for_oid(&"ab".repeat(32));
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
        let secret_cid = cid_for_oid(&fx.secret_oid);

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
        let blob_cid = cid_for_oid(&fx.public_oid);

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
        let secret_cid = cid_for_oid(&fx.secret_oid);
        let public_cid = cid_for_oid(&fx.public_oid);

        // Force the withheld walk to fail closed: a ref pointing at a blob (not
        // tree-ish) makes `git ls-tree -r` error, which `withheld_blob_oids`
        // propagates as Err → the handler's `Ok(Err)` arm skips the repo.
        let bare = std::path::PathBuf::from("/tmp")
            .join(&slug)
            .join("withhold.git");
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
        let dangling_cid = cid_for_oid(&dangling_oid);

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

    fn pins_router(state: &AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/ipfs/pins",
                axum::routing::get(crate::api::ipfs::list_pins),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state.clone())
    }

    fn signed_get(kp: &gitlawb_core::identity::Keypair, uri: &str) -> Request<Body> {
        let s = gitlawb_core::http_sig::sign_request(kp, "GET", uri, b"");
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("content-digest", s.content_digest)
            .header("signature-input", s.signature_input)
            .header("signature", s.signature)
            .body(Body::empty())
            .unwrap()
    }

    /// #121: anonymous caller gets 401 from /api/v1/ipfs/pins.
    #[sqlx::test]
    async fn pins_list_denies_anonymous(pool: PgPool) {
        let state = test_state(pool).await;
        let resp = pins_router(&state)
            .oneshot(anon_get("/api/v1/ipfs/pins"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    struct PinTestFixture {
        owner: gitlawb_core::identity::Keypair,
        owner_did: String,
        fx: CidFixture,
        repo: crate::db::RepoRecord,
    }

    async fn setup_pin_test(state: &AppState, repo_name: &str) -> PinTestFixture {
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let fs_slug = owner_did.replace([':', '/'], "_");
        let short = owner_did.split(':').next_back().unwrap().to_string();

        let fx = seed_cid_repos(&fs_slug, &short, &[repo_name]);
        let repo = seed_repo(&owner_did, repo_name);
        state.db.create_repo(&repo).await.unwrap();

        PinTestFixture {
            owner,
            owner_did,
            fx,
            repo,
        }
    }

    /// #121: authenticated caller gets 200 from /api/v1/ipfs/pins.
    ///
    /// list_pins only returns pins whose SHA-256 appears in a repo the caller
    /// can read. The test therefore:
    ///  1. Creates a real SHA-256 bare git repo on disk (via seed_cid_repos) so
    ///     list_all_objects finds the object.
    ///  2. Inserts a matching public repo row (owner_did = full DID from the keypair)
    ///     so list_all_repos/visibility_check passes.
    ///  3. Records a pin for the real object OID.
    #[sqlx::test]
    async fn pins_list_allows_authenticated(pool: PgPool) {
        let state = test_state(pool).await;
        let setup = setup_pin_test(&state, "pinrepo").await;

        let pinned_sha = setup.fx.public_oid.clone();
        let pinned_cid = cid_for_oid(&pinned_sha);

        state
            .db
            .record_pinned_cid(&pinned_sha, &pinned_cid)
            .await
            .unwrap();

        let resp = pins_router(&state)
            .oneshot(signed_get(&setup.owner, "/api/v1/ipfs/pins"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["count"], 1,
            "pin for the real git object must be returned"
        );
        assert_eq!(
            body["pins"][0]["sha256_hex"], pinned_sha,
            "returned pin must match the seeded object OID"
        );
    }

    /// #121: authenticated caller gets 200 through the production build_router.
    ///
    /// Unlike pins_list_allows_authenticated (which uses a mini pins_router with
    /// only the one route), this test exercises server::build_router to verify
    /// that /api/v1/ipfs/pins is wired through optional_signature in the real
    /// route table and that a signed request reaches list_pins successfully.
    #[sqlx::test]
    async fn pins_list_allows_authenticated_through_build_router(pool: PgPool) {
        let state = test_state(pool).await;
        let setup = setup_pin_test(&state, "build-router-pins").await;

        let pinned_sha = setup.fx.public_oid.clone();
        let pinned_cid = cid_for_oid(&pinned_sha);

        state
            .db
            .record_pinned_cid(&pinned_sha, &pinned_cid)
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(signed_get(&setup.owner, "/api/v1/ipfs/pins"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["count"], 1,
            "build_router wiring: pin for the real git object must be returned"
        );
        assert_eq!(
            body["pins"][0]["sha256_hex"], pinned_sha,
            "build_router wiring: returned pin must match the seeded object OID"
        );
    }

    #[sqlx::test]
    async fn pins_list_excludes_quarantined_repos(pool: PgPool) {
        let state = test_state(pool).await;
        let setup = setup_pin_test(&state, "pinrepo").await;

        let pinned_sha = setup.fx.public_oid.clone();
        let pinned_cid = cid_for_oid(&pinned_sha);

        state
            .db
            .set_repo_quarantine(&setup.repo.id, true)
            .await
            .unwrap();

        state
            .db
            .record_pinned_cid(&pinned_sha, &pinned_cid)
            .await
            .unwrap();

        let resp = pins_router(&state)
            .oneshot(signed_get(&setup.owner, "/api/v1/ipfs/pins"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["count"], 0,
            "quarantined repo objects must be withheld from pin index"
        );
    }

    #[sqlx::test]
    async fn pins_list_withholds_path_scoped_blobs(pool: PgPool) {
        use crate::db::VisibilityMode;
        use gitlawb_core::identity::Keypair;

        let state = test_state(pool).await;
        let setup = setup_pin_test(&state, "pinrepo").await;
        let stranger = Keypair::generate();

        let public_sha = setup.fx.public_oid.clone();
        let public_cid = cid_for_oid(&public_sha);
        let secret_sha = setup.fx.secret_oid.clone();
        let secret_cid = cid_for_oid(&secret_sha);

        state
            .db
            .set_visibility_rule(
                &setup.repo.id,
                "/secret/**",
                VisibilityMode::B,
                &[],
                &setup.owner_did,
            )
            .await
            .unwrap();

        state
            .db
            .record_pinned_cid(&public_sha, &public_cid)
            .await
            .unwrap();
        state
            .db
            .record_pinned_cid(&secret_sha, &secret_cid)
            .await
            .unwrap();

        let resp = pins_router(&state)
            .oneshot(signed_get(&stranger, "/api/v1/ipfs/pins"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;

        assert_eq!(body["count"], 1, "stranger sees only the public pin");
        assert_eq!(
            body["pins"][0]["sha256_hex"], public_sha,
            "stranger sees the public pin"
        );
    }

    // ---- #121: GET /api/v1/arweave/anchors auth and visibility gate ----

    fn anchors_router(state: &AppState) -> Router {
        Router::new()
            .route(
                "/api/v1/arweave/anchors",
                axum::routing::get(crate::api::arweave::list_anchors),
            )
            .layer(axum::middleware::from_fn(crate::auth::optional_signature))
            .with_state(state.clone())
    }

    async fn seed_anchor(db: &crate::db::Db, repo: &str, owner_did: &str) {
        use crate::db::RecordAnchorInput;
        db.record_arweave_anchor(&RecordAnchorInput {
            repo,
            owner_did,
            ref_name: "refs/heads/main",
            old_sha: "0000000000000000000000000000000000000000000000000000000000000000",
            new_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            cid: Some("bafkreihipknrba7vz6ahh2l5qk6pxwtywn3u7worv6hmi6dkt6nv5phb4u"),
            irys_tx_id: "tx-test",
            arweave_url: "https://arweave.net/test",
            node_did: "did:key:zNODE",
        })
        .await
        .unwrap();
    }

    /// #121: /api/v1/arweave/anchors without ?repo= denies anonymous.
    #[sqlx::test]
    async fn anchors_global_denies_anonymous(pool: PgPool) {
        let state = test_state(pool).await;
        let resp = anchors_router(&state)
            .oneshot(anon_get("/api/v1/arweave/anchors"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    struct AnchorTestFixture {
        owner: gitlawb_core::identity::Keypair,
        owner_did: String,
    }

    async fn setup_anchor_test(
        state: &AppState,
        repo_name: &str,
        is_public: bool,
    ) -> AnchorTestFixture {
        use gitlawb_core::identity::Keypair;

        let owner = Keypair::generate();
        let owner_did = owner.did().to_string();
        let owner_short = owner_did.split(':').next_back().unwrap().to_string();
        let short_slug = format!("{owner_short}/{repo_name}");

        let repo = if is_public {
            seed_repo(&owner_did, repo_name)
        } else {
            seed_private_repo(&owner_did, repo_name)
        };

        state.db.create_repo(&repo).await.unwrap();
        seed_anchor(&state.db, &short_slug, &owner_did).await;

        AnchorTestFixture { owner, owner_did }
    }

    /// #121: /api/v1/arweave/anchors without ?repo= allows authenticated.
    ///
    /// The global listing filters each anchor through authorize_repo_read, which
    /// splits anchor.repo on '/' to get (owner, name) and calls get_repo. The
    /// anchor row must therefore carry the same short owner slug that the push
    /// path writes (last ':'-separated segment of the DID) so get_repo's fuzzy
    /// LIKE match finds the repo record.
    #[sqlx::test]
    async fn anchors_global_allows_authenticated(pool: PgPool) {
        let state = test_state(pool).await;
        let fx = setup_anchor_test(&state, "globalrepo", true).await;

        let resp = anchors_router(&state)
            .oneshot(signed_get(&fx.owner, "/api/v1/arweave/anchors"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["count"], 1,
            "authenticated caller sees the seeded anchor"
        );
    }

    #[sqlx::test]
    async fn anchors_global_denies_non_reader(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let state = test_state(pool).await;
        let _fx = setup_anchor_test(&state, "privaterepo", false).await;
        let stranger = Keypair::generate();

        let resp = anchors_router(&state)
            .oneshot(signed_get(&stranger, "/api/v1/arweave/anchors"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["count"], 0,
            "non-reader is denied the private anchor in global listing"
        );
    }

    /// #121: /api/v1/arweave/anchors with ?repo= denies anonymous on private repo.
    ///
    /// The ?repo= path gate is purely visibility-based (authorize_repo_read returns
    /// 404 for anon on private) — no anonymous-rejection guard is needed here.
    #[sqlx::test]
    async fn anchors_repo_denies_anonymous_on_private(pool: PgPool) {
        let state = test_state(pool).await;
        let repo_name = "private-repo";
        let fx = setup_anchor_test(&state, repo_name, false).await;

        let uri = format!(
            "/api/v1/arweave/anchors?repo={}/{}",
            fx.owner_did, repo_name
        );
        let resp = anchors_router(&state)
            .oneshot(anon_get(&uri))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// #121: /api/v1/arweave/anchors with ?repo= allows anonymous on public repo.
    #[sqlx::test]
    async fn anchors_repo_allows_anonymous_on_public(pool: PgPool) {
        let state = test_state(pool).await;
        let repo_name = "public-repo";
        let fx = setup_anchor_test(&state, repo_name, true).await;

        let uri = format!(
            "/api/v1/arweave/anchors?repo={}/{}",
            fx.owner_did, repo_name
        );
        let resp = anchors_router(&state)
            .oneshot(anon_get(&uri))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["count"], 1,
            "anonymous caller sees the seeded public anchor"
        );
    }

    /// #121: /api/v1/arweave/anchors with ?repo= allows repo owner.
    ///
    /// Anchor is stored with the short owner slug that push writes; the ?repo=
    /// query carries the full DID which list_anchors normalises to the same short
    /// slug before issuing the DB query.
    #[sqlx::test]
    async fn anchors_repo_allows_owner(pool: PgPool) {
        let state = test_state(pool).await;
        let repo_name = "owners-repo";
        let fx = setup_anchor_test(&state, repo_name, false).await;

        let uri = format!(
            "/api/v1/arweave/anchors?repo={}/{}",
            fx.owner_did, repo_name
        );
        let resp = anchors_router(&state)
            .oneshot(signed_get(&fx.owner, &uri))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["count"], 1, "repo owner sees their anchor");
    }

    /// #121: /api/v1/arweave/anchors with ?repo= denies authenticated non-reader on private repo.
    #[sqlx::test]
    async fn anchors_repo_denies_non_reader(pool: PgPool) {
        use gitlawb_core::identity::Keypair;
        let state = test_state(pool).await;
        let repo_name = "private-repo";
        let fx = setup_anchor_test(&state, repo_name, false).await;
        let stranger = Keypair::generate();

        let uri = format!(
            "/api/v1/arweave/anchors?repo={}/{}",
            fx.owner_did, repo_name
        );
        let resp = anchors_router(&state)
            .oneshot(signed_get(&stranger, &uri))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
