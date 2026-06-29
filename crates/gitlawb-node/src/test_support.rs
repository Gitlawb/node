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

    /// #94 sibling: list_repo_events gates a LOCALLY-HOSTED private repo (both its
    /// ref certificates and its gossip ref-updates → 404) without breaking a repo
    /// the node knows only via gossip (no local row), which legitimately 200s.
    #[sqlx::test]
    async fn list_repo_events_gates_local_private_but_not_gossip_only(pool: PgPool) {
        use crate::db::{ReceivedRefUpdate, RefCertificate};
        let owner = "did:key:zEVTOWNERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let keypart = owner.split(':').next_back().unwrap();
        let state = test_state(pool).await;

        let pub_repo = seed_repo(owner, "evt-pub");
        state
            .db
            .create_repo(&pub_repo)
            .await
            .expect("seed public repo");
        let mut priv_repo = seed_repo(owner, "evt-priv");
        priv_repo.is_public = false;
        state
            .db
            .create_repo(&priv_repo)
            .await
            .expect("seed private repo");

        let seed_cert = |repo_id: &str, ref_name: &str, sha: &str| RefCertificate {
            id: uuid::Uuid::new_v4().to_string(),
            repo_id: repo_id.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: "0".repeat(40),
            new_sha: sha.to_string(),
            pusher_did: owner.to_string(),
            node_did: owner.to_string(),
            signature: "sig".to_string(),
            issued_at: Utc::now().to_rfc3339(),
        };
        let seed_update = |slug: &str, ref_name: &str, sha: &str| ReceivedRefUpdate {
            id: uuid::Uuid::new_v4().to_string(),
            node_did: owner.to_string(),
            pusher_did: owner.to_string(),
            repo: slug.to_string(),
            ref_name: ref_name.to_string(),
            old_sha: "0".repeat(40),
            new_sha: sha.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            cert_id: None,
            received_at: Utc::now().to_rfc3339(),
            from_peer: "peer".to_string(),
        };

        // Public local repo: a visible cert.
        state
            .db
            .insert_ref_certificate(&seed_cert(
                &pub_repo.id,
                "refs/heads/public-main",
                "pubsha00",
            ))
            .await
            .expect("seed public cert");
        // Private local repo: a secret cert AND a secret gossip update (slug uses
        // the full owner-DID key part, as the handler computes for a local repo).
        state
            .db
            .insert_ref_certificate(&seed_cert(
                &priv_repo.id,
                "refs/heads/embargo-cert",
                "certSEKRET",
            ))
            .await
            .expect("seed private cert");
        state
            .db
            .insert_ref_update(&seed_update(
                &format!("{keypart}/evt-priv"),
                "refs/heads/embargo-gossip",
                "gossipSEKRET",
            ))
            .await
            .expect("seed private gossip update");
        // Gossip-only repo: no local row; slug uses the URL owner segment.
        state
            .db
            .insert_ref_update(&seed_update(
                "zGHOSTOWNER/ghost-repo",
                "refs/heads/ghost",
                "ghostsha0",
            ))
            .await
            .expect("seed gossip-only update");

        let router = || {
            Router::new()
                .route(
                    "/api/v1/repos/{owner}/{repo}/events",
                    axum::routing::get(crate::api::events::list_repo_events),
                )
                .with_state(state.clone())
        };
        let anon = |uri: String| {
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        };
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).to_string();

        // Characterization 1: public local repo, anonymous → 200, cert present.
        let resp = router()
            .oneshot(anon(format!("/api/v1/repos/{owner}/evt-pub/events")))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "public events stay anonymous"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            text(&bytes).contains("public-main"),
            "public cert must be listed"
        );

        // Characterization 2: gossip-only repo (no local row), anonymous → 200,
        // gossip event present. This is the None path the gate must not break.
        let resp = router()
            .oneshot(anon(
                "/api/v1/repos/zGHOSTOWNER/ghost-repo/events".to_string(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "gossip-only repo still serves events"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            text(&bytes).contains("ghost"),
            "gossip-only event must be served"
        );

        // The leak fix: locally-hosted PRIVATE repo, anonymous → 404, and neither
        // the cert nor the gossip secret appears in the body.
        let resp = router()
            .oneshot(anon(format!("/api/v1/repos/{owner}/evt-priv/events")))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a non-reader of a local private repo must get 404"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = text(&bytes);
        assert!(
            !body.contains("embargo-cert"),
            "404 must not leak the cert ref"
        );
        assert!(
            !body.contains("certSEKRET"),
            "404 must not leak the cert sha"
        );
        assert!(
            !body.contains("embargo-gossip"),
            "404 must not leak the gossip ref"
        );
        assert!(
            !body.contains("gossipSEKRET"),
            "404 must not leak the gossip sha"
        );

        // Owner of the private repo → 200, events present.
        let resp = router()
            .oneshot(signed_request_as(
                owner,
                Method::GET,
                &format!("/api/v1/repos/{owner}/evt-priv/events"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "owner reads its private events"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            text(&bytes).contains("embargo-cert"),
            "owner sees the private cert"
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
}
