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
        push_limiter_trust: crate::rate_limit::TrustedProxy::None,
        sync_trigger_rate_limiter: RateLimiter::new(60, Duration::from_secs(3600)),
        peer_write_rate_limiter: RateLimiter::new(600, Duration::from_secs(3600)),
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
}
