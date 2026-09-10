pub mod mutation;
pub mod query;
pub mod subscription;
pub mod types;

use async_graphql::{Schema, SchemaBuilder};
use std::sync::Arc;

use crate::db::Db;
use crate::state::{RefUpdateBroadcast, TaskEventBroadcast};
use mutation::MutationRoot;
use query::QueryRoot;
use subscription::SubscriptionRoot;

pub type GitlawbSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

// Keep ordinary schema discovery and application queries usable while
// bounding validation work and the number of resolver selections per request.
const GRAPHQL_MAX_COMPLEXITY: usize = 400;
// The current public schema is shallow; this leaves headroom for composed
// clients without allowing recursively nested documents to grow unchecked.
const GRAPHQL_MAX_DEPTH: usize = 12;

fn apply_query_limits<Query, Mutation, Subscription>(
    builder: SchemaBuilder<Query, Mutation, Subscription>,
) -> SchemaBuilder<Query, Mutation, Subscription> {
    builder
        .limit_complexity(GRAPHQL_MAX_COMPLEXITY)
        .limit_depth(GRAPHQL_MAX_DEPTH)
}

/// Client-facing message for GraphQL resolver failures that wrap a real
/// `sqlx::Error`. The real error is logged server-side; never put sqlx/Postgres
/// detail in the GraphQL `errors` array (#250).
///
/// Kept as its own constant on this PR's base (main still renders
/// `AppError::Db` with `e.to_string()`). If/when #247's `DB_ERROR_MESSAGE`
/// lands, fold this into that shared constant.
pub const GRAPHQL_DB_ERROR_MESSAGE: &str = "a database error occurred";

fn anyhow_has_sqlx(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<sqlx::Error>().is_some())
}

/// Map an `anyhow` failure from the db layer to a GraphQL error.
///
/// - Real DB faults (`sqlx::Error` anywhere in the chain) → opaque client
///   message + `error!` log with the full `{e:#}` cause chain.
/// - Application/business errors (e.g. claim race, not-in-claimed-state) →
///   keep the actionable message; log at `warn!` so they are not mistaken for
///   infrastructure failures (#250 review).
pub(crate) fn graphql_db_err(e: anyhow::Error) -> async_graphql::Error {
    if anyhow_has_sqlx(&e) {
        tracing::error!(error = %format!("{e:#}"), "graphql database error");
        async_graphql::Error::new(GRAPHQL_DB_ERROR_MESSAGE)
    } else {
        tracing::warn!(error = %format!("{e:#}"), "graphql application error");
        async_graphql::Error::new(e.to_string())
    }
}

/// Map an `AppError` from a shared collector (e.g. ref-update feed) to a
/// GraphQL error.
///
/// Fail closed: only explicitly curated variants surface their `Display`
/// text. Unnamed variants (including `Git`, which may embed on-disk paths)
/// render opaque so a future addition cannot leak by default (#255 review).
pub(crate) fn graphql_app_err(e: crate::error::AppError) -> async_graphql::Error {
    match e {
        crate::error::AppError::Db(sql) => graphql_db_err(sql.into()),
        crate::error::AppError::Internal(err) => {
            tracing::error!(error = %format!("{err:#}"), "graphql internal error");
            async_graphql::Error::new(GRAPHQL_DB_ERROR_MESSAGE)
        }
        // Curated client-safe variants — `Display` is intentional API text.
        safe @ (crate::error::AppError::RepoNotFound(_)
        | crate::error::AppError::RepoExists(_)
        | crate::error::AppError::NotFound(_)
        | crate::error::AppError::Unauthorized(_)
        | crate::error::AppError::Forbidden(_)
        | crate::error::AppError::BadRequest(_)
        | crate::error::AppError::TooManyRequests(_)
        | crate::error::AppError::Incomplete(_)) => {
            tracing::warn!(error = %safe, "graphql application error");
            async_graphql::Error::new(safe.to_string())
        }
        other => {
            tracing::error!(error = %other, "graphql unclassified AppError (opaque)");
            async_graphql::Error::new(GRAPHQL_DB_ERROR_MESSAGE)
        }
    }
}

pub fn build_schema(
    db: Arc<Db>,
    ref_update_tx: tokio::sync::broadcast::Sender<RefUpdateBroadcast>,
    task_event_tx: tokio::sync::broadcast::Sender<TaskEventBroadcast>,
) -> GitlawbSchema {
    apply_query_limits(Schema::build(QueryRoot, MutationRoot, SubscriptionRoot))
        .data(db)
        .data(ref_update_tx)
        .data(task_event_tx)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::{EmptyMutation, EmptySubscription, Object, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn graphql_db_err_opaques_sqlx_chain() {
        let leak = "error returned from database: column \"is_public\" does not exist";
        // Context layer must not hide sqlx from the chain walk (db helpers
        // wrap with `.context(...)` in several places).
        let err = graphql_db_err(
            anyhow::Error::from(sqlx::Error::Protocol(leak.into())).context("loading repos"),
        );
        assert_eq!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!err.message.contains("is_public"));
        assert!(!err.message.contains(leak));
        assert!(!err.message.contains("loading repos"));
    }

    #[test]
    fn graphql_db_err_keeps_business_message() {
        let msg = "task not claimable: not found or already claimed";
        let err = graphql_db_err(anyhow::anyhow!("{msg}"));
        assert_eq!(err.message, msg);
    }

    #[test]
    fn graphql_app_err_opaques_db_and_internal() {
        let leak = "column \"is_public\" does not exist";
        let db_err = graphql_app_err(crate::error::AppError::Db(sqlx::Error::Protocol(
            leak.into(),
        )));
        assert_eq!(db_err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!db_err.message.contains("is_public"));

        let internal = graphql_app_err(crate::error::AppError::Internal(anyhow::anyhow!(
            "loading repo: {leak}"
        )));
        assert_eq!(internal.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!internal.message.contains("is_public"));
    }

    #[test]
    fn graphql_app_err_keeps_safe_variant_messages() {
        let err = graphql_app_err(crate::error::AppError::NotFound("widget".into()));
        assert!(
            err.message.contains("widget"),
            "safe NotFound message must reach the client: {}",
            err.message
        );
        assert_ne!(err.message, GRAPHQL_DB_ERROR_MESSAGE);

        let err = graphql_app_err(crate::error::AppError::BadRequest("bad cid".into()));
        assert!(
            err.message.contains("bad cid"),
            "safe BadRequest message must reach the client: {}",
            err.message
        );
        assert_ne!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
    }

    #[test]
    fn graphql_app_err_opaques_unclassified_variants() {
        // `Git` may embed on-disk paths from libgit2; fail closed.
        let path = "/var/lib/gitlawb/repos/owner/secret.git";
        let err = graphql_app_err(crate::error::AppError::Git(format!(
            "failed to open '{path}'"
        )));
        assert_eq!(err.message, GRAPHQL_DB_ERROR_MESSAGE);
        assert!(!err.message.contains(path));
        assert!(!err.message.contains("failed to open"));
    }

    fn production_test_schema() -> GitlawbSchema {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        production_test_schema_with_db(Arc::new(Db::for_testing(pool)))
    }

    fn production_test_schema_with_db(db: Arc<Db>) -> GitlawbSchema {
        build_schema(
            db,
            tokio::sync::broadcast::channel(1).0,
            tokio::sync::broadcast::channel(1).0,
        )
    }

    #[tokio::test]
    async fn ref_update_subscription_alias_budget() {
        assert_subscription_alias_budget("refUpdates { repo }").await;
    }

    #[tokio::test]
    async fn task_event_subscription_alias_budget() {
        assert_subscription_alias_budget("taskEvents { taskId }").await;
    }

    async fn assert_subscription_alias_budget(field: &str) {
        use futures::StreamExt;
        use std::time::Duration;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let (ref_tx, _) = tokio::sync::broadcast::channel(16);
        let (task_tx, _) = tokio::sync::broadcast::channel(16);
        let schema = build_schema(
            Arc::new(Db::for_testing(pool)),
            ref_tx.clone(),
            task_tx.clone(),
        );
        for count in [7, 8] {
            let fields = (0..count)
                .map(|n| format!("r{n}: {field}"))
                .collect::<Vec<_>>()
                .join(" ");
            let query = format!("subscription {{ {fields} }}");
            let mut responses = Box::pin(schema.execute_stream(query));
            if count == 8 {
                let response = tokio::time::timeout(Duration::from_secs(1), responses.next())
                    .await
                    .expect("over-budget subscriptions must reject before waiting for events")
                    .expect("the validation error must be returned");
                assert_eq!(response.errors.len(), 1);
                assert_eq!(response.errors[0].message, "Query is too complex.");
                assert_eq!(ref_tx.receiver_count() + task_tx.receiver_count(), 0);
                continue;
            }
            // Poll the accepted operation far enough to register its receivers.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), responses.next())
                    .await
                    .is_err()
            );
            assert_eq!(ref_tx.receiver_count() + task_tx.receiver_count(), 7);
            let _ = ref_tx.send(RefUpdateBroadcast {
                repo: "owner/repo".into(),
                ref_name: "refs/heads/main".into(),
                old_sha: "0".repeat(40),
                new_sha: "1".repeat(40),
                pusher_did: "did:key:test".into(),
                node_did: "did:key:node".into(),
                timestamp: "2026-01-01T00:00:00Z".into(),
                owner_did: "did:key:test".into(),
            });
            let _ = task_tx.send(TaskEventBroadcast {
                task_id: "task".into(),
                old_status: "pending".into(),
                new_status: "claimed".into(),
                by_did: "did:key:test".into(),
                at: "2026-01-01T00:00:00Z".into(),
            });
            let response = tokio::time::timeout(Duration::from_secs(1), responses.next())
                .await
                .unwrap()
                .unwrap();
            assert!(response.errors.is_empty(), "{:?}", response.errors);
            assert_ne!(response.data, Value::Null);
            drop(responses);
            assert_eq!(ref_tx.receiver_count() + task_tx.receiver_count(), 0);
        }
    }

    #[sqlx::test]
    async fn production_mutation_budget_accepts_seven_and_rejects_eight(pool: sqlx::PgPool) {
        let db = Arc::new(Db::for_testing(pool));
        db.run_migrations().await.unwrap();
        let caller = "did:key:reviewer";
        let now = chrono::Utc::now().to_rfc3339();
        for index in 0..8 {
            db.create_task(&crate::db::AgentTask {
                id: format!("task-{index}"),
                repo_id: None,
                kind: "test".into(),
                status: "pending".into(),
                delegator_did: caller.into(),
                assignee_did: None,
                capability: "test".into(),
                ucan_token: None,
                payload: None,
                result: None,
                created_at: now.clone(),
                updated_at: now.clone(),
                deadline: None,
            })
            .await
            .unwrap();
        }
        let schema = production_test_schema_with_db(db.clone());
        for count in [8, 7] {
            let fields = (0..count)
                .map(|n| {
                    format!("r{n}: claimTask(id: \"task-{n}\", assigneeDid: \"{caller}\") {{ id }}")
                })
                .collect::<Vec<_>>()
                .join(" ");
            let response = schema
                .execute(
                    async_graphql::Request::new(format!("mutation {{ {fields} }}"))
                        .data(crate::auth::AuthenticatedDid(caller.into())),
                )
                .await;
            if count == 8 {
                assert_eq!(response.errors.len(), 1);
                assert_eq!(response.errors[0].message, "Query is too complex.");
                assert_eq!(
                    db.list_tasks(Some("pending"), None, 8).await.unwrap().len(),
                    8
                );
                continue;
            }
            assert!(response.errors.is_empty(), "{:?}", response.errors);
            assert_eq!(
                response
                    .data
                    .into_json()
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .len(),
                7
            );
            assert_eq!(
                db.list_tasks(Some("claimed"), Some(caller), 8)
                    .await
                    .unwrap()
                    .len(),
                7
            );
            assert_eq!(
                db.get_task("task-7").await.unwrap().unwrap().status,
                "pending"
            );
        }
    }

    #[sqlx::test]
    async fn production_list_cost_scales_with_the_same_alias_count(pool: sqlx::PgPool) {
        let db = Arc::new(Db::for_testing(pool));
        db.run_migrations().await.unwrap();
        let schema = production_test_schema_with_db(db);
        for (field, selection) in [
            ("refUpdates", "repo"),
            ("tasks", "id"),
            ("reposPage", "nodes { name }"),
        ] {
            for limit in [1, 200] {
                let fields = (0..2)
                    .map(|n| format!("r{n}: {field}(limit: {limit}) {{ {selection} }}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let response = schema.execute(format!("{{ {fields} }}")).await;
                if limit == 200 {
                    assert_eq!(response.errors.len(), 1);
                    assert_eq!(response.errors[0].message, "Query is too complex.");
                    continue;
                }
                assert!(response.errors.is_empty(), "{field}: {:?}", response.errors);
                assert_eq!(
                    response
                        .data
                        .into_json()
                        .unwrap()
                        .as_object()
                        .unwrap()
                        .len(),
                    2
                );
            }
        }
    }

    #[tokio::test]
    async fn production_limits_reject_mutation_aliases_and_large_lists() {
        let schema = production_test_schema();
        for field in [
            "claimTask(id: \"missing\", assigneeDid: \"did:key:test\") { id }",
            "refUpdates(limit: 200) { repo }",
            "tasks(limit: 200) { id }",
            "reposPage(limit: 200) { nodes { name } }",
        ] {
            let count = if field.starts_with("claim") { 8 } else { 2 };
            let fields = (0..count)
                .map(|n| format!("r{n}: {field}"))
                .collect::<Vec<_>>()
                .join(" ");
            let prefix = if field.starts_with("claim") {
                "mutation"
            } else {
                "query"
            };
            let response = schema.execute(format!("{prefix} {{ {fields} }}")).await;
            assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
            assert_eq!(response.errors[0].message, "Query is too complex.");
        }
    }

    #[tokio::test]
    async fn seven_root_aliases_are_accepted() {
        struct Root(Arc<AtomicUsize>);
        #[Object]
        impl Root {
            #[graphql(complexity = "50 + child_complexity")]
            async fn repos(&self) -> Vec<Nested> {
                self.0.fetch_add(1, Ordering::Relaxed);
                vec![Nested]
            }
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let schema = apply_query_limits(Schema::build(
            Root(calls.clone()),
            EmptyMutation,
            EmptySubscription,
        ))
        .finish();
        let fields = (0..7)
            .map(|n| format!("r{n}: repos {{ value }}"))
            .collect::<Vec<_>>()
            .join(" ");
        let response = schema.execute(format!("{{ {fields} }}")).await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(calls.load(Ordering::Relaxed), 7);
    }

    #[tokio::test]
    async fn expensive_root_aliases_are_rejected_before_database_access() {
        // Use the production builder with a lazy pool: rejection must precede DB access.
        let schema = production_test_schema();
        let fields = (0..8)
            .map(|n| format!("r{n}: repos {{ name }}"))
            .collect::<Vec<_>>()
            .join(" ");

        let response = schema.execute(format!("{{ {fields} }}")).await;

        assert_eq!(response.data, Value::Null);
        assert_eq!(response.errors.len(), 1);
        assert_eq!(response.errors[0].message, "Query is too complex.");
    }

    #[tokio::test]
    async fn ordinary_schema_introspection_remains_available() {
        let schema =
            apply_query_limits(Schema::build(QueryRoot, EmptyMutation, EmptySubscription)).finish();
        let response = schema
            .execute(
                r#"
                query IntrospectionQuery {
                    __schema {
                        queryType {
                            name
                            fields {
                                name
                                type {
                                    kind
                                    name
                                    ofType { kind name }
                                }
                            }
                        }
                    }
                }
                "#,
            )
            .await;

        assert!(
            response.errors.is_empty(),
            "graphql errors: {:?}",
            response.errors
        );
        assert_ne!(response.data, Value::Null);
    }

    #[derive(Clone, Copy)]
    struct Nested;

    #[Object]
    impl Nested {
        async fn child(&self) -> Nested {
            Nested
        }

        async fn value(&self) -> i32 {
            1
        }
    }

    struct CountingQuery(Arc<AtomicUsize>);

    #[Object]
    impl CountingQuery {
        async fn nested(&self) -> Nested {
            self.0.fetch_add(1, Ordering::Relaxed);
            Nested
        }
    }

    #[tokio::test]
    async fn query_depth_limit_accepts_twelve_and_rejects_thirteen() {
        let calls = Arc::new(AtomicUsize::new(0));
        let schema = apply_query_limits(Schema::build(
            CountingQuery(Arc::clone(&calls)),
            EmptyMutation,
            EmptySubscription,
        ))
        .finish();
        let query_at_depth = |depth: usize| {
            let selection = (2..depth).fold("value".to_string(), |selection, _| {
                format!("child {{ {selection} }}")
            });
            format!("{{ nested {{ {selection} }} }}")
        };

        let accepted = schema.execute(query_at_depth(GRAPHQL_MAX_DEPTH)).await;

        assert!(
            accepted.errors.is_empty(),
            "depth {GRAPHQL_MAX_DEPTH} should be accepted: {:?}",
            accepted.errors
        );
        assert_eq!(calls.swap(0, Ordering::Relaxed), 1);

        let rejected = schema.execute(query_at_depth(GRAPHQL_MAX_DEPTH + 1)).await;

        assert_eq!(rejected.data, Value::Null);
        assert_eq!(rejected.errors.len(), 1);
        assert_eq!(rejected.errors[0].message, "Query is nested too deep.");
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn production_schema_enforces_depth_limit() {
        let schema = production_test_schema();
        // Depth 12 is accepted through the production build_schema path.
        let of_types_12 = (0..7).fold("name".to_string(), |acc, _| format!("ofType {{ {acc} }}"));
        let query_12 =
            format!("{{ __schema {{ types {{ fields {{ type {{ {of_types_12} }} }} }} }} }}");
        let accepted = schema.execute(&query_12).await;
        assert!(accepted.errors.is_empty(), "{:?}", accepted.errors);

        // Construct an introspection query of depth 13 using __schema.
        // 1: __schema
        // 2: types
        // 3: fields
        // 4: type
        // 5..12: ofType (8 times)
        // 13: name
        // Total depth = 13 > GRAPHQL_MAX_DEPTH (12).
        let of_types = (0..8).fold("name".to_string(), |acc, _| format!("ofType {{ {acc} }}"));
        let query = format!("{{ __schema {{ types {{ fields {{ type {{ {of_types} }} }} }} }} }}");

        let rejected = schema.execute(&query).await;
        assert_eq!(rejected.data, async_graphql::Value::Null);
        assert_eq!(rejected.errors.len(), 1);
        assert_eq!(rejected.errors[0].message, "Query is nested too deep.");
    }

    /// Every `.map_err(` in the GraphQL query/mutation resolvers must route
    /// through the opaque helpers, or discard the error (`|_|`). Same source-
    /// scrape pattern as `api::authz_guard` (#255 review).
    #[test]
    fn every_graphql_map_err_uses_opaque_helpers() {
        for (file, src) in [
            ("query.rs", include_str!("query.rs")),
            ("mutation.rs", include_str!("mutation.rs")),
        ] {
            for (lineno, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or(line);
                let Some(idx) = code.find(".map_err(") else {
                    continue;
                };
                let after = code[idx + ".map_err(".len()..].trim_start();
                let ok = after.starts_with("crate::graphql::graphql_db_err")
                    || after.starts_with("crate::graphql::graphql_app_err")
                    || after.starts_with("|_|")
                    || after.starts_with("|_ ");
                assert!(
                    ok,
                    "{file}:{}: `.map_err(` must use graphql_db_err / graphql_app_err \
                     or discard (`|_|`): {line}",
                    lineno + 1
                );
            }
        }
    }
}
