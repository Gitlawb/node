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
// clients and the canonical getIntrospectionQuery without allowing
// recursively nested documents to grow unchecked.
const GRAPHQL_MAX_DEPTH: usize = 14;

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
    use crate::api::events::MAX_VISIBLE_REF_UPDATES;
    use crate::db::{MAX_VISIBLE_REPO_PAGE_SIZE, MAX_VISIBLE_TASK_PAGE_SIZE};
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
        // Bounds are per-root named constants so the cases move with the
        // documented maximums instead of going stale as literals.
        for (field, selection, max) in [
            ("refUpdates", "repo", MAX_VISIBLE_REF_UPDATES),
            ("tasks", "id", MAX_VISIBLE_TASK_PAGE_SIZE),
            (
                "reposPage",
                "nodes { name }",
                MAX_VISIBLE_REPO_PAGE_SIZE as i64,
            ),
        ] {
            // Two aliases at the maximum always exceed the budget.
            let fields = (0..2)
                .map(|n| format!("r{n}: {field}(limit: {max}) {{ {selection} }}"))
                .collect::<Vec<_>>()
                .join(" ");
            let response = schema.execute(format!("{{ {fields} }}")).await;
            assert_eq!(response.errors.len(), 1);
            assert_eq!(response.errors[0].message, "Query is too complex.");

            // At limit 1 two aliases fit for the row-priced roots; reposPage
            // prices the full corpus scan, so a single alias is the most that
            // fits under the budget.
            let aliases = if field == "reposPage" { 1 } else { 2 };
            let fields = (0..aliases)
                .map(|n| format!("r{n}: {field}(limit: 1) {{ {selection} }}"))
                .collect::<Vec<_>>()
                .join(" ");
            let response = schema.execute(format!("{{ {fields} }}")).await;
            assert!(response.errors.is_empty(), "{field}: {:?}", response.errors);
            assert_eq!(
                response
                    .data
                    .into_json()
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .len(),
                aliases
            );
        }
    }

    #[tokio::test]
    async fn production_limits_reject_mutation_aliases_and_large_lists() {
        let schema = production_test_schema();
        // Limits are derived from the MAX_* constants so the boundaries move
        // with the documented maximums instead of going stale as literals.
        for (prefix, count, field) in [
            ("mutation", 8, "claimTask(id: \"missing\", assigneeDid: \"did:key:test\") { id }".to_owned()),
            ("mutation", 8, "createTask(delegatorDid: \"did:key:test\", input: { kind: \"test\", capability: \"test\" }) { id }".to_owned()),
            ("mutation", 8, "completeTask(id: \"missing\", byDid: \"did:key:test\", input: {}) { id }".to_owned()),
            ("mutation", 8, "failTask(id: \"missing\", byDid: \"did:key:test\", input: {}) { id }".to_owned()),
            ("query", 8, "task(id: \"missing\") { id }".to_owned()),
            ("query", 2, format!("refUpdates(limit: {MAX_VISIBLE_REF_UPDATES}) {{ repo }}")),
            ("query", 2, format!("tasks(limit: {MAX_VISIBLE_TASK_PAGE_SIZE}) {{ id }}")),
            ("query", 2, format!("reposPage(limit: {MAX_VISIBLE_REPO_PAGE_SIZE}) {{ nodes {{ name }} }}")),
            ("query", 8, "reposPage(limit: 1) { nodes { name } }".to_owned()),
        ] {
            let fields = (0..count)
                .map(|n| format!("r{n}: {field}"))
                .collect::<Vec<_>>()
                .join(" ");
            let response = schema.execute(format!("{prefix} {{ {fields} }}")).await;
            assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
            assert_eq!(response.errors[0].message, "Query is too complex.");
        }
    }

    #[sqlx::test]
    async fn production_repos_page_serves_the_documented_maximum(pool: sqlx::PgPool) {
        let db = Arc::new(Db::for_testing(pool));
        db.run_migrations().await.unwrap();
        let schema = production_test_schema_with_db(db);
        for selection in [
            "nodes { name }",
            "nodes { name ownerDid } hasNextPage endCursor",
        ] {
            let response = schema
                .execute(format!(
                    "{{ reposPage(limit: {MAX_VISIBLE_REPO_PAGE_SIZE}) {{ {selection} }} }}"
                ))
                .await;
            assert!(response.errors.is_empty(), "{:?}", response.errors);
            assert_eq!(
                response.data.into_json().unwrap()["reposPage"]["nodes"],
                serde_json::json!([])
            );
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
        let schema = production_test_schema();
        let canonical_introspection = r#"
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  ...FullType
                }
                directives {
                  name
                  description
                  locations
                  args {
                    ...InputValue
                  }
                }
              }
            }

            fragment FullType on __Type {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  ...InputValue
                }
                type {
                  ...TypeRef
                }
                isDeprecated
                deprecationReason
              }
              inputFields {
                ...InputValue
              }
              interfaces {
                ...TypeRef
              }
              enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
              }
              possibleTypes {
                ...TypeRef
              }
            }

            fragment InputValue on __InputValue {
              name
              description
              type { ...TypeRef }
              defaultValue
            }

            fragment TypeRef on __Type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                          ofType {
                            kind
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
        "#;
        let response = schema.execute(canonical_introspection).await;
        assert!(
            response.errors.is_empty(),
            "canonical introspection query failed against production schema: {:?}",
            response.errors
        );
        assert_ne!(response.data, Value::Null);
    }

    #[tokio::test]
    async fn ref_updates_and_tasks_single_alias_max_limit_complexity_contract() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        pool.close().await;
        let (ref_tx, _) = tokio::sync::broadcast::channel(16);
        let (task_tx, _) = tokio::sync::broadcast::channel(16);
        let schema = build_schema(Arc::new(Db::for_testing(pool)), ref_tx, task_tx);

        // refUpdates(limit: MAX_VISIBLE_REF_UPDATES):
        // Single-field selection has child_complexity 1 -> cost 100 + 200 + 1 = 301 <= 400.
        // It passes validation and reaches the resolver (which yields db error on lazy pool).
        let single_ref = schema
            .execute(format!(
                "{{ refUpdates(limit: {MAX_VISIBLE_REF_UPDATES}) {{ repo }} }}"
            ))
            .await;
        assert!(
            !single_ref
                .errors
                .iter()
                .any(|e| e.message == "Query is too complex."),
            "single-field refUpdates at max limit must pass complexity validation: {:?}",
            single_ref.errors
        );
        assert!(
            single_ref
                .errors
                .iter()
                .any(|e| e.message == GRAPHQL_DB_ERROR_MESSAGE),
            "single-field refUpdates at max limit must reach the resolver: {:?}",
            single_ref.errors
        );

        // Two-field selection has child_complexity 2 -> cost 100 + 200 + 2 = 302 <= 400.
        // The documented max-200 request stays reachable with multiple fields
        // (the old multiplicative price rejected it at 450); it passes
        // validation and reaches the resolver like the single-field case.
        let multi_ref = schema
            .execute(format!(
                "{{ refUpdates(limit: {MAX_VISIBLE_REF_UPDATES}) {{ repo refName }} }}"
            ))
            .await;
        assert!(
            !multi_ref
                .errors
                .iter()
                .any(|e| e.message == "Query is too complex."),
            "two-field refUpdates at max limit must pass complexity validation: {:?}",
            multi_ref.errors
        );
        assert!(
            multi_ref
                .errors
                .iter()
                .any(|e| e.message == GRAPHQL_DB_ERROR_MESSAGE),
            "two-field refUpdates at max limit must reach the resolver: {:?}",
            multi_ref.errors
        );

        // tasks(limit: MAX_VISIBLE_TASK_PAGE_SIZE):
        // Single-field selection has child_complexity 1, so the cost is
        // 50 + MAX_VISIBLE_TASK_PAGE_SIZE + 1 <= 400.
        // It passes validation and reaches the resolver.
        let single_task = schema
            .execute(format!(
                "{{ tasks(limit: {MAX_VISIBLE_TASK_PAGE_SIZE}) {{ id }} }}"
            ))
            .await;
        assert!(
            !single_task
                .errors
                .iter()
                .any(|e| e.message == "Query is too complex."),
            "single-field tasks at the maximum page size must pass complexity validation: {:?}",
            single_task.errors
        );
        assert!(
            single_task
                .errors
                .iter()
                .any(|e| e.message == GRAPHQL_DB_ERROR_MESSAGE),
            "single-field tasks at the maximum page size must reach the resolver: {:?}",
            single_task.errors
        );

        // Two-field selection has child_complexity 2, so the cost is
        // 50 + MAX_VISIBLE_TASK_PAGE_SIZE + 2 <= 400.
        // A request at the documented maximum stays reachable with multiple
        // fields (the old multiplicative price rejected it at 450); it passes
        // validation and reaches the resolver like the single-field case.
        let multi_task = schema
            .execute(format!(
                "{{ tasks(limit: {MAX_VISIBLE_TASK_PAGE_SIZE}) {{ id status }} }}"
            ))
            .await;
        assert!(
            !multi_task
                .errors
                .iter()
                .any(|e| e.message == "Query is too complex."),
            "two-field tasks at the maximum page size must pass complexity validation: {:?}",
            multi_task.errors
        );
        assert!(
            multi_task
                .errors
                .iter()
                .any(|e| e.message == GRAPHQL_DB_ERROR_MESSAGE),
            "two-field tasks at the maximum page size must reach the resolver: {:?}",
            multi_task.errors
        );
    }

    #[tokio::test]
    async fn two_repos_aliases_exceed_the_budget() {
        // `repos` is priced as the full page it scans
        // (50 + MAX_VISIBLE_REPO_PAGE_SIZE + child), so two `repos { name }`
        // aliases cost 2 * 251 = 502 > 400 and the document is rejected before
        // any resolver runs. If the price reverts to `50 + child_complexity`
        // the aliases cost 2 * 51 = 102, validation passes, and the failure
        // mode changes (resolver DB errors on the lazy pool): this test goes
        // red on revert.
        let schema = production_test_schema();
        let response = schema
            .execute("{ r0: repos { name } r1: repos { name } }")
            .await;
        assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
        assert_eq!(response.errors[0].message, "Query is too complex.");
    }

    #[tokio::test]
    async fn seven_repos_page_aliases_exceed_the_budget() {
        // `reposPage` is priced as the full corpus scan
        // (50 + MAX_VISIBLE_REPO_PAGE_SIZE + child_complexity), so seven
        // `reposPage(limit: 1) { nodes { name } }` aliases cost
        // 7 * (50 + 200 + 2) = 1764 > 400 and the document is rejected
        // before any resolver runs. Under the previous row-priced formula
        // the same aliases cost 7 * (50 + 1 + 2) = 371, validation passes,
        // and the failure mode changes (resolver DB errors on the lazy
        // pool): this test goes red on revert. Eight aliases are rejected
        // under both formulas, so seven is the load-bearing boundary.
        let schema = production_test_schema();
        let fields = (0..7)
            .map(|n| format!("r{n}: reposPage(limit: 1) {{ nodes {{ name }} }}"))
            .collect::<Vec<_>>()
            .join(" ");
        let response = schema.execute(format!("{{ {fields} }}")).await;
        assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
        assert_eq!(response.errors[0].message, "Query is too complex.");
    }

    #[tokio::test]
    async fn ref_updates_fixed_base_is_charged() {
        // The 100 base in the refUpdates complexity formula charges for the
        // collector's fixed work (loading the deduped repo set, the
        // quarantined set, and the visibility rules, then walking up to 16
        // keyset pages) even at limit: 1. Four aliases at limit: 1 cost
        // 4 * (100 + 1 + 1) = 408 > 400 and must be rejected. If the base
        // disappears, the cost drops to 4 * (1 + 1) = 8 and this test fails.
        let schema = production_test_schema();
        let fields = (0..4)
            .map(|n| format!("r{n}: refUpdates(limit: 1) {{ repo }}"))
            .collect::<Vec<_>>()
            .join(" ");
        let response = schema.execute(format!("{{ {fields} }}")).await;
        assert_eq!(response.errors.len(), 1, "{:?}", response.errors);
        assert_eq!(response.errors[0].message, "Query is too complex.");
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
    async fn query_depth_limit_accepts_fourteen_and_rejects_fifteen() {
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
        // Depth 14 is accepted through the production build_schema path.
        let of_types_14 = (0..9).fold("name".to_string(), |acc, _| format!("ofType {{ {acc} }}"));
        let query_14 =
            format!("{{ __schema {{ types {{ fields {{ type {{ {of_types_14} }} }} }} }} }}");
        let accepted = schema.execute(&query_14).await;
        assert!(accepted.errors.is_empty(), "{:?}", accepted.errors);

        // Construct an introspection query of depth 15 using __schema.
        // 1: __schema
        // 2: types
        // 3: fields
        // 4: type
        // 5..14: ofType (10 times)
        // 15: name
        // Total depth = 15 > GRAPHQL_MAX_DEPTH (14).
        let of_types = (0..10).fold("name".to_string(), |acc, _| format!("ofType {{ {acc} }}"));
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
