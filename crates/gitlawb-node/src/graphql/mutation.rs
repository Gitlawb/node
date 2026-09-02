use async_graphql::{Context, Object, Result};
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::{AgentTask, Db};
use crate::state::TaskEventBroadcast;

use super::types::{AgentTaskType, CreateTaskInput, FinishTaskInput};

/// The verified signer DID for this request, or an auth error (N2). The DID is
/// attached request-scoped by the `/graphql` `optional_signature` layer; its
/// absence means the request was unsigned, so every mutation rejects.
fn require_signer<'a>(ctx: &'a Context<'_>) -> Result<&'a str> {
    ctx.data::<AuthenticatedDid>()
        .map(|d| d.0.as_str())
        .map_err(|_| async_graphql::Error::new("authentication required"))
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn create_task(
        &self,
        ctx: &Context<'_>,
        delegator_did: String,
        input: CreateTaskInput,
    ) -> Result<AgentTaskType> {
        let caller = require_signer(ctx)?;
        if !crate::api::did_matches(caller, &delegator_did) {
            return Err(async_graphql::Error::new(
                "delegator_did must be the authenticated signer",
            ));
        }
        let delegator_did = caller.to_string();
        let db = ctx.data_unchecked::<Arc<Db>>();
        let now = Utc::now().to_rfc3339();
        let task = AgentTask {
            id: Uuid::new_v4().to_string(),
            repo_id: input.repo_id,
            kind: input.kind,
            status: "pending".to_string(),
            delegator_did,
            assignee_did: input.assignee_did,
            capability: input.capability,
            ucan_token: input.ucan_token,
            payload: input.payload,
            result: None,
            created_at: now.clone(),
            updated_at: now,
            deadline: input.deadline,
        };
        db.create_task(&task)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        Ok(AgentTaskType::from(task))
    }

    async fn claim_task(
        &self,
        ctx: &Context<'_>,
        id: String,
        assignee_did: String,
    ) -> Result<AgentTaskType> {
        let caller = require_signer(ctx)?;
        if !crate::api::did_matches(caller, &assignee_did) {
            return Err(async_graphql::Error::new(
                "assignee_did must be the authenticated signer",
            ));
        }
        let assignee_did = caller.to_string();
        let db = ctx.data_unchecked::<Arc<Db>>();
        let tx = ctx.data_unchecked::<tokio::sync::broadcast::Sender<TaskEventBroadcast>>();
        crate::api::tasks::get_claimable_task(db, &id, caller)
            .await
            .map_err(crate::graphql::graphql_app_err)?
            .ok_or_else(|| async_graphql::Error::new("task not found"))?;
        // Same classification REST's claim handler applies: a claim race is a
        // client-safe conflict, a genuine sqlx failure stays opaque. Routing
        // both transports through `task_write_conflict` is what stops a normal
        // race from reaching a GraphQL caller as a generic database error
        // (#327 review).
        let task = db
            .claim_task(&id, &assignee_did)
            .await
            .map_err(crate::graphql::graphql_claim_conflict)?;
        crate::api::tasks::announce_task_event(
            db,
            tx,
            TaskEventBroadcast {
                task_id: id,
                old_status: "pending".to_string(),
                new_status: "claimed".to_string(),
                by_did: assignee_did,
                at: Utc::now().to_rfc3339(),
            },
        )
        .await;
        Ok(AgentTaskType::from(task))
    }

    async fn complete_task(
        &self,
        ctx: &Context<'_>,
        id: String,
        by_did: String,
        input: FinishTaskInput,
    ) -> Result<AgentTaskType> {
        let caller = require_signer(ctx)?;
        if !crate::api::did_matches(caller, &by_did) {
            return Err(async_graphql::Error::new(
                "by_did must be the authenticated signer",
            ));
        }
        let by_did = caller.to_string();
        let db = ctx.data_unchecked::<Arc<Db>>();
        let tx = ctx.data_unchecked::<tokio::sync::broadcast::Sender<TaskEventBroadcast>>();
        // Authorize the actor: the task must be visible to the caller (returning
        // not found for invisible tasks so existence is not leaked), and only
        // the task's assignee may finish it.
        let existing = crate::api::tasks::get_visible_task(db, &id, Some(caller))
            .await
            .map_err(crate::graphql::graphql_app_err)?
            .ok_or_else(|| async_graphql::Error::new("task not found"))?;
        if !crate::api::did_matches(caller, existing.assignee_did.as_deref().unwrap_or_default()) {
            return Err(async_graphql::Error::new(
                "only the task assignee can complete it",
            ));
        }
        let task = db
            .finish_task(&id, "completed", input.result.as_deref())
            .await
            .map_err(crate::graphql::graphql_finish_conflict)?;
        crate::api::tasks::announce_task_event(
            db,
            tx,
            TaskEventBroadcast {
                task_id: id,
                old_status: "claimed".to_string(),
                new_status: "completed".to_string(),
                by_did,
                at: Utc::now().to_rfc3339(),
            },
        )
        .await;
        Ok(AgentTaskType::from(task))
    }

    async fn fail_task(
        &self,
        ctx: &Context<'_>,
        id: String,
        by_did: String,
        input: FinishTaskInput,
    ) -> Result<AgentTaskType> {
        let caller = require_signer(ctx)?;
        if !crate::api::did_matches(caller, &by_did) {
            return Err(async_graphql::Error::new(
                "by_did must be the authenticated signer",
            ));
        }
        let by_did = caller.to_string();
        let db = ctx.data_unchecked::<Arc<Db>>();
        let tx = ctx.data_unchecked::<tokio::sync::broadcast::Sender<TaskEventBroadcast>>();
        // Authorize the actor: the task must be visible to the caller (returning
        // not found for invisible tasks so existence is not leaked), and only
        // the task's assignee may fail it.
        let existing = crate::api::tasks::get_visible_task(db, &id, Some(caller))
            .await
            .map_err(crate::graphql::graphql_app_err)?
            .ok_or_else(|| async_graphql::Error::new("task not found"))?;
        if !crate::api::did_matches(caller, existing.assignee_did.as_deref().unwrap_or_default()) {
            return Err(async_graphql::Error::new(
                "only the task assignee can fail it",
            ));
        }
        let reason = input.reason.unwrap_or_default();
        let task = db
            .finish_task(&id, "failed", Some(&reason))
            .await
            .map_err(crate::graphql::graphql_finish_conflict)?;
        crate::api::tasks::announce_task_event(
            db,
            tx,
            TaskEventBroadcast {
                task_id: id,
                old_status: "claimed".to_string(),
                new_status: "failed".to_string(),
                by_did,
                at: Utc::now().to_rfc3339(),
            },
        )
        .await;
        Ok(AgentTaskType::from(task))
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::AuthenticatedDid;
    use async_graphql::{Request, Response};
    use sqlx::PgPool;

    fn errors(resp: &Response) -> String {
        resp.errors
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// N2: GraphQL mutations require a verified signer and bind the acting DID to
    /// it. Unsigned is rejected; a signer other than the claimed actor is
    /// rejected; the matching signer passes the auth gate.
    #[sqlx::test]
    async fn mutation_requires_and_binds_signer(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let schema = state.graphql_schema.as_ref();
        let assignee = "did:key:zASSIGNEEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let q = format!(
            r#"mutation {{ claimTask(id: "no-such-task", assigneeDid: "{assignee}") {{ id }} }}"#
        );

        // 1. Unsigned → rejected before any DB work.
        let resp = schema.execute(Request::new(&q)).await;
        assert!(
            errors(&resp).contains("authentication required"),
            "unsigned mutation must be rejected: {}",
            errors(&resp)
        );

        // 2. Signed as someone other than the claimed assignee → rejected.
        let resp = schema
            .execute(Request::new(&q).data(AuthenticatedDid(
                "did:key:zOTHERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
            )))
            .await;
        assert!(
            errors(&resp).contains("authenticated signer"),
            "DID mismatch must be rejected: {}",
            errors(&resp)
        );

        // 3. Signed as the claimed assignee → passes the auth gate. A missing
        //    task is gated by get_visible_task as "task not found" (same as a
        //    denied id) before claim_task runs, and must stay a business
        //    message rather than the opaque DB string (#250).
        let resp = schema
            .execute(Request::new(&q).data(AuthenticatedDid(assignee.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            !errs.contains("authentication required") && !errs.contains("authenticated signer"),
            "matching signer must pass the auth gate: {errs}"
        );
        assert!(
            errs.contains("task not found"),
            "missing task must keep its business message: {errs}"
        );
        assert!(
            !errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
            "business error must not be rewritten as opaque DB error: {errs}"
        );
    }

    /// #250: mutation DB faults must be opaque; create_task hits agent_tasks.
    #[sqlx::test]
    async fn create_task_db_error_message_is_opaque(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        sqlx::query("ALTER TABLE agent_tasks DROP COLUMN status")
            .execute(&pool)
            .await
            .unwrap();

        let delegator = "did:key:zGQLDELEGATORAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let q = format!(
            r#"mutation {{
                createTask(
                    delegatorDid: "{delegator}",
                    input: {{ kind: "build", capability: "repo:write" }}
                ) {{ id }}
            }}"#
        );
        let resp = state
            .graphql_schema
            .execute(Request::new(&q).data(AuthenticatedDid(delegator.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
            "sqlx fault must be opaque: {errs}"
        );
        assert!(
            !errs.contains("column") && !errs.contains("status"),
            "schema text leaked: {errs}"
        );
    }

    /// #327 review: `claimTask`/`completeTask`/`failTask` called
    /// `graphql_db_err` directly on db-layer business failures, so an ordinary
    /// claim race or stale finish reached GraphQL clients as a generic
    /// database error while REST clients got an actionable conflict. All three
    /// now route through the shared `task_write_conflict` classifier.
    ///
    /// Deleting either `map_err` from a mutation turns this red: the message
    /// becomes the raw anyhow text instead of the fixed conflict form.
    #[sqlx::test]
    async fn task_write_races_surface_as_conflicts_not_db_errors(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let schema = state.graphql_schema.as_ref();
        let assignee = "did:key:zGQLRACEASSIGNEEAAAAAAAAAAAAAAAAAAAAAAA";
        let rival = "did:key:zGQLRACERIVALBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let delegator = "did:key:zGQLRACEDELEGATORCCCCCCCCCCCCCCCCCCCCC";
        let now = chrono::Utc::now().to_rfc3339();

        state
            .db
            .create_repo(&crate::db::RepoRecord {
                id: "race-repo".into(),
                name: "race".into(),
                owner_did: delegator.into(),
                description: None,
                is_public: true,
                default_branch: "main".into(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                disk_path: "/tmp/race-repo".into(),
                forked_from: None,
                machine_id: None,
            })
            .await
            .unwrap();
        state
            .db
            .create_task(&crate::db::AgentTask {
                id: "race-task".into(),
                repo_id: Some("race-repo".into()),
                kind: "build".into(),
                status: "pending".into(),
                delegator_did: delegator.into(),
                assignee_did: None,
                capability: "repo:write".into(),
                ucan_token: None,
                payload: None,
                result: None,
                created_at: now.clone(),
                updated_at: now,
                deadline: None,
            })
            .await
            .unwrap();

        // The assignee wins the claim.
        let claim = |did: &str| {
            format!(r#"mutation {{ claimTask(id: "race-task", assigneeDid: "{did}") {{ id }} }}"#)
        };
        let resp = schema
            .execute(Request::new(claim(assignee)).data(AuthenticatedDid(assignee.into())))
            .await;
        assert!(resp.errors.is_empty(), "first claim: {}", errors(&resp));

        // The rival loses the race: an expected conflict, not an outage.
        let resp = schema
            .execute(Request::new(claim(rival)).data(AuthenticatedDid(rival.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains("task not claimable: not found or already claimed"),
            "a lost claim race must render the fixed conflict message: {errs}"
        );
        assert!(
            !errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
            "a claim race is not a database failure: {errs}"
        );

        // A stale finish on an already-completed task is the same class.
        let complete = format!(
            r#"mutation {{ completeTask(id: "race-task", byDid: "{assignee}", input: {{ result: "ok" }}) {{ id }} }}"#
        );
        let resp = schema
            .execute(Request::new(&complete).data(AuthenticatedDid(assignee.into())))
            .await;
        assert!(resp.errors.is_empty(), "first complete: {}", errors(&resp));

        let resp = schema
            .execute(Request::new(&complete).data(AuthenticatedDid(assignee.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains("task not found or not in claimed state"),
            "a stale complete must render the fixed conflict message: {errs}"
        );
        assert!(
            !errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
            "a stale complete is not a database failure: {errs}"
        );

        let fail = format!(
            r#"mutation {{ failTask(id: "race-task", byDid: "{assignee}", input: {{ reason: "nope" }}) {{ id }} }}"#
        );
        let resp = schema
            .execute(Request::new(&fail).data(AuthenticatedDid(assignee.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains("task not found or not in claimed state"),
            "a stale fail must render the fixed conflict message: {errs}"
        );
        assert!(
            !errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
            "a stale fail is not a database failure: {errs}"
        );
    }

    /// The other half of the same classification: a genuine SQL fault on the
    /// write itself must stay opaque. Without this, routing conflicts through
    /// `task_write_conflict` could be "fixed" by making every db failure a
    /// client-visible conflict message.
    #[sqlx::test]
    async fn task_write_sql_faults_stay_opaque(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let assignee = "did:key:zGQLOPAQUEASSIGNEEAAAAAAAAAAAAAAAAAAAAA";
        let delegator = "did:key:zGQLOPAQUEDELEGATORBBBBBBBBBBBBBBBBBBB";
        let now = chrono::Utc::now().to_rfc3339();
        state
            .db
            .create_task(&crate::db::AgentTask {
                id: "opaque-task".into(),
                repo_id: None,
                kind: "build".into(),
                status: "pending".into(),
                delegator_did: delegator.into(),
                assignee_did: Some(assignee.into()),
                capability: "repo:write".into(),
                ucan_token: None,
                payload: None,
                result: None,
                created_at: now.clone(),
                updated_at: now,
                deadline: None,
            })
            .await
            .unwrap();

        // Fault the write itself, not the schema. Dropping a column the
        // visibility pre-check also SELECTs would fail in `get_visible_task`
        // and never reach `graphql_claim_conflict`, so this test would pass
        // against a claim mapper that leaks (#327 review). A BEFORE UPDATE
        // trigger keeps every read valid and faults only inside
        // `Db::claim_task`.
        sqlx::raw_sql(
            "CREATE FUNCTION gl_test_fault_task_update() RETURNS trigger
             LANGUAGE plpgsql AS $fn$
             BEGIN RAISE EXCEPTION 'gl_test_forced_update_fault'; END;
             $fn$;
             CREATE TRIGGER gl_test_fault_task_update
             BEFORE UPDATE ON agent_tasks
             FOR EACH ROW EXECUTE FUNCTION gl_test_fault_task_update();",
        )
        .execute(&pool)
        .await
        .unwrap();

        let resp = state
            .graphql_schema
            .execute(
                Request::new(format!(
                    r#"mutation {{ claimTask(id: "opaque-task", assigneeDid: "{assignee}") {{ id }} }}"#
                ))
                .data(AuthenticatedDid(assignee.into())),
            )
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
            "a real sqlx fault on the write must stay opaque: {errs}"
        );
        assert!(
            !errs.contains("task not claimable"),
            "a write-time sqlx fault must not be reclassified as a claim race: {errs}"
        );
        assert!(
            !errs.contains("gl_test_forced_update_fault") && !errs.contains("trigger"),
            "database text leaked through the conflict mapper: {errs}"
        );
    }

    /// Adversarial-review GATE-1 (GraphQL): completing a task requires being its
    /// assignee, not merely signing as the by_did you pass. A signer who is not
    /// the assignee is rejected even though the by_did binding passes; the
    /// assignee completes.
    #[sqlx::test]
    async fn complete_task_requires_assignee(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let assignee = "did:key:zGQLASSIGNEEAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zGQLSTRANGERBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let now = chrono::Utc::now().to_rfc3339();
        let task = crate::db::AgentTask {
            id: "task-g".into(),
            repo_id: None,
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: "did:key:zGQLDELEGATORCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            assignee_did: None,
            capability: "repo:write".into(),
            ucan_token: None,
            payload: None,
            result: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            deadline: None,
        };
        state.db.create_task(&task).await.expect("seed task");
        state
            .db
            .claim_task("task-g", assignee)
            .await
            .expect("claim");
        let schema = state.graphql_schema.as_ref();

        let q = |actor: &str| {
            format!(
                r#"mutation {{ completeTask(id: "task-g", byDid: "{actor}", input: {{}}) {{ id status }} }}"#
            )
        };

        // Stranger signs as themselves on a repo-less task they cannot see:
        // invisible task returns "task not found" so existence is not leaked.
        let resp = schema
            .execute(Request::new(q(stranger)).data(AuthenticatedDid(stranger.into())))
            .await;
        assert!(
            errors(&resp).contains("task not found"),
            "an invisible task must return not found, got: {}",
            errors(&resp)
        );

        // Seed a task on a public repo that stranger CAN see, but is not assignee of:
        let pub_repo = crate::db::RepoRecord {
            id: "pub-r".into(),
            name: "pub-r".into(),
            owner_did: "did:key:zGQLDELEGATORCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            disk_path: "/tmp/pub-r".into(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&pub_repo).await.expect("create repo");
        let pub_task = crate::db::AgentTask {
            id: "task-pub".into(),
            repo_id: Some("pub-r".into()),
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: "did:key:zGQLDELEGATORCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            assignee_did: None,
            capability: "repo:write".into(),
            ucan_token: None,
            payload: None,
            result: None,
            created_at: now.clone(),
            updated_at: now,
            deadline: None,
        };
        state
            .db
            .create_task(&pub_task)
            .await
            .expect("seed pub task");
        state
            .db
            .claim_task("task-pub", assignee)
            .await
            .expect("claim pub task");

        let q_pub = |actor: &str| {
            format!(
                r#"mutation {{ completeTask(id: "task-pub", byDid: "{actor}", input: {{}}) {{ id status }} }}"#
            )
        };
        let resp = schema
            .execute(Request::new(q_pub(stranger)).data(AuthenticatedDid(stranger.into())))
            .await;
        assert!(
            errors(&resp).contains("assignee"),
            "a non-assignee signer on a visible task must be rejected: {}",
            errors(&resp)
        );

        // The assignee completes with no error.
        let resp = schema
            .execute(Request::new(q(assignee)).data(AuthenticatedDid(assignee.into())))
            .await;
        assert!(
            errors(&resp).is_empty(),
            "the assignee should complete the task: {}",
            errors(&resp)
        );
    }
}
