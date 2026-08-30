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
        let task = db
            .claim_task(&id, &assignee_did)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        let _ = tx.send(TaskEventBroadcast {
            task_id: id,
            old_status: "pending".to_string(),
            new_status: "claimed".to_string(),
            by_did: assignee_did,
            at: Utc::now().to_rfc3339(),
        });
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
        // Authorize the actor: binding by_did to the signer is necessary but not
        // sufficient — only the task's assignee may finish it.
        let existing = db
            .get_task(&id)
            .await
            .map_err(crate::graphql::graphql_db_err)?
            .ok_or_else(|| async_graphql::Error::new("task not found"))?;
        if !crate::api::did_matches(caller, existing.assignee_did.as_deref().unwrap_or_default()) {
            return Err(async_graphql::Error::new(
                "only the task assignee can complete it",
            ));
        }
        let task = db
            .finish_task(&id, "completed", input.result.as_deref())
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        let _ = tx.send(TaskEventBroadcast {
            task_id: id,
            old_status: "claimed".to_string(),
            new_status: "completed".to_string(),
            by_did,
            at: Utc::now().to_rfc3339(),
        });
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
        // Authorize the actor: only the task's assignee may fail it.
        let existing = db
            .get_task(&id)
            .await
            .map_err(crate::graphql::graphql_db_err)?
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
            .map_err(crate::graphql::graphql_db_err)?;
        let _ = tx.send(TaskEventBroadcast {
            task_id: id,
            old_status: "claimed".to_string(),
            new_status: "failed".to_string(),
            by_did,
            at: Utc::now().to_rfc3339(),
        });
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

    /// N2: every GraphQL mutation requires a verified signer and binds the acting
    /// DID to it. Unsigned is rejected; a signer other than the claimed actor is
    /// rejected; the matching signer passes the auth gate.
    #[sqlx::test]
    async fn each_mutation_requires_and_binds_signer(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let schema = state.graphql_schema.as_ref();
        let actor = "did:key:zGQLACTORAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let other = "did:key:zGQLOTHERBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let cases: Vec<(&str, String)> = vec![
            (
                "createTask",
                format!(
                    r#"mutation {{ createTask(delegatorDid: "{actor}", input: {{ kind: "build", capability: "repo:write" }}) {{ id }} }}"#
                ),
            ),
            (
                "claimTask",
                format!(
                    r#"mutation {{ claimTask(id: "no-such-task", assigneeDid: "{actor}") {{ id }} }}"#
                ),
            ),
            (
                "completeTask",
                format!(
                    r#"mutation {{ completeTask(id: "no-such-task", byDid: "{actor}", input: {{}}) {{ id }} }}"#
                ),
            ),
            (
                "failTask",
                format!(
                    r#"mutation {{ failTask(id: "no-such-task", byDid: "{actor}", input: {{}}) {{ id }} }}"#
                ),
            ),
        ];

        for (name, q) in &cases {
            let resp = schema.execute(Request::new(q.as_str())).await;
            assert!(
                errors(&resp).contains("authentication required"),
                "{name}: unsigned mutation must be rejected: {}",
                errors(&resp)
            );

            let resp = schema
                .execute(Request::new(q.as_str()).data(AuthenticatedDid(other.into())))
                .await;
            assert!(
                errors(&resp).contains("authenticated signer"),
                "{name}: DID mismatch must be rejected: {}",
                errors(&resp)
            );

            let resp = schema
                .execute(Request::new(q.as_str()).data(AuthenticatedDid(actor.into())))
                .await;
            let errs = errors(&resp);
            assert!(
                !errs.contains("authentication required") && !errs.contains("authenticated signer"),
                "{name}: matching signer must pass the auth gate: {errs}"
            );
            if *name == "claimTask" {
                assert!(
                    errs.contains("task not claimable"),
                    "claim race / missing task must keep its business message: {errs}"
                );
                assert!(
                    !errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
                    "business error must not be rewritten as opaque DB error: {errs}"
                );
            }
        }
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
            updated_at: now,
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

        // Stranger signs as themselves and passes byDid=self (so the signer
        // binding passes), but is not the assignee → rejected by authorization.
        let resp = schema
            .execute(Request::new(q(stranger)).data(AuthenticatedDid(stranger.into())))
            .await;
        assert!(
            errors(&resp).contains("assignee"),
            "a non-assignee signer must be rejected: {}",
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
