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
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
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
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
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
        let task = db
            .finish_task(&id, "completed", input.result.as_deref())
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
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
        let reason = input.reason.unwrap_or_default();
        let task = db
            .finish_task(&id, "failed", Some(&reason))
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?;
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

        // 3. Signed as the claimed assignee → passes the auth gate (any remaining
        //    error is the missing task, not an auth error).
        let resp = schema
            .execute(Request::new(&q).data(AuthenticatedDid(assignee.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            !errs.contains("authentication required") && !errs.contains("authenticated signer"),
            "matching signer must pass the auth gate: {errs}"
        );
    }
}
