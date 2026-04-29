use async_graphql::{Context, Object, Result};
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::{AgentTask, Db};
use crate::state::TaskEventBroadcast;

use super::types::{AgentTaskType, CreateTaskInput, FinishTaskInput};

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn create_task(
        &self,
        ctx: &Context<'_>,
        delegator_did: String,
        input: CreateTaskInput,
    ) -> Result<AgentTaskType> {
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
