use async_graphql::{InputObject, SimpleObject};

use crate::db::AgentTask;

#[derive(SimpleObject, Clone)]
pub struct RepoType {
    pub name: String,
    pub owner_did: String,
    pub description: Option<String>,
    pub default_branch: String,
    pub created_at: String,
}

#[derive(SimpleObject, Clone)]
pub struct AgentTaskType {
    pub id: String,
    pub repo_id: Option<String>,
    pub kind: String,
    pub status: String,
    pub delegator_did: String,
    pub assignee_did: Option<String>,
    pub capability: String,
    pub ucan_token: Option<String>,
    pub payload: Option<String>,
    pub result: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deadline: Option<String>,
}

impl From<AgentTask> for AgentTaskType {
    fn from(t: AgentTask) -> Self {
        Self {
            id: t.id,
            repo_id: t.repo_id,
            kind: t.kind,
            status: t.status,
            delegator_did: t.delegator_did,
            assignee_did: t.assignee_did,
            capability: t.capability,
            ucan_token: t.ucan_token,
            payload: t.payload,
            result: t.result,
            created_at: t.created_at,
            updated_at: t.updated_at,
            deadline: t.deadline,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct RefUpdateType {
    pub repo: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub pusher_did: String,
    pub node_did: String,
    pub timestamp: String,
}

#[derive(SimpleObject, Clone)]
pub struct TaskEventType {
    pub task_id: String,
    pub old_status: String,
    pub new_status: String,
    pub by_did: String,
    pub at: String,
}

#[derive(InputObject)]
pub struct CreateTaskInput {
    pub repo_id: Option<String>,
    pub kind: String,
    pub capability: String,
    pub ucan_token: Option<String>,
    pub payload: Option<String>,
    pub assignee_did: Option<String>,
    pub deadline: Option<String>,
}

#[derive(InputObject)]
pub struct FinishTaskInput {
    pub result: Option<String>,
    pub reason: Option<String>,
}
