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

/// Read-only projection of `AgentTask` for the `tasks`/`task` queries, as
/// opposed to `AgentTaskType`, which the task mutations (`createTask`,
/// `claimTask`, `completeTask`, `failTask` — all `require_signer`-gated)
/// return. Identical except for the missing `ucan_token` (#268): a read
/// surface never needs to echo it back, since the assignee already received it
/// at delegation/claim time via the mutation response.
#[derive(SimpleObject, Clone)]
pub struct AgentTaskReadType {
    pub id: String,
    pub repo_id: Option<String>,
    pub kind: String,
    pub status: String,
    pub delegator_did: String,
    pub assignee_did: Option<String>,
    pub capability: String,
    pub payload: Option<String>,
    pub result: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deadline: Option<String>,
}

/// Wraps a `tasks` page with the same completion signals the REST list route
/// exposes, so the two surfaces answer pagination identically.
///
/// `hasMore` and `incomplete` are separate because they are separate facts
/// (#327 review): `hasMore` says more candidates remain, `incomplete` says
/// this page is short *only* because the authorization scan hit its safety
/// wall. `nextCursor` is present exactly when `hasMore` is true and is an
/// opaque MAC'd token — it can name the last examined candidate, denied or
/// not, without disclosing it, which is what lets a caller page past a denied
/// window instead of stalling on it.
#[derive(SimpleObject, Clone)]
pub struct TaskPageType {
    pub items: Vec<AgentTaskReadType>,
    pub has_more: bool,
    pub incomplete: bool,
    pub next_cursor: Option<String>,
}

impl From<AgentTask> for AgentTaskReadType {
    fn from(t: AgentTask) -> Self {
        Self {
            id: t.id,
            repo_id: t.repo_id,
            kind: t.kind,
            status: t.status,
            delegator_did: t.delegator_did,
            assignee_did: t.assignee_did,
            capability: t.capability,
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
    pub owner_did: Option<String>,
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
