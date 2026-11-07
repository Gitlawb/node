//! REST handlers for agent task delegation API.
//!
//! Routes (all under /api/v1/tasks):
//!   POST   /api/v1/tasks                    — create task
//!   GET    /api/v1/tasks                    — list tasks
//!   GET    /api/v1/tasks/{id}               — get task
//!   POST   /api/v1/tasks/{id}/claim         — claim task
//!   POST   /api/v1/tasks/{id}/complete      — complete task
//!   POST   /api/v1/tasks/{id}/fail          — fail task

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::AuthenticatedDid;
use crate::db::AgentTask;
use crate::state::{AppState, TaskEventBroadcast};

/// 403 in this module's error shape (`(StatusCode, Json<Value>)`, not `AppError`).
fn forbidden(msg: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "forbidden", "message": msg })),
    )
}

/// This module's error shape with an opaque body: the real error is logged
/// server-side and never serialized (#250), matching the envelope
/// `AppError::Db` renders. Also mirrors its status split: pool-class failures
/// are a retryable 503 `db_unavailable`, everything else the opaque 500
/// `db_error`, so a transient outage is not reported as permanent.
fn db_error(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    tracing::error!(error = %format!("{e:#}"), "task database error");
    if let Some(sql) = e.chain().find_map(|c| c.downcast_ref::<sqlx::Error>()) {
        if crate::error::db_unavailable(sql) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": crate::error::DB_UNAVAILABLE_CODE,
                    "message": crate::error::DB_UNAVAILABLE_MESSAGE,
                })),
            );
        }
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "error": "db_error",
            "message": crate::error::DB_ERROR_MESSAGE,
        })),
    )
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTaskBody {
    pub repo_id: Option<String>,
    pub kind: String,
    pub capability: String,
    pub ucan_token: Option<String>,
    pub payload: Option<String>,
    pub assignee_did: Option<String>,
    pub delegator_did: String,
    pub deadline: Option<String>,
}

#[derive(Deserialize)]
pub struct ListTasksQuery {
    pub status: Option<String>,
    pub assignee_did: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Deserialize)]
pub struct ClaimTaskBody {
    pub assignee_did: String,
}

#[derive(Deserialize)]
pub struct CompleteTaskBody {
    pub result: Option<String>,
}

#[derive(Deserialize)]
pub struct FailTaskBody {
    pub reason: Option<String>,
}

fn task_to_json(t: &AgentTask) -> Value {
    json!({
        "id": t.id,
        "repo_id": t.repo_id,
        "kind": t.kind,
        "status": t.status,
        "delegator_did": t.delegator_did,
        "assignee_did": t.assignee_did,
        "capability": t.capability,
        "ucan_token": t.ucan_token,
        "payload": t.payload,
        "result": t.result,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
        "deadline": t.deadline,
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/tasks
pub async fn create_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Json(body): Json<CreateTaskBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // Bind the delegator to the authenticated signer (N13).
    if !crate::api::did_matches(&auth.0, &body.delegator_did) {
        return Err(forbidden("delegator_did must be the authenticated signer"));
    }
    // #496: a caller-supplied repo_id must name a repo the caller owns. Without
    // this, any signed caller can plant a task — payload and UCAN included —
    // under a foreign repo id, where the named assignee can claim it. Resolve
    // the id against hosted repos: a hosted, non-quarantined repo admits tasks
    // only from its owner (403 otherwise). An id naming no hosted repo
    // (unknown, or quarantined — which is hidden as if it did not exist, so
    // 403ing it would confirm a real id) is stored verbatim as an opaque
    // label: this is a write gate and does not bind an unresolved id to a
    // repo. Task reads are caller-independent on this base (the list endpoints
    // are not repo-scoped), before and after this change. The 403-vs-201 split
    // between a hosted repo id and an unknown one is itself a one-bit oracle —
    // a stranger holding a private repo's id learns it is hosted here — but
    // denying foreign repos requires drawing exactly that line, and repo ids
    // already surface via the task list on this base. Repo-less tasks are
    // unaffected.
    if let Some(repo_id) = body.repo_id.as_deref() {
        let record = state.db.get_repo_by_id(repo_id).await.map_err(db_error)?;
        if let Some(record) = record {
            let quarantined = state
                .db
                .is_repo_quarantined(&record.id)
                .await
                .map_err(db_error)?;
            if !quarantined && crate::api::require_repo_owner(&record, &auth.0).is_err() {
                // Same denial text the GraphQL copy relays from
                // `require_repo_owner`, so the two copies of this gate do not
                // disagree in observable output.
                return Err(forbidden(crate::api::REPO_OWNER_ONLY_MESSAGE));
            }
        }
    }
    let now = Utc::now().to_rfc3339();
    let task = AgentTask {
        id: Uuid::new_v4().to_string(),
        repo_id: body.repo_id,
        kind: body.kind,
        status: "pending".to_string(),
        delegator_did: auth.0,
        assignee_did: body.assignee_did,
        capability: body.capability,
        ucan_token: body.ucan_token,
        payload: body.payload,
        result: None,
        created_at: now.clone(),
        updated_at: now,
        deadline: body.deadline,
    };
    state.db.create_task(&task).await.map_err(db_error)?;
    Ok((StatusCode::CREATED, Json(task_to_json(&task))))
}

/// GET /api/v1/tasks
pub async fn list_tasks(
    State(state): State<AppState>,
    Query(q): Query<ListTasksQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let tasks = state
        .db
        .list_tasks(q.status.as_deref(), q.assignee_did.as_deref(), q.limit)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;
    let items: Vec<Value> = tasks.iter().map(task_to_json).collect();
    Ok(Json(json!({ "tasks": items, "count": items.len() })))
}

/// GET /api/v1/tasks/{id}
pub async fn get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match state.db.get_task(&id).await {
        Ok(Some(t)) => Ok(Json(task_to_json(&t))),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "task not found" })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )),
    }
}

/// POST /api/v1/tasks/{id}/claim
pub async fn claim_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(body): Json<ClaimTaskBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Bind the assignee to the authenticated signer (N13).
    if !crate::api::did_matches(&auth.0, &body.assignee_did) {
        return Err(forbidden("assignee_did must be the authenticated signer"));
    }
    let task = state.db.claim_task(&id, &auth.0).await.map_err(|e| {
        (
            StatusCode::CONFLICT,
            Json(json!({ "error": e.to_string() })),
        )
    })?;
    let _ = state.task_event_tx.send(TaskEventBroadcast {
        task_id: id,
        old_status: "pending".to_string(),
        new_status: "claimed".to_string(),
        by_did: auth.0,
        at: Utc::now().to_rfc3339(),
    });
    Ok(Json(task_to_json(&task)))
}

/// POST /api/v1/tasks/{id}/complete
pub async fn complete_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(body): Json<CompleteTaskBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Authorize the actor, not just bind their identity: the N13 signer-binding
    // proved the caller was whoever they claimed, but never that they were the
    // task's assignee. Load the task and require the caller to be its assignee;
    // finish_task then transitions only a claimed task.
    let existing = state
        .db
        .get_task(&id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "task not found" })),
            )
        })?;
    if !crate::api::did_matches(
        &auth.0,
        existing.assignee_did.as_deref().unwrap_or_default(),
    ) {
        return Err(forbidden("only the task assignee can complete it"));
    }
    let by_did = auth.0;
    let task = state
        .db
        .finish_task(&id, "completed", body.result.as_deref())
        .await
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                Json(json!({ "error": e.to_string() })),
            )
        })?;
    let _ = state.task_event_tx.send(TaskEventBroadcast {
        task_id: id,
        old_status: "claimed".to_string(),
        new_status: "completed".to_string(),
        by_did,
        at: Utc::now().to_rfc3339(),
    });
    Ok(Json(task_to_json(&task)))
}

/// POST /api/v1/tasks/{id}/fail
pub async fn fail_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(body): Json<FailTaskBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Authorize the actor, not just bind their identity (see complete_task): only
    // the task's assignee may fail it, and finish_task transitions only a claimed
    // task.
    let existing = state
        .db
        .get_task(&id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "task not found" })),
            )
        })?;
    if !crate::api::did_matches(
        &auth.0,
        existing.assignee_did.as_deref().unwrap_or_default(),
    ) {
        return Err(forbidden("only the task assignee can fail it"));
    }
    let by_did = auth.0;
    let reason = body.reason.unwrap_or_default();
    let task = state
        .db
        .finish_task(&id, "failed", Some(&reason))
        .await
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                Json(json!({ "error": e.to_string() })),
            )
        })?;
    let _ = state.task_event_tx.send(TaskEventBroadcast {
        task_id: id,
        old_status: "claimed".to_string(),
        new_status: "failed".to_string(),
        by_did,
        at: Utc::now().to_rfc3339(),
    });
    Ok(Json(task_to_json(&task)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate's DB helper must mirror `AppError::Db`: a pool-level failure is
    /// the retryable 503 `db_unavailable`, a query fault the opaque 500.
    #[test]
    fn db_error_matches_app_error_status_split() {
        let unavailable = db_error(anyhow::Error::from(sqlx::Error::PoolTimedOut));
        assert_eq!(unavailable.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(unavailable.1 .0["error"], crate::error::DB_UNAVAILABLE_CODE);
        assert_eq!(
            unavailable.1 .0["message"],
            crate::error::DB_UNAVAILABLE_MESSAGE
        );

        let query = db_error(anyhow::Error::from(sqlx::Error::Protocol(
            "column \"machine_id\" does not exist".into(),
        )));
        assert_eq!(query.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(query.1 .0["error"], "db_error");
        assert_eq!(query.1 .0["message"], crate::error::DB_ERROR_MESSAGE);
        assert!(!query.1 .0.to_string().contains("machine_id"));
    }

    /// `.context()` layers must not hide the sqlx error from the status split.
    #[test]
    fn db_error_sees_sqlx_through_context() {
        let wrapped = anyhow::Error::from(sqlx::Error::PoolClosed).context("repo lookup failed");
        assert_eq!(db_error(wrapped).0, StatusCode::SERVICE_UNAVAILABLE);
    }
}
