```rust
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
use crate::error::AppError;
use crate::state::{AppState, TaskEventBroadcast};

/// 403 in this module's error shape (`AppError`, not raw tuple).
fn forbidden(msg: &str) -> AppError {
    AppError::new(StatusCode::FORBIDDEN, "forbidden", msg)
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

// ── Handlers ──────────────────────────────────────────────────────────────────────

/// POST /api/v1/tasks
pub async fn create_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Json(body): Json<CreateTaskBody>,
) -> Result<Json<Value>, AppError> {
    // Validate deadline format if provided
    if let Some(deadline) = &body.deadline {
        if let Err(_) = chrono::DateTime::parse_from_rfc3339(deadline) {
            return Err(AppError::new(
                StatusCode::BAD_REQUEST,
                "invalid_date_format",
                "deadline must be in RFC3339 format",
            ));
        }
    }

    // Bind the delegator to the authenticated signer (N13).
    if !crate::api::did_matches(&auth.0, &body.delegator_did) {
        return Err(forbidden("delegator_did must be the authenticated signer"));
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

    state.db.create_task(&task).await.map_err(|e| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            &e.to_string(),
        )
    })?;

    Ok((StatusCode::CREATED, Json(task_to_json(&task))).into())
}

/// GET /api/v1/tasks
pub async fn list_tasks(
    State(state): State<AppState>,
    Query(q): Query<ListTasksQuery>,
) -> Result<Json<Value>, AppError> {
    // Validate limit parameter
    let limit = q.limit.clamp(1, 200);

    let tasks = state
        .db
        .list_tasks(q.status.as_deref(), q.assignee_did.as_deref(), limit)
        .await
        .map_err(|e| {
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                &e.to_string(),
            )
        })?;

    let items: Vec<Value> = tasks.iter().map(task_to_json).collect();
    Ok(Json(json!({ "tasks": items, "count": items.len() })).into())
}

/// GET /api/v1/tasks/{id}
pub async fn get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    // Validate UUID format
    if let Err(_) = Uuid::parse_str(&id) {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            "invalid_uuid",
            "task id must be a valid UUID",
        ));
    }

    match state.db.get_task(&id).await {
        Ok(Some(t)) => Ok(Json(task_to_json(&t)).into()),
        Ok(None) => Err(AppError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "task not found",
        )),
        Err(e) => Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            &e.to_string(),
        )),
    }
}

/// POST /api/v1/tasks/{id}/claim
pub async fn claim_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(body): Json<ClaimTaskBody>,
) -> Result<Json<Value>, AppError> {
    // Bind the assignee to the authenticated signer (N13).
    if !crate::api::did_matches(&auth.0, &body.assignee_did) {
        return Err(forbidden("assignee_did must be the authenticated signer"));
    }

    let task = state.db.claim_task(&id, &auth.0).await.map_err(|e| {
        AppError::new(
            StatusCode::CONFLICT,
            "task_claim_error",
            &e.to_string(),
        )
    })?;

    let _ = state.task_event_tx.send(TaskEventBroadcast {
        task_id: id,
        old_status: "pending".to_string(),
        new_status: "claimed".to_string(),
        by_did: auth.0,
        at: Utc::now().to_rfc3339