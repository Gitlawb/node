//! REST handlers for agent task delegation API.
//!
//! Routes (all under /api/v1/tasks):
//!   POST   /api/v1/tasks                    — create task
//!   GET    /api/v1/tasks                    — list tasks
//!   GET    /api/v1/tasks/{id}               — get task
//!   POST   /api/v1/tasks/{id}/claim         — claim task
//!   POST   /api/v1/tasks/{id}/complete      — complete task
//!   POST   /api/v1/tasks/{id}/fail          — fail task

use std::collections::{HashMap, HashSet};

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
use crate::db::{AgentTask, RepoRecord, VisibilityRule};
use crate::error::AppError;
use crate::state::{AppState, TaskEventBroadcast};

/// 403 in this module's error shape (`(StatusCode, Json<Value>)`, not `AppError`).
fn forbidden(msg: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "forbidden", "message": msg })),
    )
}

/// Map a db-layer `anyhow` from claim/finish: connection-class sqlx failures
/// stay retryable 503, business "not claimable / not claimed" stays 409 with
/// a fixed message (not the anyhow text).
fn task_write_conflict(err: anyhow::Error, message: &str) -> AppError {
    match AppError::from(err) {
        db @ AppError::Db(_) => db,
        _ => AppError::Conflict(message.into()),
    }
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
    pub after_created_at: Option<String>,
    pub after_id: Option<String>,
    pub cursor_created_at: Option<String>,
    pub cursor_id: Option<String>,
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

/// Same projection as `task_to_json`, minus `ucan_token` (#268). The read
/// surfaces (`list_tasks`, `get_task`) never need to echo it back to anyone,
/// including the delegator/assignee: it was handed to the assignee at
/// delegation/claim time via the write-side responses, which still use
/// `task_to_json` unchanged.
fn task_to_read_json(t: &AgentTask) -> Value {
    json!({
        "id": t.id,
        "repo_id": t.repo_id,
        "kind": t.kind,
        "status": t.status,
        "delegator_did": t.delegator_did,
        "assignee_did": t.assignee_did,
        "capability": t.capability,
        "payload": t.payload,
        "result": t.result,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
        "deadline": t.deadline,
    })
}

/// Hard ceiling on rows a task read surface fetches for one request, mirroring
/// `MAX_VISIBLE_REF_UPDATES` in `api/events.rs` (#112/#114) for the same
/// reason: bound the underlying query before an unauthenticated caller's
/// request size controls how much the visibility filter has to scan.
const MAX_VISIBLE_TASKS: i64 = 200;

/// Maximum task candidates one list request may inspect while searching for
/// visible rows. This keeps a denied request from walking the full task table.
const MAX_TASK_SCAN_CANDIDATES: i64 = 1_000;

/// Whether `task` should be visible to `caller` (`None` = anonymous).
///
/// The delegator and assignee can always read a task they are already party
/// to — they hold its `payload` (and held `ucan_token`, though reads never
/// echo it back) from creating or being assigned it. Otherwise, a task naming
/// a locally-hosted repo follows that repo's normal read gate, the same way
/// `ref_update_row_visible` (`visibility.rs`) drops a ref-update row for a
/// repo the caller can't read. A task with no `repo_id`, or naming a repo this
/// node does not host, is visible only to its delegator/assignee — fail
/// closed, since an open-to-everyone default is exactly the gap #268 found
/// (`GET /api/v1/tasks` and `/tasks/{id}` had no gate at all).
pub(crate) fn task_visible(
    task: &AgentTask,
    caller: Option<&str>,
    repos_by_id: &HashMap<String, RepoRecord>,
    rules_by_repo: &HashMap<String, Vec<VisibilityRule>>,
) -> bool {
    if let Some(c) = caller {
        if crate::api::did_matches(c, &task.delegator_did) {
            return true;
        }
        let assignee_match = task
            .assignee_did
            .as_deref()
            .map(|a| crate::api::did_matches(c, a))
            .unwrap_or(false);
        if assignee_match {
            return true;
        }
    }
    let Some(repo_id) = task.repo_id.as_deref() else {
        return false;
    };
    // Slash-form ids are mirror rows. Mirrors are public placeholders and do
    // not replicate visibility rules, so they cannot establish read access.
    if repo_id.contains('/') {
        return false;
    }
    let Some(record) = repos_by_id.get(repo_id) else {
        return false;
    };
    let rules = rules_by_repo
        .get(&record.id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    crate::visibility::listable_at_root(rules, record.is_public, &record.owner_did, caller)
}

/// Collect up to `limit` tasks visible to `caller`, applying the same gate the
#[derive(Debug, Clone)]
pub(crate) struct VisibleTasks {
    pub tasks: Vec<AgentTask>,
    /// True when the candidate scan hit `MAX_TASK_SCAN_CANDIDATES` and more
    /// rows remain, so the caller cannot tell an empty/short page from an
    /// exhaustive one. False when the last fetched batch was short or a
    /// one-row probe past the ceiling is empty: exactly
    /// `MAX_TASK_SCAN_CANDIDATES` rows with nothing beyond is a finished
    /// stream, not a wall. Deliberately carries no cursor: the scan position
    /// at that point is the last *examined* candidate, which may be a task
    /// the caller was denied, and handing that back would let a denied read
    /// leak the id/created_at of a row `GET /tasks/{id}` otherwise 404s (the
    /// same id `claim_task` accepts). A caller can page with
    /// `after_created_at`/`after_id` set to the last row they actually
    /// received; if a window of >= 1,000 consecutive denied tasks
    /// intervenes before the next visible row, pagination anchored on that
    /// received row stalls at the candidate ceiling and repeatedly returns
    /// empty results with `incomplete: true`.
    pub incomplete: bool,
}

/// Collect up to `limit` tasks visible to `caller`, applying the same gate the
/// GraphQL `tasks` query uses (`collect_visible_tasks` is called from both) so
/// the two surfaces cannot drift, matching the `collect_visible_ref_updates`
/// pattern in `api/events.rs`. `limit` is clamped here so a caller-supplied
/// value never reaches SQL unclamped.
///
pub(crate) async fn collect_visible_tasks(
    db: &crate::db::Db,
    status: Option<&str>,
    assignee_did: Option<&str>,
    limit: i64,
    after: Option<(&str, &str)>,
    caller: Option<&str>,
) -> crate::error::Result<VisibleTasks> {
    let bounded_limit = limit.clamp(0, MAX_VISIBLE_TASKS);
    if bounded_limit == 0 {
        return Ok(VisibleTasks {
            tasks: Vec::new(),
            incomplete: false,
        });
    }
    let mut visible = Vec::with_capacity(bounded_limit as usize);
    let mut cursor: Option<(String, String)> =
        after.map(|(ts, id)| (ts.to_string(), id.to_string()));
    let mut scanned = 0;
    let mut last_batch_full = false;

    while scanned < MAX_TASK_SCAN_CANDIDATES {
        let batch_limit = MAX_VISIBLE_TASKS.min(MAX_TASK_SCAN_CANDIDATES - scanned);
        let tasks = db
            .list_tasks_keyset(
                status,
                assignee_did,
                batch_limit,
                cursor
                    .as_ref()
                    .map(|(created_at, id)| (created_at.as_str(), id.as_str())),
            )
            .await?;
        if tasks.is_empty() {
            last_batch_full = false;
            break;
        }
        scanned += tasks.len() as i64;
        let next_cursor = tasks
            .last()
            .map(|task| (task.created_at.clone(), task.id.clone()));

        let referenced: Vec<String> = tasks
            .iter()
            .filter_map(|task| task.repo_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let repos_by_id: HashMap<String, RepoRecord> = db
            .list_repos_deduped_by_ids(&referenced)
            .await?
            .into_iter()
            .map(|repo| (repo.id.clone(), repo))
            .collect();
        let repo_ids: Vec<String> = repos_by_id.keys().cloned().collect();
        let rules_by_repo = db.list_visibility_rules_for_repos(&repo_ids).await?;

        for task in &tasks {
            if task_visible(task, caller, &repos_by_id, &rules_by_repo) {
                visible.push(task.clone());
                if visible.len() == bounded_limit as usize {
                    break;
                }
            }
        }

        last_batch_full = tasks.len() >= batch_limit as usize;
        if visible.len() == bounded_limit as usize {
            // Page filled before the scan ceiling. The caller pages from the
            // last visible row; `incomplete` is reserved for the ceiling path.
            return Ok(VisibleTasks {
                tasks: visible,
                incomplete: false,
            });
        }
        if !last_batch_full {
            break;
        }
        cursor = next_cursor;
    }

    // A full last batch at the ceiling is ambiguous: either more rows exist,
    // or the table ended on an exact multiple of the batch size. Probe one
    // more row so `incomplete` is false when the stream is exhausted.
    let incomplete = if scanned >= MAX_TASK_SCAN_CANDIDATES && last_batch_full {
        let more = db
            .list_tasks_keyset(
                status,
                assignee_did,
                1,
                cursor
                    .as_ref()
                    .map(|(created_at, id)| (created_at.as_str(), id.as_str())),
            )
            .await?;
        !more.is_empty()
    } else {
        false
    };

    Ok(VisibleTasks {
        tasks: visible,
        incomplete,
    })
}

/// Fetch a single task gated the same way `collect_visible_tasks` gates a
/// page. Returns `None` both when the task does not exist and when the caller
/// may not see it — the two are indistinguishable to the caller, matching
/// `authorize_repo_read`'s opaque not-found-vs-denied handling, so an
/// unauthorized caller cannot use this to probe which task IDs exist.
pub(crate) async fn get_visible_task(
    db: &crate::db::Db,
    id: &str,
    caller: Option<&str>,
) -> crate::error::Result<Option<AgentTask>> {
    let Some(task) = db.get_task(id).await? else {
        return Ok(None);
    };
    let (repos_by_id, rules_by_repo) = match task.repo_id.as_deref() {
        Some(repo_id) => {
            let ids = [repo_id.to_string()];
            let repos = db.list_repos_deduped_by_ids(&ids).await?;
            match repos.into_iter().find(|r| r.id == repo_id) {
                Some(record) => {
                    let rules = db.list_visibility_rules(&record.id).await?;
                    (
                        HashMap::from([(record.id.clone(), record)]),
                        HashMap::from([(repo_id.to_string(), rules)]),
                    )
                }
                None => (HashMap::new(), HashMap::new()),
            }
        }
        None => (HashMap::new(), HashMap::new()),
    };
    Ok(task_visible(&task, caller, &repos_by_id, &rules_by_repo).then_some(task))
}

/// Broadcast a task event only when the task is publicly visible.
/// Matches `if announce` on ref updates: private-task status changes stay off
/// the unauthenticated GraphQL subscription.
pub(crate) async fn announce_task_event(
    db: &crate::db::Db,
    tx: &tokio::sync::broadcast::Sender<TaskEventBroadcast>,
    event: TaskEventBroadcast,
) {
    match get_visible_task(db, &event.task_id, None).await {
        Ok(Some(_)) => {
            let _ = tx.send(event);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, task_id = %event.task_id, "skipping task event broadcast");
        }
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/tasks
pub async fn create_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Json(body): Json<CreateTaskBody>,
) -> std::result::Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
    })?;
    Ok((StatusCode::CREATED, Json(task_to_json(&task))))
}

/// Canonicalize an RFC3339 timestamp. If spaces were introduced by URL query decoding
/// (e.g. `+00:00` decoded as ` 00:00`), convert spaces back to `+` before parsing.
/// Validates RFC3339 syntax while preserving the original fractional precision
/// and string representation so comparisons against stored TEXT timestamps remain exact.
pub(crate) fn canonicalize_timestamp(raw: &str) -> crate::error::Result<String> {
    let normalized = if raw.contains(' ') {
        raw.replace(' ', "+")
    } else {
        raw.to_string()
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map_err(|e| AppError::BadRequest(format!("invalid timestamp format '{raw}': {e}")))?;
    Ok(normalized)
}

/// A cursor is two query fields (`created_at`, `id`) from either the `after_*` or `cursor_*` family.
/// Reject cross-family alias mixing, require both fields within a family, and canonicalize timestamps.
pub(crate) fn parse_after_cursor(
    after_created_at: Option<&str>,
    after_id: Option<&str>,
    cursor_created_at: Option<&str>,
    cursor_id: Option<&str>,
) -> crate::error::Result<Option<(String, String)>> {
    let has_after = after_created_at.is_some() || after_id.is_some();
    let has_cursor = cursor_created_at.is_some() || cursor_id.is_some();
    if has_after && has_cursor {
        return Err(AppError::BadRequest(
            "cannot mix after_* and cursor_* parameter aliases".into(),
        ));
    }
    let (raw_ts, raw_id) = if has_after {
        match (after_created_at, after_id) {
            (Some(ts), Some(id)) => (ts, id),
            _ => {
                return Err(AppError::BadRequest(
                    "after_created_at and after_id must be supplied together".into(),
                ))
            }
        }
    } else if has_cursor {
        match (cursor_created_at, cursor_id) {
            (Some(ts), Some(id)) => (ts, id),
            _ => {
                return Err(AppError::BadRequest(
                    "cursor_created_at and cursor_id must be supplied together".into(),
                ))
            }
        }
    } else {
        return Ok(None);
    };

    let canonical_ts = canonicalize_timestamp(raw_ts)?;
    Ok(Some((canonical_ts, raw_id.to_string())))
}

/// GET /api/v1/tasks
///
/// Open to anonymous callers, but every row is gated by `collect_visible_tasks`
/// (#268): an anonymous or unrelated caller only sees tasks against a repo they
/// can read, never another party's repo-less task or its `ucan_token`/`payload`.
pub async fn list_tasks(
    State(state): State<AppState>,
    Query(q): Query<ListTasksQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> crate::error::Result<Json<Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let after_parsed = parse_after_cursor(
        q.after_created_at.as_deref(),
        q.after_id.as_deref(),
        q.cursor_created_at.as_deref(),
        q.cursor_id.as_deref(),
    )?;
    let after = after_parsed
        .as_ref()
        .map(|(ts, id)| (ts.as_str(), id.as_str()));
    let result = collect_visible_tasks(
        &state.db,
        q.status.as_deref(),
        q.assignee_did.as_deref(),
        q.limit,
        after,
        caller,
    )
    .await?;
    let items: Vec<Value> = result.tasks.iter().map(task_to_read_json).collect();
    Ok(Json(json!({
        "tasks": items,
        "count": items.len(),
        "incomplete": result.incomplete,
    })))
}

/// GET /api/v1/tasks/{id}
///
/// Gated the same way as `list_tasks` (#268): a task the caller may not see
/// 404s, indistinguishable from a task that doesn't exist.
pub async fn get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> crate::error::Result<Json<Value>> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    match get_visible_task(&state.db, &id, caller).await? {
        Some(t) => Ok(Json(task_to_read_json(&t))),
        None => Err(AppError::NotFound("task not found".into())),
    }
}

/// POST /api/v1/tasks/{id}/claim
pub async fn claim_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(body): Json<ClaimTaskBody>,
) -> crate::error::Result<Json<Value>> {
    // Bind the assignee to the authenticated signer (N13).
    if !crate::api::did_matches(&auth.0, &body.assignee_did) {
        return Err(AppError::Forbidden(
            "assignee_did must be the authenticated signer".into(),
        ));
    }
    // Same visibility gate as complete/fail: invisible tasks are 404 so
    // existence is not leaked via a successful claim or a leaking 409.
    get_visible_task(&state.db, &id, Some(&auth.0))
        .await?
        .ok_or_else(|| AppError::NotFound("task not found".into()))?;
    let task =
        state.db.claim_task(&id, &auth.0).await.map_err(|e| {
            task_write_conflict(e, "task not claimable: not found or already claimed")
        })?;
    announce_task_event(
        &state.db,
        &state.task_event_tx,
        TaskEventBroadcast {
            task_id: id,
            old_status: "pending".to_string(),
            new_status: "claimed".to_string(),
            by_did: auth.0,
            at: Utc::now().to_rfc3339(),
        },
    )
    .await;
    Ok(Json(task_to_json(&task)))
}

/// POST /api/v1/tasks/{id}/complete
pub async fn complete_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(body): Json<CompleteTaskBody>,
) -> crate::error::Result<Json<Value>> {
    // Authorize the actor, not just bind their identity: the task must be visible
    // to the caller (returning 404 for invisible tasks so existence is not leaked),
    // and only the task's assignee may complete it.
    let existing = get_visible_task(&state.db, &id, Some(&auth.0))
        .await?
        .ok_or_else(|| AppError::NotFound("task not found".into()))?;
    if !crate::api::did_matches(
        &auth.0,
        existing.assignee_did.as_deref().unwrap_or_default(),
    ) {
        return Err(AppError::Forbidden(
            "only the task assignee can complete it".into(),
        ));
    }
    let by_did = auth.0;
    let task = state
        .db
        .finish_task(&id, "completed", body.result.as_deref())
        .await
        .map_err(|e| task_write_conflict(e, "task not found or not in claimed state"))?;
    announce_task_event(
        &state.db,
        &state.task_event_tx,
        TaskEventBroadcast {
            task_id: id,
            old_status: "claimed".to_string(),
            new_status: "completed".to_string(),
            by_did,
            at: Utc::now().to_rfc3339(),
        },
    )
    .await;
    Ok(Json(task_to_json(&task)))
}

/// POST /api/v1/tasks/{id}/fail
pub async fn fail_task(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthenticatedDid>,
    Path(id): Path<String>,
    Json(body): Json<FailTaskBody>,
) -> crate::error::Result<Json<Value>> {
    // Authorize the actor: the task must be visible to the caller (returning
    // 404 for invisible tasks so existence is not leaked), and only the task's
    // assignee may fail it.
    let existing = get_visible_task(&state.db, &id, Some(&auth.0))
        .await?
        .ok_or_else(|| AppError::NotFound("task not found".into()))?;
    if !crate::api::did_matches(
        &auth.0,
        existing.assignee_did.as_deref().unwrap_or_default(),
    ) {
        return Err(AppError::Forbidden(
            "only the task assignee can fail it".into(),
        ));
    }
    let by_did = auth.0;
    let reason = body.reason.unwrap_or_default();
    let task = state
        .db
        .finish_task(&id, "failed", Some(&reason))
        .await
        .map_err(|e| task_write_conflict(e, "task not found or not in claimed state"))?;
    announce_task_event(
        &state.db,
        &state.task_event_tx,
        TaskEventBroadcast {
            task_id: id,
            old_status: "claimed".to_string(),
            new_status: "failed".to_string(),
            by_did,
            at: Utc::now().to_rfc3339(),
        },
    )
    .await;
    Ok(Json(task_to_json(&task)))
}

#[cfg(test)]
mod visible_tasks_tests {
    use super::*;
    use crate::test_support::{signed_request_as, test_state};
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Router;
    use chrono::Utc;
    use sqlx::PgPool;
    use tower::ServiceExt;

    const DELEGATOR: &str = "did:key:z6MkDelegator";
    const ASSIGNEE: &str = "did:key:z6MkAssignee";
    const STRANGER: &str = "did:key:z6MkStranger";
    const SECRET_UCAN: &str = "SECRET-UCAN-TOKEN";

    fn repo(id: &str, owner_did: &str, name: &str, is_public: bool) -> RepoRecord {
        let now = Utc::now();
        RepoRecord {
            id: id.into(),
            name: name.into(),
            owner_did: owner_did.into(),
            description: None,
            is_public,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: format!("/tmp/{id}"),
            forked_from: None,
            machine_id: None,
        }
    }

    fn task(id: &str, repo_id: Option<&str>, delegator: &str) -> AgentTask {
        let now = Utc::now().to_rfc3339();
        AgentTask {
            id: id.into(),
            repo_id: repo_id.map(String::from),
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: delegator.into(),
            assignee_did: None,
            capability: "repo:write".into(),
            ucan_token: Some(SECRET_UCAN.into()),
            payload: Some("payload-data".into()),
            result: None,
            created_at: now.clone(),
            updated_at: now,
            deadline: None,
        }
    }

    fn list_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route("/api/v1/tasks", axum::routing::get(super::list_tasks))
            .route("/api/v1/tasks/{id}", axum::routing::get(super::get_task))
            .with_state(state)
    }

    fn anon_get(uri: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .expect("request builder")
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    /// #268 — load-bearing RED→GREEN: before this fix, `list_tasks`/`get_task`
    /// had no gate at all, so an anonymous caller could enumerate every task on
    /// the node, including another party's repo-less task, its `ucan_token`,
    /// and its `payload`. An anonymous caller must now see neither.
    #[sqlx::test]
    async fn anon_cannot_list_or_read_repo_less_task_of_another(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(
            body["tasks"].as_array().unwrap().len(),
            0,
            "anon must not see another party's repo-less task"
        );
        assert_eq!(body["count"], 0);
        let serialized = body.to_string();
        assert!(!serialized.contains("t1"));
        assert!(!serialized.contains("payload-data"));
        assert!(!serialized.contains(SECRET_UCAN));

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks/t1"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "anon get_task on an invisible task must 404, not leak it"
        );
        let body = body_json(resp).await;
        let serialized = body.to_string();
        assert!(!serialized.contains("t1"));
        assert!(!serialized.contains("payload-data"));
        assert!(!serialized.contains(SECRET_UCAN));

        let resp = list_router(state.clone())
            .oneshot(signed_request_as(
                STRANGER,
                Method::GET,
                "/api/v1/tasks",
                Body::empty(),
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["tasks"].as_array().unwrap().len(), 0);
        assert_eq!(body["count"], 0);
        let serialized = body.to_string();
        assert!(!serialized.contains("t1"));
        assert!(!serialized.contains("payload-data"));
        assert!(!serialized.contains(SECRET_UCAN));

        let resp = list_router(state)
            .oneshot(signed_request_as(
                STRANGER,
                Method::GET,
                "/api/v1/tasks/t1",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = body_json(resp).await;
        let serialized = body.to_string();
        assert!(!serialized.contains("t1"));
        assert!(!serialized.contains("payload-data"));
        assert!(!serialized.contains(SECRET_UCAN));
    }

    /// The delegator can always read their own repo-less task — the party who
    /// created it is not locked out by the new gate.
    #[sqlx::test]
    async fn delegator_sees_own_repo_less_task(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let resp = list_router(state.clone())
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::GET,
                "/api/v1/tasks",
                Body::empty(),
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["tasks"].as_array().unwrap().len(), 1);

        let resp = list_router(state)
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::GET,
                "/api/v1/tasks/t1",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The assignee can read a task they were assigned, even though they are
    /// not its delegator.
    #[sqlx::test]
    async fn assignee_sees_assigned_repo_less_task(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();
        state.db.claim_task("t1", ASSIGNEE).await.unwrap();

        let resp = list_router(state)
            .oneshot(signed_request_as(
                ASSIGNEE,
                Method::GET,
                "/api/v1/tasks/t1",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// #268 — `ucan_token` must never appear on the read surfaces, even to the
    /// delegator who legitimately holds it: they already received it via the
    /// write-side `create_task` response, so a read echo is unnecessary
    /// exposure, not a feature.
    #[sqlx::test]
    async fn ucan_token_never_appears_in_read_responses(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let resp = list_router(state.clone())
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::GET,
                "/api/v1/tasks/t1",
                Body::empty(),
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert!(
            body.get("ucan_token").is_none(),
            "get_task must never echo ucan_token, got {body:?}"
        );

        let resp = list_router(state)
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::GET,
                "/api/v1/tasks",
                Body::empty(),
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert!(
            !body.to_string().contains(SECRET_UCAN),
            "list_tasks must never echo ucan_token, got {body:?}"
        );
    }

    /// A repo-scoped task inherits that repo's read-visibility gate: hidden
    /// from a stranger, visible to the repo owner even though the owner is
    /// neither the task's delegator nor its assignee.
    #[sqlx::test]
    async fn repo_scoped_private_task_follows_repo_visibility(pool: PgPool) {
        const OWNER: &str = "did:key:z6MkRepoOwner";
        const OTHER_DELEGATOR: &str = "did:key:z6MkOtherDelegator";
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("r1", OWNER, "priv", false))
            .await
            .unwrap();
        state
            .db
            .create_task(&task("t1", Some("r1"), OTHER_DELEGATOR))
            .await
            .unwrap();

        let resp = list_router(state.clone())
            .oneshot(signed_request_as(
                STRANGER,
                Method::GET,
                "/api/v1/tasks/t1",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "a stranger must not see a private repo's task"
        );

        let resp = list_router(state)
            .oneshot(signed_request_as(
                OWNER,
                Method::GET,
                "/api/v1/tasks/t1",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the repo owner must see the task via the repo's read gate"
        );
    }

    #[sqlx::test]
    async fn mirror_only_repo_task_is_hidden_from_anonymous_reads(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .upsert_mirror_repo(DELEGATOR, "mirror", "/tmp/mirror", None, false)
            .await
            .unwrap();
        let mirror_id = format!("{DELEGATOR}/mirror");
        state
            .db
            .create_task(&task("t1", Some(&mirror_id), DELEGATOR))
            .await
            .unwrap();

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 0);

        let resp = list_router(state)
            .oneshot(anon_get("/api/v1/tasks/t1"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A negative limit must clamp to zero through `collect_visible_tasks`,
    /// not fall through to the visible set.
    #[sqlx::test]
    async fn negative_limit_returns_empty(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let resp = list_router(state)
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::GET,
                "/api/v1/tasks?limit=-1",
                Body::empty(),
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 0, "negative limit must clamp to 0");
    }

    #[sqlx::test]
    async fn older_visible_task_is_not_hidden_by_newer_denied_window(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        let mut visible = task("visible", Some("public-repo"), DELEGATOR);
        visible.created_at = "2026-01-01T00:00:00Z".into();
        visible.updated_at = visible.created_at.clone();
        state.db.create_task(&visible).await.unwrap();

        for i in 0..MAX_VISIBLE_TASKS {
            let mut hidden = task(&format!("hidden-{i:03}"), None, DELEGATOR);
            hidden.created_at = "2026-01-02T00:00:00Z".into();
            hidden.updated_at = hidden.created_at.clone();
            state.db.create_task(&hidden).await.unwrap();
        }

        let resp = list_router(state)
            .oneshot(anon_get("/api/v1/tasks?limit=1"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 1);
        assert_eq!(body["tasks"][0]["id"], "visible");
    }

    #[sqlx::test]
    async fn denied_history_scan_stops_at_candidate_ceiling_and_signals_incomplete(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        let mut visible_newer = task("newer-visible", Some("public-repo"), DELEGATOR);
        visible_newer.created_at = "2026-01-03T00:00:00Z".into();
        visible_newer.updated_at = visible_newer.created_at.clone();
        state.db.create_task(&visible_newer).await.unwrap();

        for i in 0..MAX_TASK_SCAN_CANDIDATES {
            let mut hidden = task(&format!("hidden-{i:04}"), None, DELEGATOR);
            hidden.created_at = "2026-01-02T00:00:00Z".into();
            hidden.updated_at = hidden.created_at.clone();
            state.db.create_task(&hidden).await.unwrap();
        }

        let mut visible_older = task("past-ceiling", Some("public-repo"), DELEGATOR);
        visible_older.created_at = "2026-01-01T00:00:00Z".into();
        visible_older.updated_at = visible_older.created_at.clone();
        state.db.create_task(&visible_older).await.unwrap();

        // Page 1 yields the first visible task.
        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks?limit=1"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 1);
        assert_eq!(body["incomplete"], false);
        assert_eq!(body["tasks"][0]["id"], "newer-visible");

        // Page 2 anchored on the last received row hits the 1,000 candidate scan ceiling
        // across the intervening denied rows and signals incomplete without leaking any denied row.
        let resp = list_router(state.clone())
            .oneshot(anon_get(
                "/api/v1/tasks?limit=1&after_created_at=2026-01-03T00:00:00Z&after_id=newer-visible",
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 0);
        assert_eq!(body["incomplete"], true);
        assert!(!body.to_string().contains("past-ceiling"));
        assert!(
            body.get("next_cursor").is_none(),
            "response must not disclose the last examined (denied) row's id/created_at: {body}"
        );
        assert!(
            !body.to_string().contains("hidden-"),
            "response must not leak any denied row's id: {body}"
        );

        // A subsequent request anchored on the same legitimately-held row stalls at the
        // scan ceiling rather than bypassing authorization.
        let resp = list_router(state)
            .oneshot(anon_get(
                "/api/v1/tasks?limit=1&after_created_at=2026-01-03T00:00:00Z&after_id=newer-visible",
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 0);
        assert_eq!(body["incomplete"], true);
    }

    #[sqlx::test]
    async fn list_tasks_rejects_partial_cursor_pair(pool: PgPool) {
        let state = test_state(pool).await;

        let resp = list_router(state.clone())
            .oneshot(anon_get(
                "/api/v1/tasks?after_created_at=2026-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(
            body["message"],
            "after_created_at and after_id must be supplied together"
        );

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks?after_id=some-id"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(
            body["message"],
            "after_created_at and after_id must be supplied together"
        );

        let resp = list_router(state.clone())
            .oneshot(anon_get(
                "/api/v1/tasks?cursor_created_at=2026-01-01T00:00:00Z",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(
            body["message"],
            "cursor_created_at and cursor_id must be supplied together"
        );

        let resp = list_router(state)
            .oneshot(anon_get("/api/v1/tasks?cursor_id=some-id"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(
            body["message"],
            "cursor_created_at and cursor_id must be supplied together"
        );
    }

    #[sqlx::test]
    async fn list_tasks_closed_pool_returns_503_db_unavailable(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        pool.close().await;

        let resp = list_router(state)
            .oneshot(anon_get("/api/v1/tasks"))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "closed-pool outage must be retryable 503, not 500"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"], "db_unavailable");
    }

    #[sqlx::test]
    async fn get_task_closed_pool_returns_503_db_unavailable(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        pool.close().await;

        let resp = list_router(state)
            .oneshot(anon_get("/api/v1/tasks/t1"))
            .await
            .unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "closed-pool outage must be retryable 503, not 500"
        );
        let body = body_json(resp).await;
        assert_eq!(body["error"], "db_unavailable");
    }

    #[sqlx::test]
    async fn list_tasks_rejects_mixed_cursor_alias_families(pool: PgPool) {
        let state = test_state(pool).await;

        let resp = list_router(state.clone())
            .oneshot(anon_get(
                "/api/v1/tasks?after_created_at=2026-01-01T00:00:00Z&after_id=a&cursor_created_at=2026-01-01T00:00:00Z&cursor_id=b",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "bad_request");
        assert_eq!(
            body["message"],
            "cannot mix after_* and cursor_* parameter aliases"
        );

        let resp = list_router(state.clone())
            .oneshot(anon_get(
                "/api/v1/tasks?after_created_at=2026-01-01T00:00:00Z&cursor_id=some-id",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "bad_request");
        assert_eq!(
            body["message"],
            "cannot mix after_* and cursor_* parameter aliases"
        );

        let resp = list_router(state)
            .oneshot(anon_get(
                "/api/v1/tasks?cursor_created_at=2026-01-01T00:00:00Z&after_id=some-id",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"], "bad_request");
        assert_eq!(
            body["message"],
            "cannot mix after_* and cursor_* parameter aliases"
        );
    }

    #[sqlx::test]
    async fn list_tasks_accepts_and_canonicalizes_spaces_in_timestamp(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        let mut t1 = task("t1", Some("public-repo"), DELEGATOR);
        t1.created_at = "2026-01-01T00:00:00+00:00".into();
        state.db.create_task(&t1).await.unwrap();

        let resp = list_router(state)
            .oneshot(anon_get(
                "/api/v1/tasks?after_created_at=2026-01-02T00:00:00+00:00&after_id=dummy",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[sqlx::test]
    async fn list_tasks_keyset_advances_across_trailing_zero_fraction_timestamps(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();

        let ts_sibling = "2026-06-01T00:00:00.000000000+00:00";
        let mut t2 = task("task-2", Some("public-repo"), DELEGATOR);
        t2.created_at = ts_sibling.into();
        t2.updated_at = t2.created_at.clone();
        state.db.create_task(&t2).await.unwrap();

        let mut t1 = task("task-1", Some("public-repo"), DELEGATOR);
        t1.created_at = ts_sibling.into();
        t1.updated_at = t1.created_at.clone();
        state.db.create_task(&t1).await.unwrap();

        let mut t0 = task("task-0", Some("public-repo"), DELEGATOR);
        t0.created_at = "2026-05-01T00:00:00.000000000+00:00".into();
        t0.updated_at = t0.created_at.clone();
        state.db.create_task(&t0).await.unwrap();

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks?limit=1"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 1);
        assert_eq!(body["tasks"][0]["id"], "task-2");
        let served_ts = body["tasks"][0]["created_at"].as_str().unwrap();
        assert_eq!(served_ts, ts_sibling);

        let resp = list_router(state.clone())
            .oneshot(anon_get(&format!(
                "/api/v1/tasks?limit=1&after_created_at={served_ts}&after_id=task-2"
            )))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 1);
        assert_eq!(
            body["tasks"][0]["id"], "task-1",
            "keyset pagination must advance to sibling row with equal timestamp"
        );

        let resp = list_router(state)
            .oneshot(anon_get(&format!(
                "/api/v1/tasks?limit=1&after_created_at={served_ts}&after_id=task-1"
            )))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 1);
        assert_eq!(body["tasks"][0]["id"], "task-0");
    }

    fn full_task_router(state: crate::state::AppState) -> Router {
        Router::new()
            .route("/api/v1/tasks", axum::routing::get(super::list_tasks))
            .route("/api/v1/tasks/{id}", axum::routing::get(super::get_task))
            .route(
                "/api/v1/tasks/{id}/claim",
                axum::routing::post(super::claim_task),
            )
            .route(
                "/api/v1/tasks/{id}/complete",
                axum::routing::post(super::complete_task),
            )
            .route(
                "/api/v1/tasks/{id}/fail",
                axum::routing::post(super::fail_task),
            )
            .with_state(state)
    }

    fn assert_not_found_envelope(body: &serde_json::Value) {
        assert_eq!(body["error"], "not_found");
        assert_eq!(body["message"], "task not found");
        let serialized = body.to_string();
        assert!(!serialized.contains(SECRET_UCAN));
        assert!(!serialized.contains("payload-data"));
    }

    #[sqlx::test]
    async fn complete_and_fail_task_on_invisible_task_returns_404_not_403(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let complete_resp = full_task_router(state.clone())
            .oneshot(signed_request_as(
                STRANGER,
                Method::POST,
                "/api/v1/tasks/t1/complete",
                Body::from(r#"{"result":"done"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(
            complete_resp.status(),
            StatusCode::NOT_FOUND,
            "completing an invisible task must 404, not leak existence via 403"
        );
        assert_not_found_envelope(&body_json(complete_resp).await);

        let fail_resp = full_task_router(state)
            .oneshot(signed_request_as(
                STRANGER,
                Method::POST,
                "/api/v1/tasks/t1/fail",
                Body::from(r#"{"reason":"error"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(
            fail_resp.status(),
            StatusCode::NOT_FOUND,
            "failing an invisible task must 404, not leak existence via 403"
        );
        assert_not_found_envelope(&body_json(fail_resp).await);
    }

    #[sqlx::test]
    async fn claim_task_on_invisible_task_returns_404_not_success_or_409(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let claim_resp = full_task_router(state)
            .oneshot(signed_request_as(
                STRANGER,
                Method::POST,
                "/api/v1/tasks/t1/claim",
                Body::from(format!(r#"{{"assignee_did":"{STRANGER}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            claim_resp.status(),
            StatusCode::NOT_FOUND,
            "claiming an invisible task must 404, not succeed or leak via 409"
        );
        assert_not_found_envelope(&body_json(claim_resp).await);
    }

    /// Goes RED if `claim_task`'s `assignee_did IS NULL OR assignee_did = $2`
    /// predicate is deleted: a public-repo pre-assigned task is visible to a
    /// stranger, so only the SQL guard stops them from overwriting the
    /// designated assignee.
    #[sqlx::test]
    async fn claim_task_does_not_steal_preassigned_assignee(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        let mut assigned = task("preassigned", Some("public-repo"), DELEGATOR);
        assigned.assignee_did = Some(ASSIGNEE.into());
        state.db.create_task(&assigned).await.unwrap();

        let stranger_resp = full_task_router(state.clone())
            .oneshot(signed_request_as(
                STRANGER,
                Method::POST,
                "/api/v1/tasks/preassigned/claim",
                Body::from(format!(r#"{{"assignee_did":"{STRANGER}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            stranger_resp.status(),
            StatusCode::CONFLICT,
            "a stranger must not claim a task pre-assigned to someone else"
        );
        let stranger_body = body_json(stranger_resp).await;
        assert!(!stranger_body.to_string().contains(SECRET_UCAN));
        assert_eq!(
            state
                .db
                .get_task("preassigned")
                .await
                .unwrap()
                .unwrap()
                .assignee_did
                .as_deref(),
            Some(ASSIGNEE),
            "hostile claim must leave the designated assignee in place"
        );

        let assignee_resp = full_task_router(state.clone())
            .oneshot(signed_request_as(
                ASSIGNEE,
                Method::POST,
                "/api/v1/tasks/preassigned/claim",
                Body::from(format!(r#"{{"assignee_did":"{ASSIGNEE}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(assignee_resp.status(), StatusCode::OK);
        let claimed = body_json(assignee_resp).await;
        assert_eq!(claimed["status"], "claimed");
        assert_eq!(claimed["assignee_did"], ASSIGNEE);

        let second_resp = full_task_router(state)
            .oneshot(signed_request_as(
                STRANGER,
                Method::POST,
                "/api/v1/tasks/preassigned/claim",
                Body::from(format!(r#"{{"assignee_did":"{STRANGER}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            second_resp.status(),
            StatusCode::CONFLICT,
            "a second claim after the assignee took the task must be refused"
        );
    }

    /// Goes RED if `announce_task_event` is replaced with a bare `tx.send`:
    /// a repo-less claim would then reach an anonymous subscriber.
    #[sqlx::test]
    async fn announce_task_event_skips_tasks_invisible_to_anonymous(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        state
            .db
            .create_task(&task("pub-t", Some("public-repo"), DELEGATOR))
            .await
            .unwrap();
        state
            .db
            .create_task(&task("priv-t", None, DELEGATOR))
            .await
            .unwrap();

        let mut events = state.task_event_tx.subscribe();

        let pub_resp = full_task_router(state.clone())
            .oneshot(signed_request_as(
                ASSIGNEE,
                Method::POST,
                "/api/v1/tasks/pub-t/claim",
                Body::from(format!(r#"{{"assignee_did":"{ASSIGNEE}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(pub_resp.status(), StatusCode::OK);
        let broadcast = events
            .try_recv()
            .expect("a publicly visible claim must broadcast");
        assert_eq!(broadcast.task_id, "pub-t");
        assert_eq!(broadcast.new_status, "claimed");

        let priv_resp = full_task_router(state)
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::POST,
                "/api/v1/tasks/priv-t/claim",
                Body::from(format!(r#"{{"assignee_did":"{DELEGATOR}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(priv_resp.status(), StatusCode::OK);
        assert!(
            events.try_recv().is_err(),
            "a repo-less claim must not reach an anonymous subscriber"
        );
    }

    #[sqlx::test]
    async fn exhausted_scan_of_exactly_ceiling_candidates_is_not_incomplete(pool: PgPool) {
        let state = test_state(pool).await;
        for i in 0..MAX_TASK_SCAN_CANDIDATES {
            let mut hidden = task(&format!("hidden-{i:04}"), None, DELEGATOR);
            hidden.created_at = "2026-01-02T00:00:00Z".into();
            hidden.updated_at = hidden.created_at.clone();
            state.db.create_task(&hidden).await.unwrap();
        }

        let resp = list_router(state)
            .oneshot(anon_get("/api/v1/tasks?limit=1"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 0);
        assert_eq!(
            body["incomplete"], false,
            "exactly {MAX_TASK_SCAN_CANDIDATES} denied rows with nothing beyond is a finished stream"
        );
    }

    #[sqlx::test]
    async fn task_mutations_closed_pool_returns_503_db_unavailable(pool: PgPool) {
        let state = test_state(pool.clone()).await;
        pool.close().await;

        for (uri, body) in [
            (
                "/api/v1/tasks/t1/claim",
                format!(r#"{{"assignee_did":"{ASSIGNEE}"}}"#),
            ),
            ("/api/v1/tasks/t1/complete", r#"{"result":"done"}"#.into()),
            ("/api/v1/tasks/t1/fail", r#"{"reason":"error"}"#.into()),
        ] {
            let resp = full_task_router(state.clone())
                .oneshot(signed_request_as(
                    ASSIGNEE,
                    Method::POST,
                    uri,
                    Body::from(body),
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{uri}: closed-pool outage during visibility pre-check must be retryable 503"
            );
            let json = body_json(resp).await;
            assert_eq!(json["error"], "db_unavailable", "{uri}");
        }
    }
}
