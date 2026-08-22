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
pub(crate) fn task_write_conflict(err: anyhow::Error, message: &str) -> AppError {
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
    /// Opaque continuation token from a previous response's `next_cursor`.
    /// The raw `after_created_at`/`after_id`/`cursor_created_at`/`cursor_id`
    /// pairs this replaces are gone (#327 review): a caller-typed timestamp
    /// compared against TEXT storage had no single ordering domain, and a
    /// caller-held cursor could only ever name a row the caller had already
    /// seen, which is what made a long denied window unpageable.
    pub cursor: Option<String>,
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

#[derive(Debug, Clone)]
pub(crate) struct VisibleTasks {
    pub tasks: Vec<AgentTask>,
    /// True when candidate rows remain past this page, whether or not the
    /// page filled. `next_position` is `Some` exactly when this is true.
    pub has_more: bool,
    /// True when this request stopped at `MAX_TASK_SCAN_CANDIDATES` with the
    /// page still unfilled, so a short or empty page is a paused scan rather
    /// than the end of the stream.
    ///
    /// Kept separate from `has_more` because they answer different questions
    /// (#327 review): `has_more` says another page exists, `incomplete` says
    /// *this* page is short only because the authorization scan hit its safety
    /// wall. Overloading one flag for both left a caller unable to tell a
    /// finished stream from a paused one.
    pub incomplete: bool,
    /// Keyset position of the last candidate this request *examined*, visible
    /// or not. Handed back only inside a MAC'd token (`api::task_cursor`), so
    /// resuming a scan can step past a denied window without the denied rows'
    /// ids or timestamps ever reaching the caller in the clear.
    pub next_position: Option<crate::api::task_cursor::TaskPosition>,
}

/// Collect up to `limit` tasks visible to `caller`, applying the same gate the
/// GraphQL `tasks` query uses (`collect_visible_tasks` is called from both) so
/// the two surfaces cannot drift, matching the `collect_visible_ref_updates`
/// pattern in `api/events.rs`. `limit` is clamped here so a caller-supplied
/// value never reaches SQL unclamped.
///
/// `resume` is the position decoded from a continuation token, never a
/// caller-typed cursor: the token carries `created_at` verbatim as stored, so
/// the TEXT comparison in `list_tasks_keyset` always runs against a string the
/// server wrote. That is what keeps equivalent RFC3339 spellings (`Z` versus
/// `+00:00`, differing fractional widths) from silently skipping or repeating
/// same-timestamp rows.
pub(crate) async fn collect_visible_tasks(
    db: &crate::db::Db,
    status: Option<&str>,
    assignee_did: Option<&str>,
    limit: i64,
    resume: Option<&crate::api::task_cursor::TaskPosition>,
    caller: Option<&str>,
) -> crate::error::Result<VisibleTasks> {
    use crate::api::task_cursor::TaskPosition;

    let bounded_limit = limit.clamp(0, MAX_VISIBLE_TASKS) as usize;
    if bounded_limit == 0 {
        return Ok(VisibleTasks {
            tasks: Vec::new(),
            has_more: false,
            incomplete: false,
            next_position: None,
        });
    }
    let mut visible = Vec::with_capacity(bounded_limit);
    let mut examined: Option<TaskPosition> = resume.cloned();
    let mut scanned: i64 = 0;
    let mut stream_ended = false;

    while scanned < MAX_TASK_SCAN_CANDIDATES && visible.len() < bounded_limit {
        let batch_limit = MAX_VISIBLE_TASKS.min(MAX_TASK_SCAN_CANDIDATES - scanned);
        let batch = db
            .list_tasks_keyset(
                status,
                assignee_did,
                batch_limit,
                examined.as_ref().map(TaskPosition::as_pair),
            )
            .await?;
        if batch.is_empty() {
            stream_ended = true;
            break;
        }
        let batch_len = batch.len() as i64;

        let referenced: Vec<String> = batch
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

        let mut consumed = 0usize;
        for task in &batch {
            // Advance the examined position per row, not per batch: when the
            // page fills mid-batch the resume point is that row, so the next
            // request neither repeats nor skips its successors.
            scanned += 1;
            consumed += 1;
            examined = Some(TaskPosition::new(task.created_at.clone(), task.id.clone()));
            if task_visible(task, caller, &repos_by_id, &rules_by_repo) {
                visible.push(task.clone());
                if visible.len() == bounded_limit {
                    break;
                }
            }
        }

        // A short batch only ends the stream once every row in it has been
        // examined. Filling the page mid-batch leaves rows behind that the
        // next request must still see, so the position advances and `has_more`
        // is settled by the probe below rather than assumed false.
        if consumed == batch.len() && batch_len < batch_limit {
            stream_ended = true;
            break;
        }
    }

    // A full final batch is ambiguous: more rows may exist, or the stream may
    // have ended on an exact multiple of the batch size. One probe row past
    // the last examined candidate settles it, so `has_more` never advertises a
    // page that turns out to be empty.
    let has_more = if stream_ended {
        false
    } else {
        !db.list_tasks_keyset(
            status,
            assignee_did,
            1,
            examined.as_ref().map(TaskPosition::as_pair),
        )
        .await?
        .is_empty()
    };

    let incomplete = has_more && visible.len() < bounded_limit;

    Ok(VisibleTasks {
        tasks: visible,
        has_more,
        incomplete,
        next_position: if has_more { examined } else { None },
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

/// GET /api/v1/tasks
///
/// Open to anonymous callers, but every row is gated by `collect_visible_tasks`
/// (#268): an anonymous or unrelated caller only sees tasks against a repo they
/// can read, never another party's repo-less task or its `ucan_token`/`payload`.
///
/// Paging follows the module-level contract. `limit` is echoed back as the
/// value actually applied, so a caller asking for more than
/// `MAX_VISIBLE_TASKS` can see the clamp rather than mistaking a full page for
/// the whole answer.
pub async fn list_tasks(
    State(state): State<AppState>,
    Query(q): Query<ListTasksQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> crate::error::Result<Json<Value>> {
    use crate::api::task_cursor::{self, TaskFilter};

    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let filter = TaskFilter {
        status: q.status.as_deref(),
        assignee_did: q.assignee_did.as_deref(),
    };
    let resume = q
        .cursor
        .as_deref()
        .map(|token| task_cursor::decode(&state.task_cursor_key, filter, caller, token))
        .transpose()?;
    let result = collect_visible_tasks(
        &state.db,
        q.status.as_deref(),
        q.assignee_did.as_deref(),
        q.limit,
        resume.as_ref(),
        caller,
    )
    .await?;
    let next_cursor = result
        .next_position
        .as_ref()
        .map(|pos| task_cursor::encode(&state.task_cursor_key, filter, caller, pos));
    let items: Vec<Value> = result.tasks.iter().map(task_to_read_json).collect();
    Ok(Json(json!({
        "tasks": items,
        "count": items.len(),
        "limit": q.limit.clamp(0, MAX_VISIBLE_TASKS),
        "has_more": result.has_more,
        "incomplete": result.incomplete,
        "next_cursor": next_cursor,
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

    /// #327 review: a visible row behind a denied window longer than the scan
    /// budget was permanently unreachable. The only cursor a caller could hold
    /// named the last row they *saw*, so every retry rescanned the same denied
    /// window and returned `{ tasks: [], incomplete: true }` forever.
    ///
    /// The server-issued token names the last row *examined*, so each request
    /// advances a full scan budget. This walks the whole recovery path using
    /// nothing but cursors the server handed back, and asserts the denied rows
    /// never appear in any response.
    #[sqlx::test]
    async fn denied_window_longer_than_scan_budget_is_pageable_to_the_end(pool: PgPool) {
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

        // Two and a half scan budgets' worth of rows an anonymous caller may
        // not read, so recovery provably takes more than one continuation.
        let denied = MAX_TASK_SCAN_CANDIDATES * 2 + MAX_TASK_SCAN_CANDIDATES / 2;
        for i in 0..denied {
            let mut hidden = task(&format!("hidden-{i:05}"), None, DELEGATOR);
            hidden.created_at = "2026-01-02T00:00:00Z".into();
            hidden.updated_at = hidden.created_at.clone();
            state.db.create_task(&hidden).await.unwrap();
        }

        let mut visible_older = task("past-ceiling", Some("public-repo"), DELEGATOR);
        visible_older.created_at = "2026-01-01T00:00:00Z".into();
        visible_older.updated_at = visible_older.created_at.clone();
        state.db.create_task(&visible_older).await.unwrap();

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut requests = 0;
        loop {
            requests += 1;
            assert!(requests <= 10, "recovery must terminate, not spin");
            let uri = match &cursor {
                Some(c) => format!("/api/v1/tasks?limit=1&cursor={}", c),
                None => "/api/v1/tasks?limit=1".to_string(),
            };
            let resp = list_router(state.clone())
                .oneshot(anon_get(&uri))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_json(resp).await;
            assert!(
                !body.to_string().contains("hidden-"),
                "no response may disclose a denied row's id: {body}"
            );
            for t in body["tasks"].as_array().unwrap() {
                seen.push(t["id"].as_str().unwrap().to_string());
            }
            // A short page mid-stream is the scan wall, and must say so.
            if body["has_more"].as_bool().unwrap() && body["tasks"].as_array().unwrap().is_empty() {
                assert_eq!(
                    body["incomplete"], true,
                    "an empty page with more rows behind it is a paused scan, not an end: {body}"
                );
            }
            match body["next_cursor"].as_str() {
                Some(c) => {
                    assert_eq!(body["has_more"], true);
                    cursor = Some(c.to_string());
                }
                None => {
                    assert_eq!(body["has_more"], false);
                    assert_eq!(
                        body["incomplete"], false,
                        "a terminal page is complete, not incomplete: {body}"
                    );
                    break;
                }
            }
        }

        assert_eq!(
            seen,
            vec!["newer-visible".to_string(), "past-ceiling".to_string()],
            "both visible rows must be reachable using only server-issued cursors"
        );
        assert!(
            requests > 2,
            "the denied window spans multiple scan budgets, so recovery must \
             take more than one continuation (took {requests})"
        );
    }

    /// The raw `after_*`/`cursor_*` pairs are gone (#327 review): there is one
    /// ordering domain, and it is the one the server writes. An unknown query
    /// parameter must be ignored rather than silently paging, so a client
    /// still sending the old pair gets page one, not a skipped window.
    #[sqlx::test]
    async fn removed_raw_cursor_params_do_not_page(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        for (id, ts) in [
            ("t-newer", "2026-01-03T00:00:00Z"),
            ("t-older", "2026-01-01T00:00:00Z"),
        ] {
            let mut t = task(id, Some("public-repo"), DELEGATOR);
            t.created_at = ts.into();
            t.updated_at = t.created_at.clone();
            state.db.create_task(&t).await.unwrap();
        }

        for uri in [
            "/api/v1/tasks?after_created_at=2026-01-03T00:00:00Z&after_id=t-newer",
            "/api/v1/tasks?cursor_created_at=2026-01-03T00:00:00Z&cursor_id=t-newer",
            "/api/v1/tasks?after_id=t-newer",
        ] {
            let resp = list_router(state.clone())
                .oneshot(anon_get(uri))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            let body = body_json(resp).await;
            assert_eq!(
                body["count"], 2,
                "{uri}: a removed cursor param must not page, it must be inert"
            );
        }
    }

    /// Every way a token can fail must be one indistinguishable 400, so a
    /// caller cannot use cursor validation as an oracle.
    #[sqlx::test]
    async fn list_tasks_rejects_unusable_cursors(pool: PgPool) {
        use crate::api::task_cursor::{self, TaskCursorKey, TaskFilter, TaskPosition};

        let state = test_state(pool).await;
        let position = TaskPosition::new("2026-01-03T00:00:00Z", "some-task");
        let unfiltered = TaskFilter {
            status: None,
            assignee_did: None,
        };

        let forged = task_cursor::encode(
            &TaskCursorKey::derive(&[9u8; 32]),
            unfiltered,
            None,
            &position,
        );
        let wrong_filter = task_cursor::encode(
            &state.task_cursor_key,
            TaskFilter {
                status: Some("pending"),
                assignee_did: None,
            },
            None,
            &position,
        );

        for (label, uri) in [
            ("garbage", "/api/v1/tasks?cursor=not-a-cursor".to_string()),
            (
                "forged by another node's key",
                format!("/api/v1/tasks?cursor={forged}"),
            ),
            (
                "issued for a different filter",
                format!("/api/v1/tasks?cursor={wrong_filter}"),
            ),
        ] {
            let resp = list_router(state.clone())
                .oneshot(anon_get(&uri))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{label}");
            let body = body_json(resp).await;
            assert_eq!(
                body["message"], "invalid or expired cursor",
                "{label}: every rejection must render the same message"
            );
        }

        // The same token against the filter it was issued for is accepted, so
        // the rejections above are the binding and not a blanket refusal.
        let resp = list_router(state.clone())
            .oneshot(anon_get(&format!(
                "/api/v1/tasks?status=pending&cursor={wrong_filter}"
            )))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The per-IP brake on the task read routes is WIRED, not a silent no-op:
    /// `rate_limit_by_ip` without its `IpRateLimiter` extension does nothing,
    /// so this drives the production router with a tight bucket and asserts a
    /// 429. Both routes are anon-reachable and run the #268 visibility gate (a
    /// task lookup plus deduped-repo and visibility-rule queries) before the
    /// opaque 404, so an unauthenticated prober costs the node work per request
    /// whether the id exists or not (#327 review).
    /// MUTATION (RED): drop the `axum::Extension(task_read_limiter)` layer in
    /// `server.rs` and the probes below reach the handler (200/404) instead.
    #[sqlx::test]
    async fn task_read_routes_ip_rate_limit_is_attached(pool: PgPool) {
        use std::net::SocketAddr;

        let mut state = test_state(pool).await;
        // Two slots: one known-id probe and one random-id probe pass, the third
        // request from that IP is braked whichever route it targets.
        state.task_read_rate_limiter =
            crate::rate_limit::RateLimiter::new(2, std::time::Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let probe = |peer: SocketAddr, uri: &str| {
            let mut req = anon_get(uri);
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
            req
        };
        let peer: SocketAddr = "203.0.113.42:5000".parse().unwrap();

        // A known id and a random one cost the same work and debit the same
        // bucket: the gate runs before the response can distinguish them.
        for uri in ["/api/v1/tasks/t1", "/api/v1/tasks/does-not-exist"] {
            let resp = router.clone().oneshot(probe(peer, uri)).await.unwrap();
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "{uri}: the first probes from an IP must pass the brake"
            );
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{uri}: an anonymous probe is an opaque 404 either way"
            );
        }

        let resp = router
            .clone()
            .oneshot(probe(peer, "/api/v1/tasks"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "an exhausted per-IP bucket must brake the list route too — the \
             IpRateLimiter extension must be attached to task_read_routes"
        );

        let other: SocketAddr = "203.0.113.43:5000".parse().unwrap();
        let resp = router
            .oneshot(probe(other, "/api/v1/tasks/t1"))
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a different IP must not be braked by another IP's exhausted bucket"
        );
    }

    /// The GraphQL task resolvers reach the SAME `collect_visible_tasks` /
    /// `get_visible_task` gate as the REST read routes, so they must carry the
    /// same per-IP brake — otherwise `task_read_routes` is a fence with an open
    /// gate beside it and a prober just asks over /graphql instead (#327
    /// review). The brake rides as request data rather than a router layer
    /// because /graphql is one endpoint for every operation; see
    /// `rate_limit::TaskReadBrake`.
    /// MUTATION (RED): drop the `TaskReadBrake` data from `graphql_handler`, or
    /// the `task_read_brake` call from either resolver, and the exhausted-bucket
    /// probes below answer normally instead of with the brake message.
    #[sqlx::test]
    async fn graphql_task_queries_share_the_task_read_ip_brake(pool: PgPool) {
        use std::net::SocketAddr;

        let mut state = test_state(pool).await;
        // Two slots, so the third task field from this IP is braked.
        state.task_read_rate_limiter =
            crate::rate_limit::RateLimiter::new(2, std::time::Duration::from_secs(3600));
        state.push_limiter_trust = crate::rate_limit::TrustedProxy::None;
        state
            .db
            .create_task(&task("t1", None, DELEGATOR))
            .await
            .unwrap();

        let router = crate::server::build_router(state);
        let peer: SocketAddr = "198.51.100.7:5000".parse().unwrap();
        let query = |peer: SocketAddr, q: &str| {
            let mut req = Request::builder()
                .method(Method::POST)
                .uri("/graphql")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "query": q }).to_string()))
                .unwrap();
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
            req
        };
        let run = |router: Router, peer: SocketAddr, q: &'static str| async move {
            let resp = router.oneshot(query(peer, q)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "GraphQL answers 200: {q}");
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        let braked = |body: &serde_json::Value| {
            body["errors"].as_array().is_some_and(|errs| {
                errs.iter()
                    .any(|e| e["message"].as_str() == Some(crate::rate_limit::RATE_LIMIT_MESSAGE))
            })
        };

        // Anonymous list, then anonymous single-id lookup: both run the gate,
        // both spend a slot.
        for q in ["{ tasks { items { id } } }", "{ task(id: \"t1\") { id } }"] {
            let body = run(router.clone(), peer, q).await;
            // Asserting the whole `errors` key is absent, not merely that the
            // brake message is missing: a query that failed for some other
            // reason would still spend its slot and leave this test vacuous.
            assert!(
                body.get("errors").is_none(),
                "{q}: the first probes must pass the brake and resolve, got {body}"
            );
        }

        let body = run(router.clone(), peer, "{ tasks { items { id } } }").await;
        assert!(
            braked(&body),
            "an exhausted per-IP bucket must brake the GraphQL task query too, \
             got {body}"
        );
        assert!(
            body["data"]["tasks"].is_null(),
            "a braked field must resolve to null, not answer with rows: {body}"
        );

        // The bucket is the one `task_read_routes` debits, not a second budget:
        // the REST route is already exhausted by the GraphQL traffic above.
        let mut rest = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/tasks")
            .body(Body::empty())
            .unwrap();
        rest.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let resp = router.clone().oneshot(rest).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "GraphQL and REST task reads must share one per-IP bucket"
        );

        let other: SocketAddr = "198.51.100.8:5000".parse().unwrap();
        let body = run(router, other, "{ tasks { items { id } } }").await;
        assert!(
            !braked(&body),
            "a different IP must not be braked by another IP's exhausted bucket"
        );
    }

    /// #327 review: a cursor records how far a scan got under *one* caller's
    /// visibility, so presenting it as a different caller must fail rather
    /// than resume. Here an anonymous page stops at a public task, having
    /// already examined and denied the delegator's private one that sorts
    /// ahead of it. Resuming that token as the delegator would start their
    /// scan past their own task and drop it from the answer with nothing to
    /// signal the loss.
    #[sqlx::test]
    async fn a_cursor_minted_anonymously_cannot_resume_an_authenticated_scan(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        // `created_at DESC, id DESC`: the delegator-only task sorts first, so
        // it sits *before* the position the anonymous page stops at.
        for (id, repo_id, ts) in [
            ("priv-1", None, "2026-01-03T00:00:00Z"),
            ("pub-2", Some("public-repo"), "2026-01-02T00:00:00Z"),
            ("pub-1", Some("public-repo"), "2026-01-01T00:00:00Z"),
        ] {
            let mut t = task(id, repo_id, DELEGATOR);
            t.created_at = ts.to_string();
            t.updated_at = ts.to_string();
            state.db.create_task(&t).await.unwrap();
        }

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks?limit=1"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["tasks"][0]["id"], "pub-2");
        assert_eq!(body["has_more"], true);
        let anon_cursor = body["next_cursor"]
            .as_str()
            .expect("a filled page hands back a continuation")
            .to_string();

        let resp = list_router(state.clone())
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::GET,
                &format!("/api/v1/tasks?limit=50&cursor={anon_cursor}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a cursor bound to anonymous must not resume the delegator's scan"
        );
        let body = body_json(resp).await;
        assert_eq!(body["message"], "invalid or expired cursor");

        // Load-bearing: the delegator really can read `priv-1`, so accepting
        // that cursor would have silently dropped a row they are entitled to
        // see rather than merely re-ordering their page.
        let resp = list_router(state)
            .oneshot(signed_request_as(
                DELEGATOR,
                Method::GET,
                "/api/v1/tasks?limit=50",
                Body::empty(),
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        let ids: Vec<&str> = body["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["priv-1", "pub-2", "pub-1"]);
    }

    /// #327 review: `--limit 500` printed a successful but silently truncated
    /// 200-row result. The page now fills, says so, and hands back a cursor
    /// that reaches the rest.
    #[sqlx::test]
    async fn full_page_advertises_has_more_and_enumerates_past_the_row_cap(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        let total = (MAX_VISIBLE_TASKS + 50) as usize;
        for i in 0..total {
            let mut t = task(&format!("visible-{i:04}"), Some("public-repo"), DELEGATOR);
            // Descending ids so `created_at DESC, id DESC` yields visible-0249
            // first: order is asserted below, not assumed.
            t.created_at = format!("2026-01-01T00:00:{:02}Z", i % 60);
            t.updated_at = t.created_at.clone();
            state.db.create_task(&t).await.unwrap();
        }

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks?limit=500"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(
            body["count"], MAX_VISIBLE_TASKS,
            "a request above the row cap is clamped, not served in full"
        );
        assert_eq!(
            body["limit"], MAX_VISIBLE_TASKS,
            "the response must state the effective limit it applied"
        );
        assert_eq!(
            body["has_more"], true,
            "a filled page with rows behind it must advertise a continuation"
        );
        assert_eq!(
            body["incomplete"], false,
            "a filled page is not an interrupted scan"
        );

        let mut seen: Vec<String> = body["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap().to_string())
            .collect();
        let cursor = body["next_cursor"].as_str().unwrap().to_string();

        let resp = list_router(state)
            .oneshot(anon_get(&format!(
                "/api/v1/tasks?limit=500&cursor={cursor}"
            )))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["count"], 50);
        assert_eq!(body["has_more"], false);
        assert!(body["next_cursor"].is_null());
        seen.extend(
            body["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["id"].as_str().unwrap().to_string()),
        );

        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            total,
            "paging must enumerate every visible row exactly once, no skips or repeats"
        );
    }

    /// The minimal shape of a mid-batch page fill: fewer rows than one SQL
    /// batch, and a limit smaller than that. A short batch means no rows exist
    /// *past* it, not that every row *in* it was examined, so treating the two
    /// as the same drops every row after the one that filled the page.
    #[sqlx::test]
    async fn short_batch_that_fills_the_page_still_offers_a_continuation(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        for (id, ts) in [
            ("t-3", "2026-01-03T00:00:00Z"),
            ("t-2", "2026-01-02T00:00:00Z"),
            ("t-1", "2026-01-01T00:00:00Z"),
        ] {
            let mut t = task(id, Some("public-repo"), DELEGATOR);
            t.created_at = ts.into();
            t.updated_at = t.created_at.clone();
            state.db.create_task(&t).await.unwrap();
        }

        let resp = list_router(state.clone())
            .oneshot(anon_get("/api/v1/tasks?limit=1"))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(body["tasks"][0]["id"], "t-3");
        assert_eq!(
            body["has_more"], true,
            "two rows remain in the same batch, so this is not the end of the stream: {body}"
        );
        let cursor = body["next_cursor"]
            .as_str()
            .expect("a continuation must be offered")
            .to_string();

        let resp = list_router(state)
            .oneshot(anon_get(&format!("/api/v1/tasks?limit=1&cursor={cursor}")))
            .await
            .unwrap();
        let body = body_json(resp).await;
        assert_eq!(
            body["tasks"][0]["id"], "t-2",
            "the continuation must resume inside the batch, not past it: {body}"
        );
    }

    /// Rows sharing a timestamp are the case a mis-ordered cursor skips or
    /// repeats. The token carries the stored `created_at` verbatim, so the
    /// `(created_at, id)` tie-break holds across a page boundary that lands
    /// inside a group of equal timestamps.
    #[sqlx::test]
    async fn paging_across_equal_timestamps_neither_skips_nor_repeats(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();
        // Deliberately mixed spellings of the *same* instant, as a peer or an
        // older writer could have stored them.
        for (i, ts) in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00.000+00:00",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00+00:00",
        ]
        .iter()
        .enumerate()
        {
            let mut t = task(&format!("tie-{i}"), Some("public-repo"), DELEGATOR);
            t.created_at = (*ts).into();
            t.updated_at = t.created_at.clone();
            state.db.create_task(&t).await.unwrap();
        }

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let uri = match &cursor {
                Some(c) => format!("/api/v1/tasks?limit=2&cursor={}", c),
                None => "/api/v1/tasks?limit=2".to_string(),
            };
            let resp = list_router(state.clone())
                .oneshot(anon_get(&uri))
                .await
                .unwrap();
            let body = body_json(resp).await;
            for t in body["tasks"].as_array().unwrap() {
                seen.push(t["id"].as_str().unwrap().to_string());
            }
            match body["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break,
            }
        }

        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            seen.len(),
            5,
            "five rows sharing an instant must be returned exactly once each: {seen:?}"
        );
        assert_eq!(unique.len(), 5, "no row may repeat across pages: {seen:?}");
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

    /// Equal-timestamp siblings are where a cursor with the wrong ordering
    /// domain skips or repeats a row. The token carries the served
    /// `created_at` byte-for-byte, so the `(created_at, id)` tie-break
    /// advances one row at a time through a fractional-zero sibling group.
    #[sqlx::test]
    async fn keyset_advances_across_trailing_zero_fraction_timestamps(pool: PgPool) {
        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();

        let ts_sibling = "2026-06-01T00:00:00.000000000+00:00";
        for (id, ts) in [
            ("task-2", ts_sibling),
            ("task-1", ts_sibling),
            ("task-0", "2026-05-01T00:00:00.000000000+00:00"),
        ] {
            let mut t = task(id, Some("public-repo"), DELEGATOR);
            t.created_at = ts.into();
            t.updated_at = t.created_at.clone();
            state.db.create_task(&t).await.unwrap();
        }

        let mut cursor: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..5 {
            let uri = match &cursor {
                Some(c) => format!("/api/v1/tasks?limit=1&cursor={c}"),
                None => "/api/v1/tasks?limit=1".to_string(),
            };
            let resp = list_router(state.clone())
                .oneshot(anon_get(&uri))
                .await
                .unwrap();
            let body = body_json(resp).await;
            for t in body["tasks"].as_array().unwrap() {
                // The response must echo the stored spelling verbatim; that is
                // the string the token compares against.
                if t["id"] != "task-0" {
                    assert_eq!(t["created_at"], ts_sibling);
                }
                seen.push(t["id"].as_str().unwrap().to_string());
            }
            match body["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break,
            }
        }

        assert_eq!(
            seen,
            vec![
                "task-2".to_string(),
                "task-1".to_string(),
                "task-0".to_string()
            ],
            "paging must advance one row at a time through equal timestamps"
        );
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

    /// `create_task` stores the supplied assignee form unchanged. Claim binds
    /// the authenticated DID (typically `did:key:...`) and list filters pass
    /// the query string through. Both SQL comparisons must collapse the
    /// did:key short form, or a designated assignee stored as a bare key
    /// cannot claim, and a `?assignee_did=` filter in the other form drops
    /// the row. A `did:web:` assignee sharing the same residual must stay
    /// unmatched.
    #[sqlx::test]
    async fn claim_and_list_match_bare_and_did_key_assignee_forms(pool: PgPool) {
        let bare_assignee = crate::db::normalize_owner_key(ASSIGNEE);
        assert_ne!(
            bare_assignee, ASSIGNEE,
            "test setup requires ASSIGNEE to be the full did:key form"
        );

        let state = test_state(pool).await;
        state
            .db
            .create_repo(&repo("public-repo", DELEGATOR, "public", true))
            .await
            .unwrap();

        let mut bare = task("bare-assignee", Some("public-repo"), DELEGATOR);
        bare.assignee_did = Some(bare_assignee.into());
        state.db.create_task(&bare).await.unwrap();

        let mut full = task("full-assignee", Some("public-repo"), DELEGATOR);
        full.assignee_did = Some(ASSIGNEE.into());
        state.db.create_task(&full).await.unwrap();

        let mut web = task("web-assignee", Some("public-repo"), DELEGATOR);
        web.assignee_did = Some(format!("did:web:{bare_assignee}"));
        state.db.create_task(&web).await.unwrap();

        let listed_ids = |body: &serde_json::Value| -> Vec<String> {
            body["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|task| task["id"].as_str().unwrap().to_string())
                .collect()
        };

        let full_filter = list_router(state.clone())
            .oneshot(anon_get(&format!("/api/v1/tasks?assignee_did={ASSIGNEE}")))
            .await
            .unwrap();
        assert_eq!(full_filter.status(), StatusCode::OK);
        let full_ids = listed_ids(&body_json(full_filter).await);
        assert!(
            full_ids.contains(&"bare-assignee".to_string()),
            "a did:key: filter must match a bare stored assignee"
        );
        assert!(full_ids.contains(&"full-assignee".to_string()));
        assert!(
            !full_ids.contains(&"web-assignee".to_string()),
            "did:key matching must not collapse a did:web assignee"
        );

        let bare_filter = list_router(state.clone())
            .oneshot(anon_get(&format!(
                "/api/v1/tasks?assignee_did={bare_assignee}"
            )))
            .await
            .unwrap();
        assert_eq!(bare_filter.status(), StatusCode::OK);
        let bare_ids = listed_ids(&body_json(bare_filter).await);
        assert!(
            bare_ids.contains(&"full-assignee".to_string()),
            "a bare filter must match a did:key stored assignee"
        );
        assert!(bare_ids.contains(&"bare-assignee".to_string()));
        assert!(
            !bare_ids.contains(&"web-assignee".to_string()),
            "did:key matching must not collapse a did:web assignee"
        );

        let claim_full = full_task_router(state.clone())
            .oneshot(signed_request_as(
                ASSIGNEE,
                Method::POST,
                "/api/v1/tasks/bare-assignee/claim",
                Body::from(format!(r#"{{"assignee_did":"{ASSIGNEE}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            claim_full.status(),
            StatusCode::OK,
            "claim as did:key: form must match a bare stored assignee"
        );

        let claim_bare = full_task_router(state)
            .oneshot(signed_request_as(
                bare_assignee,
                Method::POST,
                "/api/v1/tasks/full-assignee/claim",
                Body::from(format!(r#"{{"assignee_did":"{bare_assignee}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            claim_bare.status(),
            StatusCode::OK,
            "claim as a bare key must match a did:key stored assignee"
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
