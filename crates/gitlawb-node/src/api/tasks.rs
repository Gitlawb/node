//! REST handlers for agent task delegation API.
//!
//! Routes (all under /api/v1/tasks):
//!   POST   /api/v1/tasks                    — create task
//!   GET    /api/v1/tasks                    — list tasks
//!   GET    /api/v1/tasks/{id}               — get task
//!   POST   /api/v1/tasks/{id}/claim         — claim task
//!   POST   /api/v1/tasks/{id}/complete      — complete task
//!   POST   /api/v1/tasks/{id}/fail          — fail task

use std::collections::HashMap;

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
use crate::state::{AppState, TaskEventBroadcast};

/// 403 in this module's error shape (`(StatusCode, Json<Value>)`, not `AppError`).
fn forbidden(msg: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": "forbidden", "message": msg })),
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
    let Some(record) = task.repo_id.as_deref().and_then(|id| repos_by_id.get(id)) else {
        return false;
    };
    let rules = rules_by_repo
        .get(&record.id)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    crate::visibility::listable_at_root(rules, record.is_public, &record.owner_did, caller)
}

/// Collect up to `limit` tasks visible to `caller`, applying the same gate the
/// GraphQL `tasks` query uses (`collect_visible_tasks` is called from both) so
/// the two surfaces cannot drift, matching the `collect_visible_ref_updates`
/// pattern in `api/events.rs`. `limit` is clamped here so a caller-supplied
/// value never reaches SQL unclamped.
///
/// Unlike the ref-updates feed, this does not page past invisible rows: it
/// fetches one bounded page and filters it, so a request whose newest
/// `MAX_VISIBLE_TASKS` rows are mostly invisible to the caller can return
/// fewer rows than are truly visible further back. Accepted here because,
/// unlike the cross-tenant ref-updates feed, task queries are already scoped
/// by `status`/`assignee_did` up front, which keeps the visible/invisible mix
/// per query far narrower in practice.
pub(crate) async fn collect_visible_tasks(
    db: &crate::db::Db,
    status: Option<&str>,
    assignee_did: Option<&str>,
    limit: i64,
    caller: Option<&str>,
) -> crate::error::Result<Vec<AgentTask>> {
    let bounded_limit = limit.clamp(0, MAX_VISIBLE_TASKS);
    if bounded_limit == 0 {
        return Ok(Vec::new());
    }
    let tasks = db.list_tasks(status, assignee_did, bounded_limit).await?;
    if tasks.is_empty() {
        return Ok(tasks);
    }
    let repos = db.list_all_repos_deduped().await?;
    let repos_by_id: HashMap<String, RepoRecord> =
        repos.into_iter().map(|r| (r.id.clone(), r)).collect();
    let ids: Vec<String> = repos_by_id.keys().cloned().collect();
    let rules_by_repo = db.list_visibility_rules_for_repos(&ids).await?;
    Ok(tasks
        .into_iter()
        .filter(|t| task_visible(t, caller, &repos_by_id, &rules_by_repo))
        .collect())
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
            let repos = db.list_all_repos_deduped().await?;
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
pub async fn list_tasks(
    State(state): State<AppState>,
    Query(q): Query<ListTasksQuery>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    let tasks = collect_visible_tasks(
        &state.db,
        q.status.as_deref(),
        q.assignee_did.as_deref(),
        q.limit,
        caller,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
    })?;
    let items: Vec<Value> = tasks.iter().map(task_to_read_json).collect();
    Ok(Json(json!({ "tasks": items, "count": items.len() })))
}

/// GET /api/v1/tasks/{id}
///
/// Gated the same way as `list_tasks` (#268): a task the caller may not see
/// 404s, indistinguishable from a task that doesn't exist.
pub async fn get_task(
    State(state): State<AppState>,
    Path(id): Path<String>,
    auth: Option<Extension<AuthenticatedDid>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let caller = auth.as_ref().map(|e| e.0 .0.as_str());
    match get_visible_task(&state.db, &id, caller).await {
        Ok(Some(t)) => Ok(Json(task_to_read_json(&t))),
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

        let resp = list_router(state)
            .oneshot(anon_get("/api/v1/tasks/t1"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "anon get_task on an invisible task must 404, not leak it"
        );
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
}
