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
        // #496: same write gate as the REST handler — a repo_id naming a
        // hosted, non-quarantined repo admits tasks only from its owner, so a
        // stranger cannot file under a foreign repo id. An id naming no hosted
        // repo (unknown, or quarantined — hidden as if it did not exist) is
        // stored verbatim as an opaque label; the gate does not bind an
        // unresolved id to a repo. Task reads are caller-independent on this
        // base (the tasks resolver is not repo-scoped), before and after this
        // change. As in tasks.rs, the success-vs-denial split between a hosted
        // repo id and an unknown one is itself a one-bit oracle — a stranger
        // holding a private repo's id learns it is hosted here — but denying
        // foreign repos requires drawing exactly that line.
        if let Some(repo_id) = input.repo_id.as_deref() {
            let record = db
                .get_repo_by_id(repo_id)
                .await
                .map_err(crate::graphql::graphql_db_err)?;
            if let Some(record) = record {
                let quarantined = db
                    .is_repo_quarantined(&record.id)
                    .await
                    .map_err(crate::graphql::graphql_db_err)?;
                if !quarantined {
                    crate::api::require_repo_owner(&record, caller)
                        .map_err(crate::graphql::graphql_app_err)?;
                }
            }
        }
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
        // Return the stored row, not the pre-insert input: create_task
        // normalizes the assignee (whitespace-only becomes NULL/open), and a
        // response that shows the raw input lies about the reservation.
        let stored = db
            .create_task(&task)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        Ok(AgentTaskType::from(stored))
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
        // Report the stored assignee form like REST, so subscribers see the
        // same identity whichever API surface ran the transition.
        let by_did = task
            .assignee_did
            .as_deref()
            .map(crate::db::trim_assignee_did)
            .unwrap_or(assignee_did.as_str())
            .to_string();
        let _ = tx.send(TaskEventBroadcast {
            task_id: id,
            old_status: "pending".to_string(),
            new_status: "claimed".to_string(),
            by_did,
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
        if !crate::api::did_matches(
            caller,
            crate::db::trim_assignee_did(existing.assignee_did.as_deref().unwrap_or_default()),
        ) {
            return Err(async_graphql::Error::new(
                "only the task assignee can complete it",
            ));
        }
        let task = db
            .finish_task(&id, "completed", input.result.as_deref(), caller)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        let by_did = task
            .assignee_did
            .as_deref()
            .map(crate::db::trim_assignee_did)
            .unwrap_or(by_did.as_str())
            .to_string();
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
        if !crate::api::did_matches(
            caller,
            crate::db::trim_assignee_did(existing.assignee_did.as_deref().unwrap_or_default()),
        ) {
            return Err(async_graphql::Error::new(
                "only the task assignee can fail it",
            ));
        }
        let reason = input.reason.unwrap_or_default();
        let task = db
            .finish_task(&id, "failed", Some(&reason), caller)
            .await
            .map_err(crate::graphql::graphql_db_err)?;
        let by_did = task
            .assignee_did
            .as_deref()
            .map(crate::db::trim_assignee_did)
            .unwrap_or(by_did.as_str())
            .to_string();
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

    /// The `id` scalar returned by a successful `createTask` mutation.
    fn created_id(resp: &Response) -> String {
        assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
        let async_graphql::Value::Object(obj) = &resp.data else {
            panic!("data not an object: {:?}", resp.data);
        };
        let async_graphql::Value::Object(task) = obj.get("createTask").expect("createTask key")
        else {
            panic!("createTask not an object");
        };
        let async_graphql::Value::String(id) = task.get("id").expect("id key") else {
            panic!("id not a string");
        };
        id.clone()
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

    /// #496 (GraphQL): createTask applies the same repo-ownership gate as the
    /// REST handler — a stranger naming a hosted repo is rejected without
    /// persisting anything, while the owner files. The quarantined and
    /// unknown-id arms are pinned too, including that each accepted write
    /// stores the supplied id verbatim, so this copy of the gate cannot regress
    /// silently.
    #[sqlx::test]
    async fn create_task_rejects_foreign_repo_id(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let owner = "did:key:zGQLTASKOWNERAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let stranger = "did:key:zGQLTASKSTRANGERBBBBBBBBBBBBBBBBBBBBBB";
        let now = chrono::Utc::now();
        let repo = crate::db::RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "gql-task-gate-repo".to_string(),
            owner_did: owner.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/gql-task-gate-repo".to_string(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&repo).await.expect("seed repo");
        let schema = state.graphql_schema.as_ref();

        let q = |actor: &str| {
            format!(
                r#"mutation {{ createTask(delegatorDid: "{actor}", input: {{ kind: "build", capability: "repo:write", repoId: "{}" }}) {{ id }} }}"#,
                repo.id
            )
        };

        // Stranger signs as themselves (so the signer binding passes) but
        // names the victim's repo → rejected by the ownership gate, leaking
        // nothing about the repo.
        let resp = schema
            .execute(Request::new(q(stranger)).data(AuthenticatedDid(stranger.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains(crate::api::REPO_OWNER_ONLY_MESSAGE),
            "a non-owner must not file under a foreign repo id (shared denial text): {errs}"
        );

        // The denial must not persist: no task row may carry the victim's
        // repo id afterwards.
        let stored = state
            .db
            .list_tasks(None, None, 50)
            .await
            .expect("list tasks");
        assert!(
            stored
                .iter()
                .all(|t| t.repo_id.as_deref() != Some(repo.id.as_str())),
            "a denied write must not leave a task under the foreign repo id"
        );

        // The owner files under their own repo id.
        let resp = schema
            .execute(Request::new(q(owner)).data(AuthenticatedDid(owner.into())))
            .await;
        assert!(
            errors(&resp).is_empty(),
            "the owner should file against their repo: {}",
            errors(&resp)
        );

        // Unknown repo ids stay accepted as opaque labels.
        let q_unknown = format!(
            r#"mutation {{ createTask(delegatorDid: "{stranger}", input: {{ kind: "build", capability: "repo:write", repoId: "no-such-repo-id" }}) {{ id }} }}"#
        );
        let resp = schema
            .execute(Request::new(q_unknown).data(AuthenticatedDid(stranger.into())))
            .await;
        assert!(
            errors(&resp).is_empty(),
            "an id naming no hosted repo stays an opaque label: {}",
            errors(&resp)
        );
        // Read back the row: the unresolved id must be stored verbatim, not
        // dropped or rewritten to a repo it never named.
        let stored = state
            .db
            .get_task(&created_id(&resp))
            .await
            .expect("get task")
            .expect("task must be stored");
        assert_eq!(
            stored.repo_id.as_deref(),
            Some("no-such-repo-id"),
            "an unresolved id must be stored verbatim as a label"
        );

        // A quarantined repo id is treated as unknown (accepted, never a 403
        // that would confirm the id names a real repo). This pins the
        // `!quarantined` arm on this copy of the gate.
        state
            .db
            .set_repo_quarantine(&repo.id, true)
            .await
            .expect("quarantine");
        let resp = schema
            .execute(Request::new(q(stranger)).data(AuthenticatedDid(stranger.into())))
            .await;
        assert!(
            errors(&resp).is_empty(),
            "a quarantined repo id must not 403 (existence oracle): {}",
            errors(&resp)
        );
        // Read back the row: the quarantined id is stored verbatim as a label
        // too, so the accepted write is not silently dropped.
        let stored = state
            .db
            .get_task(&created_id(&resp))
            .await
            .expect("get task")
            .expect("task must be stored");
        assert_eq!(
            stored.repo_id.as_deref(),
            Some(repo.id.as_str()),
            "a quarantined id must be stored verbatim as a label"
        );
    }

    /// #496 (GraphQL): a repo-lookup fault in createTask's gate must stay
    /// opaque. Dropping a column `get_repo_by_id` selects faults that lookup;
    /// the resolver must return the fixed DB message and leak no schema text
    /// (#250), as `create_task_db_error_message_is_opaque` pins for the
    /// agent_tasks fault.
    #[sqlx::test]
    async fn create_task_gate_repo_lookup_fault_is_opaque(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let owner = "did:key:zGQLTASKFAULTOWNERAAAAAAAAAAAAAAAAAAAAAAAA";
        let now = chrono::Utc::now();
        let repo = crate::db::RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: "gql-task-gate-fault-repo".to_string(),
            owner_did: owner.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: "/tmp/gql-task-gate-fault-repo".to_string(),
            forked_from: None,
            machine_id: None,
        };
        state.db.create_repo(&repo).await.expect("seed repo");

        sqlx::query("ALTER TABLE repos DROP COLUMN machine_id")
            .execute(&pool)
            .await
            .expect("drop machine_id");

        let q = format!(
            r#"mutation {{ createTask(delegatorDid: "{owner}", input: {{ kind: "build", capability: "repo:write", repoId: "{}" }}) {{ id }} }}"#,
            repo.id
        );
        let resp = state
            .graphql_schema
            .execute(Request::new(&q).data(AuthenticatedDid(owner.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains(crate::graphql::GRAPHQL_DB_ERROR_MESSAGE),
            "gate sqlx fault must be opaque: {errs}"
        );
        assert!(
            !errs.contains("machine_id") && !errs.contains("column"),
            "schema text leaked through the gate: {errs}"
        );
    }

    /// Pre-assigned GraphQL claimTask must reject a stranger (no UCAN leak)
    /// and admit the reserved assignee.
    #[sqlx::test]
    async fn claim_task_honors_preassigned_assignee(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let reserved = "did:key:zGQLRESERVEDAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let thief = "did:key:zGQLTHIEFBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let now = chrono::Utc::now().to_rfc3339();
        let task = crate::db::AgentTask {
            id: "task-gql-reserved".into(),
            repo_id: None,
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: "did:key:zGQLDELEGATORCCCCCCCCCCCCCCCCCCCCCCCCCC".into(),
            assignee_did: Some(reserved.into()),
            capability: "repo:write".into(),
            ucan_token: Some("gql-ucan-secret".into()),
            payload: None,
            result: None,
            created_at: now.clone(),
            updated_at: now,
            deadline: None,
        };
        state.db.create_task(&task).await.expect("seed");
        let schema = state.graphql_schema.as_ref();

        let q = |actor: &str| {
            format!(
                r#"mutation {{ claimTask(id: "task-gql-reserved", assigneeDid: "{actor}") {{ id status ucanToken }} }}"#
            )
        };

        let resp = schema
            .execute(Request::new(q(thief)).data(AuthenticatedDid(thief.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.contains("reserved"),
            "stranger claim must surface reserved deny distinctly: {errs}"
        );
        assert!(
            !errs.contains("gql-ucan-secret"),
            "UCAN must not leak in GraphQL errors: {errs}"
        );
        if let Ok(data) = resp.data.into_json() {
            let s = data.to_string();
            assert!(
                !s.contains("gql-ucan-secret"),
                "UCAN must not leak in GraphQL data on failed claim: {s}"
            );
        }
        // Parity with REST: failed steal must leave the row untouched.
        let still = state
            .db
            .get_task("task-gql-reserved")
            .await
            .expect("get")
            .expect("task exists");
        assert_eq!(
            still.status, "pending",
            "status must stay pending after steal"
        );
        assert_eq!(
            still.assignee_did.as_deref(),
            Some(reserved),
            "assignee_did must stay reserved after steal"
        );

        let resp = schema
            .execute(Request::new(q(reserved)).data(AuthenticatedDid(reserved.into())))
            .await;
        assert!(
            errors(&resp).is_empty(),
            "reserved assignee must claim: {}",
            errors(&resp)
        );
        let data = resp.data.into_json().expect("json data");
        assert_eq!(data["claimTask"]["status"], "claimed");
        assert_eq!(data["claimTask"]["ucanToken"], "gql-ucan-secret");
    }

    /// create_task normalizes a whitespace-only assignee to NULL (open task),
    /// so the create response must show the stored row, not echo the input: a
    /// client trusting the echoed "reservation" would believe a claimable task
    /// is reserved. Before the fix the response was built from the pre-insert
    /// struct and returned the padded input verbatim.
    #[sqlx::test]
    async fn create_task_reports_stored_assignee_not_input(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let caller = "did:key:zGQLCREATORAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let schema = state.graphql_schema.as_ref();
        let q = format!(
            r#"mutation {{ createTask(delegatorDid: "{caller}", input: {{ kind: "build", capability: "repo:write", assigneeDid: "   " }}) {{ id assigneeDid }} }}"#
        );
        let resp = schema
            .execute(Request::new(q).data(AuthenticatedDid(caller.into())))
            .await;
        let data = resp.data.into_json().expect("json data");
        assert!(
            data["createTask"]["assigneeDid"].is_null(),
            "whitespace-only assigneeDid must come back null (stored shape): {data}"
        );
    }

    /// A task seeded with a whitespace-padded assignee must still be
    /// completable by that assignee over GraphQL: REST and Db::finish_task
    /// trim the stored value before comparing, and the GraphQL gate must do
    /// the same or padded reservations finish only through REST.
    #[sqlx::test]
    async fn graphql_finish_accepts_padded_stored_assignee(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let assignee = "did:key:zGQLPADDEDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let now = chrono::Utc::now().to_rfc3339();
        let task = crate::db::AgentTask {
            id: "task-gql-padded".into(),
            repo_id: None,
            kind: "build".into(),
            status: "pending".into(),
            delegator_did: "did:key:zGQLDELEGATORDDDDDDDDDDDDDDDDDDDDDDDDDD".into(),
            assignee_did: Some(format!("\t{assignee}\n")),
            capability: "repo:write".into(),
            ucan_token: None,
            payload: None,
            result: None,
            created_at: now.clone(),
            updated_at: now,
            deadline: None,
        };
        state.db.create_task(&task).await.expect("seed");
        let schema = state.graphql_schema.as_ref();

        let claim = format!(
            r#"mutation {{ claimTask(id: "task-gql-padded", assigneeDid: "{assignee}") {{ id status }} }}"#
        );
        let resp = schema
            .execute(Request::new(claim).data(AuthenticatedDid(assignee.into())))
            .await;
        assert!(
            errors(&resp).is_empty(),
            "reserved assignee must claim a padded reservation: {}",
            errors(&resp)
        );

        let finish = format!(
            r#"mutation {{ completeTask(id: "task-gql-padded", byDid: "{assignee}", input: {{}}) {{ id status }} }}"#
        );
        let resp = schema
            .execute(Request::new(finish).data(AuthenticatedDid(assignee.into())))
            .await;
        let errs = errors(&resp);
        assert!(
            errs.is_empty(),
            "assignee must complete a padded reservation: {errs}"
        );
        let data = resp.data.into_json().expect("json data");
        assert_eq!(data["completeTask"]["status"], "completed");
    }
}
