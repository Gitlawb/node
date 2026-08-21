//! `gl task` — agent task delegation commands.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct TaskArgs {
    #[command(subcommand)]
    pub cmd: TaskCmd,
}

#[derive(Subcommand)]
pub enum TaskCmd {
    /// Create a new agent task
    Create {
        /// Task kind (e.g. "code-review", "test-run", "deploy")
        kind: String,
        /// UCAN capability required (e.g. "git:push")
        #[arg(long, default_value = "agent:task")]
        capability: String,
        /// Optional repo ID to associate this task with
        #[arg(long)]
        repo_id: Option<String>,
        /// DID of the agent to assign this task to
        #[arg(long)]
        assignee_did: Option<String>,
        /// JSON payload for the task
        #[arg(long)]
        payload: Option<String>,
        /// UCAN token granting the capability
        #[arg(long)]
        ucan_token: Option<String>,
        /// ISO-8601 deadline for the task
        #[arg(long)]
        deadline: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List tasks on a node
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        assignee_did: Option<String>,
        /// Total tasks to return. Must be positive. Values above the node's
        /// 200-row page cap are gathered by following continuation tokens.
        #[arg(long, default_value = "50")]
        limit: i64,
        /// Resume from a previous run's `next_cursor`. Must be used with the
        /// same --status/--assignee-did filter that produced it.
        #[arg(long)]
        cursor: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// View a specific task
    View {
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Claim a pending task
    Claim {
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Mark a task as completed
    Complete {
        id: String,
        #[arg(long)]
        result: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Mark a task as failed
    Fail {
        id: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: TaskArgs) -> Result<()> {
    match args.cmd {
        TaskCmd::Create {
            kind,
            capability,
            repo_id,
            assignee_did,
            payload,
            ucan_token,
            deadline,
            node,
            dir,
        } => {
            cmd_create(
                kind,
                capability,
                repo_id,
                assignee_did,
                payload,
                ucan_token,
                deadline,
                node,
                dir,
            )
            .await
        }
        TaskCmd::List {
            status,
            assignee_did,
            limit,
            cursor,
            node,
            dir,
        } => cmd_list(status, assignee_did, limit, cursor, node, dir).await,
        TaskCmd::View { id, node, dir } => cmd_view(id, node, dir).await,
        TaskCmd::Claim { id, node, dir } => cmd_claim(id, node, dir).await,
        TaskCmd::Complete {
            id,
            result,
            node,
            dir,
        } => cmd_complete(id, result, node, dir).await,
        TaskCmd::Fail {
            id,
            reason,
            node,
            dir,
        } => cmd_fail(id, reason, node, dir).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_create(
    kind: String,
    capability: String,
    repo_id: Option<String>,
    assignee_did: Option<String>,
    payload: Option<String>,
    ucan_token: Option<String>,
    deadline: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let delegator_did = keypair.did().to_string();
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&json!({
        "kind": kind,
        "capability": capability,
        "repo_id": repo_id,
        "assignee_did": assignee_did,
        "payload": payload,
        "ucan_token": ucan_token,
        "deadline": deadline,
        "delegator_did": delegator_did,
    }))?;

    let resp: Value = client
        .post("/api/v1/tasks", &body)
        .await
        .context("failed to create task")?
        .error_for_status()
        .context("failed to create task")?
        .json()
        .await
        .context("invalid JSON response")?;
    print_json(&resp);
    Ok(())
}

/// Server-side ceiling on rows per response (`MAX_VISIBLE_TASKS` on the node).
/// A `--limit` above this needs more than one request, which is why the
/// clients follow `next_cursor` rather than printing a silently truncated page
/// (#327 review).
const SERVER_PAGE_CAP: i64 = 200;

/// Requests one `gl`/MCP list call may issue while following continuations.
/// The node examines at most 1,000 candidate rows per request, so a long
/// window of tasks the caller cannot read returns empty pages that still carry
/// a cursor. Without this cap a single `task list` against such a window would
/// walk the whole table one request at a time.
const MAX_TASK_PAGES: usize = 25;

/// Why page-following stopped before the requested limit was met.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TaskListStop {
    /// The stream ended: every visible task was returned.
    Exhausted,
    /// The caller's limit was reached; more results remain.
    LimitReached,
    /// `MAX_TASK_PAGES` requests were issued and more results remain.
    PageCap,
    /// The node reported more results but returned no cursor to reach them, so
    /// another request would repeat this one. Never expected against a healthy
    /// node; this is the guard that keeps a contract break from spinning.
    NoProgress,
}

#[derive(Debug)]
pub(crate) struct TaskList {
    pub tasks: Vec<Value>,
    /// True when the last response was short because the node's authorization
    /// scan hit its ceiling, not because the stream ended.
    pub incomplete: bool,
    pub next_cursor: Option<String>,
    pub pages: usize,
    pub stop: TaskListStop,
}

impl TaskList {
    /// Human-readable warning when the result is not the complete answer to
    /// the request, so a truncated list can never read as an exhaustive one.
    pub fn truncation_warning(&self) -> Option<String> {
        let reason = match self.stop {
            TaskListStop::Exhausted | TaskListStop::LimitReached if !self.incomplete => {
                return None
            }
            TaskListStop::PageCap => "page limit reached",
            TaskListStop::NoProgress => "node reported more results but returned no cursor",
            _ => "node's authorization scan ceiling reached",
        };
        let resume = match &self.next_cursor {
            Some(c) => format!("; continue with --cursor {c}"),
            None => String::new(),
        };
        Some(format!(
            "result incomplete: {reason} after {} page(s), {} task(s) returned{resume}",
            self.pages,
            self.tasks.len()
        ))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "tasks": self.tasks,
            "count": self.tasks.len(),
            "incomplete": self.incomplete,
            "has_more": self.next_cursor.is_some(),
            "next_cursor": self.next_cursor,
            "pages_fetched": self.pages,
            "complete": self.truncation_warning().is_none(),
        })
    }
}

/// Fetch up to `limit` visible tasks, following the node's opaque
/// `next_cursor` across requests.
///
/// Bounded on both axes so this cannot become an unbounded crawl: at most
/// `MAX_TASK_PAGES` requests, and it stops the moment a response reports more
/// results without a cursor to reach them.
///
/// `limit` must be positive. The node clamps a non-positive limit to zero and
/// answers with an empty page marked complete, which reads as "no tasks exist"
/// rather than "your request was invalid", so both clients reject it here
/// instead of sending it (#327 review).
pub(crate) async fn fetch_tasks(
    client: &NodeClient,
    status: Option<&str>,
    assignee_did: Option<&str>,
    limit: i64,
    cursor: Option<&str>,
) -> Result<TaskList> {
    if limit < 1 {
        anyhow::bail!("limit must be a positive number of tasks (got {limit})");
    }
    let mut tasks: Vec<Value> = Vec::new();
    let mut cursor = cursor.map(str::to_string);
    let mut incomplete = false;
    let mut pages = 0usize;

    let stop = loop {
        if tasks.len() as i64 >= limit {
            break TaskListStop::LimitReached;
        }
        let want = (limit - tasks.len() as i64).min(SERVER_PAGE_CAP);
        let mut path = format!("/api/v1/tasks?limit={want}");
        if let Some(s) = status {
            path.push_str(&format!("&status={}", urlencoding::encode(s)));
        }
        if let Some(a) = assignee_did {
            path.push_str(&format!("&assignee_did={}", urlencoding::encode(a)));
        }
        if let Some(c) = &cursor {
            path.push_str(&format!("&cursor={}", urlencoding::encode(c)));
        }
        let resp: Value = client
            .get_maybe_signed(&path)
            .await
            .context("failed to list tasks")?
            // No `context` here: the reqwest error already names the status,
            // and MCP surfaces this message verbatim to the model.
            .error_for_status()?
            .json()
            .await
            .context("invalid JSON response")?;
        pages += 1;

        if let Some(page) = resp["tasks"].as_array() {
            tasks.extend(page.iter().cloned());
        }
        incomplete = resp["incomplete"].as_bool().unwrap_or(false);
        let next = resp["next_cursor"].as_str().map(str::to_string);

        if !resp["has_more"].as_bool().unwrap_or(false) {
            cursor = None;
            break TaskListStop::Exhausted;
        }
        // `has_more` without a cursor, or a cursor the node did not advance,
        // means the next request would repeat this one.
        if next.is_none() || next == cursor {
            break TaskListStop::NoProgress;
        }
        cursor = next;
        if pages >= MAX_TASK_PAGES {
            break TaskListStop::PageCap;
        }
    };

    Ok(TaskList {
        tasks,
        incomplete,
        next_cursor: cursor,
        pages,
        stop,
    })
}

async fn cmd_list(
    status: Option<String>,
    assignee_did: Option<String>,
    limit: i64,
    cursor: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let client = NodeClient::new(&node, load_keypair_from_dir(dir.as_deref()).ok());
    let result = fetch_tasks(
        &client,
        status.as_deref(),
        assignee_did.as_deref(),
        limit,
        cursor.as_deref(),
    )
    .await?;
    print_json(&result.to_json());
    // stderr so stdout stays a single parseable JSON document.
    if let Some(warning) = result.truncation_warning() {
        eprintln!("warning: {warning}");
    }
    Ok(())
}

async fn cmd_view(id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let client = NodeClient::new(&node, load_keypair_from_dir(dir.as_deref()).ok());
    let resp: Value = client
        .get_maybe_signed(&format!("/api/v1/tasks/{}", id))
        .await
        .context("failed to get task")?
        .error_for_status()
        .context("failed to get task")?
        .json()
        .await
        .context("invalid JSON response")?;
    print_json(&resp);
    Ok(())
}

async fn cmd_claim(id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let assignee_did = keypair.did().to_string();
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&json!({ "assignee_did": assignee_did }))?;
    let resp: Value = client
        .post(&format!("/api/v1/tasks/{}/claim", id), &body)
        .await
        .context("failed to claim task")?
        .error_for_status()
        .context("claim request rejected")?
        .json()
        .await
        .context("invalid JSON response")?;
    print_json(&resp);
    Ok(())
}

async fn cmd_complete(
    id: String,
    result: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let by_did = keypair.did().to_string();
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&json!({ "result": result, "by_did": by_did }))?;
    let resp: Value = client
        .post(&format!("/api/v1/tasks/{}/complete", id), &body)
        .await
        .context("failed to complete task")?
        .error_for_status()
        .context("complete request rejected")?
        .json()
        .await
        .context("invalid JSON response")?;
    print_json(&resp);
    Ok(())
}

async fn cmd_fail(
    id: String,
    reason: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let by_did = keypair.did().to_string();
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&json!({ "reason": reason, "by_did": by_did }))?;
    let resp: Value = client
        .post(&format!("/api/v1/tasks/{}/fail", id), &body)
        .await
        .context("failed to fail task")?
        .error_for_status()
        .context("fail request rejected")?
        .json()
        .await
        .context("invalid JSON response")?;
    print_json(&resp);
    Ok(())
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── create ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_task_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-1","kind":"code-review","status":"pending"}"#)
            .create_async()
            .await;

        cmd_create(
            "code-review".to_string(),
            "agent:task".to_string(),
            Some("repo-42".to_string()),
            None,
            Some(r#"{"file":"main.rs"}"#.to_string()),
            None,
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_task_no_identity_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = cmd_create(
            "code-review".to_string(),
            "agent:task".to_string(),
            None,
            None,
            None,
            None,
            None,
            "http://127.0.0.1:1".to_string(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no identity found"));
    }

    #[tokio::test]
    async fn test_create_task_server_error() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"internal error"}"#)
            .create_async()
            .await;

        let err = cmd_create(
            "deploy".to_string(),
            "agent:task".to_string(),
            None,
            None,
            None,
            None,
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("failed to create task"));
    }

    // ── list ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_tasks_empty() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();

        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[]}"#)
            .create_async()
            .await;

        cmd_list(
            None,
            None,
            50,
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_delegator_list_tasks_is_signed() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"status=pending".to_string()),
            )
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1","kind":"test","status":"pending"}]}"#)
            .create_async()
            .await;

        cmd_list(
            Some("pending".to_string()),
            Some("did:key:z6Mk_test".to_string()),
            10,
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    // ── list paging ──────────────────────────────────────────────────

    fn page(ids: &[&str], has_more: bool, incomplete: bool, next: Option<&str>) -> String {
        let tasks: Vec<Value> = ids
            .iter()
            .map(|id| json!({ "id": id, "kind": "test", "status": "pending" }))
            .collect();
        json!({
            "tasks": tasks,
            "count": tasks.len(),
            "has_more": has_more,
            "incomplete": incomplete,
            "next_cursor": next,
        })
        .to_string()
    }

    fn client_for(server: &mockito::Server) -> NodeClient {
        NodeClient::new(server.url(), None)
    }

    /// #327 review: `--limit 500` used to print a successful but silently
    /// truncated 200-row page, because the client issued exactly one request
    /// and the server clamps to 200. It now follows `next_cursor`.
    #[tokio::test]
    async fn list_follows_cursors_until_the_limit_is_met() {
        let mut server = mockito::Server::new_async().await;
        let first = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["a", "b"], true, false, Some("cursor-1")))
            .create_async()
            .await;
        let second = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=cursor-1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["c"], false, false, None))
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 300, None)
            .await
            .unwrap();
        first.assert_async().await;
        second.assert_async().await;
        assert_eq!(result.tasks.len(), 3);
        assert_eq!(result.pages, 2);
        assert_eq!(result.stop, TaskListStop::Exhausted);
        assert!(result.next_cursor.is_none());
        assert!(
            result.truncation_warning().is_none(),
            "an exhausted stream is a complete result"
        );
        assert_eq!(result.to_json()["complete"], json!(true));
    }

    /// The node's authorization scan ceiling can end a run early. That must
    /// reach the user as an explicit incomplete result with a way to resume,
    /// never as a plain short list.
    #[tokio::test]
    async fn list_reports_incomplete_and_offers_a_resume_cursor() {
        let mut server = mockito::Server::new_async().await;
        // Distinct cursor per page, so the page cap is what stops this and not
        // the no-progress guard.
        let mut mocks = Vec::new();
        for step in 0..=MAX_TASK_PAGES {
            let matcher = if step == 0 {
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".into())
            } else {
                mockito::Matcher::Regex(format!(r"cursor=step-{step}$"))
            };
            mocks.push(
                server
                    .mock("GET", matcher)
                    .with_status(200)
                    .with_header("content-type", "application/json")
                    .with_body(page(
                        &["a"],
                        true,
                        true,
                        Some(&format!("step-{}", step + 1)),
                    ))
                    .create_async()
                    .await,
            );
        }

        let result = fetch_tasks(&client_for(&server), None, None, 10_000, None)
            .await
            .unwrap();
        assert_eq!(result.stop, TaskListStop::PageCap);
        assert_eq!(result.pages, MAX_TASK_PAGES);
        assert_eq!(result.tasks.len(), MAX_TASK_PAGES);
        assert!(result.incomplete);
        assert_eq!(
            result.next_cursor.as_deref(),
            Some(format!("step-{MAX_TASK_PAGES}").as_str())
        );
        let warning = result.truncation_warning().expect("must warn");
        assert!(warning.contains("page limit reached"), "{warning}");
        assert!(
            warning.contains(&format!("--cursor step-{MAX_TASK_PAGES}")),
            "{warning}"
        );
        assert_eq!(result.to_json()["complete"], json!(false));
    }

    /// A node that claims more results but hands back no cursor would spin the
    /// loop forever on the same request. The progress guard stops it.
    #[tokio::test]
    async fn list_stops_when_the_node_offers_no_way_forward() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["a"], true, false, None))
            .expect(1)
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 500, None)
            .await
            .unwrap();
        m.assert_async().await;
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert_eq!(result.pages, 1);
        let warning = result.truncation_warning().expect("must warn");
        assert!(warning.contains("no cursor"), "{warning}");
    }

    /// A node that keeps returning the same cursor is the other shape of the
    /// same fault, and must not loop either.
    #[tokio::test]
    async fn list_stops_when_the_cursor_does_not_advance() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["a"], true, false, Some("stuck")))
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 500, Some("stuck"))
            .await
            .unwrap();
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert_eq!(result.pages, 1);
    }

    /// A caller-supplied resume cursor must reach the node, and each request
    /// must ask only for the rows still outstanding.
    #[tokio::test]
    async fn list_resumes_from_a_supplied_cursor_and_narrows_each_request() {
        let mut server = mockito::Server::new_async().await;
        let first = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=3&cursor=given$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["a"], true, false, Some("next")))
            .create_async()
            .await;
        let second = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=2&cursor=next$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["b"], false, false, None))
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 3, Some("given"))
            .await
            .unwrap();
        first.assert_async().await;
        second.assert_async().await;
        assert_eq!(result.tasks.len(), 2);
    }

    /// A per-request ask must never exceed the node's page cap, so the client
    /// cannot rely on a server that forgets to clamp.
    #[tokio::test]
    async fn list_never_asks_for_more_than_the_server_page_cap() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(r"^/api/v1/tasks\?limit={SERVER_PAGE_CAP}$")),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["a"], false, false, None))
            .expect(1)
            .create_async()
            .await;

        fetch_tasks(&client_for(&server), None, None, 5_000, None)
            .await
            .unwrap();
        m.assert_async().await;
    }

    /// #327 review: `--limit 0` (or a negative one) reached the node, which
    /// clamped it to zero and answered with an empty page marked complete. A
    /// caller could read an invalid request as proof that no tasks exist, so
    /// the shared helper both clients use rejects it before the first request.
    #[tokio::test]
    async fn non_positive_limit_is_rejected_without_a_request() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&[], false, false, None))
            .expect(0)
            .create_async()
            .await;

        for limit in [0, -1] {
            let err = fetch_tasks(&client_for(&server), None, None, limit, None)
                .await
                .expect_err("a non-positive limit must not be answered with an empty list");
            assert!(
                err.to_string().contains("limit must be a positive"),
                "{err}"
            );
        }
        m.assert_async().await;
    }

    // ── view ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_assignee_view_task_is_signed() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("GET", "/api/v1/tasks/task-42")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-42","kind":"deploy","status":"completed","result":"ok"}"#)
            .create_async()
            .await;

        cmd_view(
            "task-42".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_private_repo_task_view_is_signed() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("GET", "/api/v1/tasks/private-task")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"private-task","repo_id":"private-repo"}"#)
            .create_async()
            .await;

        cmd_view(
            "private-task".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_view_task_not_found() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();

        let _m = server
            .mock("GET", "/api/v1/tasks/nope")
            .match_header("signature", mockito::Matcher::Missing)
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create_async()
            .await;

        let err = cmd_view(
            "nope".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("failed to get task"));
    }

    // ── claim ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_claim_task_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-7/claim")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-7","status":"claimed"}"#)
            .create_async()
            .await;

        cmd_claim(
            "task-7".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    // ── complete ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_complete_task_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-7/complete")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-7","status":"completed"}"#)
            .create_async()
            .await;

        cmd_complete(
            "task-7".to_string(),
            Some("all tests passed".to_string()),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_complete_task_no_result() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-8/complete")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-8","status":"completed"}"#)
            .create_async()
            .await;

        cmd_complete(
            "task-8".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    // ── fail ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_fail_task_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-9/fail")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-9","status":"failed"}"#)
            .create_async()
            .await;

        cmd_fail(
            "task-9".to_string(),
            Some("timeout".to_string()),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_fail_task_no_reason() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-10/fail")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-10","status":"failed"}"#)
            .create_async()
            .await;

        cmd_fail(
            "task-10".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }
}
