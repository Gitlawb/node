//! `gl task` — agent task delegation commands.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::collections::HashSet;
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

/// Maximum response size in bytes accepted for a single task page (2 MiB).
/// Bounds memory allocation against a hostile node returning an oversized
/// payload or chunked stream before JSON deserialization runs (#327 review).
pub(crate) const MAX_TASK_PAGE_BYTES: usize = 2 * 1024 * 1024;

/// Stream a task response body into a byte-preserving capped buffer before JSON
/// deserialization. Rejects oversized responses (both Content-Length declared
/// and chunked streams) before allocation can exceed the budget.
pub(crate) async fn read_task_page_json(mut resp: reqwest::Response) -> Result<Value> {
    if let Some(content_length) = resp.content_length() {
        if content_length > MAX_TASK_PAGE_BYTES as u64 {
            anyhow::bail!(
                "task response exceeds byte budget (declared {content_length} bytes, limit is {MAX_TASK_PAGE_BYTES} bytes)"
            );
        }
    }

    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("failed reading response body")? {
        if buf.len() + chunk.len() > MAX_TASK_PAGE_BYTES {
            anyhow::bail!(
                "task response exceeds byte budget (exceeded {MAX_TASK_PAGE_BYTES} bytes)"
            );
        }
        buf.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&buf).context("invalid JSON response")
}

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
    /// The node made no progress, returned an invalid/cyclic cursor, or repeated task rows.
    NoProgress,
    /// The node returned a legacy response without pagination metadata (`has_more`).
    LegacyProtocol,
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
                return None;
            }
            TaskListStop::PageCap => "page limit reached",
            TaskListStop::NoProgress => {
                "node made no progress or returned an invalid/cyclic cursor"
            }
            TaskListStop::LegacyProtocol => "node does not support pagination metadata",
            _ => "node's authorization scan ceiling reached",
        };
        let resume = match &self.next_cursor {
            Some(c) => {
                let sanitized = crate::http::sanitize_node_msg(c);
                format!("; continue with --cursor {sanitized}")
            }
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

#[derive(Debug)]
pub(crate) enum TaskPage {
    Paginated {
        tasks: Vec<Value>,
        has_more: bool,
        incomplete: bool,
        next_cursor: Option<String>,
    },
    Legacy {
        tasks: Vec<Value>,
    },
}

pub(crate) fn parse_task_page(val: Value) -> Result<TaskPage> {
    let obj = match val {
        Value::Object(map) => map,
        _ => anyhow::bail!("malformed task response: expected JSON object"),
    };

    let tasks_val = obj
        .get("tasks")
        .ok_or_else(|| anyhow::anyhow!("malformed task response: missing 'tasks' field"))?;
    let tasks_arr = match tasks_val {
        Value::Array(arr) => arr.clone(),
        _ => anyhow::bail!("malformed task response: 'tasks' must be an array"),
    };

    let has_more_val = obj.get("has_more");
    let incomplete_val = obj.get("incomplete");
    let next_cursor_val = obj.get("next_cursor");

    if let Some(hm) = has_more_val {
        let has_more = match hm {
            Value::Bool(b) => *b,
            _ => anyhow::bail!("malformed task response: 'has_more' must be a boolean"),
        };

        let incomplete = match incomplete_val {
            Some(Value::Bool(b)) => *b,
            Some(_) => anyhow::bail!("malformed task response: 'incomplete' must be a boolean"),
            None => false,
        };

        let next_cursor = match next_cursor_val {
            Some(Value::String(s)) => {
                if s.is_empty() {
                    None
                } else {
                    Some(s.clone())
                }
            }
            Some(Value::Null) | None => None,
            Some(_) => {
                anyhow::bail!("malformed task response: 'next_cursor' must be a string or null")
            }
        };

        if !has_more && next_cursor.is_some() {
            anyhow::bail!(
                "malformed task response: 'next_cursor' present when 'has_more' is false"
            );
        }

        Ok(TaskPage::Paginated {
            tasks: tasks_arr,
            has_more,
            incomplete,
            next_cursor,
        })
    } else {
        if incomplete_val.is_some() || next_cursor_val.is_some() {
            anyhow::bail!("malformed task response: pagination fields present without 'has_more'");
        }
        if let Some(count_val) = obj.get("count") {
            if !count_val.is_number() {
                anyhow::bail!("malformed task response: 'count' must be a number");
            }
        }
        Ok(TaskPage::Legacy { tasks: tasks_arr })
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
    let mut seen_task_ids: HashSet<String> = HashSet::new();
    let mut seen_cursors: HashSet<String> = HashSet::new();
    let mut current_request_cursor: Option<String> = cursor.map(str::to_string);
    if let Some(ref c) = current_request_cursor {
        seen_cursors.insert(c.clone());
    }
    let mut safe_resume_cursor: Option<String> = None;
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
        if let Some(c) = &current_request_cursor {
            path.push_str(&format!("&cursor={}", urlencoding::encode(c)));
        }
        let resp = client
            .get_maybe_signed(&path)
            .await
            .context("failed to list tasks")?
            // No `context` here: the reqwest error already names the status,
            // and MCP surfaces this message verbatim to the model.
            .error_for_status()?;
        let raw_val: Value = read_task_page_json(resp).await?;
        pages += 1;

        let page = parse_task_page(raw_val)?;
        let page_tasks = match &page {
            TaskPage::Paginated { tasks, .. } | TaskPage::Legacy { tasks } => tasks,
        };

        let mut page_seen = seen_task_ids.clone();
        let mut has_duplicate_row = false;
        for t in page_tasks {
            let id = match t.get("id").and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s,
                _ => anyhow::bail!("malformed task response: task missing non-empty string 'id'"),
            };
            if !page_seen.insert(id.to_string()) {
                has_duplicate_row = true;
                break;
            }
        }
        if has_duplicate_row {
            incomplete = true;
            safe_resume_cursor = None;
            break TaskListStop::NoProgress;
        }

        // `want` is the remaining total, capped at the server page.
        // A valid-shaped page larger than that can push the helper
        // (and therefore both CLI and MCP) past `--limit`. Treat it
        // as protocol-invalid rather than clipping, matching the
        // hostile-node handling for duplicate rows and cursor cycles.
        if page_tasks.len() as i64 > want {
            anyhow::bail!(
                "protocol-invalid task page: got {} tasks, asked for {want}",
                page_tasks.len()
            );
        }

        match page {
            TaskPage::Paginated {
                tasks: page_tasks,
                has_more,
                incomplete: page_incomplete,
                next_cursor,
            } => {
                seen_task_ids = page_seen;
                tasks.extend(page_tasks);
                incomplete = page_incomplete;

                if tasks.len() as i64 >= limit {
                    if has_more {
                        let Some(next) = next_cursor else {
                            incomplete = true;
                            safe_resume_cursor = None;
                            break TaskListStop::NoProgress;
                        };

                        if seen_cursors.contains(&next) {
                            incomplete = true;
                            safe_resume_cursor = None;
                            break TaskListStop::NoProgress;
                        }

                        safe_resume_cursor = Some(next);
                    } else {
                        safe_resume_cursor = None;
                    }
                    break TaskListStop::LimitReached;
                }

                if !has_more {
                    safe_resume_cursor = None;
                    break TaskListStop::Exhausted;
                }

                let Some(next) = next_cursor else {
                    incomplete = true;
                    safe_resume_cursor = None;
                    break TaskListStop::NoProgress;
                };

                if seen_cursors.contains(&next) {
                    incomplete = true;
                    safe_resume_cursor = None;
                    break TaskListStop::NoProgress;
                }

                seen_cursors.insert(next.clone());
                current_request_cursor = Some(next.clone());
                safe_resume_cursor = Some(next);

                if pages >= MAX_TASK_PAGES {
                    break TaskListStop::PageCap;
                }
            }
            TaskPage::Legacy { tasks: page_tasks } => {
                tasks.extend(page_tasks);
                incomplete = true;
                safe_resume_cursor = None;
                break TaskListStop::LegacyProtocol;
            }
        }
    };

    Ok(TaskList {
        tasks,
        incomplete,
        next_cursor: safe_resume_cursor,
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
    let keypair = crate::identity::load_optional_keypair(dir.as_deref())?;
    let client = NodeClient::new(&node, keypair);
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
    let keypair = crate::identity::load_optional_keypair(dir.as_deref())?;
    let client = NodeClient::new(&node, keypair);
    let resp = client
        .get_maybe_signed(&format!("/api/v1/tasks/{}", id))
        .await
        .context("failed to get task")?
        .error_for_status()
        .context("failed to get task")?;
    let resp_json: Value = read_task_page_json(resp).await?;
    print_json(&resp_json);
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

        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[],"has_more":false,"incomplete":false,"next_cursor":null}"#)
            .create_async()
            .await;

        cmd_list(None, None, 50, None, server.url(), None)
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
            .with_body(r#"{"tasks":[{"id":"t1","kind":"test","status":"pending"}],"has_more":false,"incomplete":false,"next_cursor":null}"#)
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
            let task_id = format!("task-{step}");
            mocks.push(
                server
                    .mock("GET", matcher)
                    .with_status(200)
                    .with_header("content-type", "application/json")
                    .with_body(page(
                        &[&task_id],
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
        assert!(result.incomplete);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.to_json()["complete"], json!(false));
        let warning = result.truncation_warning().expect("must warn");
        assert!(warning.contains("result incomplete"), "{warning}");
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
        assert!(result.incomplete);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.to_json()["complete"], json!(false));
    }

    /// A legacy node returns `{tasks, count}` without pagination metadata.
    /// The client must NOT interpret this as complete/exhausted, but instead
    /// return an explicit incomplete result with `complete: false`.
    #[tokio::test]
    async fn list_legacy_response_is_incomplete_and_does_not_claim_exhaustion() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=50$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1","kind":"test","status":"pending"}],"count":1}"#)
            .expect(1)
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 50, None)
            .await
            .unwrap();
        m.assert_async().await;
        assert_eq!(result.stop, TaskListStop::LegacyProtocol);
        assert_eq!(result.pages, 1);
        assert_eq!(result.tasks.len(), 1);
        assert!(result.incomplete);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.to_json()["complete"], json!(false));
        let warning = result
            .truncation_warning()
            .expect("legacy response must warn");
        assert!(
            warning.contains("node does not support pagination metadata"),
            "{warning}"
        );
    }

    /// When querying a legacy node with a limit above the 200-row page cap,
    /// the client stops after the first page (since no cursor is returned)
    /// and reports `complete: false` rather than claiming the 200 rows are the whole dataset.
    #[tokio::test]
    async fn list_legacy_response_with_limit_above_page_cap_stops_after_one_page() {
        let mut server = mockito::Server::new_async().await;
        let ids: Vec<String> = (0..200).map(|i| format!("t{i}")).collect();
        let tasks_json: Vec<Value> = ids
            .iter()
            .map(|id| json!({ "id": id, "kind": "test" }))
            .collect();
        let body = json!({ "tasks": tasks_json, "count": 200 }).to_string();

        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(1)
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 500, None)
            .await
            .unwrap();
        m.assert_async().await;
        assert_eq!(result.stop, TaskListStop::LegacyProtocol);
        assert_eq!(result.pages, 1);
        assert_eq!(result.tasks.len(), 200);
        assert!(result.incomplete);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.to_json()["complete"], json!(false));
        let warning = result
            .truncation_warning()
            .expect("legacy response must warn");
        assert!(
            warning.contains("node does not support pagination metadata"),
            "{warning}"
        );
    }

    /// A hostile or misconfigured node can return a well-shaped page larger
    /// than the remaining `--limit`. The helper must refuse it rather than
    /// print more tasks than the caller asked for.
    #[tokio::test]
    async fn list_rejects_oversized_page_before_exposing_it() {
        let mut server = mockito::Server::new_async().await;
        let oversized = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=3$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["a", "b", "c", "d", "e"], false, false, None))
            .expect(1)
            .create_async()
            .await;

        let err = fetch_tasks(&client_for(&server), None, None, 3, None)
            .await
            .expect_err("an oversized page must not succeed");
        oversized.assert_async().await;
        let msg = err.to_string();
        assert!(
            msg.contains("protocol-invalid") && msg.contains("asked for 3"),
            "{msg}"
        );
        assert!(
            !msg.contains("\"id\":\"d\""),
            "the extra rows must not appear in the error: {msg}"
        );
    }

    /// A legacy node returning more rows than requested must also be rejected
    /// as protocol-invalid before exposing any task rows to the caller.
    #[tokio::test]
    async fn list_rejects_oversized_legacy_page() {
        let mut server = mockito::Server::new_async().await;
        let oversized = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=1$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"tasks":[{"id":"t1","kind":"test"},{"id":"t2","kind":"test"}],"count":2}"#,
            )
            .expect(1)
            .create_async()
            .await;

        let err = fetch_tasks(&client_for(&server), None, None, 1, None)
            .await
            .expect_err("oversized legacy page must not succeed");
        oversized.assert_async().await;
        let msg = err.to_string();
        assert!(
            msg.contains("protocol-invalid") && msg.contains("asked for 1"),
            "{msg}"
        );
        assert!(
            !msg.contains("\"id\":\"t2\""),
            "the extra rows must not appear in the error: {msg}"
        );
    }

    /// Malformed responses (missing fields, wrong types) must fail with an error
    /// rather than silently succeeding.
    #[tokio::test]
    async fn list_malformed_responses_fail_visibly() {
        let mut server = mockito::Server::new_async().await;
        let bad_responses = [
            r#"{"tasks":"not-an-array"}"#,
            r#"{"count":0}"#,
            r#"{"tasks":[],"has_more":"true"}"#,
            r#"{"tasks":[],"has_more":true,"incomplete":"no"}"#,
            r#"{"tasks":[],"has_more":true,"next_cursor":123}"#,
            r#"{"tasks":[],"has_more":false,"next_cursor":"stray"}"#,
            r#"{"tasks":[],"next_cursor":"c1"}"#,
            r#"[]"#,
        ];

        for bad in bad_responses {
            let m = server
                .mock("GET", mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(bad)
                .expect(1)
                .create_async()
                .await;

            let err = fetch_tasks(&client_for(&server), None, None, 50, None)
                .await
                .expect_err(&format!("expected error for malformed body: {bad}"));
            assert!(
                err.to_string().contains("malformed") || err.to_string().contains("invalid JSON"),
                "{err}"
            );
            m.assert_async().await;
        }
    }

    /// Contradictory pagination metadata (`has_more: false` alongside a non-empty `next_cursor`)
    /// must be rejected as malformed rather than silently accepted or converting into complete: true.
    #[tokio::test]
    async fn list_rejects_contradictory_has_more_false_with_cursor() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[],"has_more":false,"next_cursor":"c1"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = fetch_tasks(&client_for(&server), None, None, 50, None)
            .await
            .expect_err("has_more: false with next_cursor must be rejected as malformed");
        m.assert_async().await;
        assert!(
            err.to_string()
                .contains("next_cursor' present when 'has_more' is false"),
            "{err}"
        );
    }

    /// A node that loops cursors (c1 -> c2 -> c1) must be detected as a cycle,
    /// terminating the loop without reaching the limit or page cap, and never
    /// reporting duplicate rows as complete or recommending a stale cursor.
    #[tokio::test]
    async fn list_stops_on_cursor_cycle_c1_c2_c1() {
        let mut server = mockito::Server::new_async().await;
        let p1 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t1"], true, false, Some("c1")))
            .create_async()
            .await;
        let p2 = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t2"], true, false, Some("c2")))
            .create_async()
            .await;
        let p3 = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c2".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t3"], true, false, Some("c1")))
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 500, None)
            .await
            .unwrap();
        p1.assert_async().await;
        p2.assert_async().await;
        p3.assert_async().await;
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert_eq!(result.pages, 3);
        assert_eq!(result.tasks.len(), 3);
        assert!(result.incomplete);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.to_json()["complete"], json!(false));
        let warning = result.truncation_warning().expect("must warn on cycle");
        assert!(
            !warning.contains("--cursor c1"),
            "must not recommend stale cursor c1: {warning}"
        );
        assert!(
            !warning.contains("--cursor c2"),
            "must not recommend stale cursor c2: {warning}"
        );
    }

    /// A longer cursor cycle (c1 -> c2 -> c3 -> c1) must terminate boundedly.
    #[tokio::test]
    async fn list_stops_on_longer_cursor_cycle() {
        let mut server = mockito::Server::new_async().await;
        let p1 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t1"], true, false, Some("c1")))
            .create_async()
            .await;
        let p2 = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t2"], true, false, Some("c2")))
            .create_async()
            .await;
        let p3 = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c2".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t3"], true, false, Some("c3")))
            .create_async()
            .await;
        let p4 = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c3".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t4"], true, false, Some("c1")))
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 500, None)
            .await
            .unwrap();
        p1.assert_async().await;
        p2.assert_async().await;
        p3.assert_async().await;
        p4.assert_async().await;
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert_eq!(result.pages, 4);
        assert!(result.incomplete);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.to_json()["complete"], json!(false));
    }

    /// A node that issues fresh cursors (c1 -> c2) but returns repeated task rows
    /// must be caught by row progress validation, preventing duplicate rows and stopping boundedly.
    #[tokio::test]
    async fn list_stops_on_fresh_cursors_with_repeated_task_rows() {
        let mut server = mockito::Server::new_async().await;
        let p1 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".into()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t1"], true, false, Some("c1")))
            .create_async()
            .await;
        let p2 = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t1"], true, false, Some("c2")))
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 500, None)
            .await
            .unwrap();
        p1.assert_async().await;
        p2.assert_async().await;
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert_eq!(result.pages, 2);
        assert_eq!(result.tasks.len(), 1, "duplicate row must not be appended");
        assert!(result.incomplete);
        assert!(result.next_cursor.is_none());
        assert_eq!(result.to_json()["complete"], json!(false));
        let warning = result.truncation_warning().expect("must warn");
        assert!(
            !warning.contains("--cursor c2"),
            "must not recommend c2: {warning}"
        );
    }

    /// If the caller supplies cursor `c1` and the node returns `next_cursor: c1` on the first request,
    /// the client stops immediately as NoProgress and does NOT recommend `--cursor c1`.
    #[tokio::test]
    async fn list_stops_on_immediate_repeat_from_caller_supplied_cursor() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c1".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page(&["t1"], true, false, Some("c1")))
            .expect(1)
            .create_async()
            .await;

        let result = fetch_tasks(&client_for(&server), None, None, 500, Some("c1"))
            .await
            .unwrap();
        m.assert_async().await;
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert_eq!(result.pages, 1);
        assert_eq!(result.tasks.len(), 1);
        assert!(result.incomplete);
        assert!(
            result.next_cursor.is_none(),
            "must not return stale input cursor c1"
        );
        assert_eq!(result.to_json()["complete"], json!(false));
        let warning = result.truncation_warning().expect("must warn");
        assert!(
            !warning.contains("--cursor c1"),
            "must not recommend stale cursor c1: {warning}"
        );
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

        let _m = server
            .mock("GET", "/api/v1/tasks/nope")
            .match_header("signature", mockito::Matcher::Missing)
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create_async()
            .await;

        let err = cmd_view("nope".to_string(), server.url(), None)
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

    // ── Exact-limit continuation & progress tests (#327 review) ──────

    #[tokio::test]
    async fn test_exact_limit_missing_cursor_marked_incomplete() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/tasks?limit=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1"}],"has_more":true,"next_cursor":null}"#)
            .create_async()
            .await;

        let client = NodeClient::new(server.url(), None);
        let result = fetch_tasks(&client, None, None, 1, None).await.unwrap();
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert!(result.incomplete);
        assert_eq!(result.next_cursor, None);
        assert!(!result.to_json()["complete"].as_bool().unwrap());
        assert!(result.truncation_warning().is_some());
    }

    #[tokio::test]
    async fn test_exact_limit_cyclic_cursor_marked_incomplete() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/tasks?limit=1&cursor=cur1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1"}],"has_more":true,"next_cursor":"cur1"}"#)
            .create_async()
            .await;

        let client = NodeClient::new(server.url(), None);
        let result = fetch_tasks(&client, None, None, 1, Some("cur1"))
            .await
            .unwrap();
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert!(result.incomplete);
        assert_eq!(result.next_cursor, None);
        assert!(!result.to_json()["complete"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_exact_limit_valid_advancing_cursor_complete() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/tasks?limit=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1"}],"has_more":true,"next_cursor":"cur2"}"#)
            .create_async()
            .await;

        let client = NodeClient::new(server.url(), None);
        let result = fetch_tasks(&client, None, None, 1, None).await.unwrap();
        assert_eq!(result.stop, TaskListStop::LimitReached);
        assert!(!result.incomplete);
        assert_eq!(result.next_cursor.as_deref(), Some("cur2"));
        assert!(result.to_json()["complete"].as_bool().unwrap());
    }

    // ── Page-local row identity & schema tests (#327 review) ─────────

    #[tokio::test]
    async fn test_page_duplicate_ids_within_single_page_marked_incomplete() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/tasks?limit=2")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"dup1"},{"id":"dup1"}],"has_more":false}"#)
            .create_async()
            .await;

        let client = NodeClient::new(server.url(), None);
        let result = fetch_tasks(&client, None, None, 2, None).await.unwrap();
        assert_eq!(result.stop, TaskListStop::NoProgress);
        assert!(result.incomplete);
        assert!(
            result.tasks.is_empty(),
            "unvalidated page must not be committed to tasks"
        );
    }

    #[tokio::test]
    async fn test_page_missing_or_empty_id_fails_validation() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/tasks?limit=2")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"kind":"test"},{"id":""}],"has_more":false}"#)
            .create_async()
            .await;

        let client = NodeClient::new(server.url(), None);
        let err = fetch_tasks(&client, None, None, 2, None).await.unwrap_err();
        assert!(err.to_string().contains("missing non-empty string 'id'"));
    }

    // ── Sanitized cursor diagnostics test (#327 review) ─────────────

    #[test]
    fn test_truncation_warning_sanitizes_terminal_cursor() {
        let malicious_cursor = "c1\x1b[31mRED\x1b[0m\nnewline\u{202e}bidi".to_string();
        let list = TaskList {
            tasks: vec![json!({"id": "t1"})],
            incomplete: true,
            next_cursor: Some(malicious_cursor.clone()),
            pages: 1,
            stop: TaskListStop::PageCap,
        };
        let warning = list.truncation_warning().unwrap();
        // Control bytes and bidi overrides must not be present in terminal warning
        assert!(!warning.contains('\x1b'));
        assert!(!warning.contains('\n'));
        assert!(!warning.contains('\u{202e}'));
        assert!(warning.contains("--cursor c1[31mRED[0mnewlinebidi"));
        // Protocol token itself remains unmodified
        assert_eq!(list.next_cursor.as_ref().unwrap(), &malicious_cursor);
    }

    // ── Response byte budget tests (#327 review) ─────────────────────

    #[tokio::test]
    async fn test_read_task_page_json_oversized_content_length() {
        let mut server = mockito::Server::new_async().await;
        let large_payload = vec![b' '; MAX_TASK_PAGE_BYTES + 1024];
        let _m = server
            .mock("GET", "/api/v1/tasks?limit=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(large_payload)
            .create_async()
            .await;

        let client = NodeClient::new(server.url(), None);
        let err = fetch_tasks(&client, None, None, 1, None).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("task response exceeds byte budget"));
    }

    #[tokio::test]
    async fn test_read_task_page_json_oversized_chunked() {
        let mut server = mockito::Server::new_async().await;
        let large_payload = "x".repeat(3 * 1024 * 1024);
        let _m = server
            .mock("GET", "/api/v1/tasks?limit=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(large_payload)
            .create_async()
            .await;

        let client = NodeClient::new(server.url(), None);
        let err = fetch_tasks(&client, None, None, 1, None).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("task response exceeds byte budget"));
    }

    // ── Identity failure zero-network-request tests (#327 review) ────

    #[tokio::test]
    async fn test_cmd_list_explicit_missing_dir_errors_no_network() {
        let server = mockito::Server::new_async().await;
        // Server has NO mocks configured: any network request would cause test failure
        let nonexistent = std::path::PathBuf::from("/nonexistent/path/for/identity/test");
        let err = cmd_list(None, None, 10, None, server.url(), Some(nonexistent))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no identity found"));
    }

    #[tokio::test]
    async fn test_cmd_list_explicit_corrupt_pem_errors_no_network() {
        let server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("identity.pem"), b"NOT A VALID PEM").unwrap();
        let err = cmd_list(
            None,
            None,
            10,
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("failed to load keypair from PEM"));
    }

    #[tokio::test]
    async fn test_cmd_view_explicit_missing_dir_errors_no_network() {
        let server = mockito::Server::new_async().await;
        let nonexistent = std::path::PathBuf::from("/nonexistent/path/for/identity/test");
        let err = cmd_view("task-1".to_string(), server.url(), Some(nonexistent))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no identity found"));
    }
}
