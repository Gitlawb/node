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
        #[arg(long, default_value = "50")]
        limit: i64,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
    /// View a specific task
    View {
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
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
            kind, capability, repo_id, assignee_did, payload,
            ucan_token, deadline, node, dir,
        } => cmd_create(kind, capability, repo_id, assignee_did, payload, ucan_token, deadline, node, dir).await,
        TaskCmd::List { status, assignee_did, limit, node } => {
            cmd_list(status, assignee_did, limit, node).await
        }
        TaskCmd::View { id, node } => cmd_view(id, node).await,
        TaskCmd::Claim { id, node, dir } => cmd_claim(id, node, dir).await,
        TaskCmd::Complete { id, result, node, dir } => cmd_complete(id, result, node, dir).await,
        TaskCmd::Fail { id, reason, node, dir } => cmd_fail(id, reason, node, dir).await,
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
        .json()
        .await
        .context("invalid JSON response")?;
    print_json(&resp);
    Ok(())
}

async fn cmd_list(
    status: Option<String>,
    assignee_did: Option<String>,
    limit: i64,
    node: String,
) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let mut path = format!("/api/v1/tasks?limit={}", limit);
    if let Some(s) = &status {
        path.push_str(&format!("&status={}", urlencoding::encode(s)));
    }
    if let Some(a) = &assignee_did {
        path.push_str(&format!("&assignee_did={}", urlencoding::encode(a)));
    }
    let resp: Value = client
        .get(&path)
        .await
        .context("failed to list tasks")?
        .json()
        .await
        .context("invalid JSON response")?;
    print_json(&resp);
    Ok(())
}

async fn cmd_view(id: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let resp: Value = client
        .get(&format!("/api/v1/tasks/{}", id))
        .await
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
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

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
            None, None, None, None, None,
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
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"internal error"}"#)
            .create_async()
            .await;

        // Should still succeed (prints JSON, doesn't check status code)
        cmd_create(
            "deploy".to_string(),
            "agent:task".to_string(),
            None, None, None, None, None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    // ── list ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_tasks_empty() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[]}"#)
            .create_async()
            .await;

        cmd_list(None, None, 50, server.url()).await.unwrap();
    }

    #[tokio::test]
    async fn test_list_tasks_with_filters() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"status=pending".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1","kind":"test","status":"pending"}]}"#)
            .create_async()
            .await;

        cmd_list(
            Some("pending".to_string()),
            Some("did:key:z6Mk_test".to_string()),
            10,
            server.url(),
        )
        .await
        .unwrap();
    }

    // ── view ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_view_task_success() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/v1/tasks/task-42")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-42","kind":"deploy","status":"completed","result":"ok"}"#)
            .create_async()
            .await;

        cmd_view("task-42".to_string(), server.url()).await.unwrap();
    }

    #[tokio::test]
    async fn test_view_task_not_found() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", "/api/v1/tasks/nope")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create_async()
            .await;

        // cmd_view doesn't check status — it prints the JSON
        cmd_view("nope".to_string(), server.url()).await.unwrap();
    }

    // ── claim ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_claim_task_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-7/claim")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-7","status":"claimed"}"#)
            .create_async()
            .await;

        cmd_claim("task-7".to_string(), server.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
    }

    // ── complete ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_complete_task_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

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
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-8/complete")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-8","status":"completed"}"#)
            .create_async()
            .await;

        cmd_complete("task-8".to_string(), None, server.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
    }

    // ── fail ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_fail_task_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

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
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/task-10/fail")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"task-10","status":"failed"}"#)
            .create_async()
            .await;

        cmd_fail("task-10".to_string(), None, server.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
    }
}
