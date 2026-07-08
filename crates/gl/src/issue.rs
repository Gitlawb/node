//! `gl issue` — issue management commands.

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;
use uuid::Uuid;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

fn signed_client(node: &str, dir: Option<&std::path::Path>) -> NodeClient {
    NodeClient::new(node, load_keypair_from_dir(dir).ok())
}

#[derive(Args)]
pub struct IssueArgs {
    #[command(subcommand)]
    pub cmd: IssueCmd,
}

#[derive(Subcommand)]
pub enum IssueCmd {
    /// Create a new issue
    Create {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        /// Issue title
        #[arg(long, short)]
        title: String,
        /// Issue body (optional)
        #[arg(long, short)]
        body: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List issues for a repository
    List {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show a specific issue
    Show {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        /// Issue ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Close an issue
    Close {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        /// Issue ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Post a comment on an issue
    Comment {
        repo: String,
        id: String,
        #[arg(long, short)]
        body: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List comments on an issue
    Comments {
        repo: String,
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: IssueArgs) -> Result<()> {
    match args.cmd {
        IssueCmd::Create {
            repo,
            title,
            body,
            node,
            dir,
        } => cmd_create(repo, title, body, node, dir).await,
        IssueCmd::List { repo, node, dir } => cmd_list(repo, node, dir).await,
        IssueCmd::Show {
            repo,
            id,
            node,
            dir,
        } => cmd_show(repo, id, node, dir).await,
        IssueCmd::Close {
            repo,
            id,
            node,
            dir,
        } => cmd_close(repo, id, node, dir).await,
        IssueCmd::Comment {
            repo,
            id,
            body,
            node,
            dir,
        } => cmd_issue_comment(repo, id, body, node, dir).await,
        IssueCmd::Comments {
            repo,
            id,
            node,
            dir,
        } => cmd_issue_comments(repo, id, node, dir).await,
    }
}

/// Resolve "repo" into (owner, name) using the caller's keypair DID when no slash given.
async fn resolve_repo(
    repo: &str,
    node: &str,
    dir: Option<&std::path::Path>,
) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        Ok((owner.to_string(), name.to_string()))
    } else {
        let short = if let Ok(kp) = load_keypair_from_dir(dir) {
            let did = kp.did().to_string();
            did.split(':').next_back().unwrap_or(&did).to_string()
        } else {
            let client = NodeClient::new(node, None);
            let info: Value = client
                .get("/")
                .await?
                .json()
                .await
                .context("failed to fetch node info")?;
            let did = info["did"].as_str().context("node info missing 'did'")?;
            did.split(':').next_back().unwrap_or(did).to_string()
        };
        Ok((short, repo.to_string()))
    }
}

async fn cmd_create(
    repo: String,
    title: String,
    body: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let did = keypair.did().to_string();

    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let issue_id = Uuid::new_v4().to_string();
    let payload = json!({
        "id": issue_id,
        "title": title,
        "body": body,
        "author": did,
        "created_at": Utc::now().to_rfc3339(),
        "status": "open",
    });

    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = keypair.sign_b64(&payload_bytes);

    let signed = json!({
        "payload": payload,
        "signer": did,
        "signature": signature,
    });

    let request_body = serde_json::to_vec(&json!({
        "title": title,
        "body": body,
        "signed_payload": signed,
    }))?;

    let client = NodeClient::new(&node, Some(keypair));
    let path = format!("/api/v1/repos/{owner}/{name}/issues");
    let resp = client
        .post(&path, &request_body)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("create issue failed ({status}): {msg}");
    }

    let id = result["id"].as_str().unwrap_or("?");
    println!("✓ Created issue #{id}");
    println!("  Title:  {title}");
    if let Some(b) = &body {
        println!("  Body:   {b}");
    }
    println!("  Author: {did}");
    Ok(())
}

async fn cmd_list(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let client = signed_client(&node, dir.as_deref());
    let path = format!("/api/v1/repos/{owner}/{name}/issues");
    let resp: Value = client
        .get_authed(&path)
        .await?
        .json()
        .await
        .context("failed to list issues")?;

    let issues = resp["issues"].as_array().cloned().unwrap_or_default();

    if issues.is_empty() {
        println!("No issues for {owner}/{name}");
        return Ok(());
    }

    println!("Issues for {owner}/{name}");
    println!();
    for issue in &issues {
        let id = issue["id"].as_str().unwrap_or("?");
        let title = issue["title"].as_str().unwrap_or("(no title)");
        let status = issue["status"].as_str().unwrap_or("?");
        let created = issue["created_at"]
            .as_str()
            .map(|s| &s[..10])
            .unwrap_or("?");
        let icon = match status {
            "open" => "○",
            "closed" => "✗",
            _ => "?",
        };
        println!("  {icon} {id:.8}  {created}  {title}");
    }
    Ok(())
}

async fn cmd_show(repo: String, id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let client = signed_client(&node, dir.as_deref());
    let path = format!("/api/v1/repos/{owner}/{name}/issues/{id}");
    let resp = client
        .get_authed(&path)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let issue: Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = issue["message"].as_str().unwrap_or("issue not found");
        anyhow::bail!("show failed ({status}): {msg}");
    }

    let title = issue["title"].as_str().unwrap_or("(no title)");
    let status = issue["status"].as_str().unwrap_or("?");
    let author = issue["author"].as_str().unwrap_or("unknown");
    let created = issue["created_at"].as_str().unwrap_or("?");
    let body = issue["body"].as_str().unwrap_or("");

    println!("Issue: {id}");
    println!("  Title:   {title}");
    println!("  Status:  {status}");
    println!("  Author:  {author}");
    println!("  Created: {created}");
    if !body.is_empty() {
        println!();
        println!("{body}");
    }
    Ok(())
}

async fn cmd_close(repo: String, id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&json!({ "status": "closed" }))?;
    let path = format!("/api/v1/repos/{owner}/{name}/issues/{id}");
    let resp = client
        .post(&format!("{path}/close"), &body)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("close issue failed ({status}): {msg}");
    }

    println!("✗ Closed issue {id}");
    Ok(())
}

async fn cmd_issue_comment(
    repo: String,
    id: String,
    body: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(keypair));

    let payload = serde_json::to_vec(&serde_json::json!({ "body": body }))?;
    let resp = client
        .post(
            &format!("/api/v1/repos/{owner}/{name}/issues/{id}/comments"),
            &payload,
        )
        .await
        .context("failed to connect to node")?;
    let code = resp.status();
    let result: Value = resp.json().await.context("invalid JSON")?;

    if !code.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("comment failed ({code}): {msg}");
    }

    println!("· Comment posted on issue {id}");
    Ok(())
}

async fn cmd_issue_comments(
    repo: String,
    id: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;
    let client = signed_client(&node, dir.as_deref());

    let resp: Value = client
        .get_authed(&format!(
            "/api/v1/repos/{owner}/{name}/issues/{id}/comments"
        ))
        .await?
        .json()
        .await
        .context("invalid JSON")?;

    let comments = resp["comments"].as_array().cloned().unwrap_or_default();
    if comments.is_empty() {
        println!("No comments on issue {id}");
        return Ok(());
    }

    println!("Comments on issue {id} ({} total)\n", comments.len());
    for c in &comments {
        let author = c["author_did"].as_str().unwrap_or("?");
        let author_short = author
            .split(':')
            .next_back()
            .map(|s| &s[..s.len().min(8)])
            .unwrap_or("?");
        let cbody = c["body"].as_str().unwrap_or("");
        let created = c["created_at"].as_str().map(|s| &s[..10]).unwrap_or("?");
        println!("  · {author_short} ({created})");
        println!("    {cbody}");
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_identity(dir: &TempDir) {
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_empty() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/issues$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"issues":[]}"#)
            .create_async()
            .await;

        cmd_list(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_with_issues() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/issues$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"issues":[{"id":"abc-123","title":"Bug report","status":"open","created_at":"2026-03-18T00:00:00Z"}]}"#)
            .create_async()
            .await;

        cmd_list(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_create_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/issues$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"uuid-1234","title":"Test issue"}"#)
            .create_async()
            .await;

        cmd_create(
            "myrepo".to_string(),
            "Test issue".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_create_server_error() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/issues$".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .create_async()
            .await;

        let result = cmd_create(
            "myrepo".to_string(),
            "Test issue".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("repo not found"));
    }

    #[tokio::test]
    async fn test_cmd_show_renders() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/issues/abc-123$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"abc-123","title":"Bug report","status":"open","author":"did:key:z6MkTest","created_at":"2026-03-18T00:00:00Z","body":"steps to reproduce..."}"#)
            .create_async()
            .await;

        cmd_show(
            "myrepo".to_string(),
            "abc-123".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_show_not_found_errors() {
        // BUG-6 regression test: cmd_show must check HTTP status and bail,
        // not silently show empty fields from a 404 error body.
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/issues/missing-id$".to_string(),
                ),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"issue not found"}"#)
            .create_async()
            .await;

        let err = cmd_show(
            "myrepo".to_string(),
            "missing-id".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("show failed"), "got: {err}");
        assert!(err.to_string().contains("issue not found"), "got: {err}");
    }

    #[tokio::test]
    async fn test_cmd_close_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/issues/abc-123/close$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"abc-123","status":"closed"}"#)
            .create_async()
            .await;

        cmd_close(
            "myrepo".to_string(),
            "abc-123".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_close_not_found_errors() {
        // BUG-5 regression test: close must not EOF on a 404 with no JSON body.
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/issues/bad-id/close$".to_string(),
                ),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"issue not found"}"#)
            .create_async()
            .await;

        let err = cmd_close(
            "myrepo".to_string(),
            "bad-id".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("close issue failed"), "got: {err}");
    }

    #[tokio::test]
    async fn test_cmd_issue_comment_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/issues/abc123/comments$".to_string()),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"c1","issue_id":"abc123","author_did":"did:key:z6Mk","body":"looks good","created_at":"2026-03-24T00:00:00Z"}"#)
            .create_async()
            .await;

        cmd_issue_comment(
            "myrepo".to_string(),
            "abc123".to_string(),
            "looks good".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_issue_comment_server_error() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/issues/bad-id/comments$".to_string(),
                ),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"issue not found"}"#)
            .create_async()
            .await;

        let err = cmd_issue_comment(
            "myrepo".to_string(),
            "bad-id".to_string(),
            "hello".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("issue not found"), "got: {err}");
    }

    #[tokio::test]
    async fn test_cmd_issue_comments_empty() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/issues/abc123/comments$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"comments":[]}"#)
            .create_async()
            .await;

        cmd_issue_comments(
            "myrepo".to_string(),
            "abc123".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_issue_comments_with_results() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/issues/abc123/comments$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"comments":[{"id":"c1","issue_id":"abc123","author_did":"did:key:z6MkTest","body":"triage: needs more info","created_at":"2026-03-24T00:00:00Z"}]}"#)
            .create_async()
            .await;

        cmd_issue_comments(
            "myrepo".to_string(),
            "abc123".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }
}
