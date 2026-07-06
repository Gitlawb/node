//! `gl webhook` — manage repo webhooks.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct WebhookArgs {
    #[command(subcommand)]
    pub cmd: WebhookCmd,
}

#[derive(Subcommand)]
pub enum WebhookCmd {
    /// Create a webhook for a repository
    Create {
        /// Repository name
        repo: String,
        /// Webhook URL (must be http:// or https://)
        #[arg(long)]
        url: String,
        /// Events to subscribe to (comma-separated). Use '*' for all events.
        /// Valid: pull_request.opened, pull_request.reviewed, pull_request.merged,
        ///        pull_request.closed, push, *
        #[arg(long, default_value = "*")]
        events: String,
        /// Optional HMAC secret for payload signing (sets X-Gitlawb-Signature-256)
        #[arg(long)]
        secret: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List webhooks for a repository
    List {
        /// Repository name
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
    /// Delete a webhook
    Delete {
        /// Repository name
        repo: String,
        /// Webhook ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: WebhookArgs) -> Result<()> {
    match args.cmd {
        WebhookCmd::Create {
            repo,
            url,
            events,
            secret,
            node,
            dir,
        } => cmd_create(repo, url, events, secret, node, dir).await,
        WebhookCmd::List { repo, node } => cmd_list(repo, node).await,
        WebhookCmd::Delete {
            repo,
            id,
            node,
            dir,
        } => cmd_delete(repo, id, node, dir).await,
    }
}

/// Resolve "repo" into (owner, name). If repo already contains a slash
/// (owner/repo form), use it directly. Otherwise, prefer the caller's own
/// identity (matching the pattern used elsewhere, e.g. cert.rs's
/// resolve_repo) so webhooks are created/listed against the DID that's
/// actually calling, not the node's own operator DID -- falls back to the
/// node's root DID only if no local keypair is available at all.
async fn resolve_owner(
    repo: &str,
    dir: Option<&std::path::Path>,
    client: &NodeClient,
) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        return Ok((owner.to_string(), name.to_string()));
    }
    let short = if let Ok(kp) = load_keypair_from_dir(dir) {
        let did = kp.did().to_string();
        did.split(':').next_back().unwrap_or(&did).to_string()
    } else {
        let info: Value = client.get("/").await?.json().await?;
        let did = info["did"]
            .as_str()
            .context("node missing DID")?
            .to_string();
        did.split(':').next_back().unwrap_or(&did).to_string()
    };
    Ok((short, repo.to_string()))
}

async fn cmd_create(
    repo: String,
    url: String,
    events: String,
    secret: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let client = NodeClient::new(&node, Some(keypair));
    let (owner, repo) = resolve_owner(&repo, dir.as_deref(), &client).await?;

    let event_list: Vec<&str> = events.split(',').map(str::trim).collect();

    let payload = serde_json::to_vec(&serde_json::json!({
        "url": url,
        "secret": secret,
        "events": event_list,
    }))?;

    let resp = client
        .post(&format!("/api/v1/repos/{owner}/{repo}/hooks"), &payload)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let hook: Value = resp.json().await.context("invalid JSON")?;

    if !status.is_success() {
        let msg = hook["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("create webhook failed ({status}): {msg}");
    }

    let id = hook["id"].as_str().unwrap_or("?");
    let hook_events = hook["events"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| events.clone());
    let has_secret = hook["secret"]
        .as_str()
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    println!("✓ Webhook created");
    println!("  ID:     {id}");
    println!("  URL:    {url}");
    println!("  Events: {hook_events}");
    if has_secret {
        println!("  Secret: set (HMAC-SHA256 signing enabled)");
    }
    println!("\n  Delete: gl webhook delete {owner}/{repo} {id}");
    Ok(())
}

async fn cmd_list(repo: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let (owner, repo) = resolve_owner(&repo, None, &client).await?;

    let resp: Value = client
        .get(&format!("/api/v1/repos/{owner}/{repo}/hooks"))
        .await?
        .json()
        .await
        .context("invalid JSON")?;

    let hooks = resp["webhooks"].as_array().cloned().unwrap_or_default();
    if hooks.is_empty() {
        println!("No webhooks for {repo}");
        return Ok(());
    }

    println!("Webhooks for {repo} ({} total)\n", hooks.len());
    for hook in &hooks {
        let id = hook["id"].as_str().unwrap_or("?");
        let url = hook["url"].as_str().unwrap_or("?");
        let events = hook["events"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let active = hook["active"].as_bool().unwrap_or(true);
        let status = if active { "active" } else { "inactive" };
        println!("  [{status}] {id}");
        println!("  URL:    {url}");
        println!("  Events: {events}");
        println!();
    }
    Ok(())
}

async fn cmd_delete(repo: String, id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let client = NodeClient::new(&node, Some(keypair));
    let (owner, repo) = resolve_owner(&repo, dir.as_deref(), &client).await?;

    let payload = serde_json::to_vec(&serde_json::json!({}))?;
    let resp = client
        .delete(
            &format!("/api/v1/repos/{owner}/{repo}/hooks/{id}"),
            &payload,
        )
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("delete webhook failed ({status}): {msg}");
    }

    println!("✓ Webhook {id} deleted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a mockito mock for the node root (returns DID for owner resolution).
    async fn mock_root(server: &mut mockito::Server) -> mockito::Mock {
        server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:z6MkTestOwner"}"#)
            .create_async()
            .await
    }

    /// Helper: write a temporary identity keypair and return the dir.
    fn tmp_identity() -> (tempfile::TempDir, gitlawb_core::identity::Keypair) {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        (dir, kp)
    }

    // ── create ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_webhook_success() {
        let mut server = mockito::Server::new_async().await;
        let (dir, _kp) = tmp_identity();
        let _root = mock_root(&mut server).await;

        let _m = server
            .mock("POST", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"hook-1","url":"https://example.com/hook","events":["push","pull_request.opened"],"secret":"s3cr3t"}"#)
            .create_async()
            .await;

        cmd_create(
            "my-repo".to_string(),
            "https://example.com/hook".to_string(),
            "push,pull_request.opened".to_string(),
            Some("s3cr3t".to_string()),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_webhook_all_events() {
        let mut server = mockito::Server::new_async().await;
        let (dir, _kp) = tmp_identity();
        let _root = mock_root(&mut server).await;

        let _m = server
            .mock("POST", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"hook-2","url":"https://example.com/all","events":["*"]}"#)
            .create_async()
            .await;

        cmd_create(
            "my-repo".to_string(),
            "https://example.com/all".to_string(),
            "*".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_webhook_server_rejects() {
        let mut server = mockito::Server::new_async().await;
        let (dir, _kp) = tmp_identity();
        let _root = mock_root(&mut server).await;

        let _m = server
            .mock("POST", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"invalid URL"}"#)
            .create_async()
            .await;

        let err = cmd_create(
            "my-repo".to_string(),
            "not-a-url".to_string(),
            "*".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid URL"));
    }

    #[tokio::test]
    async fn test_create_webhook_no_identity_errors() {
        let dir = tempfile::TempDir::new().unwrap(); // empty — no identity.pem
        let err = cmd_create(
            "repo".to_string(),
            "https://example.com".to_string(),
            "*".to_string(),
            None,
            "http://127.0.0.1:1".to_string(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no identity found"));
    }

    // ── list ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_webhooks_empty() {
        let mut server = mockito::Server::new_async().await;
        let _root = mock_root(&mut server).await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"webhooks":[]}"#)
            .create_async()
            .await;

        cmd_list("my-repo".to_string(), server.url()).await.unwrap();
    }

    #[tokio::test]
    async fn test_list_webhooks_with_items() {
        let mut server = mockito::Server::new_async().await;
        let _root = mock_root(&mut server).await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"webhooks":[{"id":"h1","url":"https://a.com","events":["push"],"active":true},{"id":"h2","url":"https://b.com","events":["*"],"active":false}]}"#)
            .create_async()
            .await;

        cmd_list("my-repo".to_string(), server.url()).await.unwrap();
    }

    // ── delete ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_webhook_success() {
        let mut server = mockito::Server::new_async().await;
        let (dir, _kp) = tmp_identity();
        let _root = mock_root(&mut server).await;

        let _m = server
            .mock(
                "DELETE",
                mockito::Matcher::Regex(r"/hooks/hook-1$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create_async()
            .await;

        cmd_delete(
            "my-repo".to_string(),
            "hook-1".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_delete_webhook_not_found() {
        let mut server = mockito::Server::new_async().await;
        let (dir, _kp) = tmp_identity();
        let _root = mock_root(&mut server).await;

        let _m = server
            .mock(
                "DELETE",
                mockito::Matcher::Regex(r"/hooks/nope$".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"webhook not found"}"#)
            .create_async()
            .await;

        let err = cmd_delete(
            "my-repo".to_string(),
            "nope".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("webhook not found"));
    }
}
