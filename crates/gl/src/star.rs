//! `gl star` — star and unstar repositories.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct StarArgs {
    #[command(subcommand)]
    pub cmd: StarCmd,
}

#[derive(Subcommand)]
pub enum StarCmd {
    /// Star a repository (idempotent — safe to call multiple times)
    Add {
        /// Repository name (owner/repo or just name — owner derived from identity)
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Unstar a repository
    Remove {
        /// Repository name (owner/repo or just name — owner derived from identity)
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show star count for a repository (no auth required)
    Count {
        /// Repository in owner/repo format
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
}

pub async fn run(args: StarArgs) -> Result<()> {
    match args.cmd {
        StarCmd::Add { repo, node, dir }    => cmd_add(repo, node, dir).await,
        StarCmd::Remove { repo, node, dir } => cmd_remove(repo, node, dir).await,
        StarCmd::Count { repo, node }       => cmd_count(repo, node).await,
    }
}

fn resolve_owner_repo(repo: &str, dir: Option<&std::path::Path>) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        return Ok((owner.to_string(), name.to_string()));
    }
    let kp = load_keypair_from_dir(dir)
        .context("identity not found — run `gl identity new` first")?;
    let did = kp.did().to_string();
    let short = did.split(':').next_back().unwrap_or(&did).to_string();
    Ok((short, repo.to_string()))
}

async fn cmd_add(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let (owner, name) = resolve_owner_repo(&repo, dir.as_deref())?;
    let client = NodeClient::new(&node, Some(kp));

    let resp = client
        .put(&format!("/api/v1/repos/{owner}/{name}/star"), b"")
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("star failed ({status}): {msg}");
    }

    let count = body["star_count"].as_i64().unwrap_or(0);
    println!("Starred {owner}/{name}  ({count} stars total)");
    Ok(())
}

async fn cmd_remove(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let (owner, name) = resolve_owner_repo(&repo, dir.as_deref())?;
    let client = NodeClient::new(&node, Some(kp));

    let resp = client
        .delete(&format!("/api/v1/repos/{owner}/{name}/star"), b"")
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("unstar failed ({status}): {msg}");
    }

    let count = body["star_count"].as_i64().unwrap_or(0);
    println!("Unstarred {owner}/{name}  ({count} stars remaining)");
    Ok(())
}

async fn cmd_count(repo: String, node: String) -> Result<()> {
    let (owner, name) = repo.split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .context("use owner/repo format for count (e.g. alice/myrepo)")?;
    let client = NodeClient::new(&node, None);

    let resp = client
        .get(&format!("/api/v1/repos/{owner}/{name}/star"))
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("star count failed ({status}): {msg}");
    }

    let count = body["star_count"].as_i64().unwrap_or(0);
    println!("{owner}/{name}: {count} stars");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cmd_add_success_new_star() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("PUT", mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/star$".to_string()))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"starred","repo":"z/myrepo","star_count":1}"#)
            .create_async()
            .await;

        cmd_add(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        ).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_add_already_starred_idempotent() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("PUT", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(200) // already starred → 200 not 201
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"starred","repo":"z/myrepo","star_count":1}"#)
            .create_async()
            .await;

        // Should succeed — idempotent
        cmd_add(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        ).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_add_no_identity_errors() {
        let dir = tempfile::TempDir::new().unwrap(); // no identity.pem written
        let err = cmd_add(
            "owner/myrepo".to_string(),
            "http://127.0.0.1:1".to_string(),
            Some(dir.path().to_path_buf()),
        ).await.unwrap_err();
        assert!(err.to_string().contains("identity not found"));
    }

    #[tokio::test]
    async fn test_cmd_add_repo_not_found() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("PUT", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .create_async()
            .await;

        let err = cmd_add(
            "owner/missing".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        ).await.unwrap_err();
        assert!(err.to_string().contains("star failed"));
    }

    #[tokio::test]
    async fn test_cmd_remove_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("DELETE", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"unstarred","repo":"z/myrepo","star_count":0}"#)
            .create_async()
            .await;

        cmd_remove(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        ).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_remove_not_found_errors() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();

        let _m = server
            .mock("DELETE", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .create_async()
            .await;

        let err = cmd_remove(
            "owner/missing".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        ).await.unwrap_err();
        assert!(err.to_string().contains("unstar failed"));
    }

    #[tokio::test]
    async fn test_cmd_count_success() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"repo":"alice/myrepo","star_count":7}"#)
            .create_async()
            .await;

        cmd_count("alice/myrepo".to_string(), server.url()).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_count_requires_slash() {
        let err = cmd_count(
            "noslash".to_string(),
            "http://127.0.0.1:1".to_string(),
        ).await.unwrap_err();
        assert!(err.to_string().contains("owner/repo format"));
    }

    #[test]
    fn test_resolve_owner_repo_with_slash() {
        let (owner, name) = resolve_owner_repo("alice/myrepo", None).unwrap();
        assert_eq!(owner, "alice");
        assert_eq!(name, "myrepo");
    }
}
