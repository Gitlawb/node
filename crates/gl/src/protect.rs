//! `gl protect` — manage branch protection rules.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct ProtectArgs {
    #[command(subcommand)]
    pub cmd: ProtectCmd,
}

#[derive(Subcommand)]
pub enum ProtectCmd {
    /// Protect a branch — only the repo owner can push to it
    Set {
        /// Branch name to protect (e.g. main)
        branch: String,
        /// Repository name or owner/repo
        #[arg(long)]
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Remove branch protection
    Remove {
        /// Branch name to unprotect
        branch: String,
        #[arg(long)]
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List protected branches for a repository
    List {
        #[arg(long)]
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: ProtectArgs) -> Result<()> {
    match args.cmd {
        ProtectCmd::Set {
            branch,
            repo,
            node,
            dir,
        } => cmd_set(branch, repo, node, dir).await,
        ProtectCmd::Remove {
            branch,
            repo,
            node,
            dir,
        } => cmd_remove(branch, repo, node, dir).await,
        ProtectCmd::List { repo, node, dir } => cmd_list(repo, node, dir).await,
    }
}

async fn resolve_owner_repo(
    repo: &str,
    node: &str,
    dir: Option<&std::path::Path>,
) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        return Ok((owner.to_string(), name.to_string()));
    }
    // No slash — derive owner from local identity
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
        let did = info["did"].as_str().context("node missing DID")?;
        did.split(':').next_back().unwrap_or(did).to_string()
    };
    Ok((short, repo.to_string()))
}

async fn cmd_set(branch: String, repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let (owner, name) = resolve_owner_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(kp));

    let resp = client
        .post(
            &format!("/api/v1/repos/{owner}/{name}/branches/{branch}/protect"),
            b"",
        )
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("protect failed ({status}): {msg}");
    }

    println!("✓ Branch '{branch}' is now protected in {owner}/{name}");
    println!("  Only the repo owner can push to this branch.");
    Ok(())
}

async fn cmd_remove(
    branch: String,
    repo: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let (owner, name) = resolve_owner_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(kp));

    let resp = client
        .delete(
            &format!("/api/v1/repos/{owner}/{name}/branches/{branch}/protect"),
            b"",
        )
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("unprotect failed ({status}): {msg}");
    }

    println!("✓ Branch '{branch}' is no longer protected in {owner}/{name}");
    Ok(())
}

async fn cmd_list(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = resolve_owner_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, None);

    let resp = client
        .get(&format!("/api/v1/repos/{owner}/{name}/branches/protected"))
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("list protected branches failed ({status}): {msg}");
    }

    let branches = body["protected_branches"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    if branches.is_empty() {
        println!("No protected branches in {owner}/{name}");
    } else {
        println!(
            "Protected branches in {owner}/{name} ({} total)\n",
            branches.len()
        );
        for b in &branches {
            println!("  🔒 {}", b.as_str().unwrap_or("?"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cmd_set_success() {
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
                "POST",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/branches/main/protect".to_string(),
                ),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"protected","repo":"z/myrepo","branch":"main"}"#)
            .create_async()
            .await;

        cmd_set(
            "main".to_string(),
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_set_forbidden() {
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
                "POST",
                mockito::Matcher::Regex(r"branches/main/protect".to_string()),
            )
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"only the repo owner can protect branches"}"#)
            .create_async()
            .await;

        let err = cmd_set(
            "main".to_string(),
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("protect failed"));
    }

    #[tokio::test]
    async fn test_cmd_remove_success() {
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
                "DELETE",
                mockito::Matcher::Regex(r"branches/main/protect".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"unprotected","branch":"main"}"#)
            .create_async()
            .await;

        cmd_remove(
            "main".to_string(),
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_empty() {
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
                mockito::Matcher::Regex(r"branches/protected".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"protected_branches":[],"count":0}"#)
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
    async fn test_cmd_list_with_branches() {
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
                mockito::Matcher::Regex(r"branches/protected".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"protected_branches":["main","release"],"count":2}"#)
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

    #[test]
    fn test_resolve_owner_repo_with_slash() {
        // owner/repo format should split correctly
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (owner, name) = rt
            .block_on(resolve_owner_repo("alice/myrepo", "http://unused", None))
            .unwrap();
        assert_eq!(owner, "alice");
        assert_eq!(name, "myrepo");
    }
}
