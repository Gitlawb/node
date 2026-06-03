//! `gl visibility`: manage path-scoped read visibility rules.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct VisibilityArgs {
    #[command(subcommand)]
    pub cmd: VisibilityCmd,
}

#[derive(Subcommand)]
pub enum VisibilityCmd {
    /// Set a visibility rule. Use "/" for the whole repo.
    Set {
        /// Path glob, e.g. "/" or "/secret-pkg/**"
        path_glob: String,
        #[arg(long)]
        repo: String,
        /// Comma-separated reader DIDs allowed to read this path
        #[arg(long, value_delimiter = ',')]
        readers: Vec<String>,
        /// Replication mode: "a" (hide, whole-repo only) or "b" (lock content)
        #[arg(long, default_value = "b")]
        mode: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Remove a visibility rule.
    Remove {
        path_glob: String,
        #[arg(long)]
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List visibility rules for a repo (owner only).
    List {
        #[arg(long)]
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: VisibilityArgs) -> Result<()> {
    match args.cmd {
        VisibilityCmd::Set {
            path_glob,
            repo,
            readers,
            mode,
            node,
            dir,
        } => cmd_set(path_glob, repo, readers, mode, node, dir).await,
        VisibilityCmd::Remove {
            path_glob,
            repo,
            node,
            dir,
        } => cmd_remove(path_glob, repo, node, dir).await,
        VisibilityCmd::List { repo, node, dir } => cmd_list(repo, node, dir).await,
    }
}

async fn resolve_owner_repo(
    repo: &str,
    node: &str,
    dir: Option<&Path>,
) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        return Ok((owner.to_string(), name.to_string()));
    }
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

async fn cmd_set(
    path_glob: String,
    repo: String,
    readers: Vec<String>,
    mode: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found, run `gl identity new` first")?;
    let (owner, name) = resolve_owner_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::to_vec(&serde_json::json!({
        "path_glob": path_glob,
        "mode": mode,
        "reader_dids": readers,
    }))?;

    let resp = client
        .put(&format!("/api/v1/repos/{owner}/{name}/visibility"), &body)
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("visibility set failed ({status}): {msg}");
    }

    println!("✓ Visibility rule set on {owner}/{name}: {path_glob} (mode {mode})");
    if path_glob != "/" {
        println!(
            "  Note: subtree content is NOT withheld from clones yet (Phase 3). Only whole-repo (\"/\") rules are enforced today. This rule is stored and will take effect when subtree enforcement ships."
        );
    }
    Ok(())
}

async fn cmd_remove(
    path_glob: String,
    repo: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found, run `gl identity new` first")?;
    let (owner, name) = resolve_owner_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::to_vec(&serde_json::json!({ "path_glob": path_glob }))?;
    let resp = client
        .delete(&format!("/api/v1/repos/{owner}/{name}/visibility"), &body)
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("visibility remove failed ({status}): {msg}");
    }

    println!("✓ Visibility rule removed from {owner}/{name}: {path_glob}");
    Ok(())
}

async fn cmd_list(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found, run `gl identity new` first")?;
    let (owner, name) = resolve_owner_repo(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(kp));

    // owner-only endpoint: must send a signed request
    let resp = client
        .get_signed(&format!("/api/v1/repos/{owner}/{name}/visibility"))
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("visibility list failed ({status}): {msg}");
    }

    let rules = body["rules"].as_array().cloned().unwrap_or_default();
    if rules.is_empty() {
        println!("No visibility rules on {owner}/{name} (repo follows its is_public flag).");
    } else {
        println!("Visibility rules for {owner}/{name}:");
        for r in rules {
            let glob = r["path_glob"].as_str().unwrap_or("?");
            let mode = r["mode"].as_str().unwrap_or("?");
            let readers = r["reader_dids"].as_array().cloned().unwrap_or_default();
            let readers: Vec<&str> = readers.iter().filter_map(|d| d.as_str()).collect();
            let readers_str = if readers.is_empty() {
                "none".to_string()
            } else {
                readers.join(", ")
            };
            println!("  {glob}  (mode {mode})  readers: {readers_str}");
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
                "PUT",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/visibility".to_string()),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"set"}"#)
            .create_async()
            .await;

        cmd_set(
            "/".to_string(),
            "myrepo".to_string(),
            vec!["did:key:abc".to_string()],
            "b".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_success() {
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
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/visibility".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"rules":[{"path_glob":"/","mode":"b","reader_dids":["did:key:abc"]}]}"#)
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
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/visibility".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"removed"}"#)
            .create_async()
            .await;

        cmd_remove(
            "/".to_string(),
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }
}
