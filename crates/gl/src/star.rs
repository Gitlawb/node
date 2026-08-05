//! `gl star` — star and unstar repositories.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
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
    /// Show star count for a repository
    Count {
        /// Repository in owner/repo format
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: StarArgs) -> Result<()> {
    match args.cmd {
        StarCmd::Add { repo, node, dir } => cmd_add(repo, node, dir).await,
        StarCmd::Remove { repo, node, dir } => cmd_remove(repo, node, dir).await,
        StarCmd::Count { repo, node, dir } => cmd_count(repo, node, dir).await,
    }
}

fn resolve_owner_repo(repo: &str, dir: Option<&std::path::Path>) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        return Ok((owner.to_string(), name.to_string()));
    }
    let kp =
        load_keypair_from_dir(dir).context("identity not found — run `gl identity new` first")?;
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

    let body = crate::http::read_json(resp, "star").await?;

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

    let body = crate::http::read_json(resp, "unstar").await?;

    let count = body["star_count"].as_i64().unwrap_or(0);
    println!("Unstarred {owner}/{name}  ({count} stars remaining)");
    Ok(())
}

async fn cmd_count(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = repo
        .split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .context("use owner/repo format for count (e.g. alice/myrepo)")?;
    let client = NodeClient::new(&node, load_keypair_from_dir(dir.as_deref()).ok());

    let resp = client
        .get_authed(&format!("/api/v1/repos/{owner}/{name}/star"))
        .await
        .context("failed to connect to node")?;

    let body = crate::http::read_json(resp, "star count").await?;

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
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock(
                "PUT",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/star$".to_string()),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"starred","repo":"z/myrepo","star_count":1}"#)
            .create_async()
            .await;

        cmd_add(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_add_already_starred_idempotent() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

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
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_add_no_identity_errors() {
        let dir = tempfile::TempDir::new().unwrap(); // no identity.pem written
        let err = cmd_add(
            "owner/myrepo".to_string(),
            "http://127.0.0.1:1".to_string(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("identity not found"));
    }

    #[tokio::test]
    async fn test_cmd_add_repo_not_found() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("PUT", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_add(
            "owner/missing".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("star failed"));
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
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
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_remove_not_found_errors() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("DELETE", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_remove(
            "owner/missing".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unstar failed"));
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
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

        cmd_count("alice/myrepo".to_string(), server.url(), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_count_requires_slash() {
        let err = cmd_count(
            "noslash".to_string(),
            "http://127.0.0.1:1".to_string(),
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("owner/repo format"));
    }

    #[test]
    fn test_resolve_owner_repo_with_slash() {
        let (owner, name) = resolve_owner_repo("alice/myrepo", None).unwrap();
        assert_eq!(owner, "alice");
        assert_eq!(name, "myrepo");
    }

    // U15 (#186): a converted handler must inherit read_json's capped + sanitized
    // error path end-to-end. A hostile 500 whose `message` carries terminal-control
    // + bidi bytes and is long must reach the terminal neither verbatim nor unbounded.
    #[tokio::test]
    async fn cmd_add_hostile_error_is_sanitized_and_bounded() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        // ESC + a long run + a right-to-left override, all inside the node message
        // (JSON \u escapes so the source has no raw control bytes).
        let hostile = format!(r#"{{"message":"a\u001b[31m{}b\u202ec"}}"#, "Z".repeat(500));
        let _m = server
            .mock("PUT", mockito::Matcher::Regex(r"/star$".to_string()))
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(hostile)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_add(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err()
        .to_string();

        assert!(
            !err.contains('\u{1b}'),
            "ESC leaked to the terminal: {err:?}"
        );
        assert!(!err.contains('\u{202e}'), "bidi override leaked: {err:?}");
        // Bounded: sanitize_node_msg caps the surfaced message, so the 500-char run
        // cannot flood the error string.
        assert!(err.len() < 300, "error not bounded ({} bytes)", err.len());
        assert!(err.contains("star failed"), "handler label lost: {err}");
        _m.assert_async().await;
    }
}
