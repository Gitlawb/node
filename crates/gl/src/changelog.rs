//! `gl changelog` — unified timeline of commits, merged PRs, and closed issues.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct ChangelogArgs {
    /// Repository name (owner/repo or just name — owner derived from identity)
    pub repo: Option<String>,
    /// Maximum number of events to show
    #[arg(long, default_value = "20")]
    pub limit: usize,
    #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
    pub node: String,
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

pub async fn run(args: ChangelogArgs) -> Result<()> {
    let repo = match &args.repo {
        Some(r) => r.clone(),
        None => {
            // Try to detect from git remote
            detect_repo_from_remote().unwrap_or_default()
        }
    };

    if repo.is_empty() {
        anyhow::bail!("no repo specified — pass <repo> or run from inside a gitlawb repo");
    }

    let (owner, name) = if let Some((o, n)) = repo.split_once('/') {
        (o.to_string(), n.to_string())
    } else {
        let short = if let Ok(kp) = load_keypair_from_dir(args.dir.as_deref()) {
            let did = kp.did().to_string();
            did.split(':').next_back().unwrap_or(&did).to_string()
        } else {
            let client = NodeClient::new(&args.node, None);
            let info = crate::http::read_json(client.get("/").await?, "node info").await?;
            let did = info["did"].as_str().context("node missing DID")?;
            did.split(':').next_back().unwrap_or(did).to_string()
        };
        (short, repo.clone())
    };

    let client = NodeClient::new(&args.node, None);
    let url = format!(
        "/api/v1/repos/{owner}/{name}/changelog?limit={}",
        args.limit
    );
    let resp = client
        .get(&url)
        .await
        .context("failed to connect to node")?;

    let body = crate::http::read_json(resp, "changelog").await?;

    let events = body["events"].as_array().cloned().unwrap_or_default();

    if events.is_empty() {
        println!("No activity yet in {owner}/{name}");
        return Ok(());
    }

    println!("Changelog — {owner}/{name}\n");

    for event in &events {
        let ts = event["timestamp"].as_str().unwrap_or("?");
        let date = &ts[..ts.len().min(10)];

        match event["type"].as_str().unwrap_or("") {
            "commit" => {
                let sha = event["sha"].as_str().unwrap_or("?");
                let msg = event["message"].as_str().unwrap_or("?");
                let first_line = msg.lines().next().unwrap_or(msg);
                let short_sha = &sha[..sha.len().min(8)];
                println!("  {date}  commit      {short_sha}  {first_line}");
            }
            "pr_merged" => {
                let n = event["number"].as_i64().unwrap_or(0);
                let title = event["title"].as_str().unwrap_or("?");
                println!("  {date}  pr merged   #{n}  {title}");
            }
            other => {
                println!("  {date}  {other}");
            }
        }
    }

    println!();
    Ok(())
}

/// Try to parse the repo from a gitlawb:// git remote.
fn detect_repo_from_remote() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let url = String::from_utf8(out.stdout).ok()?;
    let rest = url.trim().strip_prefix("gitlawb://")?;
    let slash = rest.rfind('/')?;
    let did = &rest[..slash];
    let repo = &rest[slash + 1..];
    let short_did = did.split(':').next_back().unwrap_or(did);
    Some(format!("{short_did}/{repo}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_changelog_empty() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/changelog".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"repo":"z/myrepo","events":[],"count":0}"#)
            .create_async()
            .await;

        let args = ChangelogArgs {
            repo: Some("myrepo".to_string()),
            limit: 20,
            node: server.url(),
            dir: Some(dir.path().to_path_buf()),
        };
        run(args).await.unwrap();
    }

    #[tokio::test]
    async fn test_changelog_with_commits_and_prs() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let body = r#"{
            "repo":"z/myrepo",
            "events":[
                {"type":"commit","sha":"abc123def456","message":"fix: trust score","author":"did:key:z6MkA","timestamp":"2026-03-21T10:00:00Z","branch":"main"},
                {"type":"pr_merged","number":3,"title":"Add changelog endpoint","author":"did:key:z6MkA","merged_by":"did:key:z6MkA","timestamp":"2026-03-20T09:00:00Z","source_branch":"feat/changelog","target_branch":"main"}
            ],
            "count":2
        }"#;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/changelog".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let args = ChangelogArgs {
            repo: Some("myrepo".to_string()),
            limit: 20,
            node: server.url(),
            dir: Some(dir.path().to_path_buf()),
        };
        run(args).await.unwrap();
    }

    #[tokio::test]
    async fn test_changelog_repo_not_found() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/changelog".to_string()))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .expect(1)
            .create_async()
            .await;

        let args = ChangelogArgs {
            repo: Some("missing/repo".to_string()),
            limit: 20,
            node: server.url(),
            dir: Some(dir.path().to_path_buf()),
        };
        let err = run(args).await.unwrap_err();
        assert!(err.to_string().contains("changelog failed"));
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_changelog_respects_limit_param() {
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
                mockito::Matcher::Regex(r"/changelog\?limit=5".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"repo":"z/myrepo","events":[],"count":0}"#)
            .create_async()
            .await;

        let args = ChangelogArgs {
            repo: Some("myrepo".to_string()),
            limit: 5,
            node: server.url(),
            dir: Some(dir.path().to_path_buf()),
        };
        run(args).await.unwrap();
        _m.assert_async().await;
    }

    #[test]
    fn test_no_repo_no_remote_errors() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let args = ChangelogArgs {
            repo: None,
            limit: 20,
            node: "http://127.0.0.1:1".to_string(),
            dir: Some(std::path::PathBuf::from("/tmp/no-such-dir")),
        };
        // Should error with "no repo specified"
        let err = rt.block_on(run(args)).unwrap_err();
        assert!(err.to_string().contains("no repo specified"));
    }

    #[tokio::test]
    async fn resolve_via_run_surfaces_denial() {
        // A slash-free repo with an empty identity dir forces the inline GET /
        // node-info fetch during resolution. A gated 404 there must Err (surfacing
        // the status), proving the read_json conversion is load-bearing.
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap(); // empty, no identity.pem, forces the GET / branch
        let _m = server
            .mock("GET", "/")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;
        let err = run(ChangelogArgs {
            repo: Some("noslash".to_string()),
            limit: 20,
            node: server.url(),
            dir: Some(dir.path().to_path_buf()),
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
        _m.assert_async().await;
    }
}
