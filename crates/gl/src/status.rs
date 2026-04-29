//! `gl status` — snapshot of your current context: identity, node, repo, open work.

use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct StatusArgs {
    #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
    pub node: String,
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

pub async fn run(args: StatusArgs) -> Result<()> {
    let dir = args.dir.as_deref();

    // ── Identity + trust score ─────────────────────────────────────────────
    let maybe_did = match load_keypair_from_dir(dir) {
        Ok(kp) => {
            let did = kp.did().to_string();
            let short = did.chars().take(40).collect::<String>();
            println!("  identity  {short}…");
            Some(did)
        }
        Err(_) => {
            println!("  identity  ✗ not found — run `gl identity new`");
            None
        }
    };

    // ── Trust score ───────────────────────────────────────────────────────
    let client = NodeClient::new(&args.node, None);
    if let Some(ref did) = maybe_did {
        let short_key = did.split(':').next_back().unwrap_or(did);
        match client.get(&format!("/api/v1/agents/{short_key}")).await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<Value>().await {
                    let score = body["trust_score"].as_f64().unwrap_or(0.0);
                    let bar = trust_bar(score);
                    println!("  trust     {score:.2}  {bar}");
                }
            }
            _ => {
                println!("  trust     — not registered (run `gl register`)");
            }
        }
    }

    // ── Current git repo + gitlawb remote ─────────────────────────────────
    let remote = detect_gitlawb_remote();
    match &remote {
        Some((did, repo)) => {
            let short_did = did.split(':').next_back().unwrap_or(did);
            println!("  repo      {short_did}/{repo}");
        }
        None => {
            println!("  repo      (not in a gitlawb repo — no gitlawb:// origin)");
        }
    }

    // ── Node ──────────────────────────────────────────────────────────────
    match client.get("/").await {
        Ok(resp) if resp.status().is_success() => {
            let info = resp.json::<Value>().await.unwrap_or_default();
            let version = info["version"].as_str().unwrap_or("?");
            println!("  node      {} (v{version})", args.node);
        }
        _ => {
            println!("  node      ✗ {} unreachable", args.node);
        }
    }

    // ── Open PRs in current repo ──────────────────────────────────────────
    if let Some((owner_did, repo_name)) = &remote {
        let short_owner = owner_did.split(':').next_back().unwrap_or(owner_did);
        let pr_resp = client
            .get(&format!("/api/v1/repos/{short_owner}/{repo_name}/pulls"))
            .await;
        if let Ok(r) = pr_resp {
            if let Ok(body) = r.json::<Value>().await {
                let prs = body["pulls"].as_array().cloned().unwrap_or_default();
                let open: Vec<_> = prs.iter()
                    .filter(|p| p["status"].as_str() == Some("open"))
                    .collect();
                if open.is_empty() {
                    println!("  PRs       no open pull requests");
                } else {
                    println!("  PRs       {} open", open.len());
                    for pr in open.iter().take(3) {
                        let n = pr["number"].as_i64().unwrap_or(0);
                        let title = pr["title"].as_str().unwrap_or("?");
                        println!("            #{n}  {title}");
                    }
                    if open.len() > 3 {
                        println!("            … and {} more", open.len() - 3);
                    }
                }
            }
        }

        // ── Open issues ───────────────────────────────────────────────────
        let issue_resp = client
            .get(&format!("/api/v1/repos/{short_owner}/{repo_name}/issues"))
            .await;
        if let Ok(r) = issue_resp {
            if let Ok(body) = r.json::<Value>().await {
                let issues = body["issues"].as_array().cloned().unwrap_or_default();
                let open: Vec<_> = issues.iter()
                    .filter(|i| i["status"].as_str() == Some("open"))
                    .collect();
                if open.is_empty() {
                    println!("  issues    no open issues");
                } else {
                    println!("  issues    {} open", open.len());
                    for issue in open.iter().take(3) {
                        let id = issue["id"].as_str().unwrap_or("?");
                        let title = issue["title"].as_str().unwrap_or("?");
                        println!("            {:.8}  {title}", id);
                    }
                    if open.len() > 3 {
                        println!("            … and {} more", open.len() - 3);
                    }
                }
            }
        }
    }

    println!();
    Ok(())
}

/// Render a simple ASCII trust bar: 0.75 → "███░"
fn trust_bar(score: f64) -> String {
    let filled = (score * 4.0).round() as usize;
    let empty = 4usize.saturating_sub(filled);
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

/// Parse `gitlawb://<did>/<repo>` from the git origin remote.
fn detect_gitlawb_remote() -> Option<(String, String)> {
    let out = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() { return None; }
    let url = String::from_utf8(out.stdout).ok()?;
    let rest = url.trim().strip_prefix("gitlawb://")?;
    let slash = rest.rfind('/')?;
    let did = rest[..slash].to_string();
    let repo = rest[slash + 1..].to_string();
    if did.is_empty() || repo.is_empty() { return None; }
    Some((did, repo))
}

/// Parse a gitlawb:// URL string into (did, repo) — extracted for testing.
#[cfg(test)]
fn parse_gitlawb_url(url: &str) -> Option<(String, String)> {
    let rest = url.trim().strip_prefix("gitlawb://")?;
    let slash = rest.rfind('/')?;
    let did = rest[..slash].to_string();
    let repo = rest[slash + 1..].to_string();
    if did.is_empty() || repo.is_empty() { return None; }
    Some((did, repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_gitlawb_url() {
        let result = parse_gitlawb_url("gitlawb://did:key:z6Mk1234/myrepo");
        assert_eq!(result, Some(("did:key:z6Mk1234".to_string(), "myrepo".to_string())));
    }

    #[test]
    fn parse_gitlawb_url_with_newline() {
        let result = parse_gitlawb_url("gitlawb://did:key:z6Mk1234/myrepo\n");
        assert_eq!(result, Some(("did:key:z6Mk1234".to_string(), "myrepo".to_string())));
    }

    #[test]
    fn parse_non_gitlawb_url_returns_none() {
        assert!(parse_gitlawb_url("https://github.com/user/repo").is_none());
        assert!(parse_gitlawb_url("git@github.com:user/repo.git").is_none());
    }

    #[test]
    fn parse_gitlawb_url_empty_repo_returns_none() {
        assert!(parse_gitlawb_url("gitlawb://did:key:z6Mk1234/").is_none());
    }

    #[test]
    fn parse_gitlawb_url_no_slash_returns_none() {
        assert!(parse_gitlawb_url("gitlawb://did:key:z6Mk1234").is_none());
    }

    #[test]
    fn parse_gitlawb_url_repo_name_with_dash() {
        let result = parse_gitlawb_url("gitlawb://did:key:z6MkAbc/my-cool-repo");
        assert_eq!(result, Some(("did:key:z6MkAbc".to_string(), "my-cool-repo".to_string())));
    }

    #[tokio::test]
    async fn test_node_unreachable_does_not_panic() {
        // Connects to a port that should refuse — status should still print gracefully
        let args = StatusArgs {
            node: "http://127.0.0.1:1".to_string(),
            dir: Some(std::path::PathBuf::from("/tmp/nonexistent-gitlawb-test")),
        };
        // Should not panic — just print errors gracefully
        let _ = run(args).await;
    }

    #[tokio::test]
    async fn test_status_with_live_node_health_check() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version":"0.2.2","did":"did:key:z6MkNode"}"#)
            .create_async()
            .await;

        let args = StatusArgs {
            node: server.url(),
            dir: Some(std::path::PathBuf::from("/tmp/nonexistent-gitlawb-test")),
        };
        let _ = run(args).await;
    }

    #[tokio::test]
    async fn test_status_shows_trust_score() {
        let mut server = mockito::Server::new_async().await;
        let _health = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version":"0.2.5","did":"did:key:z6MkNode"}"#)
            .create_async()
            .await;

        // Trust endpoint will be called with the short key segment — use a wildcard mock
        let _trust = server
            .mock("GET", mockito::Matcher::Regex(r"^/api/v1/agents/".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:z6MkTest","trust_score":0.15,"capabilities":["git:push"],"registered_at":"2026-03-20T00:00:00Z"}"#)
            .create_async()
            .await;

        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();

        let args = StatusArgs {
            node: server.url(),
            dir: Some(dir.path().to_path_buf()),
        };
        let _ = run(args).await;
    }

    #[tokio::test]
    async fn test_status_unregistered_shows_hint() {
        let mut server = mockito::Server::new_async().await;
        let _health = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"version":"0.2.5","did":"did:key:z6MkNode"}"#)
            .create_async()
            .await;
        let _trust = server
            .mock("GET", mockito::Matcher::Regex(r"^/api/v1/agents/".to_string()))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create_async()
            .await;

        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();

        let args = StatusArgs {
            node: server.url(),
            dir: Some(dir.path().to_path_buf()),
        };
        let _ = run(args).await;
    }

    #[test]
    fn trust_bar_empty() {
        assert_eq!(trust_bar(0.0), "░░░░");
    }

    #[test]
    fn trust_bar_full() {
        assert_eq!(trust_bar(1.0), "████");
    }

    #[test]
    fn trust_bar_half() {
        assert_eq!(trust_bar(0.5), "██░░");
    }

    #[test]
    fn trust_bar_quarter() {
        assert_eq!(trust_bar(0.25), "█░░░");
    }
}
