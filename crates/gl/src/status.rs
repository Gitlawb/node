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
        let resp = client.get(&format!("/api/v1/agents/{short_key}")).await;
        if let Some(line) = trust_line(resp).await {
            println!("{line}");
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
        if let Some(line) = section_unavailable_line("PRs", &pr_resp) {
            println!("{line}");
        } else if let Ok(r) = pr_resp {
            if let Ok(body) = r.json::<Value>().await {
                let prs = body["pulls"].as_array().cloned().unwrap_or_default();
                let open: Vec<_> = prs
                    .iter()
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
        if let Some(line) = section_unavailable_line("issues", &issue_resp) {
            println!("{line}");
        } else if let Ok(r) = issue_resp {
            if let Ok(body) = r.json::<Value>().await {
                let issues = body["issues"].as_array().cloned().unwrap_or_default();
                let open: Vec<_> = issues
                    .iter()
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

/// The status line for a repo section (PRs / issues) whose gated read returned a
/// non-2xx: the denial must surface, never render as "no open ..." (INV-8).
/// Returns `None` for a success (the caller renders the body) or a transport error
/// (the section degrades silently — R5 — so the multi-section `gl status` never
/// hard-fails on one denied read).
fn section_unavailable_line(label: &str, resp: &Result<reqwest::Response>) -> Option<String> {
    match resp {
        Ok(r) if !r.status().is_success() => {
            Some(format!("  {label:<10}unavailable ({})", r.status()))
        }
        _ => None,
    }
}

/// The `trust` status line for the caller's own identity. A genuine 404 means the
/// identity is not registered; any OTHER non-2xx (403/429/5xx) is a failed lookup
/// and must surface as unavailable rather than fabricating an unregistered state
/// (INV-8). A transport error degrades silently — the node-unreachable line below
/// already surfaces it — matching `section_unavailable_line`.
async fn trust_line(resp: Result<reqwest::Response>) -> Option<String> {
    match resp {
        Ok(r) if r.status().is_success() => {
            let body = r.json::<Value>().await.ok()?;
            let score = body["trust_score"].as_f64().unwrap_or(0.0);
            Some(format!("  trust     {score:.2}  {}", trust_bar(score)))
        }
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
            Some("  trust     — not registered (run `gl register`)".to_string())
        }
        Ok(r) => Some(format!("  trust     unavailable ({})", r.status())),
        Err(_) => None,
    }
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
    if !out.status.success() {
        return None;
    }
    let url = String::from_utf8(out.stdout).ok()?;
    let rest = url.trim().strip_prefix("gitlawb://")?;
    let slash = rest.rfind('/')?;
    let did = rest[..slash].to_string();
    let repo = rest[slash + 1..].to_string();
    if did.is_empty() || repo.is_empty() {
        return None;
    }
    Some((did, repo))
}

/// Parse a gitlawb:// URL string into (did, repo) — extracted for testing.
#[cfg(test)]
fn parse_gitlawb_url(url: &str) -> Option<(String, String)> {
    let rest = url.trim().strip_prefix("gitlawb://")?;
    let slash = rest.rfind('/')?;
    let did = rest[..slash].to_string();
    let repo = rest[slash + 1..].to_string();
    if did.is_empty() || repo.is_empty() {
        return None;
    }
    Some((did, repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_gitlawb_url() {
        let result = parse_gitlawb_url("gitlawb://did:key:z6Mk1234/myrepo");
        assert_eq!(
            result,
            Some(("did:key:z6Mk1234".to_string(), "myrepo".to_string()))
        );
    }

    #[test]
    fn parse_gitlawb_url_with_newline() {
        let result = parse_gitlawb_url("gitlawb://did:key:z6Mk1234/myrepo\n");
        assert_eq!(
            result,
            Some(("did:key:z6Mk1234".to_string(), "myrepo".to_string()))
        );
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
        assert_eq!(
            result,
            Some(("did:key:z6MkAbc".to_string(), "my-cool-repo".to_string()))
        );
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
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/agents/".to_string()),
            )
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

    // ── gl status section denial surfacing (#123 / INV-8, R5) ────────────

    async fn get_response(
        server: &mut mockito::Server,
        status: usize,
    ) -> Result<reqwest::Response> {
        let _m = server
            .mock("GET", "/x")
            .with_status(status)
            .with_header("content-type", "application/json")
            .with_body(r#"{"pulls":[]}"#)
            .create_async()
            .await;
        NodeClient::new(server.url(), None).get("/x").await
    }

    #[tokio::test]
    async fn gated_section_surfaces_unavailable_not_empty() {
        // A gated 404 on a status section must surface "unavailable", never be
        // treated as "no open PRs" (INV-8).
        let mut server = mockito::Server::new_async().await;
        let resp = get_response(&mut server, 404).await;
        assert_eq!(
            section_unavailable_line("PRs", &resp),
            Some(format!("  {:<10}unavailable (404 Not Found)", "PRs"))
        );
    }

    #[tokio::test]
    async fn success_section_returns_none_for_body_render() {
        // A 2xx returns None so the caller renders the body as before.
        let mut server = mockito::Server::new_async().await;
        let resp = get_response(&mut server, 200).await;
        assert!(section_unavailable_line("issues", &resp).is_none());
    }

    #[test]
    fn transport_error_degrades_silently() {
        // A transport error (not a status) must NOT surface — the section
        // degrades silently so gl status never hard-fails on one bad read (R5).
        let err: Result<reqwest::Response> = Err(anyhow::anyhow!("connection refused"));
        assert!(section_unavailable_line("PRs", &err).is_none());
    }

    // ── trust_line: a 404 means unregistered; any OTHER failure must surface as
    //    unavailable, never fabricate an unregistered verdict (INV-8). ──────────
    async fn agents_resp(
        server: &mut mockito::Server,
        status: usize,
        body: &str,
    ) -> Result<reqwest::Response> {
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/agents/".to_string()),
            )
            .with_status(status)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;
        NodeClient::new(server.url(), None)
            .get("/api/v1/agents/zTest")
            .await
    }

    #[tokio::test]
    async fn trust_line_registered_shows_score_only() {
        let mut s = mockito::Server::new_async().await;
        let line = trust_line(agents_resp(&mut s, 200, r#"{"trust_score":0.5}"#).await)
            .await
            .unwrap();
        assert!(line.contains("0.50"), "line={line}");
        assert!(!line.contains("not registered"), "line={line}");
        assert!(!line.contains("unavailable"), "line={line}");
    }

    #[tokio::test]
    async fn trust_line_404_is_not_registered() {
        let mut s = mockito::Server::new_async().await;
        let line = trust_line(agents_resp(&mut s, 404, r#"{"message":"agent not found"}"#).await)
            .await
            .unwrap();
        assert!(line.contains("not registered"), "line={line}");
        assert!(!line.contains("unavailable"), "line={line}");
    }

    // Load-bearing: a 403 for an existing identity is a denied lookup, not proof it is unregistered.
    #[tokio::test]
    async fn trust_line_403_is_unavailable_not_registered() {
        let mut s = mockito::Server::new_async().await;
        let line = trust_line(agents_resp(&mut s, 403, r#"{"message":"forbidden"}"#).await)
            .await
            .unwrap();
        assert!(
            line.contains("unavailable") && line.contains("403"),
            "line={line}"
        );
        assert!(!line.contains("not registered"), "line={line}");
    }

    // Load-bearing: a 5xx is a failed lookup, not an unregistered verdict.
    #[tokio::test]
    async fn trust_line_500_is_unavailable_not_registered() {
        let mut s = mockito::Server::new_async().await;
        let line = trust_line(agents_resp(&mut s, 500, r#"{"message":"boom"}"#).await)
            .await
            .unwrap();
        assert!(line.contains("unavailable"), "line={line}");
        assert!(!line.contains("not registered"), "line={line}");
    }

    // Load-bearing: a transport error degrades silently, never fabricates unregistered.
    #[tokio::test]
    async fn trust_line_transport_error_is_silent() {
        let resp = NodeClient::new("http://127.0.0.1:1", None)
            .get("/api/v1/agents/zTest")
            .await;
        assert!(trust_line(resp).await.is_none());
    }
}
