//! `gl pr` — pull request management.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct PrArgs {
    #[command(subcommand)]
    pub cmd: PrCmd,
}

#[derive(Subcommand)]
pub enum PrCmd {
    /// Create a pull request
    Create {
        /// Repository name
        repo: String,
        /// Source branch (the branch with your changes)
        #[arg(long)]
        head: String,
        /// Target branch to merge into (default: main)
        #[arg(long, default_value = "main")]
        base: String,
        /// PR title
        #[arg(long, short)]
        title: String,
        /// PR body/description
        #[arg(long, short)]
        body: Option<String>,
        /// Repo owner DID short key (defaults to your DID — use when opening a PR on another user's repo)
        #[arg(long)]
        owner: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List pull requests for a repo
    List {
        /// Repository name
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show a pull request
    View {
        /// Repository name
        repo: String,
        /// PR number
        number: u64,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show the diff for a pull request
    Diff {
        /// Repository name
        repo: String,
        /// PR number
        number: u64,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Merge a pull request
    Merge {
        /// Repository name
        repo: String,
        /// PR number
        number: u64,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Review a pull request
    Review {
        /// Repository name
        repo: String,
        /// PR number
        number: u64,
        /// Review status: approved, changes_requested, or comment
        #[arg(long, default_value = "comment")]
        status: String,
        /// Review body
        #[arg(long, short)]
        body: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Post a comment on a pull request
    Comment {
        /// Repository name
        repo: String,
        /// PR number
        number: u64,
        /// Comment body
        #[arg(long, short)]
        body: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List comments on a pull request
    Comments {
        /// Repository name
        repo: String,
        /// PR number
        number: u64,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: PrArgs) -> Result<()> {
    match args.cmd {
        PrCmd::Create {
            repo,
            head,
            base,
            title,
            body,
            owner,
            node,
            dir,
        } => cmd_create(repo, head, base, title, body, owner, node, dir).await,
        PrCmd::List { repo, node, dir } => cmd_list(repo, node, dir).await,
        PrCmd::View {
            repo,
            number,
            node,
            dir,
        } => cmd_view(repo, number, node, dir).await,
        PrCmd::Diff {
            repo,
            number,
            node,
            dir,
        } => cmd_diff(repo, number, node, dir).await,
        PrCmd::Merge {
            repo,
            number,
            node,
            dir,
        } => cmd_merge(repo, number, node, dir).await,
        PrCmd::Review {
            repo,
            number,
            status,
            body,
            node,
            dir,
        } => cmd_review(repo, number, status, body, node, dir).await,
        PrCmd::Comment {
            repo,
            number,
            body,
            node,
            dir,
        } => cmd_comment(repo, number, body, node, dir).await,
        PrCmd::Comments {
            repo,
            number,
            node,
            dir,
        } => cmd_comments(repo, number, node, dir).await,
    }
}

fn resolve_owner(keypair: &gitlawb_core::identity::Keypair) -> String {
    let did = keypair.did().to_string();
    did.split(':').next_back().unwrap_or(&did).to_string()
}

/// Try to read the owner DID short key from the current git repo's origin remote.
/// Parses `gitlawb://did:key:z6Mk.../repo-name` → `z6Mk...`
fn detect_remote_owner() -> Option<String> {
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
    Some(did.split(':').next_back().unwrap_or(did).to_string())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_create(
    repo: String,
    head: String,
    base: String,
    title: String,
    body: Option<String>,
    owner_override: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    // Priority: --owner flag > git remote origin > caller's own DID
    let owner = owner_override
        .or_else(detect_remote_owner)
        .unwrap_or_else(|| resolve_owner(&keypair));
    let client = NodeClient::new(&node, Some(keypair));

    let payload = serde_json::to_vec(&serde_json::json!({
        "title": title,
        "body": body,
        "source_branch": head,
        "target_branch": base,
    }))?;

    let resp = client
        .post(&format!("/api/v1/repos/{owner}/{repo}/pulls"), &payload)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let pr: Value = resp.json().await.context("invalid JSON")?;

    if !status.is_success() {
        let msg = pr["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("create PR failed ({status}): {msg}");
    }

    let number = pr["number"].as_i64().unwrap_or(0);
    println!("✓ Opened PR #{number}: {title}");
    println!("  {} → {}", head, base);
    println!("  View: gl pr view {repo} {number}");
    println!("  Diff: gl pr diff {repo} {number}");
    Ok(())
}

async fn cmd_list(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let owner = resolve_owner(&keypair);
    let client = NodeClient::new(&node, None);

    let resp: Value = client
        .get(&format!("/api/v1/repos/{owner}/{repo}/pulls"))
        .await?
        .json()
        .await
        .context("invalid JSON")?;

    let prs = resp["pulls"].as_array().cloned().unwrap_or_default();
    if prs.is_empty() {
        println!("No pull requests for {repo}");
        return Ok(());
    }

    println!("Pull requests for {repo} ({} total)\n", prs.len());
    for pr in &prs {
        let number = pr["number"].as_i64().unwrap_or(0);
        let title = pr["title"].as_str().unwrap_or("?");
        let status = pr["status"].as_str().unwrap_or("?");
        let source = pr["source_branch"].as_str().unwrap_or("?");
        let target = pr["target_branch"].as_str().unwrap_or("?");
        let author = pr["author_did"].as_str().unwrap_or("?");
        let author_short = author
            .split(':')
            .next_back()
            .map(|s| &s[..s.len().min(8)])
            .unwrap_or("?");
        let status_icon = match status {
            "open" => "○",
            "merged" => "✓",
            "closed" => "✗",
            _ => "?",
        };
        println!("  {status_icon} #{number}  {title}");
        println!("     {source} → {target}  by {author_short}");
        println!();
    }
    Ok(())
}

async fn cmd_view(repo: String, number: u64, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let owner = resolve_owner(&keypair);
    let client = NodeClient::new(&node, None);

    let pr: Value = client
        .get(&format!("/api/v1/repos/{owner}/{repo}/pulls/{number}"))
        .await?
        .json()
        .await
        .context("invalid JSON")?;

    let title = pr["title"].as_str().unwrap_or("?");
    let status = pr["status"].as_str().unwrap_or("?");
    let source = pr["source_branch"].as_str().unwrap_or("?");
    let target = pr["target_branch"].as_str().unwrap_or("?");
    let author = pr["author_did"].as_str().unwrap_or("?");
    let body = pr["body"].as_str().unwrap_or("");

    println!("PR #{number}: {title}");
    println!("  Status: {status}");
    println!("  Branch: {source} → {target}");
    println!("  Author: {author}");
    if !body.is_empty() {
        println!("\n{body}");
    }

    // Show reviews
    let reviews: Value = client
        .get(&format!(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews"
        ))
        .await?
        .json()
        .await
        .context("invalid JSON")?;
    let reviews = reviews["reviews"].as_array().cloned().unwrap_or_default();
    if !reviews.is_empty() {
        println!("\nReviews ({}):", reviews.len());
        for r in &reviews {
            let reviewer = r["reviewer_did"].as_str().unwrap_or("?");
            let reviewer_short = reviewer
                .split(':')
                .next_back()
                .map(|s| &s[..s.len().min(8)])
                .unwrap_or("?");
            let rstatus = r["status"].as_str().unwrap_or("?");
            let rbody = r["body"].as_str().unwrap_or("");
            let icon = match rstatus {
                "approved" => "✓",
                "changes_requested" => "✗",
                _ => "·",
            };
            println!("  {icon} {reviewer_short}: {rstatus}");
            if !rbody.is_empty() {
                println!("    {rbody}");
            }
        }
    }

    // Show comments
    let comments: Value = client
        .get(&format!(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/comments"
        ))
        .await?
        .json()
        .await
        .context("invalid JSON")?;
    let comments = comments["comments"].as_array().cloned().unwrap_or_default();
    if !comments.is_empty() {
        println!("\nComments ({}):", comments.len());
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
        }
    }
    Ok(())
}

async fn cmd_diff(repo: String, number: u64, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let owner = resolve_owner(&keypair);
    let client = NodeClient::new(&node, None);

    let resp: Value = client
        .get(&format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/diff"))
        .await?
        .json()
        .await
        .context("invalid JSON")?;

    let diff = resp["diff"].as_str().unwrap_or("");
    if diff.is_empty() {
        println!("No diff (branches may be identical or branches not found)");
    } else {
        println!("{diff}");
    }
    Ok(())
}

async fn cmd_merge(repo: String, number: u64, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let owner = resolve_owner(&keypair);
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&serde_json::json!({}))?;
    let resp = client
        .post(
            &format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/merge"),
            &body,
        )
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("merge failed ({status}): {msg}");
    }

    let sha = result["merge_sha"].as_str().unwrap_or("?");
    println!("✓ Merged PR #{number}");
    println!("  Merge commit: {}", &sha[..sha.len().min(12)]);
    Ok(())
}

async fn cmd_review(
    repo: String,
    number: u64,
    status: String,
    body: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let owner = resolve_owner(&keypair);
    let client = NodeClient::new(&node, Some(keypair));

    let payload = serde_json::to_vec(&serde_json::json!({
        "status": status,
        "body": body,
    }))?;

    let resp = client
        .post(
            &format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews"),
            &payload,
        )
        .await
        .context("failed to connect to node")?;
    let code = resp.status();
    let result: Value = resp.json().await.context("invalid JSON")?;

    if !code.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("review failed ({code}): {msg}");
    }

    let icon = match status.as_str() {
        "approved" => "✓",
        "changes_requested" => "✗",
        _ => "·",
    };
    println!("{icon} Review submitted: {status} on PR #{number}");
    Ok(())
}

async fn cmd_comment(
    repo: String,
    number: u64,
    body: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let owner = resolve_owner(&keypair);
    let client = NodeClient::new(&node, Some(keypair));

    let payload = serde_json::to_vec(&serde_json::json!({ "body": body }))?;
    let resp = client
        .post(
            &format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/comments"),
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

    println!("· Comment posted on PR #{number}");
    Ok(())
}

async fn cmd_comments(repo: String, number: u64, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let owner = resolve_owner(&keypair);
    let client = NodeClient::new(&node, None);

    let resp: Value = client
        .get(&format!(
            "/api/v1/repos/{owner}/{repo}/pulls/{number}/comments"
        ))
        .await?
        .json()
        .await
        .context("invalid JSON")?;

    let comments = resp["comments"].as_array().cloned().unwrap_or_default();
    if comments.is_empty() {
        println!("No comments on PR #{number}");
        return Ok(());
    }

    println!("Comments on PR #{number} ({} total)\n", comments.len());
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

    #[test]
    fn test_resolve_owner_extracts_key_segment() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let owner = resolve_owner(&kp);
        assert!(!owner.contains(':'));
        assert!(owner.starts_with('z'));
    }

    #[tokio::test]
    async fn test_cmd_list_no_prs() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"pulls":[]}"#)
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
    async fn test_cmd_list_with_prs() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"pulls":[{"number":1,"title":"Add feature","status":"open","source_branch":"feat","target_branch":"main","author_did":"did:key:z6MkTest"}]}"#)
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
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"number":3,"title":"My PR"}"#)
            .create_async()
            .await;

        cmd_create(
            "myrepo".to_string(),
            "feat".to_string(),
            "main".to_string(),
            "My PR".to_string(),
            None,
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
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls$".to_string()),
            )
            .with_status(422)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"branch not found"}"#)
            .create_async()
            .await;

        let result = cmd_create(
            "myrepo".to_string(),
            "missing-branch".to_string(),
            "main".to_string(),
            "My PR".to_string(),
            None,
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("branch not found"));
    }

    #[tokio::test]
    async fn test_cmd_view_shows_pr() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m1 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls/1$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"number":1,"title":"Fix it","status":"open","source_branch":"fix","target_branch":"main","author_did":"did:key:z6MkTest","body":"some body"}"#)
            .create_async()
            .await;
        let _m2 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/pulls/1/reviews$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"reviews":[]}"#)
            .create_async()
            .await;
        let _m3 = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/pulls/1/comments$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"comments":[]}"#)
            .create_async()
            .await;

        cmd_view(
            "myrepo".to_string(),
            1,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_comment_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls/1/comments$".to_string()),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"c1","pr_id":"pr1","author_did":"did:key:z6MkTest","body":"looks good","created_at":"2026-03-23T00:00:00Z"}"#)
            .create_async()
            .await;

        cmd_comment(
            "myrepo".to_string(),
            1,
            "looks good".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_comment_server_error() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/pulls/99/comments$".to_string(),
                ),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"PR not found"}"#)
            .create_async()
            .await;

        let err = cmd_comment(
            "myrepo".to_string(),
            99,
            "hello".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("PR not found"), "got: {err}");
    }

    #[tokio::test]
    async fn test_cmd_comments_empty() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/pulls/1/comments$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"comments":[]}"#)
            .create_async()
            .await;

        cmd_comments(
            "myrepo".to_string(),
            1,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_comments_with_results() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls/2/comments$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"comments":[{"id":"c1","pr_id":"pr1","author_did":"did:key:z6MkTest","body":"nice work","created_at":"2026-03-23T00:00:00Z"}]}"#)
            .create_async()
            .await;

        cmd_comments(
            "myrepo".to_string(),
            2,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_merge_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/pulls/2/merge$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"merge_sha":"abc123def456789"}"#)
            .create_async()
            .await;

        cmd_merge(
            "myrepo".to_string(),
            2,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }
}
