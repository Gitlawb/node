//! `gl bounty` — manage token-powered bounties on repositories.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

fn signed_client(node: &str, dir: Option<&std::path::Path>) -> NodeClient {
    NodeClient::new(node, load_keypair_from_dir(dir).ok())
}

#[derive(Args)]
pub struct BountyArgs {
    #[command(subcommand)]
    pub cmd: BountyCmd,
}

#[derive(Subcommand)]
pub enum BountyCmd {
    /// Create a bounty on a repository issue
    Create {
        /// Repository in owner/repo format
        repo: String,
        /// Bounty title
        #[arg(long)]
        title: String,
        /// Amount in $GITLAWB (integer, no decimals)
        #[arg(long)]
        amount: i64,
        /// Issue ID to attach the bounty to
        #[arg(long)]
        issue: Option<String>,
        /// On-chain escrow tx hash
        #[arg(long)]
        tx_hash: Option<String>,
        /// Deadline in seconds (default 7 days)
        #[arg(long)]
        deadline: Option<i64>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List bounties (global or per-repo)
    List {
        /// Optional repo in owner/repo format
        repo: Option<String>,
        /// Filter by status: open, claimed, submitted, completed
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show details of a specific bounty
    Show {
        /// Bounty ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Claim an open bounty
    Claim {
        /// Bounty ID
        id: String,
        /// Your wallet address for payout
        #[arg(long)]
        wallet: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Submit a PR as bounty completion
    Submit {
        /// Bounty ID
        id: String,
        /// Pull request ID
        #[arg(long)]
        pr: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Approve a bounty completion (as the bounty creator)
    Approve {
        /// Bounty ID
        id: String,
        /// On-chain payout tx hash
        #[arg(long)]
        tx_hash: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Cancel an open bounty
    Cancel {
        /// Bounty ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show bounty stats and leaderboard
    Stats {
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
}

pub async fn run(args: BountyArgs) -> Result<()> {
    match args.cmd {
        BountyCmd::Create {
            repo,
            title,
            amount,
            issue,
            tx_hash,
            deadline,
            node,
            dir,
        } => cmd_create(repo, title, amount, issue, tx_hash, deadline, node, dir).await,
        BountyCmd::List {
            repo,
            status,
            node,
            dir,
        } => cmd_list(repo, status, node, dir).await,
        BountyCmd::Show { id, node, dir } => cmd_show(id, node, dir).await,
        BountyCmd::Claim {
            id,
            wallet,
            node,
            dir,
        } => cmd_claim(id, wallet, node, dir).await,
        BountyCmd::Submit { id, pr, node, dir } => cmd_submit(id, pr, node, dir).await,
        BountyCmd::Approve {
            id,
            tx_hash,
            node,
            dir,
        } => cmd_approve(id, tx_hash, node, dir).await,
        BountyCmd::Cancel { id, node, dir } => cmd_cancel(id, node, dir).await,
        BountyCmd::Stats { node } => cmd_stats(node).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_create(
    repo: String,
    title: String,
    amount: i64,
    issue: Option<String>,
    tx_hash: Option<String>,
    deadline: Option<i64>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let (owner, name) = repo
        .split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .context("use owner/repo format")?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::json!({
        "title": title,
        "amount": amount,
        "issue_id": issue,
        "tx_hash": tx_hash,
        "deadline_secs": deadline,
    });

    let resp = client
        .post(
            &format!("/api/v1/repos/{owner}/{name}/bounties"),
            &serde_json::to_vec(&body)?,
        )
        .await
        .context("failed to connect to node")?;

    let body = crate::http::read_json(resp, "create bounty").await?;

    let id = body["id"].as_str().unwrap_or("?");
    println!("Bounty created: {id}");
    println!("  title:  {title}");
    println!("  amount: {amount} $GITLAWB");
    println!("  status: open");
    Ok(())
}

async fn cmd_list(
    repo: Option<String>,
    status: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let client = signed_client(&node, dir.as_deref());

    let url = if let Some(ref repo) = repo {
        let (owner, name) = repo
            .split_once('/')
            .map(|(o, n)| (o.to_string(), n.to_string()))
            .context("use owner/repo format")?;
        let mut u = format!("/api/v1/repos/{owner}/{name}/bounties");
        if let Some(ref s) = status {
            u.push_str(&format!("?status={s}"));
        }
        u
    } else {
        let mut u = "/api/v1/bounties".to_string();
        if let Some(ref s) = status {
            u.push_str(&format!("?status={s}"));
        }
        u
    };

    let body = crate::http::read_json(
        client
            .get_authed(&url)
            .await
            .context("failed to connect to node")?,
        "bounties",
    )
    .await?;

    let bounties = body["bounties"].as_array();
    if let Some(arr) = bounties {
        if arr.is_empty() {
            println!("No bounties found.");
        } else {
            for b in arr {
                let id = b["id"].as_str().unwrap_or("?");
                let title = b["title"].as_str().unwrap_or("?");
                let amount = b["amount"].as_i64().unwrap_or(0);
                let st = b["status"].as_str().unwrap_or("?");
                let short_id = &id[..8.min(id.len())];
                println!("{short_id}  {st:<10}  {amount:>12} $GITLAWB  {title}");
            }
        }
    }
    Ok(())
}

async fn cmd_show(id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let client = signed_client(&node, dir.as_deref());
    let resp = client.get_authed(&format!("/api/v1/bounties/{id}")).await?;

    let body = crate::http::read_json(resp, "show bounty").await?;

    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn cmd_claim(
    id: String,
    wallet: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::json!({ "wallet": wallet });
    let resp = client
        .post(
            &format!("/api/v1/bounties/{id}/claim"),
            &serde_json::to_vec(&body)?,
        )
        .await?;

    let _ = crate::http::read_json(resp, "claim").await?;

    println!("Bounty {id} claimed. Deadline starts now.");
    Ok(())
}

async fn cmd_submit(id: String, pr: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::json!({ "pr_id": pr });
    let resp = client
        .post(
            &format!("/api/v1/bounties/{id}/submit"),
            &serde_json::to_vec(&body)?,
        )
        .await?;

    let _ = crate::http::read_json(resp, "submit").await?;

    println!("Bounty {id} submitted with PR {pr}. Awaiting creator approval.");
    Ok(())
}

async fn cmd_approve(
    id: String,
    tx_hash: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::json!({ "tx_hash": tx_hash });
    let resp = client
        .post(
            &format!("/api/v1/bounties/{id}/approve"),
            &serde_json::to_vec(&body)?,
        )
        .await?;

    let _ = crate::http::read_json(resp, "approve").await?;

    println!("Bounty {id} approved! Payout released to agent.");
    Ok(())
}

async fn cmd_cancel(id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::json!({});
    let resp = client
        .post(
            &format!("/api/v1/bounties/{id}/cancel"),
            &serde_json::to_vec(&body)?,
        )
        .await?;

    let _ = crate::http::read_json(resp, "cancel").await?;

    println!("Bounty {id} cancelled. Tokens refunded.");
    Ok(())
}

async fn cmd_stats(node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    // Route through read_json so a node denial (403/404/5xx, incl. a non-JSON
    // body) surfaces as an error instead of a fake `Bounty Stats` with every
    // counter zeroed (#186, the denial-as-success class #123 fixes elsewhere).
    let body =
        crate::http::read_json(client.get("/api/v1/bounties/stats").await?, "bounty stats").await?;

    let open = body["open"].as_i64().unwrap_or(0);
    let claimed = body["claimed"].as_i64().unwrap_or(0);
    let completed = body["completed"].as_i64().unwrap_or(0);

    println!("Bounty Stats");
    println!("  open:      {open}");
    println!("  claimed:   {claimed}");
    println!("  completed: {completed}");

    if let Some(leaders) = body["leaderboard"].as_array() {
        if !leaders.is_empty() {
            println!("\nTop Agents:");
            for (i, entry) in leaders.iter().enumerate() {
                let did = entry["did"].as_str().unwrap_or("?");
                let count = entry["completed"].as_i64().unwrap_or(0);
                let earned = entry["total_earned"].as_i64().unwrap_or(0);
                let short = &did[did.len().saturating_sub(8)..];
                println!(
                    "  {}. ...{short}  {count} bounties  {earned} $GITLAWB",
                    i + 1
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_bounty_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", mockito::Matcher::Regex(r"/bounties$".to_string()))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"abc-123","title":"Fix bug","amount":50000,"status":"open"}"#)
            .create_async()
            .await;

        cmd_create(
            "owner/repo".to_string(),
            "Fix bug".to_string(),
            50000,
            None,
            None,
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_bounty_no_identity_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = cmd_create(
            "owner/repo".to_string(),
            "Fix bug".to_string(),
            50000,
            None,
            None,
            None,
            "http://127.0.0.1:1".to_string(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("identity not found"));
    }

    #[tokio::test]
    async fn test_list_bounties_empty() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/bounties".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"bounties":[]}"#)
            .create_async()
            .await;

        cmd_list(None, None, server.url(), None).await.unwrap();
    }

    #[tokio::test]
    async fn test_claim_bounty_success() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", mockito::Matcher::Regex(r"/claim$".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"abc-123","status":"claimed"}"#)
            .create_async()
            .await;

        cmd_claim(
            "abc-123".to_string(),
            Some("0xWALLET".to_string()),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_show_bounty_not_found() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/bounties/".to_string()))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_show("nonexistent".to_string(), server.url(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found"));
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_stats_success() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/stats$".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"open":5,"claimed":2,"completed":10,"leaderboard":[{"did":"did:key:z6Mk_test","completed":3,"total_earned":150000}]}"#)
            .create_async()
            .await;

        cmd_stats(server.url()).await.unwrap();
    }

    /// #186 (F1): a node denial on the stats endpoint must surface as an error,
    /// not print a fake `Bounty Stats` with every counter zeroed. RED before the
    /// fix (unwrap_or_default + no status check -> Ok with zeros), GREEN after
    /// (read_json bails on the non-2xx).
    #[tokio::test]
    async fn cmd_stats_surfaces_denial_not_fake_result() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/stats$".to_string()))
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"forbidden"}"#)
            .create_async()
            .await;

        let err = cmd_stats(server.url())
            .await
            .expect_err("a 403 must be an error, not a zeroed fake result");
        assert!(err.to_string().contains("403"), "err={err}");
    }

    /// #186 (F1): the same denial-as-error behavior across the non-2xx response
    /// classes, not just 403 — a 404 and a 500 (incl. a non-JSON body) must each
    /// surface as an error with the status, never a zeroed fake result.
    #[tokio::test]
    async fn cmd_stats_surfaces_denial_across_status_classes() {
        for (status, body, json) in [
            (404, r#"{"message":"not found"}"#, true),
            (500, "internal boom", false),
        ] {
            let mut server = mockito::Server::new_async().await;
            let mut m = server
                .mock("GET", mockito::Matcher::Regex(r"/stats$".to_string()))
                .with_status(status)
                .with_body(body);
            if json {
                m = m.with_header("content-type", "application/json");
            }
            let _m = m.create_async().await;

            let err = cmd_stats(server.url()).await.unwrap_err().to_string();
            assert!(
                err.contains(&status.to_string()),
                "status {status} must surface as an error, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn cmd_list_repo_scoped_surfaces_denial_not_empty() {
        // `gl bounty list --repo owner/name` hits the gated /repos/{o}/{n}/bounties;
        // a 404 must Err, not silently print nothing (INV-8).
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/repos/alice/secret/bounties".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = cmd_list(Some("alice/secret".to_string()), None, server.url(), None).await;
        assert!(
            result.is_err(),
            "bounty list --repo must Err on a gated 404"
        );
        // Prove the gated repo-scoped path was actually requested: without this,
        // an unmatched route (mockito's 501, also non-2xx) would satisfy is_err().
        _m.assert_async().await;
    }
}
