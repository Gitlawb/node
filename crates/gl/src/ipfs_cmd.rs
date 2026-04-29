//! `gl ipfs` — IPFS pin management commands.
//!
//! Communicates with the gitlawb node to list pinned CIDs and retrieve git
//! objects by their content-addressed CID.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::http::NodeClient;

#[derive(Args)]
pub struct IpfsArgs {
    #[command(subcommand)]
    pub cmd: IpfsCmd,
}

#[derive(Subcommand)]
pub enum IpfsCmd {
    /// List all CIDs pinned to the node's local IPFS daemon
    List {
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
    /// Retrieve and display a git object from the node by its CIDv1
    Get {
        /// The CIDv1 string (e.g. bafkrei...)
        cid: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
}

pub async fn run(args: IpfsArgs) -> Result<()> {
    match args.cmd {
        IpfsCmd::List { node } => cmd_list(node).await,
        IpfsCmd::Get { cid, node } => cmd_get(cid, node).await,
    }
}

async fn cmd_list(node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let resp: Value = client
        .get("/api/v1/ipfs/pins")
        .await?
        .json()
        .await
        .context("failed to parse pins response")?;

    let pins = resp["pins"].as_array().cloned().unwrap_or_default();
    let count = resp["count"].as_u64().unwrap_or(pins.len() as u64);

    if pins.is_empty() {
        println!("No IPFS pins recorded on {node}");
        println!("(Push to a repo with GITLAWB_IPFS_API set to start pinning)");
        return Ok(());
    }

    println!("IPFS pins ({count}) on {node}");
    println!();
    for pin in &pins {
        let cid = pin["cid"].as_str().unwrap_or("?");
        let sha = pin["sha256_hex"].as_str().unwrap_or("?");
        let pinned_at = pin["pinned_at"].as_str().unwrap_or("?");
        // Trim pinned_at to date+time without subseconds
        let ts = if pinned_at.len() >= 19 {
            &pinned_at[..19]
        } else {
            pinned_at
        };
        println!("  {cid}");
        println!("    sha256: {sha}");
        println!("    pinned: {ts}");
        println!();
    }
    Ok(())
}

async fn cmd_get(cid: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let path = format!("/ipfs/{cid}");
    let resp = client
        .get(&path)
        .await
        .with_context(|| format!("failed to fetch CID {cid} from {node}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("node returned {status}: {body}");
    }

    // Print headers for diagnostics
    let headers = resp.headers().clone();
    if let Some(git_hash) = headers.get("x-git-hash") {
        eprintln!("x-git-hash:   {}", git_hash.to_str().unwrap_or("?"));
    }
    if let Some(content_cid) = headers.get("x-content-cid") {
        eprintln!("x-content-cid: {}", content_cid.to_str().unwrap_or("?"));
    }

    // Write raw bytes to stdout (allows piping to files or other tools)
    let bytes = resp.bytes().await.context("failed to read response body")?;
    use std::io::Write;
    std::io::stdout()
        .write_all(&bytes)
        .context("failed to write to stdout")?;

    Ok(())
}
