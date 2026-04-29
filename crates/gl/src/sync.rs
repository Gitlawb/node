use anyhow::Result;
use clap::{Args, Subcommand};

use crate::http::NodeClient;

#[derive(Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub cmd: SyncCmd,

    /// Node URL
    #[arg(long, env = "GITLAWB_NODE", default_value = "https://node.gitlawb.com")]
    pub node: String,
}

#[derive(Subcommand)]
pub enum SyncCmd {
    /// Pull repos from all known peers into the sync queue (HTTP fallback for p2p)
    Trigger,
    /// Show the current sync queue status
    Status,
}

pub async fn run(args: SyncArgs) -> Result<()> {
    let client = NodeClient::new(&args.node, None);

    match args.cmd {
        SyncCmd::Trigger => {
            let resp: serde_json::Value = client
                .post("/api/v1/sync/trigger", b"{}")
                .await?
                .json()
                .await?;
            let peers = resp["peers_reached"].as_u64().unwrap_or(0);
            let enqueued = resp["repos_enqueued"].as_u64().unwrap_or(0);
            println!("✓ sync triggered");
            println!("  peers reached:   {peers}");
            println!("  repos enqueued:  {enqueued}");
            println!("  worker picks up within 30s");
        }
        SyncCmd::Status => {
            // Just show peer list and node stats for now
            let stats: serde_json::Value = client.get("/api/v1/stats").await?.json().await?;
            let peers: serde_json::Value = client.get("/api/v1/peers").await?.json().await?;
            println!("Node stats:");
            println!("  repos:  {}", stats["repos"].as_i64().unwrap_or(0));
            println!("  agents: {}", stats["agents"].as_i64().unwrap_or(0));
            println!("  pushes: {}", stats["pushes"].as_i64().unwrap_or(0));
            println!();
            let count = peers["count"].as_u64().unwrap_or(0);
            println!("Known peers: {count}");
            if let Some(arr) = peers["peers"].as_array() {
                for p in arr {
                    let did = p["did"].as_str().unwrap_or("?");
                    let url = p["http_url"].as_str().unwrap_or("?");
                    let ok = p["reachable"].as_bool().unwrap_or(false);
                    let status = if ok { "✓" } else { "✗" };
                    println!("  {status} {url}  ({did})");
                }
            }
        }
    }
    Ok(())
}
