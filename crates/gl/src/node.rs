//! `gl node` — node status dashboard, network info, and on-chain PoS ops.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::node_stake;

#[derive(Args)]
pub struct NodeArgs {
    #[command(subcommand)]
    pub cmd: NodeCmd,
}

#[derive(Subcommand)]
pub enum NodeCmd {
    /// Show a comprehensive status dashboard for the node
    Status {
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
    /// Check trust score for a DID
    Trust {
        did: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
    /// Resolve a DID to node info
    Resolve {
        did: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },

    // ── On-chain PoS ──────────────────────────────────────────────────────

    /// Stake $GITLAWB and register this node on-chain (Base L2)
    Register {
        /// Amount of $GITLAWB to stake (whole tokens, e.g. 10000)
        #[arg(long)]
        stake: u64,
        /// Public HTTP URL of this node
        #[arg(long)]
        http_url: String,
        /// Operator private key (0x-prefixed hex)
        #[arg(long, env = "GITLAWB_OPERATOR_PRIVATE_KEY")]
        private_key: String,
        /// $GITLAWB ERC20 address
        #[arg(long, env = "GITLAWB_TOKEN")]
        token: String,
        /// GitlawbNodeStaking contract address
        #[arg(long, env = "GITLAWB_CONTRACT_NODE_STAKING")]
        contract: String,
        /// Base RPC URL
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = node_stake::default_rpc_url())]
        rpc_url: String,
        /// Identity dir (reads DID)
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Manually post a heartbeat (usually automatic once the node is running)
    Heartbeat {
        #[arg(long, env = "GITLAWB_OPERATOR_PRIVATE_KEY")]
        private_key: String,
        #[arg(long, env = "GITLAWB_CONTRACT_NODE_STAKING")]
        contract: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = node_stake::default_rpc_url())]
        rpc_url: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// View your node's on-chain stake, rewards, and active flag
    OnchainStatus {
        #[arg(long, env = "GITLAWB_CONTRACT_NODE_STAKING")]
        contract: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = node_stake::default_rpc_url())]
        rpc_url: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Claim accumulated PoS rewards without unstaking
    Claim {
        #[arg(long, env = "GITLAWB_OPERATOR_PRIVATE_KEY")]
        private_key: String,
        #[arg(long, env = "GITLAWB_CONTRACT_NODE_STAKING")]
        contract: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = node_stake::default_rpc_url())]
        rpc_url: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Request unstake — starts the 7-day cooldown
    UnstakeRequest {
        #[arg(long, env = "GITLAWB_OPERATOR_PRIVATE_KEY")]
        private_key: String,
        #[arg(long, env = "GITLAWB_CONTRACT_NODE_STAKING")]
        contract: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = node_stake::default_rpc_url())]
        rpc_url: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Complete unstake after the 7-day cooldown — returns stake + pending rewards
    Unstake {
        #[arg(long, env = "GITLAWB_OPERATOR_PRIVATE_KEY")]
        private_key: String,
        #[arg(long, env = "GITLAWB_CONTRACT_NODE_STAKING")]
        contract: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = node_stake::default_rpc_url())]
        rpc_url: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: NodeArgs) -> Result<()> {
    match args.cmd {
        NodeCmd::Status { node } => cmd_status(node).await,
        NodeCmd::Trust { did, node } => cmd_trust(did, node).await,
        NodeCmd::Resolve { did, node } => cmd_resolve(did, node).await,
        NodeCmd::Register { stake, http_url, private_key, token, contract, rpc_url, dir } =>
            node_stake::cmd_register(stake, http_url, private_key, token, contract, rpc_url, dir).await,
        NodeCmd::Heartbeat { private_key, contract, rpc_url, dir } =>
            node_stake::cmd_heartbeat(private_key, contract, rpc_url, dir).await,
        NodeCmd::OnchainStatus { contract, rpc_url, dir } =>
            node_stake::cmd_onchain_status(contract, rpc_url, dir).await,
        NodeCmd::Claim { private_key, contract, rpc_url, dir } =>
            node_stake::cmd_claim(private_key, contract, rpc_url, dir).await,
        NodeCmd::UnstakeRequest { private_key, contract, rpc_url, dir } =>
            node_stake::cmd_unstake_request(private_key, contract, rpc_url, dir).await,
        NodeCmd::Unstake { private_key, contract, rpc_url, dir } =>
            node_stake::cmd_unstake(private_key, contract, rpc_url, dir).await,
    }
}

/// Attempt a GET and parse JSON; returns None on any error or non-2xx status.
async fn try_get_json(client: &NodeClient, path: &str) -> Option<Value> {
    let resp = client.get(path).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

async fn cmd_status(node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);

    // ── Fetch node info (required — bail if unreachable) ──────────────────
    let info_resp = client.get("/").await
        .map_err(|e| anyhow::anyhow!("Cannot reach node at {node}: {e}"))?;
    let info: Value = info_resp.json().await
        .map_err(|e| anyhow::anyhow!("Invalid JSON from node: {e}"))?;

    let did = info["did"].as_str().unwrap_or("unknown");
    let version = info["version"].as_str().unwrap_or("unknown");
    let network = info["network"].as_str().unwrap_or("unknown");

    // ── Fetch remaining endpoints in parallel ─────────────────────────────
    let (peers_val, repos_val, p2p_val, events_val, pins_val) = tokio::join!(
        try_get_json(&client, "/api/v1/peers"),
        try_get_json(&client, "/api/v1/repos"),
        try_get_json(&client, "/api/v1/p2p/info"),
        try_get_json(&client, "/api/v1/events/ref-updates?limit=5"),
        try_get_json(&client, "/api/v1/ipfs/pins"),
    );

    // ── Render dashboard ──────────────────────────────────────────────────
    println!("╔══════════════════════════════════════════════╗");
    println!("║  gitlawb node status                         ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // Identity
    println!("Identity");
    println!("  DID:      {did}");
    println!("  Node URL: {node}");
    println!("  Version:  {version}");
    println!("  Network:  {network}");
    println!();

    // Network / Peers
    println!("Network");
    if let Some(ref peers) = peers_val {
        let count = peers["count"].as_u64().unwrap_or_else(|| {
            peers["peers"].as_array().map(|a| a.len() as u64).unwrap_or(0)
        });
        let reachable = peers["peers"].as_array()
            .map(|a| a.iter().filter(|p| p["reachable"].as_bool().unwrap_or(false)).count())
            .unwrap_or(0);
        println!("  Peers:    {count} known ({reachable} reachable)");
    } else {
        println!("  Peers:    unavailable");
    }

    if let Some(ref p2p) = p2p_val {
        if p2p["enabled"].as_bool().unwrap_or(false) {
            let peer_id = p2p["peer_id"].as_str().unwrap_or("unknown");
            println!("  P2P:      enabled — peer_id: {peer_id}");
            if let Some(topics) = p2p["topics"].as_array() {
                let topic_list: Vec<&str> = topics.iter()
                    .filter_map(|t| t.as_str())
                    .collect();
                if !topic_list.is_empty() {
                    println!("  Topics:   {}", topic_list.join(", "));
                }
            }
        } else {
            println!("  P2P:      disabled");
        }
    } else {
        println!("  P2P:      unavailable");
    }
    println!();

    // Repositories
    println!("Repositories");
    if let Some(ref repos) = repos_val {
        if let Some(arr) = repos.as_array() {
            println!("  Count:    {} repos", arr.len());
            for r in arr.iter().take(5) {
                let name = r["name"].as_str().unwrap_or("?");
                let public = r["is_public"].as_bool().unwrap_or(true);
                let vis = if public { "public" } else { "private" };
                println!("    - {name}  ({vis})");
            }
            if arr.len() > 5 {
                println!("    … and {} more", arr.len() - 5);
            }
        } else {
            println!("  (no repos or unexpected format)");
        }
    } else {
        println!("  unavailable");
    }
    println!();

    // Activity (optional — endpoint may not exist yet)
    if let Some(ref events) = events_val {
        println!("Activity (recent ref-updates)");
        // Events may be a top-level array or wrapped in an "events" key
        let items: Option<&Vec<Value>> = events.as_array()
            .or_else(|| events["events"].as_array());

        if let Some(arr) = items {
            if arr.is_empty() {
                println!("  (no recent activity)");
            } else {
                for ev in arr.iter().take(5) {
                    let repo = ev["repo"].as_str().unwrap_or("?");
                    let ref_name = ev["ref"].as_str().unwrap_or("?");
                    let ts = ev["timestamp"].as_str()
                        .map(|s| &s[..10.min(s.len())])
                        .unwrap_or("?");
                    println!("  {ts}  {repo}  {ref_name}");
                }
            }
        } else {
            println!("  (no recent activity)");
        }
        println!();
    }

    // Pins
    println!("Pins");
    if let Some(ref pins) = pins_val {
        let count = pins["count"].as_u64().unwrap_or_else(|| {
            pins["pins"].as_array().map(|a| a.len() as u64).unwrap_or(0)
        });
        println!("  Pinned CIDs: {count}");
    } else {
        println!("  IPFS not configured");
    }
    println!();

    Ok(())
}

async fn cmd_trust(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/agents/{did}/trust");
    let resp = client.get(&path).await
        .map_err(|e| anyhow::anyhow!("Cannot reach node at {node}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        anyhow::bail!("trust query failed ({status}) for {did}");
    }

    let trust: Value = resp.json().await
        .map_err(|e| anyhow::anyhow!("Invalid JSON response: {e}"))?;

    let score = trust["trust_score"].as_f64().unwrap_or(0.0);
    let level = trust["level"].as_str().unwrap_or("unknown");
    let pushes = trust["push_count"].as_i64().unwrap_or(0);

    println!("Trust score for {did}");
    println!("  Score:  {score:.2}");
    println!("  Level:  {level}");
    println!("  Pushes: {pushes}");

    Ok(())
}

async fn cmd_resolve(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let info: Value = client.get("/").await
        .map_err(|e| anyhow::anyhow!("Cannot reach node at {node}: {e}"))?
        .json().await
        .map_err(|e| anyhow::anyhow!("Invalid JSON from node: {e}"))?;

    let node_did = info["did"].as_str().unwrap_or("unknown");

    // If the requested DID matches this node, show full info
    if node_did == did || did == "self" {
        println!("DID resolution for {did}");
        println!("  DID:      {node_did}");
        println!("  Node URL: {node}");
        println!("  Version:  {}", info["version"].as_str().unwrap_or("unknown"));
        println!("  Network:  {}", info["network"].as_str().unwrap_or("unknown"));
        if let Some(peer_id) = info["p2p_peer_id"].as_str() {
            println!("  P2P ID:   {peer_id}");
        }
    } else {
        // Check the peer list for the requested DID
        let peers_resp = try_get_json(&client, "/api/v1/peers").await;

        let mut found = false;
        if let Some(ref peers) = peers_resp {
            if let Some(arr) = peers["peers"].as_array() {
                for p in arr {
                    if p["did"].as_str() == Some(did.as_str()) {
                        let http_url = p["http_url"].as_str().unwrap_or("unknown");
                        let reachable = p["reachable"].as_bool().unwrap_or(false);
                        let last_seen = p["last_seen"].as_str().unwrap_or("never");
                        println!("DID resolution for {did}");
                        println!("  Node URL:   {http_url}");
                        println!("  Reachable:  {reachable}");
                        println!("  Last seen:  {last_seen}");
                        found = true;
                        break;
                    }
                }
            }
        }

        if !found {
            println!("DID not found: {did}");
            println!("  (not this node and not in peer list)");
        }
    }

    Ok(())
}
