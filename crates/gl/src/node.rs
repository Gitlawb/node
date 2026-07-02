//! `gl node` — node status dashboard, network info, and on-chain PoS ops.

use anyhow::Result;
use clap::{Args, Subcommand};
use gitlawb_core::identity::Keypair;
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;
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
        NodeCmd::Register {
            stake,
            http_url,
            private_key,
            token,
            contract,
            rpc_url,
            dir,
        } => {
            node_stake::cmd_register(stake, http_url, private_key, token, contract, rpc_url, dir)
                .await
        }
        NodeCmd::Heartbeat {
            private_key,
            contract,
            rpc_url,
            dir,
        } => node_stake::cmd_heartbeat(private_key, contract, rpc_url, dir).await,
        NodeCmd::OnchainStatus {
            contract,
            rpc_url,
            dir,
        } => node_stake::cmd_onchain_status(contract, rpc_url, dir).await,
        NodeCmd::Claim {
            private_key,
            contract,
            rpc_url,
            dir,
        } => node_stake::cmd_claim(private_key, contract, rpc_url, dir).await,
        NodeCmd::UnstakeRequest {
            private_key,
            contract,
            rpc_url,
            dir,
        } => node_stake::cmd_unstake_request(private_key, contract, rpc_url, dir).await,
        NodeCmd::Unstake {
            private_key,
            contract,
            rpc_url,
            dir,
        } => node_stake::cmd_unstake(private_key, contract, rpc_url, dir).await,
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

/// Outcome of fetching the IPFS pins panel for `gl node status`.
///
/// #134 gates `/api/v1/ipfs/pins` behind auth, so this panel signs its request
/// when an identity is available and otherwise reports that the caller must
/// sign in. A pins failure never aborts the dashboard.
#[derive(Debug)]
enum PinsPanel {
    /// Signed read succeeded and returned pins (carries the resolved count).
    Pins(u64),
    /// Signed read succeeded but the node has no pins recorded.
    Empty,
    /// Signed read was rejected (401/other) or errored.
    Unavailable,
    /// No identity available; no request was issued.
    NeedsIdentity,
}

/// Fetch the pins panel state. With a keypair, signs the `/api/v1/ipfs/pins`
/// read and maps the outcome; without one, returns `NeedsIdentity` and issues
/// no request. Injectable (node URL + optional keypair) so tests drive it with
/// a mock server and never touch the default keystore.
async fn fetch_pins(node: &str, keypair: Option<Keypair>) -> PinsPanel {
    let Some(kp) = keypair else {
        return PinsPanel::NeedsIdentity;
    };
    let client = NodeClient::new(node, Some(kp));
    let resp = match client.get_signed("/api/v1/ipfs/pins").await {
        Ok(r) => r,
        Err(_) => return PinsPanel::Unavailable,
    };
    if !resp.status().is_success() {
        return PinsPanel::Unavailable;
    }
    let Ok(body) = resp.json::<Value>().await else {
        return PinsPanel::Unavailable;
    };
    let count = body["count"]
        .as_u64()
        .unwrap_or_else(|| body["pins"].as_array().map(|a| a.len() as u64).unwrap_or(0));
    if count == 0 {
        PinsPanel::Empty
    } else {
        PinsPanel::Pins(count)
    }
}

async fn cmd_status(node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);

    // ── Fetch node info (required — bail if unreachable) ──────────────────
    let info_resp = client
        .get("/")
        .await
        .map_err(|e| anyhow::anyhow!("Cannot reach node at {node}: {e}"))?;
    let info: Value = info_resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Invalid JSON from node: {e}"))?;

    let did = info["did"].as_str().unwrap_or("unknown");
    let version = info["version"].as_str().unwrap_or("unknown");
    let network = info["network"].as_str().unwrap_or("unknown");

    // The pins panel signs its read (#134 gates /api/v1/ipfs/pins behind auth);
    // load the identity gracefully so a missing keystore never aborts status.
    let keypair = load_keypair_from_dir(None).ok();

    // ── Fetch remaining endpoints in parallel ─────────────────────────────
    // Peers/repos/p2p/events stay anonymous; only pins is signed.
    let (peers_val, repos_val, p2p_val, events_val, pins_panel) = tokio::join!(
        try_get_json(&client, "/api/v1/peers"),
        try_get_json(&client, "/api/v1/repos"),
        try_get_json(&client, "/api/v1/p2p/info"),
        try_get_json(&client, "/api/v1/events/ref-updates?limit=5"),
        fetch_pins(&node, keypair),
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
            peers["peers"]
                .as_array()
                .map(|a| a.len() as u64)
                .unwrap_or(0)
        });
        let reachable = peers["peers"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|p| p["reachable"].as_bool().unwrap_or(false))
                    .count()
            })
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
                let topic_list: Vec<&str> = topics.iter().filter_map(|t| t.as_str()).collect();
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
        let items: Option<&Vec<Value>> = events.as_array().or_else(|| events["events"].as_array());

        if let Some(arr) = items {
            if arr.is_empty() {
                println!("  (no recent activity)");
            } else {
                for ev in arr.iter().take(5) {
                    let repo = ev["repo"].as_str().unwrap_or("?");
                    let ref_name = ev["ref"].as_str().unwrap_or("?");
                    let ts = ev["timestamp"]
                        .as_str()
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
    match pins_panel {
        PinsPanel::Pins(count) => {
            println!("  Pinned CIDs: {count}");
        }
        PinsPanel::Empty => {
            println!("  Pinned CIDs: 0");
        }
        PinsPanel::Unavailable => {
            println!("  IPFS pins: unavailable");
        }
        PinsPanel::NeedsIdentity => {
            println!("  IPFS pins: sign in to view (run `gl identity new`)");
        }
    }
    println!();

    Ok(())
}

async fn cmd_trust(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/agents/{did}/trust");
    let resp = client
        .get(&path)
        .await
        .map_err(|e| anyhow::anyhow!("Cannot reach node at {node}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        anyhow::bail!("trust query failed ({status}) for {did}");
    }

    let trust: Value = resp
        .json()
        .await
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
    let info: Value = client
        .get("/")
        .await
        .map_err(|e| anyhow::anyhow!("Cannot reach node at {node}: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Invalid JSON from node: {e}"))?;

    let node_did = info["did"].as_str().unwrap_or("unknown");

    // If the requested DID matches this node, show full info
    if node_did == did || did == "self" {
        println!("DID resolution for {did}");
        println!("  DID:      {node_did}");
        println!("  Node URL: {node}");
        println!(
            "  Version:  {}",
            info["version"].as_str().unwrap_or("unknown")
        );
        println!(
            "  Network:  {}",
            info["network"].as_str().unwrap_or("unknown")
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use gitlawb_core::identity::Keypair;

    #[tokio::test]
    async fn test_fetch_pins_keyed_happy_signs_and_returns_pins() {
        let mut server = mockito::Server::new_async().await;
        let kp = Keypair::generate();

        // A keyed fetch must sign the request (RFC 9421 headers) and, on a
        // populated 200 body, land in the Pins state carrying the pins.
        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .match_header("content-digest", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"pins":[{"cid":"bafyone","sha256_hex":"abc123","pinned_at":"2026-07-02T12:00:00Z"}],"count":1}"#,
            )
            .create_async()
            .await;

        let panel = fetch_pins(&server.url(), Some(kp)).await;
        match panel {
            PinsPanel::Pins(count) => assert_eq!(count, 1),
            other => panic!("expected Pins, got {other:?}"),
        }

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_pins_keyed_empty_returns_empty() {
        let mut server = mockito::Server::new_async().await;
        let kp = Keypair::generate();

        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .match_header("signature", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"pins":[],"count":0}"#)
            .create_async()
            .await;

        let panel = fetch_pins(&server.url(), Some(kp)).await;
        assert!(
            matches!(panel, PinsPanel::Empty),
            "expected Empty, got {panel:?}"
        );

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_pins_keyed_rejected_returns_unavailable() {
        let mut server = mockito::Server::new_async().await;
        let kp = Keypair::generate();

        // Node rejects the signed read (401): the panel must degrade to
        // Unavailable without panicking, so cmd_status still completes.
        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .match_header("signature", mockito::Matcher::Any)
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"unauthorized"}"#)
            .create_async()
            .await;

        let panel = fetch_pins(&server.url(), Some(kp)).await;
        assert!(
            matches!(panel, PinsPanel::Unavailable),
            "expected Unavailable, got {panel:?}"
        );

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_fetch_pins_unkeyed_needs_identity_without_request() {
        let mut server = mockito::Server::new_async().await;

        // With no keypair the endpoint must never be hit.
        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .expect(0)
            .create_async()
            .await;

        let panel = fetch_pins(&server.url(), None).await;
        assert!(
            matches!(panel, PinsPanel::NeedsIdentity),
            "expected NeedsIdentity, got {panel:?}"
        );

        m.assert_async().await;
    }
}
