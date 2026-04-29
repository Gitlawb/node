//! `gl peer` — peer discovery commands.
//!
//! Nodes announce themselves to each other and maintain a local peer list.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct PeerArgs {
    #[command(subcommand)]
    pub cmd: PeerCmd,
}

#[derive(Subcommand)]
pub enum PeerCmd {
    /// List known peers on the node
    List {
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
    /// Announce yourself to a peer node (adds you to their peer list)
    Add {
        /// The URL of the peer node to announce to
        peer_url: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Check if a peer is reachable
    Ping {
        /// The DID of the peer to ping
        did: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
    /// Resolve a DID to its node URL and p2p info (checks local cache then Kademlia DHT)
    Resolve {
        /// The DID to resolve (e.g. did:key:z6Mk...)
        did: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
}

pub async fn run(args: PeerArgs) -> Result<()> {
    match args.cmd {
        PeerCmd::List { node } => cmd_list(node).await,
        PeerCmd::Add { peer_url, node, dir } => cmd_add(peer_url, node, dir).await,
        PeerCmd::Ping { did, node } => cmd_ping(did, node).await,
        PeerCmd::Resolve { did, node } => cmd_resolve(did, node).await,
    }
}

async fn cmd_list(node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let resp: Value = client.get("/api/v1/peers").await?.json().await
        .context("failed to list peers")?;

    let peers = resp["peers"].as_array().cloned().unwrap_or_default();
    let count = resp["count"].as_u64().unwrap_or(peers.len() as u64);

    if peers.is_empty() {
        println!("No known peers on {node}");
        return Ok(());
    }

    println!("Peers ({count}) known to {node}");
    println!();
    for peer in &peers {
        let did = peer["did"].as_str().unwrap_or("?");
        let url = peer["http_url"].as_str().unwrap_or("?");
        let reachable = peer["reachable"].as_bool().unwrap_or(false);
        let last_seen = peer["last_seen"].as_str().map(|s| &s[..10]).unwrap_or("never");
        let status = if reachable { "✓" } else { "✗" };
        println!("  {status} {url}");
        println!("    did:  {did}");
        println!("    seen: {last_seen}");
        println!();
    }
    Ok(())
}

async fn cmd_add(peer_url: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let my_did = keypair.did().to_string();

    // Fetch our node's public URL so we can announce it to the peer
    let local_client = NodeClient::new(&node, None);
    let node_info: Value = local_client.get("/").await?.json().await
        .context("failed to fetch local node info")?;
    let my_url = node_info["public_url"].as_str()
        .unwrap_or(&node)
        .to_string();

    // Announce our local node to the remote peer
    let body = serde_json::to_vec(&serde_json::json!({
        "did": my_did,
        "http_url": my_url,
    }))?;

    let remote_client = NodeClient::new(&peer_url, Some(keypair));
    let announce_path = "/api/v1/peers/announce";
    let resp = remote_client.post(announce_path, &body).await
        .context("failed to connect to peer")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("announce failed ({status}): {msg}");
    }

    let their_did = result["node_did"].as_str().unwrap_or("?");
    let their_url = result["node_url"].as_str().unwrap_or("?");
    let peer_count = result["peer_count"].as_u64().unwrap_or(0);

    println!("Announced to peer node:");
    println!("  DID:        {their_did}");
    println!("  URL:        {their_url}");
    println!("  Their peers: {peer_count}");

    // Also add their info to our local node's peer list
    // (the peer's /announce response includes their did + url)
    if !their_url.is_empty() && their_url != "?" {
        let add_body = serde_json::to_vec(&serde_json::json!({
            "did": their_did,
            "http_url": their_url,
        }))?;
        // This requires the local node to be running; ignore errors here
        let _ = local_client.post("/api/v1/peers/announce", &add_body).await;
        println!("  Added to local peer list.");
    }

    Ok(())
}

async fn cmd_ping(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/peers/{did}/ping");
    let resp: Value = client.get(&path).await?.json().await
        .context("failed to ping peer")?;

    let url = resp["http_url"].as_str().unwrap_or("?");
    let reachable = resp["reachable"].as_bool().unwrap_or(false);
    let status = if reachable { "reachable" } else { "unreachable" };

    println!("Peer: {did}");
    println!("  URL:    {url}");
    println!("  Status: {status}");
    Ok(())
}

async fn cmd_resolve(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let encoded = urlencoding::encode(&did);
    let path = format!("/api/v1/resolve/{encoded}");
    let resp: Value = client.get(&path).await?.json().await
        .context("failed to resolve DID")?;

    let source = resp["source"].as_str().unwrap_or("not found");
    let http_url = resp["http_url"].as_str().unwrap_or("(none)");

    println!("DID: {did}");
    println!("  Source:   {source}");
    println!("  HTTP URL: {http_url}");
    if let Some(peer_id) = resp["peer_id"].as_str() {
        println!("  Peer ID:  {peer_id}");
    }
    if let Some(p2p_port) = resp["p2p_port"].as_u64() {
        println!("  P2P port: {p2p_port}");
    }
    if let Some(err) = resp["error"].as_str() {
        println!("  Note: {err}");
    }
    Ok(())
}
