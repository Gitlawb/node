//! `gl peer` — peer discovery commands.
//!
//! Nodes announce themselves to each other and maintain a local peer list.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
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
        PeerCmd::Add {
            peer_url,
            node,
            dir,
        } => cmd_add(peer_url, node, dir).await,
        PeerCmd::Ping { did, node } => cmd_ping(did, node).await,
        PeerCmd::Resolve { did, node } => cmd_resolve(did, node).await,
    }
}

async fn cmd_list(node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let resp = crate::http::read_json(client.get("/api/v1/peers").await?, "peers").await?;

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
        let last_seen = peer["last_seen"]
            .as_str()
            .map(|s| &s[..10])
            .unwrap_or("never");
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

    // Fetch our node's public URL so we can announce it to the peer. This lookup
    // is a deliberate fail-soft diagnostic: it only improves the URL we advertise.
    // A response-level failure (denial, error, garbage body) falls back to the
    // --node value with a visible note rather than aborting; only a transport
    // failure on the GET itself is fatal. The announce below keeps the
    // fail-closed read_json check.
    let local_client = NodeClient::new(&node, None);
    let my_url = match crate::http::read_json(local_client.get("/").await?, "node info").await {
        Ok(info) => info["public_url"].as_str().unwrap_or(&node).to_string(),
        Err(e) => {
            eprintln!("note: local node info unavailable ({e}); announcing {node}");
            node.clone()
        }
    };

    // Announce our local node to the remote peer
    let body = serde_json::to_vec(&serde_json::json!({
        "did": my_did,
        "http_url": my_url,
    }))?;

    let remote_client = NodeClient::new(&peer_url, Some(keypair));
    let announce_path = "/api/v1/peers/announce";
    let resp = remote_client
        .post(announce_path, &body)
        .await
        .context("failed to connect to peer")?;
    let result = crate::http::read_json(resp, "announce").await?;

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
        // Best-effort: the local node may be down, and cmd_add still succeeds
        // either way. But report the outcome honestly instead of printing a
        // success line after a failed local add.
        match local_client.post("/api/v1/peers/announce", &add_body).await {
            Ok(resp) if resp.status().is_success() => {
                println!("  Added to local peer list.");
            }
            _ => {
                eprintln!("note: could not add the peer to the local node's peer list");
            }
        }
    }

    Ok(())
}

async fn cmd_ping(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/peers/{did}/ping");
    let resp = crate::http::read_json(client.get(&path).await?, "ping peer").await?;

    let url = resp["http_url"].as_str().unwrap_or("?");
    let reachable = resp["reachable"].as_bool().unwrap_or(false);
    let status = if reachable {
        "reachable"
    } else {
        "unreachable"
    };

    println!("Peer: {did}");
    println!("  URL:    {url}");
    println!("  Status: {status}");
    Ok(())
}

async fn cmd_resolve(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let encoded = urlencoding::encode(&did);
    let path = format!("/api/v1/resolve/{encoded}");
    let resp = crate::http::read_json(client.get(&path).await?, "resolve DID").await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cmd_list_surfaces_denial_not_empty() {
        // A node error must Err, not print "No known peers" as if the list were empty.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/peers")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"boom"}"#)
            .expect(1)
            .create_async()
            .await;
        let err = cmd_list(server.url()).await.unwrap_err();
        assert!(err.to_string().contains("500"), "got: {err}");
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_ping_surfaces_denial_not_unreachable() {
        // A node error must Err, not print a fabricated "unreachable" peer.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/peers/peer1/ping")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let err = cmd_ping("peer1".to_string(), server.url())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_resolve_surfaces_denial_not_notfound() {
        // A node error must Err, not print "Source: not found" as if resolved-absent.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/resolve/".to_string()),
            )
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"boom"}"#)
            .expect(1)
            .create_async()
            .await;
        let err = cmd_resolve("peer1".to_string(), server.url())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"), "got: {err}");
        _m.assert_async().await;
    }

    // cmd_add needs a local identity to build my_did before the GET /.
    fn identity_dir() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        dir
    }

    /// Mock a successful announce that requires `http_url` in the POSTed body.
    /// The `{}` response body matters: it leaves `node_url` absent, so cmd_add
    /// skips the follow-up local peer-list POST.
    async fn announce_ok_mock(server: &mut mockito::ServerGuard, http_url: &str) -> mockito::Mock {
        announce_mock_with_body(server, http_url, "{}").await
    }

    /// Like [`announce_ok_mock`] but with a custom response body, for tests
    /// that need `node_url` populated so the follow-up local add runs.
    async fn announce_mock_with_body(
        server: &mut mockito::ServerGuard,
        http_url: &str,
        body: &str,
    ) -> mockito::Mock {
        server
            .mock("POST", "/api/v1/peers/announce")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "http_url": http_url,
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(1)
            .create_async()
            .await
    }

    // The local `GET /` lookup in cmd_add is a fail-soft diagnostic: a denied
    // or error node-info response must fall back to announcing the --node URL
    // (with a stderr note), not abort the command before the announce POST.
    #[tokio::test]
    async fn cmd_add_announces_fallback_url_when_node_info_denied() {
        let mut local = mockito::Server::new_async().await;
        let _info = local
            .mock("GET", "/")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"internal"}"#)
            .expect(1)
            .create_async()
            .await;
        let mut remote = mockito::Server::new_async().await;
        let _announce = announce_ok_mock(&mut remote, &local.url()).await;

        let dir = identity_dir();
        cmd_add(remote.url(), local.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        _info.assert_async().await;
        _announce.assert_async().await;
    }

    // Same fallback for a 200 node-info response whose body is not JSON.
    #[tokio::test]
    async fn cmd_add_falls_back_on_malformed_node_info() {
        let mut local = mockito::Server::new_async().await;
        let _info = local
            .mock("GET", "/")
            .with_status(200)
            .with_body("not json")
            .expect(1)
            .create_async()
            .await;
        let mut remote = mockito::Server::new_async().await;
        let _announce = announce_ok_mock(&mut remote, &local.url()).await;

        let dir = identity_dir();
        cmd_add(remote.url(), local.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        _info.assert_async().await;
        _announce.assert_async().await;
    }

    // Must-not case: the announce POST itself stays fail-closed. A denied
    // announce surfaces as an Err naming the status, never a printed success.
    #[tokio::test]
    async fn cmd_add_surfaces_denied_announce() {
        let mut local = mockito::Server::new_async().await;
        let _info = local
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"public_url":"https://pub.example"}"#)
            .expect(1)
            .create_async()
            .await;
        let mut remote = mockito::Server::new_async().await;
        let _announce = remote
            .mock("POST", "/api/v1/peers/announce")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;

        let dir = identity_dir();
        let err = cmd_add(remote.url(), local.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("403"), "got: {err}");
        _info.assert_async().await;
        _announce.assert_async().await;
    }

    // Success path unchanged: a usable node-info response announces its
    // public_url; the --node fallback must not leak in.
    #[tokio::test]
    async fn cmd_add_uses_public_url_when_lookup_succeeds() {
        let mut local = mockito::Server::new_async().await;
        let _info = local
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"public_url":"https://pub.example"}"#)
            .expect(1)
            .create_async()
            .await;
        let mut remote = mockito::Server::new_async().await;
        let _announce = announce_ok_mock(&mut remote, "https://pub.example").await;

        let dir = identity_dir();
        cmd_add(remote.url(), local.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        _info.assert_async().await;
        _announce.assert_async().await;
    }

    // When the peer's announce response carries a node_url, cmd_add posts the
    // peer back to the local node's peer list; a successful local POST is the
    // one case that prints the added line.
    #[tokio::test]
    async fn cmd_add_adds_peer_to_local_list_on_success() {
        let mut local = mockito::Server::new_async().await;
        let _info = local
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"public_url":"https://pub.example"}"#)
            .expect(1)
            .create_async()
            .await;
        let _local_add = local
            .mock("POST", "/api/v1/peers/announce")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"added"}"#)
            .expect(1)
            .create_async()
            .await;
        let mut remote = mockito::Server::new_async().await;
        let _announce = announce_mock_with_body(
            &mut remote,
            "https://pub.example",
            r#"{"node_did":"their-did","node_url":"http://their.example"}"#,
        )
        .await;

        let dir = identity_dir();
        cmd_add(remote.url(), local.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        _info.assert_async().await;
        _announce.assert_async().await;
        _local_add.assert_async().await;
    }

    // The local add stays best-effort: a failing local POST must not fail the
    // command (the announce to the remote peer already succeeded), it only
    // changes the printed outcome.
    #[tokio::test]
    async fn cmd_add_stays_ok_when_local_add_fails() {
        let mut local = mockito::Server::new_async().await;
        let _info = local
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"public_url":"https://pub.example"}"#)
            .expect(1)
            .create_async()
            .await;
        let _local_add = local
            .mock("POST", "/api/v1/peers/announce")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"boom"}"#)
            .expect(1)
            .create_async()
            .await;
        let mut remote = mockito::Server::new_async().await;
        let _announce = announce_mock_with_body(
            &mut remote,
            "https://pub.example",
            r#"{"node_did":"their-did","node_url":"http://their.example"}"#,
        )
        .await;

        let dir = identity_dir();
        cmd_add(remote.url(), local.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        _info.assert_async().await;
        _announce.assert_async().await;
        _local_add.assert_async().await;
    }
}
