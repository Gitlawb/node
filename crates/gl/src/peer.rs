//! `gl peer` — peer discovery commands.
//!
//! Nodes announce themselves to each other and maintain a local peer list.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::{read_body_capped, sanitize_node_msg, NodeClient};
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
    let resp: Value = client
        .get("/api/v1/peers")
        .await?
        .json()
        .await
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

/// The warning text for a local peer-add reply, or `None` when the node
/// accepted it.
///
/// Split out so the refusal path is assertable. The node now answers 403 when
/// an unproven caller tries to repoint an existing peer's `http_url`, so a
/// reply that arrived and refused must not reach the success line.
fn local_add_refusal(status: reqwest::StatusCode, body: &Value) -> Option<String> {
    if status.is_success() {
        return None;
    }
    // The message is the node's, not ours, so it is defanged before it reaches
    // the terminal. Only the message: the status and the prose are ours.
    let msg = sanitize_node_msg(body["message"].as_str().unwrap_or("unknown error"));
    Some(format!(
        "warning: local peer list not updated ({status}): {msg}"
    ))
}

/// The error text for a remote announce reply, or `None` when the peer accepted
/// it.
///
/// Split out so the ordering is assertable: the status has to reach the caller
/// even when the body does not parse. That case is reachable rather than
/// theoretical, because the read above is capped, so a peer answering with a
/// body past the cap leaves truncated JSON behind, and `peer_url` is whatever
/// the caller passed, so a non-JSON error page is just as easy. Parsing first
/// and failing on the parse would swallow the status the user needs.
fn remote_announce_failure(status: reqwest::StatusCode, raw: &str) -> Option<String> {
    if status.is_success() {
        return None;
    }
    // Falls back to the body itself when there is no `message` field, which is
    // what a truncated or non-JSON reply leaves. Sanitized either way: it is the
    // peer's text and it is headed for the terminal.
    let parsed: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
    let msg = sanitize_node_msg(parsed["message"].as_str().unwrap_or(raw));
    Some(format!("announce failed ({status}): {msg}"))
}

/// The block printed after a peer accepts our announce. Split out so the
/// defanging is assertable: the DID and URL are the remote peer's own strings,
/// and `peer_url` is caller-chosen, so this is the least trusted body the
/// command handles. Only the display is sanitized; the values sent on to our
/// local node stay verbatim, since that is data rather than terminal output and
/// the node runs its own validation on them.
fn announced_peer_summary(their_did: &str, their_url: &str, peer_count: u64) -> String {
    format!(
        "Announced to peer node:\n  DID:        {}\n  URL:        {}\n  Their peers: {peer_count}\n",
        sanitize_node_msg(their_did),
        sanitize_node_msg(their_url),
    )
}

async fn cmd_add(peer_url: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let my_did = keypair.did().to_string();

    // Fetch our node's public URL so we can announce it to the peer
    let local_client = NodeClient::new(&node, None);
    let node_info: Value = local_client
        .get("/")
        .await?
        .json()
        .await
        .context("failed to fetch local node info")?;
    let my_url = node_info["public_url"]
        .as_str()
        .unwrap_or(&node)
        .to_string();

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
    let status = resp.status();
    // `peer_url` is fully caller-chosen, so this body is the least trusted one
    // in the command: bound the read, and defang the message before it reaches
    // the terminal through the error return. An announce reply is a DID, a URL
    // and a count, so 8 KiB is well past what the shape needs.
    let raw = read_body_capped(resp, 8 * 1024).await;

    if let Some(failure) = remote_announce_failure(status, &raw) {
        anyhow::bail!("{failure}");
    }

    let result: Value = serde_json::from_str(&raw).context("invalid JSON response")?;

    let their_did = result["node_did"].as_str().unwrap_or("?");
    let their_url = result["node_url"].as_str().unwrap_or("?");
    let peer_count = result["peer_count"].as_u64().unwrap_or(0);

    print!(
        "{}",
        announced_peer_summary(their_did, their_url, peer_count)
    );

    // Also add their info to our local node's peer list
    // (the peer's /announce response includes their did + url)
    if !their_url.is_empty() && their_url != "?" {
        let add_body = serde_json::to_vec(&serde_json::json!({
            "did": their_did,
            "http_url": their_url,
        }))?;
        // This requires the local node to be running, so a transport failure
        // stays a warning rather than failing the command. A reply that
        // ARRIVED and refused is different: the announce route answers 403
        // when an unproven caller tries to repoint an existing peer, and
        // printing the success line over that reports a completed add that
        // never happened. Same status handling as the remote announce above,
        // except best effort.
        match local_client.post("/api/v1/peers/announce", &add_body).await {
            Ok(resp) => {
                let status = resp.status();
                // Same bound as the remote announce above: a compromised local
                // node (or a MITM on plain http) must not force an unbounded
                // read. A body that does not parse stays `Null`, which still
                // routes a non-success status to the warning.
                let raw = read_body_capped(resp, 8 * 1024).await;
                let result: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                match local_add_refusal(status, &result) {
                    Some(warning) => eprintln!("{warning}"),
                    None => println!("  Added to local peer list."),
                }
            }
            Err(e) => eprintln!("warning: local peer list not updated: {e}"),
        }
    }

    Ok(())
}

async fn cmd_ping(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/peers/{did}/ping");
    let resp: Value = client
        .get(&path)
        .await?
        .json()
        .await
        .context("failed to ping peer")?;

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
    let resp: Value = client
        .get(&path)
        .await?
        .json()
        .await
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

#[cfg(test)]
mod tests {
    use super::{announced_peer_summary, cmd_add, local_add_refusal, remote_announce_failure};
    use reqwest::StatusCode;
    use serde_json::json;

    /// The node's 403 for repointing an existing peer must surface, not print
    /// as a completed add. Without the status check the command prints "Added
    /// to local peer list." over a refusal.
    ///
    /// The fixture body is the real wire shape, not an invented one: the
    /// message is the Display of `PeerWriteDenied::UnprovenRepoint`, declared
    /// in `crates/gitlawb-node/src/db/mod.rs`. The executable detector for a
    /// wording change is the node-side pin
    /// `announce_unsigned_repoint_is_a_403_denial` in
    /// `crates/gitlawb-node/src/api/peers.rs`, which asserts this same
    /// substring against a response driven through the real router, so
    /// rewording the Display turns that test red and the grep for the old
    /// phrase lands here.
    ///
    /// The assertion bites rather than echoing its own input because the
    /// substring is reachable only through the helper's `body["message"]`
    /// extraction; the fixture's `error` field carries a different string, so
    /// reading `body["error"]` instead fails this test.
    #[test]
    fn a_refused_local_add_warns_with_the_node_reason() {
        let warning = local_add_refusal(
            StatusCode::FORBIDDEN,
            &json!({
                "error": "forbidden",
                "message": "unproven announce cannot change an existing peer's http_url: did:key:z6MkuMqUm4i228K9qXidJ57zqSWAcQLgrcbMxB8RKVLuqitj"
            }),
        )
        .expect("a refusal must not render as success");

        assert!(warning.contains("403"), "must name the status: {warning}");
        assert!(
            warning.contains("unproven announce cannot change an existing peer"),
            "must carry the node's own reason: {warning}"
        );
    }

    /// A refusal with no message body still warns rather than passing silently.
    #[test]
    fn a_refusal_without_a_message_still_warns() {
        let warning = local_add_refusal(StatusCode::BAD_REQUEST, &serde_json::Value::Null)
            .expect("a refusal must not render as success");
        assert!(warning.contains("400"), "must name the status: {warning}");
    }

    /// The accepted case stays quiet, so the success line still prints.
    #[test]
    fn an_accepted_local_add_produces_no_warning() {
        assert!(local_add_refusal(StatusCode::OK, &json!({ "peer_count": 3 })).is_none());
    }

    /// The warning is printed straight to a terminal, so a node-supplied message
    /// carrying an OSC title-rewrite plus a C0 escape must reach it defanged.
    #[test]
    fn a_refusal_message_cannot_carry_terminal_escapes() {
        let warning = local_add_refusal(
            StatusCode::FORBIDDEN,
            &json!({ "message": "\u{1b}]2;pwned\u{7}legit-looking text" }),
        )
        .expect("a refusal must not render as success");

        assert!(
            !warning.chars().any(|c| c.is_control()),
            "control char leaked to the terminal: {warning:?}"
        );
        assert!(
            warning.contains("legit-looking text"),
            "printable text dropped: {warning:?}"
        );
    }

    /// Bidi format chars are not `char::is_control`, yet they reorder the
    /// displayed line, so a refusal must not carry them either.
    #[test]
    fn a_refusal_message_cannot_carry_bidi_overrides() {
        let warning = local_add_refusal(
            StatusCode::FORBIDDEN,
            &json!({ "message": "peer \u{202e}refused\u{202c} here" }),
        )
        .expect("a refusal must not render as success");

        assert!(
            !warning.chars().any(gitlawb_core::sanitize::is_bidi_format),
            "bidi format char leaked to the terminal: {warning:?}"
        );
    }

    /// A hostile node must not be able to dump an arbitrary amount of text into
    /// the user's scrollback through the warning line.
    #[test]
    fn a_refusal_message_is_length_bounded() {
        let warning = local_add_refusal(
            StatusCode::FORBIDDEN,
            &json!({ "message": "x".repeat(5000) }),
        )
        .expect("a refusal must not render as success");

        assert!(
            warning.chars().count() < 500,
            "warning not bounded: {} chars",
            warning.chars().count()
        );
    }

    /// The status is the part the user can act on, so it must survive a body
    /// that does not parse. The read is capped, so a peer answering past the cap
    /// leaves exactly this: a valid status and truncated JSON.
    #[test]
    fn a_remote_announce_failure_keeps_the_status_when_the_body_does_not_parse() {
        let truncated = r#"{"error":"service_unavailable","message":"backend is do"#;
        let failure = remote_announce_failure(StatusCode::SERVICE_UNAVAILABLE, truncated)
            .expect("a non-success status must produce a failure");

        assert!(
            failure.contains("503"),
            "the status must survive an unparseable body: {failure:?}"
        );
    }

    /// A parseable error body still reports the peer's own message.
    #[test]
    fn a_remote_announce_failure_carries_the_peers_message() {
        let failure = remote_announce_failure(
            StatusCode::FORBIDDEN,
            r#"{"error":"forbidden","message":"unproven announce cannot change an existing peer"}"#,
        )
        .expect("a non-success status must produce a failure");

        assert!(
            failure.contains("403")
                && failure.contains("unproven announce cannot change an existing peer"),
            "status and reason must both survive: {failure:?}"
        );
    }

    /// The fallback path prints the raw body, so it is defanged like every other
    /// peer-supplied string headed for the terminal.
    #[test]
    fn a_remote_announce_failure_defangs_an_unparseable_body() {
        let failure = remote_announce_failure(
            StatusCode::BAD_GATEWAY,
            "\u{1b}]2;pwned\u{7}<html>gateway error</html>",
        )
        .expect("a non-success status must produce a failure");

        assert!(
            !failure.chars().any(|c| c.is_control()),
            "control char leaked to the terminal: {failure:?}"
        );
        assert!(failure.contains("502"), "status dropped: {failure:?}");
        assert!(
            failure.contains("gateway error"),
            "the body is all the user gets when there is no message field: {failure:?}"
        );
    }

    /// The unit tests above bind the helper. This one binds the CALL SITE: the
    /// failure check has to run before the parse, or a body past the read cap
    /// turns a 503 into "invalid JSON response" and the status the user needs is
    /// gone. Reordering the two statements in `cmd_add` compiles and passes every
    /// other test in this file, so only driving the command catches it.
    #[tokio::test]
    async fn a_peer_failure_past_the_read_cap_still_reports_its_status() {
        let mut peer = mockito::Server::new_async().await;
        let mut local = mockito::Server::new_async().await;

        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _local_info = local
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"public_url":"https://me.example"}"#)
            .create_async()
            .await;

        // Valid JSON, but past the 8 KiB read cap, so what survives the read is
        // truncated and unparseable. This is the shape the cap itself creates.
        let oversized = format!(r#"{{"message":"{}"}}"#, "x".repeat(16 * 1024));
        let _peer_refusal = peer
            .mock("POST", "/api/v1/peers/announce")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(oversized)
            .create_async()
            .await;

        let err = cmd_add(peer.url(), local.url(), Some(dir.path().to_path_buf()))
            .await
            .expect_err("a 503 from the peer must fail the command");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("503"),
            "the status must survive a body past the read cap: {rendered:?}"
        );
        assert!(
            !rendered.contains("invalid JSON response"),
            "the parse failure must not stand in for the status: {rendered:?}"
        );
    }

    /// An accepted announce produces no error, so the caller proceeds to parse.
    #[test]
    fn an_accepted_remote_announce_produces_no_failure() {
        assert!(remote_announce_failure(StatusCode::OK, r#"{"peer_count":3}"#).is_none());
    }

    /// The accepted-announce block prints the remote peer's own DID and URL, so
    /// a hostile peer answering 200 must not get escapes onto the terminal that
    /// way either. The refusal path is not the only sink in this command.
    #[test]
    fn an_accepted_announce_summary_cannot_carry_terminal_escapes() {
        let summary = announced_peer_summary(
            "did:key:z6Mk\u{1b}]2;pwned\u{7}abc",
            "https://peer.example\u{202e}moc.live//:sptth",
            3,
        );

        assert!(
            !summary.chars().any(|c| c.is_control() && c != '\n'),
            "control char leaked to the terminal: {summary:?}"
        );
        assert!(
            !summary.chars().any(gitlawb_core::sanitize::is_bidi_format),
            "bidi format char leaked to the terminal: {summary:?}"
        );
        assert!(
            summary.contains("did:key:z6Mk") && summary.contains("Their peers: 3"),
            "printable content dropped: {summary:?}"
        );
    }

    /// The counterweight to the stripping tests: a legitimate message with RTL
    /// script letters and a ZWJ must survive intact, so the sanitizer is not
    /// proven by over-stripping.
    #[test]
    fn a_legitimate_refusal_message_survives_intact() {
        let warning = local_add_refusal(
            StatusCode::FORBIDDEN,
            &json!({ "message": "peer refused \u{0627}\u{200D}b" }),
        )
        .expect("a refusal must not render as success");

        assert!(
            warning.contains("peer refused \u{0627}\u{200D}b"),
            "legitimate text mangled: {warning:?}"
        );
    }
}
