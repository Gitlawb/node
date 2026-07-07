use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub cmd: SyncCmd,

    /// Node URL
    #[arg(long, env = "GITLAWB_NODE", default_value = "https://node.gitlawb.com")]
    pub node: String,

    /// Identity directory for signed sync trigger requests
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum SyncCmd {
    /// Pull repos from all known peers into the sync queue (HTTP fallback for p2p)
    Trigger,
    /// Show the current sync queue status
    Status,
}

pub async fn run(args: SyncArgs) -> Result<()> {
    match args.cmd {
        SyncCmd::Trigger => {
            let keypair = load_keypair_from_dir(args.dir.as_deref()).ok();
            let client = NodeClient::new(&args.node, keypair);
            let resp = client.post("/api/v1/sync/trigger", b"{}").await?;
            // The node now requires a signature on this route and rate-limits it,
            // so a denial (401/429/…) is expected. Check the status BEFORE parsing:
            // otherwise a JSON-ish error body deserializes into a zero-count struct
            // and prints a fabricated "✓ sync triggered / 0 peers" success.
            let status = resp.status();
            if !status.is_success() {
                let raw = resp.text().await.unwrap_or_default();
                let msg = serde_json::from_str::<serde_json::Value>(&raw)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or_else(|| v.get("error"))
                            .and_then(|m| m.as_str())
                            .map(str::to_string)
                    })
                    .unwrap_or(raw);
                anyhow::bail!(
                    "sync trigger failed ({status}): {}",
                    sanitize_node_msg(&msg)
                );
            }
            let resp: serde_json::Value = resp.json().await?;
            let peers = resp["peers_reached"].as_u64().unwrap_or(0);
            let enqueued = resp["repos_enqueued"].as_u64().unwrap_or(0);
            println!("✓ sync triggered");
            println!("  peers reached:   {peers}");
            println!("  repos enqueued:  {enqueued}");
            println!("  worker picks up within 30s");
        }
        SyncCmd::Status => {
            let client = NodeClient::new(&args.node, None);
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

/// Strip control characters from (and cap the length of) a node-supplied error
/// string before surfacing it to the terminal. The node a caller talks to could
/// be hostile or compromised and embed ANSI/OSC escape sequences in its error
/// body; those must not reach the terminal verbatim (INV-6). Removing the C0/C1
/// control bytes defangs the sequence — the remaining printable text is inert.
fn sanitize_node_msg(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trigger_args(node: String) -> (SyncArgs, tempfile::TempDir) {
        // Empty identity dir → unsigned client. The mock returns a fixed status
        // regardless of the signature; we only exercise the client's status
        // handling. Return the TempDir so the caller keeps it alive.
        let dir = tempfile::TempDir::new().unwrap();
        let args = SyncArgs {
            cmd: SyncCmd::Trigger,
            node,
            dir: Some(dir.path().to_path_buf()),
        };
        (args, dir)
    }

    #[tokio::test]
    async fn trigger_surfaces_401_as_error_not_fake_success() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/sync/trigger")
            .with_status(401)
            .with_header("content-type", "application/json")
            // Valid JSON: the parse-without-status-check bug deserializes this
            // into a zero-count success struct and prints "✓ sync triggered".
            .with_body(r#"{"message":"unauthorized"}"#)
            .create_async()
            .await;
        let (args, _dir) = trigger_args(server.url());
        let err = run(args).await.unwrap_err();
        assert!(
            err.to_string().contains("401"),
            "expected 401 surfaced, got: {err}"
        );
    }

    #[tokio::test]
    async fn trigger_surfaces_429_as_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/sync/trigger")
            .with_status(429)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"slow down"}"#)
            .create_async()
            .await;
        let (args, _dir) = trigger_args(server.url());
        let err = run(args).await.unwrap_err();
        assert!(
            err.to_string().contains("429"),
            "expected 429 surfaced, got: {err}"
        );
    }

    #[tokio::test]
    async fn trigger_sanitizes_control_chars_in_node_error() {
        // A hostile node embeds an ANSI color escape (ESC) and a bell (BEL) in
        // the JSON message field. The surfaced error must contain neither raw
        // control byte, while keeping the printable text.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/sync/trigger")
            .with_status(401)
            .with_header("content-type", "application/json")
            // Valid JSON whose message carries JSON-escaped ESC (\u001b) and
            // BEL (\u0007); serde decodes them to real control bytes a naive
            // client would print. (The status-check bug fake-successes here.)
            .with_body("{\"message\":\"pwned\\u001b[31m\\u0007bad\"}")
            .create_async()
            .await;
        let (args, _dir) = trigger_args(server.url());
        let err = run(args).await.unwrap_err();
        let s = err.to_string();
        assert!(!s.contains('\u{1b}'), "ESC leaked to terminal: {s:?}");
        assert!(!s.contains('\u{07}'), "BEL leaked to terminal: {s:?}");
        assert!(
            s.contains("pwned") && s.contains("bad"),
            "message text dropped: {s:?}"
        );
    }

    #[tokio::test]
    async fn trigger_ok_prints_counts() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/sync/trigger")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"peers_reached":2,"repos_enqueued":5}"#)
            .create_async()
            .await;
        let (args, _dir) = trigger_args(server.url());
        run(args).await.unwrap();
    }
}
