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
                // Bound the read: a hostile or broken node must not force an
                // unbounded allocation just to surface a denial (INV-6, read half).
                let raw = read_body_capped(resp, 8 * 1024).await;
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
            let (peers, enqueued) = trigger_counts(&resp);
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

/// Extract `(peers_reached, repos_enqueued)` from a successful sync-trigger
/// response. Split out so the extraction is unit-testable (missing or malformed
/// fields default to 0 rather than panicking).
fn trigger_counts(resp: &serde_json::Value) -> (u64, u64) {
    (
        resp["peers_reached"].as_u64().unwrap_or(0),
        resp["repos_enqueued"].as_u64().unwrap_or(0),
    )
}

/// Read at most `cap` bytes of a response body. Bounds the allocation from a
/// hostile or broken node returning a huge error body — the display is capped
/// separately, but the read itself must not be unbounded (INV-6, read half).
async fn read_body_capped(mut resp: reqwest::Response, cap: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < cap {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = (cap - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // hit the cap mid-chunk
                }
            }
            _ => break, // end of body or read error — return what we have
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Strip terminal-dangerous characters from (and cap the length of) a
/// node-supplied error string before surfacing it. The node a caller talks to
/// could be hostile and embed escape sequences in its error body; those must not
/// reach the terminal verbatim (INV-6). We drop the C0/C1 control bytes (which
/// defangs ANSI/OSC escapes) AND the Unicode bidi/format controls (which
/// `char::is_control` does not cover — they can reorder the displayed line).
fn sanitize_node_msg(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_bidi_format(*c))
        .take(200)
        .collect()
}

/// Unicode bidirectional and directional-isolate format characters (category
/// `Cf`). These are not `char::is_control()` (that is category `Cc` only), but a
/// right-to-left override or isolate can visually reorder a terminal line to
/// spoof the error text, so they are stripped alongside the control bytes.
fn is_bidi_format(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}' | '\u{061C}'   // LRM, RLM, ALM
        | '\u{202A}'..='\u{202E}'              // LRE, RLE, PDF, LRO, RLO
        | '\u{2066}'..='\u{2069}'              // LRI, RLI, FSI, PDI
    )
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

    #[test]
    fn sanitize_strips_controls_bidi_and_caps_length() {
        // C0 (ESC/BEL) and the Cf bidi override (U+202E) are both removed; the
        // printable text survives. (Note: a stripped ESC leaves any following
        // "[31m" as inert literal text — that is the point, so the input here
        // avoids that residue to keep the expectation unambiguous.)
        let out = sanitize_node_msg("a\u{1b}\u{07}b\u{202e}c");
        assert!(
            !out.chars().any(|c| c.is_control()),
            "control char leaked: {out:?}"
        );
        assert!(
            !out.contains('\u{202e}'),
            "RLO bidi override leaked: {out:?}"
        );
        assert_eq!(out, "abc");
        // Length is capped at 200 chars regardless of input size.
        let long = "x".repeat(250);
        assert_eq!(sanitize_node_msg(&long).chars().count(), 200);
    }

    #[tokio::test]
    async fn trigger_handles_oversized_error_body_without_unbounded_output() {
        // A hostile/broken node returns a 2 MB error body. The command must still
        // surface the denial with a bounded message, not hang or dump the body.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/sync/trigger")
            .with_status(401)
            .with_body("A".repeat(2_000_000))
            .create_async()
            .await;
        let (args, _dir) = trigger_args(server.url());
        let err = run(args).await.unwrap_err();
        let s = err.to_string();
        assert!(s.contains("401"), "denial not surfaced: {s:.80?}");
        assert!(
            s.len() < 500,
            "error message not bounded: {} chars",
            s.len()
        );
    }

    #[tokio::test]
    async fn read_body_capped_bounds_the_read() {
        // The read must stop at the cap — a 2 MB body yields at most `cap` bytes,
        // not the whole thing (which resp.text() would return).
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/big")
            .with_status(200)
            .with_body("A".repeat(2_000_000))
            .create_async()
            .await;
        let resp = reqwest::get(format!("{}/big", server.url())).await.unwrap();
        let out = read_body_capped(resp, 8192).await;
        assert!(out.len() <= 8192, "read not bounded: {} bytes", out.len());
        assert!(!out.is_empty(), "expected some body");
    }

    #[test]
    fn trigger_counts_extracts_both_values() {
        let v = serde_json::json!({"peers_reached": 2, "repos_enqueued": 5});
        assert_eq!(trigger_counts(&v), (2, 5));
        // Missing/malformed fields default to 0, never panic.
        assert_eq!(trigger_counts(&serde_json::json!({})), (0, 0));
        assert_eq!(
            trigger_counts(&serde_json::json!({"peers_reached": "x"})),
            (0, 0)
        );
    }
}
