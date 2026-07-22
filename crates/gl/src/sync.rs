use anyhow::{Context, Result};
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
            // /api/v1/sync/trigger always requires a signature, so a missing or
            // unreadable identity must fail here, locally, rather than sending an
            // unsigned request that can only 401 remotely (matches the other
            // signed CLI writes).
            let keypair = load_keypair_from_dir(args.dir.as_deref())
                .context("identity not found — run `gl identity new` first")?;
            let client = NodeClient::new(&args.node, Some(keypair));
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
            let stats =
                crate::http::read_json(client.get("/api/v1/stats").await?, "node stats").await?;
            let peers = crate::http::read_json(client.get("/api/v1/peers").await?, "peers").await?;
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
pub(crate) async fn read_body_capped(mut resp: reqwest::Response, cap: usize) -> String {
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
pub(crate) fn sanitize_node_msg(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !gitlawb_core::sanitize::is_bidi_format(*c))
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trigger_args(node: String) -> (SyncArgs, tempfile::TempDir) {
        // Seed a real identity so `run` gets past the mandatory-keypair check and
        // reaches the status-handling path. The mocks below return a fixed status
        // regardless of the signature, so these tests exercise the client's
        // status-check-before-parse, not signature verification (that is proved
        // server-side). Return the TempDir so the caller keeps it alive.
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let args = SyncArgs {
            cmd: SyncCmd::Trigger,
            node,
            dir: Some(dir.path().to_path_buf()),
        };
        (args, dir)
    }

    #[tokio::test]
    async fn trigger_requires_identity_fails_before_request() {
        // Empty identity dir → no keypair. `sync trigger` must fail locally with
        // a clear identity error BEFORE issuing any request. The node URL points
        // at an unreachable port, so a request attempt would surface a different
        // (connection) error; getting the identity error proves we never dialed.
        let dir = tempfile::TempDir::new().unwrap();
        let args = SyncArgs {
            cmd: SyncCmd::Trigger,
            node: "http://127.0.0.1:1".to_string(),
            dir: Some(dir.path().to_path_buf()),
        };
        let err = run(args).await.unwrap_err();
        assert!(
            err.to_string().contains("identity not found"),
            "expected a local identity error before any request, got: {err}"
        );
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
            .expect(1)
            .create_async()
            .await;
        let (args, _dir) = trigger_args(server.url());
        let err = run(args).await.unwrap_err();
        assert!(
            err.to_string().contains("401"),
            "expected 401 surfaced, got: {err}"
        );
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn trigger_surfaces_429_as_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/sync/trigger")
            .with_status(429)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"slow down"}"#)
            .expect(1)
            .create_async()
            .await;
        let (args, _dir) = trigger_args(server.url());
        let err = run(args).await.unwrap_err();
        assert!(
            err.to_string().contains("429"),
            "expected 429 surfaced, got: {err}"
        );
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
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
            .expect(1)
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
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
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

    #[test]
    fn sanitize_preserves_legitimate_and_rtl_text() {
        // Must not over-strip: a plain word, a genuine RTL SCRIPT letter (Arabic
        // U+0627, category Lo — NOT a format char), and ZWJ (U+200D, a legitimate
        // Cf char, e.g. emoji sequences) all survive. Guards the shared predicate
        // against being widened into a blanket Cf stripper.
        let out = sanitize_node_msg("ok \u{0627}\u{200D}b");
        assert_eq!(out, "ok \u{0627}\u{200D}b");
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
            .expect(1)
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
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
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

    #[tokio::test]
    async fn status_surfaces_stats_denial_not_fake_zeros() {
        // A node error on /stats must Err, not print "0 repos / 0 agents / 0 pushes".
        let mut server = mockito::Server::new_async().await;
        let stats = server
            .mock("GET", "/api/v1/stats")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"boom"}"#)
            .expect(1)
            .create_async()
            .await;
        // A peers mock so the pre-fix path reaches a clean success rather than a
        // 501 on an unmocked route; after the fix the /stats denial bails first.
        let _peers = server
            .mock("GET", "/api/v1/peers")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"count":0,"peers":[]}"#)
            .create_async()
            .await;
        let args = SyncArgs {
            cmd: SyncCmd::Status,
            node: server.url(),
            dir: None,
        };
        let err = run(args).await.unwrap_err();
        assert!(
            err.to_string().contains("500"),
            "expected 500 surfaced, got: {err}"
        );
        stats.assert_async().await;
    }

    #[tokio::test]
    async fn status_surfaces_peers_denial() {
        // /stats succeeds but /peers denies — the peers read must Err too, not
        // print "Known peers: 0".
        let mut server = mockito::Server::new_async().await;
        let _stats = server
            .mock("GET", "/api/v1/stats")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"repos":1,"agents":2,"pushes":3}"#)
            .create_async()
            .await;
        let peers = server
            .mock("GET", "/api/v1/peers")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"boom"}"#)
            .expect(1)
            .create_async()
            .await;
        let args = SyncArgs {
            cmd: SyncCmd::Status,
            node: server.url(),
            dir: None,
        };
        let err = run(args).await.unwrap_err();
        assert!(
            err.to_string().contains("500"),
            "expected 500 surfaced, got: {err}"
        );
        peers.assert_async().await;
    }
}
