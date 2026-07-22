//! `gl ipfs` — IPFS pin management commands.
//!
//! Communicates with the gitlawb node to list pinned CIDs and retrieve git
//! objects by their content-addressed CID.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::http::{capped_response, NodeClient};

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
        /// Identity directory (default: ~/.gitlawb)
        #[arg(long)]
        dir: Option<PathBuf>,
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
        IpfsCmd::List { node, dir } => cmd_list(node, dir).await,
        IpfsCmd::Get { cid, node } => cmd_get(cid, node).await,
    }
}

async fn cmd_list(node: String, dir: Option<PathBuf>) -> Result<()> {
    // #134 gates /api/v1/ipfs/pins behind auth: sign the request with the
    // caller's identity. On no identity, propagate load_keypair_from_dir's
    // error (it already names `gl identity new`) rather than a bare 401.
    let keypair = crate::identity::load_keypair_from_dir(dir.as_deref())?;
    let client = NodeClient::new(&node, Some(keypair));
    let (pins, incomplete) = list_pins_paginated(&client).await?;

    let count = pins.len();

    if pins.is_empty() {
        if incomplete {
            println!("IPFS pins on {node}: listing incomplete — unable to enumerate all pins");
        } else {
            println!("No IPFS pins recorded on {node}");
            println!("(Push to a repo with GITLAWB_IPFS_API set to start pinning)");
        }
        return Ok(());
    }

    print!("IPFS pins ({count}) on {node}");
    if incomplete {
        print!(" (truncated — too many results)");
    }
    println!();
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

/// Sanitize a node response body for inclusion in CLI error messages.
/// Strips ANSI/OSC control sequences and non-printable bytes (except
/// newline and tab) so a malicious or compromised node cannot inject
/// terminal output through an otherwise bounded error body (P2).
/// Truncates on a char boundary (not a byte boundary) to avoid panicking
/// on multi-byte UTF-8 (P2).
fn sanitize_body(body: &str) -> String {
    const MAX_BODY_CHARS: usize = 500;
    body.chars()
        .take(MAX_BODY_CHARS)
        .filter(|&c| c.is_ascii_graphic() || c == ' ' || c == '\n' || c == '\t')
        .collect()
}

/// Paginate through the full pin listing, collecting all pins and handling
/// the expired-truncated_cursor retry (P2).  The last_next_cursor restore
/// may cause a duplicate page (self-limiting via the cycle guard).
async fn list_pins_paginated(client: &NodeClient) -> Result<(Vec<Value>, bool)> {
    let mut all_pins = Vec::new();
    let mut all_pins_bytes = 0usize;
    let mut cursor: Option<String> = None;
    let mut truncated_cursor: Option<String> = None;
    // Persist the last next_cursor across the truncated leg so that an
    // expired truncated_cursor (400) can resume from where we left off
    // rather than restarting at page 1 (P2).  Note: this may re-fetch
    // the page before the truncated one (self-limiting via cycle guard).
    let mut last_next_cursor: Option<String> = None;
    // Advancement guard: track every cursor value seen to detect cycles.
    let mut seen_cursors: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut incomplete = false;
    let mut pages = 0u32;
    // Consecutive empty pages without forward progress: a buggy or hostile
    // node that returns empty pages with fresh cursors cannot loop
    // indefinitely (P2).
    let mut consecutive_empty_pages = 0u32;
    const MAX_CONSECUTIVE_EMPTY: u32 = 5;
    // Bounds: at most 10 000 pages, 1 000 000 rows total, 512 MiB
    // aggregate retained JSON, or 64 MiB per response body — limits
    // unbounded loops and prevents a single oversized page from
    // exhausting memory before the row cap is checked (P2).
    const MAX_PAGES: u32 = 10_000;
    const MAX_ROWS: usize = 1_000_000;
    const MAX_AGGREGATE_BYTES: usize = 512 * 1024 * 1024;
    const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

    loop {
        pages += 1;
        if pages > MAX_PAGES {
            incomplete = true;
            break;
        }

        // Request the maximum page size to minimise page-turn requests
        // against the per-DID quota (P2).
        // Server clamps limit to 200 per page (P2).  Request the max so we
        // minimise page-turn requests against the per-DID quota.
        let mut path = "/api/v1/ipfs/pins?limit=200".to_string();
        let mut params = Vec::new();
        let mut had_truncated = false;
        if let Some(c) = cursor.take() {
            params.push(format!("cursor={}", urlencoding::encode(&c)));
        }
        if let Some(tc) = truncated_cursor.take() {
            had_truncated = true;
            params.push(format!("truncated_cursor={}", urlencoding::encode(&tc)));
        }
        for p in &params {
            path.push('&');
            path.push_str(p);
        }

        let resp = client.get_signed(&path).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            // P1: rate-limited — surface a partial result instead of failing.
            if status == 429 {
                incomplete = true;
                break;
            }
            if status == 400 && had_truncated {
                let body = String::from_utf8_lossy(
                    &capped_response(resp, MAX_RESPONSE_BYTES)
                        .await
                        .unwrap_or_default(),
                )
                .to_string();
                // Only treat a 400 as expired-cursor when the server explicitly
                // says so.  Any other 400 — malformed cursor, protocol change,
                // node bug — is surfaced as an error.
                if body.contains("invalid or expired truncated_cursor") {
                    cursor = last_next_cursor.clone();
                    continue;
                }
                anyhow::bail!(
                    "node returned 400 for pins listing: {}",
                    sanitize_body(&body)
                );
            }
            let body = String::from_utf8_lossy(
                &capped_response(resp, MAX_RESPONSE_BYTES)
                    .await
                    .unwrap_or_default(),
            )
            .to_string();
            anyhow::bail!(
                "node returned {status} for pins listing: {}",
                sanitize_body(&body)
            );
        }
        let body = capped_response(resp, MAX_RESPONSE_BYTES).await?;
        let resp: Value = serde_json::from_slice(&body).with_context(|| {
            format!(
                "failed to parse pins response ({len} bytes)",
                len = body.len()
            )
        })?;

        let pins = resp["pins"].as_array().cloned().unwrap_or_default();

        if pins.is_empty() {
            consecutive_empty_pages += 1;
            if consecutive_empty_pages >= MAX_CONSECUTIVE_EMPTY {
                incomplete = true;
                break;
            }
        } else {
            consecutive_empty_pages = 0;
        }

        if all_pins.len() + pins.len() > MAX_ROWS {
            incomplete = true;
            break;
        }

        // Aggregate memory bound: track the serialised size of each pin
        // JSON object to prevent a malicious node from exhausting the
        // CLI's memory with many small pages of oversized fields (P2).
        for pin in &pins {
            all_pins_bytes += serde_json::to_string(pin).map(|s| s.len()).unwrap_or(256);
        }
        if all_pins_bytes > MAX_AGGREGATE_BYTES {
            incomplete = true;
            break;
        }

        let next = resp["next_cursor"].as_str().map(String::from);
        let new_trunc = resp["truncated_cursor"].as_str().map(String::from);

        // Detect cursor cycling: keys on the exact (next_cursor, truncated)
        // pair, so a node that returns a fresh pair every page never trips it.
        // MAX_PAGES provides the ultimate bound (10 K round-trips per listing).
        let cycle_key =
            next.as_deref().unwrap_or("").to_string() + "|" + new_trunc.as_deref().unwrap_or("");

        // Bound cursor / cycle-key retained bytes alongside pin data so a
        // node returning fresh near-64 MiB cursors per page cannot exhaust
        // memory via the seen_cursors set (P3).  Account for the cycle_key
        // string that will be stored in seen_cursors plus HashSet entry
        // overhead (~32 bytes per entry).
        all_pins_bytes += cycle_key.len() + 32;
        if all_pins_bytes > MAX_AGGREGATE_BYTES {
            incomplete = true;
            break;
        }

        if !cycle_key.is_empty() && !seen_cursors.insert(cycle_key) {
            incomplete = true;
            break;
        }

        all_pins.extend(pins);

        if next.is_none() && new_trunc.is_none() {
            break;
        }
        if let Some(ref n) = next {
            last_next_cursor = Some(n.clone());
        }
        cursor = next;
        truncated_cursor = new_trunc;
    }

    Ok((all_pins, incomplete))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed a keypair into a temp dir the way `load_keypair_from_dir` expects,
    /// then return the dir handle (keeps it alive for the test's duration).
    fn seed_keystore() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        dir
    }

    #[tokio::test]
    async fn test_cmd_list_signs_request_and_renders_pins() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        // Happy path: signed GET to /api/v1/ipfs/pins carrying the RFC 9421
        // signature headers, node returns a populated pins body.
        let m = server
            .mock("GET", mockito::Matcher::Regex(r"^/api/v1/ipfs/pins".to_string()))
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .match_header("content-digest", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"pins":[{"cid":"bafyone","sha256_hex":"abc123","pinned_at":"2026-07-02T12:00:00.123456Z"}],"count":1}"#,
            )
            .create_async()
            .await;

        cmd_list(server.url(), Some(keystore.path().to_path_buf()))
            .await
            .unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_empty_pins() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/ipfs/pins".to_string()),
            )
            .match_header("signature", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"pins":[],"count":0}"#)
            .create_async()
            .await;

        cmd_list(server.url(), Some(keystore.path().to_path_buf()))
            .await
            .unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_no_identity_errors_without_request() {
        let mut server = mockito::Server::new_async().await;
        // Empty keystore dir: no identity.pem present.
        let empty = tempfile::TempDir::new().unwrap();

        // The endpoint must never be hit when there is no identity.
        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/ipfs/pins".to_string()),
            )
            .expect(0)
            .create_async()
            .await;

        let err = cmd_list(server.url(), Some(empty.path().to_path_buf()))
            .await
            .expect_err("no identity should be an error");
        assert!(
            err.to_string().contains("gl identity new")
                || err.to_string().contains("no identity found"),
            "error should name `gl identity new`, got: {err}"
        );

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_non_success_status_is_error_not_empty() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        // A signed request the node rejects (401) must surface as an error,
        // not be silently parsed into an empty pin list.
        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/ipfs/pins".to_string()),
            )
            .match_header("signature", mockito::Matcher::Any)
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"unauthorized"}"#)
            .create_async()
            .await;

        let err = cmd_list(server.url(), Some(keystore.path().to_path_buf()))
            .await
            .expect_err("non-2xx status should be an error");
        assert!(
            err.to_string().contains("401"),
            "error should mention the status, got: {err}"
        );

        m.assert_async().await;
    }
}
