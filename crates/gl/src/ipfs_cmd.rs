//! `gl ipfs` — IPFS pin management commands.
//!
//! Communicates with the gitlawb node to list pinned CIDs and retrieve git
//! objects by their content-addressed CID.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::http::NodeClient;

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
    let resp: Value = client
        .get_signed("/api/v1/ipfs/pins")
        .await?
        .json()
        .await
        .context("failed to parse pins response")?;

    let pins = resp["pins"].as_array().cloned().unwrap_or_default();
    let count = resp["count"].as_u64().unwrap_or(pins.len() as u64);

    if pins.is_empty() {
        println!("No IPFS pins recorded on {node}");
        println!("(Push to a repo with GITLAWB_IPFS_API set to start pinning)");
        return Ok(());
    }

    println!("IPFS pins ({count}) on {node}");
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
            .mock("GET", "/api/v1/ipfs/pins")
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
            .mock("GET", "/api/v1/ipfs/pins")
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
            .mock("GET", "/api/v1/ipfs/pins")
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
}
