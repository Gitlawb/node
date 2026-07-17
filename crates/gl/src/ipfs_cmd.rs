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
        /// Identity directory (default: ~/.gitlawb)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: IpfsArgs) -> Result<()> {
    match args.cmd {
        IpfsCmd::List { node, dir } => cmd_list(node, dir).await,
        IpfsCmd::Get { cid, node, dir } => cmd_get(cid, node, dir).await,
    }
}

async fn cmd_list(node: String, dir: Option<PathBuf>) -> Result<()> {
    // #134 gates /api/v1/ipfs/pins behind auth: sign the request with the
    // caller's identity. On no identity, propagate load_keypair_from_dir's
    // error (it already names `gl identity new`) rather than a bare 401.
    let keypair = crate::identity::load_keypair_from_dir(dir.as_deref())?;
    let client = NodeClient::new(&node, Some(keypair));
    let resp = client.get_signed("/api/v1/ipfs/pins").await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("node returned {status} for pins listing: {body}");
    }
    let resp: Value = resp.json().await.context("failed to parse pins response")?;

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

async fn cmd_get(cid: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    // #173 (F5): the resolver now serves path-scoped objects to authorized readers,
    // so sign with an available identity like `gl ipfs list` — otherwise an owner or
    // listed reader gets the opaque anonymous 404 for content they can read.
    // `get_authed` signs when a keypair is present and falls back to unsigned.
    //
    // An explicit `--dir` is a request to use THAT identity: propagate a
    // missing/corrupt-keystore error (like `list`) instead of silently sending an
    // anonymous request the authorized reader would see as the node's opaque 404
    // (#173 review). Only the default (no `--dir`) keeps the best-effort unsigned
    // fallback, so `get` stays usable for genuinely public content.
    let keypair = match dir.as_deref() {
        Some(dir) => Some(crate::identity::load_keypair_from_dir(Some(dir))?),
        None => crate::identity::load_keypair_from_dir(None).ok(),
    };
    let client = NodeClient::new(&node, keypair);
    // #173 review (F1): the node now accepts equivalent multibase spellings,
    // including base64 CIDs (prefix 'm'), whose alphabet contains '/', '+', '='.
    // Interpolating the CID raw would make the client request (and sign)
    // `/ipfs/<prefix>/<suffix>`, which neither matches the single-segment Axum
    // route nor points at the intended target. Percent-encode the CID as exactly
    // one path segment so the signed and sent target agree and the server's
    // `Path` extractor decodes it back to the original CID.
    let path = format!("/ipfs/{}", encode_cid_segment(&cid));
    let resp = client
        .get_authed(&path)
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

/// Percent-encode a CID so it occupies exactly one path segment of `/ipfs/<cid>`.
/// `urlencoding::encode` escapes every byte outside the RFC 3986 unreserved set
/// (ALPHA / DIGIT / `-._~`), so the base64-CID characters that would otherwise
/// break the single-segment route — `/`, `+`, `=` — are all escaped, and the
/// server's `Path` extractor decodes the result back to the original CID (#173
/// review, F1).
fn encode_cid_segment(cid: &str) -> String {
    urlencoding::encode(cid).into_owned()
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

    #[tokio::test]
    async fn test_cmd_list_non_success_status_is_error_not_empty() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        // A signed request the node rejects (401) must surface as an error,
        // not be silently parsed into an empty pin list.
        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
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

    /// #173 (F5): `gl ipfs get` must SIGN with an available identity, like
    /// `gl ipfs list`, so an owner/reader can retrieve a path-scoped object the node
    /// now resolves by CID. RED before the fix: cmd_get ignores the identity dir and
    /// sends an unsigned request, so the signature-matching mock is never hit
    /// (cmd_get errors on the unmatched 501, and m.assert fails). GREEN after: the
    /// signed request carries the RFC 9421 headers and is served 200.
    #[tokio::test]
    async fn test_cmd_get_signs_when_identity_present() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        let m = server
            .mock("GET", "/ipfs/bafkreitestcid")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("x-git-hash", "abc123")
            .with_body("object bytes")
            .create_async()
            .await;

        cmd_get(
            "bafkreitestcid".to_string(),
            server.url(),
            Some(keystore.path().to_path_buf()),
        )
        .await
        .expect("signed get of a resolvable object should succeed");

        m.assert_async().await;
    }

    /// #173 (F5) must-not: a genuine anonymous denial must surface as an error, not
    /// be masked as success. With no identity dir the request is unsigned; a 404
    /// from the node must produce an Err mentioning the status.
    #[tokio::test]
    async fn test_cmd_get_anonymous_denial_is_error() {
        let mut server = mockito::Server::new_async().await;

        let m = server
            .mock("GET", "/ipfs/bafkreidenied")
            .with_status(404)
            .with_header("content-type", "text/plain")
            .with_body("no git object found")
            .create_async()
            .await;

        let err = cmd_get("bafkreidenied".to_string(), server.url(), None)
            .await
            .expect_err("a 404 denial must be an error, not masked success");
        assert!(
            err.to_string().contains("404"),
            "error should mention the status, got: {err}"
        );

        m.assert_async().await;
    }

    /// #173 (INV-8) must-not: the node's new 503 "search incomplete" (the legacy CID
    /// scan hit its bound and could not prove absence) must surface as an actionable
    /// Err naming the status, NOT be rendered as an empty/"not found" success — a
    /// retryable outcome the caller has to see. Mirrors the 404 denial case for the
    /// bounded-search response the resolver now emits.
    #[tokio::test]
    async fn test_cmd_get_search_incomplete_503_is_error() {
        let mut server = mockito::Server::new_async().await;

        let m = server
            .mock("GET", "/ipfs/bafkreiincomplete")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"search_incomplete","message":"CID search incomplete — retry"}"#)
            .create_async()
            .await;

        let err = cmd_get("bafkreiincomplete".to_string(), server.url(), None)
            .await
            .expect_err("a 503 incomplete-search must be an error, not masked as not-found");
        assert!(
            err.to_string().contains("503"),
            "error should mention the status, got: {err}"
        );

        m.assert_async().await;
    }

    /// #173 review (F1): a base64 CID (multibase prefix 'm') can contain '/', '+',
    /// and '='. The client must percent-encode it into ONE path segment before
    /// building and signing `/ipfs/<cid>`; otherwise the '/' splits the target so
    /// it misses the single-segment Axum route and the signature covers the wrong
    /// path. Assert the encoded segment carries no raw '/', '+', or '=', and that
    /// it decodes back to the original CID (the server's `Path` extractor performs
    /// that same decode). RED with the old raw `format!("/ipfs/{cid}")`: the
    /// segment still contains '/'.
    #[test]
    fn test_encode_cid_segment_escapes_base64_alphabet() {
        let cid = "mFoo/Bar+baz==";
        let encoded = encode_cid_segment(cid);

        assert!(
            !encoded.contains('/'),
            "encoded CID must be a single path segment (no raw '/'), got: {encoded}"
        );
        assert!(
            !encoded.contains('+'),
            "encoded CID must escape '+', got: {encoded}"
        );
        assert!(
            !encoded.contains('='),
            "encoded CID must escape '=', got: {encoded}"
        );

        let decoded = urlencoding::decode(&encoded).expect("encoded CID must decode");
        assert_eq!(
            decoded, cid,
            "encoding must round-trip back to the original CID"
        );
    }

    /// #173 review: `gl ipfs get --dir <path>` must PROPAGATE a missing/corrupt
    /// identity-load error like `gl ipfs list`, not silently fall back to an anonymous
    /// request — otherwise an authorized reader pointing `--dir` at a broken keystore
    /// gets the node's opaque 404 instead of the actionable key-load error. The
    /// unsigned fallback is preserved only when NO `--dir` is given (covered by
    /// `test_cmd_get_anonymous_denial_is_error`). RED before the fix (`.ok()` swallows
    /// the error, an anonymous request is sent, and the `.expect(0)` mock is hit),
    /// GREEN after.
    #[tokio::test]
    async fn test_cmd_get_explicit_dir_no_identity_errors_without_request() {
        let mut server = mockito::Server::new_async().await;
        // Empty keystore dir passed explicitly via --dir: no identity.pem present.
        let empty = tempfile::TempDir::new().unwrap();

        // The endpoint must never be hit when an explicit --dir fails to load.
        let m = server
            .mock("GET", "/ipfs/bafkreitestcid")
            .expect(0)
            .create_async()
            .await;

        let err = cmd_get(
            "bafkreitestcid".to_string(),
            server.url(),
            Some(empty.path().to_path_buf()),
        )
        .await
        .expect_err("an explicit --dir that fails to load must be an error");
        assert!(
            err.to_string().contains("gl identity new")
                || err.to_string().contains("no identity found")
                || err.to_string().contains("failed to load keypair"),
            "error should name the key-load failure, got: {err}"
        );

        m.assert_async().await;
    }
}
