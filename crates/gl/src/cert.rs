//! `gl cert` — ref certificate commands.
//!
//! Certificates are node-signed receipts proving that a push was accepted.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

fn signed_client(node: &str, dir: Option<&std::path::Path>) -> NodeClient {
    NodeClient::new(node, load_keypair_from_dir(dir).ok())
}

#[derive(Args)]
pub struct CertArgs {
    #[command(subcommand)]
    pub cmd: CertCmd,
}

#[derive(Subcommand)]
pub enum CertCmd {
    /// List ref certificates for a repository
    List {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show a specific ref certificate and verify its signature
    Show {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        /// Certificate ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Exit non-zero unless the Ed25519 signature verifies AND the
        /// issuing node matches the queried node (or --expect-node)
        #[arg(long)]
        verify: bool,
        /// Expected issuing node DID for --verify. A valid signature alone
        /// only proves the cert is internally consistent — signed by whatever
        /// key it names — so --verify also anchors the issuer to a DID you
        /// trust: this value when given, else the queried node's DID.
        #[arg(long, requires = "verify")]
        expect_node: Option<String>,
    },
}

pub async fn run(args: CertArgs) -> Result<()> {
    match args.cmd {
        CertCmd::List { repo, node, dir } => cmd_list(repo, node, dir).await,
        CertCmd::Show {
            repo,
            id,
            node,
            dir,
            verify,
            expect_node,
        } => cmd_show(repo, id, node, dir, verify, expect_node).await,
    }
}

/// Resolve "repo" into (owner, name) using the caller's DID when no slash is given.
async fn resolve_repo(
    repo: &str,
    node: &str,
    dir: Option<&std::path::Path>,
) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        Ok((owner.to_string(), name.to_string()))
    } else {
        let short = if let Ok(kp) = load_keypair_from_dir(dir) {
            let did = kp.did().to_string();
            did.split(':').next_back().unwrap_or(&did).to_string()
        } else {
            let client = signed_client(node, dir);
            let info = crate::http::read_json(client.get_authed("/").await?, "node info").await?;
            let did = info["did"].as_str().context("node info missing 'did'")?;
            did.split(':').next_back().unwrap_or(did).to_string()
        };
        Ok((short, repo.to_string()))
    }
}

async fn cmd_list(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let client = signed_client(&node, dir.as_deref());
    let path = format!("/api/v1/repos/{owner}/{name}/certs");
    let resp = crate::http::read_json(client.get_authed(&path).await?, "certificates").await?;

    let certs = resp["certificates"].as_array().cloned().unwrap_or_default();

    if certs.is_empty() {
        println!("No ref certificates for {owner}/{name}");
        return Ok(());
    }

    println!("Ref certificates for {owner}/{name}");
    println!();
    for cert in &certs {
        let id = cert["id"].as_str().unwrap_or("?");
        let ref_name = cert["ref_name"].as_str().unwrap_or("?");
        let new_sha = cert["new_sha"].as_str().unwrap_or("?");
        let issued_at = cert["issued_at"].as_str().map(|s| &s[..19]).unwrap_or("?");
        println!("  {id:.8}  {issued_at}  {ref_name}  {new_sha:.12}");
    }
    Ok(())
}

async fn cmd_show(
    repo: String,
    id: String,
    node: String,
    dir: Option<PathBuf>,
    require_valid: bool,
    expect_node: Option<String>,
) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let client = signed_client(&node, dir.as_deref());
    let id = resolve_cert_id(&client, &owner, &name, &id).await?;

    // Fetch the certificate. read_json checks status first and surfaces the node's
    // capped+sanitized message on a non-2xx (a bounded error read, not the whole body).
    let path = format!("/api/v1/repos/{owner}/{name}/certs/{id}");
    let cert = crate::http::read_json(client.get_authed(&path).await?, "certificate").await?;

    let cert_id = cert["id"].as_str().unwrap_or("?");
    let ref_name = cert["ref_name"].as_str().unwrap_or("?");
    let old_sha = cert["old_sha"].as_str().unwrap_or("?");
    let new_sha = cert["new_sha"].as_str().unwrap_or("?");
    let pusher = cert["pusher_did"].as_str().unwrap_or("?");
    let node_did = cert["node_did"].as_str().unwrap_or("?");
    let signature = cert["signature"].as_str().unwrap_or("?");
    let issued_at = cert["issued_at"].as_str().unwrap_or("?");

    println!("Ref Certificate: {cert_id}");
    println!("  Ref:       {ref_name}");
    println!("  Old SHA:   {old_sha}");
    println!("  New SHA:   {new_sha}");
    println!("  Pusher:    {pusher}");
    println!("  Node DID:  {node_did}");
    println!("  Issued at: {issued_at}");
    println!("  Signature: {signature}");
    println!();

    // Verify the Ed25519 signature: rebuild the exact canonical payload the
    // node signed (see gitlawb-node/src/cert.rs::issue_ref_certificate) and
    // check it against the public key embedded in the certificate's node DID.
    // This proves the cert is internally authentic — signed by the key it
    // names; the node-DID comparison below covers *which* node that is.
    let repo_id = cert["repo_id"].as_str().unwrap_or("");
    let verdict = verify_signature(
        repo_id, ref_name, old_sha, new_sha, pusher, node_did, issued_at, signature,
    );

    println!("Signature verification:");
    match &verdict {
        Ok(()) => {
            println!(
                "  VALID — Ed25519 signature verified against the key the certificate names ({node_did})"
            );
        }
        Err(reason) => {
            println!("  INVALID — {reason}");
        }
    }

    // Contextual only — the verdict above stands on its own, so a node-info
    // hiccup here must not turn a successfully displayed certificate into an
    // error exit.
    let current_node_did = match client.get("/").await {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|info| info["did"].as_str().map(str::to_string)),
        Err(_) => None,
    };
    match current_node_did.as_deref() {
        Some(current) if current == node_did => {
            println!("  Issuing node DID matches the node being queried.");
        }
        Some(current) => {
            println!("  WARNING: Certificate node DID ({node_did}) does not match");
            println!("           current node DID ({current}).");
            println!("           This certificate was issued by a different node.");
        }
        None => {
            println!("  NOTE: could not fetch current node info — skipping node-DID comparison.");
        }
    }

    if require_valid {
        if let Err(reason) = verdict {
            anyhow::bail!("certificate signature did not verify: {reason}");
        }
        // A valid signature proves internal consistency only: the payload was
        // signed by whatever key the certificate itself names. A hostile
        // source can mint a keypair, put its DID in node_did, and self-sign.
        // --verify therefore also anchors the issuer to a trusted DID:
        // --expect-node when given, else the DID of the node being queried.
        let expected = expect_node.as_deref().or(current_node_did.as_deref());
        match expected {
            Some(expected) if expected == node_did => {}
            Some(expected) => anyhow::bail!(
                "certificate is signed by {node_did}, but the expected issuer is {expected} — \
                 a valid signature alone proves internal consistency, not a trusted issuer"
            ),
            None => anyhow::bail!(
                "cannot anchor the issuer: node info is unreachable and no --expect-node was given"
            ),
        }
    }

    Ok(())
}

/// Rebuild the node's canonical signing payload (field order must match
/// gitlawb-node/src/cert.rs::issue_ref_certificate exactly) and verify the
/// certificate's Ed25519 signature against the key embedded in `node_did`.
#[allow(clippy::too_many_arguments)]
fn verify_signature(
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher: &str,
    node_did: &str,
    issued_at: &str,
    signature_b64: &str,
) -> std::result::Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use std::str::FromStr;

    let payload = serde_json::json!({
        "repo_id": repo_id,
        "ref":     ref_name,
        "old":     old_sha,
        "new":     new_sha,
        "pusher":  pusher,
        "node":    node_did,
        "ts":      issued_at,
    });
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| format!("could not serialize payload: {e}"))?;

    let did =
        gitlawb_core::did::Did::from_str(node_did).map_err(|e| format!("bad node DID: {e}"))?;
    let verifying_key = did
        .to_verifying_key()
        .map_err(|e| format!("cannot derive a public key from {node_did}: {e}"))?;

    let sig_vec = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| format!("signature is not valid base64url: {e}"))?;
    let sig_bytes: [u8; 64] = sig_vec
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())?;

    gitlawb_core::identity::verify(&verifying_key, &payload_bytes, &sig_bytes)
        .map_err(|_| "Ed25519 signature does not match the signed payload".to_string())
}

async fn resolve_cert_id(client: &NodeClient, owner: &str, name: &str, id: &str) -> Result<String> {
    if id.len() >= 36 {
        return Ok(id.to_string());
    }

    let path = format!("/api/v1/repos/{owner}/{name}/certs?prefix={id}");
    let resp = crate::http::read_json(client.get_authed(&path).await?, "certificates").await?;

    let certs = resp["certificates"].as_array().cloned().unwrap_or_default();
    let matches: Vec<String> = certs
        .iter()
        .filter_map(|cert| cert["id"].as_str())
        .map(ToString::to_string)
        .collect();

    match matches.as_slice() {
        [full_id] => Ok(full_id.to_string()),
        [] => Ok(id.to_string()),
        _ => anyhow::bail!("certificate prefix {id} matches multiple certificates"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins gl's payload reconstruction to the frozen canonical byte form the
    /// node signs (default serde_json maps = alphabetically ordered keys). If
    /// serialization drifts — a field added, or a preserve_order feature
    /// landing anywhere in the workspace (feature unification flips every
    /// crate at once) — this literal stops matching and the test fails,
    /// instead of every real certificate silently rendering INVALID.
    #[test]
    fn payload_serialization_matches_frozen_canonical_form() {
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "oldsha",
            "new":     "newsha",
            "pusher":  "did:key:z6MkPusher",
            "node":    "did:key:z6MkNode",
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let frozen = concat!(
            r#"{"new":"newsha","node":"did:key:z6MkNode","old":"oldsha","#,
            r#""pusher":"did:key:z6MkPusher","ref":"refs/heads/main","#,
            r#""repo_id":"repo-1","ts":"2026-07-22T00:00:00+00:00"}"#,
        );
        assert_eq!(serde_json::to_string(&payload).unwrap(), frozen);
    }

    /// Signing exactly as the node does must round-trip through
    /// verify_signature; any field tampering must fail it.
    #[test]
    fn verify_signature_round_trip_and_tamper() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did().as_str().to_string();

        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = kp.sign_b64(&serde_json::to_vec(&payload).unwrap());

        let ok = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            &sig,
        );
        assert!(ok.is_ok(), "expected valid signature, got: {ok:?}");

        let tampered = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"b".repeat(40), // new_sha changed after signing
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            &sig,
        );
        assert!(tampered.is_err(), "tampered payload must not verify");

        let garbage = verify_signature(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
            "not-base64url!!!",
        );
        assert!(garbage.is_err(), "malformed signature must not verify");
    }

    #[tokio::test]
    async fn cmd_list_surfaces_denial_not_empty() {
        // A gated 404 on the repo-scoped certs read must Err, not print "No certificates".
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/alice/secret/certs$".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = cmd_list("alice/secret".to_string(), server.url(), None).await;
        assert!(result.is_err(), "cert list must Err on a gated 404");
        // Prove the gated certs path was actually requested: without this, an
        // unmatched route (mockito's 501, also non-2xx) would satisfy is_err().
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn resolve_repo_surfaces_denial() {
        // A slash-free repo with an empty identity dir forces the GET / node-info
        // fetch. A gated 404 there must Err (surfacing the status), proving the
        // read_json conversion is load-bearing rather than silently ignored.
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap(); // empty, no identity.pem, forces the GET / branch
        let _m = server
            .mock("GET", "/")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;
        let err = resolve_repo("noslash", &server.url(), Some(dir.path()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
        _m.assert_async().await;
    }

    // The `GET /` node-info lookup after the cert loads is a fail-soft diagnostic:
    // a response-level failure degrades to a could-not-compare hint and the command
    // completes Ok, never a fabricated mismatch warning and never a fatal Err. The
    // cert fetch itself stays fail-closed. A >=36-char id skips resolve_cert_id so
    // only two mocks are needed.
    #[tokio::test]
    async fn cmd_show_completes_with_degraded_hint_when_node_info_denied() {
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "cert show must complete despite a denied node-info lookup: {result:?}"
        );
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_degrades_on_malformed_node_info() {
        // A 2xx node-info body that fails to parse degrades the same way a denial
        // does: hint printed, command completes Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_body("not json")
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "cert show must complete despite malformed node info: {result:?}"
        );
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_degrades_when_node_info_lacks_did() {
        // A 2xx node-info body with no `did` routes to the degraded hint, not a
        // fabricated empty-DID mismatch warning; the command completes Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "cert show must complete when node info lacks a DID: {result:?}"
        );
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    // Must-not case: the certificate fetch itself stays fail-closed. A gated 404
    // aborts the command with the status surfaced, and the node-info lookup is
    // never reached (the expect(0) assert proves it never ran).
    #[tokio::test]
    async fn cmd_show_surfaces_denied_certificate() {
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"n"}"#)
            .expect(0)
            .create_async()
            .await;

        let err = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_reports_matching_node_did() {
        // Pins the unchanged success path: node info fetched, DIDs compared, Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"n"}"#)
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(result.is_ok(), "got: {result:?}");
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_warns_on_mismatching_node_did() {
        // A real, differing node DID drives the WARNING branch end to end; the
        // command still completes Ok.
        let mut server = mockito::Server::new_async().await;
        let long_id = "a".repeat(36);
        let _cert = server
            .mock(
                "GET",
                format!("/api/v1/repos/alice/secret/certs/{long_id}").as_str(),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"c1","ref_name":"refs/heads/main","old_sha":"0","new_sha":"1","pusher_did":"p","node_did":"n","signature":"s","issued_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create_async()
            .await;
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:other"}"#)
            .expect(1)
            .create_async()
            .await;

        let result = cmd_show(
            "alice/secret".to_string(),
            long_id,
            server.url(),
            None,
            false,
            None,
        )
        .await;
        assert!(result.is_ok(), "got: {result:?}");
        _cert.assert_async().await;
        _root.assert_async().await;
    }
}
