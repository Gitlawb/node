//! `gl cert` — ref certificate commands.
//!
//! Certificates are node-signed receipts proving that a push was accepted.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
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
    // error exit. Route the lookup through read_json so a denial or a capped
    // error body yields a reportable reason instead of an opaque None, and keep
    // "carried no DID" distinct from "the lookup failed": an empty DID must not
    // reach the comparison and fabricate a mismatch warning.
    let current: std::result::Result<String, String> = match client.get("/").await {
        Ok(resp) => match crate::http::read_json(resp, "node info").await {
            Ok(info) => did_from_node_info(&info),
            Err(e) => Err(e.to_string()),
        },
        Err(e) => Err(e.to_string()),
    };
    let current_node_did = current.as_ref().ok().cloned();
    for line in did_check_report(&current, node_did) {
        println!("{line}");
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

/// Pull the node's DID out of a `GET /` body for the comparison in `cmd_show`.
///
/// A missing OR empty `did` is a failure, not a value: letting `""` through
/// would reach the comparison and print a mismatch WARNING against a DID the
/// node never claimed, which reads as "issued by a different node" when the
/// truth is that the lookup told us nothing.
fn did_from_node_info(info: &serde_json::Value) -> std::result::Result<String, String> {
    match info["did"].as_str() {
        Some(did) if !did.is_empty() => Ok(did.to_string()),
        _ => Err("node info response carried no DID".to_string()),
    }
}

/// Select the report lines for the node-DID comparison in `cmd_show`.
///
/// `current` is the current node's DID, or the reason it could not be
/// determined. A comparison verdict (match or WARNING) is only produced when a
/// real DID was obtained; otherwise the report degrades to a could-not-compare
/// hint naming the reason, plus the offline-verification guidance. The signature
/// verdict printed above stands on its own either way — this block only answers
/// *which* node issued the certificate.
fn did_check_report(current: &std::result::Result<String, String>, node_did: &str) -> Vec<String> {
    match current {
        Ok(current) if current == node_did => {
            vec!["  Issuing node DID matches the node being queried.".to_string()]
        }
        Ok(current) => vec![
            format!("  WARNING: Certificate node DID ({node_did}) does not match"),
            format!("           current node DID ({current})."),
            "           This certificate was issued by a different node.".to_string(),
        ],
        Err(reason) => vec![
            format!("  Could not fetch the current node's DID ({reason}), so the comparison"),
            "  with the certificate's node DID is unavailable.".to_string(),
            "  To verify offline, use the node's Ed25519 public key derived from:".to_string(),
            format!("    did:key → {node_did}"),
        ],
    }
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

    // ── --verify issuer anchoring ────────────────────────────────────────────
    //
    // Every other cmd_show test passes require_valid=false, so the whole
    // `if require_valid` block went unexecuted. It is the security-bearing half of
    // the command: a valid signature only proves the certificate is internally
    // consistent (a hostile node can mint a keypair, name it in node_did, and
    // self-sign), so --verify must additionally anchor the issuer to a DID the
    // caller trusts. These drive all four outcomes plus the must-not case.
    //
    // The certificate must carry a REAL signature over the canonical payload:
    // with a bogus one, --verify bails on the signature and never reaches the
    // anchoring, which would make every assertion below vacuous.
    fn signed_cert(node_kp: &gitlawb_core::identity::Keypair) -> (String, String) {
        let node_did = node_kp.did().as_str().to_string();
        let id = "a".repeat(36); // >= 36 chars skips resolve_cert_id's prefix lookup
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "b".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
        let sig = node_kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        let body = serde_json::json!({
            "id": id,
            "repo_id": "repo-1",
            "ref_name": "refs/heads/main",
            "old_sha": "0".repeat(40),
            "new_sha": "b".repeat(40),
            "pusher_did": "did:key:z6MkPusher",
            "node_did": node_did,
            "signature": sig,
            "issued_at": "2026-07-22T00:00:00+00:00",
        })
        .to_string();
        (id, body)
    }

    /// Mount the cert fetch, plus a `GET /` answering with `node_info` (a JSON
    /// body) or a denial when `None`.
    async fn cert_server(
        server: &mut mockito::Server,
        id: &str,
        cert_body: &str,
        node_info: Option<&str>,
    ) -> (mockito::Mock, mockito::Mock) {
        let cert = server
            .mock("GET", format!("/api/v1/repos/alice/r/certs/{id}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(cert_body)
            .expect(1)
            .create_async()
            .await;
        let root = match node_info {
            Some(b) => {
                server
                    .mock("GET", "/")
                    .with_status(200)
                    .with_header("content-type", "application/json")
                    .with_body(b)
                    .create_async()
                    .await
            }
            None => {
                server
                    .mock("GET", "/")
                    .with_status(403)
                    .with_header("content-type", "application/json")
                    .with_body(r#"{"message":"denied"}"#)
                    .create_async()
                    .await
            }
        };
        (cert, root)
    }

    #[tokio::test]
    async fn verify_ok_when_issuing_node_is_the_queried_node() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let info = format!(r#"{{"did":"{}"}}"#, kp.did().as_str());
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, Some(&info)).await;

        let got = cmd_show("alice/r".to_string(), id, server.url(), None, true, None).await;
        assert!(
            got.is_ok(),
            "valid sig + matching issuer must pass: {got:?}"
        );
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_bails_when_issuer_is_a_different_node() {
        // The self-signing-hostile-node case: the signature verifies against the
        // key the cert names, but that key is not the node we queried.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let other = gitlawb_core::identity::Keypair::generate();
        let info = format!(r#"{{"did":"{}"}}"#, other.did().as_str());
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, Some(&info)).await;

        let err = cmd_show("alice/r".to_string(), id, server.url(), None, true, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected issuer"), "got: {err}");
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_bails_when_node_info_denied_and_no_expect_node() {
        // Fail closed: with no trusted DID to anchor against, --verify must NOT
        // fall through to a pass just because the signature checked out.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, None).await;

        let err = cmd_show("alice/r".to_string(), id, server.url(), None, true, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot anchor the issuer"), "got: {err}");
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_ok_when_expect_node_anchors_a_denied_lookup() {
        // --expect-node supplies the trust anchor the denied lookup could not, so
        // the same denial that fails the case above now passes.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &body, None).await;

        let got = cmd_show(
            "alice/r".to_string(),
            id,
            server.url(),
            None,
            true,
            Some(kp.did().as_str().to_string()),
        )
        .await;
        assert!(got.is_ok(), "explicit anchor must pass: {got:?}");
        cert.assert_async().await;
    }

    #[tokio::test]
    async fn verify_bails_on_a_bad_signature_before_anchoring() {
        // The must-not: a forged certificate naming the queried node must fail on
        // the signature, even though its issuer would otherwise anchor cleanly.
        let kp = gitlawb_core::identity::Keypair::generate();
        let (id, body) = signed_cert(&kp);
        let forged = body.replace(&"b".repeat(40), &"c".repeat(40));
        let info = format!(r#"{{"did":"{}"}}"#, kp.did().as_str());
        let mut server = mockito::Server::new_async().await;
        let (cert, _root) = cert_server(&mut server, &id, &forged, Some(&info)).await;

        let err = cmd_show("alice/r".to_string(), id, server.url(), None, true, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("signature did not verify"), "got: {err}");
        cert.assert_async().await;
    }

    // The must-not case for the DID extraction: an empty or missing `did` has to
    // become a could-not-compare reason. If it leaks through as a value, the
    // comparison below fabricates a mismatch WARNING against a DID the node
    // never claimed.
    #[test]
    fn did_from_node_info_rejects_empty_and_missing() {
        assert!(did_from_node_info(&serde_json::json!({"did": "n"})).is_ok());
        for body in [
            serde_json::json!({"did": ""}),
            serde_json::json!({}),
            serde_json::json!({"did": 7}),
        ] {
            let got = did_from_node_info(&body);
            assert!(
                got.is_err(),
                "must not yield a comparable DID: {body} -> {got:?}"
            );
        }
        // And the reason it produces must route to the degraded hint, never a verdict.
        let report =
            did_check_report(&did_from_node_info(&serde_json::json!({"did": ""})), "n").join("\n");
        assert!(
            !report.contains("WARNING"),
            "fabricated a mismatch: {report}"
        );
        assert!(report.contains("Could not fetch"), "got: {report}");
    }

    // did_check_report is the three-way selector between the match text, the
    // mismatch WARNING, and the degraded could-not-compare hint. Substring
    // asserts (not full-line equality) so cosmetic wording edits don't break them.

    #[test]
    fn did_check_report_match() {
        let report = did_check_report(&Ok("n".to_string()), "n").join("\n");
        assert!(
            report.contains("matches the node being queried"),
            "got: {report}"
        );
        assert!(!report.contains("WARNING"), "got: {report}");
        assert!(!report.contains("Could not fetch"), "got: {report}");
    }

    #[test]
    fn did_check_report_mismatch() {
        let report = did_check_report(&Ok("did:key:other".to_string()), "n").join("\n");
        assert!(report.contains("WARNING"), "got: {report}");
        assert!(report.contains("does not match"), "got: {report}");
        assert!(report.contains("did:key:other"), "got: {report}");
        assert!(!report.contains("Could not fetch"), "got: {report}");
    }

    #[test]
    fn did_check_report_missing_did_reason() {
        let report =
            did_check_report(&Err("node info response carried no DID".to_string()), "n").join("\n");
        assert!(report.contains("Could not fetch"), "got: {report}");
        assert!(
            report.contains("node info response carried no DID"),
            "got: {report}"
        );
        assert!(report.contains("verify offline"), "got: {report}");
        // The must-not case: no real DID was obtained, so no comparison verdict
        // may be claimed in either direction.
        assert!(!report.contains("WARNING"), "got: {report}");
        assert!(
            !report.contains("matches the node being queried"),
            "got: {report}"
        );
    }

    #[test]
    fn did_check_report_lookup_error_reason() {
        let report =
            did_check_report(&Err("node info failed (403): denied".to_string()), "n").join("\n");
        assert!(report.contains("Could not fetch"), "got: {report}");
        assert!(report.contains("403"), "got: {report}");
        assert!(report.contains("verify offline"), "got: {report}");
        assert!(!report.contains("WARNING"), "got: {report}");
    }
}
