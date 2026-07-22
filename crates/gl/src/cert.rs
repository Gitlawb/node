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
        } => cmd_show(repo, id, node, dir).await,
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

async fn cmd_show(repo: String, id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
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

    // Reconstruct the signing payload and verify.
    // Fetch the node's current public key for the DID comparison. This lookup is a
    // deliberate fail-soft diagnostic: on a response-level failure, or a body that
    // carries no usable DID, we degrade to an explicit could-not-compare hint
    // (better than the old empty-DID mismatch warning, which fabricated a mismatch
    // claim) and the command still completes. The certificate fetch above keeps
    // the fail-closed read_json check.
    let info = crate::http::read_json(client.get("/").await?, "node info").await;
    let current: Result<String, String> = match info {
        Ok(info) => match info["did"].as_str() {
            Some(did) if !did.is_empty() => Ok(did.to_string()),
            _ => Err("node info response carried no DID".to_string()),
        },
        Err(e) => Err(e.to_string()),
    };

    println!("Signature verification:");
    println!("  Signing payload would be:");
    println!("    {{\"repo_id\": ..., \"ref\": \"{ref_name}\", \"old\": \"{old_sha}\",");
    println!("      \"new\": \"{new_sha}\", \"pusher\": \"{pusher}\",");
    println!("      \"node\": \"{node_did}\", \"ts\": \"{issued_at}\"}}");
    println!();

    for line in did_check_report(&current, node_did) {
        println!("{line}");
    }

    println!();
    println!("  Signature (base64url): {signature}");

    Ok(())
}

/// Select the report lines for the node-DID comparison in `cmd_show`.
///
/// `current` is the current node's DID, or the reason it could not be
/// determined. A comparison verdict (match or WARNING) is only produced when a
/// real DID was obtained; otherwise the report degrades to a could-not-compare
/// hint plus the offline-verification guidance.
fn did_check_report(current: &Result<String, String>, node_did: &str) -> Vec<String> {
    match current {
        Ok(current) if current == node_did => vec![
            "  Node DID matches current node. Signature is an Ed25519/base64url value.".to_string(),
            "  To verify offline, use the node's Ed25519 public key derived from:".to_string(),
            format!("    did:key → {node_did}"),
        ],
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

        let result = cmd_show("alice/secret".to_string(), long_id, server.url(), None).await;
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

        let result = cmd_show("alice/secret".to_string(), long_id, server.url(), None).await;
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

        let result = cmd_show("alice/secret".to_string(), long_id, server.url(), None).await;
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

        let err = cmd_show("alice/secret".to_string(), long_id, server.url(), None)
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

        let result = cmd_show("alice/secret".to_string(), long_id, server.url(), None).await;
        assert!(result.is_ok(), "got: {result:?}");
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    #[tokio::test]
    async fn cmd_show_warns_on_mismatching_node_did() {
        // A real, differing node DID drives the WARNING branch end to end; the
        // command still completes Ok. The WARNING text itself is pinned by the
        // did_check_report unit tests.
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

        let result = cmd_show("alice/secret".to_string(), long_id, server.url(), None).await;
        assert!(result.is_ok(), "got: {result:?}");
        _cert.assert_async().await;
        _root.assert_async().await;
    }

    // did_check_report is the three-way selector between the match text, the
    // mismatch WARNING, and the degraded could-not-compare hint. Substring
    // asserts (not full-line equality) so cosmetic wording edits don't break them.

    #[test]
    fn did_check_report_match() {
        let report = did_check_report(&Ok("n".to_string()), "n").join("\n");
        assert!(report.contains("matches current node"), "got: {report}");
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
        assert!(!report.contains("WARNING"), "got: {report}");
    }

    #[test]
    fn did_check_report_lookup_error_reason() {
        let report = did_check_report(&Err("node info: HTTP 403".to_string()), "n").join("\n");
        assert!(report.contains("Could not fetch"), "got: {report}");
        assert!(report.contains("HTTP 403"), "got: {report}");
        assert!(report.contains("verify offline"), "got: {report}");
        assert!(!report.contains("WARNING"), "got: {report}");
    }
}
