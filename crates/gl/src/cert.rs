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
        /// Exit non-zero unless the Ed25519 signature verifies
        #[arg(long)]
        verify: bool,
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
        } => cmd_show(repo, id, node, dir, verify).await,
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
            let info: Value = client
                .get_authed("/")
                .await?
                .json()
                .await
                .context("failed to fetch node info")?;
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
    let resp: Value = client
        .get_authed(&path)
        .await?
        .json()
        .await
        .context("failed to list certificates")?;

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
) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node, dir.as_deref()).await?;

    let client = signed_client(&node, dir.as_deref());
    let id = resolve_cert_id(&client, &owner, &name, &id).await?;

    // Fetch the certificate
    let path = format!("/api/v1/repos/{owner}/{name}/certs/{id}");
    let resp = client
        .get_authed(&path)
        .await?
        .error_for_status()
        .context("certificate not found")?;
    let cert: Value = resp.json().await.context("certificate not found")?;

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
            println!("  VALID — Ed25519 signature verified against the key in {node_did}");
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
    let resp: Value = client
        .get_authed(&path)
        .await?
        .error_for_status()
        .context("failed to list certificates")?
        .json()
        .await
        .context("failed to list certificates")?;

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
}
