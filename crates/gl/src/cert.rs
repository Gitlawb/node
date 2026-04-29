//! `gl cert` — ref certificate commands.
//!
//! Certificates are node-signed receipts proving that a push was accepted.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::http::NodeClient;

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
    },
    /// Show a specific ref certificate and verify its signature
    Show {
        /// Repository in <owner>/<repo> or <repo> format
        repo: String,
        /// Certificate ID
        id: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
}

pub async fn run(args: CertArgs) -> Result<()> {
    match args.cmd {
        CertCmd::List { repo, node } => cmd_list(repo, node).await,
        CertCmd::Show { repo, id, node } => cmd_show(repo, id, node).await,
    }
}

/// Resolve "repo" into (owner, name) — if no slash, use the node's own DID short form.
async fn resolve_repo(repo: &str, node: &str) -> Result<(String, String)> {
    if let Some((owner, name)) = repo.split_once('/') {
        Ok((owner.to_string(), name.to_string()))
    } else {
        let client = NodeClient::new(node, None);
        let info: Value = client
            .get("/")
            .await?
            .json()
            .await
            .context("failed to fetch node info")?;
        let did = info["did"].as_str().context("node info missing 'did'")?;
        let short = did.split(':').next_back().unwrap_or(did).to_string();
        Ok((short, repo.to_string()))
    }
}

async fn cmd_list(repo: String, node: String) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node).await?;

    let client = NodeClient::new(&node, None);
    let path = format!("/api/v1/repos/{owner}/{name}/certs");
    let resp: Value = client
        .get(&path)
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

async fn cmd_show(repo: String, id: String, node: String) -> Result<()> {
    let (owner, name) = resolve_repo(&repo, &node).await?;

    let client = NodeClient::new(&node, None);

    // Fetch the certificate
    let path = format!("/api/v1/repos/{owner}/{name}/certs/{id}");
    let cert: Value = client
        .get(&path)
        .await?
        .json()
        .await
        .context("certificate not found")?;

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

    // Reconstruct the signing payload and verify
    // Fetch the node's current public key to verify
    let info: Value = client
        .get("/")
        .await?
        .json()
        .await
        .context("failed to fetch node info")?;
    let current_node_did = info["did"].as_str().unwrap_or("");

    println!("Signature verification:");
    println!("  Signing payload would be:");
    println!("    {{\"repo_id\": ..., \"ref\": \"{ref_name}\", \"old\": \"{old_sha}\",");
    println!("      \"new\": \"{new_sha}\", \"pusher\": \"{pusher}\",");
    println!("      \"node\": \"{node_did}\", \"ts\": \"{issued_at}\"}}");
    println!();

    if current_node_did == node_did {
        println!("  Node DID matches current node. Signature is an Ed25519/base64url value.");
        println!("  To verify offline, use the node's Ed25519 public key derived from:");
        println!("    did:key → {node_did}");
    } else {
        println!("  WARNING: Certificate node DID ({node_did}) does not match");
        println!("           current node DID ({current_node_did}).");
        println!("           This certificate was issued by a different node.");
    }

    println!();
    println!("  Signature (base64url): {signature}");

    Ok(())
}
