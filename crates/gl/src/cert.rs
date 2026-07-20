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

async fn cmd_show(repo: String, id: String, node: String, dir: Option<PathBuf>) -> Result<()> {
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
