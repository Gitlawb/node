//! `gl register` — register this agent identity with a gitlawb node.
//!
//! Sends a signed POST /api/register request and saves the returned bootstrap
//! UCAN token as `ucan.json` beside the identity key, where the other commands
//! look for it.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct RegisterArgs {
    /// Node URL to register with
    #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
    pub node: String,

    /// Capabilities to advertise (comma-separated)
    #[arg(
        long,
        default_value = "git:push,git:fetch,issue:create,pr:open",
        value_delimiter = ','
    )]
    pub capabilities: Vec<String>,

    /// Model/agent type identifier (optional)
    #[arg(long)]
    pub model: Option<String>,

    /// Identity directory (default: the parent of $GITLAWB_KEY, else ~/.gitlawb)
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

pub async fn run(args: RegisterArgs) -> Result<()> {
    let keypair = load_keypair_from_dir(args.dir.as_deref())?;
    let did = keypair.did();

    println!("Registering agent with {}...", args.node);
    println!("  DID:          {did}");
    println!("  Capabilities: {}", args.capabilities.join(", "));

    let client = NodeClient::new(&args.node, Some(keypair.clone()));

    let body = serde_json::to_vec(&json!({
        "did": did.to_string(),
        "capabilities": args.capabilities,
        "model": args.model,
    }))?;

    let resp = client
        .post("/api/register", &body)
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let payload: Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = payload
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("registration failed ({status}): {msg}");
    }

    // Save bootstrap UCAN
    let ucan = payload.get("ucan").and_then(|v| v.as_str()).unwrap_or("");

    let saved_to = if ucan.is_empty() {
        None
    } else {
        let path = ucan_path(args.dir.as_deref())?;
        let record = json!({
            "ucan": ucan,
            "node": args.node,
            "did": did.to_string(),
            "saved_at": chrono::Utc::now().to_rfc3339(),
        });
        std::fs::write(&path, serde_json::to_string_pretty(&record)?)?;
        tracing::debug!("saved UCAN to {}", path.display());
        Some(path)
    };

    let trust = payload
        .get("trust_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let expires = payload
        .get("expires")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let message = payload
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    println!();
    println!("  {message}");
    println!("  Trust score:  {trust:.2}");
    println!("  UCAN expires: {expires}");
    println!();
    // The real path, not the default one: `GITLAWB_KEY` moves it, and an operator
    // told to look in `~/.gitlawb` would find nothing there.
    // Registration without a stored token means the registration-gated
    // capabilities never arrived, so the closing line must not claim they did.
    match &saved_to {
        Some(path) => {
            println!("  Bootstrap UCAN saved to {}", path.display());
            println!("  You are now a verified agent on the gitlawb network.");
        }
        None => {
            println!("  The node returned no bootstrap UCAN, so this identity is not");
            println!("  a verified agent yet. Re-run `gl register` once the node issues one.");
        }
    }

    Ok(())
}

/// Where the bootstrap UCAN is stored: beside the identity key, always.
///
/// Routed through `gitlawb_dir` rather than resolving `~/.gitlawb` locally. The
/// key is READ from the parent of `GITLAWB_KEY`, so writing the token anywhere
/// else splits the two: registration succeeds, and `gl doctor`, `gl ucan show`,
/// `gl init`, and `gl mcp ucan_show` all read `ucan.json` from the key's
/// directory and report an unregistered identity.
fn ucan_path(dir: Option<&std::path::Path>) -> Result<PathBuf> {
    let base = crate::identity::gitlawb_dir(dir.map(std::path::Path::to_path_buf))?;
    std::fs::create_dir_all(&base)
        .with_context(|| format!("failed to create {}", base.display()))?;
    Ok(base.join("ucan.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_identity(dir: &TempDir) {
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn test_register_success_saves_ucan() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/register")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Welcome","ucan":"eyJhbGci.test.token","trust_score":0.5,"expires":"2026-12-31"}"#)
            .create_async()
            .await;

        run(RegisterArgs {
            node: server.url(),
            capabilities: vec!["git:push".to_string(), "git:fetch".to_string()],
            model: None,
            dir: Some(dir.path().to_path_buf()),
        })
        .await
        .unwrap();

        // ucan.json should have been written
        let ucan_file = dir.path().join("ucan.json");
        assert!(ucan_file.exists());
        let content: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(ucan_file).unwrap()).unwrap();
        assert_eq!(content["ucan"].as_str().unwrap(), "eyJhbGci.test.token");
        assert_eq!(content["node"].as_str().unwrap(), server.url());
    }

    /// `gl register` READS the identity from the parent of `GITLAWB_KEY`, so it has
    /// to WRITE the bootstrap token there too. Sending it to `~/.gitlawb` instead is
    /// silent split-brain: registration prints success, and every command that later
    /// reads `ucan.json` — `gl doctor`, `gl ucan show`, `gl init`, `gl mcp` — looks
    /// beside the key, finds nothing, and reports an unregistered identity.
    #[tokio::test]
    async fn register_saves_the_bootstrap_ucan_beside_the_key() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);
        // No --dir: the destination has to come from GITLAWB_KEY alone.
        let _env = crate::identity::test_env::set_key(Some(dir.path().join("identity.pem")));

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/register")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"message":"Welcome","ucan":"eyJhbGci.test.token","trust_score":0.5,"expires":"2026-12-31"}"#,
            )
            .create_async()
            .await;

        run(RegisterArgs {
            node: server.url(),
            capabilities: vec!["git:push".to_string()],
            model: None,
            dir: None,
        })
        .await
        .unwrap();

        let beside_the_key = dir.path().join("ucan.json");
        assert!(
            beside_the_key.exists(),
            "the bootstrap UCAN must land beside GITLAWB_KEY, not in ~/.gitlawb"
        );
        let content: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(beside_the_key).unwrap()).unwrap();
        assert_eq!(content["ucan"].as_str().unwrap(), "eyJhbGci.test.token");
    }

    #[tokio::test]
    async fn test_register_server_error() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/register")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"invalid signature"}"#)
            .create_async()
            .await;

        let result = run(RegisterArgs {
            node: server.url(),
            capabilities: vec!["git:push".to_string()],
            model: None,
            dir: Some(dir.path().to_path_buf()),
        })
        .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid signature"));
    }

    #[tokio::test]
    async fn test_register_no_identity_fails() {
        let dir = TempDir::new().unwrap(); // no identity written

        let result = run(RegisterArgs {
            node: "http://unused".to_string(),
            capabilities: vec![],
            model: None,
            dir: Some(dir.path().to_path_buf()),
        })
        .await;

        assert!(result.is_err());
    }
}
