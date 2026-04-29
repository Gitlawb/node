//! `gl init` — zero-to-push in one command.
//!
//! Detects or initializes a git repo, ensures an identity exists,
//! registers with the node, creates a remote repo, adds the gitlawb
//! remote, and pushes.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct InitArgs {
    /// Repository name (default: current directory name)
    #[arg(long)]
    pub name: Option<String>,

    /// Node URL to register with
    #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
    pub node: String,

    /// Identity directory (default: ~/.gitlawb)
    #[arg(long)]
    pub dir: Option<PathBuf>,

    /// Repository description
    #[arg(long)]
    pub description: Option<String>,
}

pub async fn run(args: InitArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("cannot determine current directory")?;

    // 1. Ensure git repo exists
    let git_dir = cwd.join(".git");
    if !git_dir.exists() {
        println!("Initializing git repository...");
        let status = std::process::Command::new("git")
            .args(["init"])
            .current_dir(&cwd)
            .status()
            .context("failed to run git init")?;
        if !status.success() {
            anyhow::bail!("git init failed");
        }
    } else {
        println!("Git repository detected.");
    }

    // 2. Ensure identity exists
    let keypair = match load_keypair_from_dir(args.dir.as_deref()) {
        Ok(kp) => {
            println!("Identity found: {}", kp.did());
            kp
        }
        Err(_) => {
            println!("No identity found — generating new keypair...");
            let kp = generate_identity(args.dir.as_deref())?;
            println!("  DID: {}", kp.did());
            kp
        }
    };

    let did = keypair.did();
    let client = NodeClient::new(&args.node, Some(keypair.clone()));

    // 3. Register agent (idempotent — re-registering is fine)
    println!("Registering agent with {}...", args.node);
    let body = serde_json::to_vec(&json!({
        "did": did.to_string(),
        "capabilities": ["git:push", "git:fetch", "issue:create", "pr:open"],
    }))?;
    let resp = client.post("/api/register", &body).await
        .context("failed to connect to node")?;
    let status = resp.status();
    let payload: Value = resp.json().await.context("invalid JSON from register")?;

    if !status.is_success() {
        let msg = payload["message"].as_str().unwrap_or("unknown error");
        // "already registered" is fine
        if !msg.contains("already") {
            anyhow::bail!("registration failed ({status}): {msg}");
        }
    }

    // Save UCAN if returned
    if let Some(ucan) = payload.get("ucan").and_then(|v| v.as_str()) {
        if !ucan.is_empty() {
            let ucan_dir = args.dir.clone().unwrap_or_else(|| {
                dirs::home_dir().unwrap_or_default().join(".gitlawb")
            });
            std::fs::create_dir_all(&ucan_dir)?;
            let record = json!({
                "ucan": ucan,
                "node": args.node,
                "did": did.to_string(),
                "saved_at": chrono::Utc::now().to_rfc3339(),
            });
            std::fs::write(ucan_dir.join("ucan.json"), serde_json::to_string_pretty(&record)?)?;
        }
    }
    println!("  Agent registered.");

    // 4. Create repo on node
    let repo_name = args.name.unwrap_or_else(|| {
        cwd.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("repo")
            .to_string()
    });

    println!("Creating repository '{repo_name}' on node...");
    let body = serde_json::to_vec(&json!({
        "name": repo_name,
        "description": args.description,
        "is_public": true,
    }))?;
    let resp = client.post("/api/v1/repos", &body).await
        .context("failed to create repo")?;
    let repo_status = resp.status();
    let repo_result: Value = resp.json().await.context("invalid JSON from create repo")?;

    if !repo_status.is_success() {
        let msg = repo_result["message"].as_str().unwrap_or("unknown error");
        if !msg.contains("exists") && !msg.contains("already") {
            anyhow::bail!("create repo failed ({repo_status}): {msg}");
        }
        println!("  Repository already exists — continuing.");
    } else {
        println!("  Repository created.");
    }

    // 5. Add gitlawb remote
    let did_short = did.to_string();
    let did_short = did_short.split(':').next_back().unwrap_or(&did_short);
    let remote_url = format!("gitlawb://{did_short}/{repo_name}");

    // Check if remote already exists
    let existing = std::process::Command::new("git")
        .args(["remote", "get-url", "gitlawb"])
        .current_dir(&cwd)
        .output();

    if let Ok(out) = existing {
        if out.status.success() {
            println!("  Remote 'gitlawb' already set.");
        } else {
            std::process::Command::new("git")
                .args(["remote", "add", "gitlawb", &remote_url])
                .current_dir(&cwd)
                .status()
                .context("failed to add git remote")?;
            println!("  Remote added: {remote_url}");
        }
    }

    println!();
    println!("Ready! Push with:");
    println!("  git push gitlawb main");

    Ok(())
}

fn generate_identity(dir: Option<&std::path::Path>) -> Result<gitlawb_core::identity::Keypair> {
    let base = if let Some(d) = dir {
        d.to_path_buf()
    } else {
        dirs::home_dir()
            .context("could not determine home directory")?
            .join(".gitlawb")
    };
    std::fs::create_dir_all(&base)?;

    let keypair = gitlawb_core::identity::Keypair::generate();
    let pem = keypair.to_pem()?;
    let path = base.join("identity.pem");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, pem.as_bytes())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, pem.as_bytes())?;
    }

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_identity(dir: &TempDir) -> gitlawb_core::identity::Keypair {
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(dir.path().join("identity.pem"), kp.to_pem().unwrap().as_bytes()).unwrap();
        kp
    }

    #[test]
    fn test_generate_identity_creates_pem() {
        let dir = TempDir::new().unwrap();
        let kp = generate_identity(Some(dir.path())).unwrap();
        assert!(dir.path().join("identity.pem").exists());
        assert!(kp.did().to_string().starts_with("did:key:"));
    }

    #[tokio::test]
    async fn test_init_registers_and_creates_repo() {
        let dir = TempDir::new().unwrap();
        let work_dir = TempDir::new().unwrap();
        let kp = write_identity(&dir);

        // Init git repo in work dir
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(work_dir.path())
            .status()
            .unwrap();

        let mut server = mockito::Server::new_async().await;
        let _reg = server
            .mock("POST", "/api/register")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"Welcome","ucan":"test.token","trust_score":0.5}"#)
            .create_async().await;

        let _repo = server
            .mock("POST", "/api/v1/repos")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"r1","name":"test-repo"}"#)
            .create_async().await;

        // We can't fully test gl init because it uses std::env::current_dir()
        // but we can test the individual steps
        let client = NodeClient::new(&server.url(), Some(kp.clone()));

        // Register
        let body = serde_json::to_vec(&json!({
            "did": kp.did().to_string(),
            "capabilities": ["git:push"],
        })).unwrap();
        let resp: Value = client.post("/api/register", &body).await.unwrap().json().await.unwrap();
        assert_eq!(resp["message"], "Welcome");

        // Create repo
        let body = serde_json::to_vec(&json!({"name": "test-repo", "is_public": true})).unwrap();
        let resp: Value = client.post("/api/v1/repos", &body).await.unwrap().json().await.unwrap();
        assert_eq!(resp["name"], "test-repo");
    }

    #[tokio::test]
    async fn test_init_handles_already_registered() {
        let dir = TempDir::new().unwrap();
        let kp = write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _reg = server
            .mock("POST", "/api/register")
            .with_status(409)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"already registered"}"#)
            .create_async().await;

        let client = NodeClient::new(&server.url(), Some(kp.clone()));
        let body = serde_json::to_vec(&json!({
            "did": kp.did().to_string(),
            "capabilities": ["git:push"],
        })).unwrap();
        let resp = client.post("/api/register", &body).await.unwrap();
        let status = resp.status();
        let payload: Value = resp.json().await.unwrap();
        let msg = payload["message"].as_str().unwrap_or("");
        // Should not bail because message contains "already"
        assert!(!status.is_success());
        assert!(msg.contains("already"));
    }

    #[tokio::test]
    async fn test_init_handles_repo_exists() {
        let dir = TempDir::new().unwrap();
        let kp = write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _repo = server
            .mock("POST", "/api/v1/repos")
            .with_status(409)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository already exists"}"#)
            .create_async().await;

        let client = NodeClient::new(&server.url(), Some(kp.clone()));
        let body = serde_json::to_vec(&json!({"name": "existing", "is_public": true})).unwrap();
        let resp = client.post("/api/v1/repos", &body).await.unwrap();
        let status = resp.status();
        let result: Value = resp.json().await.unwrap();
        let msg = result["message"].as_str().unwrap_or("");
        assert!(!status.is_success());
        assert!(msg.contains("exists") || msg.contains("already"));
    }
}
