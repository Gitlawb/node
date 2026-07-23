//! `gl quickstart` — interactive wizard to get started with gitlawb.
//!
//! Steps:
//!   1. Create identity (if not present)
//!   2. Register with the public node
//!   3. Create a first repository
//!   4. Print next steps

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::io::{self, Write};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

const PUBLIC_NODE: &str = "https://node.gitlawb.com";

#[derive(Args)]
pub struct QuickstartArgs {
    /// Node URL to register with
    #[arg(long, default_value = PUBLIC_NODE, env = "GITLAWB_NODE")]
    pub node: String,

    /// Identity directory (default: ~/.gitlawb)
    #[arg(long)]
    pub dir: Option<PathBuf>,

    /// Skip prompts, use defaults for everything
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(args: QuickstartArgs) -> Result<()> {
    println!();
    println!("Welcome to gitlawb.");
    println!("This wizard will set up your identity, register you with a node,");
    println!("and create your first repository.");
    println!();

    let dir = args.dir.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gitlawb")
    });

    // ── Step 1: Identity ──────────────────────────────────────────────────
    println!("── Step 1: Identity ─────────────────────────────────────────────────");
    println!();

    let pem_path = dir.join("identity.pem");
    let keypair = if pem_path.exists() {
        match load_keypair_from_dir(Some(&dir)) {
            Ok(kp) => {
                let did = kp.did();
                println!("  ✓  Identity already exists");
                println!("     DID: {did}");
                println!();
                kp
            }
            Err(_) => {
                println!("  Identity file exists but is unreadable. Regenerating...");
                generate_identity(&dir)?
            }
        }
    } else {
        println!("  No identity found. Generating a new Ed25519 keypair...");
        generate_identity(&dir)?
    };

    let did = keypair.did().to_string();

    // ── Step 2: Register with node ────────────────────────────────────────
    println!("── Step 2: Register with node ───────────────────────────────────────");
    println!();

    // Check if already registered with this node
    let ucan_path = dir.join("ucan.json");
    let already_registered = std::fs::read_to_string(&ucan_path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v["node"].as_str().map(|n| n == args.node))
        .unwrap_or(false);

    if already_registered {
        println!("  ✓  Already registered with {}", args.node);
        println!();
    } else {
        println!("  Registering with {}...", args.node);

        let client = NodeClient::new(&args.node, Some(keypair.clone()));
        let body = serde_json::to_vec(&json!({
            "did": did,
            "capabilities": ["git:push", "git:fetch", "issue:create", "pr:open"],
        }))?;

        match client.post("/api/register", &body).await {
            Ok(resp) if resp.status().is_success() => {
                let payload: Value = resp.json().await.unwrap_or_default();
                let ucan = payload["ucan"].as_str().unwrap_or("");
                if !ucan.is_empty() {
                    std::fs::create_dir_all(&dir)?;
                    let record = json!({
                        "ucan": ucan,
                        "node": args.node,
                        "did": did,
                        "saved_at": chrono::Utc::now().to_rfc3339(),
                    });
                    std::fs::write(&ucan_path, serde_json::to_string_pretty(&record)?)?;
                }
                let trust = payload["trust_score"].as_f64().unwrap_or(0.0);
                println!("  ✓  Registered successfully");
                println!("     Trust score: {trust:.2}");
                println!("     UCAN saved to {}", ucan_path.display());
                println!();
            }
            Ok(resp) => {
                let status = resp.status();
                let body: Value = resp.json().await.unwrap_or_default();
                let msg = body["message"].as_str().unwrap_or("unknown");
                println!("  ✗  Registration failed ({status}): {msg}");
                println!("     You can retry with: gl register --node {}", args.node);
                println!();
                // Non-fatal — continue to repo creation
            }
            Err(e) => {
                println!("  ✗  Could not reach {}: {e}", args.node);
                println!(
                    "     You can retry later with: gl register --node {}",
                    args.node
                );
                println!();
                // Non-fatal — continue
            }
        }
    }

    // ── Step 3: Create first repository ───────────────────────────────────
    println!("── Step 3: Create your first repository ─────────────────────────────");
    println!();

    let repo_name = if args.yes {
        "my-first-repo".to_string()
    } else {
        prompt("  Repository name", "my-first-repo")?
    };

    let description = if args.yes {
        String::new()
    } else {
        prompt("  Description (optional)", "")?
    };

    println!();
    println!("  Creating repository '{repo_name}' on {}...", args.node);

    let client = NodeClient::new(&args.node, Some(keypair));
    let body = serde_json::to_vec(&json!({
        "name": repo_name,
        "description": if description.is_empty() { None } else { Some(&description) },
        "is_public": true,
        "default_branch": "main",
    }))?;

    match client.post("/api/v1/repos", &body).await {
        Ok(resp) if resp.status().is_success() => {
            // Fetch node DID to build gitlawb:// URL
            let info_client = NodeClient::new(&args.node, None);
            let node_info: Value = match info_client.get("/").await {
                Ok(r) => r.json().await.unwrap_or_default(),
                Err(_) => Value::Null,
            };
            let node_did_str = node_info["did"].as_str().unwrap_or(&did).to_string();
            let node_did = node_did_str.as_str();

            let gitlawb_url = format!("gitlawb://{node_did}/{repo_name}");

            println!("  ✓  Repository created");
            println!();
            println!("══════════════════════════════════════════════════════════════════════");
            println!("  You're set up on gitlawb.");
            println!();
            println!("  Your DID:   {did}");
            println!("  Node:       {}", args.node);
            println!("  Repo:       {repo_name}");
            println!();
            println!("  Clone your repo:");
            println!("    git clone {gitlawb_url}");
            println!();
            println!("  Or start from an existing directory:");
            println!("    git remote add origin {gitlawb_url}");
            println!("    git push -u origin main");
            println!();
            println!("  Explore:");
            println!("    gl repo list                 list all your repos");
            println!("    gl node status               live node dashboard");
            println!("    gl mcp serve                 start the MCP server for AI agents");
            println!("    gl name available <name>     claim a name on Base L2");
            println!();
            println!("  Docs:  https://docs.gitlawb.com");
            println!("══════════════════════════════════════════════════════════════════════");
        }
        Ok(resp) => {
            let status = resp.status();
            let payload: Value = resp.json().await.unwrap_or_default();
            let msg = payload["message"].as_str().unwrap_or("unknown");
            println!("  ✗  Repo creation failed ({status}): {msg}");
            println!(
                "     Try manually: gl repo create {repo_name} --node {}",
                args.node
            );
        }
        Err(e) => {
            println!("  ✗  Could not reach node: {e}");
            println!(
                "     Try manually: gl repo create {repo_name} --node {}",
                args.node
            );
        }
    }

    println!();
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn generate_identity(dir: &PathBuf) -> Result<gitlawb_core::identity::Keypair> {
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let keypair = gitlawb_core::identity::Keypair::generate();
    let pem = keypair.to_pem()?;
    let path = dir.join("identity.pem");

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

    let did = keypair.did();
    println!("  ✓  Generated new identity");
    println!("     DID: {did}");
    println!("     Key: {}", path.display());
    println!();

    Ok(keypair)
}

fn prompt(label: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label} [{default}]: ");
    }
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();

    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}
