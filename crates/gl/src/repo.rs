//! `gl repo` — repository management commands.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct RepoArgs {
    #[command(subcommand)]
    pub cmd: RepoCmd,
}

#[derive(Subcommand)]
pub enum RepoCmd {
    /// Create a new repository
    Create {
        name: String,
        #[arg(long, short)]
        description: Option<String>,
        #[arg(long)]
        private: bool,
        #[arg(long, default_value = "main")]
        branch: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List repositories on a node
    List {
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Print the gitlawb:// clone command for a repo
    Clone {
        name: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show repository metadata
    Info {
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List commits on a branch
    Commits {
        /// Repository name
        repo: String,
        /// Branch name (default: main)
        #[arg(long, default_value = "main")]
        branch: String,
        /// Max number of commits to show
        #[arg(long, short, default_value = "20")]
        limit: u32,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Fork a repository into your own namespace
    Fork {
        /// Repository in <owner>/<repo> format
        repo: String,
        /// New name for the fork (defaults to source repo name)
        #[arg(long, short)]
        name: Option<String>,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Add a label to a repository
    LabelAdd {
        repo: String,
        label: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Remove a label from a repository
    LabelRemove {
        repo: String,
        label: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List labels on a repository
    LabelList {
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Check who owns a repo and whether you can push to protected branches
    Owner {
        /// Repository name or owner/repo
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Output structured JSON for scripting
        #[arg(long)]
        json: bool,
    },
    /// Register this node as a replica of someone else's repo
    ReplicaRegister {
        /// Repository in owner/repo format
        repo: String,
        /// Publicly-reachable URL of YOUR node (the one hosting the replica)
        #[arg(long)]
        url: String,
        /// URL of the origin node (where the repo lives)
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Unregister this node as a replica
    ReplicaUnregister {
        /// Repository in owner/repo format
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// List nodes currently mirroring a repo
    Replicas {
        /// Repository in owner/repo format
        repo: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: RepoArgs) -> Result<()> {
    match args.cmd {
        RepoCmd::Create {
            name,
            description,
            private,
            branch,
            node,
            dir,
        } => cmd_create(name, description, !private, branch, node, dir).await,
        RepoCmd::List { node, dir } => cmd_list(node, dir).await,
        RepoCmd::Clone { name, node, dir } => cmd_clone(name, node, dir).await,
        RepoCmd::Info { repo, node, dir } => cmd_info(repo, node, dir).await,
        RepoCmd::Commits {
            repo,
            branch,
            limit,
            node,
            dir,
        } => cmd_commits(repo, branch, limit, node, dir).await,
        RepoCmd::Fork {
            repo,
            name,
            node,
            dir,
        } => cmd_fork(repo, name, node, dir).await,
        RepoCmd::LabelAdd {
            repo,
            label,
            node,
            dir,
        } => cmd_label_add(repo, label, node, dir).await,
        RepoCmd::LabelRemove {
            repo,
            label,
            node,
            dir,
        } => cmd_label_remove(repo, label, node, dir).await,
        RepoCmd::LabelList { repo, node, dir } => cmd_label_list(repo, node, dir).await,
        RepoCmd::Owner {
            repo,
            node,
            dir,
            json,
        } => cmd_owner(repo, node, dir, json).await,
        RepoCmd::ReplicaRegister {
            repo,
            url,
            node,
            dir,
        } => cmd_replica_register(repo, url, node, dir).await,
        RepoCmd::ReplicaUnregister { repo, node, dir } => {
            cmd_replica_unregister(repo, node, dir).await
        }
        RepoCmd::Replicas { repo, node, dir } => cmd_replicas(repo, node, dir).await,
    }
}

/// Derive the short DID key segment from a keypair, or fall back to the node's DID.
/// Resolve the owner short-DID for a bare repo name from the LOCAL identity.
/// Never falls back to the node's own DID (that produced bogus "owned by the
/// node" results for repos that don't exist) — if there's no local identity the
/// caller must pass an explicit `owner/name`.
async fn resolve_owner_did(_node: &str, dir: Option<&std::path::Path>) -> Result<String> {
    let kp = load_keypair_from_dir(dir).context(
        "no local identity to resolve the repo owner — pass `owner/name`, or run `gl identity new`",
    )?;
    let did = kp.did().to_string();
    Ok(did.split(':').next_back().unwrap_or(&did).to_string())
}

async fn cmd_create(
    name: String,
    description: Option<String>,
    is_public: bool,
    default_branch: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    // Derive owner DID before keypair is moved into the client
    let owner_did = keypair.did().to_string();
    let owner_short = owner_did
        .split(':')
        .next_back()
        .unwrap_or(&owner_did)
        .to_string();
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&json!({
        "name": name,
        "description": description,
        "is_public": is_public,
        "default_branch": default_branch,
    }))?;

    let resp = client
        .post("/api/v1/repos", &body)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let payload: Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = payload["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("create failed ({status}): {msg}");
    }

    let clone_url = payload["clone_url"].as_str().unwrap_or("");
    let gitlawb_url = format!("gitlawb://{owner_did}/{name}");

    println!("✓ Created repository: {name}");
    println!("  Clone: git clone {gitlawb_url}");
    println!("  HTTP:  {clone_url}");
    println!("  View:  https://gitlawb.com/{owner_short}/{name}");
    if let Some(desc) = payload["description"].as_str().filter(|s| !s.is_empty()) {
        println!("  Desc:  {desc}");
    }
    Ok(())
}

async fn cmd_list(node: String, dir: Option<PathBuf>) -> Result<()> {
    let owner = resolve_owner_did(&node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, None);

    let url = format!("/api/v1/repos?owner={owner}");
    let repos: Value = client
        .get(&url)
        .await?
        .json()
        .await
        .context("failed to list repos")?;
    let repos = repos.as_array().context("expected array")?;

    if repos.is_empty() {
        println!("No repositories found for {owner}");
        return Ok(());
    }

    println!("Repositories ({owner}...)");
    println!();
    for r in repos {
        let name = r["name"].as_str().unwrap_or("?");
        let desc = r["description"].as_str().unwrap_or("");
        let public = r["is_public"].as_bool().unwrap_or(true);
        let updated = r["updated_at"].as_str().map(|s| &s[..10]).unwrap_or("?");
        let vis = if public { "public" } else { "private" };
        println!("  {name:<24}  {vis:<8}  {updated}  {desc}");
    }
    Ok(())
}

async fn cmd_clone(name: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    // Owner is taken from an explicit `owner/name`, else the LOCAL identity —
    // never the node's own DID. A missing repo then surfaces as the helper's
    // clear 404 rather than a clone under an invented owner.
    let (did, repo_name) = if let Some((owner, rest)) = name.split_once('/') {
        (owner.to_string(), rest.to_string())
    } else {
        // Bare name: derive the SHORT owner key via the same helper the other
        // commands use, so the URL is `gitlawb://z6Mk.../name` — not the full
        // `did:key:z6Mk...` form, whose colons in the authority break the helper.
        (resolve_owner_did(&node, dir.as_deref()).await?, name)
    };
    let url = format!("gitlawb://{did}/{repo_name}");
    println!("  cloning {url}");
    let status = std::process::Command::new("git")
        .arg("clone")
        .arg(&url)
        // Point the remote helper at the same node the user selected.
        .env("GITLAWB_NODE", &node)
        .status()
        .context("failed to run git clone — is git installed?")?;
    if !status.success() {
        anyhow::bail!("git clone failed — does the repo exist on this node?");
    }
    Ok(())
}

async fn cmd_info(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    // Sign when an identity is available so the read-visibility-gated replica
    // sub-fetch below resolves for a private repo's owner (public repos still
    // work anonymously).
    let client = NodeClient::new(&node, load_keypair_from_dir(dir.as_deref()).ok());

    let (owner, name) = if repo.contains('/') {
        let (o, n) = repo.split_once('/').unwrap();
        (o.to_string(), n.to_string())
    } else {
        let short = resolve_owner_did(&node, dir.as_deref()).await?;
        (short, repo)
    };

    let resp = client
        .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}"))
        .await
        .context("failed to connect to node")?;
    // A non-existent (or unreadable/quarantined) repo is a real 404 from the
    // node — surface it plainly instead of printing a stub card with `?` fields
    // and a placeholder owner DID.
    if !resp.status().is_success() {
        if resp.status().as_u16() == 404 {
            anyhow::bail!("repository '{owner}/{name}' not found");
        }
        let status = resp.status();
        let msg = resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v["message"].as_str().map(String::from))
            .unwrap_or_else(|| "request failed".to_string());
        anyhow::bail!("repo info failed ({status}): {msg}");
    }
    let r: Value = resp.json().await.context("parse repo info")?;

    let owner_did = r["owner_did"].as_str().unwrap_or(&owner);
    let gitlawb_url = format!("gitlawb://{owner_did}/{name}");
    let http_url = r["clone_url"].as_str().unwrap_or("?");

    println!("Repository: {owner}/{name}");
    println!("  ID:         {}", r["id"].as_str().unwrap_or("?"));
    println!("  Owner DID:  {owner_did}");
    println!("  Public:     {}", r["is_public"].as_bool().unwrap_or(true));
    println!(
        "  Branch:     {}",
        r["default_branch"].as_str().unwrap_or("main")
    );
    println!("  Clone:      git clone {gitlawb_url}");
    println!("  HTTP URL:   {http_url}");
    println!("  Updated:    {}", r["updated_at"].as_str().unwrap_or("?"));
    if let Some(desc) = r["description"].as_str().filter(|s| !s.is_empty()) {
        println!("  Desc:       {desc}");
    }

    // Replica count — failure to fetch is non-fatal (older nodes don't expose this).
    if let Ok(resp) = client
        .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}/replicas"))
        .await
    {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(count) = json["replica_count"].as_i64() {
                    println!("  Replicas:   {count}");
                }
            }
        }
    }

    Ok(())
}

async fn cmd_replica_register(
    repo: String,
    url: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let (owner, name) = repo
        .split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .context("use owner/repo format (e.g. did:key:.../myrepo)")?;

    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let client = NodeClient::new(&node, Some(kp));

    let body = serde_json::to_vec(&json!({ "url": url }))?;
    let resp = client
        .put(&format!("/api/v1/repos/{owner}/{name}/replicas"), &body)
        .await
        .context("failed to connect to origin node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("replica register failed ({status}): {msg}");
    }

    let count = body["replica_count"].as_i64().unwrap_or(0);
    println!("Registered as replica of {owner}/{name}");
    println!("  Your URL:   {url}");
    println!("  Replicas:   {count} total");
    println!();
    println!("Next: ensure your node has a copy of the repo —");
    println!("  git clone gitlawb://{owner}/{name}");
    Ok(())
}

async fn cmd_replica_unregister(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = repo
        .split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .context("use owner/repo format")?;

    let kp = load_keypair_from_dir(dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let client = NodeClient::new(&node, Some(kp));

    let resp = client
        .delete(&format!("/api/v1/repos/{owner}/{name}/replicas"), b"")
        .await
        .context("failed to connect to origin node")?;

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("replica unregister failed ({status}): {msg}");
    }

    let count = body["replica_count"].as_i64().unwrap_or(0);
    println!("Unregistered as replica of {owner}/{name}  ({count} replicas remaining)");
    Ok(())
}

async fn cmd_replicas(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = repo
        .split_once('/')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .context("use owner/repo format")?;

    // Read-visibility-gated: public repos list anonymously, private repos need
    // the owner's signature. Sign when an identity is available.
    let client = NodeClient::new(&node, load_keypair_from_dir(dir.as_deref()).ok());
    let resp = client
        .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}/replicas"))
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("replicas list failed ({status}): {msg}");
    }

    let count = body["replica_count"].as_i64().unwrap_or(0);
    println!("{owner}/{name}: {count} replicas");
    if let Some(arr) = body["replicas"].as_array() {
        for r in arr {
            let did = r["replica_did"].as_str().unwrap_or("?");
            let url = r["replica_url"].as_str().unwrap_or("?");
            let registered = r["registered_at"]
                .as_str()
                .map(|s| &s[..10.min(s.len())])
                .unwrap_or("?");
            println!("  {registered}  {did}  →  {url}");
        }
    }
    Ok(())
}

pub(crate) async fn cmd_commits(
    repo: String,
    branch: String,
    limit: u32,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let client = NodeClient::new(&node, None);

    let (owner, name) = if repo.contains('/') {
        let (o, n) = repo.split_once('/').unwrap();
        (o.to_string(), n.to_string())
    } else {
        let short = resolve_owner_did(&node, dir.as_deref()).await?;
        (short, repo)
    };

    let url = format!("/api/v1/repos/{owner}/{name}/commits?branch={branch}&limit={limit}");
    let resp: Value = client
        .get(&url)
        .await?
        .json()
        .await
        .context("failed to fetch commits")?;

    let commits = resp["commits"].as_array().cloned().unwrap_or_default();
    if commits.is_empty() {
        println!("No commits on {branch} in {owner}/{name}");
        return Ok(());
    }

    println!("Commits on {branch} ({owner}/{name})");
    println!();
    for c in &commits {
        let sha = c["hash"]
            .as_str()
            .or_else(|| c["sha"].as_str())
            .or_else(|| c["oid"].as_str())
            .unwrap_or("?");
        let short_sha = &sha[..sha.len().min(10)];
        let msg = c["message"].as_str().unwrap_or("(no message)");
        let first_line = msg.lines().next().unwrap_or(msg);
        let author = c["author_name"]
            .as_str()
            .or_else(|| c["author"].as_str())
            .unwrap_or("?");
        let date = c["date"]
            .as_str()
            .or_else(|| c["committer_date"].as_str())
            .map(|s| &s[..10.min(s.len())])
            .unwrap_or("?");
        println!("  {short_sha}  {date}  {first_line}  ({author})");
    }
    Ok(())
}

async fn cmd_fork(
    repo: String,
    name: Option<String>,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let client = NodeClient::new(&node, Some(keypair));

    let (owner, repo_name) = if let Some((o, r)) = repo.split_once('/') {
        (o.to_string(), r.to_string())
    } else {
        anyhow::bail!("repo must be in <owner>/<repo> format for fork");
    };

    let body = serde_json::to_vec(&serde_json::json!({ "name": name }))?;
    let resp = client
        .post(&format!("/api/v1/repos/{owner}/{repo_name}/fork"), &body)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON response")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("fork failed ({status}): {msg}");
    }

    let fork_name = result["name"].as_str().unwrap_or(&repo_name);
    let owner_did = result["owner_did"].as_str().unwrap_or("?");
    println!("⑂  Forked {owner}/{repo_name} → {fork_name}");
    println!("   Clone: git clone gitlawb://{owner_did}/{fork_name}");
    Ok(())
}

/// Returns (owner, repo_name) — if repo contains '/', splits on it; otherwise uses caller's DID.
pub(crate) async fn resolve_owner_repo_pair(
    repo: &str,
    node: &str,
    dir: Option<&std::path::Path>,
) -> Result<(String, String)> {
    if let Some((o, r)) = repo.split_once('/') {
        Ok((o.to_string(), r.to_string()))
    } else {
        let owner = resolve_owner_did(node, dir).await?;
        Ok((owner, repo.to_string()))
    }
}

async fn cmd_label_add(
    repo: String,
    label: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let (owner, name) = resolve_owner_repo_pair(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(keypair));

    let body = serde_json::to_vec(&serde_json::json!({ "label": label }))?;
    let resp = client
        .post(&format!("/api/v1/repos/{owner}/{name}/labels"), &body)
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("add label failed ({status}): {msg}");
    }

    let added = result["added"].as_bool().unwrap_or(true);
    if added {
        println!("+ Label added: {label} on {owner}/{name}");
    } else {
        println!("  Label already present: {label} on {owner}/{name}");
    }
    Ok(())
}

async fn cmd_label_remove(
    repo: String,
    label: String,
    node: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let (owner, name) = resolve_owner_repo_pair(&repo, &node, dir.as_deref()).await?;
    let client = NodeClient::new(&node, Some(keypair));

    let resp = client
        .delete(&format!("/api/v1/repos/{owner}/{name}/labels/{label}"), &[])
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let result: Value = resp.json().await.context("invalid JSON")?;

    if !status.is_success() {
        let msg = result["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("remove label failed ({status}): {msg}");
    }

    println!("- Label removed: {label} from {owner}/{name}");
    Ok(())
}

async fn cmd_label_list(repo: String, node: String, dir: Option<PathBuf>) -> Result<()> {
    let (owner, name) = resolve_owner_repo_pair(&repo, &node, dir.as_deref()).await?;
    // Read-visibility-gated like the sibling read surfaces (replicas, protected
    // branches): sign when an identity is available so a private-repo owner can
    // read their own labels, while public repos stay anonymously listable.
    let client = NodeClient::new(&node, load_keypair_from_dir(dir.as_deref()).ok());

    let resp = client
        .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}/labels"))
        .await
        .context("failed to connect to node")?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or_default();
    if !status.is_success() {
        let msg = body["message"].as_str().unwrap_or("unknown error");
        anyhow::bail!("list labels failed ({status}): {msg}");
    }

    let labels = body["labels"].as_array().cloned().unwrap_or_default();
    if labels.is_empty() {
        println!("No labels on {owner}/{name}");
    } else {
        println!("Labels on {owner}/{name}:");
        for l in &labels {
            println!("  · {}", l.as_str().unwrap_or("?"));
        }
    }
    Ok(())
}

/// Parse the protected-branch list from the node's `GET /branches/protected`
/// response. The endpoint returns `{"protected_branches": [...], "count": N}`
/// (see `crates/gitlawb-node/src/api/protect.rs`); each entry may be a plain
/// branch-name string or an object carrying a `name` field.
fn parse_protected_branches(val: &Value) -> Vec<String> {
    val["protected_branches"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|b| {
                    b.as_str()
                        .map(String::from)
                        .or_else(|| b["name"].as_str().map(String::from))
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn cmd_owner(repo: String, node: String, dir: Option<PathBuf>, json_out: bool) -> Result<()> {
    let keypair = load_keypair_from_dir(dir.as_deref())?;
    let my_did = keypair.did().to_string();
    let my_short = my_did.split(':').next_back().unwrap_or(&my_did).to_string();

    let (owner, name) = resolve_owner_repo_pair(&repo, &node, dir.as_deref()).await?;
    // Sign with the loaded identity so the read-visibility-gated protected-branch
    // fetch below works on the owner's own private repos.
    let client = NodeClient::new(&node, Some(keypair));

    // Fetch repo info (get_repo is read-visibility-gated; sign so the owner can
    // inspect their own private repo).
    let resp = client
        .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}"))
        .await
        .context("failed to connect to node")?;
    if !resp.status().is_success() {
        anyhow::bail!("repo not found: {owner}/{name}");
    }
    let info: Value = resp.json().await.context("invalid JSON")?;
    let owner_did = info["owner_did"].as_str().unwrap_or(&owner).to_string();
    let owner_short = owner_did
        .split(':')
        .next_back()
        .unwrap_or(&owner_did)
        .to_string();
    let is_owner = my_did == owner_did || my_short == owner_short;

    // Fetch protected branches (read-visibility-gated; signed via the client).
    let protected: Vec<String> = match client
        .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}/branches/protected"))
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let val: Value = resp.json().await.unwrap_or_default();
            parse_protected_branches(&val)
        }
        _ => Vec::new(),
    };

    if json_out {
        let out = json!({
            "repo": format!("{owner_short}/{name}"),
            "owner_did": owner_did,
            "my_did": my_did,
            "is_owner": is_owner,
            "protected_branches": protected,
            "can_push_protected": is_owner,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Repo:       {owner_short}/{name}");
        println!("Owner:      {owner_did}");
        println!("You:        {my_did}");
        println!("Is owner:   {}", if is_owner { "yes" } else { "no" });
        if protected.is_empty() {
            println!("Protected:  (none)");
        } else {
            println!("Protected:  {}", protected.join(", "));
            for branch in &protected {
                let can = if is_owner { "yes" } else { "no (not owner)" };
                println!("Can push:   {branch} → {can}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parse_protected_branches_reads_node_shape() {
        use serde_json::json;
        assert_eq!(
            parse_protected_branches(&json!({"protected_branches":["main","release"],"count":2})),
            vec!["main".to_string(), "release".to_string()]
        );
        assert!(parse_protected_branches(&json!({"count":0})).is_empty());
        assert_eq!(
            parse_protected_branches(&json!({"protected_branches":[{"name":"main"}]})),
            vec!["main".to_string()]
        );
    }

    fn write_identity(dir: &TempDir) {
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn test_resolve_owner_did_uses_keypair() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);
        let owner = resolve_owner_did("http://unused", Some(dir.path()))
            .await
            .unwrap();
        // Should be the key segment of a did:key DID — starts with 'z'
        assert!(owner.starts_with('z'));
        assert!(!owner.contains(':'));
    }

    #[tokio::test]
    async fn test_cmd_create_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/repos")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"name":"myrepo","clone_url":"gitlawb://did:key:z6Mk/myrepo","description":null}"#)
            .create_async()
            .await;

        cmd_create(
            "myrepo".to_string(),
            None,
            true,
            "main".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_create_server_error() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v1/repos")
            .with_status(409)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository already exists"}"#)
            .create_async()
            .await;

        let result = cmd_create(
            "myrepo".to_string(),
            None,
            true,
            "main".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn test_cmd_list_empty() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos\?owner=".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[]"#)
            .create_async()
            .await;

        cmd_list(server.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_with_repos() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"^/api/v1/repos\?owner=".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"name":"testrepo","description":"a test","is_public":true,"updated_at":"2026-03-18T00:00:00Z"}]"#)
            .create_async()
            .await;

        cmd_list(server.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_sends_owner_query_param() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos\?owner=z".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[{"name":"myrepo","is_public":true,"updated_at":"2026-03-20T00:00:00Z"}]"#,
            )
            .create_async()
            .await;

        cmd_list(server.url(), Some(dir.path().to_path_buf()))
            .await
            .unwrap();
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_commits_empty() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/commits".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"commits":[]}"#)
            .create_async()
            .await;

        cmd_commits(
            "myrepo".to_string(),
            "main".to_string(),
            20,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_commits_with_data() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/commits".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"commits":[{"sha":"abc1234567","message":"initial commit","author_name":"alice","date":"2026-03-18T00:00:00Z"}]}"#)
            .create_async()
            .await;

        cmd_commits(
            "myrepo".to_string(),
            "main".to_string(),
            20,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_fork_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/alice/myrepo/fork$".to_string()),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"fork-1","name":"myrepo","owner_did":"did:key:z6MkMe","is_public":true}"#,
            )
            .create_async()
            .await;

        cmd_fork(
            "alice/myrepo".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_fork_conflict_error() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/alice/myrepo/fork$".to_string()),
            )
            .with_status(400)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"you already have a repo named myrepo"}"#)
            .create_async()
            .await;

        let err = cmd_fork(
            "alice/myrepo".to_string(),
            None,
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("already have a repo"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_cmd_fork_requires_owner_slash_repo() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let err = cmd_fork(
            "myrepo".to_string(), // no owner/ prefix
            None,
            "http://unused".to_string(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("owner>/<repo"), "got: {err}");
    }

    #[tokio::test]
    async fn test_cmd_label_add_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "POST",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/labels$".to_string()),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"label":"language:rust","added":true}"#)
            .create_async()
            .await;

        cmd_label_add(
            "myrepo".to_string(),
            "language:rust".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_label_remove_success() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "DELETE",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/labels/language:rust$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"label":"language:rust","removed":true}"#)
            .create_async()
            .await;

        cmd_label_remove(
            "myrepo".to_string(),
            "language:rust".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_label_list_empty() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/labels$".to_string()),
            )
            // Identity is loaded, so get_maybe_signed must sign — requiring the
            // header guards against a regression back to bare get().
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"labels":[]}"#)
            .create_async()
            .await;

        cmd_label_list(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_label_list_with_labels() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/labels$".to_string()),
            )
            // Identity is loaded, so get_maybe_signed must sign — requiring the
            // header guards against a regression back to bare get().
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"labels":["language:rust","topic:defi"]}"#)
            .create_async()
            .await;

        cmd_label_list(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_label_list_anonymous_when_no_identity() {
        // Empty dir → no identity → get_maybe_signed must fall back to an
        // anonymous GET (the public-repo path). Assert NO signature header.
        let dir = TempDir::new().unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/labels$".to_string()))
            .match_header("signature", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"labels":[]}"#)
            .create_async()
            .await;

        cmd_label_list(
            "owner/pubrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_label_list_404_errors() {
        // A non-reader of a private repo gets 404 from the now-gated endpoint.
        // The client must surface that as an error, not print "No labels" and
        // exit 0 (the error body has no `labels` key).
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/labels$".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .create_async()
            .await;

        let err = cmd_label_list(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("list labels failed (404")
                && err.to_string().contains("repo not found"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_cmd_label_list_non_json_error_surfaces_status() {
        // A non-2xx response with a non-JSON body (e.g. a proxy 502) must still
        // surface the HTTP status, not collapse to a bare JSON-parse error.
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo/labels$".to_string()),
            )
            .with_status(502)
            .with_header("content-type", "text/html")
            .with_body("<html>502 Bad Gateway</html>")
            .create_async()
            .await;

        let err = cmd_label_list(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("list labels failed (502"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_cmd_owner_is_owner() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();
        let short = did.split(':').next_back().unwrap().to_string();

        let mut server = mockito::Server::new_async().await;
        // Both fetches are read-visibility-gated; with an identity loaded they
        // must be signed. Requiring the header guards a regression to get().
        let _repo = server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(r"^/api/v1/repos/{short}/myrepo$")),
            )
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"name":"myrepo","owner_did":"{did}","is_public":true}}"#
            ))
            .create_async()
            .await;
        let _prot = server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(
                    r"^/api/v1/repos/{short}/myrepo/branches/protected$"
                )),
            )
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"protected_branches":["main"],"count":1}"#)
            .create_async()
            .await;

        cmd_owner(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
            false,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_owner_not_owner() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _repo = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"name":"myrepo","owner_did":"did:key:z6MkSomeOtherOwner","is_public":true}"#,
            )
            .create_async()
            .await;
        let _prot = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/branches/protected$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"protected_branches":["main","release"],"count":2}"#)
            .create_async()
            .await;

        cmd_owner(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
            false,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_owner_json_output() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _repo = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/myrepo$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"name":"myrepo","owner_did":"did:key:z6MkSomeOtherOwner","is_public":true}"#,
            )
            .create_async()
            .await;
        let _prot = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/api/v1/repos/[^/]+/myrepo/branches/protected$".to_string(),
                ),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"protected_branches":["main"],"count":1}"#)
            .create_async()
            .await;

        cmd_owner(
            "myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
            true,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_owner_repo_not_found() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _repo = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/[^/]+/ghost$".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create_async()
            .await;

        let err = cmd_owner(
            "ghost".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    }

    #[tokio::test]
    async fn test_cmd_replicas_signs_when_identity_present() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        // Read-visibility-gated: with an identity the request must be signed.
        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/replicas$".to_string()))
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"repo":"owner/myrepo","replica_count":0,"replicas":[]}"#)
            .create_async()
            .await;

        cmd_replicas(
            "owner/myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_replicas_anonymous_when_no_identity() {
        // Empty dir → no identity → get_maybe_signed must fall back to an
        // anonymous GET (the public-repo path). Assert NO signature header.
        let dir = TempDir::new().unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/replicas$".to_string()))
            .match_header("signature", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"repo":"owner/pubrepo","replica_count":0,"replicas":[]}"#)
            .create_async()
            .await;

        cmd_replicas(
            "owner/pubrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_info_signs_repo_and_replica_fetches() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        // Both the primary repo fetch and the replica sub-fetch are
        // read-visibility-gated; with an identity loaded both must be signed.
        let _repo = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/owner/myrepo$".to_string()),
            )
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"id":"r1","name":"myrepo","owner_did":"did:key:zOwner","is_public":false,"default_branch":"main"}"#,
            )
            .create_async()
            .await;
        let _replicas = server
            .mock("GET", mockito::Matcher::Regex(r"/replicas$".to_string()))
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"replica_count":0,"replicas":[]}"#)
            .create_async()
            .await;

        cmd_info(
            "owner/myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_info_404_surfaces_error_not_fake_repo() {
        // A non-reader of a private repo gets a JSON 404 from the now-gated
        // GET /api/v1/repos/{owner}/{name}. The command must surface that as an
        // error, not parse the error body and print a fabricated repo summary
        // (owner / "?" / public=true / main) before exiting 0.
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _repo = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/owner/myrepo$".to_string()),
            )
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo not found"}"#)
            .create_async()
            .await;

        let err = cmd_info(
            "owner/myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        // The merged cmd_info maps a 404 to a generic "not found" (it does not
        // echo the server's message body on 404), which still surfaces the error
        // rather than fabricating a repo card, and avoids leaking any
        // server-provided detail on a private-repo denial.
        assert!(
            err.to_string()
                .contains("repository 'owner/myrepo' not found"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_cmd_info_non_json_error_surfaces_status() {
        // A non-2xx response with a non-JSON body (e.g. a proxy 502) must still
        // surface the HTTP status, not collapse to a bare JSON-parse error.
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let mut server = mockito::Server::new_async().await;
        let _repo = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/owner/myrepo$".to_string()),
            )
            .with_status(502)
            .with_header("content-type", "text/html")
            .with_body("<html>502 Bad Gateway</html>")
            .create_async()
            .await;

        let err = cmd_info(
            "owner/myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("repo info failed (502"),
            "got: {err}"
        );
    }
}

// Drives the three deny/negative arms that the merge reconciliation changed but
// that no existing test executed (they were only reasoned): resolve_owner_did
// with no identity, cmd_info on an authenticated-but-denied 403, and
// get_maybe_signed with no keypair. Each asserts the must-not case.
#[cfg(test)]
mod vet_merge_deny_arms {
    use super::*;
    use tempfile::TempDir;

    fn write_identity(dir: &TempDir) {
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
    }

    // No local identity must hard-error, never fall back to the node's own DID.
    // (Load-bearing: #113's pre-merge resolve_owner_did returned Ok via a node
    // fetch here; a reintroduced fallback makes this go red.)
    #[tokio::test]
    async fn resolve_owner_did_no_identity_errors_not_fallback() {
        let empty = TempDir::new().unwrap(); // no identity.pem written
        let err = resolve_owner_did("http://unused.invalid", Some(empty.path()))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("no local identity to resolve the repo owner"),
            "got: {err}"
        );
    }

    // An authenticated caller DENIED with a 403 must surface an error, never
    // render a repo card (deny-as-success is the INV-8 client-contract break).
    #[tokio::test]
    async fn cmd_info_403_denied_surfaces_error_not_card() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/repos/owner/myrepo$".to_string()),
            )
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"forbidden"}"#)
            .create_async()
            .await;
        let err = cmd_info(
            "owner/myrepo".to_string(),
            server.url(),
            Some(dir.path().to_path_buf()),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("repo info failed (403"),
            "got: {err}"
        );
    }

    // No keypair must send an unsigned GET; the mock only matches when the
    // Signature header is absent, so a wrongly-signed request fails to match.
    #[tokio::test]
    async fn get_maybe_signed_no_keypair_sends_unsigned() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/owner/pub")
            .match_header("signature", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("{}")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .get_maybe_signed("/api/v1/repos/owner/pub")
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "unsigned GET should match the Missing-signature mock; got {}",
            resp.status()
        );
    }
}
