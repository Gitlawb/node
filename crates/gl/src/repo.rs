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
async fn resolve_owner_did(node: &str, dir: Option<&std::path::Path>) -> Result<String> {
    if let Ok(kp) = load_keypair_from_dir(dir) {
        let did = kp.did().to_string();
        return Ok(did.split(':').next_back().unwrap_or(&did).to_string());
    }
    let client = NodeClient::new(node, None);
    let info: Value = client
        .get("/")
        .await?
        .json()
        .await
        .context("failed to fetch node info")?;
    let did = info["did"].as_str().context("node missing DID")?;
    Ok(did.split(':').next_back().unwrap_or(did).to_string())
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
    let did = if let Ok(kp) = load_keypair_from_dir(dir.as_deref()) {
        kp.did().to_string()
    } else {
        let client = NodeClient::new(&node, None);
        let info: Value = client.get("/").await?.json().await?;
        info["did"]
            .as_str()
            .context("node missing DID")?
            .to_string()
    };
    let url = format!("gitlawb://{did}/{name}");
    println!("  cloning {url}");
    let status = std::process::Command::new("git")
        .arg("clone")
        .arg(&url)
        .status()
        .context("failed to run git clone — is git installed?")?;
    if !status.success() {
        anyhow::bail!("git clone failed");
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

    let r: Value = client
        .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}"))
        .await?
        .json()
        .await
        .context("repo not found")?;

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
async fn resolve_owner_repo_pair(
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
    let client = NodeClient::new(&node, None);

    let resp: Value = client
        .get(&format!("/api/v1/repos/{owner}/{name}/labels"))
        .await?
        .json()
        .await
        .context("invalid JSON")?;

    let labels = resp["labels"].as_array().cloned().unwrap_or_default();
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
            val.as_array()
                .or_else(|| val["branches"].as_array())
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
            .with_body(r#"["main"]"#)
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
            .with_body(r#"["main","release"]"#)
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
            .with_body(r#"["main"]"#)
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
}
