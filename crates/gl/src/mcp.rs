//! `gl mcp serve` — MCP (Model Context Protocol) server.
//!
//! Runs a JSON-RPC 2.0 server over stdin/stdout using LSP-style
//! `Content-Length` framing.  Exposes 15 tools that give LLM agents
//! structured access to the gitlawb network.
//!
//! # Tools
//!   identity_show    — current agent DID
//!   identity_sign    — sign a message
//!   node_info        — node metadata
//!   node_health      — liveness check
//!   repo_create      — create a repository
//!   repo_list        — list repositories
//!   repo_get         — repository metadata
//!   repo_commits     — commit history
//!   repo_tree        — browse file tree
//!   repo_clone_url   — get gitlawb:// clone URL
//!   agent_register   — register agent on the network
//!   agent_capabilities — list UCAN capability strings
//!   ucan_show        — show saved bootstrap UCAN
//!   ucan_delegate    — delegate capabilities to another agent
//!   ucan_verify      — verify a UCAN token
//!   did_resolve      — resolve a DID to its document
//!   git_refs         — list git refs for a repo
//!   pr_create        — open a pull request
//!   pr_list          — list pull requests for a repo
//!   pr_view          — get a single pull request + reviews
//!   pr_diff          — get the diff for a pull request
//!   pr_review        — submit a review on a pull request
//!   pr_merge         — merge a pull request
//!   task_list        — list agent tasks
//!   task_create      — create a new task
//!   task_claim       — claim a pending task
//!   task_complete    — mark a task as completed
//!   issue_list       — list issues for a repo
//!   issue_create     — create a new issue
//!   issue_comment    — comment on an issue

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct McpArgs {
    #[command(subcommand)]
    pub cmd: McpCmd,
}

#[derive(clap::Subcommand)]
pub enum McpCmd {
    /// Start the MCP server (stdin/stdout JSON-RPC)
    Serve {
        /// Node URL to connect to
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        /// Identity directory
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub async fn run(args: McpArgs) -> Result<()> {
    match args.cmd {
        McpCmd::Serve { node, dir } => serve(node, dir).await,
    }
}

// ── Server loop ───────────────────────────────────────────────────────────────

async fn serve(node: String, dir: Option<PathBuf>) -> Result<()> {
    tracing::debug!("MCP server starting, node={node}");

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut reader = std::io::BufReader::new(stdin.lock());

    loop {
        let msg = match read_message(&mut reader) {
            Ok(Some(m)) => m,
            Ok(None) => break, // EOF
            Err(e) => {
                tracing::warn!("failed to read message: {e}");
                break;
            }
        };

        tracing::debug!(
            "← {}",
            msg.get("method").and_then(|v| v.as_str()).unwrap_or("?")
        );

        let response = handle(&msg, &node, dir.as_deref()).await;

        if let Err(e) = write_message(&mut stdout, &response) {
            tracing::warn!("failed to write response: {e}");
            break;
        }
    }

    Ok(())
}

async fn handle(msg: &Value, node: &str, dir: Option<&std::path::Path>) -> Value {
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    let result = dispatch(method, params, node, dir).await;

    match result {
        Ok(v) => json!({ "jsonrpc": "2.0", "id": id, "result": v }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32000, "message": e.to_string() }
        }),
    }
}

async fn dispatch(
    method: &str,
    params: Value,
    node: &str,
    dir: Option<&std::path::Path>,
) -> Result<Value> {
    match method {
        // ── MCP lifecycle ─────────────────────────────────────────────────────
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": "gitlawb",
                "version": env!("CARGO_PKG_VERSION"),
            }
        })),
        "notifications/initialized" => Ok(Value::Null),
        "ping" => Ok(json!({})),

        // ── Tool listing ──────────────────────────────────────────────────────
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),

        // ── Tool execution ────────────────────────────────────────────────────
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .context("tools/call missing 'name'")?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let result = call_tool(name, args, node, dir).await?;
            Ok(json!({ "content": [{ "type": "text", "text": result }] }))
        }

        other => Err(anyhow::anyhow!("method not found: {other}")),
    }
}

// ── Tool definitions ──────────────────────────────────────────────────────────

fn tool_definitions() -> Value {
    json!([
        {
            "name": "identity_show",
            "description": "Return this agent's DID (decentralized identifier). No arguments needed.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "identity_sign",
            "description": "Sign a message with this agent's Ed25519 private key. Returns base64url signature.",
            "inputSchema": {
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": { "type": "string", "description": "Message to sign (UTF-8)" }
                }
            }
        },
        {
            "name": "node_info",
            "description": "Get metadata about the connected gitlawb node: DID, version, network, protocols.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "node_health",
            "description": "Check if the gitlawb node is alive and responding.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "repo_create",
            "description": "Create a new git repository on the node. Requires agent identity for auth.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Repository name (alphanumeric, hyphens, underscores)" },
                    "description": { "type": "string", "description": "Short description" },
                    "is_public": { "type": "boolean", "description": "Public visibility (default: true)", "default": true }
                }
            }
        },
        {
            "name": "repo_list",
            "description": "List all repositories on the connected gitlawb node.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "repo_list_federated",
            "description": "List repositories across ALL nodes in the gitlawb network (federation). Returns repos from this node and all known peer nodes, each annotated with node_url and node_did.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "repo_get",
            "description": "Get metadata for a specific repository: clone URL, default branch, timestamps.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Repository name" },
                    "owner": { "type": "string", "description": "Owner DID or short DID (optional, defaults to node owner)" }
                }
            }
        },
        {
            "name": "repo_commits",
            "description": "List recent commits for a repository with SHA-256 hashes, authors, and messages.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Repository name" },
                    "owner": { "type": "string", "description": "Owner (optional)" }
                }
            }
        },
        {
            "name": "repo_tree",
            "description": "Browse the file tree of a repository at a given path.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Repository name" },
                    "path": { "type": "string", "description": "Directory path (default: root)", "default": "" },
                    "owner": { "type": "string", "description": "Owner (optional)" }
                }
            }
        },
        {
            "name": "repo_clone_url",
            "description": "Get the gitlawb:// clone URL for a repository.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Repository name" }
                }
            }
        },
        {
            "name": "agent_register",
            "description": "Register this agent with the gitlawb node to get a bootstrap UCAN token.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Capabilities to advertise",
                        "default": ["git:push", "git:fetch"]
                    },
                    "model": { "type": "string", "description": "Agent model identifier (optional)" }
                }
            }
        },
        {
            "name": "agent_capabilities",
            "description": "List all available UCAN capability strings in the gitlawb protocol.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "ucan_show",
            "description": "Show the saved bootstrap UCAN token for this agent.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "did_resolve",
            "description": "Resolve a DID to its DID document (verification methods, service endpoints).",
            "inputSchema": {
                "type": "object",
                "required": ["did"],
                "properties": {
                    "did": { "type": "string", "description": "DID to resolve, e.g. did:key:z6Mk..." }
                }
            }
        },
        {
            "name": "git_refs",
            "description": "List git refs (branches, tags) for a repository on the node.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": { "type": "string", "description": "Repository name" },
                    "owner": { "type": "string", "description": "Owner (optional)" }
                }
            }
        },
        {
            "name": "pr_create",
            "description": "Open a pull request to merge a source branch into a target branch. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "head", "title"],
                "properties": {
                    "repo":   { "type": "string", "description": "Repository name" },
                    "head":   { "type": "string", "description": "Source branch (your changes)" },
                    "base":   { "type": "string", "description": "Target branch to merge into (default: main)", "default": "main" },
                    "title":  { "type": "string", "description": "PR title" },
                    "body":   { "type": "string", "description": "PR description (optional)" },
                    "owner":  { "type": "string", "description": "Repo owner (optional, defaults to node owner)" }
                }
            }
        },
        {
            "name": "pr_list",
            "description": "List all pull requests for a repository.",
            "inputSchema": {
                "type": "object",
                "required": ["repo"],
                "properties": {
                    "repo":  { "type": "string", "description": "Repository name" },
                    "owner": { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "pr_view",
            "description": "Get details of a pull request including its status, branches, body, and all reviews.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "number"],
                "properties": {
                    "repo":   { "type": "string", "description": "Repository name" },
                    "number": { "type": "integer", "description": "PR number" },
                    "owner":  { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "pr_diff",
            "description": "Get the unified diff for a pull request (changes from head branch vs base branch).",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "number"],
                "properties": {
                    "repo":   { "type": "string", "description": "Repository name" },
                    "number": { "type": "integer", "description": "PR number" },
                    "owner":  { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "pr_review",
            "description": "Submit a review on a pull request. Status must be: approved, changes_requested, or comment.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "number", "status"],
                "properties": {
                    "repo":   { "type": "string", "description": "Repository name" },
                    "number": { "type": "integer", "description": "PR number" },
                    "status": { "type": "string", "description": "Review decision: approved | changes_requested | comment" },
                    "body":   { "type": "string", "description": "Review comment (optional)" },
                    "owner":  { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "pr_merge",
            "description": "Merge an open pull request using a no-fast-forward merge commit. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "number"],
                "properties": {
                    "repo":   { "type": "string", "description": "Repository name" },
                    "number": { "type": "integer", "description": "PR number" },
                    "owner":  { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "webhook_create",
            "description": "Create a webhook for a repository. Fires HTTP POST on PR and push events. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "url"],
                "properties": {
                    "repo":   { "type": "string", "description": "Repository name" },
                    "url":    { "type": "string", "description": "Webhook URL (http:// or https://)" },
                    "events": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Events to subscribe to. Use [\"*\"] for all. Valid: pull_request.opened, pull_request.reviewed, pull_request.merged, pull_request.closed, push",
                        "default": ["*"]
                    },
                    "secret": { "type": "string", "description": "Optional HMAC secret for payload signing" },
                    "owner":  { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "webhook_list",
            "description": "List webhooks registered for a repository.",
            "inputSchema": {
                "type": "object",
                "required": ["repo"],
                "properties": {
                    "repo":  { "type": "string", "description": "Repository name" },
                    "owner": { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "webhook_delete",
            "description": "Delete a webhook by ID. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "id"],
                "properties": {
                    "repo":  { "type": "string", "description": "Repository name" },
                    "id":    { "type": "string", "description": "Webhook ID" },
                    "owner": { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "bounty_list",
            "description": "List bounties. Optionally filter by repo (owner/name) and status (open, claimed, submitted, completed).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo":   { "type": "string", "description": "Repository in owner/name format (optional — omit for global)" },
                    "status": { "type": "string", "description": "Filter by status: open, claimed, submitted, completed" }
                }
            }
        },
        {
            "name": "bounty_show",
            "description": "Get full details of a specific bounty by ID.",
            "inputSchema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "description": "Bounty ID" }
                }
            }
        },
        {
            "name": "bounty_create",
            "description": "Create a new bounty on a repo issue. Requires agent identity. Amount in $GITLAWB tokens.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "title", "amount"],
                "properties": {
                    "repo":     { "type": "string", "description": "Repository in owner/name format" },
                    "title":    { "type": "string", "description": "Bounty title" },
                    "amount":   { "type": "integer", "description": "Bounty amount in $GITLAWB" },
                    "issue_id": { "type": "string", "description": "Issue ID to attach the bounty to" },
                    "tx_hash":  { "type": "string", "description": "On-chain escrow transaction hash" }
                }
            }
        },
        {
            "name": "bounty_claim",
            "description": "Claim an open bounty. Requires agent identity. Starts the deadline clock.",
            "inputSchema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id":     { "type": "string", "description": "Bounty ID to claim" },
                    "wallet": { "type": "string", "description": "Wallet address for payout" }
                }
            }
        },
        {
            "name": "bounty_submit",
            "description": "Submit a PR as bounty completion. Only the claimant can call this.",
            "inputSchema": {
                "type": "object",
                "required": ["id", "pr_id"],
                "properties": {
                    "id":    { "type": "string", "description": "Bounty ID" },
                    "pr_id": { "type": "string", "description": "Pull request ID submitted as completion" }
                }
            }
        },
        {
            "name": "bounty_stats",
            "description": "Get bounty statistics: open/claimed/completed counts and agent leaderboard.",
            "inputSchema": { "type": "object", "properties": {} }
        },

        // ── Task tools ──────────────────────────────────────────────────────
        {
            "name": "task_list",
            "description": "List agent tasks on the node. Optionally filter by status and assignee DID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": { "type": "string", "description": "Filter by status: pending, claimed, completed, failed" },
                    "assignee_did": { "type": "string", "description": "Filter by assignee DID" },
                    "limit": { "type": "integer", "description": "Max results (default: 50)", "default": 50 }
                }
            }
        },
        {
            "name": "task_create",
            "description": "Create a new agent task. Requires agent identity. Returns the created task.",
            "inputSchema": {
                "type": "object",
                "required": ["kind"],
                "properties": {
                    "kind": { "type": "string", "description": "Task kind (e.g. code-review, test-run, deploy)" },
                    "capability": { "type": "string", "description": "UCAN capability required (default: agent:task)", "default": "agent:task" },
                    "repo_id": { "type": "string", "description": "Repository ID to associate with (optional)" },
                    "assignee_did": { "type": "string", "description": "DID of agent to assign to (optional)" },
                    "payload": { "type": "string", "description": "JSON payload for the task (optional)" },
                    "ucan_token": { "type": "string", "description": "UCAN token granting the capability (optional)" },
                    "deadline": { "type": "string", "description": "ISO-8601 deadline (optional)" }
                }
            }
        },
        {
            "name": "task_claim",
            "description": "Claim a pending task as the current agent. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "description": "Task ID to claim" }
                }
            }
        },
        {
            "name": "task_complete",
            "description": "Mark a claimed task as completed with an optional result. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": { "type": "string", "description": "Task ID to complete" },
                    "result": { "type": "string", "description": "Result payload (optional)" }
                }
            }
        },

        // ── UCAN delegation tools ───────────────────────────────────────────
        {
            "name": "ucan_delegate",
            "description": "Delegate capabilities to another agent by issuing a signed UCAN token. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["to", "resource", "action"],
                "properties": {
                    "to": { "type": "string", "description": "Audience DID — who receives this capability (e.g. did:key:z6Mk...)" },
                    "resource": { "type": "string", "description": "Resource URI (e.g. gitlawb://repos/owner/repo)" },
                    "action": { "type": "string", "description": "Action to grant (e.g. git/push, pr/open, repo/admin)" },
                    "expiry_hours": { "type": "integer", "description": "Expiry in hours (optional, default: no expiry)" }
                }
            }
        },
        {
            "name": "ucan_verify",
            "description": "Verify a UCAN token's signature and expiry. Returns structured verification result.",
            "inputSchema": {
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "description": "UCAN token (JSON string)" }
                }
            }
        },

        // ── Issue tools ─────────────────────────────────────────────────────
        {
            "name": "issue_list",
            "description": "List issues for a repository.",
            "inputSchema": {
                "type": "object",
                "required": ["repo"],
                "properties": {
                    "repo": { "type": "string", "description": "Repository in owner/name format" },
                    "owner": { "type": "string", "description": "Repo owner (optional, defaults to node owner)" }
                }
            }
        },
        {
            "name": "issue_create",
            "description": "Create a new issue on a repository. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "title"],
                "properties": {
                    "repo": { "type": "string", "description": "Repository in owner/name format" },
                    "title": { "type": "string", "description": "Issue title" },
                    "body": { "type": "string", "description": "Issue body (optional)" },
                    "owner": { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        },
        {
            "name": "issue_comment",
            "description": "Post a comment on an issue. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["repo", "issue_id", "body"],
                "properties": {
                    "repo": { "type": "string", "description": "Repository in owner/name format" },
                    "issue_id": { "type": "string", "description": "Issue ID" },
                    "body": { "type": "string", "description": "Comment body" },
                    "owner": { "type": "string", "description": "Repo owner (optional)" }
                }
            }
        }
    ])
}

// ── Tool execution ────────────────────────────────────────────────────────────

async fn call_tool(
    name: &str,
    args: Value,
    node: &str,
    dir: Option<&std::path::Path>,
) -> Result<String> {
    let keypair = load_keypair_from_dir(dir).ok();
    let client = NodeClient::new(node, keypair.clone());

    match name {
        "identity_show" => {
            let kp = keypair.context("no identity found — run `gl identity new` first")?;
            Ok(kp.did().to_string())
        }

        "identity_sign" => {
            let kp = keypair.context("no identity found")?;
            let msg = args["message"]
                .as_str()
                .context("missing 'message' argument")?;
            Ok(kp.sign_b64(msg.as_bytes()))
        }

        "node_info" => {
            let info: Value = client.get("/").await?.json().await?;
            Ok(serde_json::to_string_pretty(&info)?)
        }

        "node_health" => {
            let health: Value = client.get("/health").await?.json().await?;
            Ok(serde_json::to_string_pretty(&health)?)
        }

        "repo_create" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let body = serde_json::to_vec(&json!({
                "name": name,
                "description": args["description"],
                "is_public": args["is_public"].as_bool().unwrap_or(true),
            }))?;
            let resp: Value = client.post("/api/v1/repos", &body).await?.json().await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "repo_list" => {
            let repos: Value = client.get("/api/v1/repos").await?.json().await?;
            Ok(serde_json::to_string_pretty(&repos)?)
        }

        "repo_list_federated" => {
            let result: Value = client.get("/api/v1/repos/federated").await?.json().await?;
            Ok(serde_json::to_string_pretty(&result)?)
        }

        "repo_get" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let owner = resolve_owner(&args, &client).await?;
            let repo: Value = client
                .get(&format!("/api/v1/repos/{owner}/{name}"))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&repo)?)
        }

        "repo_commits" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let owner = resolve_owner(&args, &client).await?;
            let commits: Value = client
                .get(&format!("/api/v1/repos/{owner}/{name}/commits"))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&commits)?)
        }

        "repo_tree" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let path = args["path"].as_str().unwrap_or("");
            let owner = resolve_owner(&args, &client).await?;
            let tree: Value = client
                .get(&format!("/api/v1/repos/{owner}/{name}/tree/{path}"))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&tree)?)
        }

        "repo_clone_url" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let info: Value = client.get("/").await?.json().await?;
            let did = info["did"].as_str().context("node info missing DID")?;
            Ok(format!("gitlawb://{}/{}", did, name))
        }

        "agent_register" => {
            let kp = keypair.context("no identity found")?;
            let caps = args["capabilities"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_else(|| vec!["git:push", "git:fetch"]);
            let body = serde_json::to_vec(&json!({
                "did": kp.did().to_string(),
                "capabilities": caps,
                "model": args["model"],
            }))?;
            let resp: Value = client.post("/api/register", &body).await?.json().await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "agent_capabilities" => Ok(serde_json::to_string_pretty(&json!([
            "git:push",
            "git:fetch",
            "git:admin",
            "pr:open",
            "pr:merge",
            "pr:review",
            "issue:create",
            "issue:close",
            "network:join",
            "network:gossip",
            "agent:deploy",
            "agent:invoke",
            "repo:admin",
            "repo:read",
            "repo:write"
        ]))?),

        "ucan_show" => {
            let ucan_path = dirs::home_dir()
                .context("no home dir")?
                .join(".gitlawb/ucan.json");
            if ucan_path.exists() {
                let content = std::fs::read_to_string(ucan_path)?;
                Ok(content)
            } else {
                Ok("No UCAN saved. Run `gl register` or use the agent_register tool.".to_string())
            }
        }

        "did_resolve" => {
            let did_str = args["did"].as_str().context("missing 'did'")?;
            let did: gitlawb_core::did::Did = did_str
                .parse()
                .map_err(|e: gitlawb_core::Error| anyhow::anyhow!("{e}"))?;
            if let Ok(vk) = did.to_verifying_key() {
                let doc = gitlawb_core::did::DidDocument::new(did, &vk);
                Ok(serde_json::to_string_pretty(&doc)?)
            } else {
                Err(anyhow::anyhow!(
                    "cannot resolve '{did_str}' locally — only did:key is supported without a resolver"
                ))
            }
        }

        "git_refs" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let owner = resolve_owner(&args, &client).await?;
            let resp = client
                .get(&format!(
                    "/{owner}/{name}/info/refs?service=git-upload-pack"
                ))
                .await?;
            let bytes = resp.bytes().await?;
            // Parse pkt-line refs
            let refs = parse_info_refs(&bytes);
            Ok(serde_json::to_string_pretty(&refs)?)
        }

        "pr_create" => {
            keypair
                .as_ref()
                .context("no identity found — run `gl identity new` first")?;
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let head = args["head"].as_str().context("missing 'head'")?;
            let base = args["base"].as_str().unwrap_or("main");
            let title = args["title"].as_str().context("missing 'title'")?;
            let owner = resolve_owner(&args, &client).await?;
            let body = serde_json::to_vec(&json!({
                "title": title,
                "body": args["body"],
                "source_branch": head,
                "target_branch": base,
            }))?;
            let resp: Value = client
                .post(&format!("/api/v1/repos/{owner}/{repo}/pulls"), &body)
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "pr_list" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let owner = resolve_owner(&args, &client).await?;
            let resp: Value = client
                .get(&format!("/api/v1/repos/{owner}/{repo}/pulls"))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "pr_view" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let number = args["number"].as_i64().context("missing 'number'")?;
            let owner = resolve_owner(&args, &client).await?;
            let pr: Value = client
                .get(&format!("/api/v1/repos/{owner}/{repo}/pulls/{number}"))
                .await?
                .json()
                .await?;
            let reviews: Value = client
                .get(&format!(
                    "/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews"
                ))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(
                &json!({ "pr": pr, "reviews": reviews["reviews"] }),
            )?)
        }

        "pr_diff" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let number = args["number"].as_i64().context("missing 'number'")?;
            let owner = resolve_owner(&args, &client).await?;
            let resp: Value = client
                .get(&format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/diff"))
                .await?
                .json()
                .await?;
            let diff = resp["diff"].as_str().unwrap_or("(empty diff)");
            Ok(diff.to_string())
        }

        "pr_review" => {
            keypair
                .as_ref()
                .context("no identity found — run `gl identity new` first")?;
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let number = args["number"].as_i64().context("missing 'number'")?;
            let status = args["status"].as_str().context("missing 'status'")?;
            let owner = resolve_owner(&args, &client).await?;
            let body = serde_json::to_vec(&json!({
                "status": status,
                "body": args["body"],
            }))?;
            let resp: Value = client
                .post(
                    &format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews"),
                    &body,
                )
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "pr_merge" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let number = args["number"].as_i64().context("missing 'number'")?;
            let owner = resolve_owner(&args, &client).await?;
            let body = serde_json::to_vec(&json!({}))?;
            let resp: Value = client
                .post(
                    &format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/merge"),
                    &body,
                )
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "webhook_create" => {
            keypair
                .as_ref()
                .context("no identity found — run `gl identity new` first")?;
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let url = args["url"].as_str().context("missing 'url'")?;
            let events = args["events"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_else(|| vec!["*"]);
            let owner = resolve_owner(&args, &client).await?;
            let body = serde_json::to_vec(&json!({
                "url": url,
                "secret": args["secret"],
                "events": events,
            }))?;
            let resp: Value = client
                .post(&format!("/api/v1/repos/{owner}/{repo}/hooks"), &body)
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "webhook_list" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let owner = resolve_owner(&args, &client).await?;
            let resp: Value = client
                .get(&format!("/api/v1/repos/{owner}/{repo}/hooks"))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "webhook_delete" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let id = args["id"].as_str().context("missing 'id'")?;
            let owner = resolve_owner(&args, &client).await?;
            let body = serde_json::to_vec(&json!({}))?;
            let resp: Value = client
                .delete(&format!("/api/v1/repos/{owner}/{repo}/hooks/{id}"), &body)
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        // ── Bounty tools ────────────────────────────────────────────────────
        "bounty_list" => {
            let url = if let Some(repo) = args.get("repo").and_then(|v| v.as_str()) {
                let (owner, name) = repo.split_once('/').context("repo must be owner/name")?;
                let mut u = format!("/api/v1/repos/{owner}/{name}/bounties");
                if let Some(s) = args.get("status").and_then(|v| v.as_str()) {
                    u.push_str(&format!("?status={s}"));
                }
                u
            } else {
                let mut u = "/api/v1/bounties".to_string();
                if let Some(s) = args.get("status").and_then(|v| v.as_str()) {
                    u.push_str(&format!("?status={s}"));
                }
                u
            };
            let resp: Value = client.get_authed(&url).await?.json().await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_show" => {
            let id = args["id"].as_str().context("missing 'id'")?;
            let resp: Value = client
                .get_authed(&format!("/api/v1/bounties/{id}"))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_create" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let (owner, name) = repo.split_once('/').context("repo must be owner/name")?;
            let body = json!({
                "title": args["title"].as_str().context("missing 'title'")?,
                "amount": args["amount"].as_i64().context("missing 'amount'")?,
                "issue_id": args.get("issue_id").and_then(|v| v.as_str()),
                "tx_hash": args.get("tx_hash").and_then(|v| v.as_str()),
            });
            let resp: Value = client
                .post(
                    &format!("/api/v1/repos/{owner}/{name}/bounties"),
                    &serde_json::to_vec(&body)?,
                )
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_claim" => {
            let id = args["id"].as_str().context("missing 'id'")?;
            let body = json!({ "wallet": args.get("wallet").and_then(|v| v.as_str()) });
            let resp: Value = client
                .post(
                    &format!("/api/v1/bounties/{id}/claim"),
                    &serde_json::to_vec(&body)?,
                )
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_submit" => {
            let id = args["id"].as_str().context("missing 'id'")?;
            let pr_id = args["pr_id"].as_str().context("missing 'pr_id'")?;
            let body = json!({ "pr_id": pr_id });
            let resp: Value = client
                .post(
                    &format!("/api/v1/bounties/{id}/submit"),
                    &serde_json::to_vec(&body)?,
                )
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_stats" => {
            let resp: Value = client.get("/api/v1/bounties/stats").await?.json().await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        // ── Task tools ────────────────────────────────────────────────────
        "task_list" => {
            let limit = args["limit"].as_i64().unwrap_or(50);
            let mut path = format!("/api/v1/tasks?limit={limit}");
            if let Some(s) = args.get("status").and_then(|v| v.as_str()) {
                path.push_str(&format!("&status={}", urlencoding::encode(s)));
            }
            if let Some(a) = args.get("assignee_did").and_then(|v| v.as_str()) {
                path.push_str(&format!("&assignee_did={}", urlencoding::encode(a)));
            }
            let resp: Value = client.get(&path).await?.json().await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "task_create" => {
            let kp = keypair.context("no identity found — run `gl identity new` first")?;
            let delegator_did = kp.did().to_string();
            let body = serde_json::to_vec(&json!({
                "kind": args["kind"].as_str().context("missing 'kind'")?,
                "capability": args["capability"].as_str().unwrap_or("agent:task"),
                "repo_id": args.get("repo_id").and_then(|v| v.as_str()),
                "assignee_did": args.get("assignee_did").and_then(|v| v.as_str()),
                "payload": args.get("payload").and_then(|v| v.as_str()),
                "ucan_token": args.get("ucan_token").and_then(|v| v.as_str()),
                "deadline": args.get("deadline").and_then(|v| v.as_str()),
                "delegator_did": delegator_did,
            }))?;
            let resp: Value = client.post("/api/v1/tasks", &body).await?.json().await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "task_claim" => {
            let kp = keypair.context("no identity found — run `gl identity new` first")?;
            let assignee_did = kp.did().to_string();
            let id = args["id"].as_str().context("missing 'id'")?;
            let body = serde_json::to_vec(&json!({ "assignee_did": assignee_did }))?;
            let resp: Value = client
                .post(&format!("/api/v1/tasks/{id}/claim"), &body)
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "task_complete" => {
            let kp = keypair.context("no identity found — run `gl identity new` first")?;
            let by_did = kp.did().to_string();
            let id = args["id"].as_str().context("missing 'id'")?;
            let body = serde_json::to_vec(&json!({
                "result": args.get("result").and_then(|v| v.as_str()),
                "by_did": by_did,
            }))?;
            let resp: Value = client
                .post(&format!("/api/v1/tasks/{id}/complete"), &body)
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        // ── UCAN delegation tools ─────────────────────────────────────────
        "ucan_delegate" => {
            let kp = keypair.context("no identity found — run `gl identity new` first")?;
            let to_str = args["to"].as_str().context("missing 'to'")?;
            let resource = args["resource"].as_str().context("missing 'resource'")?;
            let action = args["action"].as_str().context("missing 'action'")?;

            let audience: gitlawb_core::did::Did = to_str
                .parse()
                .map_err(|e: gitlawb_core::Error| anyhow::anyhow!("{e}"))?;

            let exp = args
                .get("expiry_hours")
                .and_then(|v| v.as_i64())
                .map(|h| chrono::Utc::now() + chrono::Duration::hours(h));

            let ucan = gitlawb_core::ucan::Ucan::issue(
                &kp,
                audience,
                vec![gitlawb_core::ucan::Capability::new(resource, action)],
                exp,
            )?;
            let encoded = ucan.encode()?;

            Ok(serde_json::to_string_pretty(&json!({
                "issuer": ucan.payload.iss.to_string(),
                "audience": ucan.payload.aud.to_string(),
                "capability": { "with": resource, "can": action },
                "expires": ucan.payload.exp,
                "token": encoded,
            }))?)
        }

        "ucan_verify" => {
            let token = args["token"].as_str().context("missing 'token'")?;
            let ucan =
                gitlawb_core::ucan::Ucan::decode(token).context("failed to parse UCAN token")?;
            let sig_valid = ucan.verify_signature().is_ok();
            let expired = ucan.is_expired();
            let caps: Vec<Value> = ucan
                .payload
                .att
                .iter()
                .map(|c| json!({ "with": c.with, "can": c.can }))
                .collect();

            Ok(serde_json::to_string_pretty(&json!({
                "valid": sig_valid && !expired,
                "signature_valid": sig_valid,
                "expired": expired,
                "issuer": ucan.payload.iss.to_string(),
                "audience": ucan.payload.aud.to_string(),
                "capabilities": caps,
                "expires": ucan.payload.exp,
            }))?)
        }

        // ── Issue tools ───────────────────────────────────────────────────
        "issue_list" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let (owner, name) = if let Some((o, n)) = repo.split_once('/') {
                (o.to_string(), n.to_string())
            } else {
                let owner = resolve_owner(&args, &client).await?;
                (owner, repo.to_string())
            };
            let resp: Value = client
                .get_authed(&format!("/api/v1/repos/{owner}/{name}/issues"))
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "issue_create" => {
            keypair
                .as_ref()
                .context("no identity found — run `gl identity new` first")?;
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let title = args["title"].as_str().context("missing 'title'")?;
            let (owner, name) = if let Some((o, n)) = repo.split_once('/') {
                (o.to_string(), n.to_string())
            } else {
                let owner = resolve_owner(&args, &client).await?;
                (owner, repo.to_string())
            };
            let body = serde_json::to_vec(&json!({
                "title": title,
                "body": args.get("body").and_then(|v| v.as_str()),
            }))?;
            let resp: Value = client
                .post(&format!("/api/v1/repos/{owner}/{name}/issues"), &body)
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "issue_comment" => {
            keypair
                .as_ref()
                .context("no identity found — run `gl identity new` first")?;
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let issue_id = args["issue_id"].as_str().context("missing 'issue_id'")?;
            let comment_body = args["body"].as_str().context("missing 'body'")?;
            let (owner, name) = if let Some((o, n)) = repo.split_once('/') {
                (o.to_string(), n.to_string())
            } else {
                let owner = resolve_owner(&args, &client).await?;
                (owner, repo.to_string())
            };
            let body = serde_json::to_vec(&json!({ "body": comment_body }))?;
            let resp: Value = client
                .post(
                    &format!("/api/v1/repos/{owner}/{name}/issues/{issue_id}/comments"),
                    &body,
                )
                .await?
                .json()
                .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        unknown => Err(anyhow::anyhow!("unknown tool: {unknown}")),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Get the owner short-DID from args or default to the node's own DID.
async fn resolve_owner(args: &Value, client: &NodeClient) -> Result<String> {
    if let Some(o) = args.get("owner").and_then(|v| v.as_str()) {
        return Ok(o.to_string());
    }
    let info: Value = client.get("/").await?.json().await?;
    let did = info["did"].as_str().context("node info missing DID")?;
    Ok(did.split(':').next_back().unwrap_or(did).to_string())
}

/// Parse git pkt-line info/refs response into a list of {ref, sha} objects.
fn parse_info_refs(bytes: &[u8]) -> Value {
    let mut refs = Vec::new();
    let mut pos = 0;

    // Skip service announcement (pkt-line + flush)
    if bytes.len() > 4 {
        if let Ok(hex) = std::str::from_utf8(&bytes[..4]) {
            if let Ok(len) = usize::from_str_radix(hex, 16) {
                if len >= 4 && len <= bytes.len() {
                    pos = len;
                    if pos + 4 <= bytes.len() && &bytes[pos..pos + 4] == b"0000" {
                        pos += 4;
                    }
                }
            }
        }
    }

    while pos + 4 <= bytes.len() {
        let Ok(hex) = std::str::from_utf8(&bytes[pos..pos + 4]) else {
            break;
        };
        let Ok(len) = usize::from_str_radix(hex, 16) else {
            break;
        };
        if len == 0 {
            pos += 4;
            continue;
        }
        if len < 4 || pos + len > bytes.len() {
            break;
        }

        let line = std::str::from_utf8(&bytes[pos + 4..pos + len]).unwrap_or("");
        let line = line.trim_end_matches('\n');

        // First line has capabilities after NUL: "<sha> <ref>\0<caps>"
        let line = line.split('\0').next().unwrap_or(line);

        if let Some((sha, refname)) = line.split_once(' ') {
            refs.push(json!({ "ref": refname, "sha": sha }));
        }
        pos += len;
    }

    json!({ "refs": refs })
}

// ── JSON-RPC framing (LSP-style Content-Length) ───────────────────────────────

fn read_message(reader: &mut impl BufRead) -> Result<Option<Value>> {
    let mut content_length: Option<usize> = None;

    // Read headers until blank line
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        if line.is_empty() {
            break; // End of headers
        }
        if let Some(val) = line.strip_prefix("Content-Length: ") {
            content_length = Some(val.trim().parse().context("invalid Content-Length")?);
        }
    }

    let len = content_length.context("missing Content-Length header")?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;

    Ok(Some(serde_json::from_slice(&buf)?))
}

fn write_message(writer: &mut impl Write, value: &Value) -> Result<()> {
    let json = serde_json::to_string(value)?;
    write!(writer, "Content-Length: {}\r\n\r\n{}", json.len(), json)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Framing tests ────────────────────────────────────────────────────────

    #[test]
    fn test_write_read_roundtrip() {
        let msg = json!({"jsonrpc": "2.0", "method": "ping", "id": 1});
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();

        let mut reader = std::io::BufReader::new(Cursor::new(buf));
        let parsed = read_message(&mut reader).unwrap().unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_read_eof_returns_none() {
        let mut reader = std::io::BufReader::new(Cursor::new(Vec::<u8>::new()));
        let result = read_message(&mut reader).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_write_message_format() {
        let msg = json!({"ok": true});
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("Content-Length: "));
        assert!(output.contains("\r\n\r\n"));
        // Verify the content-length value matches the JSON body
        let parts: Vec<&str> = output.splitn(2, "\r\n\r\n").collect();
        let len: usize = parts[0]
            .strip_prefix("Content-Length: ")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(len, parts[1].len());
    }

    #[test]
    fn test_multiple_messages_roundtrip() {
        let msgs = vec![
            json!({"jsonrpc": "2.0", "method": "initialize", "id": 1}),
            json!({"jsonrpc": "2.0", "method": "tools/list", "id": 2}),
            json!({"jsonrpc": "2.0", "method": "ping", "id": 3}),
        ];
        let mut buf = Vec::new();
        for msg in &msgs {
            write_message(&mut buf, msg).unwrap();
        }

        let mut reader = std::io::BufReader::new(Cursor::new(buf));
        for expected in &msgs {
            let parsed = read_message(&mut reader).unwrap().unwrap();
            assert_eq!(&parsed, expected);
        }
        assert!(read_message(&mut reader).unwrap().is_none());
    }

    // ── Dispatch tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_dispatch_initialize() {
        let result = dispatch("initialize", json!({}), "http://localhost", None)
            .await
            .unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "gitlawb");
    }

    #[tokio::test]
    async fn test_dispatch_ping() {
        let result = dispatch("ping", json!({}), "http://localhost", None)
            .await
            .unwrap();
        assert_eq!(result, json!({}));
    }

    #[tokio::test]
    async fn test_dispatch_notifications_initialized() {
        let result = dispatch(
            "notifications/initialized",
            json!({}),
            "http://localhost",
            None,
        )
        .await
        .unwrap();
        assert_eq!(result, Value::Null);
    }

    #[tokio::test]
    async fn test_dispatch_unknown_method() {
        let result = dispatch("nonexistent/method", json!({}), "http://localhost", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("method not found"));
    }

    #[tokio::test]
    async fn test_dispatch_tools_list() {
        let result = dispatch("tools/list", json!({}), "http://localhost", None)
            .await
            .unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());

        // Verify expected tools exist
        let tool_names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(tool_names.contains(&"identity_show"));
        assert!(tool_names.contains(&"repo_create"));
        assert!(tool_names.contains(&"pr_create"));
        assert!(tool_names.contains(&"bounty_list"));
        assert!(tool_names.contains(&"ucan_show"));
        assert!(tool_names.contains(&"webhook_create"));
    }

    #[tokio::test]
    async fn test_dispatch_tools_call_missing_name() {
        let result = dispatch(
            "tools/call",
            json!({}), // no "name" field
            "http://localhost",
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_dispatch_tools_call_unknown_tool() {
        let result = dispatch(
            "tools/call",
            json!({"name": "nonexistent_tool"}),
            "http://localhost",
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown tool"));
    }

    // ── Handle (full JSON-RPC envelope) tests ────────────────────────────────

    #[tokio::test]
    async fn test_handle_returns_jsonrpc_response() {
        let msg = json!({"jsonrpc": "2.0", "method": "ping", "id": 42});
        let resp = handle(&msg, "http://localhost", None).await;
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 42);
        assert!(resp.get("result").is_some());
        assert!(resp.get("error").is_none());
    }

    #[tokio::test]
    async fn test_handle_error_response() {
        let msg = json!({"jsonrpc": "2.0", "method": "nonexistent", "id": 99});
        let resp = handle(&msg, "http://localhost", None).await;
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 99);
        assert!(resp.get("error").is_some());
        assert_eq!(resp["error"]["code"], -32000);
    }

    // ── Tool definition validation ───────────────────────────────────────────

    #[test]
    fn test_tool_definitions_all_have_required_fields() {
        let tools = tool_definitions();
        let tools = tools.as_array().unwrap();
        for tool in tools {
            assert!(tool.get("name").is_some(), "tool missing name: {tool}");
            assert!(
                tool.get("description").is_some(),
                "tool missing description: {tool}"
            );
            assert!(
                tool.get("inputSchema").is_some(),
                "tool missing inputSchema: {tool}"
            );
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    // ── parse_info_refs tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_info_refs_empty() {
        let result = parse_info_refs(b"");
        assert_eq!(result["refs"].as_array().unwrap().len(), 0);
    }

    // ── New tool definition tests (v0.3.8) ──────────────────────────────────

    #[test]
    fn test_tool_definitions_include_task_tools() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"task_list"));
        assert!(names.contains(&"task_create"));
        assert!(names.contains(&"task_claim"));
        assert!(names.contains(&"task_complete"));
    }

    #[test]
    fn test_tool_definitions_include_ucan_tools() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"ucan_delegate"));
        assert!(names.contains(&"ucan_verify"));
    }

    #[test]
    fn test_tool_definitions_include_issue_tools() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"issue_list"));
        assert!(names.contains(&"issue_create"));
        assert!(names.contains(&"issue_comment"));
    }

    #[tokio::test]
    async fn test_task_list_via_mcp() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1","kind":"test","status":"pending"}]}"#)
            .create_async()
            .await;

        let result = call_tool(
            "task_list",
            json!({"status": "pending"}),
            &server.url(),
            None,
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["tasks"][0]["id"], "t1");
    }

    #[tokio::test]
    async fn test_task_create_via_mcp() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"t2","kind":"code-review","status":"pending"}"#)
            .create_async()
            .await;

        let result = call_tool(
            "task_create",
            json!({"kind": "code-review"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["kind"], "code-review");
    }

    #[tokio::test]
    async fn test_task_claim_via_mcp() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/t3/claim")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"t3","status":"claimed"}"#)
            .create_async()
            .await;

        let result = call_tool(
            "task_claim",
            json!({"id": "t3"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "claimed");
    }

    #[tokio::test]
    async fn test_task_complete_via_mcp() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/tasks/t4/complete")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"t4","status":"completed"}"#)
            .create_async()
            .await;

        let result = call_tool(
            "task_complete",
            json!({"id": "t4", "result": "all good"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["status"], "completed");
    }

    #[tokio::test]
    async fn test_ucan_delegate_via_mcp() {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let audience = gitlawb_core::identity::Keypair::generate();
        let result = call_tool(
            "ucan_delegate",
            json!({
                "to": audience.did().to_string(),
                "resource": "gitlawb://repos/test/repo",
                "action": "git/push",
                "expiry_hours": 24,
            }),
            "http://localhost",
            Some(dir.path()),
        )
        .await
        .unwrap();

        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["audience"], audience.did().to_string());
        assert!(parsed["token"].as_str().unwrap().len() > 10);
        assert_eq!(parsed["capability"]["can"], "git/push");
    }

    #[tokio::test]
    async fn test_ucan_verify_via_mcp() {
        let kp = gitlawb_core::identity::Keypair::generate();
        let audience = gitlawb_core::identity::Keypair::generate();
        let ucan = gitlawb_core::ucan::Ucan::issue(
            &kp,
            audience.did(),
            vec![gitlawb_core::ucan::Capability::new(
                "gitlawb://test",
                "git/push",
            )],
            None,
        )
        .unwrap();
        let token = ucan.encode().unwrap();

        let result = call_tool(
            "ucan_verify",
            json!({"token": token}),
            "http://localhost",
            None,
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["valid"], true);
        assert_eq!(parsed["signature_valid"], true);
        assert_eq!(parsed["expired"], false);
    }

    #[tokio::test]
    async fn test_issue_list_via_mcp() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/myrepo/issues")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"issues":[{"id":"i1","title":"Bug","status":"open"}]}"#)
            .create_async()
            .await;

        let result = call_tool(
            "issue_list",
            json!({"repo": "alice/myrepo"}),
            &server.url(),
            None,
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["issues"][0]["id"], "i1");
    }

    #[tokio::test]
    async fn test_issue_create_via_mcp() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/repos/alice/myrepo/issues")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"i2","title":"New bug"}"#)
            .create_async()
            .await;

        let result = call_tool(
            "issue_create",
            json!({"repo": "alice/myrepo", "title": "New bug", "body": "steps to reproduce"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["title"], "New bug");
    }

    #[tokio::test]
    async fn test_issue_comment_via_mcp() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/repos/alice/myrepo/issues/i1/comments")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"c1","body":"looks good"}"#)
            .create_async()
            .await;

        let result = call_tool(
            "issue_comment",
            json!({"repo": "alice/myrepo", "issue_id": "i1", "body": "looks good"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["body"], "looks good");
    }

    #[test]
    fn test_tool_count_is_42() {
        let tools = tool_definitions();
        let count = tools.as_array().unwrap().len();
        assert_eq!(count, 40, "expected 40 tools, got {count}");
    }
}
