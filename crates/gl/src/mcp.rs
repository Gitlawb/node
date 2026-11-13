//! `gl mcp serve` — MCP (Model Context Protocol) server.
//!
//! Runs a JSON-RPC 2.0 server over stdin/stdout using LSP-style
//! `Content-Length` framing.  Exposes 15 tools that give LLM agents
//! structured access to the Twigpine network.
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
        #[arg(
            long,
            default_value = "https://node.twigpine.com",
            env = "GITLAWB_NODE"
        )]
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
            "description": "Get metadata about the connected Twigpine node: DID, version, network, protocols.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "node_health",
            "description": "Check if the Twigpine node is alive and responding.",
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
            "description": "List all repositories on the connected Twigpine node.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "repo_list_federated",
            "description": "List repositories across ALL nodes in the Twigpine network (federation). Returns repos from this node and all known peer nodes, each annotated with node_url and node_did.",
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
            "description": "Register this agent with the Twigpine node to get a bootstrap UCAN token.",
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
            "description": "List all available UCAN capability strings in the Twigpine protocol.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "ucan_show",
            "description": "Show the saved bootstrap UCAN for this agent: issuer, audience, capabilities, expiry, and signature validity. The token itself is not returned.",
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
                    "limit": { "type": "integer", "minimum": 1, "description": "Total results to return (default: 50). Must be positive; a non-positive limit is rejected rather than answered with an empty list. Values above the node's 200-row page cap are gathered by following continuation tokens.", "default": 50 },
                    "cursor": { "type": "string", "description": "Resume from a previous call's next_cursor. Must be paired with the same status/assignee_did filter that produced it." }
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
            "description": "Delegate capabilities to another agent by issuing a signed UCAN token. Requires agent identity. The recipient stores it with `gl ucan import <token>` or the `ucan_import` tool so their `git push` can present it.",
            "inputSchema": {
                "type": "object",
                "required": ["to", "resource", "action"],
                "properties": {
                    "to": { "type": "string", "description": "Audience DID — who receives this capability (e.g. did:key:z6Mk...)" },
                    "resource": { "type": "string", "description": "Resource URI (e.g. gitlawb://repos/owner/repo)" },
                    "action": { "type": "string", "description": "Action to grant (e.g. git/push, pr/open, repo/admin)" },
                    "expiry_hours": { "type": "integer", "minimum": 1, "description": "Expiry in hours (default: 720, the same as `gl ucan delegate`). Every link of a push chain must expire, so there is no unbounded option." }
                }
            }
        },
        {
            "name": "ucan_verify",
            "description": "Verify a UCAN token: signature, expiry, and the proof chain back to its root issuer. `valid` is true only when all three hold.",
            "inputSchema": {
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "description": "UCAN token (JSON string)" }
                }
            }
        },
        {
            "name": "ucan_import",
            "description": "Store a delegation received from a repository owner where `git push` (git-remote-gitlawb) will present it. Same checks as `gl ucan import`: addressed to this identity, owner-rooted, every link bounded and naming one repository. Requires agent identity.",
            "inputSchema": {
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": { "type": "string", "description": "UCAN token JSON, as returned by ucan_delegate" }
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
    // An explicit dir with no identity file is a clean anonymous caller
    // (main's unsigned `webhook_list` path lets the node answer the denial);
    // a present but unloadable identity is an error, never a silent
    // downgrade to anonymous (this PR's `load_optional_keypair` contract).
    let keypair = match dir {
        Some(d) if !d.join("identity.pem").exists() => None,
        _ => crate::identity::load_optional_keypair(dir)?,
    };
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
            let info = crate::http::read_json(client.get("/").await?, "node info").await?;
            Ok(serde_json::to_string_pretty(&info)?)
        }

        "node_health" => {
            let health =
                crate::http::read_json(client.get("/health").await?, "node health").await?;
            Ok(serde_json::to_string_pretty(&health)?)
        }

        "repo_create" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let body = serde_json::to_vec(&json!({
                "name": name,
                "description": args["description"],
                "is_public": args["is_public"].as_bool().unwrap_or(true),
            }))?;
            let resp =
                crate::http::read_json(client.post("/api/v1/repos", &body).await?, "create repo")
                    .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "repo_list" => {
            let repos =
                crate::http::read_json(client.get("/api/v1/repos").await?, "list repos").await?;
            Ok(serde_json::to_string_pretty(&repos)?)
        }

        "repo_list_federated" => {
            let result = crate::http::read_json(
                client.get("/api/v1/repos/federated").await?,
                "list federated repos",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&result)?)
        }

        "repo_get" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let owner = resolve_signed_read_owner(&args, &keypair, &client).await?;
            let repo = crate::http::read_json(
                client
                    .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}"))
                    .await?,
                "repo",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&repo)?)
        }

        "repo_commits" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let owner = resolve_signed_read_owner(&args, &keypair, &client).await?;
            let commits = crate::http::read_json(
                client
                    .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}/commits"))
                    .await?,
                "commits",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&commits)?)
        }

        "repo_tree" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let path = args["path"].as_str().unwrap_or("");
            let owner = resolve_owner(&args, &client).await?;
            let tree = crate::http::read_json(
                client
                    .get(&format!("/api/v1/repos/{owner}/{name}/tree/{path}"))
                    .await?,
                "tree",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&tree)?)
        }

        "repo_clone_url" => {
            let name = args["name"].as_str().context("missing 'name'")?;
            let info = crate::http::read_json(client.get("/").await?, "node info").await?;
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
            let resp = crate::http::read_json(
                client.post("/api/register", &body).await?,
                "register agent",
            )
            .await?;
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
            // The directory the server was started with, like every sibling tool.
            // Reading the default here while the rest honour `--dir` splits one MCP
            // session across two identity directories.
            let ucan_path = crate::identity::gitlawb_dir(dir.map(std::path::Path::to_path_buf))?
                .join("ucan.json");
            if !ucan_path.exists() {
                return Ok(
                    "No UCAN saved. Run `gl register` or use the agent_register tool.".to_string(),
                );
            }
            let content = std::fs::read_to_string(&ucan_path)?;
            // Decoded fields, matching what `gl ucan show` reports — the two are the
            // same question asked through different surfaces and should not answer
            // it in different shapes.
            //
            // Returning the file verbatim also handed the caller the bootstrap token
            // itself. That is the credential the agent presents, and an MCP response
            // travels further than a terminal: into a model's context, transcripts,
            // and logs. The fields below are what a caller actually needs to know
            // whether it is registered and until when.
            let ucan = crate::ucan_cmd::decode_saved_ucan(&content).with_context(|| {
                format!("could not read the saved UCAN at {}", ucan_path.display())
            })?;
            Ok(serde_json::to_string_pretty(&json!({
                "issuer": crate::ucan_cmd::shown(&ucan.payload.iss.to_string()),
                "audience": crate::ucan_cmd::shown(&ucan.payload.aud.to_string()),
                "version": crate::ucan_cmd::shown(&ucan.payload.ucan),
                "capabilities": ucan.payload.att.iter()
                    .map(|c| json!({ "with": crate::ucan_cmd::shown(&c.with), "can": crate::ucan_cmd::shown(&c.can) }))
                    .collect::<Vec<_>>(),
                "expires": ucan.payload.exp.map(|e| {
                    chrono::DateTime::from_timestamp(e, 0)
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_else(|| e.to_string())
                }),
                "expired": ucan.is_expired(),
                "signature_valid": ucan.verify_signature().is_ok(),
                "path": ucan_path.display().to_string(),
            }))?)
        }

        "did_resolve" => {
            let did_str = args["did"].as_str().context("missing 'did'")?;
            let did: gitlawb_core::did::Did = did_str
                .parse()
                .map_err(|e: gitlawb_core::Error| anyhow::anyhow!("{e}"))?;
            let is_did_key = did.is_did_key();
            match did.to_verifying_key() {
                Ok(vk) => {
                    let doc = gitlawb_core::did::DidDocument::new(did, &vk);
                    Ok(serde_json::to_string_pretty(&doc)?)
                }
                Err(e) => Err(anyhow::anyhow!(did_resolve_failure_message(
                    did_str, is_did_key, &e
                ))),
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
            let status = resp.status();
            if !status.is_success() {
                anyhow::bail!("git refs failed ({status})");
            }
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
            let resp = crate::http::read_json(
                client
                    .post(&format!("/api/v1/repos/{owner}/{repo}/pulls"), &body)
                    .await?,
                "create pull request",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "pr_list" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let owner = resolve_signed_read_owner(&args, &keypair, &client).await?;
            let resp = crate::http::read_json(
                client
                    .get_maybe_signed(&format!("/api/v1/repos/{owner}/{repo}/pulls"))
                    .await?,
                "pull requests",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "pr_view" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let number = args["number"].as_i64().context("missing 'number'")?;
            let owner = resolve_signed_read_owner(&args, &keypair, &client).await?;
            let pr = crate::http::read_json(
                client
                    .get_maybe_signed(&format!("/api/v1/repos/{owner}/{repo}/pulls/{number}"))
                    .await?,
                "pull request",
            )
            .await?;
            let reviews = crate::http::read_json(
                client
                    .get_maybe_signed(&format!(
                        "/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews"
                    ))
                    .await?,
                "reviews",
            )
            .await?;
            Ok(serde_json::to_string_pretty(
                &json!({ "pr": pr, "reviews": reviews["reviews"] }),
            )?)
        }

        "pr_diff" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let number = args["number"].as_i64().context("missing 'number'")?;
            let owner = resolve_signed_read_owner(&args, &keypair, &client).await?;
            let resp = crate::http::read_json(
                client
                    .get_maybe_signed(&format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/diff"))
                    .await?,
                "diff",
            )
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
            let resp = crate::http::read_json(
                client
                    .post(
                        &format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/reviews"),
                        &body,
                    )
                    .await?,
                "submit review",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "pr_merge" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let number = args["number"].as_i64().context("missing 'number'")?;
            let owner = resolve_owner(&args, &client).await?;
            let body = serde_json::to_vec(&json!({}))?;
            let resp = crate::http::read_json(
                client
                    .post(
                        &format!("/api/v1/repos/{owner}/{repo}/pulls/{number}/merge"),
                        &body,
                    )
                    .await?,
                "merge pull request",
            )
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
            let (owner, name) = resolve_owner_repo(&args, repo, &keypair, &client).await?;
            let body = serde_json::to_vec(&json!({
                "url": url,
                "secret": args["secret"],
                "events": events,
            }))?;
            let resp = crate::http::read_json(
                client
                    .post(&format!("/api/v1/repos/{owner}/{name}/hooks"), &body)
                    .await?,
                "create webhook",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "webhook_list" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            // Owner-gated route: `owner/repo` splits first, an explicit `owner`
            // arg wins next, otherwise the signing keypair's short DID (NOT the
            // node DID that resolve_owner returns). The request is signed by
            // this keypair, so the path owner must match it or the node
            // returns 403/404.
            let (owner, name) = resolve_owner_repo(&args, repo, &keypair, &client).await?;
            // Owner-gated AND auth-required route (list_webhooks 401s a headerless
            // caller, then 403s a non-owner). get_maybe_signed signs when an
            // identity is present (so the owner is authorized) and otherwise sends
            // unsigned — the node then returns the 401/403/404 denial, which
            // read_json (#186) surfaces as an error instead of a fake result, with
            // a bounded error read. Unlike get_signed, this still ISSUES the request
            // without a local identity (surfacing the node's denial) rather than
            // failing client-side before the node is contacted.
            let resp = crate::http::read_json(
                client
                    .get_maybe_signed(&format!("/api/v1/repos/{owner}/{name}/hooks"))
                    .await?,
                "webhook_list",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "webhook_delete" => {
            let repo = args["repo"].as_str().context("missing 'repo'")?;
            let id = args["id"].as_str().context("missing 'id'")?;
            let (owner, name) = resolve_owner_repo(&args, repo, &keypair, &client).await?;
            let body = serde_json::to_vec(&json!({}))?;
            let resp = crate::http::read_json(
                client
                    .delete(&format!("/api/v1/repos/{owner}/{name}/hooks/{id}"), &body)
                    .await?,
                "delete webhook",
            )
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
            let resp = crate::http::read_json(client.get_authed(&url).await?, "bounties").await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_show" => {
            let id = args["id"].as_str().context("missing 'id'")?;
            let resp = crate::http::read_json(
                client.get_authed(&format!("/api/v1/bounties/{id}")).await?,
                "bounty",
            )
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
            let resp = crate::http::read_json(
                client
                    .post(
                        &format!("/api/v1/repos/{owner}/{name}/bounties"),
                        &serde_json::to_vec(&body)?,
                    )
                    .await?,
                "create bounty",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_claim" => {
            let id = args["id"].as_str().context("missing 'id'")?;
            let body = json!({ "wallet": args.get("wallet").and_then(|v| v.as_str()) });
            let resp = crate::http::read_json(
                client
                    .post(
                        &format!("/api/v1/bounties/{id}/claim"),
                        &serde_json::to_vec(&body)?,
                    )
                    .await?,
                "claim bounty",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_submit" => {
            let id = args["id"].as_str().context("missing 'id'")?;
            let pr_id = args["pr_id"].as_str().context("missing 'pr_id'")?;
            let body = json!({ "pr_id": pr_id });
            let resp = crate::http::read_json(
                client
                    .post(
                        &format!("/api/v1/bounties/{id}/submit"),
                        &serde_json::to_vec(&body)?,
                    )
                    .await?,
                "submit bounty",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "bounty_stats" => {
            let resp =
                crate::http::read_json(client.get("/api/v1/bounties/stats").await?, "bounty stats")
                    .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        // ── Task tools ────────────────────────────────────────────────────
        "task_list" => {
            // Follows the node's opaque `next_cursor` so a limit above the
            // 200-row server page cap returns what was asked for instead of a
            // silently truncated page, and reports an explicit incomplete
            // result when a guard or the node's scan ceiling stops it (#327).
            let limit = match args.get("limit") {
                None | Some(Value::Null) => 50,
                Some(val) => val.as_i64().context("invalid limit: expected an integer")?,
            };
            let cursor = match args.get("cursor") {
                None | Some(Value::Null) => None,
                Some(val) => Some(val.as_str().context("invalid cursor: expected a string")?),
            };
            let result = crate::task::fetch_tasks(
                &client,
                args.get("status").and_then(|v| v.as_str()),
                args.get("assignee_did").and_then(|v| v.as_str()),
                limit,
                cursor,
            )
            .await?;
            let mut out = result.to_json();
            if let Some(warning) = result.truncation_warning() {
                out["warning"] = Value::String(warning);
            }
            Ok(serde_json::to_string_pretty(&out)?)
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
            let resp =
                crate::http::read_json(client.post("/api/v1/tasks", &body).await?, "create task")
                    .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        "task_claim" => {
            let kp = keypair.context("no identity found — run `gl identity new` first")?;
            let assignee_did = kp.did().to_string();
            let id = args["id"].as_str().context("missing 'id'")?;
            let body = serde_json::to_vec(&json!({ "assignee_did": assignee_did }))?;
            let resp = crate::http::read_json(
                client
                    .post(&format!("/api/v1/tasks/{id}/claim"), &body)
                    .await?,
                "claim task",
            )
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
            let resp = crate::http::read_json(
                client
                    .post(&format!("/api/v1/tasks/{id}/complete"), &body)
                    .await?,
                "complete task",
            )
            .await?;
            Ok(serde_json::to_string_pretty(&resp)?)
        }

        // ── UCAN delegation tools ─────────────────────────────────────────
        "ucan_delegate" => {
            let kp = keypair.context("no identity found — run `gl identity new` first")?;
            let to_str = args["to"].as_str().context("missing 'to'")?;
            let resource = args["resource"].as_str().context("missing 'resource'")?;
            let action = args["action"].as_str().context("missing 'action'")?;

            // The same canonicalization `gl ucan delegate` applies, so a token
            // minted here names the repository the way import, the helper, and
            // the node all resolve it.
            let resource = crate::ucan_cmd::canonical_resource(resource);
            let resource = resource.as_str();

            // The same refusal `gl ucan delegate` applies. A push-class wildcard cannot
            // be honoured anywhere downstream — import refuses it, the helper refuses
            // it, the node refuses it — so issuing one only manufactures a token that
            // fails later with less context than this.
            if gitlawb_core::ucan::push::is_push_wildcard(resource, action) {
                anyhow::bail!(
                    "a wildcard resource cannot carry a push capability: a delegation is \
                     scoped to the repositories it names when issued, and `*` cannot say \
                     which those were. Use resource gitlawb://repos/<owner>/<repo>."
                );
            }

            let audience: gitlawb_core::did::Did = to_str
                .parse()
                .map_err(|e: gitlawb_core::Error| anyhow::anyhow!("{e}"))?;

            // The CLI defaults to `DEFAULT_DELEGATION_EXPIRY_HOURS` and has no way
            // to issue an unbounded token. An omitted field here used to mean "no
            // expiry", which for a push capability is dead on arrival: import
            // refuses it and so does the node (`chain_lifetime_is_bounded`). Same
            // default, same rule.
            let hours = match args.get("expiry_hours") {
                None | Some(Value::Null) => crate::ucan_cmd::DEFAULT_DELEGATION_EXPIRY_HOURS as i64,
                Some(v) => v
                    .as_i64()
                    .context("invalid expiry_hours: expected an integer")?,
            };
            if hours < 1 {
                anyhow::bail!("expiry_hours must be at least 1: a token that has already expired grants nothing");
            }
            anyhow::ensure!(
                hours <= crate::ucan_cmd::MAX_EXPIRY_HOURS as i64,
                "expiry_hours is out of range ({hours}): a DateTime cannot represent it"
            );
            let exp = Some(chrono::Utc::now() + chrono::Duration::hours(hours));

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
            // The same report `gl ucan verify` prints, so the two cannot disagree
            // about what "valid" means. In particular the proof chain is walked:
            // a leaf with a good signature on a broken chain used to report valid
            // here and then fail at import and at the node.
            let report = crate::ucan_cmd::VerifyReport::of(&ucan);
            Ok(serde_json::to_string_pretty(&report.to_json())?)
        }

        "ucan_import" => {
            let token = args["token"].as_str().context("missing 'token'")?;
            // `gl ucan import` with a JSON answer: one set of checks, one store, so
            // an MCP-only agent can complete the delegated-push workflow without
            // a shell and without a second copy of the rules.
            let imported = crate::ucan_cmd::import_delegation(token, dir).await?;
            Ok(serde_json::to_string_pretty(&json!({
                "owner": imported.owner,
                "repo": imported.repo,
                "root_issuer": imported.root,
                "expires": imported.expires,
                "path": imported.path.display().to_string(),
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
            let resp = crate::http::read_json(
                client
                    .get_authed(&format!("/api/v1/repos/{owner}/{name}/issues"))
                    .await?,
                "issues",
            )
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
            let resp = crate::http::read_json(
                client
                    .post(&format!("/api/v1/repos/{owner}/{name}/issues"), &body)
                    .await?,
                "create issue",
            )
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
            let resp = crate::http::read_json(
                client
                    .post(
                        &format!("/api/v1/repos/{owner}/{name}/issues/{issue_id}/comments"),
                        &body,
                    )
                    .await?,
                "comment on issue",
            )
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
    let info = crate::http::read_json(client.get("/").await?, "node info").await?;
    let did = info["did"].as_str().context("node info missing DID")?;
    Ok(did.split(':').next_back().unwrap_or(did).to_string())
}

/// Owner for the owner-gated signed reads (`repo_get`, `repo_commits`,
/// `pr_list`, `pr_view`, `pr_diff`): an explicit `owner` arg wins, then the
/// signing keypair's short DID, and only a caller with no identity falls back to
/// the node root DID. The request is signed by the keypair, so a path owner that
/// names the node instead would be aimed at a namespace the signer does not own
/// and the node would deny it.
async fn resolve_signed_read_owner(
    args: &Value,
    keypair: &Option<gitlawb_core::identity::Keypair>,
    client: &NodeClient,
) -> Result<String> {
    if let Some(o) = args.get("owner").and_then(|v| v.as_str()) {
        return Ok(o.to_string());
    }
    if let Some(kp) = keypair {
        let did = kp.did().to_string();
        return Ok(did.split(':').next_back().unwrap_or(&did).to_string());
    }
    resolve_owner(args, client).await
}

/// Resolve (owner, repo) for the webhook tools, matching the CLI's
/// `resolve_owner_repo_pair` contract: an `owner/repo` string splits first, an
/// explicit `owner` arg wins next, then the signing keypair's short DID. The
/// last resort is the node root DID via `resolve_owner`, reachable only by
/// callers that have no keypair — the unsigned `webhook_list` arm, and an
/// unsigned `webhook_delete` the same way `resolve_owner` always served it —
/// for a bare
/// repo name under a signed caller the path owner must be the caller's DID or
/// the node 403/404s the request under the wrong namespace.
async fn resolve_owner_repo(
    args: &Value,
    repo: &str,
    keypair: &Option<gitlawb_core::identity::Keypair>,
    client: &NodeClient,
) -> Result<(String, String)> {
    if let Some((o, r)) = repo.split_once('/') {
        return Ok((o.to_string(), r.to_string()));
    }
    if let Some(o) = args.get("owner").and_then(|v| v.as_str()) {
        return Ok((o.to_string(), repo.to_string()));
    }
    if let Some(kp) = keypair {
        let did = kp.did().to_string();
        return Ok((
            did.split(':').next_back().unwrap_or(&did).to_string(),
            repo.to_string(),
        ));
    }
    let owner = resolve_owner(args, client).await?;
    Ok((owner, repo.to_string()))
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

/// Message for a `did_resolve` failure. A `did:key` that fails to resolve is a
/// different situation from a DID method we have no resolver for, so saying
/// "only did:key is supported" about something that IS a did:key sends the
/// reader looking for the wrong problem.
fn did_resolve_failure_message(
    did_str: &str,
    is_did_key: bool,
    err: &gitlawb_core::Error,
) -> String {
    if is_did_key {
        format!("cannot resolve '{did_str}': {err}")
    } else {
        format!("cannot resolve '{did_str}' locally — only did:key is supported without a resolver")
    }
}

#[cfg(test)]
mod did_resolve_message_tests {
    use super::did_resolve_failure_message;
    use gitlawb_core::did::Did;
    use std::str::FromStr;

    /// A well-formed did:key encoding the compressed identity point, which is
    /// small-order. Derived from the point bytes so the fixture states WHY it
    /// is weak rather than pinning an opaque string (the literal also trips
    /// secret scanners, which cannot tell a public DID from an API key).
    fn weak_did_key() -> String {
        let mut weak = [0u8; 32];
        weak[0] = 1; // compressed identity point
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&weak).expect("decompresses");
        Did::from_verifying_key(&vk).to_string()
    }

    #[test]
    fn test_did_key_failure_does_not_claim_did_key_is_unsupported() {
        // Drive the real parse and the real resolution error rather than
        // hardcoding the discriminator, so flipping it at the call site fails.
        let did_str = &weak_did_key();
        let did = Did::from_str(did_str).expect("well-formed did:key");
        let err = did
            .to_verifying_key()
            .expect_err("a small-order did:key must not resolve");

        let msg = did_resolve_failure_message(did_str, did.is_did_key(), &err);
        assert!(
            !msg.contains("only did:key is supported"),
            "a did:key must not be told did:key is unsupported: {msg}"
        );
        assert!(
            msg.contains("small-order"),
            "the real cause must survive into the message: {msg}"
        );
    }

    #[test]
    fn test_non_key_method_keeps_the_no_resolver_message() {
        let did_str = "did:web:example.com";
        let did = Did::from_str(did_str).expect("did:web parses");
        let err = did
            .to_verifying_key()
            .expect_err("did:web has no local resolver");

        let msg = did_resolve_failure_message(did_str, did.is_did_key(), &err);
        assert!(
            msg.contains("only did:key is supported"),
            "an unresolvable method keeps its existing explanation: {msg}"
        );
    }
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
        assert!(names.contains(&"ucan_import"));
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
            .with_body(r#"{"tasks":[{"id":"t1","kind":"test","status":"pending"}],"has_more":false,"incomplete":false,"next_cursor":null}"#)
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
        assert_eq!(parsed["complete"], json!(true));
    }

    #[tokio::test]
    async fn test_task_list_via_mcp_uses_loaded_identity() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"tasks":[{"id":"t1"}],"has_more":false,"incomplete":false,"next_cursor":null}"#,
            )
            .create_async()
            .await;

        let result = call_tool("task_list", json!({}), &server.url(), Some(dir.path()))
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["tasks"][0]["id"], "t1");
        assert_eq!(parsed["complete"], json!(true));
    }

    /// #327 review: MCP `task_list` issued one request and exposed no
    /// continuation, so a limit above the node's 200-row page cap returned a
    /// silently truncated result the model had no way to detect. It now
    /// follows cursors and, when a guard stops it, says so in the payload.
    #[tokio::test]
    async fn test_task_list_via_mcp_follows_cursors() {
        // The env-mutating suites serialize on test_env's lock; a resolver
        // reader that skips it can observe a half-set GITLAWB_KEY mid-race.
        // Taking it here (with the key absent) keeps this read deterministic.
        let _key_guard = crate::identity::test_env::set_key(None::<&str>);
        let mut server = mockito::Server::new_async().await;
        let first = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"tasks":[{"id":"t1"}],"has_more":true,"incomplete":false,"next_cursor":"c1"}"#,
            )
            .create_async()
            .await;
        let second = server
            .mock("GET", mockito::Matcher::Regex(r"cursor=c1".to_string()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t2"}],"has_more":false,"next_cursor":null}"#)
            .create_async()
            .await;

        let result = call_tool("task_list", json!({"limit": 500}), &server.url(), None)
            .await
            .unwrap();
        first.assert_async().await;
        second.assert_async().await;
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["count"], 2);
        assert_eq!(parsed["tasks"][1]["id"], "t2");
        assert_eq!(parsed["complete"], json!(true));
        assert!(parsed.get("warning").is_none());
    }

    /// A truncated MCP result must carry an explicit warning and a resume
    /// cursor, so the model cannot read it as the whole answer.
    #[tokio::test]
    async fn test_task_list_via_mcp_flags_incomplete_results() {
        let _key_guard = crate::identity::test_env::set_key(None::<&str>);

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"tasks":[{"id":"t1"}],"has_more":true,"incomplete":true,"next_cursor":"resume-me"}"#,
            )
            .create_async()
            .await;

        let result = call_tool("task_list", json!({"limit": 1}), &server.url(), None)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["complete"], json!(false));
        assert_eq!(parsed["incomplete"], json!(true));
        assert_eq!(parsed["next_cursor"], "resume-me");
        assert!(
            parsed["warning"]
                .as_str()
                .unwrap()
                .contains("result incomplete"),
            "{parsed}"
        );
    }

    /// A legacy response without pagination metadata is reported as incomplete via MCP.
    #[tokio::test]
    async fn test_task_list_via_mcp_legacy_response_is_incomplete() {
        let _key_guard = crate::identity::test_env::set_key(None::<&str>);
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[{"id":"t1"}],"count":1}"#)
            .create_async()
            .await;

        let result = call_tool("task_list", json!({"limit": 50}), &server.url(), None)
            .await
            .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["complete"], json!(false));
        assert_eq!(parsed["incomplete"], json!(true));
        assert!(parsed["next_cursor"].is_null());
        assert!(
            parsed["warning"]
                .as_str()
                .unwrap()
                .contains("node does not support pagination metadata"),
            "{parsed}"
        );
    }

    /// A legacy response with limit > 200 stops after 1 page and does not claim completeness via MCP.
    #[tokio::test]
    async fn test_task_list_via_mcp_legacy_limit_above_page_cap() {
        let _key_guard = crate::identity::test_env::set_key(None::<&str>);
        let mut server = mockito::Server::new_async().await;
        let ids: Vec<String> = (0..200).map(|i| format!("t{i}")).collect();
        let tasks_json: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
        let body = json!({ "tasks": tasks_json, "count": 200 }).to_string();

        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/api/v1/tasks\?limit=200$".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(1)
            .create_async()
            .await;

        let result = call_tool("task_list", json!({"limit": 500}), &server.url(), None)
            .await
            .unwrap();
        m.assert_async().await;
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["count"], 200);
        assert_eq!(parsed["complete"], json!(false));
        assert_eq!(parsed["incomplete"], json!(true));
        assert!(parsed["next_cursor"].is_null());
        assert!(
            parsed["warning"]
                .as_str()
                .unwrap()
                .contains("node does not support pagination metadata"),
            "{parsed}"
        );
    }

    /// A cursor the model passes back must reach the node.
    #[tokio::test]
    async fn test_task_list_via_mcp_forwards_cursor_argument() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"cursor=given-cursor".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[],"has_more":false,"incomplete":false,"next_cursor":null}"#)
            .expect(1)
            .create_async()
            .await;

        call_tool(
            "task_list",
            json!({"cursor": "given-cursor"}),
            &server.url(),
            None,
        )
        .await
        .unwrap();
        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_task_list_via_mcp_returns_http_errors() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"failed"}"#)
            .create_async()
            .await;

        let err = call_tool("task_list", json!({}), &server.url(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("500"));
    }

    /// Malformed server responses fail visibly in MCP.
    #[tokio::test]
    async fn test_task_list_via_mcp_malformed_response_errors() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":"not-an-array"}"#)
            .create_async()
            .await;

        let err = call_tool("task_list", json!({}), &server.url(), None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("malformed") || err.to_string().contains("invalid JSON"),
            "{err}"
        );
    }

    /// #327 review: a model that sends `limit: 0` used to get an empty list
    /// marked complete, which reads as "this node has no tasks". The shared
    /// helper rejects it, so the model sees an invalid argument instead.
    #[tokio::test]
    async fn test_task_list_via_mcp_rejects_non_positive_limit() {
        let _key_guard = crate::identity::test_env::set_key(None::<&str>);
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[],"has_more":false,"incomplete":false,"next_cursor":null}"#)
            .expect(0)
            .create_async()
            .await;

        let err = call_tool("task_list", json!({"limit": 0}), &server.url(), None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("limit must be a positive"),
            "{err}"
        );
        m.assert_async().await;
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

    /// The same refusal the CLI applies. `test_ucan_delegate_via_mcp` uses a named
    /// resource, so it could never catch the MCP arm issuing a wildcard the CLI
    /// refuses.
    #[tokio::test]
    async fn test_ucan_delegate_via_mcp_refuses_a_push_class_wildcard() {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let audience = gitlawb_core::identity::Keypair::generate();

        for action in ["git/push", "*", "repo/admin"] {
            let err = call_tool(
                "ucan_delegate",
                json!({
                    "to": audience.did().to_string(),
                    "resource": "*",
                    "action": action,
                    "expiry_hours": 24,
                }),
                "http://localhost",
                Some(dir.path()),
            )
            .await
            .expect_err("MCP must refuse a push-class wildcard like the CLI does");
            assert!(err.to_string().contains("wildcard"), "{action}: {err}");
        }
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
        assert_eq!(parsed["chain_valid"], true);
        assert_eq!(parsed["root_issuer"], kp.did().to_string());
    }

    /// The round-ten P2: `ucan_verify` answered from the leaf alone. A leaf with a
    /// good signature sitting on a proof that never named its issuer reported
    /// `valid: true` here, and was then refused by import and by the node.
    #[tokio::test]
    async fn test_ucan_verify_via_mcp_walks_the_proof_chain() {
        let alice = gitlawb_core::identity::Keypair::generate();
        let bob = gitlawb_core::identity::Keypair::generate();
        let eve = gitlawb_core::identity::Keypair::generate();
        let node = gitlawb_core::identity::Keypair::generate();
        let cap = || {
            vec![gitlawb_core::ucan::Capability::new(
                "gitlawb://repos/alice/r",
                "git/push",
            )]
        };
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);

        // Alice grants Bob; Eve presents Alice's grant as if it were hers. Eve's
        // own signature is fine — the break is in the chain.
        let root = gitlawb_core::ucan::Ucan::issue(&alice, bob.did(), cap(), Some(hour)).unwrap();
        let forged =
            gitlawb_core::ucan::Ucan::delegate(&eve, node.did(), cap(), Some(hour), &root).unwrap();
        assert!(
            forged.verify_signature().is_ok(),
            "fixture: the leaf signature is valid"
        );

        let result = call_tool(
            "ucan_verify",
            json!({"token": forged.encode().unwrap()}),
            "http://localhost",
            None,
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["signature_valid"], true);
        assert_eq!(parsed["expired"], false);
        assert_eq!(parsed["chain_valid"], false);
        assert_eq!(
            parsed["valid"], false,
            "a broken proof chain must not report valid: {parsed}"
        );
        assert!(
            parsed["chain_error"]
                .as_str()
                .unwrap_or_default()
                .contains("proof chain broken"),
            "the reason must be reported: {parsed}"
        );
        assert!(parsed["root_issuer"].is_null());
    }

    /// The workflow an MCP-only agent could not finish: it could be issued a
    /// delegation and verify it, but not store it where `git-remote-gitlawb`
    /// looks. `ucan_import` is `gl ucan import` behind a tool — same checks, same
    /// file — so a token the CLI would store lands in the same place, and one the
    /// CLI would refuse is refused with the same reason.
    #[tokio::test]
    async fn test_ucan_import_via_mcp_stores_where_the_helper_looks() {
        let dir = tempfile::TempDir::new().unwrap();
        let me = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            me.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let owner = gitlawb_core::identity::Keypair::generate();
        let owner_did = owner.did().to_string();
        let hour = chrono::Utc::now() + chrono::Duration::hours(1);
        let token = gitlawb_core::ucan::Ucan::issue(
            &owner,
            me.did(),
            vec![gitlawb_core::ucan::Capability::new(
                format!("gitlawb://repos/{owner_did}/ci-repo"),
                "git/push",
            )],
            Some(hour),
        )
        .unwrap()
        .encode()
        .unwrap();

        let result = call_tool(
            "ucan_import",
            json!({"token": token}),
            "http://localhost",
            Some(dir.path()),
        )
        .await
        .expect("a delegation addressed to this identity must import");
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["owner"], owner_did);
        assert_eq!(parsed["repo"], "ci-repo");
        assert_eq!(parsed["root_issuer"], owner_did);
        assert_eq!(parsed["expires"], hour.timestamp());

        let stored = crate::ucan_cmd::delegation_path(dir.path(), &owner_did, "ci-repo");
        assert_eq!(parsed["path"], stored.display().to_string());
        assert_eq!(
            std::fs::read_to_string(&stored).unwrap(),
            token,
            "the token must be stored byte-for-byte where the helper reads it"
        );

        // Same refusals as the CLI: a token addressed to someone else is unusable
        // here however well-formed it is.
        let stranger = gitlawb_core::identity::Keypair::generate();
        let misaddressed = gitlawb_core::ucan::Ucan::issue(
            &owner,
            stranger.did(),
            vec![gitlawb_core::ucan::Capability::new(
                format!("gitlawb://repos/{owner_did}/ci-repo"),
                "git/push",
            )],
            Some(hour),
        )
        .unwrap()
        .encode()
        .unwrap();
        let err = call_tool(
            "ucan_import",
            json!({"token": misaddressed}),
            "http://localhost",
            Some(dir.path()),
        )
        .await
        .expect_err("a token addressed to another identity must be refused");
        assert!(err.to_string().contains("addressed to"), "{err}");
    }

    /// The round-ten P2: an omitted `expiry_hours` issued an unbounded token, which
    /// import and the node both refuse for push. The default is now the CLI's.
    #[tokio::test]
    async fn test_ucan_delegate_via_mcp_defaults_to_the_cli_expiry() {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let audience = gitlawb_core::identity::Keypair::generate();

        let before = chrono::Utc::now();
        let result = call_tool(
            "ucan_delegate",
            json!({
                "to": audience.did().to_string(),
                "resource": "gitlawb://repos/test/repo",
                "action": "git/push",
            }),
            "http://localhost",
            Some(dir.path()),
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();

        let expires = parsed["expires"]
            .as_i64()
            .expect("an omitted expiry_hours must still produce an expiring token");
        let expected = (before
            + chrono::Duration::hours(crate::ucan_cmd::DEFAULT_DELEGATION_EXPIRY_HOURS as i64))
        .timestamp();
        assert!(
            (expires - expected).abs() <= 60,
            "expiry must default to the CLI's {} hours, got {expires} vs {expected}",
            crate::ucan_cmd::DEFAULT_DELEGATION_EXPIRY_HOURS
        );
        let token = gitlawb_core::ucan::Ucan::decode(parsed["token"].as_str().unwrap()).unwrap();
        assert!(
            token.chain_lifetime_is_bounded(),
            "the token must satisfy the rule import and the node apply"
        );

        // A token that has already expired grants nothing, so the request is a
        // mistake to report, not a token to mint.
        for bad in [json!(0), json!(-5)] {
            let err = call_tool(
                "ucan_delegate",
                json!({
                    "to": audience.did().to_string(),
                    "resource": "gitlawb://repos/test/repo",
                    "action": "git/push",
                    "expiry_hours": bad,
                }),
                "http://localhost",
                Some(dir.path()),
            )
            .await
            .expect_err("a non-positive expiry must be refused");
            assert!(err.to_string().contains("expiry_hours"), "{bad}: {err}");
        }
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

    #[tokio::test]
    async fn test_webhook_list_via_mcp_signs_the_request() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        // /hooks is owner-gated, so the MCP webhook_list tool must send a SIGNED
        // request (get_signed). Requiring the header catches a regression to get().
        // Passing `owner` in args makes resolve_owner skip the node-root lookup.
        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"webhooks":[],"count":0}"#)
            .create_async()
            .await;

        let result = call_tool(
            "webhook_list",
            json!({"owner": "alice", "repo": "myrepo"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert!(result.contains("webhooks"), "got: {result}");
    }

    /// Drive one owner-gated MCP read with an identity and a mock that requires
    /// the signature headers (#115). `path` is the exact request path; a
    /// regression of that arm to an unsigned `get` leaves the mock unmatched, so
    /// the call errors on mockito's 501.
    async fn assert_mcp_read_is_signed(tool: &str, args: Value, path: &str, body: &str) -> String {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let m = server
            .mock("GET", path)
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let out = call_tool(tool, args, &server.url(), Some(dir.path()))
            .await
            .unwrap_or_else(|e| panic!("{tool} must send a signed request: {e:#}"));
        m.assert_async().await;
        out
    }

    #[tokio::test]
    async fn test_repo_get_via_mcp_signs_the_request() {
        let out = assert_mcp_read_is_signed(
            "repo_get",
            json!({"name": "myrepo", "owner": "alice"}),
            "/api/v1/repos/alice/myrepo",
            r#"{"name":"myrepo"}"#,
        )
        .await;
        assert!(out.contains("myrepo"), "got: {out}");
    }

    #[tokio::test]
    async fn test_repo_commits_via_mcp_signs_the_request() {
        assert_mcp_read_is_signed(
            "repo_commits",
            json!({"name": "myrepo", "owner": "alice"}),
            "/api/v1/repos/alice/myrepo/commits",
            r#"{"commits":[]}"#,
        )
        .await;
    }

    #[tokio::test]
    async fn test_pr_list_via_mcp_signs_the_request() {
        assert_mcp_read_is_signed(
            "pr_list",
            json!({"repo": "myrepo", "owner": "alice"}),
            "/api/v1/repos/alice/myrepo/pulls",
            r#"{"pulls":[]}"#,
        )
        .await;
    }

    #[tokio::test]
    async fn test_pr_diff_via_mcp_signs_the_request() {
        let out = assert_mcp_read_is_signed(
            "pr_diff",
            json!({"repo": "myrepo", "owner": "alice", "number": 1}),
            "/api/v1/repos/alice/myrepo/pulls/1/diff",
            r#"{"diff":"diff --git a/x b/x"}"#,
        )
        .await;
        assert!(out.contains("diff --git"), "got: {out}");
    }

    /// pr_view issues two gated GETs; each must be signed on its own.
    #[tokio::test]
    async fn test_pr_view_via_mcp_signs_both_requests() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        let pr = server
            .mock("GET", "/api/v1/repos/alice/myrepo/pulls/1")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"number":1}"#)
            .expect(1)
            .create_async()
            .await;
        let reviews = server
            .mock("GET", "/api/v1/repos/alice/myrepo/pulls/1/reviews")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"reviews":[]}"#)
            .expect(1)
            .create_async()
            .await;
        call_tool(
            "pr_view",
            json!({"repo": "myrepo", "owner": "alice", "number": 1}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .expect("pr_view must send signed requests");
        pr.assert_async().await;
        reviews.assert_async().await;
    }

    /// With `owner` omitted and an identity present, the path owner must be the
    /// signing keypair's short DID, not the node root DID: a signed request whose
    /// keyid differs from the path owner is denied on a private repo. Every
    /// changed read tool is driven; the node-root mock returns a different DID,
    /// so a fallback to it leaves the keypair-owner mock unmatched.
    #[tokio::test]
    async fn test_gated_mcp_reads_default_owner_is_keypair_not_node_did() {
        let cases: [(&str, Value, &str); 5] = [
            ("repo_get", json!({"name": "myrepo"}), ""),
            ("repo_commits", json!({"name": "myrepo"}), "/commits"),
            ("pr_list", json!({"repo": "myrepo"}), "/pulls"),
            (
                "pr_view",
                json!({"repo": "myrepo", "number": 1}),
                "/pulls/1",
            ),
            (
                "pr_diff",
                json!({"repo": "myrepo", "number": 1}),
                "/pulls/1/diff",
            ),
        ];
        for (tool, args, suffix) in cases {
            let mut server = mockito::Server::new_async().await;
            let dir = tempfile::TempDir::new().unwrap();
            let kp = gitlawb_core::identity::Keypair::generate();
            std::fs::write(
                dir.path().join("identity.pem"),
                kp.to_pem().unwrap().as_bytes(),
            )
            .unwrap();
            let did = kp.did().to_string();
            let short = did.split(':').next_back().unwrap_or(&did).to_string();

            let _root = server
                .mock("GET", "/")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"did":"did:key:z6MkNodeRootDid"}"#)
                .create_async()
                .await;
            let m = server
                .mock(
                    "GET",
                    format!("/api/v1/repos/{short}/myrepo{suffix}").as_str(),
                )
                .match_header("signature", mockito::Matcher::Any)
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"diff":"d","reviews":[]}"#)
                .expect(1)
                .create_async()
                .await;
            // pr_view's second GET (reviews) lives under the same owner.
            let _reviews = server
                .mock(
                    "GET",
                    format!("/api/v1/repos/{short}/myrepo/pulls/1/reviews").as_str(),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"reviews":[]}"#)
                .create_async()
                .await;

            call_tool(tool, args, &server.url(), Some(dir.path()))
                .await
                .unwrap_or_else(|e| panic!("{tool} must default owner to the keypair: {e:#}"));
            m.assert_async().await;
        }
    }

    /// An explicit `owner` still wins over the keypair default.
    #[tokio::test]
    async fn test_gated_mcp_read_explicit_owner_beats_keypair() {
        assert_mcp_read_is_signed(
            "pr_list",
            json!({"repo": "myrepo", "owner": "bob"}),
            "/api/v1/repos/bob/myrepo/pulls",
            r#"{"pulls":[]}"#,
        )
        .await;
    }

    /// The MCP tool deliberately diverges from the CLI here: `gl webhook list`
    /// requires a local identity and fails client-side without one, while the MCP
    /// tool issues the request unsigned and lets the node answer. Pin that path,
    /// since the divergence is only defensible if the denial actually reaches the
    /// caller as an error rather than as an empty webhook list.
    #[tokio::test]
    async fn test_webhook_list_unsigned_without_identity_surfaces_the_node_denial() {
        let mut server = mockito::Server::new_async().await;

        // No identity dir, and an explicit `owner`, so the tool cannot sign and
        // does not fall back to the keypair for the owner segment. The node
        // owner-gates /hooks and answers a headerless caller with 401.
        let m = server
            .mock("GET", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .match_header("signature", mockito::Matcher::Missing)
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"signature required"}"#)
            .expect(1)
            .create_async()
            .await;

        // Point at an EMPTY dir rather than passing `None`: `None` falls back to
        // the ambient ~/.gitlawb/identity.pem, which exists on a dev box and not
        // on CI, so the request would be signed here and unsigned there.
        let empty = tempfile::TempDir::new().unwrap();
        let err = call_tool(
            "webhook_list",
            json!({"owner": "alice", "repo": "myrepo"}),
            &server.url(),
            Some(empty.path()),
        )
        .await
        .expect_err("a 401 must surface as an error, not an empty webhook list");

        let err = err.to_string();
        assert!(err.contains("401"), "must name the status: {err}");
        assert!(
            err.contains("signature required"),
            "must carry the node's own reason: {err}"
        );
        // The request must actually have been issued unsigned; failing
        // client-side before contacting the node would leave this unmatched.
        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_webhook_list_default_owner_is_keypair_not_node_did() {
        // When `owner` is omitted, the owner segment must come from the signing
        // keypair's short DID, NOT the node root DID. The "/" mock returns a
        // different DID; the /hooks mock only matches the keypair's short DID,
        // so a regression to the node DID would leave the request unmatched.
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:z6MkNodeRootDid"}"#)
            .create_async()
            .await;

        let did = kp.did().to_string();
        let short = did.split(':').next_back().unwrap_or(&did).to_string();

        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(r"/api/v1/repos/{short}/myrepo/hooks$")),
            )
            .match_header("signature", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"webhooks":[],"count":0}"#)
            .expect(1)
            .create_async()
            .await;

        let result = call_tool(
            "webhook_list",
            json!({"repo": "myrepo"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert!(result.contains("webhooks"), "got: {result}");
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_webhook_list_explicit_owner_overrides_keypair() {
        // An explicit `owner` arg must win over the keypair default and the node
        // DID. The path must use the supplied owner; "/" must not even be hit.
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/repos/someoneelse/myrepo/hooks$".to_string()),
            )
            .match_header("signature", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"webhooks":[],"count":0}"#)
            .expect(1)
            .create_async()
            .await;

        let result = call_tool(
            "webhook_list",
            json!({"repo": "myrepo", "owner": "someoneelse"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .unwrap();
        assert!(result.contains("webhooks"), "got: {result}");
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_webhook_list_non_success_status_errors() {
        // A 403 (or any non-2xx) JSON error body for a missing identity, wrong
        // owner, or private/deleted repo must fail the tool call, NOT be returned
        // as a successful result. Mirrors the `gl webhook list` status check.
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("GET", mockito::Matcher::Regex(r"/hooks$".to_string()))
            .match_header("signature", mockito::Matcher::Any)
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"only the repo owner can perform this action"}"#)
            .create_async()
            .await;

        let err = call_tool(
            "webhook_list",
            json!({"owner": "alice", "repo": "myrepo"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .expect_err("non-2xx must error, not return the error body as success");
        let msg = err.to_string();
        assert!(msg.contains("webhook_list failed (403"), "got: {msg}");
        assert!(
            msg.contains("only the repo owner"),
            "must surface the node message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_webhook_list_without_keypair_surfaces_node_denial() {
        // No identity loaded and no explicit owner → the tool falls back to the
        // node DID for the path and still issues the GET unsigned, so the node
        // itself answers the denial (list_webhooks 401s a headerless caller)
        // rather than the client inventing a failure before contact.
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap(); // empty: no identity.pem
        let _root = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:z6MkNodeOperator"}"#)
            .create_async()
            .await;
        let _hooks = server
            .mock("GET", "/api/v1/repos/z6MkNodeOperator/myrepo/hooks")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"signature required"}"#)
            .create_async()
            .await;

        let err = call_tool(
            "webhook_list",
            json!({"repo": "myrepo"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .expect_err("unsigned list must surface the node denial");
        let msg = err.to_string();
        assert!(
            msg.contains("401") || msg.contains("signature required"),
            "got: {msg}"
        );
        _hooks.assert_async().await;
    }

    #[tokio::test]
    async fn test_task_list_invalid_limit_rejected() {
        let server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let err = call_tool(
            "task_list",
            json!({"limit": "50"}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .expect_err("string limit must be rejected");
        assert!(
            err.to_string()
                .contains("invalid limit: expected an integer"),
            "got: {err}"
        );

        let err_float = call_tool(
            "task_list",
            json!({"limit": 50.5}),
            &server.url(),
            Some(dir.path()),
        )
        .await
        .expect_err("float limit must be rejected");
        assert!(
            err_float
                .to_string()
                .contains("invalid limit: expected an integer"),
            "got: {err_float}"
        );
    }

    #[tokio::test]
    async fn test_task_list_invalid_cursor_rejected() {
        let server = mockito::Server::new_async().await;
        for invalid in [json!(123), json!({}), json!([]), json!(true)] {
            let err = call_tool("task_list", json!({"cursor": invalid}), &server.url(), None)
                .await
                .expect_err("non-string cursor must be rejected");
            assert!(
                err.to_string()
                    .contains("invalid cursor: expected a string"),
                "for {invalid}: got {err}"
            );
        }
    }

    #[tokio::test]
    async fn test_task_list_null_or_absent_cursor_accepted() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tasks":[],"has_more":false,"incomplete":false,"next_cursor":null}"#)
            .expect(2)
            .create_async()
            .await;

        call_tool("task_list", json!({}), &server.url(), None)
            .await
            .unwrap();

        call_tool("task_list", json!({"cursor": null}), &server.url(), None)
            .await
            .unwrap();
    }

    #[test]
    fn test_tool_count_matches_the_shipped_list() {
        let tools = tool_definitions();
        let count = tools.as_array().unwrap().len();
        // 41 with `ucan_import`. Bump this when a tool is added or removed; the
        // point is that no tool is added without someone noticing.
        assert_eq!(count, 41, "expected 41 tools, got {count}");
    }
}

#[cfg(test)]
mod ucan_show_tests {
    use super::*;

    /// The MCP tool and `gl ucan show` answer the same question and must answer it
    /// in the same shape — decoded fields, not the file. Returning the file verbatim
    /// also handed back the bootstrap token, which an MCP response carries much
    /// further than a terminal does.
    #[tokio::test]
    async fn ucan_show_returns_decoded_fields_and_withholds_the_token() {
        let dir = tempfile::TempDir::new().unwrap();
        let issuer = gitlawb_core::identity::Keypair::generate();
        let audience = gitlawb_core::identity::Keypair::generate();
        let token = gitlawb_core::ucan::Ucan::issue(
            &issuer,
            audience.did(),
            vec![gitlawb_core::ucan::Capability::new(
                "gitlawb://repos/z6MkAbc/myrepo",
                gitlawb_core::ucan::caps::GIT_PUSH,
            )],
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .unwrap()
        .encode()
        .unwrap();

        // The envelope shape every writer produces.
        std::fs::write(
            dir.path().join("ucan.json"),
            serde_json::to_string_pretty(&json!({
                "ucan": token,
                "node": "https://node.gitlawb.com",
                "did": issuer.did().to_string(),
                "saved_at": "2026-08-18T00:00:00Z",
            }))
            .unwrap(),
        )
        .unwrap();

        let out = call_tool("ucan_show", json!({}), "http://localhost", Some(dir.path()))
            .await
            .expect("ucan_show must read the envelope every writer produces");
        let v: serde_json::Value = serde_json::from_str(&out).expect("must be JSON");

        assert_eq!(v["issuer"], issuer.did().to_string());
        assert_eq!(v["audience"], audience.did().to_string());
        assert_eq!(v["capabilities"][0]["can"], "git/push");
        assert_eq!(v["expired"], false);
        assert_eq!(v["signature_valid"], true);

        // NOT `!out.contains(&token)`: the token is itself JSON, so embedding it in
        // a pretty-printed response escapes every quote and that assertion passes
        // whether or not the token leaked. The signature is a bare base64 string that
        // survives escaping unchanged, so it is the substring that actually proves
        // absence.
        let sig = serde_json::from_str::<serde_json::Value>(&token).unwrap()["s"]
            .as_str()
            .expect("a UCAN carries its signature in `s`")
            .to_string();
        assert!(!sig.is_empty());
        assert!(
            !out.contains(&sig),
            "the bootstrap token must not be returned to an MCP caller"
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&out)
                .unwrap()
                .get("ucan")
                .is_none(),
            "no field may carry the token itself"
        );
    }

    /// An unregistered agent gets a usable message, not a decode error.
    #[tokio::test]
    async fn ucan_show_reports_no_saved_ucan() {
        let dir = tempfile::TempDir::new().unwrap();
        let out = call_tool("ucan_show", json!({}), "http://localhost", Some(dir.path()))
            .await
            .unwrap();
        assert!(out.contains("No UCAN saved"), "got: {out}");
    }

    // ── Gated read arms surface node denials, not fabricated results (#123) ──

    #[tokio::test]
    async fn repo_get_surfaces_denial_not_fabricated_repo() {
        // The node returns the opaque 404 for a private repo the caller cannot read.
        // The tool must Err surfacing it, NOT Ok with the error body serialized as the repo.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;

        let result = call_tool(
            "repo_get",
            json!({"owner": "alice", "name": "secret"}),
            &server.url(),
            None,
        )
        .await;

        let err = result
            .expect_err("repo_get must Err on a 404, not fabricate a repo")
            .to_string();
        assert!(err.contains("404"), "err={err}");
        assert!(err.contains("not found"), "err={err}");
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn repo_get_returns_repo_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/myrepo")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"name":"myrepo","owner_did":"did:gitlawb:alice"}"#)
            .create_async()
            .await;
        let result = call_tool(
            "repo_get",
            json!({"owner": "alice", "name": "myrepo"}),
            &server.url(),
            None,
        )
        .await
        .unwrap();
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["name"], "myrepo");
    }

    #[tokio::test]
    async fn repo_commits_surfaces_denial_not_empty_list() {
        // Before the fix a 404 rendered as "no commits" (empty). Now it must Err.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret/commits")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = call_tool(
            "repo_commits",
            json!({"owner": "alice", "name": "secret"}),
            &server.url(),
            None,
        )
        .await;
        assert!(result.is_err(), "repo_commits must Err on 404");
        assert!(result.unwrap_err().to_string().contains("not found"));
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn repo_tree_surfaces_denial_not_fabricated_tree() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret/tree/")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = call_tool(
            "repo_tree",
            json!({"owner": "alice", "name": "secret"}),
            &server.url(),
            None,
        )
        .await;
        assert!(result.is_err(), "repo_tree must Err on 404");
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn pr_list_surfaces_denial_not_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret/pulls")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = call_tool(
            "pr_list",
            json!({"owner": "alice", "repo": "secret"}),
            &server.url(),
            None,
        )
        .await;
        assert!(result.is_err(), "pr_list must Err on 404");
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn webhook_list_surfaces_denial_not_hook_targets() {
        // Client half of #94: a non-owner hooks read must surface the denial,
        // never render the webhook target URLs as a result.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret/hooks")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = call_tool(
            "webhook_list",
            json!({"owner": "alice", "repo": "secret"}),
            &server.url(),
            None,
        )
        .await;
        assert!(result.is_err(), "webhook_list must Err on 404");
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn issue_list_surfaces_denial_not_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret/issues")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = call_tool(
            "issue_list",
            json!({"repo": "alice/secret"}),
            &server.url(),
            None,
        )
        .await;
        assert!(result.is_err(), "issue_list must Err on 404");
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn pr_view_surfaces_denial_not_stub() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret/pulls/1")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = call_tool(
            "pr_view",
            json!({"owner": "alice", "repo": "secret", "number": 1}),
            &server.url(),
            None,
        )
        .await;
        assert!(result.is_err(), "pr_view must Err on 404");
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn pr_diff_surfaces_denial_not_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/repos/alice/secret/pulls/1/diff")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repository 'alice/secret' not found"}"#)
            .expect(1)
            .create_async()
            .await;
        let result = call_tool(
            "pr_diff",
            json!({"owner": "alice", "repo": "secret", "number": 1}),
            &server.url(),
            None,
        )
        .await;
        assert!(result.is_err(), "pr_diff must Err on 404");
        // Prove the gated route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy is_err() vacuously.
        _m.assert_async().await;
    }

    // ── Across the MCP twin: every tool that renders a node response must
    //    surface a denial as an Err, not print the 4xx/5xx body as a success. ──

    /// Drive one MCP tool against a node returning a 404 and assert it Errs
    /// (surfacing the denial) rather than returning the error body as a result.
    /// `.expect(1)` proves the tool hit the intended endpoint, so a wrong-path
    /// request (mockito's 501) can't satisfy the Err assertion vacuously.
    async fn assert_tool_surfaces_denial(
        tool: &str,
        method: &str,
        path: mockito::Matcher,
        args: Value,
        with_identity: bool,
    ) {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        if with_identity {
            let kp = gitlawb_core::identity::Keypair::generate();
            std::fs::write(
                dir.path().join("identity.pem"),
                kp.to_pem().unwrap().as_bytes(),
            )
            .unwrap();
        }
        let _m = server
            .mock(method, path)
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;
        let dir_opt = with_identity.then(|| dir.path());
        let err = call_tool(tool, args, &server.url(), dir_opt)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("404"),
            "{tool} must surface the 404 denial as an Err, got: {err}"
        );
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn node_info_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "node_info",
            "GET",
            mockito::Matcher::Regex(r"^/$".to_string()),
            json!({}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn node_health_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "node_health",
            "GET",
            mockito::Matcher::Regex(r"^/health$".to_string()),
            json!({}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn repo_create_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "repo_create",
            "POST",
            mockito::Matcher::Regex(r"^/api/v1/repos$".to_string()),
            json!({"name": "r"}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn repo_list_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "repo_list",
            "GET",
            mockito::Matcher::Regex(r"^/api/v1/repos$".to_string()),
            json!({}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn repo_list_federated_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "repo_list_federated",
            "GET",
            mockito::Matcher::Regex(r"^/api/v1/repos/federated$".to_string()),
            json!({}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn agent_register_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "agent_register",
            "POST",
            mockito::Matcher::Regex(r"^/api/register$".to_string()),
            json!({}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn pr_create_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "pr_create",
            "POST",
            mockito::Matcher::Regex(r"/pulls$".to_string()),
            json!({"owner": "alice", "repo": "r", "head": "h", "title": "t"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn pr_review_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "pr_review",
            "POST",
            mockito::Matcher::Regex(r"/pulls/1/reviews$".to_string()),
            json!({"owner": "alice", "repo": "r", "number": 1, "status": "approve"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn pr_merge_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "pr_merge",
            "POST",
            mockito::Matcher::Regex(r"/pulls/1/merge$".to_string()),
            json!({"owner": "alice", "repo": "r", "number": 1}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn webhook_create_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "webhook_create",
            "POST",
            mockito::Matcher::Regex(r"/hooks$".to_string()),
            json!({"owner": "alice", "repo": "r", "url": "http://example.com"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn webhook_delete_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "webhook_delete",
            "DELETE",
            mockito::Matcher::Regex(r"/hooks/h1$".to_string()),
            json!({"owner": "alice", "repo": "r", "id": "h1"}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn bounty_show_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "bounty_show",
            "GET",
            mockito::Matcher::Regex(r"/api/v1/bounties/b1$".to_string()),
            json!({"id": "b1"}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn bounty_create_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "bounty_create",
            "POST",
            mockito::Matcher::Regex(r"/bounties$".to_string()),
            json!({"repo": "a/b", "title": "t", "amount": 100}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn bounty_claim_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "bounty_claim",
            "POST",
            mockito::Matcher::Regex(r"/api/v1/bounties/b1/claim$".to_string()),
            json!({"id": "b1"}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn bounty_submit_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "bounty_submit",
            "POST",
            mockito::Matcher::Regex(r"/api/v1/bounties/b1/submit$".to_string()),
            json!({"id": "b1", "pr_id": "p1"}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn bounty_stats_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "bounty_stats",
            "GET",
            mockito::Matcher::Regex(r"^/api/v1/bounties/stats$".to_string()),
            json!({}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn task_list_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "task_list",
            "GET",
            mockito::Matcher::Regex(r"/api/v1/tasks\?".to_string()),
            json!({}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn task_create_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "task_create",
            "POST",
            mockito::Matcher::Regex(r"^/api/v1/tasks$".to_string()),
            json!({"kind": "code-review"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn task_claim_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "task_claim",
            "POST",
            mockito::Matcher::Regex(r"/api/v1/tasks/t1/claim$".to_string()),
            json!({"id": "t1"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn task_complete_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "task_complete",
            "POST",
            mockito::Matcher::Regex(r"/api/v1/tasks/t1/complete$".to_string()),
            json!({"id": "t1"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn issue_create_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "issue_create",
            "POST",
            mockito::Matcher::Regex(r"/issues$".to_string()),
            json!({"owner": "alice", "repo": "r", "title": "t"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn issue_comment_via_mcp_surfaces_denial() {
        assert_tool_surfaces_denial(
            "issue_comment",
            "POST",
            mockito::Matcher::Regex(r"/issues/i1/comments$".to_string()),
            json!({"owner": "alice", "repo": "r", "issue_id": "i1", "body": "b"}),
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn git_refs_via_mcp_surfaces_denial() {
        // git_refs reads pkt-line bytes, not JSON, so a 404 body would otherwise
        // parse to an empty ref list and render as a successful (empty) result.
        assert_tool_surfaces_denial(
            "git_refs",
            "GET",
            mockito::Matcher::Regex(r"/info/refs".to_string()),
            json!({"owner": "alice", "name": "r"}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn repo_clone_url_via_mcp_surfaces_denial() {
        // repo_clone_url resolves the node DID via GET / (read_json). A gated 404
        // there must Err (surfacing the status), not fabricate a clone URL.
        assert_tool_surfaces_denial(
            "repo_clone_url",
            "GET",
            mockito::Matcher::Regex(r"^/$".to_string()),
            json!({"name": "r"}),
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn mcp_resolve_owner_surfaces_denial() {
        // With no "owner" arg, resolve_owner GETs / for the node DID via read_json.
        // A gated 404 there must Err (surfacing the status), proving the conversion
        // is load-bearing rather than silently ignored.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"denied"}"#)
            .expect(1)
            .create_async()
            .await;
        let err = resolve_owner(&json!({}), &NodeClient::new(server.url(), None))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("404"), "got: {err}");
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn resolve_owner_repo_splits_slash_form() {
        let server = mockito::Server::new_async().await;
        let (owner, name) = resolve_owner_repo(
            &json!({}),
            "alice/proj",
            &None,
            &NodeClient::new(server.url(), None),
        )
        .await
        .unwrap();
        assert_eq!((owner.as_str(), name.as_str()), ("alice", "proj"));
    }

    #[tokio::test]
    async fn resolve_owner_repo_owner_arg_beats_keypair() {
        let server = mockito::Server::new_async().await;
        let kp = gitlawb_core::identity::Keypair::generate();
        let (owner, name) = resolve_owner_repo(
            &json!({"owner": "bob"}),
            "proj",
            &Some(kp.clone()),
            &NodeClient::new(server.url(), None),
        )
        .await
        .unwrap();
        assert_eq!((owner.as_str(), name.as_str()), ("bob", "proj"));
    }

    #[tokio::test]
    async fn resolve_owner_repo_bare_repo_uses_keypair_did() {
        let mut server = mockito::Server::new_async().await;
        // A root mock answering with a different DID must never be consulted:
        // under a signed caller the path owner is the keypair's short DID.
        let _m = server
            .mock("GET", "/")
            .with_status(200)
            .with_body(r#"{"did":"did:key:z6MkNodeOperator"}"#)
            .expect(0)
            .create_async()
            .await;
        let kp = gitlawb_core::identity::Keypair::generate();
        let short = kp
            .did()
            .to_string()
            .split(':')
            .next_back()
            .unwrap()
            .to_string();
        let (owner, name) = resolve_owner_repo(
            &json!({}),
            "proj",
            &Some(kp),
            &NodeClient::new(server.url(), None),
        )
        .await
        .unwrap();
        assert_eq!((owner.as_str(), name.as_str()), (short.as_str(), "proj"));
        _m.assert_async().await;
    }
}
