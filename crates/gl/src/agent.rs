//! `gl agent` — list and inspect registered agents on a node.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::http::NodeClient;

#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub cmd: AgentCmd,
}

#[derive(Subcommand)]
pub enum AgentCmd {
    /// List agents registered on a node
    List {
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        /// Filter by capability (e.g. git:push)
        #[arg(long)]
        capability: Option<String>,
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Show details for a specific agent DID
    Show {
        /// Agent DID or short key segment
        did: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
    },
}

pub async fn run(args: AgentArgs) -> Result<()> {
    match args.cmd {
        AgentCmd::List {
            node,
            capability,
            dir: _,
        } => cmd_list(node, capability).await,
        AgentCmd::Show { did, node } => cmd_show(did, node).await,
    }
}

async fn cmd_list(node: String, capability: Option<String>) -> Result<()> {
    let client = NodeClient::new(&node, None);

    let path = match &capability {
        Some(cap) => format!("/api/v1/agents?capability={cap}"),
        None => "/api/v1/agents".to_string(),
    };

    let resp = client
        .get(&path)
        .await
        .context("failed to connect to node")?;
    // Keep the bespoke 404 hint (older node without the agents API) ahead of
    // read_json; every other status routes through it (capped + sanitized error).
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!(
            "this node does not yet support the agents API (v0.3+)\n\
             upgrade the node or check GITLAWB_NODE is pointing to the right server"
        );
    }

    let body = crate::http::read_json(resp, "list agents").await?;

    let agents = body["agents"].as_array().cloned().unwrap_or_default();

    if agents.is_empty() {
        println!("No agents registered on {node}");
        return Ok(());
    }

    println!("Agents on {} ({} total)\n", node, agents.len());
    for agent in &agents {
        let did = agent["did"].as_str().unwrap_or("?");
        let short = did
            .split(':')
            .next_back()
            .map(|s| &s[..s.len().min(16)])
            .unwrap_or("?");
        let trust = agent["trust_score"].as_f64().unwrap_or(0.0);
        let caps = agent["capabilities"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let model = agent["model"].as_str().unwrap_or("");
        println!("  {short}…  trust={trust:.2}  {caps}");
        if !model.is_empty() {
            println!("    model: {model}");
        }
    }
    Ok(())
}

async fn cmd_show(did: String, node: String) -> Result<()> {
    let client = NodeClient::new(&node, None);

    let resp = client
        .get(&format!("/api/v1/agents/{did}"))
        .await
        .context("failed to connect to node")?;
    // Keep the bespoke 404 hint ahead of read_json; other statuses route through it.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!(
            "agent not found, or this node does not yet support the agents API (v0.3+)\n\
             upgrade the node or check GITLAWB_NODE is pointing to the right server"
        );
    }

    let agent = crate::http::read_json(resp, "agent").await?;

    let full_did = agent["did"].as_str().unwrap_or("?");
    let trust = agent["trust_score"].as_f64().unwrap_or(0.0);
    let caps = agent["capabilities"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let registered = agent["registered_at"].as_str().unwrap_or("?");
    let model = agent["model"].as_str().unwrap_or("(none)");

    println!("Agent: {full_did}");
    println!("  Trust score:  {trust:.2}");
    println!("  Capabilities: {caps}");
    println!("  Model:        {model}");
    println!("  Registered:   {registered}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cmd_list_empty() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"agents":[]}"#)
            .create_async()
            .await;

        cmd_list(server.url(), None).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_with_agents() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"agents":[{"did":"did:key:z6MkAgent1","trust_score":0.25,"capabilities":["git:push","git:pull"],"registered_at":"2026-03-18T00:00:00Z"}]}"#)
            .create_async()
            .await;

        cmd_list(server.url(), None).await.unwrap();
    }

    #[tokio::test]
    async fn test_cmd_list_capability_filter_sends_query_param() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents?capability=git:push")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"agents":[]}"#)
            .create_async()
            .await;

        cmd_list(server.url(), Some("git:push".to_string()))
            .await
            .unwrap();
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_404_returns_clear_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_list(server.url(), None).await.unwrap_err();
        assert!(err.to_string().contains("agents API"));
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_server_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"internal error"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_list(server.url(), None).await.unwrap_err();
        assert!(err.to_string().contains("list agents failed"));
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_show_success() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents/did:key:z6MkTest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:z6MkTest","trust_score":0.50,"capabilities":["git:push"],"registered_at":"2026-03-18T00:00:00Z"}"#)
            .create_async()
            .await;

        cmd_show("did:key:z6MkTest".to_string(), server.url())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_cmd_show_not_found() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents/did:key:z6MkMissing")
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"agent not found"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_show("did:key:z6MkMissing".to_string(), server.url())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("agents API") || err.to_string().contains("not found"));
        // Prove the mocked route was actually requested; a non-matching request (mockito's 501, also non-2xx) would otherwise satisfy the error assertion vacuously.
        _m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_show_trust_score_displayed() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/api/v1/agents/did:key:z6MkHigh")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:z6MkHigh","trust_score":0.75,"capabilities":["git:push","git:merge"],"registered_at":"2026-01-01T00:00:00Z"}"#)
            .create_async()
            .await;

        cmd_show("did:key:z6MkHigh".to_string(), server.url())
            .await
            .unwrap();
    }
}
