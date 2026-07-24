//! `gl whoami` — print current identity and optional node registration info.

use anyhow::{bail, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;
use crate::sync::{read_body_capped, sanitize_node_msg};

#[derive(Args)]
pub struct WhoamiArgs {
    /// Identity directory (default: ~/.gitlawb)
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Node URL to query for registration info
    #[arg(long, env = "GITLAWB_NODE")]
    node: Option<String>,
    /// Output structured JSON for scripting
    #[arg(long)]
    json: bool,
}

pub async fn run(args: WhoamiArgs) -> Result<()> {
    let keypair = load_keypair_from_dir(args.dir.as_deref())?;
    let did = keypair.did().to_string();
    let short = did.split(':').next_back().unwrap_or(&did).to_string();

    let mut registered: Option<bool> = None;
    let mut trust_score: Option<f64> = None;
    let mut capabilities: Vec<String> = Vec::new();
    let mut repo_count: Option<u64> = None;

    if let Some(node) = &args.node {
        let client = NodeClient::new(node, None);
        match client.get(&format!("/api/v1/agents/{did}")).await {
            Ok(resp) if resp.status().is_success() => {
                let info: Value = resp.json().await.unwrap_or_default();
                registered = Some(true);
                trust_score = info["trust_score"].as_f64();
                if let Some(caps) = info["capabilities"].as_array() {
                    capabilities = caps
                        .iter()
                        .filter_map(|c| c.as_str().map(String::from))
                        .collect();
                }
                // Try to get repo count
                if let Ok(repos_resp) = client.get(&format!("/api/v1/repos?owner={short}")).await {
                    if let Ok(repos) = repos_resp.json::<Value>().await {
                        repo_count = repos.as_array().map(|a| a.len() as u64);
                    }
                }
            }
            Ok(resp) if resp.status().as_u16() == 404 => {
                bail!(
                    "agent not found, or this node does not yet support the agents API (v0.3+)\n\
                     upgrade the node or check GITLAWB_NODE is pointing to the right server"
                );
            }
            Ok(resp) => {
                let status = resp.status();
                let raw = read_body_capped(resp, 8 * 1024).await;
                let msg = serde_json::from_str::<Value>(&raw)
                    .ok()
                    .and_then(|v| {
                        v.get("message")
                            .or_else(|| v.get("error"))
                            .and_then(|m| m.as_str())
                            .map(String::from)
                    })
                    .unwrap_or(raw);
                bail!(
                    "agent lookup failed ({status}): {}",
                    sanitize_node_msg(&msg)
                );
            }
            Err(e) => {
                bail!("agent lookup failed: {e}");
            }
        }
    }

    if args.json {
        let mut out = json!({
            "did": did,
            "short": short,
        });
        if let Some(reg) = registered {
            out["registered"] = json!(reg);
        }
        if let Some(ts) = trust_score {
            out["trust_score"] = json!(ts);
        }
        if !capabilities.is_empty() {
            out["capabilities"] = json!(capabilities);
        }
        if let Some(rc) = repo_count {
            out["repos"] = json!(rc);
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("DID:        {did}");
        println!("Short:      {short}");
        if let Some(reg) = registered {
            println!("Registered: {}", if reg { "yes" } else { "no" });
        }
        if let Some(ts) = trust_score {
            println!("Trust:      {ts:.2}");
        }
        if !capabilities.is_empty() {
            println!("Caps:       {}", capabilities.join(", "));
        }
        if let Some(rc) = repo_count {
            println!("Repos:      {rc}");
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
    async fn test_whoami_local_only() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: None,
            json: false,
        };
        run(args).await.unwrap();
    }

    #[tokio::test]
    async fn test_whoami_json_local() {
        let dir = TempDir::new().unwrap();
        write_identity(&dir);

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: None,
            json: true,
        };
        run(args).await.unwrap();
    }

    #[tokio::test]
    async fn test_whoami_with_node_registered() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();
        let short = did.split(':').next_back().unwrap().to_string();

        let mut server = mockito::Server::new_async().await;
        let _agent = server
            .mock("GET", format!("/api/v1/agents/{did}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"trust_score":0.35,"capabilities":["git:push","git:pull"]}"#)
            .create_async()
            .await;
        let _repos = server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(r"^/api/v1/repos\?owner={short}")),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"name":"repo1"},{"name":"repo2"},{"name":"repo3"},{"name":"repo4"}]"#)
            .create_async()
            .await;

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: false,
        };
        run(args).await.unwrap();
    }

    #[tokio::test]
    async fn test_whoami_with_node_not_registered() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();

        let mut server = mockito::Server::new_async().await;
        let _agent = server
            .mock("GET", format!("/api/v1/agents/{did}").as_str())
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"not found"}"#)
            .create_async()
            .await;

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: false,
        };
        let err = run(args).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("agents API"),
            "expected ambiguous 404 error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_whoami_with_node_forbidden() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();

        let mut server = mockito::Server::new_async().await;
        let _agent = server
            .mock("GET", format!("/api/v1/agents/{did}").as_str())
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"forbidden"}"#)
            .create_async()
            .await;

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: false,
        };
        let err = run(args).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("403"), "expected 403 error, got: {msg}");
        assert!(
            msg.contains("forbidden"),
            "expected 'forbidden' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_whoami_with_node_server_error() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();

        let mut server = mockito::Server::new_async().await;
        let _agent = server
            .mock("GET", format!("/api/v1/agents/{did}").as_str())
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"internal error"}"#)
            .create_async()
            .await;

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: false,
        };
        let err = run(args).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("500"), "expected 500 error, got: {msg}");
        assert!(
            msg.contains("internal error"),
            "expected 'internal error' in error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_whoami_with_node_transport_error() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some("http://127.0.0.1:1".to_string()),
            json: false,
        };
        let err = run(args).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("agent lookup failed"),
            "expected transport error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_whoami_server_error_caps_body_size() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();

        let mut server = mockito::Server::new_async().await;
        let _agent = server
            .mock("GET", format!("/api/v1/agents/{did}").as_str())
            .with_status(502)
            .with_header("content-type", "application/json")
            .with_body("x".repeat(100_000))
            .create_async()
            .await;

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: false,
        };
        let err = run(args).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("502"),
            "expected 502 error with bounded body, got: {msg}"
        );
        let display = format!("{err}");
        assert!(
            display.len() < 1000,
            "error message too long ({} bytes) — body was not capped",
            display.len()
        );
    }

    #[tokio::test]
    async fn test_whoami_server_error_sanitizes_controls() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();

        let mut server = mockito::Server::new_async().await;
        let _agent = server
            .mock("GET", format!("/api/v1/agents/{did}").as_str())
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body("{\"message\":\"\\u{1b}[31mowned\\u{07}\\u{202e}evil\"}")
            .create_async()
            .await;

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: false,
        };
        let err = run(args).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("owned"),
            "expected sanitized error body, got: {msg}"
        );
        assert!(!msg.contains('\u{1b}'), "ESC control char leaked: {msg}");
        assert!(!msg.contains('\u{07}'), "BEL control char leaked: {msg}");
        assert!(!msg.contains('\u{202e}'), "RTL override leaked: {msg}");
    }

    #[tokio::test]
    async fn test_whoami_json_with_node() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();
        let did = kp.did().to_string();
        let short = did.split(':').next_back().unwrap().to_string();

        let mut server = mockito::Server::new_async().await;
        let _agent = server
            .mock("GET", format!("/api/v1/agents/{did}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"trust_score":0.80,"capabilities":["git:push"]}"#)
            .create_async()
            .await;
        let _repos = server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(r"^/api/v1/repos\?owner={short}")),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"name":"repo1"}]"#)
            .create_async()
            .await;

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: true,
        };
        run(args).await.unwrap();
    }
}
