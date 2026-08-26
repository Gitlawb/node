//! `gl whoami` — print current identity and optional node registration info.

use anyhow::{bail, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::http::{read_body_capped, sanitize_node_msg, NodeClient};
use crate::identity::load_keypair_from_dir;

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
    run_to_writer(args, &mut std::io::stdout()).await
}

pub(crate) async fn run_to_writer(args: WhoamiArgs, w: &mut impl std::io::Write) -> Result<()> {
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
                        .filter_map(|c| c.as_str().map(sanitize_node_msg))
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
                registered = Some(false);
            }
            Ok(resp) => {
                let status = resp.status();
                let raw = read_body_capped(resp, 8 * 1024).await;
                let msg = serde_json::from_str::<Value>(&raw)
                    .ok()
                    .and_then(|v| {
                        let non_empty = |m: Option<&Value>| {
                            m.and_then(|m| m.as_str())
                                .map(String::from)
                                .filter(|s| !s.is_empty())
                        };
                        non_empty(v.get("message")).or_else(|| non_empty(v.get("error")))
                    })
                    .unwrap_or(raw);
                bail!(
                    "agent lookup failed ({status}): {}",
                    sanitize_node_msg(&msg)
                );
            }
            Err(e) => {
                let detail: String = e
                    .chain()
                    .map(|e| sanitize_node_msg(&e.to_string()))
                    .collect::<Vec<_>>()
                    .join(": ");
                bail!("agent lookup failed: {detail}");
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
        writeln!(w, "{}", serde_json::to_string_pretty(&out)?)?;
    } else {
        writeln!(w, "DID:        {did}")?;
        writeln!(w, "Short:      {short}")?;
        if let Some(reg) = registered {
            writeln!(w, "Registered: {}", if reg { "yes" } else { "no" })?;
        }
        if let Some(ts) = trust_score {
            writeln!(w, "Trust:      {ts:.2}")?;
        }
        if !capabilities.is_empty() {
            writeln!(w, "Caps:       {}", capabilities.join(", "))?;
        }
        if let Some(rc) = repo_count {
            writeln!(w, "Repos:      {rc}")?;
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
        let mut out = Vec::new();
        run_to_writer(args, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Registered: no"), "unexpected output: {out}");

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: true,
        };
        let mut out = Vec::new();
        run_to_writer(args, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("\"registered\": false"),
            "unexpected output: {out}"
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
    async fn test_whoami_server_error_unusable_message_uses_error() {
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
            .with_body(r#"{"message":"","error":"boom"}"#)
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
            msg.contains("boom"),
            "expected 'boom' from error field, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_whoami_with_node_transport_error() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let node = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(node),
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
    async fn test_whoami_transport_sanitizes_control_chars_in_node_url() {
        let dir = TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        let pem = kp.to_pem().unwrap();
        std::fs::write(dir.path().join("identity.pem"), pem.as_bytes()).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let node = format!("http://127.0.0.1:{port}/\u{1b}]0;PWNED\u{7} \u{202e}gnitirw");
        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(node),
            json: false,
        };
        let err = run(args).await.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("agent lookup failed"),
            "expected transport error, got: {msg}"
        );
        assert!(!msg.contains('\u{1b}'), "ESC leaked into output: {msg:?}");
        assert!(!msg.contains('\u{7}'), "BEL leaked into output: {msg:?}");
        assert!(!msg.contains('\u{202e}'), "RLO leaked into output: {msg:?}");
    }

    #[tokio::test]
    async fn test_whoami_server_error_body_display_bounded() {
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
            .with_body("{\"message\":\"\\u001b[31mowned\\u0007\\u202eevil\"}")
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

    #[tokio::test]
    async fn test_whoami_sanitizes_hostile_capabilities() {
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
            .with_body(
                "{\"trust_score\":0.5,\"capabilities\":[\"\\u001b]0;PWNED\\u0007repo:write\",\"\\u202egnitirw-tfel\"]}",
            )
            .create_async()
            .await;
        let _repos = server
            .mock(
                "GET",
                mockito::Matcher::Regex(format!(r"^/api/v1/repos\?owner={short}")),
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;

        // Human mode: no control bytes or bidi overrides reach the terminal
        let mut buf = Vec::new();
        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: false,
        };
        run_to_writer(args, &mut buf).await.unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains('\u{1b}'), "ESC leaked in human mode: {out:?}");
        assert!(!out.contains('\u{07}'), "BEL leaked in human mode: {out:?}");
        assert!(
            !out.contains('\u{202e}'),
            "RLO leaked in human mode: {out:?}"
        );
        assert!(out.contains("repo:write"), "benign text missing: {out:?}");
        assert!(out.contains("tfel"), "reversed text missing: {out:?}");

        // JSON mode: serde escapes C0 but passes bidi — ensure no U+202E
        let mut buf = Vec::new();
        let args = WhoamiArgs {
            dir: Some(dir.path().to_path_buf()),
            node: Some(server.url()),
            json: true,
        };
        run_to_writer(args, &mut buf).await.unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains('\u{202e}'),
            "RLO leaked in JSON mode: {out:?}"
        );
    }
}
