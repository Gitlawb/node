//! End-to-end test for the `View:` line printed by `gl repo create` (#370).
//!
//! `cmd_create` is the load-bearing #370 path: it is the one place the CLI
//! prints a `View:` line, and the only thing keeping it from being a
//! hardcoded `https://gitlawb.com/...` 404 is `fetch_node_web_url`. The
//! helper-level tests in `repo.rs` cover the helper, not the command path —
//! if `cmd_create` went back to a hardcoded constant, every helper test
//! would still pass.
//!
//! This integration test drives the real `gl` binary against a mockito
//! server that answers both `POST /api/v1/repos` and `GET /`. Asserting on
//! the subprocess's stdout is straightforward: bytes are bytes, with no
//! libtest / gag / in-process capture race.
//!
//! CARGO_BIN_EXE_gl is set by Cargo for integration tests of a `[[bin]]`
//! in the same package, so the test always picks up the in-tree build.

use std::process::Stdio;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

fn gl_bin() -> String {
    std::env::var("CARGO_BIN_EXE_gl").expect("CARGO_BIN_EXE_gl is unset for this test")
}

async fn write_identity(dir: &TempDir) {
    let kp = gitlawb_core::identity::Keypair::generate();
    let pem = kp.to_pem().unwrap();
    let path = dir.path().join("identity.pem");
    let mut f = tokio::fs::File::create(&path).await.unwrap();
    f.write_all(pem.as_bytes()).await.unwrap();
}

/// The trailing key segment of the freshly-generated identity. Mirrors the
/// in-source `resolve_owner_did` test helper but lives in this integration
/// file because that helper is `pub(crate)`.
async fn owner_short(dir: &TempDir) -> String {
    let pem = tokio::fs::read_to_string(dir.path().join("identity.pem"))
        .await
        .unwrap();
    let kp = gitlawb_core::identity::Keypair::from_pem(&pem).unwrap();
    let did = kp.did().to_string();
    did.split(':').next_back().unwrap_or(&did).to_string()
}

async fn run_gl_create(node_url: &str, dir: &TempDir) -> String {
    let output = Command::new(gl_bin())
        .arg("repo")
        .arg("create")
        .arg("myrepo")
        .arg("--private")
        .arg("--branch")
        .arg("main")
        .arg("--node")
        .arg(node_url)
        .arg("--dir")
        .arg(dir.path())
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to spawn `gl repo create`");
    assert!(
        output.status.success(),
        "`gl repo create` failed: stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    String::from_utf8(output.stdout).expect("`gl` wrote non-UTF-8 to stdout")
}

#[tokio::test]
async fn cmd_create_view_url_tracks_node_advertisement() {
    let dir = TempDir::new().unwrap();
    write_identity(&dir).await;
    let owner = owner_short(&dir).await;

    // Case 1: node advertises a web_url. The `View:` line must use the
    // advertised origin and the resolved owner/short name.
    {
        let mut server = mockito::Server::new_async().await;
        let _m_create = server
            .mock("POST", "/api/v1/repos")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"name":"myrepo","clone_url":"gitlawb://did:key:z6Mk/myrepo"}"#)
            .create_async()
            .await;
        let _m_info = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"web_url":"https://git.example","did":"did:key:z6Mk"}"#)
            .create_async()
            .await;
        let server_url = server.url();

        let out = run_gl_create(&server_url, &dir).await;
        let view_line = out
            .lines()
            .find(|l| l.trim_start().starts_with("View:"))
            .unwrap_or_else(|| panic!("View: line missing from stdout:\n{out}"));
        assert!(
            view_line.contains(&format!("https://git.example/{owner}/myrepo")),
            "View: line must use the advertised origin, got: {view_line:?}"
        );
    }

    // Case 2: node does NOT advertise a web_url. The `View:` line must be
    // absent, so a self-hosted node without a web front-end never produces
    // a 404 link (#370).
    {
        let mut server = mockito::Server::new_async().await;
        let _m_create = server
            .mock("POST", "/api/v1/repos")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"name":"myrepo","clone_url":"gitlawb://did:key:z6Mk/myrepo"}"#)
            .create_async()
            .await;
        let _m_info = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"did":"did:key:z6Mk"}"#)
            .create_async()
            .await;
        let server_url = server.url();

        let out = run_gl_create(&server_url, &dir).await;
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("View:")),
            "View: line must be absent when node omits web_url; got:\n{out}"
        );
    }
}
