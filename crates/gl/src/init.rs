//! `gl init` — zero-to-push in one command.
//!
//! Detects or initializes a git repo, ensures an identity exists,
//! registers with the node, creates a remote repo, adds the gitlawb
//! remote, and pushes.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;

use crate::http::{json_or_denial, NodeClient};
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
    run_in(&cwd, args).await
}

/// The body of [`run`], with the working directory passed in. Split out so the
/// whole flow (including what it prints on a node denial) is testable without
/// mutating the process-wide current directory.
async fn run_in(cwd: &std::path::Path, args: InitArgs) -> Result<()> {
    let cwd = cwd.to_path_buf();

    // 1. Ensure git repo exists
    let git_dir = cwd.join(".git");
    if !git_dir.exists() {
        println!("Initializing git repository...");
        // -b main: the push flow targets `main`; without it a fresh repo uses
        // the user's init.defaultBranch (often `master`). Older git (<2.28)
        // lacks the flag, so fall back to a plain init.
        let status = std::process::Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&cwd)
            .status()
            .context("failed to run git init")?;
        if !status.success() {
            let status = std::process::Command::new("git")
                .args(["init"])
                .current_dir(&cwd)
                .status()
                .context("failed to run git init")?;
            if !status.success() {
                anyhow::bail!("git init failed");
            }
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
    let resp = client
        .post("/api/register", &body)
        .await
        .context("failed to connect to node")?;
    // No tolerated failure here: `register_agent` upserts, so re-registering a
    // known DID is a 201, not a conflict (node `api/register.rs`, and the ON
    // CONFLICT clause in `db::register_agent`). An older check let any message
    // containing "already" through, which included the replay denial "this
    // signature has already been used".
    let payload: Value = json_or_denial("registration", resp).await?;

    // Save UCAN if returned
    if let Some(ucan) = payload.get("ucan").and_then(|v| v.as_str()) {
        if !ucan.is_empty() {
            let ucan_dir = args
                .dir
                .clone()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".gitlawb"));
            std::fs::create_dir_all(&ucan_dir)?;
            let record = json!({
                "ucan": ucan,
                "node": args.node,
                "did": did.to_string(),
                "saved_at": chrono::Utc::now().to_rfc3339(),
            });
            std::fs::write(
                ucan_dir.join("ucan.json"),
                serde_json::to_string_pretty(&record)?,
            )?;
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
    let mut resp = client
        .post("/api/v1/repos", &body)
        .await
        .context("failed to create repo")?;
    let repo_status = resp.status();
    if !repo_status.is_success() {
        let raw = crate::http::read_body_capped(&mut resp, crate::http::DENIAL_BODY_CAP).await;
        let repo_result: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        if !repo_already_exists(&repo_result) {
            let msg = repo_result["message"]
                .as_str()
                .or_else(|| repo_result["error"].as_str())
                .unwrap_or("unknown error");
            anyhow::bail!(
                "create repo failed ({repo_status}): {}",
                crate::http::sanitize_node_msg(msg)
            );
        }
        println!("  Repository already exists — continuing.");
    } else {
        let _repo_result: Value = resp.json().await.context("invalid JSON from create repo")?;
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

    // The hint must match the repo's actual state: with no commits yet, a bare
    // `git push` fails with "src refspec ... does not match any" — exactly the
    // trap a zero-to-push command must not set.
    let has_commits = std::process::Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(&cwd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    // symbolic-ref succeeds on a branch (including an unborn one) and fails
    // on a detached HEAD — where guessing "main" could push the wrong ref.
    let branch = std::process::Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .current_dir(&cwd)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    println!();
    match (branch, has_commits) {
        (Some(branch), true) => {
            println!("Ready! Push with:");
            println!("  git push gitlawb {branch}");
        }
        (Some(branch), false) => {
            println!("Ready! Nothing is committed yet — commit, then push:");
            println!("  git add -A && git commit -m \"initial commit\"");
            println!("  git push gitlawb {branch}");
        }
        (None, _) => {
            println!("Ready! HEAD is detached — create or switch to a branch, then push:");
            println!("  git switch -c main");
            println!("  git push gitlawb main");
        }
    }

    Ok(())
}

/// Is this failed create-repo reply the benign "you already own that repo" case?
/// `AppError::RepoExists` is the only thing the node renders as `repo_exists`
/// (node `error.rs`), and it is the only non-success reply `gl init` may treat
/// as "keep going".
fn repo_already_exists(payload: &Value) -> bool {
    payload["error"].as_str() == Some("repo_exists")
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
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
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
            .create_async()
            .await;

        let _repo = server
            .mock("POST", "/api/v1/repos")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"r1","name":"test-repo"}"#)
            .create_async()
            .await;

        // We can't fully test gl init because it uses std::env::current_dir()
        // but we can test the individual steps
        let client = NodeClient::new(server.url(), Some(kp.clone()));

        // Register
        let body = serde_json::to_vec(&json!({
            "did": kp.did().to_string(),
            "capabilities": ["git:push"],
        }))
        .unwrap();
        let resp: Value = client
            .post("/api/register", &body)
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["message"], "Welcome");

        // Create repo
        let body = serde_json::to_vec(&json!({"name": "test-repo", "is_public": true})).unwrap();
        let resp: Value = client
            .post("/api/v1/repos", &body)
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["name"], "test-repo");
    }

    /// A work dir with a git repo in it, plus an identity dir, wired to `node`.
    fn init_args(node: String, id_dir: &TempDir) -> (InitArgs, TempDir) {
        let work = TempDir::new().unwrap();
        std::process::Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(work.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        let args = InitArgs {
            name: Some("test-repo".to_string()),
            node,
            dir: Some(id_dir.path().to_path_buf()),
            description: None,
        };
        (args, work)
    }

    fn has_gitlawb_remote(work: &TempDir) -> bool {
        std::process::Command::new("git")
            .args(["remote", "get-url", "gitlawb"])
            .current_dir(work.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn mock_register(server: &mut mockito::ServerGuard) -> mockito::Mock {
        server
            .mock("POST", "/api/register")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"accepted","message":"welcome","ucan":"test.token"}"#)
            .create_async()
            .await
    }

    #[tokio::test]
    async fn init_fails_on_replay_409_without_the_error_header() {
        // The node refused the create (the signature was already spent) and a
        // proxy stripped `x-gitlawb-error`, so the client layer cannot see the
        // denial and hands the 409 straight back. `gl init` used to read
        // "already" out of the prose, print "Repository already exists —
        // continuing", add the remote, print "Ready! Push with", and exit 0 for
        // a repo that does not exist. Comparing the structured error code is
        // what makes it fail instead, before any of that.
        let id_dir = TempDir::new().unwrap();
        write_identity(&id_dir);
        let mut server = mockito::Server::new_async().await;
        let _reg = mock_register(&mut server).await;
        let _repo = server
            .mock("POST", "/api/v1/repos")
            .with_status(409)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"error":"signature_replayed","message":"this signature has already been used - sign a fresh request"}"#,
            )
            .create_async()
            .await;

        let (args, work) = init_args(server.url(), &id_dir);
        let err = run_in(work.path(), args)
            .await
            .expect_err("a replayed signature must fail `gl init`, not report success");
        let err = format!("{err:#}");
        assert!(err.contains("create repo failed"), "got: {err}");
        assert!(err.contains("409"), "status not surfaced: {err}");
        // The remote is added several lines after the point where the old code
        // decided "already exists, continuing", so its absence proves we bailed
        // before printing "Ready! Push with".
        assert!(
            !has_gitlawb_remote(&work),
            "init continued past the denial and configured the remote"
        );
    }

    #[tokio::test]
    async fn init_still_continues_on_a_real_repo_exists_409() {
        // The regression guard for the fix above: a genuine repo_exists conflict
        // must behave exactly as before (continue, add the remote, succeed).
        let id_dir = TempDir::new().unwrap();
        write_identity(&id_dir);
        let mut server = mockito::Server::new_async().await;
        let _reg = mock_register(&mut server).await;
        let _repo = server
            .mock("POST", "/api/v1/repos")
            .with_status(409)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"error":"repo_exists","message":"repository 'test-repo' already exists"}"#,
            )
            .create_async()
            .await;

        let (args, work) = init_args(server.url(), &id_dir);
        run_in(work.path(), args)
            .await
            .expect("an existing repo must still be a successful `gl init`");
        assert!(
            has_gitlawb_remote(&work),
            "init must still configure the remote for an existing repo"
        );
    }

    #[tokio::test]
    async fn init_fails_when_registration_is_refused() {
        // Registration is an upsert on the node, so any non-success is a real
        // failure. The old `contains("already")` tolerance also swallowed the
        // replay denial here.
        let id_dir = TempDir::new().unwrap();
        write_identity(&id_dir);
        let mut server = mockito::Server::new_async().await;
        let _reg = server
            .mock("POST", "/api/register")
            .with_status(409)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"error":"signature_replayed","message":"this signature has already been used"}"#,
            )
            .create_async()
            .await;

        let (args, work) = init_args(server.url(), &id_dir);
        let err = run_in(work.path(), args)
            .await
            .expect_err("a refused registration must fail `gl init`");
        let err = format!("{err:#}");
        assert!(err.contains("registration failed"), "got: {err}");
        assert!(err.contains("409"), "status not surfaced: {err}");
        assert!(!has_gitlawb_remote(&work));
    }

    #[test]
    fn repo_already_exists_matches_the_code_not_the_prose() {
        assert!(repo_already_exists(
            &json!({"error":"repo_exists","message":"repository 'x' already exists"})
        ));
        // The replay denial's message contains "already" and "exists" is one
        // word away; only the code separates them.
        assert!(!repo_already_exists(&json!({
            "error": "signature_replayed",
            "message": "this signature has already been used - sign a fresh request"
        })));
        assert!(!repo_already_exists(
            &json!({"message":"repository already exists"})
        ));
        assert!(!repo_already_exists(&json!({})));
    }
}
