//! `gl mirror` — clone a public GitHub/GitLab/any-git repo and push it to gitlawb.
//!
//! Flow:
//!   1. Parse source URL → derive repo name (or use --repo override)
//!   2. `git clone --mirror <source>` into a temp dir
//!   3. Create the repo on the gitlawb node (authenticated)
//!   4. `git push --mirror gitlawb://<did>/<name>`
//!   5. Clean up temp dir

use anyhow::{bail, Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct MirrorArgs {
    /// Source repository URL (https://github.com/owner/repo, GitLab, or any public git URL)
    pub source: String,

    /// Name to use on gitlawb (default: last path segment of source URL, .git suffix stripped)
    #[arg(long)]
    pub repo: Option<String>,

    /// Optional description for the gitlawb repo
    #[arg(long, short)]
    pub description: Option<String>,

    #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
    pub node: String,

    #[arg(long)]
    pub dir: Option<PathBuf>,
}

/// Argv for the mirror clone, with `--` immediately before the first positional
/// so an option-shaped `source` cannot be parsed as a git option (#374).
///
/// This is a separate function purely so the delimiter's placement can be driven
/// through real git by a test. The production call keeps `.status()` rather than
/// `.output()`: a mirror clone of a large repo streams git's progress to the
/// user's terminal, and capturing it to assert on stderr here would swallow that.
fn mirror_clone_args<'a>(source: &'a str, dest: &'a str) -> [&'a str; 5] {
    ["clone", "--mirror", "--", source, dest]
}

pub async fn run(args: MirrorArgs) -> Result<()> {
    let source = args.source.trim_end_matches('/').to_string();

    // ── 1. Derive repo name ───────────────────────────────────────────────
    let name = match args.repo {
        Some(n) => n,
        None => extract_repo_name(&source).with_context(|| {
            format!("could not derive repo name from '{source}' — use --repo <name>")
        })?,
    };

    // Validate: same rules as `gl repo create`
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        bail!("repo name '{name}' must contain only alphanumeric characters, hyphens, and underscores\nUse --repo to provide a valid name");
    }

    // ── 2. Load identity ──────────────────────────────────────────────────
    let kp = load_keypair_from_dir(args.dir.as_deref())
        .context("identity not found — run `gl identity new` first")?;
    let owner_did = kp.did().to_string();

    println!("Mirroring {source}");
    println!("  → gitlawb repo: {name}");
    println!();

    // ── 3. git clone --mirror into a temp dir ─────────────────────────────
    // UUID-named subdir in the system temp dir — cleaned up via Drop.
    let tmp_root = std::env::temp_dir().join(format!("gl-mirror-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_root).context("failed to create temp dir")?;
    let mirror_path = tmp_root.join(&name);
    // RAII guard: removes the temp dir when this binding is dropped (success or failure).
    struct TmpGuard(PathBuf);
    impl Drop for TmpGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _guard = TmpGuard(tmp_root);

    println!("Cloning source (this may take a while for large repos)...");
    let clone_status = Command::new("git")
        .args(mirror_clone_args(&source, mirror_path.to_str().unwrap()))
        .status()
        .context("failed to run git clone — is git installed?")?;

    if !clone_status.success() {
        bail!("git clone --mirror failed\nCheck that the source URL is accessible: {source}");
    }

    // ── 4. Create the repo on gitlawb ─────────────────────────────────────
    println!("Creating repo on gitlawb node...");
    let client = NodeClient::new(&args.node, Some(kp));

    let body = serde_json::to_vec(&json!({
        "name": name,
        "description": args.description.as_deref().unwrap_or(&format!("Mirrored from {source}")),
        "is_public": true,
        "default_branch": "main",
    }))?;

    let resp = client
        .post("/api/v1/repos", &body)
        .await
        .context("failed to connect to node")?;

    let status = resp.status();
    let payload: Value = resp.json().await.unwrap_or_default();

    if !status.is_success() {
        let msg = payload["message"].as_str().unwrap_or("unknown error");
        bail!("failed to create repo ({status}): {msg}");
    }

    // ── 5. git push --mirror to gitlawb ───────────────────────────────────
    let gitlawb_url = format!("gitlawb://{owner_did}/{name}");
    println!("Pushing to {gitlawb_url}...");

    let push_status = Command::new("git")
        .args(["push", "--mirror", &gitlawb_url])
        .current_dir(&mirror_path)
        .env("GITLAWB_NODE", &args.node)
        .status()
        .context("failed to run git push")?;

    if !push_status.success() {
        bail!("git push --mirror failed\nThe repo was created on gitlawb but the push did not complete.\nYou can retry with:\n  cd {path} && git push --mirror {gitlawb_url}",
            path = mirror_path.display());
    }

    // ── 6. Done ───────────────────────────────────────────────────────────
    let owner_short = owner_did.split(':').next_back().unwrap_or(&owner_did);
    println!();
    println!("✓ Mirror complete: {name}");
    println!("  Clone:  git clone {gitlawb_url}");
    println!("  View:   https://gitlawb.com/{owner_short}/{name}");

    Ok(())
}

/// Extract the repo name from a git URL.
/// - `https://github.com/owner/repo`     → `"repo"`
/// - `https://github.com/owner/repo.git` → `"repo"`
/// - `https://gitlab.com/group/sub/repo` → `"repo"`
pub fn extract_repo_name(url: &str) -> Option<String> {
    // Strip scheme (https://, git://, ssh://, etc.) so we can tell whether
    // there is a real path beyond just the hostname.
    let after_scheme = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };
    // Must have at least one '/' after the host (i.e. a real path component).
    if !after_scheme.contains('/') {
        return None;
    }
    let last = url.trim_end_matches('/').split('/').next_back()?;
    if last.is_empty() {
        return None;
    }
    let name = last.trim_end_matches(".git");
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #374: `gl mirror` interpolates the user-supplied source into a
    /// `git clone --mirror` argv. `--` must sit immediately before the first
    /// positional so an option-shaped source is read as a repository.
    ///
    /// This drives the production argv through real git rather than asserting on
    /// the array's contents, so it fails on a delimiter that is missing *or*
    /// misplaced. It cannot go through `run()`: that loads an identity keypair and
    /// contacts a node before reaching the clone, and its bail message interpolates
    /// `{source}` unconditionally, so an assertion there would pass with `--` gone.
    ///
    /// Asserting on git's single-quoted `repository '<value>'` is what makes this
    /// red without the delimiter — undelimited, git consumes the value as an option
    /// and names the destination as the repository instead.
    #[test]
    fn mirror_clone_never_parses_the_source_as_a_git_option() {
        let td = tempfile::TempDir::new().unwrap();
        let dest = td.path().join("mirror.git");
        let injected = "--upload-pack=false";

        let out = Command::new("git")
            .args(mirror_clone_args(injected, dest.to_str().unwrap()))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);

        assert!(
            !out.status.success(),
            "an option-shaped source is not a repository and must fail the clone"
        );
        assert!(
            stderr.contains(&format!("repository '{injected}'")),
            "git must name the source as the repository, not consume it as an option: {stderr}"
        );
    }

    #[test]
    fn test_extract_github_url() {
        assert_eq!(
            extract_repo_name("https://github.com/torvalds/linux"),
            Some("linux".into())
        );
    }

    #[test]
    fn test_extract_github_url_git_suffix() {
        assert_eq!(
            extract_repo_name("https://github.com/torvalds/linux.git"),
            Some("linux".into())
        );
    }

    #[test]
    fn test_extract_gitlab_url() {
        assert_eq!(
            extract_repo_name("https://gitlab.com/inkscape/inkscape"),
            Some("inkscape".into())
        );
    }

    #[test]
    fn test_extract_nested_gitlab_url() {
        assert_eq!(
            extract_repo_name("https://gitlab.com/group/subgroup/repo"),
            Some("repo".into())
        );
    }

    #[test]
    fn test_extract_trailing_slash() {
        assert_eq!(
            extract_repo_name("https://github.com/owner/myrepo/"),
            Some("myrepo".into())
        );
    }

    #[test]
    fn test_extract_no_path_returns_none() {
        assert_eq!(extract_repo_name("https://github.com"), None);
    }

    #[test]
    fn test_extract_dot_git_only_returns_none() {
        // edge case: URL ending in just ".git" with no name
        assert_eq!(extract_repo_name("https://example.com/.git"), None);
    }

    #[tokio::test]
    async fn test_create_repo_conflict_error() {
        let mut server = mockito::Server::new_async().await;
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();

        let _m = server
            .mock("POST", "/api/v1/repos")
            .with_status(409)
            .with_header("content-type", "application/json")
            .with_body(r#"{"message":"repo already exists"}"#)
            .create_async()
            .await;

        // The git subprocess argv is pinned separately by
        // `mirror_clone_never_parses_the_source_as_a_git_option`; this covers the
        // API error path by calling the create step directly via NodeClient.
        let kp2 = gitlawb_core::identity::Keypair::generate();
        let client = NodeClient::new(server.url(), Some(kp2));
        let body =
            serde_json::to_vec(&json!({"name":"myrepo","is_public":true,"default_branch":"main"}))
                .unwrap();
        let resp = client.post("/api/v1/repos", &body).await.unwrap();
        assert_eq!(resp.status(), 409);
        let payload: Value = resp.json().await.unwrap();
        assert_eq!(payload["message"].as_str(), Some("repo already exists"));
    }

    #[tokio::test]
    async fn test_create_repo_success_response() {
        let mut server = mockito::Server::new_async().await;

        let _m = server
            .mock("POST", "/api/v1/repos")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"abc","name":"myrepo","clone_url":"http://node/z/myrepo.git","star_count":0}"#)
            .create_async()
            .await;

        let kp = gitlawb_core::identity::Keypair::generate();
        let client = NodeClient::new(server.url(), Some(kp));
        let body =
            serde_json::to_vec(&json!({"name":"myrepo","is_public":true,"default_branch":"main"}))
                .unwrap();
        let resp = client.post("/api/v1/repos", &body).await.unwrap();
        assert!(resp.status().is_success());
        let payload: Value = resp.json().await.unwrap();
        assert_eq!(payload["name"].as_str(), Some("myrepo"));
    }
}
