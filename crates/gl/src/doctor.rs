//! `gl doctor` — check your gitlawb installation and connectivity.
//!
//! Checks:
//!   1. Identity        — ~/.gitlawb/identity.pem exists, DID parseable
//!   2. Registration    — ~/.gitlawb/ucan.json exists (registered with a node)
//!   3. GITLAWB_NODE    — env var is set to a non-localhost URL
//!   4. Node            — GITLAWB_NODE is reachable (default: https://node.gitlawb.com)
//!   5. git helper      — git-remote-gitlawb is in PATH
//!   6. git             — git is installed
//!   7. version         — gl is up to date with latest GitHub release

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use crate::http::NodeClient;

const PUBLIC_NODE: &str = "https://node.gitlawb.com";
const GITHUB_API_BASE: &str = "https://api.github.com";

#[derive(Args)]
pub struct DoctorArgs {
    /// Node URL to check connectivity against
    #[arg(long, default_value = PUBLIC_NODE, env = "GITLAWB_NODE")]
    pub node: String,

    /// Identity directory (default: ~/.gitlawb)
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

struct Check {
    label: &'static str,
    state: CheckState,
    detail: String,
    fix: Option<String>,
}

enum CheckState {
    Ok,
    Warn,
    Fail,
}

impl Check {
    fn pass(label: &'static str, detail: impl Into<String>) -> Self {
        Self {
            label,
            state: CheckState::Ok,
            detail: detail.into(),
            fix: None,
        }
    }
    fn warn(label: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            label,
            state: CheckState::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn fail(label: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            label,
            state: CheckState::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

pub async fn run(args: DoctorArgs) -> Result<()> {
    println!("gl doctor — checking your gitlawb setup");
    println!();

    let dir = args.dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gitlawb")
    });

    let mut checks = Vec::new();
    let mut all_ok = true;

    // ── 1. Identity ───────────────────────────────────────────────────────
    let pem_path = dir.join("identity.pem");
    if pem_path.exists() {
        match std::fs::read_to_string(&pem_path)
            .ok()
            .and_then(|pem| gitlawb_core::identity::Keypair::from_pem(&pem).ok())
        {
            Some(kp) => {
                let did = kp.did().to_string();
                let short = did.chars().take(40).collect::<String>();
                checks.push(Check::pass("identity", format!("{short}…")));
            }
            None => {
                checks.push(Check::fail(
                    "identity",
                    format!("exists at {} but could not be parsed", pem_path.display()),
                    "gl identity new --force",
                ));
            }
        }
    } else {
        checks.push(Check::fail(
            "identity",
            format!("not found at {}", pem_path.display()),
            "gl identity new",
        ));
    }

    // ── 2. Registration ───────────────────────────────────────────────────
    let ucan_path = dir.join("ucan.json");
    if ucan_path.exists() {
        match std::fs::read_to_string(&ucan_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        {
            Some(v) => {
                let node = v["node"].as_str().unwrap_or("unknown");
                checks.push(Check::pass(
                    "registration",
                    format!("registered with {node}"),
                ));
            }
            None => {
                checks.push(Check::fail(
                    "registration",
                    "ucan.json exists but is malformed",
                    "gl register",
                ));
            }
        }
    } else {
        checks.push(Check::fail(
            "registration",
            "not registered with any node",
            "gl register",
        ));
    }

    // ── 3. GITLAWB_NODE env var ───────────────────────────────────────────
    match std::env::var("GITLAWB_NODE") {
        // A loopback host is a legitimate setup (self-hosted node, dev
        // harness) — the connectivity check below fails loudly if it is not
        // actually reachable, so don't red-flag the configuration itself.
        Ok(v) if is_loopback_url(&v) => {
            checks.push(Check::pass(
                "GITLAWB_NODE",
                format!(
                    "{v} (local node — intentional for self-hosting/dev; unset to target the public network)"
                ),
            ));
        }
        Ok(v) if !v.is_empty() => {
            checks.push(Check::pass("GITLAWB_NODE", v.to_string()));
        }
        _ => {
            checks.push(Check::fail(
                "GITLAWB_NODE",
                "not set — git-remote-gitlawb will fall back to http://127.0.0.1:7545",
                "export GITLAWB_NODE=https://node.gitlawb.com",
            ));
        }
    }

    // ── 4. Node connectivity ──────────────────────────────────────────────
    let client = NodeClient::new(&args.node, None);
    match client.get("/").await {
        Ok(resp) if resp.status().is_success() => {
            let info = resp.json::<serde_json::Value>().await.unwrap_or_default();
            let version = info["version"].as_str().unwrap_or("?");
            let did = info["did"].as_str().unwrap_or("?");
            let short_did = did.chars().take(30).collect::<String>();
            checks.push(Check::pass(
                "node",
                format!("{} — v{version} ({short_did}…)", args.node),
            ));
            // Capability drift: a node newer than this CLI may require features
            // (RFC 9421 signing, iCaptcha) the CLI doesn't speak.
            let gl_ver = env!("CARGO_PKG_VERSION");
            if version != "?" && is_newer(version, gl_ver) {
                checks.push(Check::warn(
                    "gl version",
                    format!(
                        "node is v{version} but gl is v{gl_ver} — your CLI may be missing \
                         features (signing / iCaptcha) this node requires"
                    ),
                    "upgrade gl: curl -sSf https://gitlawb.com/install.sh | sh",
                ));
            }
        }
        Ok(resp) => {
            checks.push(Check::fail(
                "node",
                format!("{} returned HTTP {}", args.node, resp.status()),
                "check GITLAWB_NODE env var or try gl register --node <url>",
            ));
        }
        Err(e) => {
            checks.push(Check::fail(
                "node",
                format!("{} unreachable: {e}", args.node),
                "check your internet connection or set GITLAWB_NODE",
            ));
        }
    }

    // ── 4b. iCaptcha capability ───────────────────────────────────────────
    // Gated writes (repo create / register / fork) auto-solve a challenge at the
    // iCaptcha service; check it's reachable so the failure mode is obvious.
    let icaptcha_url = std::env::var("GITLAWB_ICAPTCHA_URL")
        .unwrap_or_else(|_| icaptcha_client::DEFAULT_URL.to_string());
    match NodeClient::new(&icaptcha_url, None).get("/v1/pubkey").await {
        Ok(resp) if resp.status().is_success() => {
            checks.push(Check::pass("iCaptcha", format!("{icaptcha_url} reachable")));
        }
        Ok(resp) => {
            checks.push(Check::warn(
                "iCaptcha",
                format!("{icaptcha_url} returned HTTP {}", resp.status()),
                "gated writes (repo create / register) may fail until iCaptcha is reachable",
            ));
        }
        Err(e) => {
            checks.push(Check::warn(
                "iCaptcha",
                format!("{icaptcha_url} unreachable: {e}"),
                "set GITLAWB_ICAPTCHA_URL or check connectivity — repo create / register solve a challenge there",
            ));
        }
    }

    // ── 5. git-remote-gitlawb helper ──────────────────────────────────────
    // Use PATH lookup only — invoking the binary directly triggers git internals
    // that error with "fatal: not a git repository" outside of a git repo.
    if which_in_path("git-remote-gitlawb") {
        checks.push(Check::pass("git-remote-gitlawb", "found in PATH"));
    } else {
        checks.push(Check::fail(
            "git-remote-gitlawb",
            "not found in PATH — gitlawb:// clone/push will not work",
            "curl -sSf https://gitlawb.com/install.sh | sh",
        ));
    }

    // ── 5b. shell alias shadowing ─────────────────────────────────────────
    // oh-my-zsh's default `git` plugin aliases gl='git pull', which silently
    // shadows this binary in every interactive zsh — the classic symptom is
    // `gl` printing "fatal: not a git repository". Aliases beat PATH, so no
    // install method can fix it; the user's rc file has to unalias.
    if let Some(check) = check_shell_alias_shadowing(dirs::home_dir()) {
        checks.push(check);
    }

    // ── 6. git ────────────────────────────────────────────────────────────
    match std::process::Command::new("git")
        .arg("--version")
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => {
            let ver = String::from_utf8_lossy(&o.stdout);
            checks.push(Check::pass("git", ver.trim().to_string()));
        }
        _ => {
            checks.push(Check::fail(
                "git",
                "git not found in PATH",
                "install git: https://git-scm.com",
            ));
        }
    }

    // ── 7. Version up to date ─────────────────────────────────────────────
    let current = env!("CARGO_PKG_VERSION");
    checks.push(check_version(current, GITHUB_API_BASE).await);

    // ── Render ────────────────────────────────────────────────────────────
    for check in &checks {
        let icon = match check.state {
            CheckState::Ok => "✓",
            CheckState::Warn => "⚠",
            CheckState::Fail => "✗",
        };
        println!("  {icon}  {:<24}  {}", check.label, check.detail);
        if matches!(check.state, CheckState::Fail) {
            all_ok = false;
        }
    }

    println!();

    let has_issues = checks
        .iter()
        .any(|c| matches!(c.state, CheckState::Fail | CheckState::Warn));
    if !has_issues {
        println!("Everything looks good. Run `gl quickstart` to create your first repo.");
    } else {
        if all_ok {
            println!("Setup looks good with some warnings:");
        } else {
            println!("Some checks failed. Suggested fixes:");
        }
        for check in &checks {
            if matches!(check.state, CheckState::Fail | CheckState::Warn) {
                if let Some(fix) = &check.fix {
                    println!("  {}:  {fix}", check.label);
                }
            }
        }
        println!();
        if !all_ok {
            println!("Run `gl quickstart` for a guided setup.");
        }
    }

    Ok(())
}

/// Check if a binary name exists anywhere on PATH.
/// True when the rc file contains a real `unalias` command naming `gl` —
/// not a comment, and not a longer word like `unalias global`. Ordering
/// relative to oh-my-zsh loading is not modeled (an unalias placed before the
/// plugin loads would be ineffective); acceptable slack for a warning check.
fn rc_unaliases_gl(rc: &str) -> bool {
    rc.lines().any(|line| {
        let line = line.trim_start();
        if line.starts_with('#') {
            return false;
        }
        line.split([';', '&', '|']).any(|cmd| {
            // A trailing comment must not count: `unalias foo  # gl`
            let cmd = cmd.split('#').next().unwrap_or("");
            let mut tokens = cmd.split_whitespace();
            tokens.next() == Some("unalias") && tokens.any(|t| t == "gl")
        })
    })
}

/// True when the URL's host is exactly a loopback address. Substring checks
/// misclassify hosts like `localhost.example` or URLs with "localhost" in the
/// path, so parse and compare the actual host.
fn is_loopback_url(value: &str) -> bool {
    reqwest::Url::parse(value)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]" || h == "::1")
        })
        .unwrap_or(false)
}

/// Detect interactive-shell setups where an alias shadows `gl` (aliases beat
/// PATH, so no install method can fix this). Best-effort heuristic over
/// ~/.zshrc: an explicit `alias gl=`, or oh-my-zsh's `git` plugin (which
/// ships gl='git pull'). Returns None when nothing suspicious is found or the
/// rc file already contains an `unalias gl`.
fn check_shell_alias_shadowing(home: Option<PathBuf>) -> Option<Check> {
    let home = home?;
    let rc = std::fs::read_to_string(home.join(".zshrc")).ok()?;
    if rc_unaliases_gl(&rc) {
        return None;
    }

    let explicit_alias = rc.lines().any(|l| l.trim_start().starts_with("alias gl="));
    // Single-line `plugins=(git ...)` is the overwhelmingly common form; a
    // multi-line plugins array slips past this heuristic, which is acceptable
    // for a warning-level check.
    let omz_git_plugin = home.join(".oh-my-zsh/plugins/git").exists()
        && rc.lines().any(|l| {
            let l = l.trim_start();
            l.starts_with("plugins=")
                && l.trim_start_matches("plugins=(")
                    .trim_end_matches(')')
                    .split_whitespace()
                    .any(|p| p == "git")
        });

    if explicit_alias || omz_git_plugin {
        let source = if explicit_alias {
            "~/.zshrc defines `alias gl=`"
        } else {
            "oh-my-zsh's git plugin aliases gl='git pull'"
        };
        Some(Check::warn(
            "shell alias",
            format!(
                "{source} — interactive shells run that instead of this binary \
                 (symptom: `gl` prints \"fatal: not a git repository\")"
            ),
            "echo 'unalias gl 2>/dev/null' >> ~/.zshrc && source ~/.zshrc  (must come after oh-my-zsh loads)",
        ))
    } else {
        None
    }
}

fn which_in_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                dir.join(name).exists()
                    || (cfg!(target_os = "windows") && dir.join(format!("{name}.exe")).exists())
            })
        })
        .unwrap_or(false)
}

/// Fetch the latest release tag from Gitlawb/node (the actual release repo — see install.sh's
/// `GITLAWB_RELEASE_REPO` default) and compare to current version.
async fn check_version(current: &'static str, github_api_base: &str) -> Check {
    let client = match reqwest::Client::builder()
        .user_agent(format!("gl/{current}"))
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Check::pass("version", format!("v{current} (could not check)")),
    };

    let resp = match client
        .get(format!(
            "{github_api_base}/repos/Gitlawb/node/releases/latest"
        ))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return Check::pass("version", format!("v{current} (offline — could not check)")),
    };

    if !resp.status().is_success() {
        return Check::pass(
            "version",
            format!("v{current} (GitHub API returned HTTP {})", resp.status()),
        );
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Check::pass("version", format!("v{current} (invalid response)")),
    };

    let tag = match body["tag_name"].as_str() {
        Some(t) => t.trim_start_matches('v'),
        None => {
            return Check::pass(
                "version",
                format!("v{current} (could not parse latest tag)"),
            )
        }
    };

    if is_newer(tag, current) {
        Check::warn(
            "version",
            format!("v{current} → v{tag} available"),
            "curl -sSf https://gitlawb.com/install.sh | sh",
        )
    } else {
        Check::pass("version", format!("v{current} (up to date)"))
    }
}

/// Returns true if `latest` is strictly newer than `current` (simple semver comparison).
fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> (u32, u32, u32) {
        let mut parts = v.splitn(3, '.').map(|p| p.parse::<u32>().unwrap_or(0));
        (
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
            parts.next().unwrap_or(0),
        )
    }
    parse(latest) > parse(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_home(zshrc: Option<&str>, with_omz_git: bool) -> tempfile::TempDir {
        let home = tempfile::TempDir::new().unwrap();
        if let Some(rc) = zshrc {
            std::fs::write(home.path().join(".zshrc"), rc).unwrap();
        }
        if with_omz_git {
            std::fs::create_dir_all(home.path().join(".oh-my-zsh/plugins/git")).unwrap();
        }
        home
    }

    #[test]
    fn alias_shadowing_flags_omz_git_plugin() {
        let home = fake_home(Some("plugins=(git z)\nsource $ZSH/oh-my-zsh.sh\n"), true);
        let check = check_shell_alias_shadowing(Some(home.path().to_path_buf()));
        assert!(check.is_some(), "omz git plugin without unalias must warn");
    }

    #[test]
    fn alias_shadowing_flags_explicit_alias() {
        let home = fake_home(Some("alias gl='git pull'\n"), false);
        assert!(check_shell_alias_shadowing(Some(home.path().to_path_buf())).is_some());
    }

    #[test]
    fn alias_shadowing_silent_when_unaliased() {
        let home = fake_home(
            Some("plugins=(git z)\nsource $ZSH/oh-my-zsh.sh\nunalias gl 2>/dev/null\n"),
            true,
        );
        assert!(check_shell_alias_shadowing(Some(home.path().to_path_buf())).is_none());
    }

    #[test]
    fn alias_shadowing_ignores_fake_unaliases() {
        // None of these actually free `gl` — the warning must survive them.
        for rc in [
            "plugins=(git)\n# unalias gl\n",          // commented out
            "plugins=(git)\nunalias global\n",        // longer word
            "plugins=(git)\nunalias foo  # gl\n",     // gl only in a comment
            "plugins=(git)\necho unalias-gl-later\n", // not an unalias command
        ] {
            let home = fake_home(Some(rc), true);
            assert!(
                check_shell_alias_shadowing(Some(home.path().to_path_buf())).is_some(),
                "must still warn for rc: {rc:?}"
            );
        }
        // Real unalias forms that do free it — all must silence the warning.
        for rc in [
            "plugins=(git)\nunalias gl\n",
            "plugins=(git)\nunalias gl 2>/dev/null\n",
            "plugins=(git)\ntrue; unalias gl\n",
            "plugins=(git)\nunalias glog gl gst\n",
        ] {
            let home = fake_home(Some(rc), true);
            assert!(
                check_shell_alias_shadowing(Some(home.path().to_path_buf())).is_none(),
                "must be silent for rc: {rc:?}"
            );
        }
    }

    #[test]
    fn loopback_url_detection_is_host_exact() {
        assert!(is_loopback_url("http://127.0.0.1:7545"));
        assert!(is_loopback_url("http://localhost:7545"));
        assert!(is_loopback_url("http://[::1]:7545"));
        assert!(!is_loopback_url("https://localhost.example"));
        assert!(!is_loopback_url("https://node.gitlawb.com/localhost"));
        assert!(!is_loopback_url("not a url"));
    }

    #[test]
    fn alias_shadowing_silent_without_signals() {
        let home = fake_home(Some("plugins=(z)\nexport EDITOR=vim\n"), false);
        assert!(check_shell_alias_shadowing(Some(home.path().to_path_buf())).is_none());
        let no_rc = fake_home(None, false);
        assert!(check_shell_alias_shadowing(Some(no_rc.path().to_path_buf())).is_none());
        assert!(check_shell_alias_shadowing(None).is_none());
    }

    #[test]
    fn test_is_newer_minor_bump() {
        assert!(is_newer("0.2.0", "0.1.0"));
    }

    #[test]
    fn test_is_newer_patch_bump() {
        assert!(is_newer("0.1.1", "0.1.0"));
    }

    #[test]
    fn test_is_newer_major_bump() {
        assert!(is_newer("1.0.0", "0.9.9"));
    }

    #[test]
    fn test_is_newer_same_version() {
        assert!(!is_newer("0.1.0", "0.1.0"));
    }

    #[test]
    fn test_is_newer_older_version() {
        assert!(!is_newer("0.1.0", "0.2.0"));
    }

    #[test]
    fn test_which_in_path_git_present() {
        // git should be installed on any dev machine
        assert!(which_in_path("git"));
    }

    #[test]
    fn test_which_in_path_missing_binary() {
        assert!(!which_in_path("this-binary-does-not-exist-gl-test-12345"));
    }

    #[tokio::test]
    async fn test_check_version_queries_gitlawb_node_releases() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/Gitlawb/node/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tag_name":"v9.9.9"}"#)
            .create_async()
            .await;

        let check = check_version("0.1.0", &server.url()).await;
        assert!(matches!(check.state, CheckState::Warn));
        assert!(check.detail.contains("v9.9.9"));
    }

    #[tokio::test]
    async fn test_check_version_up_to_date() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/Gitlawb/node/releases/latest")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"tag_name":"v0.1.0"}"#)
            .create_async()
            .await;

        let check = check_version("0.1.0", &server.url()).await;
        assert!(matches!(check.state, CheckState::Ok));
        assert!(check.detail.contains("up to date"));
    }

    #[tokio::test]
    async fn test_check_version_http_error() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/repos/Gitlawb/node/releases/latest")
            .with_status(403)
            .create_async()
            .await;

        let check = check_version("0.1.0", &server.url()).await;
        assert!(matches!(check.state, CheckState::Ok));
        assert!(check.detail.contains("GitHub API returned HTTP 403"));
    }
}
