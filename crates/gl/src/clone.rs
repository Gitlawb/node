//! `gl clone`: clean partial clone of a gitlawb repo with private subtrees.
//!
//! A repo may withhold blob content under some path globs from the caller
//! (Phase 3). The resulting pack is not closed under reachability, so a stock
//! `git clone` is refused at fetch. This command clones as a promisor
//! (`--filter=blob:none`) and sparse-excludes the caller's withheld globs,
//! producing a clean checkout: public files present, private paths absent.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde_json::Value;
use std::path::Path;
use std::process::Command;

use crate::http::NodeClient;
use crate::identity::load_keypair_from_dir;

#[derive(Args)]
pub struct CloneArgs {
    /// Repo to clone: gitlawb://<owner_did>/<name> or <owner>/<name>.
    pub repo: String,

    /// Destination directory (default: the repo name).
    pub dir: Option<String>,

    /// Branch to check out (default: the remote's default branch).
    #[arg(long)]
    pub branch: Option<String>,

    #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
    pub node: String,
}

/// Run a git command inside `dir`, erroring with stderr on failure.
fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("running git {args:?}"))?;
    if !out.status.success() {
        bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Run a git command not tied to a working tree (e.g. `clone`).
fn git_global(args: &[&str]) -> Result<()> {
    let out = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("running git {args:?}"))?;
    if !out.status.success() {
        bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Sparse-checkout pattern(s) for a visibility glob. A subtree glob
/// (`/secret/**`) maps to the directory `/secret/`. A wildcard-free glob
/// (`/docs/private`) matches both the exact path and a subtree at that path
/// (mirroring the node's `glob_matches`), so it maps to both `/docs/private`
/// and `/docs/private/`. Callers prefix these with `!` to exclude.
fn sparse_patterns(glob: &str) -> Vec<String> {
    match glob.strip_suffix("/**") {
        Some(base) => vec![format!("{base}/")],
        None => vec![glob.to_string(), format!("{glob}/")],
    }
}

/// Clone `remote_url` into `dest`, excluding `withheld_globs` from checkout.
/// `dest` must not already exist. With nothing withheld this is a plain full
/// clone. With globs withheld it clones as a promisor (`--filter=blob:none`,
/// marking the repo a promisor so the node's non-closed pack is accepted)
/// without checkout, sparse-excludes each glob, then checks out so the absent
/// blobs are never materialized. `--no-cone` is required for negated excludes.
pub fn setup_partial_clone(
    dest: &Path,
    remote_url: &str,
    withheld_globs: &[String],
    reinclude_globs: &[String],
    branch: Option<&str>,
) -> Result<()> {
    let dest_str = dest
        .to_str()
        .context("destination path is not valid UTF-8")?;

    if withheld_globs.is_empty() {
        match branch {
            Some(b) => git_global(&["clone", "-q", "--branch", b, remote_url, dest_str])?,
            None => git_global(&["clone", "-q", remote_url, dest_str])?,
        }
        return Ok(());
    }

    git_global(&[
        "clone",
        "-q",
        "--filter=blob:none",
        "--no-checkout",
        remote_url,
        dest_str,
    ])?;
    git(dest, &["sparse-checkout", "init", "--no-cone"])?;
    // Non-cone sparse-checkout, gitignore-style and order-sensitive: include
    // everything, exclude the withheld globs, then re-include any allowed globs
    // nested under an excluded one (later patterns win).
    let mut spec = String::from("/*\n");
    for g in withheld_globs {
        for pat in sparse_patterns(g) {
            spec.push('!');
            spec.push_str(&pat);
            spec.push('\n');
        }
    }
    for g in reinclude_globs {
        for pat in sparse_patterns(g) {
            spec.push_str(&pat);
            spec.push('\n');
        }
    }
    std::fs::write(dest.join(".git/info/sparse-checkout"), spec)
        .context("writing sparse-checkout spec")?;

    match branch {
        Some(b) => git(dest, &["checkout", "-q", b])?,
        None => {
            let out = Command::new("git")
                .args(["remote", "show", "origin"])
                .current_dir(dest)
                .output()?;
            let text = String::from_utf8_lossy(&out.stdout);
            let head = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("HEAD branch: "))
                .map(|s| s.to_string())
                .context("could not determine default branch")?;
            git(dest, &["checkout", "-q", &head])?;
        }
    }
    Ok(())
}

/// Parse `repo` into (gitlawb_url, owner, name). Accepts a full
/// `gitlawb://<owner>/<name>` URL or a bare `<owner>/<name>`. The owner DID may
/// itself contain colons but no slash, so split on the first slash.
fn parse_repo(repo: &str) -> Result<(String, String, String)> {
    let stripped = repo.strip_prefix("gitlawb://").unwrap_or(repo);
    let (owner, name) = stripped
        .trim_end_matches('/')
        .split_once('/')
        .context("repo must be <owner>/<name> or gitlawb://<owner>/<name>")?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        bail!("repo must be <owner>/<name> or gitlawb://<owner>/<name>");
    }
    Ok((
        format!("gitlawb://{owner}/{name}"),
        owner.to_string(),
        name.to_string(),
    ))
}

/// Ask the node which globs are withheld for this caller and which allowed globs
/// nested under them must be re-included. Returns `(withheld, reinclude)`. A
/// node that does not implement the endpoint (404/501) yields empties so public
/// repos on older nodes still clone normally. Other failures (network, auth,
/// 5xx, malformed JSON) are propagated: failing open here would silently fall
/// back to a stock clone, which the node refuses once blobs are withheld, hiding
/// the real cause behind a confusing fetch error.
async fn fetch_withheld(node: &str, owner: &str, name: &str) -> Result<(Vec<String>, Vec<String>)> {
    let kp = load_keypair_from_dir(None).ok();
    let signed = kp.is_some();
    let client = NodeClient::new(node, kp);
    let path = format!("/api/v1/repos/{owner}/{name}/withheld-paths");
    let resp = if signed {
        client.get_signed(&path).await
    } else {
        client.get(&path).await
    };
    let resp = match resp {
        Ok(r) if r.status().is_success() => r,
        Ok(r) if matches!(r.status().as_u16(), 404 | 501) => return Ok((Vec::new(), Vec::new())),
        Ok(r) => bail!("withheld-paths lookup failed: {}", r.status()),
        Err(err) => return Err(err).context("fetching withheld paths"),
    };
    let body: Value = resp
        .json()
        .await
        .context("parsing withheld-paths response")?;
    let globs = |field: &str| -> Vec<String> {
        body.get(field)
            .and_then(|w| w.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok((globs("withheld"), globs("reinclude")))
}

pub async fn run(args: CloneArgs) -> Result<()> {
    let (url, owner, name) = parse_repo(&args.repo)?;
    let dest_name = args.dir.unwrap_or_else(|| name.clone());
    let dest = std::path::PathBuf::from(&dest_name);
    if dest.exists() {
        bail!("destination '{dest_name}' already exists");
    }

    let (withheld, reinclude) = fetch_withheld(&args.node, &owner, &name).await?;
    if withheld.is_empty() {
        println!("Cloning {url} into {dest_name}");
    } else {
        println!(
            "Cloning {url} into {dest_name} ({} private path(s) excluded)",
            withheld.len()
        );
    }

    setup_partial_clone(&dest, &url, &withheld, &reinclude, args.branch.as_deref())?;
    println!("Done. Cloned into {dest_name}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    fn g(args: &[&str], dir: &Path) {
        assert!(Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn setup_partial_clone_excludes_withheld_path() {
        let td = TempDir::new().unwrap();
        let origin = td.path().join("origin");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(origin.join("secret")).unwrap();
        std::fs::create_dir_all(origin.join("public")).unwrap();
        std::fs::write(origin.join("public/a.txt"), b"pub\n").unwrap();
        std::fs::write(origin.join("secret/b.txt"), b"SECRET\n").unwrap();
        g(&["init", "-q"], &origin);
        g(&["config", "user.email", "t@t"], &origin);
        g(&["config", "user.name", "t"], &origin);
        g(&["add", "."], &origin);
        g(&["commit", "-qm", "init"], &origin);
        g(
            &[
                "clone",
                "-q",
                "--bare",
                origin.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        // file:// so --filter is honored (local-path clones ignore it).
        let dest = td.path().join("dest");
        let url = format!("file://{}", bare.display());
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();

        assert!(dest.join("public/a.txt").exists(), "public file present");
        assert!(
            !dest.join("secret/b.txt").exists(),
            "withheld path must be excluded from checkout"
        );
    }

    /// Build a bare remote with the given files (relative path -> contents),
    /// committed on one branch. Returns (tempdir, file:// url).
    fn bare_remote(files: &[(&str, &[u8])]) -> (TempDir, String) {
        let td = TempDir::new().unwrap();
        let origin = td.path().join("origin");
        let bare = td.path().join("bare.git");
        for (path, contents) in files {
            let full = origin.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, contents).unwrap();
        }
        g(&["init", "-q"], &origin);
        g(&["config", "user.email", "t@t"], &origin);
        g(&["config", "user.name", "t"], &origin);
        g(&["add", "."], &origin);
        g(&["commit", "-qm", "init"], &origin);
        g(
            &[
                "clone",
                "-q",
                "--bare",
                origin.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        let url = format!("file://{}", bare.display());
        (td, url)
    }

    #[test]
    fn reinclude_restores_allowed_nested_path() {
        let (td, url) = bare_remote(&[
            ("public/a.txt", b"pub\n"),
            ("secret/private/p.txt", b"PRIV\n"),
            ("secret/public/s.txt", b"SHARED\n"),
        ]);
        let dest = td.path().join("dest");
        setup_partial_clone(
            &dest,
            &url,
            &["/secret/**".to_string()],
            &["/secret/public/**".to_string()],
            None,
        )
        .unwrap();

        assert!(dest.join("public/a.txt").exists(), "public present");
        assert!(
            dest.join("secret/public/s.txt").exists(),
            "allowed nested path must be re-included"
        );
        assert!(
            !dest.join("secret/private/p.txt").exists(),
            "denied nested path must stay excluded"
        );
    }

    #[test]
    fn exact_path_glob_is_excluded() {
        // A wildcard-free glob must exclude the exact file, not just a subtree.
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("docs/private", b"SECRET\n")]);
        let dest = td.path().join("dest");
        setup_partial_clone(&dest, &url, &["/docs/private".to_string()], &[], None).unwrap();

        assert!(dest.join("public/a.txt").exists(), "public present");
        assert!(
            !dest.join("docs/private").exists(),
            "exact-path withheld file must be excluded"
        );
    }

    #[test]
    fn sparse_patterns_subtree_and_exact() {
        assert_eq!(sparse_patterns("/secret/**"), vec!["/secret/".to_string()]);
        assert_eq!(
            sparse_patterns("/docs/private"),
            vec!["/docs/private".to_string(), "/docs/private/".to_string()]
        );
    }

    #[test]
    fn parse_repo_accepts_url_and_bare() {
        let (url, o, n) = parse_repo("gitlawb://did:key:zAbc/myrepo").unwrap();
        assert_eq!(url, "gitlawb://did:key:zAbc/myrepo");
        assert_eq!((o.as_str(), n.as_str()), ("did:key:zAbc", "myrepo"));

        let (url2, o2, n2) = parse_repo("did:key:zAbc/myrepo").unwrap();
        assert_eq!(url2, "gitlawb://did:key:zAbc/myrepo");
        assert_eq!((o2.as_str(), n2.as_str()), ("did:key:zAbc", "myrepo"));
    }

    #[test]
    fn parse_repo_rejects_malformed() {
        assert!(parse_repo("noslash").is_err());
        assert!(parse_repo("gitlawb://owner/").is_err());
        assert!(parse_repo("/name").is_err());
        // An extra slash would otherwise smuggle a path segment into the name.
        assert!(parse_repo("owner/name/extra").is_err());
    }
}
