//! `gl clone`: clean partial clone of a gitlawb repo with private subtrees.
//!
//! A repo may withhold blob content under some path globs from the caller
//! (Phase 3). The resulting pack is not closed under reachability, so a stock
//! `git clone` is refused at fetch. This command clones as a promisor
//! (`--filter=blob:none`) and sparse-excludes the caller's withheld globs,
//! producing a clean checkout: public files present, private paths absent.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Deserialize;
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

    /// Arweave gateway for B3 manifest discovery/fetch when a node cannot supply
    /// the encrypted-blob mapping.
    #[arg(
        long,
        default_value = "https://arweave.net",
        env = "GITLAWB_ARWEAVE_GATEWAY"
    )]
    pub arweave_gateway: String,

    /// Public IPFS gateway for fetching encrypted envelopes during B3 recovery.
    #[arg(
        long,
        default_value = "https://dweb.link",
        env = "GITLAWB_IPFS_GATEWAY"
    )]
    pub ipfs_gateway: String,
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
    // Non-cone sparse-checkout, gitignore-style: include everything, exclude the
    // withheld globs, then re-include any allowed globs nested under an excluded
    // one. Emitting all excludes before the re-includes is safe even for deeper
    // re-denials (deny /secret, allow /secret/public, deny /secret/public/admin):
    // git does not re-traverse an explicitly excluded directory, so a broader
    // parent re-include never resurrects a more specific excluded subtree.
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
            // Read the default branch from the local `origin/HEAD` symref that
            // clone just set, instead of parsing `git remote show origin`, whose
            // "HEAD branch:" line is localized and needs a network round-trip.
            let out = Command::new("git")
                .args(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])
                .current_dir(dest)
                .output()?;
            if !out.status.success() {
                bail!(
                    "could not determine default branch: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            let symref = String::from_utf8_lossy(&out.stdout);
            let head = symref
                .trim()
                .strip_prefix("origin/")
                .context("unexpected origin/HEAD format")?;
            git(dest, &["checkout", "-q", head])?;
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
    let body: WithheldPathsResponse = resp
        .json()
        .await
        .context("parsing withheld-paths response")?;
    Ok((body.withheld, body.reinclude))
}

/// The node's `/withheld-paths` 200 body. Both fields are always emitted as JSON
/// arrays; deserializing into this struct (rather than poking at a `Value`) makes
/// a missing or mistyped field a hard error instead of silently becoming `[]`,
/// which would mask a server regression behind a confusing later clone failure.
#[derive(Deserialize)]
struct WithheldPathsResponse {
    withheld: Vec<String>,
    reinclude: Vec<String>,
}

/// After the base clone, recover encrypted blobs the caller is authorized for
/// that are missing locally: fetch the envelope, decrypt with the caller's key,
/// install as a loose object. Returns the repo-relative paths recovered.
/// Best-effort; logs and continues on any per-blob failure.
async fn recover_encrypted_blobs(
    node: &str,
    owner: &str,
    name: &str,
    dest: &Path,
    keypair: &gitlawb_core::identity::Keypair,
) -> Result<Vec<String>> {
    use gitlawb_core::encrypt::open_blob;
    use std::collections::HashMap;
    use std::io::Write;

    let dest_str = dest.to_str().context("dest path not utf-8")?;
    let client = NodeClient::new(node, Some(keypair.clone()));

    let resp = match client
        .get_signed(&format!("/api/v1/repos/{owner}/{name}/encrypted-blobs"))
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Ok(vec![]),
    };
    let body: serde_json::Value = resp.json().await.context("parsing encrypted-blobs")?;
    let blobs = body
        .get("blobs")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    if blobs.is_empty() {
        return Ok(vec![]);
    }

    // Map oid -> repo-relative path from the cloned tree.
    let ls = Command::new("git")
        .args(["-C", dest_str, "ls-tree", "-r", "HEAD"])
        .output()?;
    let mut oid_to_path: HashMap<String, String> = HashMap::new();
    for line in String::from_utf8_lossy(&ls.stdout).lines() {
        if let Some((meta, path)) = line.split_once('\t') {
            if let Some(oid) = meta.split_whitespace().nth(2) {
                oid_to_path.insert(oid.to_string(), path.to_string());
            }
        }
    }

    let mut recovered = Vec::new();
    for entry in blobs {
        let Some(oid) = entry.get("oid").and_then(|o| o.as_str()) else {
            continue;
        };
        // Skip if already present locally.
        let present = Command::new("git")
            .args(["-C", dest_str, "cat-file", "-e", oid])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if present {
            continue;
        }
        let env_resp = match client
            .get_signed(&format!(
                "/api/v1/repos/{owner}/{name}/encrypted-blob/{oid}"
            ))
            .await
        {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let Ok(envelope) = env_resp.bytes().await else {
            continue;
        };
        let plaintext = match open_blob(&envelope, keypair) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: could not decrypt {oid}: {e}");
                continue;
            }
        };
        // Install as a loose object; verify the OID matches.
        let mut child = Command::new("git")
            .args(["-C", dest_str, "hash-object", "-w", "-t", "blob", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(&plaintext)?;
        let out = child.wait_with_output()?;
        let written = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if written == oid {
            if let Some(p) = oid_to_path.get(oid) {
                recovered.push(p.clone());
            }
        } else {
            eprintln!("warning: recovered blob {oid} hashed to {written}; discarding");
        }
    }
    Ok(recovered)
}

/// One blob entry in an Arweave-anchored encrypted manifest. The manifest also
/// carries a `recipients` field per blob, but `gl` does not need it: authorization
/// is enforced by whether `open_blob` can decrypt with the caller's key. Unknown
/// JSON fields are ignored by serde, so `recipients` is simply not declared here.
#[derive(Deserialize)]
struct ManifestBlob {
    oid: String,
    cid: String,
}

/// An Arweave-anchored per-push encrypted manifest (Option B3).
#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    blobs: Vec<ManifestBlob>,
}

/// Extract transaction ids from an Arweave GraphQL `transactions` response.
fn parse_tx_ids(v: &serde_json::Value) -> Vec<String> {
    v.get("data")
        .and_then(|d| d.get("transactions"))
        .and_then(|t| t.get("edges"))
        .and_then(|e| e.as_array())
        .map(|edges| {
            edges
                .iter()
                .filter_map(|edge| {
                    edge.get("node")
                        .and_then(|n| n.get("id"))
                        .and_then(|i| i.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Merge per-push manifests into a single `oid -> cid` map, latest-wins by the
/// manifest `timestamp` (RFC3339, compared lexicographically; a later push that
/// re-sealed a blob overrides the earlier entry).
fn merge_manifests(manifests: Vec<Manifest>) -> std::collections::HashMap<String, String> {
    let mut best: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new(); // oid -> (cid, timestamp)
    for m in manifests {
        for b in m.blobs {
            match best.get(&b.oid) {
                Some((_, ts)) if ts.as_str() >= m.timestamp.as_str() => {}
                _ => {
                    best.insert(b.oid, (b.cid, m.timestamp.clone()));
                }
            }
        }
    }
    best.into_iter().map(|(oid, (cid, _))| (oid, cid)).collect()
}

/// Option B3 fallback recovery, with no dependency on a gitlawb node API. Query
/// the Arweave gateway for this repo's encrypted manifests, merge them, and for
/// each blob still missing locally that the caller can decrypt, pull the envelope
/// from a public IPFS gateway, decrypt, and install it as a loose object. Returns
/// the repo-relative paths recovered. Best-effort; silent when gateways are
/// unreachable, leaving the clone exactly as node-based recovery left it.
async fn recover_from_arweave(
    arweave_gateway: &str,
    ipfs_gateway: &str,
    owner: &str,
    name: &str,
    dest: &Path,
    keypair: &gitlawb_core::identity::Keypair,
) -> Result<Vec<String>> {
    use gitlawb_core::encrypt::open_blob;
    use std::collections::HashMap;
    use std::io::Write;

    let dest_str = dest.to_str().context("dest path not utf-8")?;
    let owner_short = owner.split(':').next_back().unwrap_or(owner);
    let slug = format!("{owner_short}/{name}");
    let ag = arweave_gateway.trim_end_matches('/');
    let ig = ipfs_gateway.trim_end_matches('/');
    let client = reqwest::Client::new();

    // 1. Discover manifest transaction ids via Arweave GraphQL.
    let query = r#"query($repo:String!){transactions(tags:[{name:"App-Name",values:["gitlawb"]},{name:"Schema",values:["gitlawb/encrypted-manifest/v1"]},{name:"Repo",values:[$repo]}],first:100){edges{node{id}}}}"#;
    let gql_body = serde_json::json!({ "query": query, "variables": { "repo": slug } });
    let resp = match client
        .post(format!("{ag}/graphql"))
        .json(&gql_body)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Ok(vec![]),
    };
    let gql: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return Ok(vec![]),
    };
    let tx_ids = parse_tx_ids(&gql);
    if tx_ids.is_empty() {
        return Ok(vec![]);
    }

    // 2. Fetch and parse each manifest body, then merge latest-wins per oid.
    let mut manifests = Vec::new();
    for tx in tx_ids {
        let m = match client.get(format!("{ag}/{tx}")).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        if let Ok(parsed) = m.json::<Manifest>().await {
            manifests.push(parsed);
        }
    }
    let oid_cid = merge_manifests(manifests);
    if oid_cid.is_empty() {
        return Ok(vec![]);
    }

    // Map oid -> repo-relative path from the cloned tree.
    let ls = Command::new("git")
        .args(["-C", dest_str, "ls-tree", "-r", "HEAD"])
        .output()?;
    let mut oid_to_path: HashMap<String, String> = HashMap::new();
    for line in String::from_utf8_lossy(&ls.stdout).lines() {
        if let Some((meta, path)) = line.split_once('\t') {
            if let Some(oid) = meta.split_whitespace().nth(2) {
                oid_to_path.insert(oid.to_string(), path.to_string());
            }
        }
    }

    // 3. Recover each missing blob the caller can decrypt.
    let mut recovered = Vec::new();
    for (oid, cid) in oid_cid {
        let present = Command::new("git")
            .args(["-C", dest_str, "cat-file", "-e", &oid])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if present {
            continue;
        }
        let env_resp = match client.get(format!("{ig}/ipfs/{cid}")).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let Ok(envelope) = env_resp.bytes().await else {
            continue;
        };
        // open_blob succeeds only if this caller is a recipient: this is the
        // authorization gate (no node, no DID check needed).
        let plaintext = match open_blob(&envelope, keypair) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let mut child = Command::new("git")
            .args(["-C", dest_str, "hash-object", "-w", "-t", "blob", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(&plaintext)?;
        let out = child.wait_with_output()?;
        let written = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if written == oid {
            if let Some(p) = oid_to_path.get(&oid) {
                recovered.push(p.clone());
            }
        } else {
            eprintln!("warning: recovered blob {oid} hashed to {written}; discarding");
        }
    }
    Ok(recovered)
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

    if let Ok(keypair) = load_keypair_from_dir(None) {
        // Node-based recovery first (B1/B2), then the B3 Arweave/IPFS gateway
        // fallback for any authorized blobs the node could not supply.
        let mut paths = recover_encrypted_blobs(&args.node, &owner, &name, &dest, &keypair)
            .await
            .unwrap_or_default();
        let from_arweave = recover_from_arweave(
            &args.arweave_gateway,
            &args.ipfs_gateway,
            &owner,
            &name,
            &dest,
            &keypair,
        )
        .await
        .unwrap_or_default();
        paths.extend(from_arweave);

        if !paths.is_empty() {
            // Re-include recovered paths if this was a sparse clone, then
            // materialize them in the working tree.
            let spec = dest.join(".git/info/sparse-checkout");
            if spec.exists() {
                if let Ok(mut s) = std::fs::read_to_string(&spec) {
                    for p in &paths {
                        s.push_str(&format!("/{p}\n"));
                    }
                    let _ = std::fs::write(&spec, s);
                }
            }
            let _ = git(&dest, &["checkout", "--", "."]);
            println!(
                "Recovered {} private file(s) you are authorized to read",
                paths.len()
            );
        }
    }

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
    fn three_level_alternating_nesting_respects_specificity() {
        // deny /secret, allow /secret/public, deny /secret/public/admin.
        // The deepest deny must win even though a shallower allow re-includes
        // its parent: order patterns by depth, not all-excludes-then-includes.
        let (td, url) = bare_remote(&[
            ("public/a.txt", b"pub\n"),
            ("secret/private/p.txt", b"PRIV\n"),
            ("secret/public/s.txt", b"SHARED\n"),
            ("secret/public/admin/k.txt", b"ADMIN\n"),
        ]);
        let dest = td.path().join("dest");
        setup_partial_clone(
            &dest,
            &url,
            &[
                "/secret/**".to_string(),
                "/secret/public/admin/**".to_string(),
            ],
            &["/secret/public/**".to_string()],
            None,
        )
        .unwrap();

        assert!(dest.join("public/a.txt").exists(), "public present");
        assert!(
            dest.join("secret/public/s.txt").exists(),
            "allowed middle path must be re-included"
        );
        assert!(
            !dest.join("secret/private/p.txt").exists(),
            "denied sibling must stay excluded"
        );
        assert!(
            !dest.join("secret/public/admin/k.txt").exists(),
            "deepest denied path must stay excluded despite the shallower re-include"
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
    fn withheld_response_requires_both_fields() {
        let ok: WithheldPathsResponse =
            serde_json::from_str(r#"{"withheld":["/secret/**"],"reinclude":[]}"#).unwrap();
        assert_eq!(ok.withheld, vec!["/secret/**".to_string()]);
        assert!(ok.reinclude.is_empty());

        // A missing field is a schema mismatch: it must error, not default to [].
        assert!(serde_json::from_str::<WithheldPathsResponse>(r#"{"withheld":[]}"#).is_err());
        // A wrong-typed field must error too.
        assert!(serde_json::from_str::<WithheldPathsResponse>(
            r#"{"withheld":"nope","reinclude":[]}"#
        )
        .is_err());
    }

    #[test]
    fn parse_tx_ids_extracts_node_ids() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"data":{"transactions":{"edges":[{"node":{"id":"TX1"}},{"node":{"id":"TX2"}}]}}}"#,
        )
        .unwrap();
        assert_eq!(parse_tx_ids(&v), vec!["TX1".to_string(), "TX2".to_string()]);
    }

    #[test]
    fn parse_tx_ids_empty_on_no_edges() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"data":{"transactions":{"edges":[]}}}"#).unwrap();
        assert!(parse_tx_ids(&v).is_empty());
    }

    #[test]
    fn manifest_parses_and_ignores_recipients() {
        let m: Manifest = serde_json::from_str(
            r#"{"timestamp":"2026-06-11T00:00:00Z","blobs":[{"oid":"o1","cid":"c1","recipients":["did:key:zA"]}]}"#,
        )
        .unwrap();
        assert_eq!(m.timestamp, "2026-06-11T00:00:00Z");
        assert_eq!(m.blobs.len(), 1);
        assert_eq!(m.blobs[0].oid, "o1");
        assert_eq!(m.blobs[0].cid, "c1");
    }

    #[test]
    fn merge_manifests_latest_wins_per_oid() {
        let older = Manifest {
            timestamp: "2026-06-10T00:00:00Z".to_string(),
            blobs: vec![ManifestBlob {
                oid: "o1".to_string(),
                cid: "cidOLD".to_string(),
            }],
        };
        let newer = Manifest {
            timestamp: "2026-06-11T00:00:00Z".to_string(),
            blobs: vec![
                ManifestBlob {
                    oid: "o1".to_string(),
                    cid: "cidNEW".to_string(),
                },
                ManifestBlob {
                    oid: "o2".to_string(),
                    cid: "cid2".to_string(),
                },
            ],
        };
        let merged = merge_manifests(vec![older, newer]);
        assert_eq!(merged.get("o1").map(String::as_str), Some("cidNEW"));
        assert_eq!(merged.get("o2").map(String::as_str), Some("cid2"));
    }

    #[test]
    fn merge_manifests_is_order_independent() {
        let older = Manifest {
            timestamp: "2026-06-10T00:00:00Z".to_string(),
            blobs: vec![ManifestBlob {
                oid: "o1".to_string(),
                cid: "cidOLD".to_string(),
            }],
        };
        let newer = Manifest {
            timestamp: "2026-06-11T00:00:00Z".to_string(),
            blobs: vec![ManifestBlob {
                oid: "o1".to_string(),
                cid: "cidNEW".to_string(),
            }],
        };
        // Newer first, older second: newer must still win.
        let merged = merge_manifests(vec![newer, older]);
        assert_eq!(merged.get("o1").map(String::as_str), Some("cidNEW"));
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

    #[test]
    fn recovered_blob_installs_with_matching_oid() {
        use gitlawb_core::encrypt::{open_blob, seal_blob};
        use gitlawb_core::identity::Keypair;
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("dest");
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();
        let oid = {
            let out = std::process::Command::new("git")
                .args([
                    "-C",
                    dest.to_str().unwrap(),
                    "rev-parse",
                    "HEAD:secret/b.txt",
                ])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let reader = Keypair::generate();
        let env = seal_blob(b"SECRET\n", &[reader.verifying_key()]).unwrap();
        let plaintext = open_blob(&env, &reader).unwrap();
        let mut child = std::process::Command::new("git")
            .args([
                "-C",
                dest.to_str().unwrap(),
                "hash-object",
                "-w",
                "-t",
                "blob",
                "--stdin",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(&plaintext).unwrap();
        let out = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), oid);
    }
}
