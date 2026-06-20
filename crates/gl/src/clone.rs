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

/// The node's `/encrypted-blobs` 200 body. Same rationale as `WithheldPathsResponse`:
/// deserializing into a typed struct makes a missing or mistyped `blobs` field (or a
/// blob entry missing its `oid`) a hard error instead of silently becoming "nothing
/// to recover", which would mask a server schema regression behind a clone that
/// quietly omits authorized files. Unknown server fields (e.g. `size`) are ignored
/// by serde, so the response may carry extra keys without breaking.
#[derive(Deserialize)]
struct EncryptedBlobsResponse {
    blobs: Vec<EncryptedBlobEntry>,
}

#[derive(Deserialize)]
struct EncryptedBlobEntry {
    oid: String,
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
    let body: EncryptedBlobsResponse = resp.json().await.context("parsing encrypted-blobs")?;
    if body.blobs.is_empty() {
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
    for entry in body.blobs {
        let oid = entry.oid.as_str();
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

/// One discovered manifest transaction: its Arweave id and block height. The
/// height is `None` only when the anchor is not yet mined (no `block`), in which
/// case it is the most recent and sorts as newest in the merge tie-break. A mined
/// anchor is always `Some(_)` (0 if the gateway reported an unreadable height) so
/// a malformed height can never masquerade as pending/newest.
struct TxRef {
    id: String,
    height: Option<u64>,
}

/// Edges requested per Arweave GraphQL page (`first:` in the discovery query) and
/// the per-page bound enforced when parsing a response. The `first:N` literal in
/// the query string MUST equal this constant.
const ARWEAVE_PAGE_SIZE: usize = 100;

/// A parsed page of an Arweave GraphQL `transactions` response: the edge refs
/// plus pagination state. `has_next` is `None` when the response omitted
/// `pageInfo` entirely (an older or partial gateway), which the discovery loop
/// treats as terminal but flags when the page was full (possible truncation).
struct TxPage {
    refs: Vec<TxRef>,
    has_next: Option<bool>,
    end_cursor: Option<String>,
}

/// Parse one Arweave GraphQL `transactions` page: each edge's tx id and block
/// height, plus `pageInfo` for cursor pagination. Hand-walks the `Value` (the
/// envelope nests `data.transactions.{edges,pageInfo}`) rather than deriving a
/// wrapper struct, matching the surrounding style.
///
/// At most `ARWEAVE_PAGE_SIZE` edges are taken from a single page: the query asks
/// for `first:100`, so a response with more edges is a misbehaving (or hostile)
/// gateway. Bounding here caps per-page allocation and the downstream per-id fetch
/// loop so the `MAX_TX_IDS` budget can't be defeated by one oversized page.
fn parse_tx_page(v: &serde_json::Value) -> TxPage {
    let txns = v.get("data").and_then(|d| d.get("transactions"));
    let refs: Vec<TxRef> = txns
        .and_then(|t| t.get("edges"))
        .and_then(|e| e.as_array())
        .map(|edges| {
            edges
                .iter()
                .take(ARWEAVE_PAGE_SIZE)
                .filter_map(|edge| {
                    let node = edge.get("node")?;
                    let id = node.get("id").and_then(|i| i.as_str())?.to_string();
                    // Distinguish "not yet mined" from "mined but height unreadable".
                    // Only a genuinely absent/null `block` is pending (`None`,
                    // ranked newest). A present `block` means the anchor IS mined, so
                    // it must not be promoted to newest: parse the height permissively
                    // (number or numeric string, guarding a gateway that stringifies
                    // large ints), and an unreadable height ranks lowest (0) rather
                    // than collapsing to `None`/newest.
                    let height = match node.get("block") {
                        None | Some(serde_json::Value::Null) => None,
                        Some(b) => Some(
                            b.get("height")
                                .and_then(|h| {
                                    h.as_u64()
                                        .or_else(|| h.as_str().and_then(|s| s.parse::<u64>().ok()))
                                })
                                .unwrap_or(0),
                        ),
                    };
                    Some(TxRef { id, height })
                })
                .collect()
        })
        .unwrap_or_default();
    let page_info = txns.and_then(|t| t.get("pageInfo"));
    let has_next = page_info
        .and_then(|p| p.get("hasNextPage"))
        .and_then(|h| h.as_bool());
    let end_cursor = page_info
        .and_then(|p| p.get("endCursor"))
        .and_then(|c| c.as_str())
        .map(String::from);
    TxPage {
        refs,
        has_next,
        end_cursor,
    }
}

/// Order a block height so that a not-yet-mined anchor (`None`) sorts above any
/// mined one, and mined anchors order by ascending height. Higher rank == newer.
fn height_rank(h: Option<u64>) -> (u8, u64) {
    match h {
        None => (1, 0),    // pending anchor: newest
        Some(v) => (0, v), // mined: by block height
    }
}

/// Merge per-push manifests into a single `oid -> cid` map. A later seal of an
/// oid overrides an earlier one, ranked by the composite key
/// `(timestamp, block height, cid)`:
///   - manifest `timestamp` (RFC3339, lexicographic) is primary — the unchanged
///     latest-wins behavior;
///   - Arweave block height breaks equal-timestamp ties by anchor recency (a
///     pending anchor counts as newest), preserving the "newest wins" that
///     single-page `HEIGHT_DESC` discovery used to provide by insertion order.
///     The height is gateway-reported (chain-derived but not independently
///     verified here), so it removes order-dependence and honest-node clock skew,
///     not trust in the gateway — discovery already assumes an honest gateway;
///   - cid is a final lexicographic tiebreak so two anchors in the *same* block
///     still resolve deterministically (arbitrary, not recency-ordered, within a
///     block), independent of discovery order.
fn merge_manifests(
    manifests: Vec<(Manifest, Option<u64>)>,
) -> std::collections::HashMap<String, String> {
    // oid -> (cid, timestamp, height_rank)
    let mut best: std::collections::HashMap<String, (String, String, (u8, u64))> =
        std::collections::HashMap::new();
    for (m, height) in manifests {
        let cand_rank = height_rank(height);
        for b in m.blobs {
            let keep_incumbent = match best.get(&b.oid) {
                // Incumbent wins iff its composite key is >= the candidate's. The
                // `>=` (not `>`) keeps the incumbent only on a full tie, where the
                // entries are identical anyway. A strictly-greater candidate key
                // (newer timestamp, or equal timestamp + higher block, or equal
                // both + larger cid) replaces it.
                Some((cur_cid, cur_ts, cur_rank)) => {
                    (cur_ts.as_str(), cur_rank, cur_cid.as_str())
                        >= (m.timestamp.as_str(), &cand_rank, b.cid.as_str())
                }
                None => false,
            };
            if !keep_incumbent {
                best.insert(b.oid, (b.cid, m.timestamp.clone(), cand_rank));
            }
        }
    }
    best.into_iter()
        .map(|(oid, (cid, _, _))| (oid, cid))
        .collect()
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
    // Bound every gateway request: this runs on every clone, so a slow or hung
    // public gateway must not stall it. Best-effort recovery, so a timeout just
    // skips the affected blob.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // 1. Discover manifest transactions via paginated Arweave GraphQL. Collect
    //    (tx id, block height) refs across every page, deduping by id and bounding
    //    the loop so a hostile or buggy gateway cannot grow the set, the page
    //    count, or the downstream per-id fetch loop without limit. Best-effort: a
    //    page-1 failure (gateway down/unconfigured) stays silent as before; a
    //    failure or cap reached *after* discovery began warns, since the recovery
    //    is then knowingly partial.
    const MAX_PAGES: usize = 1000;
    const MAX_TX_IDS: usize = 10_000;
    // `first:100` below must equal ARWEAVE_PAGE_SIZE (the per-page bound enforced
    // in `parse_tx_page`); the query string keeps the literal because formatting
    // it would mean escaping the brace-heavy GraphQL body.
    let query = r#"query($repo:String!,$cursor:String){transactions(tags:[{name:"App-Name",values:["gitlawb"]},{name:"Schema",values:["gitlawb/encrypted-manifest/v1"]},{name:"Repo",values:[$repo]}],first:100,after:$cursor){pageInfo{hasNextPage endCursor}edges{cursor node{id block{height}}}}}"#;
    let mut after: Option<String> = None;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut refs: Vec<TxRef> = Vec::new();
    let mut prev_cursor: Option<String> = None;
    let mut page_num = 0usize;
    loop {
        if page_num >= MAX_PAGES {
            eprintln!(
                "warning: Arweave manifest discovery hit the {MAX_PAGES}-page cap; \
                 some authorized files may not be recovered"
            );
            break;
        }
        page_num += 1;
        let gql_body =
            serde_json::json!({ "query": query, "variables": { "repo": slug, "cursor": after } });
        // Any gateway failure (non-2xx, send error, unparseable body) ends the loop.
        let response = match client
            .post(format!("{ag}/graphql"))
            .json(&gql_body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r.json::<serde_json::Value>().await.ok(),
            _ => None,
        };
        let value = match response {
            Some(v) => v,
            None => {
                // A failure *after* discovery began means recovery is knowingly
                // partial, so warn. A page-1 failure is the benign unconfigured/
                // unreachable-gateway case and stays silent, exactly as before.
                if !refs.is_empty() {
                    eprintln!(
                        "warning: Arweave manifest discovery was interrupted by a gateway \
                         error; some authorized files may not be recovered"
                    );
                }
                break;
            }
        };
        let page = parse_tx_page(&value);
        let full = page.refs.len() >= ARWEAVE_PAGE_SIZE;
        for r in page.refs {
            if seen.insert(r.id.clone()) {
                refs.push(r);
            }
        }
        // Cap checked at the page boundary so a partial page is never half-merged.
        if refs.len() >= MAX_TX_IDS {
            eprintln!(
                "warning: Arweave manifest discovery hit the {MAX_TX_IDS}-transaction cap; \
                 some authorized files may not be recovered"
            );
            break;
        }
        match page.has_next {
            Some(true) => match page.end_cursor {
                // Advance only on a fresh cursor; a missing or repeating cursor is
                // a degenerate gateway response and must not loop forever.
                Some(c) if Some(&c) != prev_cursor.as_ref() => {
                    prev_cursor = Some(c.clone());
                    after = Some(c);
                }
                _ => break,
            },
            Some(false) => break,
            // No pageInfo: terminal. A *full* page without it may be a silently
            // truncated gateway, so flag that; a short page is genuinely the end.
            None => {
                if full {
                    eprintln!(
                        "warning: Arweave gateway returned a full page without pagination \
                         metadata; discovery may be incomplete and some authorized files may \
                         not be recovered"
                    );
                }
                break;
            }
        }
    }
    if refs.is_empty() {
        return Ok(vec![]);
    }

    // 2. Fetch each manifest body, pair it with its anchor's block height, then
    //    merge (latest-wins by timestamp, tie-broken by block height then cid).
    let mut manifests: Vec<(Manifest, Option<u64>)> = Vec::new();
    for r in refs {
        let m = match client.get(format!("{ag}/{}", r.id)).send().await {
            Ok(resp) if resp.status().is_success() => resp,
            _ => continue,
        };
        if let Ok(parsed) = m.json::<Manifest>().await {
            manifests.push((parsed, r.height));
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
        // Local presence check. GIT_NO_LAZY_FETCH stops git from making a wasted
        // promisor fetch attempt (we are recovering precisely because the promisor
        // cannot supply the blob), and `.output()` captures git's "missing object"
        // stderr so that expected case does not leak a confusing error to the user.
        let present = Command::new("git")
            .args(["-C", dest_str, "cat-file", "-e", &oid])
            .env("GIT_NO_LAZY_FETCH", "1")
            .output()
            .map(|o| o.status.success())
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
            .unwrap_or_else(|e| {
                // A node-recovery error must not abort the clone (the Arweave
                // fallback still runs), but the strict /encrypted-blobs parse now
                // fails closed on schema drift, so surface it rather than letting
                // `.unwrap_or_default()` silently swallow it into "no paths".
                eprintln!("warning: encrypted-blobs recovery failed: {e}");
                Vec::new()
            });
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
                match std::fs::read_to_string(&spec) {
                    Ok(mut s) => {
                        for p in &paths {
                            s.push_str(&format!("/{p}\n"));
                        }
                        if let Err(e) = std::fs::write(&spec, &s) {
                            eprintln!(
                                "warning: failed to update sparse-checkout, recovered files may not appear: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: failed to read sparse-checkout, recovered files may not appear: {e}"
                        );
                    }
                }
            }
            if let Err(e) = git(&dest, &["checkout", "--", "."]) {
                eprintln!(
                    "warning: checkout after recovery failed, recovered files may not appear: {e}"
                );
            }
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
    fn encrypted_blobs_response_is_schema_strict() {
        // Happy path: a well-formed body parses and exposes the oids.
        let ok: EncryptedBlobsResponse =
            serde_json::from_str(r#"{"blobs":[{"oid":"abc"}]}"#).unwrap();
        assert_eq!(ok.blobs.len(), 1);
        assert_eq!(ok.blobs[0].oid, "abc");

        // Unknown server fields on an entry are tolerated (no deny_unknown_fields).
        let extra: EncryptedBlobsResponse =
            serde_json::from_str(r#"{"blobs":[{"oid":"abc","size":42}]}"#).unwrap();
        assert_eq!(extra.blobs[0].oid, "abc");

        // Empty list is valid and distinct from a missing field.
        let empty: EncryptedBlobsResponse = serde_json::from_str(r#"{"blobs":[]}"#).unwrap();
        assert!(empty.blobs.is_empty());

        // Schema drift is a hard error, not a silent "nothing to recover":
        // missing `blobs`, wrong-typed `blobs`, and an entry missing `oid`.
        assert!(serde_json::from_str::<EncryptedBlobsResponse>(r#"{"items":[]}"#).is_err());
        assert!(serde_json::from_str::<EncryptedBlobsResponse>(r#"{"blobs":"nope"}"#).is_err());
        assert!(
            serde_json::from_str::<EncryptedBlobsResponse>(r#"{"blobs":[{"size":1}]}"#).is_err()
        );
    }

    #[test]
    fn parse_tx_page_extracts_node_ids_and_heights() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"data":{"transactions":{"pageInfo":{"hasNextPage":true,"endCursor":"C1"},"edges":[{"node":{"id":"TX1","block":{"height":100}}},{"node":{"id":"TX2","block":null}}]}}}"#,
        )
        .unwrap();
        let page = parse_tx_page(&v);
        let ids: Vec<&str> = page.refs.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["TX1", "TX2"]);
        assert_eq!(page.refs[0].height, Some(100));
        assert_eq!(page.refs[1].height, None); // null block -> pending -> None
        assert_eq!(page.has_next, Some(true));
        assert_eq!(page.end_cursor.as_deref(), Some("C1"));
    }

    #[test]
    fn parse_tx_page_empty_on_no_edges() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"data":{"transactions":{"edges":[]}}}"#).unwrap();
        let page = parse_tx_page(&v);
        assert!(page.refs.is_empty());
        // No pageInfo present -> has_next None (the loop treats it as terminal).
        assert_eq!(page.has_next, None);
        assert_eq!(page.end_cursor, None);
    }

    #[test]
    fn parse_tx_page_missing_block_is_none() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"data":{"transactions":{"edges":[{"node":{"id":"TX1"}}]}}}"#)
                .unwrap();
        let page = parse_tx_page(&v);
        assert_eq!(page.refs[0].height, None);
    }

    #[test]
    fn parse_tx_page_height_parsing_is_robust() {
        // A gateway that serializes height as a JSON string (a habit to dodge
        // 53-bit float precision) must still parse to the real height, not
        // collapse to None and masquerade as a pending/newest anchor.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"data":{"transactions":{"edges":[
                {"node":{"id":"TXSTR","block":{"height":"12345"}}},
                {"node":{"id":"TXBAD","block":{"height":"not-a-number"}}},
                {"node":{"id":"TXNOH","block":{}}}
            ]}}}"#,
        )
        .unwrap();
        let page = parse_tx_page(&v);
        // Numeric string parses to the real height.
        assert_eq!(page.refs[0].height, Some(12345));
        // A present block with an unreadable/absent height is mined-but-unknown:
        // it ranks lowest (Some(0)), NOT None/newest, so it can't steal a tie.
        assert_eq!(page.refs[1].height, Some(0));
        assert_eq!(page.refs[2].height, Some(0));
    }

    #[test]
    fn parse_tx_page_bounds_edges_per_page() {
        // A hostile gateway returning more than ARWEAVE_PAGE_SIZE edges on one
        // page must not defeat the MAX_TX_IDS budget: parse caps per-page refs so
        // the downstream fetch loop stays bounded.
        let edges: String = (0..ARWEAVE_PAGE_SIZE + 50)
            .map(|i| format!(r#"{{"node":{{"id":"TX{i}"}}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let v: serde_json::Value = serde_json::from_str(&format!(
            r#"{{"data":{{"transactions":{{"edges":[{edges}]}}}}}}"#
        ))
        .unwrap();
        let page = parse_tx_page(&v);
        assert_eq!(page.refs.len(), ARWEAVE_PAGE_SIZE);
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
        let merged = merge_manifests(vec![(older, Some(1)), (newer, Some(2))]);
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
        let merged = merge_manifests(vec![(newer, Some(2)), (older, Some(1))]);
        assert_eq!(merged.get("o1").map(String::as_str), Some("cidNEW"));
    }

    // Helper: a single-blob manifest for the merge tie-break tests.
    fn manifest_with(ts: &str, oid: &str, cid: &str) -> Manifest {
        Manifest {
            timestamp: ts.to_string(),
            blobs: vec![ManifestBlob {
                oid: oid.to_string(),
                cid: cid.to_string(),
            }],
        }
    }

    #[test]
    fn merge_equal_timestamp_breaks_by_block_height() {
        // Same timestamp, different block heights: the higher block (newer
        // anchor) must win, regardless of input order.
        let lo = manifest_with("2026-06-11T00:00:00Z", "o1", "cidLO");
        let hi = manifest_with("2026-06-11T00:00:00Z", "o1", "cidHI");
        let a = merge_manifests(vec![
            (
                manifest_with("2026-06-11T00:00:00Z", "o1", "cidLO"),
                Some(10),
            ),
            (
                manifest_with("2026-06-11T00:00:00Z", "o1", "cidHI"),
                Some(20),
            ),
        ]);
        assert_eq!(a.get("o1").map(String::as_str), Some("cidHI"));
        // Reversed order, same result.
        let b = merge_manifests(vec![(hi, Some(20)), (lo, Some(10))]);
        assert_eq!(b.get("o1").map(String::as_str), Some("cidHI"));
    }

    #[test]
    fn merge_pending_anchor_is_newest_on_tie() {
        // Same timestamp; one mined anchor, one pending (None height). The
        // pending one is the most recent and must win, order-independently.
        let mined = manifest_with("2026-06-11T00:00:00Z", "o1", "cidMINED");
        let pending = manifest_with("2026-06-11T00:00:00Z", "o1", "cidPENDING");
        let a = merge_manifests(vec![(mined, Some(99)), (pending, None)]);
        assert_eq!(a.get("o1").map(String::as_str), Some("cidPENDING"));
        let mined2 = manifest_with("2026-06-11T00:00:00Z", "o1", "cidMINED");
        let pending2 = manifest_with("2026-06-11T00:00:00Z", "o1", "cidPENDING");
        let b = merge_manifests(vec![(pending2, None), (mined2, Some(99))]);
        assert_eq!(b.get("o1").map(String::as_str), Some("cidPENDING"));
    }

    #[test]
    fn merge_same_block_breaks_by_cid_deterministically() {
        // Equal timestamp AND equal height: the cid tiebreak makes the result
        // deterministic and order-independent (lexicographically-larger cid wins).
        let a = merge_manifests(vec![
            (
                manifest_with("2026-06-11T00:00:00Z", "o1", "cidAAA"),
                Some(5),
            ),
            (
                manifest_with("2026-06-11T00:00:00Z", "o1", "cidBBB"),
                Some(5),
            ),
        ]);
        let b = merge_manifests(vec![
            (
                manifest_with("2026-06-11T00:00:00Z", "o1", "cidBBB"),
                Some(5),
            ),
            (
                manifest_with("2026-06-11T00:00:00Z", "o1", "cidAAA"),
                Some(5),
            ),
        ]);
        assert_eq!(a.get("o1"), b.get("o1"));
        assert_eq!(a.get("o1").map(String::as_str), Some("cidBBB"));
    }

    #[test]
    fn merge_newer_timestamp_wins_regardless_of_height() {
        // Timestamp is primary: a newer timestamp wins even with a lower block
        // height than the older-timestamp manifest.
        let older_hi_block = manifest_with("2026-06-10T00:00:00Z", "o1", "cidOLD");
        let newer_lo_block = manifest_with("2026-06-11T00:00:00Z", "o1", "cidNEW");
        let merged = merge_manifests(vec![
            (older_hi_block, Some(9999)),
            (newer_lo_block, Some(1)),
        ]);
        assert_eq!(merged.get("o1").map(String::as_str), Some("cidNEW"));
    }

    #[test]
    fn merge_empty_timestamp_loses_to_timestamped() {
        // A manifest with a missing/empty timestamp (serde default) sorts lowest
        // and loses to any timestamped manifest for the same oid. Pins the
        // empty-sorts-lowest precondition as a deliberate decision.
        let untimestamped = manifest_with("", "o1", "cidEMPTY");
        let timestamped = manifest_with("2026-06-11T00:00:00Z", "o1", "cidTS");
        let a = merge_manifests(vec![(untimestamped, Some(50)), (timestamped, Some(1))]);
        assert_eq!(a.get("o1").map(String::as_str), Some("cidTS"));
    }

    /// Read-path end-to-end over a mocked Arweave + IPFS gateway: discover the
    /// manifest via GraphQL, fetch it, fetch the envelope, decrypt with the
    /// caller's key, and install the previously-withheld blob.
    #[tokio::test]
    async fn recover_from_arweave_installs_authorized_blob() {
        use gitlawb_core::encrypt::seal_blob;
        use gitlawb_core::identity::Keypair;

        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("dest");
        // Make the bare honor `--filter=blob:none` over file:// so the withheld
        // blob is genuinely omitted from the local store, not just unchecked-out.
        let bare = url.strip_prefix("file://").unwrap();
        assert!(Command::new("git")
            .args(["-C", bare, "config", "uploadpack.allowFilter", "true"])
            .status()
            .unwrap()
            .success());
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();
        assert!(
            !dest.join("secret/b.txt").exists(),
            "secret starts withheld"
        );

        let oid = {
            let out = Command::new("git")
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

        // Simulate origin death: drop the promisor remote so `cat-file -e` cannot
        // lazily fetch the withheld blob. This is exactly the B3 premise (the node
        // can no longer serve it), and forces recovery to go through Arweave/IPFS.
        std::fs::remove_dir_all(url.strip_prefix("file://").unwrap()).unwrap();

        let reader = Keypair::generate();
        let envelope = seal_blob(b"SECRET\n", &[reader.verifying_key()]).unwrap();

        let cid = "testcid123";
        let mut server = mockito::Server::new_async().await;
        let _gql = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"transactions":{"edges":[{"node":{"id":"TX1"}}]}}}"#)
            .create_async()
            .await;
        let manifest_body = serde_json::json!({
            "timestamp": "2026-06-11T00:00:00Z",
            "blobs": [{ "oid": oid, "cid": cid, "recipients": [] }],
        })
        .to_string();
        let _tx = server
            .mock("GET", "/TX1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(manifest_body)
            .create_async()
            .await;
        let _blob = server
            .mock("GET", format!("/ipfs/{cid}").as_str())
            .with_status(200)
            .with_body(envelope)
            .create_async()
            .await;

        let paths = recover_from_arweave(
            &server.url(),
            &server.url(),
            "alice",
            "myrepo",
            &dest,
            &reader,
        )
        .await
        .unwrap();
        assert_eq!(paths, vec!["secret/b.txt".to_string()]);

        let present = Command::new("git")
            .args(["-C", dest.to_str().unwrap(), "cat-file", "-e", &oid])
            .env("GIT_NO_LAZY_FETCH", "1")
            .output()
            .unwrap()
            .status
            .success();
        assert!(
            present,
            "authorized reader's blob must be installed locally"
        );
    }

    /// Discovery must follow cursor pagination: a blob whose manifest is anchored
    /// only on the SECOND page is still recovered. If the loop stopped at page 1
    /// (the old `first:100` behavior), this blob would be lost.
    #[tokio::test]
    async fn recover_from_arweave_paginates_to_later_page() {
        use gitlawb_core::encrypt::seal_blob;
        use gitlawb_core::identity::Keypair;

        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("dest");
        let bare = url.strip_prefix("file://").unwrap();
        assert!(Command::new("git")
            .args(["-C", bare, "config", "uploadpack.allowFilter", "true"])
            .status()
            .unwrap()
            .success());
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();
        let oid = {
            let out = Command::new("git")
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
        std::fs::remove_dir_all(url.strip_prefix("file://").unwrap()).unwrap();

        let reader = Keypair::generate();
        let envelope = seal_blob(b"SECRET\n", &[reader.verifying_key()]).unwrap();
        let cid = "testcid123";

        let mut server = mockito::Server::new_async().await;
        // Page 1 (cursor null): hasNextPage=true, endCursor C1, an empty manifest
        // anchor that does NOT carry the withheld blob.
        let _gql_p1 = server
            .mock("POST", "/graphql")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"variables":{"cursor":null}}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"transactions":{"pageInfo":{"hasNextPage":true,"endCursor":"C1"},"edges":[{"node":{"id":"TXP1","block":{"height":10}}}]}}}"#,
            )
            .create_async()
            .await;
        // Page 2 (cursor "C1"): hasNextPage=false, the anchor with the blob.
        let _gql_p2 = server
            .mock("POST", "/graphql")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"variables":{"cursor":"C1"}}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"transactions":{"pageInfo":{"hasNextPage":false,"endCursor":"C2"},"edges":[{"node":{"id":"TX1","block":{"height":20}}}]}}}"#,
            )
            .create_async()
            .await;
        let _tx_p1 = server
            .mock("GET", "/TXP1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"timestamp":"2026-06-10T00:00:00Z","blobs":[]}"#)
            .create_async()
            .await;
        let manifest_body = serde_json::json!({
            "timestamp": "2026-06-11T00:00:00Z",
            "blobs": [{ "oid": oid, "cid": cid, "recipients": [] }],
        })
        .to_string();
        let _tx1 = server
            .mock("GET", "/TX1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(manifest_body)
            .create_async()
            .await;
        let _blob = server
            .mock("GET", format!("/ipfs/{cid}").as_str())
            .with_status(200)
            .with_body(envelope)
            .create_async()
            .await;

        let paths = recover_from_arweave(
            &server.url(),
            &server.url(),
            "alice",
            "myrepo",
            &dest,
            &reader,
        )
        .await
        .unwrap();
        assert_eq!(
            paths,
            vec!["secret/b.txt".to_string()],
            "blob anchored only on page 2 must be recovered via pagination"
        );
    }

    /// Best-effort on mid-pagination failure: page 1 already yielded a usable
    /// anchor; page 2 fails. Recovery still installs page 1's blob (partial Ok),
    /// never aborts the clone.
    #[tokio::test]
    async fn recover_from_arweave_partial_on_midpagination_failure() {
        use gitlawb_core::encrypt::seal_blob;
        use gitlawb_core::identity::Keypair;

        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("dest");
        let bare = url.strip_prefix("file://").unwrap();
        assert!(Command::new("git")
            .args(["-C", bare, "config", "uploadpack.allowFilter", "true"])
            .status()
            .unwrap()
            .success());
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();
        let oid = {
            let out = Command::new("git")
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
        std::fs::remove_dir_all(url.strip_prefix("file://").unwrap()).unwrap();

        let reader = Keypair::generate();
        let envelope = seal_blob(b"SECRET\n", &[reader.verifying_key()]).unwrap();
        let cid = "testcid123";

        let mut server = mockito::Server::new_async().await;
        // Page 1 (cursor null): the blob anchor, hasNextPage=true.
        let manifest_body = serde_json::json!({
            "timestamp": "2026-06-11T00:00:00Z",
            "blobs": [{ "oid": oid, "cid": cid, "recipients": [] }],
        })
        .to_string();
        let _gql_p1 = server
            .mock("POST", "/graphql")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"variables":{"cursor":null}}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"transactions":{"pageInfo":{"hasNextPage":true,"endCursor":"C1"},"edges":[{"node":{"id":"TX1","block":{"height":20}}}]}}}"#,
            )
            .create_async()
            .await;
        // Page 2 (cursor "C1"): gateway error.
        let _gql_p2 = server
            .mock("POST", "/graphql")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"variables":{"cursor":"C1"}}"#.into(),
            ))
            .with_status(500)
            .create_async()
            .await;
        let _tx1 = server
            .mock("GET", "/TX1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(manifest_body)
            .create_async()
            .await;
        let _blob = server
            .mock("GET", format!("/ipfs/{cid}").as_str())
            .with_status(200)
            .with_body(envelope)
            .create_async()
            .await;

        let paths = recover_from_arweave(
            &server.url(),
            &server.url(),
            "alice",
            "myrepo",
            &dest,
            &reader,
        )
        .await
        .expect("mid-pagination failure must not abort recovery");
        assert_eq!(
            paths,
            vec!["secret/b.txt".to_string()],
            "page-1 blob must still be recovered when page 2 fails"
        );
    }

    /// A gateway that reports `hasNextPage=true` but never advances the cursor
    /// (returns the same `endCursor` every page) must not loop forever: the
    /// degenerate-cursor guard terminates the loop and recovery returns based on
    /// what was seen. The test completing at all proves no hang.
    #[tokio::test]
    async fn recover_from_arweave_terminates_on_nonadvancing_cursor() {
        use gitlawb_core::encrypt::seal_blob;
        use gitlawb_core::identity::Keypair;

        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("dest");
        let bare = url.strip_prefix("file://").unwrap();
        assert!(Command::new("git")
            .args(["-C", bare, "config", "uploadpack.allowFilter", "true"])
            .status()
            .unwrap()
            .success());
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();
        let oid = {
            let out = Command::new("git")
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
        std::fs::remove_dir_all(url.strip_prefix("file://").unwrap()).unwrap();

        let reader = Keypair::generate();
        let envelope = seal_blob(b"SECRET\n", &[reader.verifying_key()]).unwrap();
        let cid = "testcid123";

        let mut server = mockito::Server::new_async().await;
        // Every GraphQL POST returns hasNextPage=true with the SAME endCursor.
        // Without the guard this would request pages until MAX_PAGES; with it the
        // loop breaks after the first non-advancing cursor.
        let manifest_body = serde_json::json!({
            "timestamp": "2026-06-11T00:00:00Z",
            "blobs": [{ "oid": oid, "cid": cid, "recipients": [] }],
        })
        .to_string();
        let _gql = server
            .mock("POST", "/graphql")
            .expect_at_most(3) // a couple at most; certainly not MAX_PAGES
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"transactions":{"pageInfo":{"hasNextPage":true,"endCursor":"STUCK"},"edges":[{"node":{"id":"TX1","block":{"height":20}}}]}}}"#,
            )
            .create_async()
            .await;
        let _tx1 = server
            .mock("GET", "/TX1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(manifest_body)
            .create_async()
            .await;
        let _blob = server
            .mock("GET", format!("/ipfs/{cid}").as_str())
            .with_status(200)
            .with_body(envelope)
            .create_async()
            .await;

        let paths = recover_from_arweave(
            &server.url(),
            &server.url(),
            "alice",
            "myrepo",
            &dest,
            &reader,
        )
        .await
        .expect("non-advancing cursor must terminate, not hang or error");
        assert_eq!(paths, vec!["secret/b.txt".to_string()]);
    }

    /// A tx id repeated across pages must be fetched only once: the cross-page
    /// dedup (R8) bounds the downstream per-id manifest fetch loop.
    #[tokio::test]
    async fn recover_from_arweave_dedups_tx_ids_across_pages() {
        use gitlawb_core::encrypt::seal_blob;
        use gitlawb_core::identity::Keypair;

        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("dest");
        let bare = url.strip_prefix("file://").unwrap();
        assert!(Command::new("git")
            .args(["-C", bare, "config", "uploadpack.allowFilter", "true"])
            .status()
            .unwrap()
            .success());
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();
        let oid = {
            let out = Command::new("git")
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
        std::fs::remove_dir_all(url.strip_prefix("file://").unwrap()).unwrap();

        let reader = Keypair::generate();
        let envelope = seal_blob(b"SECRET\n", &[reader.verifying_key()]).unwrap();
        let cid = "testcid123";

        let mut server = mockito::Server::new_async().await;
        // Page 1 and page 2 both list TX1 (cursor advances); the dedup must fetch
        // the /TX1 manifest exactly once.
        let _gql_p1 = server
            .mock("POST", "/graphql")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"variables":{"cursor":null}}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"transactions":{"pageInfo":{"hasNextPage":true,"endCursor":"C1"},"edges":[{"node":{"id":"TX1","block":{"height":20}}}]}}}"#,
            )
            .create_async()
            .await;
        let _gql_p2 = server
            .mock("POST", "/graphql")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"variables":{"cursor":"C1"}}"#.into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"data":{"transactions":{"pageInfo":{"hasNextPage":false,"endCursor":"C2"},"edges":[{"node":{"id":"TX1","block":{"height":20}}}]}}}"#,
            )
            .create_async()
            .await;
        let manifest_body = serde_json::json!({
            "timestamp": "2026-06-11T00:00:00Z",
            "blobs": [{ "oid": oid, "cid": cid, "recipients": [] }],
        })
        .to_string();
        let tx1 = server
            .mock("GET", "/TX1")
            .expect(1) // dedup: fetched once despite appearing on both pages
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(manifest_body)
            .create_async()
            .await;
        let _blob = server
            .mock("GET", format!("/ipfs/{cid}").as_str())
            .with_status(200)
            .with_body(envelope)
            .create_async()
            .await;

        let paths = recover_from_arweave(
            &server.url(),
            &server.url(),
            "alice",
            "myrepo",
            &dest,
            &reader,
        )
        .await
        .unwrap();
        assert_eq!(paths, vec!["secret/b.txt".to_string()]);
        tx1.assert_async().await; // exactly one /TX1 fetch
    }

    /// A caller who is not a recipient cannot decrypt the envelope, so nothing is
    /// recovered even though the manifest and envelope are reachable.
    #[tokio::test]
    async fn recover_from_arweave_skips_unauthorized() {
        use gitlawb_core::encrypt::seal_blob;
        use gitlawb_core::identity::Keypair;

        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("dest");
        let bare = url.strip_prefix("file://").unwrap();
        assert!(Command::new("git")
            .args(["-C", bare, "config", "uploadpack.allowFilter", "true"])
            .status()
            .unwrap()
            .success());
        setup_partial_clone(&dest, &url, &["/secret/**".to_string()], &[], None).unwrap();

        let oid = {
            let out = Command::new("git")
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

        // Simulate origin death (see the authorized test) so the withheld blob
        // cannot be lazily fetched from the promisor remote.
        std::fs::remove_dir_all(url.strip_prefix("file://").unwrap()).unwrap();

        // Sealed to a different reader; the caller below is not a recipient.
        let authorized = Keypair::generate();
        let envelope = seal_blob(b"SECRET\n", &[authorized.verifying_key()]).unwrap();
        let intruder = Keypair::generate();

        let cid = "testcid123";
        let mut server = mockito::Server::new_async().await;
        let _gql = server
            .mock("POST", "/graphql")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"transactions":{"edges":[{"node":{"id":"TX1"}}]}}}"#)
            .create_async()
            .await;
        let manifest_body = serde_json::json!({
            "timestamp": "2026-06-11T00:00:00Z",
            "blobs": [{ "oid": oid, "cid": cid, "recipients": [] }],
        })
        .to_string();
        let _tx = server
            .mock("GET", "/TX1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(manifest_body)
            .create_async()
            .await;
        let _blob = server
            .mock("GET", format!("/ipfs/{cid}").as_str())
            .with_status(200)
            .with_body(envelope)
            .create_async()
            .await;

        let paths = recover_from_arweave(
            &server.url(),
            &server.url(),
            "alice",
            "myrepo",
            &dest,
            &intruder,
        )
        .await
        .unwrap();
        assert!(paths.is_empty(), "non-recipient must recover nothing");

        let present = Command::new("git")
            .args(["-C", dest.to_str().unwrap(), "cat-file", "-e", &oid])
            .env("GIT_NO_LAZY_FETCH", "1")
            .output()
            .unwrap()
            .status
            .success();
        assert!(!present, "non-recipient must not install the blob");
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
