//! Resolve which blob OIDs must be withheld from a caller because every path
//! at which the blob appears is denied by the repo's visibility rules. Trees
//! and commits are never withheld (mode B keeps SHAs intact); only blob
//! content is held back.

use crate::db::VisibilityRule;
use crate::git::store;
use crate::visibility::{visibility_check, Decision};
use anyhow::{Context, Result};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

/// Fail closed unless every ref ultimately resolves to a commit (a ref pointing
/// directly at a blob or tree, or an annotated tag — even a nested one — of such
/// an object is refused). `git rev-list --all` silently *skips* such refs, but
/// `git upload-pack` (serve) and the whole-repo pin fallback
/// (`git cat-file --batch-all-objects`) still expose their target object, so a
/// tolerant walk would under-withhold. Refuse rather than leak.
///
/// Each ref is peeled fully with `<ref>^{}` through `git cat-file --batch-check`.
/// Full peeling is why this is not `for-each-ref %(*objecttype)`, which
/// dereferences only one tag level and so misclassifies a tag-of-a-tag-of-a-
/// commit as a non-commit.
fn assert_all_refs_are_commits(repo_path: &Path) -> Result<()> {
    let refs = std::process::Command::new("git")
        .args(["for-each-ref", "--format=%(refname)"])
        .current_dir(repo_path)
        .output()
        .context("git for-each-ref failed")?;
    if !refs.status.success() {
        anyhow::bail!(
            "git for-each-ref failed: {}",
            String::from_utf8_lossy(&refs.stderr)
        );
    }
    let refs_stdout = String::from_utf8_lossy(&refs.stdout);
    let refnames: Vec<&str> = refs_stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if refnames.is_empty() {
        return Ok(());
    }

    // Peel every ref in one `git cat-file --batch-check` pass: one
    // `<refname>^{}` query per line, one output line per input line, in order.
    // The stdin write runs on a separate thread so this thread can drain stdout
    // concurrently. cat-file echoes the full query on a `<query> missing` line,
    // so output scales with refname length (not a fixed size per ref); writing
    // all of stdin before reading any stdout would deadlock both pipes once the
    // child's stdout buffer fills. Dropping `stdin` at the end of the closure
    // sends EOF.
    let queries = refnames
        .iter()
        .map(|r| format!("{r}^{{}}"))
        .collect::<Vec<_>>()
        .join("\n");
    use std::io::Write;
    let mut child = std::process::Command::new("git")
        .args(["cat-file", "--batch-check=%(objecttype)"])
        .current_dir(repo_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn git cat-file")?;
    // Feed stdin on a writer thread so this thread can drain stdout via
    // wait_with_output concurrently; a None handle (the pipe vanished) becomes a
    // broken-pipe write error. wait_with_output reaps the child unconditionally
    // before any error is surfaced, so no path drops it unwaited (#53), and the
    // writer is joined only after the drain so the join cannot deadlock.
    let writer = child
        .stdin
        .take()
        .map(|mut stdin| std::thread::spawn(move || stdin.write_all(queries.as_bytes())));
    let peel_result = child.wait_with_output();
    let write_result = match writer {
        Some(handle) => handle
            .join()
            .map_err(|_| anyhow::anyhow!("git cat-file stdin writer thread panicked"))?,
        None => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "git cat-file stdin unavailable",
        )),
    };
    // Surface a write error only if the process didn't already fail with a
    // clearer status.
    let peel = peel_result.context("git cat-file failed")?;
    if !peel.status.success() {
        anyhow::bail!(
            "git cat-file --batch-check failed: {}",
            String::from_utf8_lossy(&peel.stderr)
        );
    }
    write_result.context("failed to write to git cat-file stdin")?;

    let peel_stdout = String::from_utf8_lossy(&peel.stdout);
    let types: Vec<&str> = peel_stdout.lines().map(str::trim).collect();
    // A short read means at least one ref went unclassified — fail closed.
    if types.len() != refnames.len() {
        anyhow::bail!(
            "git cat-file returned {} lines for {} refs; \
             refusing to produce a partial (under-withheld) set",
            types.len(),
            refnames.len()
        );
    }
    for (refname, kind) in refnames.iter().zip(types.iter()) {
        // git emits `<query> missing` (not the objecttype) when the peel target
        // is absent; the status word is the last token.
        if kind.split_ascii_whitespace().last() == Some("missing") {
            anyhow::bail!(
                "ref {refname} does not resolve to an object; \
                 refusing to produce a partial (under-withheld) set"
            );
        }
        if *kind != "commit" {
            anyhow::bail!(
                "ref {refname} resolves to a {kind}, not a commit; \
                 refusing to produce a partial (under-withheld) set"
            );
        }
    }
    Ok(())
}

/// List every (blob_oid, "/repo/relative/path") pair reachable from any commit in
/// `repo_path` — every ref *and* every historical commit those refs reach, not just
/// the ref tips. `git upload-pack` (serve) and the whole-repo pin fallback
/// (`git cat-file --batch-all-objects`) expose the full reachable object graph,
/// including a blob that only ever existed
/// in an older commit (a since-deleted file, a rotated secret whose previous version
/// is still in history). Classifying only ref-tip trees would leave those blobs
/// unwithheld while pin/serve still hand them out in cleartext, so we enumerate all
/// reachable commits and walk each commit's tree.
///
/// `--all` covers every ref namespace (a blob reachable only through `refs/notes/*`
/// must not escape withholding); HEAD is added explicitly for the detached case,
/// where HEAD reaches commits that no ref does. `git ls-tree -rz <commit>` per commit
/// keeps every path a blob lives at (the same blob content can appear at several
/// paths, and the per-path visibility check needs all of them). This is why it is
/// not `git rev-list --objects`, which reports only one path per object. Pairs are
/// de-duplicated across commits. Paths carry a leading "/" to match the glob form
/// used by visibility rules ("/secret/**").
///
/// Fails closed: if commit enumeration or any tree walk fails, returns an error so
/// the caller aborts the serve/pin rather than producing a partial (under-withheld)
/// set.
fn blob_paths(repo_path: &Path) -> Result<Vec<(String, String)>> {
    assert_all_refs_are_commits(repo_path)?;

    // Enumerate every reachable commit, not just ref tips. `--all` walks all refs;
    // append HEAD so a detached HEAD (reachable by rev-list/upload-pack but in no
    // ref) is still classified. When HEAD does not resolve (unborn branch on an
    // empty repo) `--all` alone yields nothing, which is correct — no objects exist.
    let head = store::head_commit(repo_path).context("resolve HEAD failed")?;
    let mut rev_args = vec!["rev-list", "--all"];
    if head.is_some() {
        rev_args.push("HEAD");
    }
    let commits = std::process::Command::new("git")
        .args(&rev_args)
        .current_dir(repo_path)
        .output()
        .context("git rev-list --all failed")?;
    if !commits.status.success() {
        anyhow::bail!(
            "git rev-list --all failed: {}",
            String::from_utf8_lossy(&commits.stderr)
        );
    }
    let commits_stdout = String::from_utf8_lossy(&commits.stdout);
    let mut out: HashSet<(String, String)> = HashSet::new();
    for commit in commits_stdout.lines() {
        let commit = commit.trim();
        if commit.is_empty() {
            continue;
        }
        let listing = std::process::Command::new("git")
            .args(["ls-tree", "-rz", commit])
            .current_dir(repo_path)
            .output()
            .context("git ls-tree -rz failed")?;
        if !listing.status.success() {
            anyhow::bail!(
                "git ls-tree -rz {commit} failed: {}",
                String::from_utf8_lossy(&listing.stderr)
            );
        }
        // `-z` NUL-delimits records and emits paths raw; plain `git ls-tree -r`
        // C-quotes any path with non-ASCII or special bytes (e.g. café.txt becomes
        // "secret/caf\303\251.txt"), and that quoted literal would not match a
        // visibility rule like "/secret/**", under-withholding the blob. The TAB
        // field separator survives `-z`, so the per-record parse is unchanged.
        //
        // Parse strictly: a lossy decode would replace an invalid byte in a denied
        // path (e.g. a non-UTF-8 directory name) with U+FFFD, and the mangled string
        // would no longer match its deny rule — the same under-withholding class, one
        // layer down. Fail closed instead so the caller aborts rather than leaks.
        let Ok(listing_stdout) = std::str::from_utf8(&listing.stdout) else {
            anyhow::bail!(
                "git ls-tree -rz {commit} returned a non-UTF-8 path; \
                 refusing to produce a partial (under-withheld) set"
            );
        };
        for record in listing_stdout.split('\0') {
            // "<mode> blob <oid>\t<path>"
            let Some((meta, path)) = record.split_once('\t') else {
                continue;
            };
            let mut parts = meta.split_whitespace();
            let _mode = parts.next();
            let kind = parts.next();
            let oid = parts.next();
            if kind == Some("blob") {
                if let Some(oid) = oid {
                    out.insert((oid.to_string(), format!("/{path}")));
                }
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// Blob OIDs the caller may not read. A blob is withheld only if visibility
/// denies the caller at *every* path the blob appears at; a blob that is also
/// reachable through an allowed path is sent (its content is public elsewhere).
///
/// The whole-repo "/" gate is handled by the caller before this function runs:
/// if "/" denies, the caller gets a 404 and never reaches the filtered serve.
pub fn withheld_blob_oids(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    let pairs = blob_paths(repo_path)?;
    Ok(withheld_from_pairs(
        &pairs, rules, is_public, owner_did, caller,
    ))
}

/// Withheld set from an already-computed (oid, "/path") listing: a blob is
/// withheld only when visibility denies the caller at *every* path it appears
/// at. Split out so a caller that already walked `blob_paths` (e.g.
/// `withheld_blob_recipients`) reuses the listing instead of walking history
/// again.
fn withheld_from_pairs(
    pairs: &[(String, String)],
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> HashSet<String> {
    let mut denied: HashSet<String> = HashSet::new();
    let mut allowed: HashSet<String> = HashSet::new();
    for (oid, path) in pairs {
        match visibility_check(rules, is_public, owner_did, caller, path) {
            Decision::Deny => {
                denied.insert(oid.clone());
            }
            Decision::Allow => {
                allowed.insert(oid.clone());
            }
        }
    }
    denied.difference(&allowed).cloned().collect()
}

/// True if any rule scopes a sub-path of the repo (i.e. is not the whole-repo
/// "/" rule). When this returns `false`, no rule can withhold an individual
/// blob: the only rules present are whole-repo "/" rules, which are already
/// resolved by the "/" gate the caller runs *before* reaching the serve /
/// replication walk (a denying "/" rule 404s the caller; see
/// `withheld_blob_oids` above). For any caller that has passed that gate,
/// `withheld_blob_oids` therefore returns an empty set, so such callers may
/// skip the (potentially expensive) per-blob walk. Do not skip the walk on this
/// predicate without the "/" gate having run first.
///
/// Validator dependency: this predicate treats `path_glob == "/"` as the only
/// whole-repo scope. That holds because `validate_path_glob`
/// (crates/gitlawb-node/src/api/visibility.rs) rejects `/**`, the only other
/// glob whose prefix collapses to `/` and would therefore match every path. If
/// glob syntax is ever extended, revisit this predicate.
pub fn has_path_scoped_rule(rules: &[VisibilityRule]) -> bool {
    rules.iter().any(|r| r.path_glob != "/")
}

/// Objects that may replicate to the public: everything not in `withheld`.
/// Order-preserving. The single seam every replication site (IPFS, Pinata)
/// passes its object list through; option B would later reroute the withheld
/// ones through encrypt-then-pin instead of dropping them.
pub fn replicable_objects(all: Vec<String>, withheld: &HashSet<String>) -> Vec<String> {
    all.into_iter()
        .filter(|oid| !withheld.contains(oid))
        .collect()
}

/// The reachable blob OIDs that visibility ALLOWS the anonymous replication
/// audience at some path — the only blobs the fail-closed pin filter treats as
/// safe. Mirrors the `allowed` side of `withheld_from_pairs`: a blob reachable
/// at an allowed path is included even when also denied elsewhere (its content
/// is public elsewhere). A dangling blob is absent from the reachable walk, so
/// it is never in this set and the fail-closed filter drops it (#99).
pub fn replicable_blob_set(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> Result<HashSet<String>> {
    allowed_blob_set_for_caller(repo_path, rules, is_public, owner_did, None)
}

/// Reachable blob OIDs that visibility ALLOWS `caller` at some path. The
/// caller-aware generalization of `replicable_blob_set` (which is the anonymous
/// `caller = None` case). Used by `GET /ipfs/{cid}` to gate fail-closed against
/// dangling/unreachable blobs (#126): a blob written via `git hash-object -w`
/// but unreferenced is absent from the reachable walk, so it is never in this
/// set and the IPFS serve path drops it — even from the owner, who has no path
/// to authorize the blob at.
///
/// A blob reachable at an allowed path is included even when also denied
/// elsewhere (its content is readable to this caller elsewhere). Trees and
/// commits are NOT included here; the caller decides per object type whether
/// the allow-set applies (it does not for trees/commits — KTD3).
pub fn allowed_blob_set_for_caller(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    let pairs = blob_paths(repo_path)?;
    let mut allowed = HashSet::new();
    for (oid, path) in &pairs {
        if visibility_check(rules, is_public, owner_did, caller, path) == Decision::Allow {
            allowed.insert(oid.clone());
        }
    }
    Ok(allowed)
}

/// Objects safe to replicate, failing closed on blobs (#99). A candidate
/// replicates iff it is NOT a blob (`all_blob_oids` — commits and trees are
/// structural, never content-withheld) OR it is in `allowed_blobs` (reachable
/// and visibility-allowed). This drops both withheld reachable blobs and
/// dangling/unreachable blobs the reachable walk never classified, without
/// tagging the candidate list with per-object types. Used on the full-scan pin
/// path, where the candidate set can contain dangling objects the reachable-only
/// withheld set cannot cover; the delta path keeps `replicable_objects`.
pub fn replicable_objects_fail_closed(
    candidates: Vec<String>,
    allowed_blobs: &HashSet<String>,
    all_blob_oids: &HashSet<String>,
) -> Vec<String> {
    candidates
        .into_iter()
        .filter(|oid| !all_blob_oids.contains(oid) || allowed_blobs.contains(oid))
        .collect()
}

/// For every blob withheld from anonymous, the DIDs allowed to read it: the
/// owner plus any reader DID that `visibility_check` Allows at some path the
/// blob appears at. Least-privilege: a reader of one private subtree is not a
/// recipient of a blob that only lives in another.
pub fn withheld_blob_recipients(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> Result<HashMap<String, BTreeSet<String>>> {
    // One history walk feeds both the withheld set and the recipient mapping.
    let pairs = blob_paths(repo_path)?;
    let withheld = withheld_from_pairs(&pairs, rules, is_public, owner_did, None);
    if withheld.is_empty() {
        return Ok(HashMap::new());
    }
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for r in rules {
        for d in &r.reader_dids {
            candidates.insert(d.clone());
        }
    }
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (oid, path) in &pairs {
        if !withheld.contains(oid) {
            continue;
        }
        let entry = out.entry(oid.clone()).or_default();
        entry.insert(owner_did.to_string());
        for did in &candidates {
            if visibility_check(rules, is_public, owner_did, Some(did), path) == Decision::Allow {
                entry.insert(did.clone());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::VisibilityMode;
    use chrono::Utc;
    use std::process::Command;
    use tempfile::TempDir;

    fn rule(path_glob: &str, readers: &[&str]) -> VisibilityRule {
        VisibilityRule {
            id: "x".into(),
            repo_id: "r1".into(),
            path_glob: path_glob.into(),
            mode: VisibilityMode::B,
            reader_dids: readers.iter().map(|s| s.to_string()).collect(),
            created_by: "did:key:zOwner".into(),
            created_at: Utc::now(),
        }
    }

    const OWNER: &str = "did:key:zOwner";

    /// Build a bare repo with public/a.txt and secret/b.txt at one commit.
    /// Returns (tempdir, bare_path, secret_blob_oid, public_blob_oid).
    fn fixture() -> (TempDir, std::path::PathBuf, String, String) {
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let run = |args: &[&str], dir: &Path| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?} failed");
        };
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"public bytes\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"TOP SECRET\n").unwrap();
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        let oid = |path: &str| {
            let out = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{path}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let secret = oid("secret/b.txt");
        let public = oid("public/a.txt");
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        (td, bare, secret, public)
    }

    #[test]
    fn anonymous_caller_withholds_only_private_blob() {
        let (_td, bare, secret_oid, public_oid) = fixture();
        let rules = [rule("/secret/**", &[])];
        // caller = None models the public / any peer: what must not replicate.
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "secret blob must be withheld"
        );
        assert!(
            !withheld.contains(&public_oid),
            "public blob must replicate"
        );
        // Trees and commits are never withheld; the set holds only the secret blob.
        assert_eq!(withheld.len(), 1, "only the secret blob OID is withheld");
    }

    #[test]
    fn non_reader_withholds_only_the_private_blob() {
        let (_td, bare, secret, public) = fixture();
        let rules = [rule("/secret/**", &["did:key:zFriend"])];
        let withheld =
            withheld_blob_oids(&bare, &rules, true, OWNER, Some("did:key:zStranger")).unwrap();
        assert!(withheld.contains(&secret), "secret blob must be withheld");
        assert!(
            !withheld.contains(&public),
            "public blob must NOT be withheld"
        );
    }

    #[test]
    fn owner_withholds_nothing() {
        let (_td, bare, secret, public) = fixture();
        let rules = [rule("/secret/**", &["did:key:zFriend"])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, Some(OWNER)).unwrap();
        assert!(withheld.is_empty(), "owner sees everything");
        let _ = (secret, public);
    }

    #[test]
    fn listed_reader_withholds_nothing() {
        let (_td, bare, _secret, _public) = fixture();
        let rules = [rule("/secret/**", &["did:key:zFriend"])];
        let withheld =
            withheld_blob_oids(&bare, &rules, true, OWNER, Some("did:key:zFriend")).unwrap();
        assert!(withheld.is_empty(), "listed reader sees the subtree");
    }

    #[test]
    fn no_subtree_rules_withholds_nothing() {
        let (_td, bare, _secret, _public) = fixture();
        let withheld = withheld_blob_oids(&bare, &[], true, OWNER, None).unwrap();
        assert!(
            withheld.is_empty(),
            "public repo, no rules, nothing withheld"
        );
    }

    #[test]
    fn has_path_scoped_rule_empty_is_false() {
        assert!(!has_path_scoped_rule(&[]));
    }

    #[test]
    fn has_path_scoped_rule_single_root_is_false() {
        assert!(!has_path_scoped_rule(&[rule("/", &[])]));
    }

    #[test]
    fn has_path_scoped_rule_single_scoped_is_true() {
        assert!(has_path_scoped_rule(&[rule("/secret/**", &[])]));
    }

    #[test]
    fn has_path_scoped_rule_mixed_is_true() {
        assert!(has_path_scoped_rule(&[
            rule("/", &[]),
            rule("/secret/**", &[]),
        ]));
    }

    #[test]
    fn has_path_scoped_rule_multiple_root_is_false() {
        assert!(!has_path_scoped_rule(&[rule("/", &[]), rule("/", &[])]));
    }

    #[test]
    fn has_path_scoped_rule_safety_invariant_matches_withheld_walk() {
        // Pin the claim the predicate's docs make, with its real precondition:
        // when no rule is path-scoped, then *for any caller that has passed the
        // whole-repo "/" gate*, withheld_blob_oids returns an empty set, so the
        // walk is safe to skip. The "/" gate (resolved before the serve /
        // replication call sites) is what excludes the denying-root caller; this
        // function does not re-check it, so the test models only gate-passing
        // callers — matching how U2/U3 consult the predicate.
        let (_td, bare, _secret, _public) = fixture();
        // (rules, caller) pairs where the caller is Allowed at "/":
        //  - public repo, no rules, anonymous: "/" allows (is_public).
        //  - root-only allow-rule, the listed reader: "/" allows them.
        //  - root-only deny-all rule, the owner: owner bypasses every rule.
        let cases: [(Vec<VisibilityRule>, Option<&str>); 3] = [
            (Vec::new(), None),
            (
                vec![rule("/", &["did:key:zFriend"])],
                Some("did:key:zFriend"),
            ),
            (vec![rule("/", &[])], Some(OWNER)),
        ];
        for (rules, caller) in cases {
            assert!(!has_path_scoped_rule(&rules));
            let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, caller).unwrap();
            assert!(
                withheld.is_empty(),
                "no path-scoped rule must withhold nothing for a gate-passing caller (caller={caller:?})"
            );
        }
    }

    #[test]
    fn serve_decision_skips_walk_for_root_only_and_withholds_for_path_scoped() {
        // Drive the git_upload_pack serve decision over a real bare repo, both
        // branches the has_path_scoped_rule gate selects, for the INV-2 caller:
        // a reader allowed at whole-repo "/" but denied a path-scoped subtree.
        // `replicable_objects` is the seam the serve path filters through, so the
        // returned set models exactly what the served pack would carry.
        let (_td, bare, secret, public) = fixture();
        let reader = Some("did:key:zReader");
        let all = vec![secret.clone(), public.clone()];

        // Branch A — predicate false: skip the walk and serve the full pack. The
        // skip is only sound if the walk would have withheld nothing, so assert
        // the walk is empty and the served set is complete.
        let root_only = vec![rule("/", &["did:key:zReader"])];
        assert!(!has_path_scoped_rule(&root_only));
        let withheld_a = withheld_blob_oids(&bare, &root_only, true, OWNER, reader).unwrap();
        assert!(
            withheld_a.is_empty(),
            "root-only rules withhold nothing for a gate-passing reader; the skip is safe"
        );
        let served_a = replicable_objects(all.clone(), &withheld_a);
        assert!(
            served_a.contains(&secret) && served_a.contains(&public),
            "the full pack is served when no rule is path-scoped"
        );

        // Branch B — predicate true: run the walk and serve the filtered pack.
        // /secret/** is scoped to a different DID, so the reader (allowed at "/")
        // is denied /secret and the secret blob must be excluded.
        let scoped = vec![
            rule("/", &["did:key:zReader"]),
            rule("/secret/**", &["did:key:zOther"]),
        ];
        assert!(has_path_scoped_rule(&scoped));
        let withheld_b = withheld_blob_oids(&bare, &scoped, true, OWNER, reader).unwrap();
        let served_b = replicable_objects(all, &withheld_b);
        assert!(
            !served_b.contains(&secret),
            "a reader denied /secret must not be served the secret blob"
        );
        assert!(
            served_b.contains(&public),
            "the public blob the reader may see stays in the served pack"
        );

        // Branch C — same path-scoped rules, but the caller is the owner. The
        // owner bypasses every rule, so the walk withholds nothing and the full
        // pack (secret included) is served even though a path-scoped rule exists.
        let withheld_c = withheld_blob_oids(&bare, &scoped, true, OWNER, Some(OWNER)).unwrap();
        assert!(
            withheld_c.is_empty(),
            "the owner bypasses path-scoped rules and is served everything"
        );
    }

    #[test]
    fn replicable_objects_drops_withheld_keeps_rest() {
        let all = vec!["aaa".to_string(), "bbb".to_string(), "ccc".to_string()];
        let withheld: HashSet<String> = ["bbb".to_string()].into_iter().collect();
        let got = replicable_objects(all, &withheld);
        assert_eq!(got, vec!["aaa".to_string(), "ccc".to_string()]);
    }

    #[test]
    fn replicable_objects_empty_withheld_keeps_all() {
        let all = vec!["aaa".to_string(), "bbb".to_string()];
        let withheld: HashSet<String> = HashSet::new();
        let got = replicable_objects(all.clone(), &withheld);
        assert_eq!(got, all);
    }

    #[test]
    fn fail_closed_keeps_nonblobs_and_allowed_blobs_only() {
        // Non-blob objects (commit/tree) always pass; a blob passes only if it
        // is in the allowed set. A withheld blob and a dangling blob (both in
        // all_blob_oids, neither in allowed) are dropped.
        let allowed: HashSet<String> = ["b_pub".to_string()].into_iter().collect();
        let all_blobs: HashSet<String> = ["b_pub", "b_secret", "b_dangling"]
            .into_iter()
            .map(String::from)
            .collect();
        let candidates = vec![
            "commit1".to_string(),
            "tree1".to_string(),
            "b_pub".to_string(),
            "b_secret".to_string(),
            "b_dangling".to_string(),
        ];
        let got = replicable_objects_fail_closed(candidates, &allowed, &all_blobs);
        assert_eq!(
            got,
            vec![
                "commit1".to_string(),
                "tree1".to_string(),
                "b_pub".to_string()
            ]
        );
    }

    #[test]
    fn fail_closed_drops_dangling_private_blob() {
        // #99: a private blob orphaned by a force-push/amend is unreachable but
        // still present in the object DB. The full-scan candidate set includes
        // it; the reachable-only allowed walk never classifies it. The
        // fail-closed filter must drop it — it is a blob not in the allowed set.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"public bytes\n").unwrap();
        let run = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&work)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        run(&["add", "."]);
        run(&["commit", "-qm", "init"]);
        let oid_of = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let public_oid = oid_of("HEAD:public/a.txt");

        // Write a blob straight into the object DB, referenced by no tree or
        // commit — exactly the dangling state #99 is about.
        std::fs::write(work.join("orphan.bin"), b"DANGLING SECRET\n").unwrap();
        let dangling_oid = {
            let out = Command::new("git")
                .args(["hash-object", "-w", "orphan.bin"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        let all_blobs = crate::git::push_delta::all_blob_oids(&work).unwrap();
        assert!(
            all_blobs.contains(&dangling_oid),
            "precondition: the dangling blob is in the all-objects universe"
        );

        let rules: Vec<VisibilityRule> = vec![];
        let allowed = replicable_blob_set(&work, &rules, true, OWNER).unwrap();
        assert!(
            !allowed.contains(&dangling_oid),
            "dangling blob is unreachable, so never in the allowed set"
        );
        assert!(
            allowed.contains(&public_oid),
            "reachable public blob is in the allowed set"
        );

        // Full-scan candidate set includes the dangling blob; fail-closed drops it.
        let candidates = vec![dangling_oid.clone(), public_oid.clone()];
        let replicable = replicable_objects_fail_closed(candidates, &allowed, &all_blobs);
        assert!(
            !replicable.contains(&dangling_oid),
            "#99: a dangling private blob must not replicate"
        );
        assert!(
            replicable.contains(&public_oid),
            "the public blob still replicates"
        );
    }

    #[test]
    fn allowed_set_excludes_dangling_blob_for_every_caller() {
        // #126: a blob written via `git hash-object -w` but never referenced has
        // no path to gate on, so it is absent from the reachable allowed-set —
        // for anonymous callers, listed readers, AND the owner. The IPFS serve
        // path relies on this fail-closed property to drop dangling withheld
        // blobs that the deny-set model leaked.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"public bytes\n").unwrap();
        let run = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&work)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        run(&["add", "."]);
        run(&["commit", "-qm", "init"]);
        let oid_of = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let public_oid = oid_of("HEAD:public/a.txt");

        std::fs::write(work.join("orphan.bin"), b"DANGLING SECRET\n").unwrap();
        let dangling_oid = {
            let out = Command::new("git")
                .args(["hash-object", "-w", "orphan.bin"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert!(
            matches!(dangling_oid.len(), 40 | 64),
            "precondition: hash-object stored the dangling blob"
        );

        // Path-scoped rule: /secret/** denied to anon, allowed to a listed reader.
        let reader = "did:key:zReader";
        let rules = [rule("/secret/**", &[reader])];

        // Every gate-relevant caller: anonymous, listed reader, owner. None of
        // them can put the dangling blob in the allowed set — it has no path.
        for caller in [None, Some(reader), Some(OWNER)] {
            let allowed = allowed_blob_set_for_caller(&work, &rules, true, OWNER, caller).unwrap();
            assert!(
                !allowed.contains(&dangling_oid),
                "dangling blob must be absent from allowed-set (caller={caller:?})"
            );
            // Sanity: the reachable public blob is still in the set for every
            // caller (the rule does not deny /public/**).
            assert!(
                allowed.contains(&public_oid),
                "reachable public blob must be in allowed-set (caller={caller:?})"
            );
        }
    }

    #[test]
    fn recipients_are_owner_plus_allowed_readers_only() {
        let (_td, repo, secret_oid, public_oid) = fixture();
        let reader = "did:key:zReader";
        let rules = vec![rule("/secret/**", &[reader])];
        let map = withheld_blob_recipients(&repo, &rules, true, OWNER).unwrap();

        let recips = map.get(&secret_oid).expect("secret blob has recipients");
        assert!(recips.contains(OWNER));
        assert!(recips.contains(reader));
        assert!(
            !map.contains_key(&public_oid),
            "public blob is not encrypted"
        );
    }

    #[test]
    fn node_seal_open_round_trip() {
        use gitlawb_core::encrypt::{open_blob, seal_blob};
        use gitlawb_core::identity::Keypair;
        let (_td, repo, secret_oid, _public) = fixture();
        let (_t, bytes) = crate::git::store::read_object(&repo, &secret_oid)
            .unwrap()
            .unwrap();
        let reader = Keypair::generate();
        let env = seal_blob(&bytes, &[reader.verifying_key()]).unwrap();
        assert_eq!(open_blob(&env, &reader).unwrap(), bytes);
    }

    #[test]
    fn withholds_blob_reachable_only_via_nonstandard_ref() {
        let (_td, bare, secret_oid, _public) = fixture();
        // Move the sole ref out of refs/heads/* into a custom namespace so the
        // secret blob is reachable only through a ref the old heads/tags filter
        // skipped. It must still be withheld.
        let head_ref = {
            let out = Command::new("git")
                .args(["symbolic-ref", "HEAD"])
                .current_dir(&bare)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let run = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&bare)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["update-ref", "refs/custom/snap", "HEAD"]);
        run(&["update-ref", "-d", &head_ref]);

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "blob reachable only via refs/custom/* must still be withheld"
        );
    }

    #[test]
    fn withholds_blob_reachable_only_via_detached_head() {
        let (_td, bare, secret_oid, _public) = fixture();
        // Detach HEAD onto the only commit, then delete the branch it pointed to,
        // so the secret blob is reachable ONLY through HEAD. `for-each-ref` omits
        // HEAD, but `rev-list --all` (pin) and upload-pack (serve) reach it, so it
        // must still be withheld.
        let head_ref = {
            let out = Command::new("git")
                .args(["symbolic-ref", "HEAD"])
                .current_dir(&bare)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let head_oid = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&bare)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let run = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&bare)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["update-ref", "--no-deref", "HEAD", &head_oid]);
        run(&["update-ref", "-d", &head_ref]);

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "blob reachable only via detached HEAD must still be withheld"
        );
    }

    #[test]
    fn withholds_secret_blob_deleted_at_tip_but_reachable_in_history() {
        // commit 1 adds secret/b.txt; commit 2 deletes it. The secret blob is no
        // longer in any ref-tip tree, but `rev-list --objects --all` (pin) and
        // upload-pack (serve) still expose it from history, so it must be withheld.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("public.txt"), b"public\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"TOP SECRET\n").unwrap();
        let run = |args: &[&str], dir: &Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "c1"], &work);
        let secret_oid = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD:secret/b.txt"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        run(&["rm", "-q", "secret/b.txt"], &work);
        run(&["commit", "-qm", "c2 delete secret"], &work);
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        // Sanity: the blob is gone from the tip tree but still in the pin set.
        let tip = Command::new("git")
            .args(["ls-tree", "-r", "HEAD"])
            .current_dir(&bare)
            .output()
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&tip.stdout).contains(&secret_oid),
            "precondition: secret blob is absent from the tip tree"
        );

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "secret blob deleted at the tip but reachable in history must be withheld"
        );
    }

    #[test]
    fn withholds_secret_blob_at_non_ascii_path() {
        // A secret blob under a non-ASCII path inside a denied subtree must be
        // withheld. Plain `git ls-tree -r` C-quotes the path (café.txt becomes
        // "secret/caf\303\251.txt"), which would not match "/secret/**" and would
        // leak the blob in cleartext; `-rz` emits the raw path so the rule matches.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("public.txt"), b"public\n").unwrap();
        std::fs::write(work.join("secret/café.txt"), b"TOP SECRET\n").unwrap();
        let run = |args: &[&str], dir: &Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        let oid = |path: &str| {
            let out = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{path}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let secret_oid = oid("secret/café.txt");
        let public_oid = oid("public.txt");
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "secret blob at a non-ASCII path must be withheld"
        );
        // Guard against an over-withholding (deny-all) regression: the public blob
        // must still replicate.
        assert!(
            !withheld.contains(&public_oid),
            "public blob must NOT be withheld"
        );
    }

    #[test]
    fn withholds_secret_blob_across_nfc_nfd_normalization_skew() {
        // #101: the secret lives under a directory whose name is committed in NFD
        // ("se" + combining acute U+0301), while the deny rule is authored in NFC
        // ("é" = U+00E9). The variant byte sits INSIDE the rule-covered directory
        // name, so a byte-exact matcher under-withholds and leaks the blob on the
        // replication path. NFC normalization at the matcher seam closes it. (The
        // sibling café.txt test does not exercise this: there the rule prefix
        // "/secret" is pure ASCII and byte-identical regardless of how é is encoded
        // in the filename, so it passes for the wrong reason.)
        let nfd_dir = "se\u{0301}cret"; // decomposed
        let nfc_rule = "/s\u{00e9}cret/**"; // composed
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(work.join(nfd_dir)).unwrap();
        std::fs::write(work.join("public.txt"), b"public\n").unwrap();
        std::fs::write(work.join(nfd_dir).join("key.pem"), b"TOP SECRET\n").unwrap();
        let run = |args: &[&str], dir: &Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["config", "core.precomposeunicode", "false"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        let oid = |path: &str| {
            let out = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{path}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let secret_oid = oid(&format!("{nfd_dir}/key.pem"));
        let public_oid = oid("public.txt");
        // Guard against a vacuous pass: the NFD-named blob must actually exist.
        // Accept SHA-1 (40) or SHA-256 (64) object ids so the test is
        // hash-format agnostic, matching the fixture guard later in this file.
        assert!(
            matches!(secret_oid.len(), 40 | 64),
            "secret blob was not stored under the NFD path"
        );
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        let rules = [rule(nfc_rule, &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "NFC-authored deny rule must withhold the secret blob under the NFD-named directory"
        );
        assert!(
            !withheld.contains(&public_oid),
            "public blob must NOT be withheld"
        );
    }

    // TAB/newline are legal filename bytes on unix but rejected by the Windows
    // filesystem, so building the fixture only makes sense (and only compiles the
    // OsStr handling) under cfg(unix), matching fails_closed_on_non_utf8_path.
    #[cfg(unix)]
    #[test]
    fn withholds_secret_blob_at_path_with_tab_and_newline() {
        // A path containing literal TAB and newline bytes must still be withheld.
        // This pins two parse choices: `-rz` emits the path raw (plain `-r` would
        // C-quote the TAB/newline and break the "/secret/**" match), and splitting
        // records on NUL rather than newline keeps the embedded newline from
        // splitting one record into two and truncating the path. A revert to
        // `git ls-tree -r` or to `.lines()` would regress this case.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("public.txt"), b"public\n").unwrap();
        let weird = "secret/a\tb\nc.txt";
        std::fs::write(work.join(weird), b"TOP SECRET\n").unwrap();
        let run = |args: &[&str], dir: &Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        let oid = |path: &str| {
            let out = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{path}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let secret_oid = oid(weird);
        let public_oid = oid("public.txt");
        // Guard against a vacuous pass: if git ever failed to store the oddly-named
        // file, rev-parse would yield an empty/garbage string and the withholding
        // assert could trivially hold. A real blob OID is a 40-char (SHA-1) or
        // 64-char (SHA-256) hex id.
        assert!(
            matches!(secret_oid.len(), 40 | 64),
            "fixture did not store the TAB/newline path (got oid {secret_oid:?})"
        );
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "secret blob at a path with TAB/newline must be withheld"
        );
        assert!(
            !withheld.contains(&public_oid),
            "public blob must NOT be withheld"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fails_closed_on_non_utf8_path() {
        // A path with a non-UTF-8 byte (here an invalid 0xFF in the denied
        // directory name) must not be lossy-decoded: U+FFFD substitution would stop
        // the path matching its deny rule and leak the blob. blob_paths must fail
        // closed (Err) instead. git stores raw path bytes, so we write the tree by
        // hand via `git update-index --cacheinfo` to embed the invalid byte.
        use std::os::unix::ffi::OsStrExt;
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(&work).unwrap();
        let run = |args: &[&str], dir: &Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        // Hash a blob, then index it at a path whose directory byte is invalid UTF-8.
        let blob_oid = {
            let out = Command::new("git")
                .args(["hash-object", "-w", "--stdin"])
                .current_dir(&work)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut c| {
                    use std::io::Write;
                    c.stdin.take().unwrap().write_all(b"TOP SECRET\n")?;
                    c.wait_with_output()
                })
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let mut bad_path = std::ffi::OsString::from("s");
        bad_path.push(std::ffi::OsStr::from_bytes(&[0xFF]));
        bad_path.push("cret/b.txt");
        let cacheinfo = {
            let mut s = std::ffi::OsString::from(format!("100644,{blob_oid},"));
            s.push(&bad_path);
            s
        };
        assert!(
            Command::new("git")
                .arg("update-index")
                .arg("--add")
                .arg("--cacheinfo")
                .arg(&cacheinfo)
                .current_dir(&work)
                .status()
                .unwrap()
                .success(),
            "git update-index failed"
        );
        run(&["commit", "-qm", "init"], &work);
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        let rules = [rule("/s\u{fffd}cret/**", &[])];
        let result = withheld_blob_oids(&bare, &rules, true, OWNER, None);
        assert!(
            result.is_err(),
            "a non-UTF-8 path must fail closed (Err), not be lossy-decoded and leaked"
        );
    }

    #[test]
    fn fails_closed_when_a_ref_cannot_be_traversed() {
        let (_td, bare, secret, _public) = fixture();
        // Point a ref at a blob (a valid object that is not tree-ish). `ls-tree -r`
        // fails on it; that must propagate as Err rather than silently dropping the
        // ref and under-withholding.
        std::fs::write(bare.join("refs/heads/blobref"), format!("{secret}\n")).unwrap();
        let rules = [rule("/secret/**", &[])];
        let result = withheld_blob_oids(&bare, &rules, true, OWNER, None);
        assert!(
            result.is_err(),
            "a ref that cannot be traversed must fail closed (Err)"
        );
    }

    #[test]
    fn annotated_tag_to_commit_does_not_fail_closed() {
        let (_td, bare, secret_oid, _public) = fixture();
        // An annotated tag — even one nested over another annotated tag —
        // ultimately resolves to a commit, so it must NOT trip the non-commit
        // fail-closed guard. A one-level `%(*objecttype)` peel would misread the
        // nested tag as a non-commit and refuse the whole walk.
        let run = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&bare)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        run(&["tag", "-a", "-m", "inner", "v1", "HEAD"]);
        run(&["tag", "-a", "-m", "outer", "v2", "v1"]);

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "secret blob must still be withheld with annotated and nested tags present"
        );
    }

    #[test]
    fn fails_closed_on_annotated_tag_of_a_blob() {
        let (_td, bare, secret, _public) = fixture();
        // An annotated tag whose target peels to a blob is not a commit; the
        // guard must fail closed rather than skip the ref.
        let run = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&bare)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        run(&["tag", "-a", "-m", "blobtag", "blobtag", &secret]);

        let rules = [rule("/secret/**", &[])];
        let result = withheld_blob_oids(&bare, &rules, true, OWNER, None);
        assert!(
            result.is_err(),
            "an annotated tag of a blob must fail closed (Err)"
        );
    }

    #[test]
    fn fails_closed_when_a_ref_points_at_a_missing_object() {
        let (_td, bare, _secret, _public) = fixture();
        // A ref whose target object does not exist (pruned object, corrupt ref)
        // peels to `<query> missing`. for-each-ref still lists it, so the guard
        // must fail closed rather than skip the unclassifiable ref.
        std::fs::write(
            bare.join("refs/heads/dangling"),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n",
        )
        .unwrap();
        let rules = [rule("/secret/**", &[])];
        let result = withheld_blob_oids(&bare, &rules, true, OWNER, None);
        assert!(
            result.is_err(),
            "a ref pointing at a missing object must fail closed (Err)"
        );
    }

    #[test]
    fn many_long_named_unresolvable_refs_do_not_deadlock() {
        // Regression guard for the cat-file stdin/stdout deadlock. cat-file
        // echoes the full query on a `<query> missing` line, so a few hundred
        // long-named dangling refs emit >64 KiB of stdout — enough to fill the
        // pipe buffer and hang a write-all-before-drain implementation. The
        // concurrent stdin writer must keep it live and fail closed. Bounded by
        // a timeout so a regression fails the test instead of hanging the suite.
        let (_td, bare, _secret, _public) = fixture();
        let longname = "z".repeat(200);
        let mut packed = String::new();
        for i in 0..500 {
            packed.push_str(&format!(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef refs/heads/{longname}-{i}\n"
            ));
        }
        std::fs::write(bare.join("packed-refs"), packed).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rules = [rule("/secret/**", &[])];
            let is_err = withheld_blob_oids(&bare, &rules, true, OWNER, None).is_err();
            let _ = tx.send(is_err);
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(is_err) => assert!(is_err, "refs pointing at missing objects must fail closed"),
            Err(_) => panic!("withheld_blob_oids did not return within 10s (deadlock?)"),
        }
    }

    #[test]
    fn same_blob_at_allowed_and_denied_path_is_not_withheld() {
        // Identical content at a denied and an allowed path shares one blob OID.
        // A blob reachable through ANY allowed path must not be withheld.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let run = |args: &[&str], dir: &Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?} failed"
            );
        };
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("secret/shared.txt"), b"SHARED\n").unwrap();
        std::fs::write(work.join("public/shared.txt"), b"SHARED\n").unwrap();
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        let oid = |path: &str| {
            let out = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{path}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let shared_oid = oid("secret/shared.txt");
        assert_eq!(
            shared_oid,
            oid("public/shared.txt"),
            "precondition: identical content shares one blob OID"
        );
        run(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            !withheld.contains(&shared_oid),
            "a blob also reachable via an allowed path must not be withheld"
        );
    }
}
