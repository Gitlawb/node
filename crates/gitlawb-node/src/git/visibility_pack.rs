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
/// where HEAD reaches commits that no ref does. `git ls-tree -r <commit>` per commit
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
            .args(["ls-tree", "-r", commit])
            .current_dir(repo_path)
            .output()
            .context("git ls-tree -r failed")?;
        if !listing.status.success() {
            anyhow::bail!(
                "git ls-tree -r {commit} failed: {}",
                String::from_utf8_lossy(&listing.stderr)
            );
        }
        for line in String::from_utf8_lossy(&listing.stdout).lines() {
            // "<mode> blob <oid>\t<path>"
            let Some((meta, path)) = line.split_once('\t') else {
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

/// Objects that may replicate to the public: everything not in `withheld`.
/// Order-preserving. The single seam every replication site (IPFS, Pinata)
/// passes its object list through; option B would later reroute the withheld
/// ones through encrypt-then-pin instead of dropping them.
pub fn replicable_objects(all: Vec<String>, withheld: &HashSet<String>) -> Vec<String> {
    all.into_iter()
        .filter(|oid| !withheld.contains(oid))
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
