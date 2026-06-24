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

/// List every (blob_oid, "/repo/relative/path") pair reachable from any branch
/// ref in `repo_path`. Uses `git ls-tree -r` per ref so each path a blob lives
/// at is represented (the same blob content can appear at several paths). Paths
/// are returned with a leading "/" to match the glob form used by visibility
/// rules ("/secret/**").
fn blob_paths(repo_path: &Path) -> Result<Vec<(String, String)>> {
    let refs = store::list_refs(repo_path).context("list_refs failed")?;
    let mut out = Vec::new();
    for (refname, _oid) in refs {
        if !refname.starts_with("refs/heads/") && !refname.starts_with("refs/tags/") {
            continue;
        }
        let listing = std::process::Command::new("git")
            .args(["ls-tree", "-r", &refname])
            .current_dir(repo_path)
            .output()
            .context("git ls-tree -r failed")?;
        if !listing.status.success() {
            continue;
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
                    out.push((oid.to_string(), format!("/{path}")));
                }
            }
        }
    }
    Ok(out)
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
    let mut denied: HashSet<String> = HashSet::new();
    let mut allowed: HashSet<String> = HashSet::new();
    for (oid, path) in blob_paths(repo_path)? {
        match visibility_check(rules, is_public, owner_did, caller, &path) {
            Decision::Deny => {
                denied.insert(oid);
            }
            Decision::Allow => {
                allowed.insert(oid);
            }
        }
    }
    Ok(denied.difference(&allowed).cloned().collect())
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
    let withheld = withheld_blob_oids(repo_path, rules, is_public, owner_did, None)?;
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
    for (oid, path) in blob_paths(repo_path)? {
        if !withheld.contains(&oid) {
            continue;
        }
        let entry = out.entry(oid).or_default();
        entry.insert(owner_did.to_string());
        for did in &candidates {
            if visibility_check(rules, is_public, owner_did, Some(did), &path) == Decision::Allow {
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
}
