//! Resolve which blob OIDs must be withheld from a caller because every path
//! at which the blob appears is denied by the repo's visibility rules. Trees
//! and commits are never withheld (mode B keeps SHAs intact); only blob
//! content is held back.

use crate::db::VisibilityRule;
use crate::git::store;
use crate::visibility::{visibility_check, Decision};
use anyhow::{Context, Result};
use std::collections::HashSet;
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

/// Objects that may replicate to the public: everything not in `withheld`.
/// Order-preserving. The single seam every replication site (IPFS, Pinata)
/// passes its object list through; option B would later reroute the withheld
/// ones through encrypt-then-pin instead of dropping them.
pub fn replicable_objects(all: Vec<String>, withheld: &HashSet<String>) -> Vec<String> {
    all.into_iter()
        .filter(|oid| !withheld.contains(oid))
        .collect()
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
}
