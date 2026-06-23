//! Push-delta object enumeration for the IPFS/Pinata pin path.
//!
//! The pin path needs the set of git objects to consider for pinning after a
//! push. Historically both pin functions enumerated the *whole* repo
//! (`git cat-file --batch-all-objects`) on every push, so cost scaled with
//! repo size rather than push size (finding N16). This module computes the
//! per-push *delta* instead — the objects a push introduced — and keeps the
//! whole-repo lister for the reconciliation sweep and the fail-closed fallback.
//!
//! ## Correctness framing (do not confuse with the #84 withholding direction)
//!
//! The pin enumeration is part of the *exposure* set, not the withheld filter.
//! Narrowing it per push only *shrinks* what is pinned, so it cannot create an
//! under-withholding leak — the withheld filter (`visibility_pack`) still
//! subtracts from whatever, smaller, set we feed it. The only risk here is
//! *under-pinning* (a durability gap), which the reconciliation sweep backstops.
//!
//! Because the pin candidate set needs only the OID *set* (never the per-path
//! information the withheld classifier needs), `git rev-list --objects
//! --no-object-names` is safe here. The "rev-list reports one path per object"
//! trap from #84 applies only to `visibility_pack`'s per-path `ls-tree` walk.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Env var that forces the push path to always full-scan, bypassing the delta
/// optimization (KTD7 kill-switch). Reuses the already-tested fallback branch
/// rather than introducing a second enumeration path. Does not gate the sweep.
const FORCE_FULL_SCAN_ENV: &str = "GITLAWB_PIN_FORCE_FULLSCAN";

/// The objects a push introduced, or a signal that the delta could not be
/// computed safely and the caller should fall back to a full scan.
///
/// Three-valued by design: `Delta(vec![])` (a no-op push — pin nothing) is a
/// *different* fact from `FullScanRequired` (could not compute — fall back),
/// and they drive different actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCandidates {
    /// Objects reachable from the new tips but not the old tips.
    Delta(Vec<String>),
    /// The delta is not safe to use; the caller must enumerate the whole repo
    /// with [`list_all_objects`] instead. Returned on a non-commit tip, any git
    /// error, or the force-full-scan kill-switch.
    FullScanRequired,
}

/// Resolve the set of objects introduced by a push from its ref updates.
///
/// `new_tips` / `old_tips` are the non-zero new/old SHAs of the push's ref
/// updates (the caller strips the all-zeros create/delete sentinel). Keeping
/// the helper on plain SHA slices (not the `api` `RefUpdate` type) keeps it
/// unit-testable without the HTTP layer.
///
/// Fail-closed: any condition where the introduced set cannot be safely
/// determined returns [`PinCandidates::FullScanRequired`] rather than a partial
/// set, so the caller full-scans instead of silently under-pinning.
pub fn resolve_push_delta(repo_path: &Path, new_tips: &[&str], old_tips: &[&str]) -> PinCandidates {
    // KTD7 kill-switch: force the (already-tested) full-scan fallback. The env
    // read is split out from the pure logic so the resolver stays unit-testable
    // without touching process-global state.
    resolve_push_delta_inner(repo_path, new_tips, old_tips, force_full_scan())
}

/// Whether the force-full-scan kill-switch env var is set.
fn force_full_scan() -> bool {
    std::env::var_os(FORCE_FULL_SCAN_ENV).is_some()
}

// Intentionally private but reachable from the test module (via `use super::*`)
// so the kill-switch can be exercised without mutating process-global env.
fn resolve_push_delta_inner(
    repo_path: &Path,
    new_tips: &[&str],
    old_tips: &[&str],
    force_full_scan: bool,
) -> PinCandidates {
    if force_full_scan {
        tracing::debug!("{FORCE_FULL_SCAN_ENV} set — forcing full scan");
        return PinCandidates::FullScanRequired;
    }

    // A push that only deleted refs introduces no objects.
    if new_tips.is_empty() {
        return PinCandidates::Delta(Vec::new());
    }

    // Ref-type guard (the fail-closed mechanism). `git rev-list` does NOT error
    // on a non-commit tip — a blob/tree/tag-of-non-commit all exit 0 and walk
    // the object — so the rev-list exit code cannot catch this. Check each new
    // tip's *fully-peeled* type with `cat-file -t '<sha>^{}'` (recursive peel:
    // tag-of-commit -> commit, tag-of-tree -> tree, tag-of-tag-of-commit ->
    // commit). Bare `cat-file -t` returns `tag` for an annotated tag, and
    // `for-each-ref %(*objecttype)` peels only one level — neither is correct.
    for tip in new_tips {
        match peeled_object_type(repo_path, tip) {
            Some(t) if t == "commit" => {}
            other => {
                tracing::debug!(
                    tip = %tip,
                    peeled_type = ?other,
                    "push tip is not a commit (or type lookup failed) — forcing full scan"
                );
                return PinCandidates::FullScanRequired;
            }
        }
    }

    match rev_list_delta(repo_path, new_tips, old_tips) {
        Ok(oids) => PinCandidates::Delta(oids),
        Err(e) => {
            tracing::debug!(err = %e, "push-delta rev-list failed — forcing full scan");
            PinCandidates::FullScanRequired
        }
    }
}

/// Return the fully-peeled object type of `sha` (e.g. `commit`, `tree`,
/// `blob`), or `None` if the object is missing/unpeelable or git errored.
fn peeled_object_type(repo_path: &Path, sha: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["cat-file", "-t", &format!("{sha}^{{}}")])
        .current_dir(repo_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run `git rev-list --objects --no-object-names <new> --not <old>` and return
/// the bare OID set. Decides on `status.success()` *before* parsing stdout, so
/// a walk that prints a valid prefix then errors mid-walk is discarded.
fn rev_list_delta(repo_path: &Path, new_tips: &[&str], old_tips: &[&str]) -> Result<Vec<String>> {
    let mut args: Vec<&str> = vec!["rev-list", "--objects", "--no-object-names"];
    args.extend_from_slice(new_tips);
    if !old_tips.is_empty() {
        args.push("--not");
        args.extend_from_slice(old_tips);
    }

    let output = Command::new("git")
        .args(&args)
        .current_dir(repo_path)
        .output()
        .context("failed to run git rev-list for push delta")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-list failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// List every object in the repository via
/// `git cat-file --batch-all-objects --batch-check='%(objectname)'`.
///
/// This is the whole-repo enumeration the push path falls back to and the
/// reconciliation sweep relies on. It returns *all* objects (including
/// unreachable/dangling ones), which is what the sweep needs to catch
/// stragglers — do not swap it for a reachability walk.
pub fn list_all_objects(repo_path: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args([
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ])
        .current_dir(repo_path)
        .output()
        .context("failed to run git cat-file")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git cat-file failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Resolve the pin candidate OID set for a push, off the async worker.
///
/// Runs [`resolve_push_delta`] in `spawn_blocking` (git subprocess) and applies
/// the full-scan fallback for [`PinCandidates::FullScanRequired`]. Owns the
/// dispatch so the push call site stays thin and this wiring is unit-testable
/// without the HTTP layer.
///
/// Every degraded path is **logged**, not silent: a full-scan fallback, a
/// failed full scan, and a panicked blocking task each emit a warning. On a
/// failed full scan or a task panic the candidate set is empty (pin nothing
/// this push); that is a durability gap the reconciliation sweep backstops, and
/// it can never leak because the withheld filter still runs on whatever set is
/// returned.
pub async fn resolve_candidates_for_push(
    repo_path: PathBuf,
    new_tips: Vec<String>,
    old_tips: Vec<String>,
) -> Vec<String> {
    tokio::task::spawn_blocking(move || {
        let new_refs: Vec<&str> = new_tips.iter().map(String::as_str).collect();
        let old_refs: Vec<&str> = old_tips.iter().map(String::as_str).collect();
        match resolve_push_delta(&repo_path, &new_refs, &old_refs) {
            PinCandidates::Delta(objs) => {
                tracing::info!(delta = objs.len(), repo = %repo_path.display(), "pin candidate set from push delta");
                objs
            }
            PinCandidates::FullScanRequired => {
                tracing::warn!(repo = %repo_path.display(), "pin delta unavailable (non-commit tip, git error, or force-full-scan) — full-scan fallback");
                match list_all_objects(&repo_path) {
                    Ok(objs) => objs,
                    Err(e) => {
                        tracing::warn!(repo = %repo_path.display(), err = %e, "full-scan fallback failed; pinning nothing this push (reconciliation sweep backstops)");
                        Vec::new()
                    }
                }
            }
        }
    })
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(err = %e, "pin candidate computation task panicked; pinning nothing this push (reconciliation sweep backstops)");
        Vec::new()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::TempDir;

    /// Minimal git helper for building test repos.
    struct Repo {
        _td: TempDir,
        path: std::path::PathBuf,
    }

    impl Repo {
        fn new() -> Self {
            let td = TempDir::new().unwrap();
            let path = td.path().to_path_buf();
            let r = Repo { _td: td, path };
            r.git(&["init", "-q", "-b", "main"]);
            r.git(&["config", "user.email", "t@t"]);
            r.git(&["config", "user.name", "t"]);
            r
        }

        fn git(&self, args: &[&str]) -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(&self.path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn commit_file(&self, name: &str, body: &str) -> String {
            std::fs::write(self.path.join(name), body).unwrap();
            self.git(&["add", name]);
            self.git(&["commit", "-qm", &format!("add {name}")]);
            self.git(&["rev-parse", "HEAD"])
        }

        fn rev(&self, r: &str) -> String {
            self.git(&["rev-parse", r])
        }
    }

    const ZERO: &str = "0000000000000000000000000000000000000000";

    fn delta(c: PinCandidates) -> Vec<String> {
        match c {
            PinCandidates::Delta(v) => v,
            PinCandidates::FullScanRequired => panic!("expected Delta, got FullScanRequired"),
        }
    }

    #[test]
    fn single_new_commit_delta_excludes_preexisting_objects() {
        let repo = Repo::new();
        let c1 = repo.commit_file("a.txt", "one\n");
        let c2 = repo.commit_file("b.txt", "two\n");
        let got: HashSet<String> = delta(resolve_push_delta(&repo.path, &[&c2], &[&c1]))
            .into_iter()
            .collect();
        // The new blob b.txt and commit c2 are in the delta; the old blob a.txt
        // and commit c1 are not.
        let new_blob = repo.rev("HEAD:b.txt");
        let old_blob = repo.rev(&format!("{c1}:a.txt"));
        assert!(got.contains(&c2), "new commit in delta");
        assert!(got.contains(&new_blob), "new blob in delta");
        assert!(!got.contains(&c1), "old commit excluded");
        assert!(!got.contains(&old_blob), "old blob excluded");
    }

    #[test]
    fn created_ref_is_superset_of_new_objects() {
        // A created ref (old tip all-zeros, filtered out by caller) with no old
        // tips walks everything reachable from the new tip — a superset of the
        // genuinely new objects, never fewer.
        let repo = Repo::new();
        let c1 = repo.commit_file("a.txt", "one\n");
        let got: HashSet<String> = delta(resolve_push_delta(&repo.path, &[&c1], &[]))
            .into_iter()
            .collect();
        assert!(got.contains(&c1));
        assert!(got.contains(&repo.rev("HEAD:a.txt")));
        assert!(got.contains(&repo.rev("HEAD^{tree}")));
    }

    #[test]
    fn force_push_delta_is_objects_unique_to_new_tip() {
        let repo = Repo::new();
        let base = repo.commit_file("a.txt", "one\n");
        let old_tip = repo.commit_file("b.txt", "two\n");
        // Rewrite history: reset to base, commit a different file.
        repo.git(&["reset", "-q", "--hard", &base]);
        let new_tip = repo.commit_file("c.txt", "three\n");
        let got: HashSet<String> = delta(resolve_push_delta(&repo.path, &[&new_tip], &[&old_tip]))
            .into_iter()
            .collect();
        assert!(got.contains(&new_tip), "new tip in delta");
        assert!(got.contains(&repo.rev(&format!("{new_tip}:c.txt"))));
        // No error; force-push computes new-minus-old cleanly.
    }

    #[test]
    fn deleted_ref_only_yields_empty_delta_without_git() {
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        // All updates were deletions => new_tips empty after the caller strips zeros.
        assert_eq!(
            resolve_push_delta(&repo.path, &[], &[ZERO]),
            PinCandidates::Delta(Vec::new())
        );
    }

    #[test]
    fn blob_tip_forces_full_scan() {
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        let blob = repo.rev("HEAD:a.txt");
        assert_eq!(
            resolve_push_delta(&repo.path, &[&blob], &[]),
            PinCandidates::FullScanRequired,
            "a blob tip must force full scan (rev-list would exit 0 and walk it)"
        );
    }

    #[test]
    fn tree_tip_forces_full_scan() {
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        let tree = repo.rev("HEAD^{tree}");
        assert_eq!(
            resolve_push_delta(&repo.path, &[&tree], &[]),
            PinCandidates::FullScanRequired
        );
    }

    #[test]
    fn annotated_tag_of_tree_forces_full_scan() {
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        let tree = repo.rev("HEAD^{tree}");
        repo.git(&["tag", "-a", "treetag", "-m", "x", &tree]);
        let tag = repo.rev("treetag");
        assert_eq!(
            resolve_push_delta(&repo.path, &[&tag], &[]),
            PinCandidates::FullScanRequired,
            "annotated tag peeling to a tree must force full scan"
        );
    }

    #[test]
    fn tag_of_tag_of_noncommit_forces_full_scan() {
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        let blob = repo.rev("HEAD:a.txt");
        repo.git(&["tag", "-a", "t1", "-m", "x", &blob]);
        let t1 = repo.rev("t1");
        repo.git(&["tag", "-a", "t2", "-m", "x", &t1]);
        let t2 = repo.rev("t2");
        assert_eq!(
            resolve_push_delta(&repo.path, &[&t2], &[]),
            PinCandidates::FullScanRequired
        );
    }

    #[test]
    fn annotated_tag_of_commit_proceeds_as_delta() {
        // DISCRIMINATING positive-path regression: an annotated tag whose peeled
        // target is a commit must return Delta, not FullScanRequired. A
        // FullScanRequired here means the guard used bare `cat-file -t` (returns
        // `tag`) instead of the `^{}` peel.
        let repo = Repo::new();
        let c1 = repo.commit_file("a.txt", "one\n");
        repo.git(&["tag", "-a", "rel", "-m", "release", &c1]);
        let tag = repo.rev("rel");
        let got: HashSet<String> = delta(resolve_push_delta(&repo.path, &[&tag], &[]))
            .into_iter()
            .collect();
        assert!(
            got.contains(&c1),
            "peeled commit's objects are in the delta"
        );
    }

    #[test]
    fn tag_of_tag_of_commit_proceeds_as_delta() {
        // Deep-peel positive path: tag -> tag -> commit must recurse to `commit`
        // via `^{}` and return Delta. Complements tag_of_tag_of_noncommit (which
        // forces full scan) — guards against a regression in peel depth that
        // would silently downgrade a legitimate nested-tag push to full scan.
        let repo = Repo::new();
        let c1 = repo.commit_file("a.txt", "one\n");
        repo.git(&["tag", "-a", "t1", "-m", "x", &c1]);
        let t1 = repo.rev("t1");
        repo.git(&["tag", "-a", "t2", "-m", "x", &t1]);
        let t2 = repo.rev("t2");
        let got: HashSet<String> = delta(resolve_push_delta(&repo.path, &[&t2], &[]))
            .into_iter()
            .collect();
        assert!(
            got.contains(&c1),
            "peeled commit's objects are in the delta"
        );
    }

    #[tokio::test]
    async fn resolve_candidates_for_push_returns_delta() {
        // The extracted wiring returns the per-push delta on the happy path.
        let repo = Repo::new();
        let c1 = repo.commit_file("a.txt", "one\n");
        let c2 = repo.commit_file("b.txt", "two\n");
        let got: HashSet<String> =
            resolve_candidates_for_push(repo.path.clone(), vec![c2.clone()], vec![c1.clone()])
                .await
                .into_iter()
                .collect();
        let new_blob = repo.rev("HEAD:b.txt");
        assert!(
            got.contains(&c2) && got.contains(&new_blob),
            "new objects pinned"
        );
        assert!(!got.contains(&c1), "old commit excluded from delta");
    }

    #[tokio::test]
    async fn resolve_candidates_for_push_falls_back_to_full_scan_on_noncommit_tip() {
        // A non-commit tip forces FullScanRequired, and the wiring resolves that
        // to the whole-repo list (a superset), never an empty set.
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        let blob = repo.rev("HEAD:a.txt");
        let all: HashSet<String> = list_all_objects(&repo.path).unwrap().into_iter().collect();
        let got: HashSet<String> =
            resolve_candidates_for_push(repo.path.clone(), vec![blob], vec![])
                .await
                .into_iter()
                .collect();
        assert_eq!(got, all, "non-commit tip falls back to full repo scan");
    }

    #[test]
    fn missing_oid_tip_forces_full_scan() {
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        let bogus = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        assert_eq!(
            resolve_push_delta(&repo.path, &[bogus], &[]),
            PinCandidates::FullScanRequired,
            "a missing/corrupt tip OID must force full scan"
        );
    }

    #[test]
    fn present_noncommit_old_tip_is_safe() {
        // A present-but-non-commit old_sha (a --not arg) must not under-pin:
        // either rev-list errors (FullScanRequired) or it over-lists (Delta).
        // Either way the new tip's objects are covered; never fewer.
        let repo = Repo::new();
        let c1 = repo.commit_file("a.txt", "one\n");
        let c2 = repo.commit_file("b.txt", "two\n");
        let old_tree = repo.rev(&format!("{c1}^{{tree}}"));
        let result = resolve_push_delta(&repo.path, &[&c2], &[&old_tree]);
        match result {
            PinCandidates::FullScanRequired => {} // safe: caller full-scans
            PinCandidates::Delta(objs) => {
                // Safe direction: must still contain the new commit (over-list ok).
                assert!(objs.contains(&c2), "new tip objects must be covered");
            }
        }
    }

    #[test]
    fn multi_ref_push_unions_ranges() {
        let repo = Repo::new();
        let base = repo.commit_file("a.txt", "one\n");
        // branch1 advances
        let b1 = repo.commit_file("b.txt", "two\n");
        // branch2 from base advances independently
        repo.git(&["checkout", "-q", "-b", "branch2", &base]);
        let b2 = repo.commit_file("c.txt", "three\n");
        let got: HashSet<String> =
            delta(resolve_push_delta(&repo.path, &[&b1, &b2], &[&base, &base]))
                .into_iter()
                .collect();
        assert!(got.contains(&b1), "branch1 new commit");
        assert!(got.contains(&b2), "branch2 new commit");
    }

    #[test]
    fn empty_repo_no_tips_yields_empty_delta() {
        let repo = Repo::new();
        assert_eq!(
            resolve_push_delta(&repo.path, &[], &[]),
            PinCandidates::Delta(Vec::new())
        );
    }

    #[test]
    fn force_full_scan_flag_overrides() {
        // Test the kill-switch via the pure inner fn so we never touch
        // process-global env (which would race with parallel tests, and is
        // unsafe in Rust 2024). The public resolve_push_delta wires the env
        // read into this same flag.
        let repo = Repo::new();
        let c1 = repo.commit_file("a.txt", "one\n");
        assert_eq!(
            resolve_push_delta_inner(&repo.path, &[&c1], &[], true),
            PinCandidates::FullScanRequired
        );
        // And with the flag off, the same push yields a Delta.
        assert!(matches!(
            resolve_push_delta_inner(&repo.path, &[&c1], &[], false),
            PinCandidates::Delta(_)
        ));
    }

    #[test]
    fn list_all_objects_returns_full_repo() {
        let repo = Repo::new();
        repo.commit_file("a.txt", "one\n");
        repo.commit_file("b.txt", "two\n");
        let all = list_all_objects(&repo.path).unwrap();
        // 2 commits + 2 trees + 2 blobs = 6 objects.
        assert_eq!(all.len(), 6, "got: {all:?}");
    }
}
