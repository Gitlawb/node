use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Initialize a new bare git repository with SHA-1 object format (default).
///
/// SHA-1 is used for maximum compatibility with standard git clients.
pub fn init_bare(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("repository already exists at {}", path.display());
    }
    std::fs::create_dir_all(path)?;

    let output = Command::new("git")
        .args(["init", "--bare", "--object-format=sha1"])
        .arg(path)
        .output()
        .context("failed to run git init")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git init failed: {stderr}");
    }

    // Write a default HEAD pointing to main
    std::fs::write(path.join("HEAD"), "ref: refs/heads/main\n")?;

    tracing::info!("initialized bare repo at {}", path.display());
    Ok(())
}

/// Check if a path contains a valid bare git repository.
#[allow(dead_code)]
pub fn is_valid_bare(path: &Path) -> bool {
    path.join("HEAD").exists() && path.join("objects").exists()
}

/// List all refs in a bare repository.
/// Returns (ref_name, commit_hash) pairs.
pub fn list_refs(repo_path: &Path) -> Result<Vec<(String, String)>> {
    let output = Command::new("git")
        .args(["for-each-ref", "--format=%(refname) %(objectname)"])
        .current_dir(repo_path)
        .output()
        .context("failed to run git for-each-ref")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git for-each-ref failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let refs = stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let refname = parts.next()?.to_string();
            let hash = parts.next()?.to_string();
            Some((refname, hash))
        })
        .collect();

    Ok(refs)
}

/// Read the object id a single ref currently points to. Returns None if the
/// ref does not exist. Used to snapshot a ref's pre-write state so a failed
/// durable upload can roll the local write back.
pub fn ref_oid(repo_path: &Path, ref_name: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", ref_name])
        .current_dir(repo_path)
        .output()
        .context("failed to run git rev-parse")?;
    if !output.status.success() {
        return Ok(None);
    }
    let oid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if oid.is_empty() {
        return Ok(None);
    }
    Ok(Some(oid))
}

/// Force a single ref back to a captured object id — rolls back a local write
/// (e.g. a merge commit) whose durable upload failed, so a local-fast-path
/// read does not serve the un-uploaded state. The now-dangling objects are
/// harmless.
pub fn set_ref(repo_path: &Path, ref_name: &str, oid: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["update-ref", ref_name, oid])
        .current_dir(repo_path)
        .output()
        .context("failed to run git update-ref")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git update-ref failed: {stderr}");
    }
    Ok(())
}

/// Restore a repo's refs to a previously captured snapshot: reset every
/// snapshot ref to its captured object id, and delete any ref that exists now
/// but was absent from the snapshot (created by the intervening write). Used
/// to roll back a receive-pack whose durable upload failed, so the next
/// local-fast-path read does not serve refs that never reached object storage.
/// Best-effort per ref: an individual failure is collected and reported, but
/// the remaining refs are still attempted.
pub fn restore_refs(repo_path: &Path, snapshot: &[(String, String)]) -> Result<()> {
    use std::collections::HashSet;

    let mut errors: Vec<String> = Vec::new();

    // Reset every snapshot ref to its captured oid (recreates refs the write
    // deleted, and rewinds refs the write advanced).
    for (ref_name, oid) in snapshot {
        if let Err(e) = set_ref(repo_path, ref_name, oid) {
            errors.push(format!("{ref_name}: {e}"));
        }
    }

    // Delete refs that exist now but were not in the snapshot (created by the
    // write being rolled back). A failure to LIST the current refs is collected
    // like any per-ref failure, never returned early: the snapshot-reset half
    // above already ran, and bailing here would discard its collected errors.
    let snapshot_names: HashSet<&str> = snapshot.iter().map(|(r, _)| r.as_str()).collect();
    match list_refs(repo_path) {
        Ok(current) => {
            for (ref_name, _) in &current {
                if !snapshot_names.contains(ref_name.as_str()) {
                    match Command::new("git")
                        .args(["update-ref", "-d", ref_name])
                        .current_dir(repo_path)
                        .output()
                    {
                        Ok(output) if output.status.success() => {}
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            errors.push(format!("{ref_name} (delete): {stderr}"));
                        }
                        Err(e) => {
                            errors.push(format!(
                                "{ref_name} (delete): failed to run git update-ref -d: {e}"
                            ));
                        }
                    }
                }
            }
        }
        Err(e) => {
            errors.push(format!("(extra-ref sweep) listing current refs: {e}"));
        }
    }

    if !errors.is_empty() {
        bail!(
            "failed to restore {} ref(s): {}",
            errors.len(),
            errors.join("; ")
        );
    }
    Ok(())
}

/// Read the current HEAD commit hash of a repository.
/// Returns None if the repo is empty (no commits yet).
pub fn head_commit(repo_path: &Path) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(repo_path)
        .output()
        .context("failed to run git rev-parse")?;

    if !output.status.success() {
        // Empty repo — HEAD doesn't resolve
        return Ok(None);
    }

    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(Some(hash))
}

/// Resolve the best available ref to use for tree/log operations.
///
/// Priority:
///   1. HEAD (if it resolves to a commit)
///   2. `preferred_branch` (e.g. the DB default_branch)
///   3. Any branch ref returned by `list_refs` (first alphabetically — main/master preferred)
///
/// Returns the refname string to pass to `log` / `ls_tree`.
pub fn resolve_head(repo_path: &Path, preferred_branch: &str) -> String {
    // 1. Try HEAD
    if head_commit(repo_path).ok().flatten().is_some() {
        return "HEAD".to_string();
    }

    // 2. Try preferred branch
    let preferred = format!("refs/heads/{preferred_branch}");
    let output = Command::new("git")
        .args(["rev-parse", "--verify", &preferred])
        .current_dir(repo_path)
        .output();
    if matches!(output, Ok(ref o) if o.status.success()) {
        return preferred;
    }

    // 3. Walk all refs — prefer main/master, then take the first one
    if let Ok(refs) = list_refs(repo_path) {
        let branches: Vec<_> = refs
            .iter()
            .filter(|(r, _)| r.starts_with("refs/heads/"))
            .collect();
        // Preferred names in order
        for name in &["refs/heads/main", "refs/heads/master", "refs/heads/develop"] {
            if branches.iter().any(|(r, _)| r == name) {
                return name.to_string();
            }
        }
        if let Some((r, _)) = branches.first() {
            return r.clone();
        }
    }

    // Fallback: return HEAD even if it doesn't resolve
    "HEAD".to_string()
}

/// Get commit log for a ref (up to `limit` entries).
pub fn log(repo_path: &Path, refname: &str, limit: usize) -> Result<Vec<CommitInfo>> {
    let output = Command::new("git")
        .args([
            "log",
            "--format=%H%n%an%n%ae%n%at%n%s",
            "-n",
            &limit.to_string(),
            refname,
        ])
        .current_dir(repo_path)
        .output()
        .context("failed to run git log")?;

    if !output.status.success() {
        return Ok(vec![]); // empty repo
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut commits = Vec::new();
    let mut lines = stdout.lines();

    loop {
        let hash = match lines.next() {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => break,
        };
        let author_name = lines.next().unwrap_or("").to_string();
        let author_email = lines.next().unwrap_or("").to_string();
        let timestamp: i64 = lines.next().unwrap_or("0").parse().unwrap_or(0);
        let subject = lines.next().unwrap_or("").to_string();

        commits.push(CommitInfo {
            hash,
            author_name,
            author_email,
            timestamp,
            subject,
        });
    }

    Ok(commits)
}

/// List files in a tree at the given ref and path.
pub fn ls_tree(repo_path: &Path, refname: &str, tree_path: &str) -> Result<Vec<TreeEntry>> {
    let tree_spec = if tree_path.is_empty() {
        refname.to_string()
    } else {
        format!("{refname}:{tree_path}")
    };

    // Use -l to include blob sizes; standard output: "<mode> <type> <hash> <size>\t<name>"
    let output = Command::new("git")
        .args(["ls-tree", "-l", &tree_spec])
        .current_dir(repo_path)
        .output()
        .context("failed to run git ls-tree")?;

    if !output.status.success() {
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries = stdout
        .lines()
        .filter_map(|line| {
            // format: "100644 blob <hash>      <size>\t<name>"
            let (meta, name) = line.split_once('\t')?;
            let mut parts = meta.split_whitespace();
            let mode = parts.next()?.to_string();
            let kind = parts.next()?.to_string();
            let hash = parts.next()?.to_string();
            let size: Option<u64> = parts.next().and_then(|s| s.parse().ok());
            Some(TreeEntry {
                mode,
                kind,
                hash,
                path: name.to_string(),
                size,
            })
        })
        .collect();

    Ok(entries)
}

/// Read the contents of a file blob at refname:path.
pub fn read_file(repo_path: &Path, refname: &str, file_path: &str) -> Result<Vec<u8>> {
    let spec = format!("{refname}:{file_path}");
    let output = Command::new("git")
        .args(["show", &spec])
        .current_dir(repo_path)
        .output()
        .context("failed to run git show")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git show failed: {stderr}");
    }

    Ok(output.stdout)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CommitInfo {
    pub hash: String,
    #[serde(rename = "author")]
    pub author_name: String,
    #[serde(skip)]
    #[allow(dead_code)]
    pub author_email: String,
    #[serde(rename = "date", serialize_with = "serialize_timestamp")]
    pub timestamp: i64,
    #[serde(rename = "message")]
    pub subject: String,
}

fn serialize_timestamp<S: serde::Serializer>(ts: &i64, s: S) -> Result<S::Ok, S::Error> {
    use chrono::TimeZone;
    let dt = chrono::Utc
        .timestamp_opt(*ts, 0)
        .single()
        .unwrap_or_else(chrono::Utc::now);
    s.serialize_str(&dt.to_rfc3339())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TreeEntry {
    pub mode: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub hash: String,
    #[serde(rename = "name")]
    pub path: String,
    pub size: Option<u64>,
}

/// Read a git object by its SHA-256 hex object ID.
///
/// Returns `(object_type, content_bytes)` where `content_bytes` is the raw
/// object content (without the git framing header). The CID served over
/// `/ipfs/<cid>` is computed from these same content bytes via
/// `gitlawb_core::cid::Cid::from_git_object_bytes`.
///
/// Get just the object type. Returns `None` if the object doesn't exist.
pub fn object_type(repo_path: &Path, sha256_hex: &str) -> Result<Option<String>> {
    let type_output = Command::new("git")
        .args(["cat-file", "-t", sha256_hex])
        .current_dir(repo_path)
        .output()
        .context("failed to run git cat-file -t")?;

    if !type_output.status.success() {
        return Ok(None);
    }

    Ok(Some(
        String::from_utf8_lossy(&type_output.stdout)
            .trim()
            .to_string(),
    ))
}

/// Read an object's content if its type is already known.
pub fn read_object_content(repo_path: &Path, sha256_hex: &str, obj_type: &str) -> Result<Vec<u8>> {
    let content_output = Command::new("git")
        .args(["cat-file", obj_type, sha256_hex])
        .current_dir(repo_path)
        .output()
        .context("failed to run git cat-file <type>")?;

    if !content_output.status.success() {
        let stderr = String::from_utf8_lossy(&content_output.stderr);
        bail!("git cat-file failed: {stderr}");
    }

    Ok(content_output.stdout)
}

/// Read a git object by its SHA-256 hex object ID.
///
/// Returns `(object_type, content_bytes)` where `content_bytes` is the raw
/// object content (without the git framing header). The CID served over
/// `/ipfs/<cid>` is computed from these same content bytes via
/// `gitlawb_core::cid::Cid::from_git_object_bytes`.
///
/// Returns `None` if the object does not exist in this repo.
pub fn read_object(repo_path: &Path, sha256_hex: &str) -> Result<Option<(String, Vec<u8>)>> {
    let obj_type = match object_type(repo_path, sha256_hex)? {
        Some(t) => t,
        None => return Ok(None),
    };
    let content = read_object_content(repo_path, sha256_hex, &obj_type)?;
    Ok(Some((obj_type, content)))
}

/// Get the diff between two branches: changes on source_branch not in target_branch.
pub fn branch_diff(repo_path: &Path, target_branch: &str, source_branch: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["diff", &format!("{target_branch}...{source_branch}")])
        .current_dir(repo_path)
        .output()
        .context("failed to run git diff")?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// The repo-relative paths changed by `git diff target...source` (the same range
/// as `branch_diff`). Used to enforce per-path visibility on a PR diff: if the
/// caller cannot read one of these paths, the diff is withheld.
pub fn branch_diff_names(
    repo_path: &Path,
    target_branch: &str,
    source_branch: &str,
) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "-z",
            &format!("{target_branch}...{source_branch}"),
        ])
        .current_dir(repo_path)
        .output()
        .context("failed to run git diff --name-only")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git diff --name-only failed: {stderr}");
    }
    // Split on NUL (`-z`) so paths containing newlines keep their exact bytes;
    // `--name-only` without `-z` would quote/escape such paths and they would no
    // longer match the visibility globs in get_pr_diff, leaking the diff.
    Ok(output
        .stdout
        .split(|b| *b == b'\0')
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

/// Merge source_branch into target_branch in a bare repo using a temporary worktree.
/// Returns the new merge commit hash.
pub fn merge_branch(
    repo_path: &Path,
    target_branch: &str,
    source_branch: &str,
    author_did: &str,
    pr_title: &str,
) -> Result<String> {
    let worktree_path = repo_path.join("_merge_worktree");

    // Clean up any leftover worktree
    if worktree_path.exists() {
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force", "_merge_worktree"])
            .current_dir(repo_path)
            .output();
        let _ = std::fs::remove_dir_all(&worktree_path);
    }

    // Create worktree on target branch
    let wt = Command::new("git")
        .args(["worktree", "add", "_merge_worktree", target_branch])
        .current_dir(repo_path)
        .output()
        .context("failed to create worktree")?;
    if !wt.status.success() {
        bail!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&wt.stderr)
        );
    }

    // Run merge in worktree
    let merge = Command::new("git")
        .args([
            "merge",
            "--no-ff",
            source_branch,
            "-m",
            &format!(
                "Merge branch '{}' into {} ({})",
                source_branch, target_branch, pr_title
            ),
        ])
        .current_dir(&worktree_path)
        .env("GIT_AUTHOR_NAME", author_did)
        .env("GIT_AUTHOR_EMAIL", format!("{}@gitlawb", author_did))
        .env("GIT_COMMITTER_NAME", author_did)
        .env("GIT_COMMITTER_EMAIL", format!("{}@gitlawb", author_did))
        .output()
        .context("failed to run git merge")?;

    let success = merge.status.success();

    // Always remove worktree
    let _ = Command::new("git")
        .args(["worktree", "remove", "--force", "_merge_worktree"])
        .current_dir(repo_path)
        .output();
    let _ = std::fs::remove_dir_all(&worktree_path);

    if !success {
        bail!(
            "git merge failed: {}",
            String::from_utf8_lossy(&merge.stderr)
        );
    }

    // Get new HEAD of target branch
    let head = Command::new("git")
        .args(["rev-parse", &format!("refs/heads/{target_branch}")])
        .current_dir(repo_path)
        .output()
        .context("failed to get merge commit")?;

    Ok(String::from_utf8_lossy(&head.stdout).trim().to_string())
}

/// Resolve a repo disk path: {repos_dir}/{owner_slug}/{repo_name}.git
pub fn repo_disk_path(repos_dir: &Path, owner_did: &str, repo_name: &str) -> PathBuf {
    // Sanitize the DID for use as a directory name
    let owner_slug = owner_did.replace([':', '/'], "_");
    repos_dir.join(owner_slug).join(format!("{repo_name}.git"))
}

#[cfg(test)]
mod tests {
    use super::{branch_diff_names, list_refs, restore_refs};
    use std::path::Path;
    use std::process::Command;

    fn run_git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Bare repo with main at c2 and keeper at c2, whose "pre-push" state was
    /// main and keeper both at c1. Returns (workdir, baredir, bare_path, c1, c2).
    fn advanced_bare_repo() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        std::path::PathBuf,
        String,
        String,
    ) {
        let work = tempfile::TempDir::new().unwrap();
        run_git(work.path(), &["init", "-q", "-b", "main", "."]);
        run_git(work.path(), &["config", "user.email", "t@t"]);
        run_git(work.path(), &["config", "user.name", "t"]);
        std::fs::write(work.path().join("f.txt"), "one").unwrap();
        run_git(work.path(), &["add", "f.txt"]);
        run_git(work.path(), &["commit", "-qm", "c1"]);
        let c1 = run_git(work.path(), &["rev-parse", "HEAD"]);
        std::fs::write(work.path().join("f.txt"), "two").unwrap();
        run_git(work.path(), &["add", "f.txt"]);
        run_git(work.path(), &["commit", "-qm", "c2"]);
        let c2 = run_git(work.path(), &["rev-parse", "HEAD"]);

        let dir = tempfile::TempDir::new().unwrap();
        let bare = dir.path().join("repo.git");
        let out = Command::new("git")
            .args([
                "clone",
                "--bare",
                "-q",
                &work.path().to_string_lossy(),
                &bare.to_string_lossy(),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "clone --bare failed");
        // "The push" advanced main to c2 (already there from the clone), moved
        // keeper c1 -> c2, and created feature at c2.
        run_git(&bare, &["update-ref", "refs/heads/keeper", &c2]);
        run_git(&bare, &["update-ref", "refs/heads/feature", &c2]);
        (work, dir, bare, c1, c2)
    }

    fn sorted_refs(bare: &Path) -> Vec<(String, String)> {
        let mut refs = list_refs(bare).unwrap();
        refs.sort();
        refs
    }

    /// A single unrestorable snapshot entry (invalid oid, `set_ref` fails) must
    /// not abort the restore: every OTHER snapshot ref is still reset and the
    /// push-created extra ref is still deleted, and the fn returns Err carrying
    /// the failure. RED with the reset loop reverted to `set_ref(..)?`: the
    /// broken entry is first in the snapshot, so an early return leaves keeper
    /// at c2 and feature alive.
    #[test]
    fn restore_refs_partial_failure_still_resets_rest_and_deletes_extras() {
        let (_work, _dir, bare, c1, c2) = advanced_bare_repo();

        let snapshot = vec![
            (
                "refs/heads/broken".to_string(),
                "not-a-valid-oid".to_string(),
            ),
            ("refs/heads/main".to_string(), c1.clone()),
            ("refs/heads/keeper".to_string(), c1.clone()),
        ];
        let err = restore_refs(&bare, &snapshot).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refs/heads/broken"),
            "the aggregated error names the failed ref: {msg}"
        );

        let refs = sorted_refs(&bare);
        assert_eq!(
            refs,
            vec![
                ("refs/heads/keeper".to_string(), c1.clone()),
                ("refs/heads/main".to_string(), c1.clone()),
            ],
            "keeper and main are reset to c1 and feature is deleted despite the \
             broken entry (c2 was {c2})"
        );
    }

    /// Happy path unchanged by the hardening: a fully valid snapshot restores
    /// exactly (refs rewound, created ref deleted) and returns Ok.
    #[test]
    fn restore_refs_happy_path_restores_snapshot_exactly() {
        let (_work, _dir, bare, c1, _c2) = advanced_bare_repo();

        let snapshot = vec![
            ("refs/heads/main".to_string(), c1.clone()),
            ("refs/heads/keeper".to_string(), c1.clone()),
        ];
        restore_refs(&bare, &snapshot).unwrap();

        let refs = sorted_refs(&bare);
        assert_eq!(
            refs,
            vec![
                ("refs/heads/keeper".to_string(), c1.clone()),
                ("refs/heads/main".to_string(), c1),
            ],
            "restore must reproduce the snapshot exactly"
        );
    }

    /// When the internal `list_refs` (extra-ref sweep) fails, the snapshot-reset
    /// half must still have run and its collected failures must surface in the
    /// aggregated error, not be discarded by an early `?` return. The repo is a
    /// real bare repo declaring repositoryformatversion=999, so both `set_ref`
    /// and `list_refs` fail deterministically. RED with the sweep reverted to
    /// `let current = list_refs(repo_path)?;`: the raw for-each-ref error
    /// propagates without the "failed to restore" aggregate or the ref name.
    #[test]
    fn restore_refs_aggregates_when_internal_list_refs_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let bare = dir.path().join("repo.git");
        let out = Command::new("git")
            .args(["init", "--bare", "-q", &bare.to_string_lossy()])
            .output()
            .unwrap();
        assert!(out.status.success(), "git init --bare failed");
        std::fs::write(
            bare.join("config"),
            "[core]\n\trepositoryformatversion = 999\n\tbare = true\n",
        )
        .unwrap();
        assert!(
            list_refs(&bare).is_err(),
            "precondition: list_refs must fail on the corrupted repo"
        );

        let snapshot = vec![("refs/heads/main".to_string(), "a".repeat(40))];
        let err = restore_refs(&bare, &snapshot).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("failed to restore"),
            "must return the aggregated error, not the raw list_refs error: {msg}"
        );
        assert!(
            msg.contains("refs/heads/main"),
            "the set_ref failure from the reset half must survive the sweep \
             failure: {msg}"
        );
        assert!(
            msg.contains("listing current refs"),
            "the sweep failure itself is also collected: {msg}"
        );
    }

    #[test]
    fn branch_diff_names_lists_changed_paths() {
        let td = tempfile::TempDir::new().unwrap();
        let work: &Path = td.path();
        let g = |args: &[&str]| {
            assert!(Command::new("git")
                .args(args)
                .current_dir(work)
                .status()
                .unwrap()
                .success());
        };
        g(&["init", "-q"]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        std::fs::write(work.join("base.txt"), b"base\n").unwrap();
        g(&["add", "."]);
        g(&["commit", "-qm", "base"]);
        let main = {
            let o = Command::new("git")
                .args(["symbolic-ref", "--short", "HEAD"])
                .current_dir(work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        g(&["checkout", "-q", "-b", "feature"]);
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::write(work.join("secret/x.txt"), b"secret\n").unwrap();
        g(&["add", "."]);
        g(&["commit", "-qm", "feat"]);

        let names = branch_diff_names(work, &main, "feature").unwrap();
        assert!(
            names.iter().any(|p| p == "secret/x.txt"),
            "expected secret/x.txt in changed paths, got {names:?}"
        );
        assert!(
            !names.iter().any(|p| p == "base.txt"),
            "unchanged file must not appear: {names:?}"
        );
    }
}
