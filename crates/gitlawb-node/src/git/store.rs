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
/// Get just the object type. Returns `None` if the object doesn't exist; a
/// probe that could not examine the object store is `Err`, never `None`.
pub fn object_type(repo_path: &Path, sha256_hex: &str) -> Result<Option<String>> {
    let type_output = Command::new("git")
        .args(["cat-file", "-t", sha256_hex])
        .current_dir(repo_path)
        .output()
        .context("failed to run git cat-file -t")?;

    if !type_output.status.success() {
        // A nonzero exit is an ABSENCE verdict only when git could examine the
        // object store: missing-object and invalid-oid probes die with a single
        // clean `fatal:` line. A broken repo dir (`fatal: not a git repository`)
        // or a corrupt object (`error: inflate` / `error: unable to unpack`
        // lines before the fatal) proves nothing about absence, so it must
        // surface as Err — the /ipfs scan taints on Err rather than treating
        // the repo as probed-clean.
        let stderr = String::from_utf8_lossy(&type_output.stderr);
        if stderr.contains("not a git repository")
            || stderr.lines().any(|l| l.starts_with("error:"))
        {
            bail!("git cat-file -t failed: {}", stderr.trim());
        }
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

/// Bounded, reaped variant of [`object_type`] for the async `/ipfs` serve path
/// (#174 F3): runs `git cat-file -t` off the caller's runtime through the
/// process-group + watchdog reaper, so a hung or corrupt object store cannot pin a
/// runtime worker or an IPFS admission permit past `deadline`. Exit classification
/// is identical to [`object_type`] — a missing object is `Ok(None)`, a store-access
/// failure is `Err` — so the serve path's 404-vs-503 semantics are unchanged.
pub fn object_type_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    deadline: std::time::Instant,
) -> Result<Option<String>> {
    let (status, stdout, stderr) = crate::git::visibility_pack::run_bounded_git_raw(
        git_bin,
        &["cat-file", "-t", sha256_hex],
        repo_path,
        &[],
        deadline,
    )?;
    if status.success() {
        return Ok(Some(String::from_utf8_lossy(&stdout).trim().to_string()));
    }
    // A nonzero exit whose stderr proves git could not EXAMINE the object store —
    // "not a git repository", or any `error:` line (corrupt loose object, bad idx) —
    // is not an absence verdict, so surface it as Err (#173/#174: never a false 404).
    let stderr = String::from_utf8_lossy(&stderr);
    if stderr.contains("not a git repository") || stderr.lines().any(|l| l.starts_with("error:")) {
        bail!("git cat-file -t failed: {}", stderr.trim());
    }
    // Any other bare `fatal:` ("could not get object info") is the absence-vs-
    // unreadable-pack COLLISION (#174 F5): a genuinely missing object and a packed
    // object whose pack/idx is unreadable (permissions, or a mid-repack race) emit the
    // identical string. Disambiguate OUT OF BAND: if the object store is not readable,
    // this is not an absence verdict -> Err (taint -> retryable 503).
    if !object_store_readable(repo_path) {
        bail!(
            "git cat-file -t inconclusive: object store not readable at {} (not an absence verdict)",
            repo_path.display()
        );
    }
    // Store readable: re-probe once. An object still absent on a confirmed-readable
    // store is very likely truly absent (Ok(None)); if a mid-repack race resolved and
    // the re-probe now finds it, return the type. This narrows, but cannot fully close,
    // the concurrent-repack window (the readability check samples a different instant).
    let (status2, stdout2, stderr2) = crate::git::visibility_pack::run_bounded_git_raw(
        git_bin,
        &["cat-file", "-t", sha256_hex],
        repo_path,
        &[],
        deadline,
    )?;
    if status2.success() {
        return Ok(Some(String::from_utf8_lossy(&stdout2).trim().to_string()));
    }
    let stderr2 = String::from_utf8_lossy(&stderr2);
    if stderr2.contains("not a git repository") || stderr2.lines().any(|l| l.starts_with("error:"))
    {
        bail!("git cat-file -t failed: {}", stderr2.trim());
    }
    Ok(None)
}

/// Best-effort check that a repo's object store is readable, used to disambiguate a
/// genuine missing-object `git cat-file` fatal from an unreadable or racing pack
/// (both emit "could not get object info"). Returns false on any unreadable
/// `objects/` dir or any pack/idx that cannot be opened (EACCES / EIO), so the
/// caller surfaces an error rather than a false absence. Cheap — a couple of readdir
/// plus open probes. It narrows, but does not close, the concurrent-repack TOCTOU: it
/// samples a different instant than the failing cat-file.
fn object_store_readable(repo_path: &Path) -> bool {
    let objects = repo_path.join("objects");
    // The objects dir itself must be listable; drain the iterator so a mid-listing
    // EACCES/EIO surfaces, not just the initial open.
    let Ok(entries) = std::fs::read_dir(&objects) else {
        return false;
    };
    for entry in entries {
        if entry.is_err() {
            return false;
        }
    }
    // Every pack file and its index must be openable for read. A loose-only store
    // (no pack dir) is fine — the objects readdir above already proved reachability.
    if let Ok(pack_entries) = std::fs::read_dir(objects.join("pack")) {
        for entry in pack_entries {
            let Ok(entry) = entry else {
                return false;
            };
            let path = entry.path();
            if matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("pack") | Some("idx")
            ) && std::fs::File::open(&path).is_err()
            {
                return false;
            }
        }
    }
    true
}

/// Bounded, reaped variant of [`read_object_content`] for the async `/ipfs` serve
/// path (#174 F3). Same teardown guarantees as [`object_type_bounded`].
pub fn read_object_content_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    obj_type: &str,
    deadline: std::time::Instant,
) -> Result<Vec<u8>> {
    let (status, stdout, stderr) = crate::git::visibility_pack::run_bounded_git_raw(
        git_bin,
        &["cat-file", obj_type, sha256_hex],
        repo_path,
        &[],
        deadline,
    )?;
    if !status.success() {
        bail!("git cat-file failed: {}", String::from_utf8_lossy(&stderr));
    }
    Ok(stdout)
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
    use super::branch_diff_names;
    use std::path::Path;
    use std::process::Command;

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

    /// #174 F5 (RED-before/GREEN-after): a packed object whose pack/idx is unreadable
    /// makes `git cat-file -t` emit "could not get object info" — byte-identical to a
    /// genuine miss. `object_type_bounded` must report absence ONLY when the object
    /// store is confirmed readable; an unreadable store is Err (-> retryable 503),
    /// never Ok(None) (-> a wrong 404 for a present object).
    #[cfg(unix)]
    #[test]
    fn object_type_bounded_unreadable_pack_is_error_not_absence() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(&work).unwrap();
        let g = |args: &[&str], dir: &Path| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?}"
            );
        };
        g(&["init", "-q", "--object-format=sha256", "."], &work);
        g(&["config", "user.email", "t@t"], &work);
        g(&["config", "user.name", "t"], &work);
        std::fs::write(work.join("file.txt"), b"packed f5 content\n").unwrap();
        g(&["add", "file.txt"], &work);
        g(&["commit", "-qm", "c1"], &work);
        let blob = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD:file.txt"])
                .current_dir(&work)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        g(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        g(&["gc", "-q"], &bare);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        // Readable store: the packed blob probes present; a genuine miss is Ok(None).
        assert_eq!(
            super::object_type_bounded("git", &bare, &blob, deadline)
                .unwrap()
                .as_deref(),
            Some("blob"),
            "a packed blob on a readable store must probe present"
        );
        assert!(
            super::object_type_bounded("git", &bare, &"0".repeat(64), deadline)
                .unwrap()
                .is_none(),
            "a genuinely-absent object on a readable store must be Ok(None)"
        );

        // Make the pack unreadable: cat-file -t now emits the collided fatal for the
        // PRESENT blob. It must surface as Err, not a false Ok(None).
        let pack_dir = bare.join("objects").join("pack");
        let set_pack_mode = |mode: u32| {
            for e in std::fs::read_dir(&pack_dir).unwrap() {
                let p = e.unwrap().path();
                if matches!(
                    p.extension().and_then(|s| s.to_str()),
                    Some("pack") | Some("idx")
                ) {
                    let mut perms = std::fs::metadata(&p).unwrap().permissions();
                    perms.set_mode(mode);
                    std::fs::set_permissions(&p, perms).unwrap();
                }
            }
        };
        set_pack_mode(0o000);
        // Root bypasses file permissions, so the chmod won't block reads there; only
        // assert the error path when the pack is genuinely unreadable to this process.
        let a_pack = std::fs::read_dir(&pack_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|s| s.to_str()) == Some("pack"));
        let genuinely_unreadable = a_pack
            .as_ref()
            .map(|p| std::fs::File::open(p).is_err())
            .unwrap_or(false);
        let res = super::object_type_bounded("git", &bare, &blob, deadline);
        set_pack_mode(0o644); // restore so TempDir cleanup succeeds

        if genuinely_unreadable {
            assert!(
                res.is_err(),
                "an unreadable pack must surface as Err (-> retryable 503), not Ok(None) \
                 (-> a wrong 404 for a present object); got {res:?}"
            );
        }
    }
}
