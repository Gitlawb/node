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

/// Bounded twin of [`object_type`] for the `GET /ipfs/{cid}` serve path (#173
/// round-10, R1/KTD2). Runs `git cat-file -t` under
/// [`run_bounded_git`](crate::git::visibility_pack::run_bounded_git) so the child runs
/// in its own process group and a watchdog reaps it (SIGTERM -> grace -> SIGKILL) at
/// `timeout`. The bare [`object_type`] is a `spawn_blocking` `Command::output` that an
/// async timeout cannot cancel, so a wedged `cat-file` there pins the caller's held
/// /ipfs walk admission for the whole hang; this twin cannot. Semantics mirror
/// [`object_type`]: `Ok(Some(t))` for an existing object, `Ok(None)` when git exits
/// non-zero without timing out (the object is absent), and
/// `Err(`[`GitServiceTimeout`](crate::git::smart_http::GitServiceTimeout)`)` on the
/// deadline so the handler can mark the search truncated (retryable 503) rather than a
/// false not-found. Callers off the /ipfs path keep the bare helper.
pub fn object_type_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    timeout: std::time::Duration,
) -> Result<Option<String>> {
    let deadline = std::time::Instant::now() + timeout;
    match crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["cat-file", "-t", sha256_hex],
        repo_path,
        b"",
        deadline,
    ) {
        Ok(out) => Ok(Some(String::from_utf8_lossy(&out).trim().to_string())),
        Err(e) if e.is::<crate::git::smart_http::GitServiceTimeout>() => Err(e),
        // A non-timeout failure is git reporting no such object (a non-zero exit),
        // matching `object_type`'s `Ok(None)`.
        Err(_) => Ok(None),
    }
}

/// Bounded `git cat-file -s` size read for the `GET /ipfs/{cid}` serve path (#173
/// round-10, R1/KTD2): reads the object size WITHOUT its content (so an oversized object
/// is rejected before it is buffered, #173 F6), under
/// [`run_bounded_git`](crate::git::visibility_pack::run_bounded_git) so a wedged size
/// read is reaped at `timeout` instead of pinning the held /ipfs walk admission.
/// `Ok(Some(n))` on success, `Ok(None)` when the object is absent (a non-timeout
/// non-zero exit), `Err(GitServiceTimeout)` on the deadline.
pub fn object_size_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    timeout: std::time::Duration,
) -> Result<Option<u64>> {
    let deadline = std::time::Instant::now() + timeout;
    match crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["cat-file", "-s", sha256_hex],
        repo_path,
        b"",
        deadline,
    ) {
        Ok(out) => Ok(String::from_utf8_lossy(&out).trim().parse::<u64>().ok()),
        Err(e) if e.is::<crate::git::smart_http::GitServiceTimeout>() => Err(e),
        Err(_) => Ok(None),
    }
}

/// Bounded twin of [`read_object_content`] for the `GET /ipfs/{cid}` serve path (#173
/// round-10, R1/KTD2): `git cat-file <type>` under
/// [`run_bounded_git`](crate::git::visibility_pack::run_bounded_git) so a wedged content
/// read is reaped at `timeout` instead of pinning the held /ipfs walk admission. Returns
/// the raw object bytes on success and an error (including `GitServiceTimeout` on the
/// deadline) otherwise, mirroring [`read_object_content`].
pub fn read_object_content_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    obj_type: &str,
    timeout: std::time::Duration,
) -> Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + timeout;
    crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["cat-file", obj_type, sha256_hex],
        repo_path,
        b"",
        deadline,
    )
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

/// Bounded twin of [`read_object`] for write-side callers that must not hang on a
/// wedged `git cat-file` (the post-push pin path, #173): composes
/// [`object_type_bounded`] and [`read_object_content_bounded`] under ONE shared
/// deadline (mirroring `get_by_cid`'s read stage and `build_filtered_pack`), so a
/// single object read holds for at most `timeout` total, not one full timeout per
/// stage. `Ok(Some((type, bytes)))` on success, `Ok(None)` when the object is absent,
/// and `Err(`[`GitServiceTimeout`](crate::git::smart_http::GitServiceTimeout)`)` when
/// either stage overruns the deadline. The bare [`read_object`] is an unbounded
/// `Command::output` an async timeout cannot cancel, so a wedged `cat-file` there pins
/// the post-push coalescing key until process death; this twin cannot.
pub fn read_object_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    timeout: std::time::Duration,
) -> Result<Option<(String, Vec<u8>)>> {
    let deadline = std::time::Instant::now() + timeout;
    let obj_type = match object_type_bounded(
        git_bin,
        repo_path,
        sha256_hex,
        deadline.saturating_duration_since(std::time::Instant::now()),
    )? {
        Some(t) => t,
        None => return Ok(None),
    };
    let content = read_object_content_bounded(
        git_bin,
        repo_path,
        sha256_hex,
        &obj_type,
        deadline.saturating_duration_since(std::time::Instant::now()),
    )?;
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

    /// #173 round-10 (KTD2): `object_type_bounded` reaps a wedged `cat-file` child at its
    /// deadline instead of blocking on it to natural exit, so a hung probe cannot pin the
    /// /ipfs walk admission the owning task holds. A fake `git` records its pid and sleeps
    /// far past the 1s deadline; the `run_bounded_git` watchdog (SIGTERM -> grace ->
    /// SIGKILL of the process group) must kill it well before that natural exit, and the
    /// call must surface `GitServiceTimeout`. REVERT PROOF (RED): swap the twin's
    /// `run_bounded_git` for the bare `Command::output()` and the wedged child stays alive
    /// past the deadline — the mid-flight liveness poll below reads it still running.
    #[cfg(unix)]
    #[test]
    fn object_type_bounded_reaps_wedged_child_at_deadline() {
        use std::time::Duration;
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("catfile.pid");
        // `cat-file` records its own pid then sleeps 8s (>> the 1s deadline) so the probe
        // is genuinely wedged; the watchdog is what must end it.
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               cat-file) echo $$ > \"{}\"; sleep 8 ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            pidfile.display()
        );
        let git_path = tmp.path().join("fakegit");
        std::fs::write(&git_path, &body).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&git_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&git_path, perm).unwrap();
        }
        let repo = tmp.path().to_path_buf();
        let git = git_path.to_str().unwrap().to_string();

        let alive = |pid: i32| unsafe { libc::kill(pid, 0) == 0 };

        // The bounded probe blocks until the watchdog tears the child down, so run it on
        // a worker thread and poll for the reap from here.
        let handle = std::thread::spawn(move || {
            super::object_type_bounded(&git, &repo, "deadbeef", Duration::from_secs(1))
        });

        let mut pid = None;
        for _ in 0..500 {
            if let Some(p) = std::fs::read_to_string(&pidfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                pid = Some(p);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = pid.expect("the fake cat-file must have spawned and recorded its pid");

        // Past the 1s deadline + SIGTERM grace but well before the 8s natural exit: the
        // watchdog must already have reaped the wedged group. A bare, unbounded read would
        // leave it running here — the load-bearing RED.
        std::thread::sleep(Duration::from_secs(3));
        let reaped = !alive(pid);
        // Defensive reap so a RED run leaks no orphan.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        assert!(
            reaped,
            "object_type_bounded must reap the wedged cat-file child at the deadline, \
             not leave it running to its natural exit"
        );

        let res = handle.join().expect("probe thread joins");
        let err = res.expect_err("a deadline overrun must be an error, not a value");
        assert!(
            err.is::<crate::git::smart_http::GitServiceTimeout>(),
            "a deadline overrun must surface GitServiceTimeout, got: {err:?}"
        );
    }
}
