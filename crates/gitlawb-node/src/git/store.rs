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

    // #26 Split PR 1: turn reflogs ON for this bare repo. `core.logAllRefUpdates`
    // defaults to FALSE for bare repositories, so without this a bare repo keeps no
    // record of what a ref did — only what it currently points at.
    //
    // The durable post-receive outbox's startup reconcile needs exactly that record.
    // Its job is to decide whether a `prepared` transition (old -> new) actually
    // LANDED after a crash, and the current SHA alone cannot answer that: a row
    // claiming B -> A also "matches" a ref that was already sitting at A for some
    // unrelated reason, and promoting it would write a push event, a certificate,
    // and an anchor for a transition that never happened. The reflog is git's own
    // per-ref landing record — one line per update carrying `<old> <new>` plus the
    // time it happened — so [`ref_reflog_entries`] can prove the ref moved the way
    // the row claims, and prove it moved AFTER the row was written.
    //
    // Failure is non-fatal on purpose: a repo without reflogs still serves every
    // git operation, it only loses AUTOMATIC crash recovery for its outbox rows
    // (the reconcile leaves those rows `prepared` for human-attended recovery
    // rather than promoting something it cannot prove).
    let config = Command::new("git")
        .args(["config", "core.logAllRefUpdates", "true"])
        .current_dir(path)
        .output();
    match config {
        Ok(out) if !out.status.success() => {
            tracing::warn!(
                path = %path.display(),
                stderr = %String::from_utf8_lossy(&out.stderr),
                "failed to enable core.logAllRefUpdates; durable-outbox reconcile will \
                 not be able to prove ref landings for this repo"
            );
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                err = %e,
                "failed to run git config core.logAllRefUpdates; durable-outbox reconcile \
                 will not be able to prove ref landings for this repo"
            );
        }
        Ok(_) => {}
    }

    tracing::info!("initialized bare repo at {}", path.display());
    Ok(())
}

/// One parsed reflog entry: the `<old> <new>` pair a single ref update recorded,
/// plus the unix timestamp git stamped it with.
///
/// This is the unit of PER-REF LANDING PROOF the durable-outbox reconcile runs on.
/// A row that claims `old -> new` is only promoted when the ref's reflog carries an
/// entry with the same pair, stamped at or after the row was written; see
/// [`crate::durable_outbox::reconcile_prepared_from_disk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflogEntry {
    pub old_sha: String,
    pub new_sha: String,
    /// Seconds since the unix epoch, as git wrote them.
    pub at: i64,
}

/// Read the reflog of one ref in a bare repository, newest entry LAST.
///
/// Reads `logs/<ref_name>` directly rather than shelling out to `git reflog`: the
/// file format is stable and documented, the reconcile may call this once per
/// stranded row at startup, and a plain file read cannot be defeated by the ref's
/// reflog having been expired out of the `git reflog show` default window.
///
/// Returns `Ok(None)` when the repo keeps no reflog for that ref — either because
/// `core.logAllRefUpdates` was off when the ref moved (repos created before
/// [`init_bare`] started enabling it) or because the ref was deleted (git removes a
/// deleted ref's reflog with it). `None` is NOT evidence that nothing landed; it is
/// the absence of evidence, and callers must treat it as "unproven", never as
/// "proven false".
///
/// Line format (`git-check-ref-format`/`refs` docs):
/// `<old-sha> <new-sha> <committer name> <email> <unix-ts> <tz>\t<message>`
pub fn ref_reflog_entries(repo_path: &Path, ref_name: &str) -> Result<Option<Vec<ReflogEntry>>> {
    // Refuse anything that could climb out of `logs/`. Ref names are validated at
    // the push edge, but this function takes a name off a DB row, so it re-checks
    // rather than trusting the row.
    if ref_name.is_empty()
        || ref_name.contains("..")
        || ref_name.starts_with('/')
        || !ref_name.starts_with("refs/")
    {
        bail!("refusing to read a reflog for a non-refs/ ref name: {ref_name}");
    }
    let path = repo_path.join("logs").join(ref_name);
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("failed to read reflog"),
    };
    let mut out = Vec::new();
    for line in raw.lines() {
        // The message after the TAB can contain anything, including spaces and
        // (in a `git commit -m` subject) tabs of its own, so split the header off
        // at the FIRST tab and tokenize only that.
        let header = line.split('\t').next().unwrap_or(line);
        let tokens: Vec<&str> = header.split_whitespace().collect();
        // `<old> <new> <ident...> <ts> <tz>`: at minimum old, new, ts, tz.
        if tokens.len() < 4 {
            continue;
        }
        let at = match tokens[tokens.len() - 2].parse::<i64>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push(ReflogEntry {
            old_sha: tokens[0].to_string(),
            new_sha: tokens[1].to_string(),
            at,
        });
    }
    Ok(Some(out))
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

/// Why an `/ipfs` existence probe could not return an absence verdict (#174 F5/U4).
/// The caller (`api::ipfs`) maps the variant to an HTTP status, and the split exists
/// only for that mapping: a `Transient` fault is retryable (503), a `Deterministic`
/// fault is terminal (500).
///
/// The discriminator is object-store readability, NOT any English `git` wording, so a
/// future `git` message change cannot silently reclassify a fault (KTD-4): if the
/// store cannot be read (an unreadable or mid-repack pack, a removed `objects/` dir,
/// a permissions fault) the fault may clear on its own -> `Transient`; if the store IS
/// readable yet `git` still fails (a corrupt repo, a bad `.git/config`) a retry cannot
/// fix it -> `Deterministic`, so a conformant client is told not to retry-storm a
/// fresh `git cat-file` per attempt against a persistently broken repo.
#[derive(Debug)]
pub enum ProbeError {
    /// Retryable (-> 503): the object store could not be read right now.
    Transient(anyhow::Error),
    /// Terminal (-> 500): a persistent, deterministic fault a retry cannot fix.
    Deterministic(anyhow::Error),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Transient(e) => write!(f, "transient probe fault: {e}"),
            ProbeError::Deterministic(e) => write!(f, "deterministic probe fault: {e}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Structured outcome of one `git cat-file --batch-check` existence probe.
enum BatchProbe {
    /// Present: git printed `<oid> <type> <size>` on exit 0.
    Present(String),
    /// A structured, CLEAN absence: git printed `<oid> missing` on exit 0 with no
    /// `error:` diagnostics on stderr. This is the ONLY signal that can become an
    /// `Ok(None)` (404) absence verdict — and even then only after the store-readable
    /// disambiguation below, since an unreadable pack ALSO prints a clean `missing`.
    Missing,
    /// git could not honestly examine the object store: a hard exit (bad config, not a
    /// git repo) OR an exit-0 `missing` accompanied by `error:` diagnostics (a corrupt
    /// loose object still prints `missing` on stdout but complains on stderr). Never an
    /// absence verdict. Carries the raw git detail for the server log only.
    Fault(anyhow::Error),
}

/// One bounded, reaped `git cat-file --batch-check` probe (the oid is fed on stdin, so
/// no prose is matched to decide presence — the `missing` token and the exit code are
/// the structured signal). See [`object_type_bounded`] for the surrounding teardown
/// guarantees.
fn batch_check_probe(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    deadline: std::time::Instant,
) -> std::result::Result<BatchProbe, ProbeError> {
    let stdin = format!("{sha256_hex}\n");
    let (status, stdout, stderr) = crate::git::visibility_pack::run_bounded_git_raw(
        git_bin,
        &["cat-file", "--batch-check"],
        repo_path,
        stdin.as_bytes(),
        deadline,
    )
    // A spawn/timeout failure of the reaped child is not deterministic — retry it.
    .map_err(ProbeError::Transient)?;

    let stderr = String::from_utf8_lossy(&stderr);
    // A corrupt object makes `--batch-check` print `missing` on stdout (exit 0) yet
    // emit `error:` lines on stderr; those diagnostics disqualify a clean-absence read
    // regardless of the exit code, so they are checked before anything else.
    let has_error_diag = stderr.lines().any(|l| l.starts_with("error:"));

    if status.success() && !has_error_diag {
        let line = String::from_utf8_lossy(&stdout);
        let line = line.trim();
        // `<oid> missing` is the structured absence token; `<oid> <type> <size>` is a
        // hit. Anything else on a "success" exit is unexpected and not an absence.
        if line
            .rsplit(' ')
            .next()
            .is_some_and(|last| last == "missing")
        {
            return Ok(BatchProbe::Missing);
        }
        let mut parts = line.split_whitespace();
        if let (Some(_oid), Some(ty), Some(_size)) = (parts.next(), parts.next(), parts.next()) {
            return Ok(BatchProbe::Present(ty.to_string()));
        }
        return Ok(BatchProbe::Fault(anyhow::anyhow!(
            "unexpected git cat-file --batch-check output: {line:?}"
        )));
    }

    Ok(BatchProbe::Fault(anyhow::anyhow!(
        "git cat-file --batch-check failed (exit {:?}): {}",
        status.code(),
        stderr.trim()
    )))
}

/// Bounded, reaped variant of [`object_type`] for the async `/ipfs` serve path
/// (#174 F3/F5): runs `git cat-file --batch-check` off the caller's runtime through the
/// process-group + watchdog reaper, so a hung or corrupt object store cannot pin a
/// runtime worker or an IPFS admission permit past `deadline`.
///
/// Absence is keyed on `--batch-check`'s STRUCTURED `<oid> missing` token on exit 0,
/// never on any English `fatal:` wording (KTD-4): a genuinely-absent object is the only
/// `Ok(None)` (404) path. A probe that could not honestly examine the store is a
/// [`ProbeError`], split by object-store readability into `Transient` (retryable 503)
/// and `Deterministic` (terminal 500) so the serve path can shed the right status. The
/// deadline itself arrives as a `Transient` fault, so the handler marks the search
/// truncated rather than reporting a false not-found (#173 round-10 R1/KTD2).
pub fn object_type_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    deadline: std::time::Instant,
) -> std::result::Result<Option<String>, ProbeError> {
    let probe_started = std::time::Instant::now();
    match batch_check_probe(git_bin, repo_path, sha256_hex, deadline)? {
        BatchProbe::Present(ty) => Ok(Some(ty)),
        BatchProbe::Fault(detail) => Err(classify_store_fault(repo_path, sha256_hex, detail)),
        BatchProbe::Missing => {
            // A clean `missing` is the absence-vs-unreadable-pack COLLISION (#174 F5):
            // a genuinely missing object AND a packed object whose pack/idx is
            // unreadable (permissions, or a mid-repack race) both print an identical
            // clean `missing`. Disambiguate OUT OF BAND on store readability — an
            // unreadable store is not an absence verdict (taint -> retryable 503).
            if !object_store_readable(repo_path, sha256_hex) {
                return Err(ProbeError::Transient(anyhow::anyhow!(
                    "git cat-file inconclusive: object store not readable at {} (not an absence verdict)",
                    repo_path.display()
                )));
            }
            // Only re-probe if the budget can actually pay for it. The re-probe runs the
            // SAME command, so it needs roughly what the first probe took; with less than
            // that left, the child is spawned only to be reaped, and the watchdog's
            // SIGTERM grace plus SIGKILL settle carries this call well past `deadline`
            // (measured ~2x a 1s budget before this check existed). `/ipfs/{cid}` is
            // anon-reachable and an absent CID drives this branch once per repo, so an
            // unaffordable re-probe is pure overshoot on a permissionless path. An
            // inconclusive disambiguation is NOT an absence verdict, so taint to a
            // retryable Transient rather than spawn or return a false Ok(None).
            let first_probe_took = probe_started.elapsed();
            if deadline.saturating_duration_since(std::time::Instant::now()) < first_probe_took {
                return Err(ProbeError::Transient(anyhow::anyhow!(
                    "git cat-file inconclusive: no budget left for the confirming re-probe at {} (not an absence verdict)",
                    repo_path.display()
                )));
            }
            // Store readable and budget available: re-probe once. Still `missing` on a
            // confirmed-readable store is very likely truly absent (Ok(None)); a
            // mid-repack race that resolved returns the type. This narrows, but cannot
            // fully close, the concurrent-repack window (the readability check samples a
            // different instant than the failing probe).
            match batch_check_probe(git_bin, repo_path, sha256_hex, deadline)? {
                BatchProbe::Present(ty) => Ok(Some(ty)),
                BatchProbe::Fault(detail) => {
                    Err(classify_store_fault(repo_path, sha256_hex, detail))
                }
                BatchProbe::Missing => Ok(None),
            }
        }
    }
}

/// Classify a probe fault by object-store readability (#174 F5/U4). An unreadable store
/// may be a transient permissions/mid-repack condition (retryable 503); a readable
/// store on which git still fails is a persistent, deterministic fault — a corrupt repo
/// or a bad `.git/config` — that a retry cannot fix (terminal 500). The `detail` is
/// carried for the server log; the client-facing body is opaque (set by the caller).
///
/// Readability is judged FOR `sha256_hex`: the probe checks the oid's own loose fan-out
/// directory rather than all 256, so the verdict is scoped to the location git would
/// actually need for THIS object and one unrelated broken directory cannot veto every
/// probe on the repo.
fn classify_store_fault(repo_path: &Path, sha256_hex: &str, detail: anyhow::Error) -> ProbeError {
    if object_store_readable(repo_path, sha256_hex) {
        ProbeError::Deterministic(detail)
    } else {
        ProbeError::Transient(detail)
    }
}

/// Best-effort check that a repo's object store is readable FOR `sha256_hex`, used to
/// disambiguate a genuine missing-object `git cat-file` verdict from an unreadable or
/// racing store (both emit an identical clean `missing`). Returns false on an unreadable
/// `objects/` dir, an unreadable `objects/pack` dir, any pack/idx that cannot be opened,
/// or an unreadable loose fan-out directory for this oid (EACCES / EIO), so the caller
/// surfaces an error rather than a false absence.
///
/// Only `NotFound` is benign, on both the pack and the loose leg: a loose-only store has
/// no `objects/pack`, and a packed or genuinely-absent object has no loose file. Any
/// OTHER error is a store the process cannot read, and absence cannot be certified
/// through it. Treating EACCES like NotFound is exactly the #174 F2 swallow this replaces.
///
/// The loose leg is a single `File::open` of THIS oid's `objects/<xx>/<rest>`, not a
/// drain of the fan-out directory. The caller supplies the CID, the CID fixes the sha,
/// and the sha selects which of the 256 directories would be drained, so a drain would
/// let an anonymous `/ipfs/{cid}` caller choose how much dirent work the probe does. The
/// open detects the same fault: path resolution through an unreadable directory fails
/// with EACCES even when the file inside does not exist.
///
/// Accepted direction: an unreadable fan-out dir makes this false for EVERY oid in that
/// fan-out, including one that is packed or genuinely absent, so such a CID sheds a
/// retryable 503 instead of a 404. That is the fail-closed answer (absence cannot be
/// certified through a directory we cannot read), and a conservative shed, not a leak.
///
/// Cheap: two readdirs plus a couple of opens. It narrows, but does not close, the
/// concurrent-repack TOCTOU: it samples a different instant than the failing cat-file.
fn object_store_readable(repo_path: &Path, sha256_hex: &str) -> bool {
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
    // (no pack dir) is fine, since the objects readdir above already proved reachability,
    // but only that NotFound is fine; an unreadable pack dir is not.
    match std::fs::read_dir(objects.join("pack")) {
        Ok(pack_entries) => {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return false,
    }
    // Validate the oid BEFORE deriving any path component from it: `get(..2)` alone
    // bounds the length but would admit `..` and other non-hex pairs into a path built
    // from a caller-supplied string. Both of git's object-id widths are accepted:
    // `init_bare` runs `git init --bare --object-format=sha1`, so production oids are 40
    // hex and a 64-only guard would make this whole leg dead code there. A non-oid skips
    // the loose leg and lets the objects/ and pack checks carry the verdict.
    let is_hex_oid =
        matches!(sha256_hex.len(), 40 | 64) && sha256_hex.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex_oid {
        match std::fs::File::open(objects.join(&sha256_hex[0..2]).join(&sha256_hex[2..])) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
    }
    true
}

/// Is the object store readable AT ALL, independent of any single object?
///
/// [`object_store_readable`] judges readability FOR one oid: when the string is a real
/// 40/64-hex object id it also probes that oid's own loose fan-out directory, so one
/// unreadable `objects/<xx>` (1/256 of the store) makes the verdict false for the oids that
/// live there and true for everything else. Passing the EMPTY STRING deliberately fails
/// that hex-oid guard, which skips the per-oid leg entirely and leaves the `objects/` and
/// `objects/pack` checks to carry the verdict. The skip is not incidental: it is pinned by
/// `object_store_readable_rejects_a_non_hex_sha_without_building_a_path`.
///
/// Callers use this to tell a store-wide fault, where every remaining object fails
/// identically and stopping is the right answer, from an object-scoped one, where stopping
/// forfeits healthy objects. Cheap: two readdirs and a couple of opens, no child spawn.
pub(crate) fn object_store_readable_store_wide(repo_path: &Path) -> bool {
    object_store_readable(repo_path, "")
}

/// Bounded `git cat-file -s` size read for the `GET /ipfs/{cid}` serve path (#173
/// round-10, R1/KTD2): reads the object size WITHOUT its content (so an oversized object
/// is rejected before it is buffered, #173 F6), under
/// [`run_bounded_git`](crate::git::visibility_pack::run_bounded_git) so a wedged size
/// read is reaped at `deadline` instead of pinning the held /ipfs walk admission.
/// `Ok(n)` on success, and otherwise a [`ProbeError`] in the same vocabulary the type and
/// content stages use: a reaped child is `Transient` (retryable), and every other failure
/// goes through [`classify_store_fault`], so it is `Transient` when the object store is
/// not readable and `Deterministic` when it is.
///
/// There is deliberately NO absence value (#173 round 12). This returned
/// `Ok(None)` for every non-timeout failure, which `gate_and_serve` reads as a verified
/// absence and does not taint the search for, so a corrupt object, an unreadable pack, or
/// a failed spawn handed an authorized caller a definitive 404 instead of the retryable
/// 503 tail. Absence is also not this stage's question: the caller has already had a
/// `Present` verdict from [`object_type_bounded`], so an object that cannot be sized here
/// is a fault, not a not-found, and the one honest exception (a concurrent gc between the
/// two stages) is classified by store readability like any other. Making the absence
/// unrepresentable is what keeps the next caller from reintroducing the swallow.
///
/// Takes the shared `deadline` rather than its own timeout so a caller that pairs this
/// size check with a later read spends ONE budget across the pair, not one per stage.
pub fn object_size_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    deadline: std::time::Instant,
) -> std::result::Result<u64, ProbeError> {
    match crate::git::visibility_pack::run_bounded_git(
        git_bin,
        &["cat-file", "-s", sha256_hex],
        repo_path,
        b"",
        deadline,
    ) {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out);
            text.trim().parse::<u64>().map_err(|e| {
                // git exited 0 but did not print a size: the store answered something
                // this code cannot read, which is a fault and never an absence.
                classify_store_fault(
                    repo_path,
                    sha256_hex,
                    anyhow::anyhow!("unparseable `cat-file -s` output {:?}: {e}", text.trim()),
                )
            })
        }
        // The watchdog reaped the child at `deadline`; retryable whatever the store looks
        // like, so it is routed before readability gets a say (same rule as the content
        // stage in `read_object_bounded`).
        Err(e) if e.is::<crate::git::smart_http::GitServiceTimeout>() => {
            Err(ProbeError::Transient(e))
        }
        Err(e) => Err(classify_store_fault(repo_path, sha256_hex, e)),
    }
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

/// Bounded, reaped variant of [`read_object`] (#174 F3): composes [`object_type_bounded`]
/// with [`read_object_content_bounded`] against a single `deadline`, so a caller that
/// needs type+bytes gets one bounded call instead of two unbounded ones.
///
/// Contract:
/// - `Ok(None)` means a VERIFIED absence, never "we could not tell". Every probe or read
///   the store could not honestly serve is a [`ProbeError`], so a caller can distinguish
///   an absent object from an unreadable one.
/// - A content-stage failure lands in the same [`ProbeError`] vocabulary the type stage
///   uses, and by the same rules: a watchdog timeout of the reaped child is `Transient`
///   (retryable), exactly as the type stage classifies that identical failure, and every
///   other content failure goes through [`classify_store_fault`], so it is `Transient` when
///   the object store is not readable and `Deterministic` (terminal) when it is. The timeout
///   is split out first because readability says nothing about a child that was reaped: the
///   store is readable in the common case, which would make one fault retryable at the type
///   stage and terminal at the content stage.
/// - Same process-group teardown guarantees as its two constituents: SIGTERM grace then
///   an unconditional group SIGKILL at `deadline`, with the leader reaped.
///
/// This is SYNCHRONOUS blocking work (child spawn, pipe drain, watchdog join). Async
/// callers must run it under `tokio::task::spawn_blocking`, as `api/ipfs` already does
/// for the two constituents; calling it directly from a runtime task blocks a worker.
pub fn read_object_bounded(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    deadline: std::time::Instant,
) -> std::result::Result<Option<(String, Vec<u8>)>, ProbeError> {
    match object_type_bounded(git_bin, repo_path, sha256_hex, deadline)? {
        None => Ok(None),
        Some(obj_type) => {
            match read_object_content_bounded(git_bin, repo_path, sha256_hex, &obj_type, deadline) {
                Ok(bytes) => Ok(Some((obj_type, bytes))),
                // The watchdog reaped the child at `deadline`. That is the same failure
                // `batch_check_probe` maps to `Transient` at the type stage, and it is
                // retryable regardless of how readable the store is, so it is routed
                // before readability gets a say.
                Err(e)
                    if e.downcast_ref::<crate::git::smart_http::GitServiceTimeout>()
                        .is_some() =>
                {
                    Err(ProbeError::Transient(e))
                }
                Err(e) => Err(classify_store_fault(repo_path, sha256_hex, e)),
            }
        }
    }
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

    /// #26 split 1/4: a bare repo this node creates must KEEP REFLOGS, because
    /// the durable-outbox reconcile has no other way to prove that a stranded
    /// transition actually landed. `core.logAllRefUpdates` defaults to false for
    /// bare repos, so without the explicit config a crashed push is unrecoverable
    /// — the reconcile can see where a ref points, never how it got there.
    ///
    /// MUTATION (RED): drop the `git config core.logAllRefUpdates` call in
    /// `init_bare` and no `logs/refs/heads/main` file appears.
    #[test]
    fn init_bare_keeps_reflogs_so_a_landing_can_be_proven() {
        let td = tempfile::TempDir::new().unwrap();
        let bare = td.path().join("repo.git");
        super::init_bare(&bare).unwrap();

        // Build a commit and move a ref onto it, the way receive-pack would.
        let run = |args: &[&str]| -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(&bare)
                .stdin(std::process::Stdio::null())
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        let tree = run(&["mktree"]);
        let commit = run(&["commit-tree", &tree, "-m", "root"]);
        run(&["update-ref", "refs/heads/main", &commit]);

        let entries = super::ref_reflog_entries(&bare, "refs/heads/main")
            .unwrap()
            .expect("a repo created by init_bare keeps a reflog for its refs");
        assert_eq!(entries.len(), 1, "one update, one entry");
        assert_eq!(
            entries[0].old_sha, "0000000000000000000000000000000000000000",
            "the entry records where the ref came FROM — the half a current-SHA \
             check can never recover"
        );
        assert_eq!(entries[0].new_sha, commit);
        assert!(
            entries[0].at > 0,
            "the entry is timestamped, so proof can be required to postdate the intent"
        );
    }

    /// A ref with no reflog reads as `None` — "no evidence", which callers must
    /// treat as unproven rather than as proof of nothing having happened.
    #[test]
    fn ref_reflog_entries_is_none_when_the_repo_kept_no_log() {
        let td = tempfile::TempDir::new().unwrap();
        let bare = td.path().join("repo.git");
        super::init_bare(&bare).unwrap();
        assert!(
            super::ref_reflog_entries(&bare, "refs/heads/never-existed")
                .unwrap()
                .is_none(),
            "a missing reflog is None, not an empty proof set"
        );
        // A name that could climb out of `logs/` is refused outright.
        assert!(
            super::ref_reflog_entries(&bare, "../../etc/passwd").is_err(),
            "reflog lookups take a ref name off a DB row, so the path is re-checked"
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
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            super::object_type_bounded(&git, &repo, "deadbeef", deadline)
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
        // A reaped deadline is a retryable fault, not a verdict about the object, so it
        // must arrive as Transient (-> 503) carrying GitServiceTimeout.
        let super::ProbeError::Transient(inner) = &err else {
            panic!("a deadline overrun must be a Transient probe fault, got: {err:?}");
        };
        assert!(
            inner.is::<crate::git::smart_http::GitServiceTimeout>(),
            "a deadline overrun must surface GitServiceTimeout, got: {inner:?}"
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

    /// Shared setup: a bare sha256 repo carrying one committed blob. Returns the repo
    /// path and the blob's oid.
    #[cfg(unix)]
    fn bare_repo_with_blob(td: &std::path::Path) -> (std::path::PathBuf, String) {
        let work = td.join("work");
        let bare = td.join("bare.git");
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
        std::fs::write(work.join("file.txt"), b"f5 u4 content\n").unwrap();
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
            td,
        );
        (bare, blob)
    }

    /// #174 F2 (RED-before/GREEN-after): an unreadable pack DIRECTORY (distinct from the
    /// unreadable pack FILE case above) was swallowed by `if let Ok(..) = read_dir(pack)`,
    /// which treats EACCES exactly like the benign NotFound of a loose-only store. The
    /// store then read as readable and the fault classified DETERMINISTIC (terminal 500)
    /// for a condition a chmod can clear.
    ///
    /// Observed here, not assumed (the fixture looks like it should behave otherwise):
    /// with the blob PACKED and `objects/pack` at mode 000, `cat-file --batch-check`
    /// exits 0 printing `<oid> missing` on stdout AND `error: unable to open object pack
    /// directory` on stderr. `has_error_diag` runs before the present/missing parse, so
    /// this reaches `BatchProbe::Fault` and therefore `classify_store_fault`, not the
    /// clean-`missing` branch. The assertion must therefore match the VARIANT: `is_err()`
    /// is already satisfied at head and would be vacuous.
    #[cfg(unix)]
    #[test]
    fn object_type_bounded_unreadable_pack_dir_is_transient_not_deterministic() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let (bare, blob) = bare_repo_with_blob(td.path());
        assert!(Command::new("git")
            .args(["gc", "-q"])
            .current_dir(&bare)
            .status()
            .unwrap()
            .success());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        let pack_dir = bare.join("objects").join("pack");
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&pack_dir).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&pack_dir, perms).unwrap();
        };
        chmod(0o000);
        // Root bypasses permission bits, so witness the exact operation the probe
        // performs (`read_dir` of the pack dir) and skip rather than falsely fail.
        let genuinely_unreadable = std::fs::read_dir(&pack_dir).is_err();
        let res = super::object_type_bounded("git", &bare, &blob, deadline);
        chmod(0o755); // restore BEFORE any assertion that can panic, so TempDir cleans up

        if genuinely_unreadable {
            assert!(
                matches!(res, Err(super::ProbeError::Transient(_))),
                "an unreadable pack DIRECTORY is a store-readability fault: it must be a \
                 retryable Transient (-> 503), not a terminal Deterministic (-> 500); got {res:?}"
            );
        }

        // Must-not direction: with permissions restored the same store is healthy again,
        // so the fix cannot have hard-wired the repo into permanently-broken.
        assert_eq!(
            super::object_type_bounded("git", &bare, &blob, deadline)
                .unwrap()
                .as_deref(),
            Some("blob"),
            "a packed blob on a restored store must probe present again"
        );
        assert!(
            super::object_type_bounded("git", &bare, &"0".repeat(64), deadline)
                .unwrap()
                .is_none(),
            "a genuinely-absent oid on a restored store must still be Ok(None)"
        );
    }

    /// #174 F2 (RED-before/GREEN-after): no LOOSE fan-out directory was probed at all.
    /// Draining `read_dir(objects)` enumerates the fan-out dir NAMES but proves none of
    /// them listable, so an unreadable `objects/<xx>` read as a healthy store and the
    /// fault classified Deterministic.
    ///
    /// Observed here, not assumed: with the blob LOOSE and `objects/<xx>` at mode 000,
    /// `cat-file --batch-check` exits 0 printing `<oid> missing` on stdout AND `error:
    /// unable to open loose object <oid>: Permission denied` on stderr, so it reaches
    /// `BatchProbe::Fault` rather than the clean-`missing` branch. Match the VARIANT:
    /// `is_err()` holds at head and would make this vacuous.
    #[cfg(unix)]
    #[test]
    fn object_type_bounded_unreadable_fanout_is_transient_not_deterministic() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        // No `gc`: the blob stays loose, which is what puts it behind a fan-out dir.
        let (bare, blob) = bare_repo_with_blob(td.path());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        let fanout = bare.join("objects").join(&blob[0..2]);
        let loose = fanout.join(&blob[2..]);
        assert!(
            loose.is_file(),
            "fixture must leave the blob loose at {loose:?}"
        );
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&fanout).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&fanout, perms).unwrap();
        };
        chmod(0o000);
        // Witness with `File::open` of the exact loose path, the operation the probe
        // itself makes; a `read_dir` witness would be a proxy that can drift from the code.
        let genuinely_unreadable = std::fs::File::open(&loose).is_err();
        let res = super::object_type_bounded("git", &bare, &blob, deadline);
        chmod(0o755); // restore BEFORE any assertion that can panic

        if genuinely_unreadable {
            assert!(
                matches!(res, Err(super::ProbeError::Transient(_))),
                "an unreadable loose fan-out directory is a store-readability fault: it \
                 must be a retryable Transient (-> 503), not Deterministic (-> 500); got {res:?}"
            );
        }

        // Must-not direction: restored store probes present, and an absent oid (whose
        // fan-out dir does not exist at all) must stay benign NotFound -> Ok(None).
        assert_eq!(
            super::object_type_bounded("git", &bare, &blob, deadline)
                .unwrap()
                .as_deref(),
            Some("blob"),
            "the loose blob must probe present again once the fan-out dir is readable"
        );
        assert!(
            super::object_type_bounded("git", &bare, &"0".repeat(64), deadline)
                .unwrap()
                .is_none(),
            "an absent oid whose fan-out dir does not exist must remain Ok(None), or the \
             fan-out probe has over-tightened into 'every healthy store is broken'"
        );
    }

    /// #174 F2 must-not direction: the fan-out and pack-dir tightening must not turn a
    /// HEALTHY loose-only store into "not readable". A loose-only store has no
    /// `objects/pack` at all, and a genuinely-absent oid has no loose file, so NotFound
    /// has to stay benign on both legs. Get this wrong and every packed object's probe
    /// (which has no loose file either) sheds a 503 for a perfectly healthy repo.
    #[cfg(unix)]
    #[test]
    fn object_store_readable_loose_only_store_is_readable() {
        let td = tempfile::TempDir::new().unwrap();
        let (bare, blob) = bare_repo_with_blob(td.path());
        // `git clone --bare` creates an empty objects/pack; a true loose-only store has
        // none, which is the state that must not be mistaken for an unreadable one.
        let _ = std::fs::remove_dir_all(bare.join("objects").join("pack"));

        assert!(
            super::object_store_readable(&bare, &blob),
            "a loose-only store with no objects/pack must read as readable"
        );
        assert!(
            super::object_store_readable(&bare, &"0".repeat(64)),
            "an absent oid (no loose file, no fan-out dir) must stay benign NotFound"
        );
    }

    /// #174 F2, pinning the accepted direction from the plan rather than leaving it to be
    /// discovered in production: on a PACKED store, a leftover but unreadable fan-out
    /// directory makes the probe false for every oid in that fan-out, including one whose
    /// object is packed or genuinely absent. That is deliberate fail-closed behavior (we
    /// cannot certify absence through a directory we cannot read), and it sheds a
    /// retryable 503 rather than asserting a false 404.
    ///
    /// The recreate step is required, not optional: `git gc` REMOVES the emptied fan-out
    /// directory (afterwards `objects/` holds only `info` and `pack`), so a test that
    /// assumed a leftover directory could not construct its state at all.
    #[cfg(unix)]
    #[test]
    fn object_store_readable_packed_store_with_leftover_unreadable_fanout_is_not_readable() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let (bare, blob) = bare_repo_with_blob(td.path());
        assert!(Command::new("git")
            .args(["gc", "-q"])
            .current_dir(&bare)
            .status()
            .unwrap()
            .success());
        let fanout = bare.join("objects").join(&blob[0..2]);
        assert!(
            !fanout.exists(),
            "gc is expected to remove the emptied fan-out dir; recreate it deliberately"
        );
        std::fs::create_dir_all(&fanout).unwrap();
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&fanout).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&fanout, perms).unwrap();
        };
        chmod(0o000);
        // Same euid==0 witness discipline: root ignores the bits, so probe the exact
        // operation the code performs before asserting on its outcome.
        let genuinely_unreadable = std::fs::File::open(fanout.join(&blob[2..])).is_err();
        let packed = super::object_store_readable(&bare, &blob);
        // An oid that shares the broken fan-out but is genuinely absent: same verdict.
        let absent_in_broken_fanout = format!("{}{}", &blob[0..2], "0".repeat(blob.len() - 2));
        let absent = super::object_store_readable(&bare, &absent_in_broken_fanout);
        chmod(0o755); // restore BEFORE any assertion that can panic

        if genuinely_unreadable {
            assert!(
                !packed,
                "a packed object behind an unreadable fan-out dir must read as not-readable"
            );
            assert!(
                !absent,
                "an absent oid in the same unreadable fan-out must ALSO read as \
                 not-readable (fail closed: absence cannot be certified through it)"
            );
        }
        assert!(
            super::object_store_readable(&bare, &blob),
            "restoring the fan-out dir must restore the readable verdict"
        );
    }

    /// #174 F2: the oid is validated as ASCII hex of one of git's two widths BEFORE any
    /// path component is derived from it. `get(..2)` alone bounds the length but admits
    /// `..` and other non-hex pairs into a path built from a caller-supplied string.
    /// A non-oid skips the loose leg entirely and lets the objects/ and pack checks carry
    /// the verdict, so the answer on a healthy repo is `true`, with no path touched
    /// outside `objects/`.
    ///
    /// Must-not direction on the same fixture: a real 40-hex oid is NOT skipped. Width 40
    /// matters because `init_bare` runs `git init --bare --object-format=sha1`, so every
    /// production oid is 40 hex; a 64-only guard would silently make the fan-out probe
    /// dead code on exactly the repos the node creates.
    #[cfg(unix)]
    #[test]
    fn object_store_readable_rejects_a_non_hex_sha_without_building_a_path() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let (bare, blob) = bare_repo_with_blob(td.path());

        // A healthy repo answers `true` for every malformed oid, because the loose leg is
        // skipped rather than being handed `../../etc` to join.
        for bad in [
            "../../etc",
            &"a".repeat(41),
            &format!("{}z", "a".repeat(39)),
        ] {
            assert!(
                super::object_store_readable(&bare, bad),
                "a malformed oid must skip the fan-out leg, not veto a healthy store: {bad:?}"
            );
        }

        // Now break one fan-out dir and probe it two ways: a 40-hex oid living in it must
        // be checked (-> false), while a 41-character string with the same prefix must
        // still be skipped (-> true). Same broken directory, so the only difference is
        // whether the guard admitted the oid.
        let broken = bare.join("objects").join("aa");
        std::fs::create_dir_all(&broken).unwrap();
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&broken).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&broken, perms).unwrap();
        };
        chmod(0o000);
        let oid40 = format!("aa{}", "b".repeat(38));
        let genuinely_unreadable = std::fs::File::open(broken.join(&oid40[2..])).is_err();
        let checked = super::object_store_readable(&bare, &oid40);
        let skipped = super::object_store_readable(&bare, &format!("aa{}", "b".repeat(39)));
        chmod(0o755); // restore BEFORE any assertion that can panic

        if genuinely_unreadable {
            assert!(
                !checked,
                "a 40-hex oid must reach the fan-out probe, or the guard has disabled the \
                 whole check on the sha1 repos init_bare creates"
            );
            assert!(
                skipped,
                "a 41-character string must be rejected before any path is built from it"
            );
        }
        // Sanity: the healthy sha256 oid is unaffected by the unrelated broken directory.
        assert!(
            super::object_store_readable(&bare, &blob),
            "an unrelated broken fan-out dir must not veto a probe scoped to another oid"
        );
    }

    /// #174 F5/U4 (RED-before/GREEN-after, the CORE regression guard): a repo with a
    /// corrupt `.git/config` makes `git cat-file` die with `fatal: bad config line N`
    /// (exit 128, NO `error:` line) while `objects/` stays fully readable. The old
    /// `-t` path let that fall through to `Ok(None)` — a false 404 for content that
    /// may well exist. `object_type_bounded` must instead classify it as a
    /// DETERMINISTIC fault (a retry cannot fix it) so the serve path renders a
    /// terminal 500, never a 404 and never a retryable 503.
    ///
    /// LOAD-BEARING: revert the classification (route `BatchProbe::Fault` on a readable
    /// store back to `Ok(None)`, or drop the `has_error_diag`/exit checks so a hard
    /// `fatal:` is read as `missing`) and this goes RED — the probe reports the corrupt
    /// repo as an absent object.
    #[cfg(unix)]
    #[test]
    fn object_type_bounded_bad_config_is_deterministic_not_absence() {
        let td = tempfile::TempDir::new().unwrap();
        let (bare, blob) = bare_repo_with_blob(td.path());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        // Baseline on the healthy repo: present blob probes present, genuine miss is
        // the clean Ok(None) absence verdict.
        assert_eq!(
            super::object_type_bounded("git", &bare, &blob, deadline)
                .unwrap()
                .as_deref(),
            Some("blob"),
            "a present blob on a healthy readable store must probe present"
        );
        assert!(
            super::object_type_bounded("git", &bare, &"0".repeat(64), deadline)
                .unwrap()
                .is_none(),
            "a genuinely-absent object on a healthy readable store must be Ok(None) (404)"
        );

        // Corrupt the config; objects/ is untouched (and stays readable).
        {
            use std::io::Write;
            let mut cfg = std::fs::OpenOptions::new()
                .append(true)
                .open(bare.join("config"))
                .unwrap();
            cfg.write_all(b"\n[broken section\nnot a valid = = = line\n")
                .unwrap();
        }
        assert!(
            super::object_store_readable(&bare, &blob),
            "config corruption must leave objects/ readable (that is the whole point: \
             a readable store + a git failure == deterministic, not transient)"
        );

        // Probing the PRESENT blob under the bad config must be a DETERMINISTIC fault,
        // never Ok(None) (the old false 404) and never a Transient (retryable 503).
        let res = super::object_type_bounded("git", &bare, &blob, deadline);
        assert!(
            matches!(res, Err(super::ProbeError::Deterministic(_))),
            "a bad-config fatal on a readable store must be a terminal Deterministic \
             fault (-> 500), never Ok(None) (-> false 404) or Transient (-> 503); got {res:?}"
        );
        // And a genuinely-absent oid under the bad config is ALSO not an absence verdict.
        let res_absent = super::object_type_bounded("git", &bare, &"0".repeat(64), deadline);
        assert!(
            matches!(res_absent, Err(super::ProbeError::Deterministic(_))),
            "even a would-be-absent oid must not read as Ok(None) once the config is \
             corrupt; got {res_absent:?}"
        );
    }

    /// #173 round 12 (jatmn): the SIZE probe must use the same absence-versus-fault
    /// vocabulary the type probe does. It mapped every non-timeout failure to `Ok(None)`,
    /// which `gate_and_serve` reads as a verified absence and does not taint, so a
    /// corrupt object, an unreadable pack, or a failed spawn ended the search cleanly and
    /// handed an authorized caller a definitive 404 instead of the retryable 503 tail.
    ///
    /// A corrupt loose object is the same fixture the type stage uses for this, and it is
    /// the honest case: the object EXISTS, the type probe says so, and only the size read
    /// fails. RED before the change (`Ok(None)`).
    #[cfg(unix)]
    #[test]
    fn object_size_bounded_corrupt_loose_object_is_fault_not_absence() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let work = td.path().join("sizecorrupt");
        std::fs::create_dir_all(&work).unwrap();
        let g = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&work)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?}"
            );
        };
        g(&["init", "-q", "--object-format=sha256", "."]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        std::fs::write(work.join("f.txt"), b"loose object content\n").unwrap();
        g(&["add", "f.txt"]);
        g(&["commit", "-qm", "c1"]);
        let blob = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD:f.txt"])
                .current_dir(&work)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        // Healthy first: the probe reads the real size, so the fault case below is not
        // passing for the trivial reason that this fixture never worked.
        let healthy = super::object_size_bounded("git", &work, &blob, deadline);
        assert!(
            matches!(healthy, Ok(n) if n > 0),
            "a readable object reports its size; got {healthy:?}"
        );

        let obj = work.join(".git/objects").join(&blob[0..2]).join(&blob[2..]);
        let mut perms = std::fs::metadata(&obj).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&obj, perms).unwrap();
        std::fs::write(&obj, b"garbage not a zlib stream").unwrap();

        let res = super::object_size_bounded("git", &work, &blob, deadline);
        assert!(
            res.is_err(),
            "a corrupt object must surface as a probe fault, never as an absence the \
             resolver renders as a clean 404; got {res:?}"
        );
    }

    /// #173 round 12 (jatmn), the transient arm: a store this process cannot read is the
    /// retryable case, so the size probe classifies it `Transient` exactly as the type
    /// probe does. Distinguishing the two arms is the whole point of routing through
    /// `classify_store_fault` rather than returning one undifferentiated error.
    #[cfg(unix)]
    #[test]
    fn object_size_bounded_unreadable_store_is_transient() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let work = td.path().join("sizeunreadable");
        std::fs::create_dir_all(&work).unwrap();
        let g = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&work)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?}"
            );
        };
        g(&["init", "-q", "--object-format=sha256", "."]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        std::fs::write(work.join("f.txt"), b"loose object content\n").unwrap();
        g(&["add", "f.txt"]);
        g(&["commit", "-qm", "c1"]);
        let blob = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD:f.txt"])
                .current_dir(&work)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        // Make this oid's loose fan-out unreadable: git fails, and the store cannot
        // certify absence, so the fault is retryable rather than terminal.
        let fanout = work.join(".git/objects").join(&blob[0..2]);
        let mut perms = std::fs::metadata(&fanout).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&fanout, perms).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let res = super::object_size_bounded("git", &work, &blob, deadline);

        let mut restore = std::fs::metadata(&fanout).unwrap().permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(&fanout, restore).unwrap();

        assert!(
            matches!(res, Err(super::ProbeError::Transient(_))),
            "an unreadable object store is the retryable arm; got {res:?}"
        );
    }

    /// #174 F5/U4: a corrupt LOOSE object makes `git cat-file --batch-check` print
    /// `<oid> missing` on stdout (exit 0) yet emit `error:` diagnostics on stderr. The
    /// clean-`missing` absence path must NOT fire here — the `error:` line disqualifies
    /// a clean-absence read — so the probe surfaces a fault, not a false Ok(None) 404.
    /// The object store is readable (a corrupt object file still opens), so this is a
    /// Deterministic fault. LOAD-BEARING: drop the `has_error_diag` guard and a corrupt
    /// object reads as `missing` -> Ok(None) -> false 404 (RED).
    #[cfg(unix)]
    #[test]
    fn object_type_bounded_corrupt_loose_object_is_fault_not_absence() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let work = td.path().join("loose");
        std::fs::create_dir_all(&work).unwrap();
        let g = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&work)
                    .status()
                    .unwrap()
                    .success(),
                "git {args:?}"
            );
        };
        g(&["init", "-q", "--object-format=sha256", "."]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        std::fs::write(work.join("f.txt"), b"loose object content\n").unwrap();
        g(&["add", "f.txt"]);
        g(&["commit", "-qm", "c1"]);
        let blob = String::from_utf8(
            Command::new("git")
                .args(["rev-parse", "HEAD:f.txt"])
                .current_dir(&work)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        // Overwrite the loose object file with non-zlib garbage (it is 0o444 by default).
        let obj = work.join(".git/objects").join(&blob[0..2]).join(&blob[2..]);
        let mut perms = std::fs::metadata(&obj).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&obj, perms).unwrap();
        std::fs::write(&obj, b"garbage not a zlib stream").unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let res = super::object_type_bounded("git", &work, &blob, deadline);
        assert!(
            res.is_err(),
            "a corrupt loose object (error: on stderr, `missing` on stdout) must be Err, \
             never a false Ok(None) 404; got {res:?}"
        );
    }

    /// #174 U1 follow-up (RED-before/GREEN-after): the absent-CID path must not spawn a
    /// confirming re-probe it cannot afford. `object_type_bounded` disambiguates a clean
    /// `missing` by re-running the probe, but the re-probe took the SAME deadline with no
    /// check that any budget was left, so a first probe that nearly exhausted the budget
    /// still spawned a second child that could only be reaped. The watchdog's SIGTERM
    /// grace plus SIGKILL settle then carried the whole call to ~2x the budget, on a
    /// route an unauthenticated caller drives for every repo by spraying absent CIDs.
    ///
    /// Load-bearing: remove the affordability check and this goes RED on both assertions
    /// (a second spawn appears, and elapsed crosses 2x the budget). Measured before the
    /// fix: spawns=2, elapsed 2021ms against a 1000ms budget.
    #[cfg(unix)]
    #[test]
    fn absent_probe_skips_a_reprobe_it_cannot_afford() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(bare.join("objects/pack")).unwrap();
        let log = td.path().join("spawns.log");
        let fake = td.path().join("fakegit");
        // Burns 0.9s of a 1s budget, then reports the structured absence token cleanly.
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho call >> {}\nsleep 0.9\necho 'deadbeef missing'\nexit 0\n",
                log.display()
            ),
        )
        .unwrap();
        let mut perm = std::fs::metadata(&fake).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).unwrap();

        let budget = std::time::Duration::from_millis(1000);
        let deadline = std::time::Instant::now() + budget;
        let started = std::time::Instant::now();
        let res = super::object_type_bounded(fake.to_str().unwrap(), &bare, "deadbeef", deadline);
        let elapsed = started.elapsed();
        let spawns = std::fs::read_to_string(&log)
            .map(|s| s.lines().count())
            .unwrap_or(0);

        assert_eq!(
            spawns, 1,
            "a re-probe with no remaining budget must not be spawned at all; a second \
             spawn here is a child created only to be reaped, and its teardown grace is \
             what pushes this call past the deadline"
        );
        assert!(
            elapsed < budget + std::time::Duration::from_millis(400),
            "the call must not overshoot its deadline by the reap grace; got {elapsed:?} \
             against a {budget:?} budget (pre-fix this was ~2x the budget)"
        );
        assert!(
            matches!(res, Err(super::ProbeError::Transient(_))),
            "an unaffordable disambiguation is NOT an absence verdict: it must taint to \
             a retryable Transient, never a false Ok(None) 404; got {res:?}"
        );
    }

    /// #174 F3: the composed bounded read must round-trip a present object exactly as
    /// the unbounded `read_object` does: same `(type, bytes)` shape, bytes without the
    /// git framing header.
    #[cfg(unix)]
    #[test]
    fn read_object_bounded_roundtrips_a_present_blob() {
        let td = tempfile::TempDir::new().unwrap();
        let (bare, blob) = bare_repo_with_blob(td.path());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        let got = super::read_object_bounded("git", &bare, &blob, deadline)
            .expect("a healthy store must not fault")
            .expect("a present blob must not read as absent");
        assert_eq!(got.0, "blob");
        assert_eq!(
            got.1, b"f5 u4 content\n",
            "the content bytes must be the raw object content the CID is computed from"
        );
    }

    /// #174 F3: `Ok(None)` is reserved for a VERIFIED absence, and a healthy store must
    /// still produce it, so the composed helper must not fault-taint every miss.
    #[cfg(unix)]
    #[test]
    fn read_object_bounded_absent_is_none() {
        let td = tempfile::TempDir::new().unwrap();
        let (bare, _blob) = bare_repo_with_blob(td.path());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        let res = super::read_object_bounded("git", &bare, &"0".repeat(64), deadline);
        assert!(
            matches!(res, Ok(None)),
            "a genuinely-absent oid on a healthy store must be Ok(None); got {res:?}"
        );
    }

    /// #174 F3, the whole point of the helper: a wedged git cannot hold the caller past
    /// the deadline. The fake traps SIGTERM and sleeps a BOUNDED 30s, so a regression
    /// reports rather than wedges the suite, and the watchdog must escalate to SIGKILL to
    /// reap it. The failure is a spawn/timeout of the reaped child, which is retryable, so
    /// the variant is Transient.
    #[cfg(unix)]
    #[test]
    fn read_object_bounded_returns_by_deadline_with_a_hung_git() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        let td = tempfile::TempDir::new().unwrap();
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(bare.join("objects/pack")).unwrap();
        let fake = td.path().join("fakegit");
        std::fs::write(&fake, "#!/bin/sh\ntrap '' TERM\necho $$ > pid\nsleep 30\n").unwrap();
        let mut perm = std::fs::metadata(&fake).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).unwrap();
        let git_bin = fake.to_str().unwrap().to_string();

        let (tx, rx) = std::sync::mpsc::channel();
        let path = bare.clone();
        let oid = "0".repeat(64);
        std::thread::spawn(move || {
            let started = Instant::now();
            let res = super::read_object_bounded(
                &git_bin,
                &path,
                &oid,
                Instant::now() + Duration::from_secs(1),
            );
            let _ = tx.send((res, started.elapsed()));
        });
        // Generous ceiling, following the visibility_pack reap tests: this asserts only
        // "returned within the ceiling", never tight timing.
        let (res, elapsed) = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("read_object_bounded must return by its deadline, not on the child's lifetime");
        assert!(
            matches!(res, Err(super::ProbeError::Transient(_))),
            "a reaped hung child is a retryable fault, never an absence verdict; got {res:?}"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "elapsed {elapsed:?} must stay inside the watchdog budget"
        );

        // The child's process group must be gone when the call returns.
        let pid: i32 = std::fs::read_to_string(bare.join("pid"))
            .expect("the fake git must have recorded its pid")
            .trim()
            .parse()
            .unwrap();
        let mut gone = false;
        for _ in 0..200 {
            // SAFETY: kill(2) with signal 0 only probes existence; ESRCH means gone.
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            gone,
            "the hung git child (pid {pid}) must be reaped, not orphaned"
        );
    }

    /// #174 F3: a fault raised by the CONTENT stage must be classified through the same
    /// `classify_store_fault` vocabulary as the type stage, not leak out as a bare error
    /// and not decay into a false absence. The fixture is a fake git that answers
    /// `cat-file --batch-check` cleanly (so the type stage succeeds and the content stage
    /// is genuinely reached) and then fails the content read; the store itself is
    /// readable, so the classification is Deterministic.
    #[cfg(unix)]
    #[test]
    fn read_object_bounded_content_read_fault_is_classified() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(bare.join("objects/pack")).unwrap();
        let fake = td.path().join("fakegit");
        std::fs::write(
            &fake,
            "#!/bin/sh\nif [ \"$2\" = \"--batch-check\" ]; then read oid; echo \"$oid blob 6\"; exit 0; fi\n\
             echo 'error: unable to read object' >&2\nexit 128\n",
        )
        .unwrap();
        let mut perm = std::fs::metadata(&fake).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let res =
            super::read_object_bounded(fake.to_str().unwrap(), &bare, &"a".repeat(64), deadline);
        assert!(
            matches!(res, Err(super::ProbeError::Deterministic(_))),
            "a content-read failure on a READABLE store is a terminal Deterministic fault \
             (-> 500), never Ok(None) (-> a false 404) and never Transient; got {res:?}"
        );
    }

    /// #174 F3: the two stages must agree about ONE fault. A watchdog timeout of the
    /// reaped child is `Transient` when the TYPE stage raises it (a spawn or timeout
    /// failure is retryable), so the CONTENT stage must not route the identical failure
    /// through `classify_store_fault` and call it `Deterministic` just because the store
    /// happens to be readable. The fixture answers `--batch-check` cleanly, so the content
    /// stage is genuinely reached, and then hangs past the deadline with SIGTERM trapped so
    /// the watchdog has to escalate; the store itself is readable, which is exactly the
    /// condition that used to flip the verdict to terminal.
    ///
    /// The sleep is a BOUNDED 30s and the call runs on its own thread, following the
    /// sibling reap tests: a regression reports rather than wedging the suite.
    #[cfg(unix)]
    #[test]
    fn read_object_bounded_content_stage_timeout_is_transient_not_deterministic() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        let td = tempfile::TempDir::new().unwrap();
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(bare.join("objects/pack")).unwrap();
        let fake = td.path().join("fakegit");
        std::fs::write(
            &fake,
            "#!/bin/sh\nif [ \"$2\" = \"--batch-check\" ]; then read oid; echo \"$oid blob 6\"; exit 0; fi\n\
             trap '' TERM\necho $$ > pid\nsleep 30\n",
        )
        .unwrap();
        let mut perm = std::fs::metadata(&fake).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).unwrap();
        let git_bin = fake.to_str().unwrap().to_string();

        let (tx, rx) = std::sync::mpsc::channel();
        let path = bare.clone();
        std::thread::spawn(move || {
            let res = super::read_object_bounded(
                &git_bin,
                &path,
                &"a".repeat(64),
                Instant::now() + Duration::from_secs(1),
            );
            let _ = tx.send(res);
        });
        let res = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("the content stage must return by its deadline, not on the child's lifetime");

        // Prove the content stage was actually reached, or the assertion below would be
        // about the type stage's own timeout arm and prove nothing new.
        assert!(
            bare.join("pid").exists(),
            "the fixture must have reached the content read, or this test pins the wrong stage"
        );
        assert!(
            matches!(res, Err(super::ProbeError::Transient(_))),
            "a reaped content-stage child is the same retryable failure the type stage calls \
             Transient; classifying it by store readability makes one fault terminal at one \
             stage and retryable at the other; got {res:?}"
        );
    }

    /// #174 F3 companion: a fault raised by the TYPE stage propagates through the
    /// composed helper with its classification intact (a corrupt `.git/config` on a
    /// readable objects/ dir is Deterministic).
    #[cfg(unix)]
    #[test]
    fn read_object_bounded_type_stage_fault_keeps_its_classification() {
        use std::io::Write;
        let td = tempfile::TempDir::new().unwrap();
        let (bare, blob) = bare_repo_with_blob(td.path());
        let mut cfg = std::fs::OpenOptions::new()
            .append(true)
            .open(bare.join("config"))
            .unwrap();
        cfg.write_all(b"\n[broken section\nnot a valid = = = line\n")
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let res = super::read_object_bounded("git", &bare, &blob, deadline);
        assert!(
            matches!(res, Err(super::ProbeError::Deterministic(_))),
            "a bad-config fatal on a readable store must stay Deterministic through the \
             composed helper; got {res:?}"
        );
    }

    /// Companion must-not-regress case for the affordability check above: with an ample
    /// budget the confirming re-probe MUST still run, so the #174 F5 disambiguation is
    /// intact and the check did not simply disable it. Two spawns, and a clean absence.
    #[cfg(unix)]
    #[test]
    fn absent_probe_still_reprobes_when_the_budget_allows() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::TempDir::new().unwrap();
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(bare.join("objects/pack")).unwrap();
        let log = td.path().join("spawns.log");
        let fake = td.path().join("fakegit");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\necho call >> {}\necho 'deadbeef missing'\nexit 0\n",
                log.display()
            ),
        )
        .unwrap();
        let mut perm = std::fs::metadata(&fake).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let res = super::object_type_bounded(fake.to_str().unwrap(), &bare, "deadbeef", deadline);
        let spawns = std::fs::read_to_string(&log)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        assert_eq!(
            spawns, 2,
            "with budget to spare the confirming re-probe must still run, or the \
             absence-vs-unreadable-pack disambiguation is gone"
        );
        assert!(
            matches!(res, Ok(None)),
            "a clean `missing` twice on a readable store is a genuine absence; got {res:?}"
        );
    }
}
