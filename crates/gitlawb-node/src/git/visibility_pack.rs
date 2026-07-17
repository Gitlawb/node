//! Resolve which blob OIDs must be withheld from a caller because every path
//! at which the blob appears is denied by the repo's visibility rules. Trees
//! and commits are never withheld (mode B keeps SHAs intact); only blob
//! content is held back.

use crate::db::VisibilityRule;
use crate::visibility::{visibility_check, Decision};
use anyhow::{Context, Result};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Fixed budget bounding the whole withheld-blob classification walk (#174 U3).
/// The walk is fast for a real repo; this bound exists to reap a hung or
/// pathologically slow git child so it cannot pin a served-git permit (the read
/// permit on the upload-pack serve path, the write permit on the receive-pack
/// post-push replication path) past the deadline. Every caller funnels through
/// `blob_paths`, so bounding here bounds both paths at one seam. Production callers
/// pass the operator-configured `GITLAWB_GIT_SERVICE_TIMEOUT_SECS` instead; this
/// fixed budget only backs the `git_bin`-less test wrappers.
#[cfg(test)]
const WALK_TIMEOUT: Duration = Duration::from_secs(600);

/// How long the process-group watchdog waits after SIGTERM before escalating to
/// SIGKILL, giving a well-behaved git child time to clean up its `*.lock` files. Only
/// paid on a timeout (already the exceptional path).
#[cfg(unix)]
const WATCHDOG_TERM_GRACE: Duration = Duration::from_secs(1);

/// Run one git child under a shared `deadline` with process-group teardown,
/// BLOCKING, and return its stdout. The child runs in its own process group; a
/// watchdog thread SIGTERMs (lets git clean up its `*.lock` files), then SIGKILLs,
/// the whole group if the deadline passes before the child is reaped, so a hung or
/// slow git can pin neither a served-git permit nor a blocking thread past the
/// deadline (jatmn's "retain admission until they are reaped"). This is the
/// blocking-side counterpart of `smart_http::drive_git_child`, needed because the
/// walk's callers run it inside `spawn_blocking`, which an async timeout cannot
/// cancel. Returns [`crate::git::smart_http::GitServiceTimeout`] on the deadline so
/// the serve handler maps it to 504. `git_bin` is injectable so a fake `git` can
/// drive the teardown in tests without mutating the process-global PATH;
/// `stdin_bytes` feeds children that read stdin (empty for the arg-only children).
/// Returns true if `pid` (a process-group leader we spawned) has terminated, WITHOUT
/// reaping it. `waitid(..., WNOWAIT)` reports the exit state but leaves the child
/// waitable, so the caller's later `child.wait()` still collects the status and the
/// pid/pgid stays live until then — which is what keeps the watchdog's `kill(-pgid)`
/// teardown from ever racing a recycled pgid. Used to distinguish "the child actually
/// exited" from "the child merely closed stdout" after the drain returns (#174 P1-a).
#[cfg(unix)]
fn child_terminated_without_reaping(pid: i32) -> bool {
    // SAFETY: waitid writes only into the zeroed siginfo and borrows no Rust memory;
    // WNOWAIT leaves the child unreaped, WNOHANG makes the probe non-blocking.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // rc == 0 with si_pid == 0 means "no state change yet" (still running); a non-zero
    // si_pid means the child has entered a waitable, exited state. EINTR/other errors
    // (rc != 0) are treated as "not yet terminated" and the caller re-polls.
    rc == 0 && unsafe { info.si_pid() } != 0
}

#[cfg(unix)]
pub(crate) fn run_bounded_git(
    git_bin: &str,
    args: &[&str],
    repo_path: &Path,
    stdin_bytes: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc::RecvTimeoutError;

    let label = args.first().copied().unwrap_or("git");
    let mut child = std::process::Command::new(git_bin)
        .args(args)
        .current_dir(repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .with_context(|| format!("failed to spawn git {label}"))?;
    // With process_group(0) the child leads its own group, so pgid == its pid.
    let pgid = child.id() as i32;

    // Watchdog: on the deadline, tear the WHOLE process group down — SIGTERM, a grace
    // for a well-behaved child to clean up its `*.lock` files, then an UNCONDITIONAL
    // SIGKILL of the group. It never stands down on leader-reap alone: a group member
    // that ignores SIGTERM while the leader exits cleanly would otherwise escape the
    // SIGKILL and keep running past the deadline (finding 3, #174). The main thread
    // defers reaping the leader until this thread returns (see below), so the leader's
    // pid is still unreaped while every `kill(-pgid)` fires and the pgid cannot have
    // been recycled — which is why this no longer needs the old `reaped` short-circuit.
    // Kept off the main thread because the main thread's stdout drain is exactly what
    // blocks until a hung child is torn down.
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || -> bool {
        let wait = deadline.saturating_duration_since(Instant::now());
        match done_rx.recv_timeout(wait) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => false,
            Err(RecvTimeoutError::Timeout) => {
                // SAFETY: kill(2) takes only integers and borrows no Rust memory;
                // ESRCH on an already-gone group is ignored.
                unsafe { libc::kill(-pgid, libc::SIGTERM) };
                // Fixed grace: because the main thread defers the leader's reap, a
                // fully-exited group still shows a zombie leader here, so polling for
                // ESRCH cannot detect early completion — just wait the grace, then
                // SIGKILL. On a group of only zombies the SIGKILL is a harmless no-op;
                // on a SIGTERM-ignoring member it is what actually kills it.
                std::thread::sleep(WATCHDOG_TERM_GRACE);
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
                // Brief settle so the SIGKILL is delivered before the main thread
                // reaps the leader and frees the pgid. A wedged (D-state) member
                // survives even SIGKILL — the documented residual, as in smart_http.
                std::thread::sleep(Duration::from_millis(20));
                if unsafe { libc::kill(-pgid, 0) } == 0 {
                    tracing::warn!(
                        pgid,
                        "withheld-walk git survived SIGKILL past the watchdog cap (uninterruptible I/O?)"
                    );
                }
                true
            }
        }
    });

    // Feed stdin on a writer thread and drain stderr on a reader thread so the main
    // thread can drain stdout concurrently; writing all of stdin (or draining one
    // pipe) before the others can deadlock once a pipe buffer fills.
    let mut stdin = child.stdin.take();
    let input = stdin_bytes.to_vec();
    let writer = std::thread::spawn(move || {
        if let Some(mut s) = stdin.take() {
            let _ = s.write_all(&input);
        }
    });
    let mut stderr = child.stderr.take().context("git stderr was not piped")?;
    let err_reader = std::thread::spawn(move || {
        let mut err = Vec::new();
        let _ = stderr.read_to_end(&mut err);
        err
    });
    let mut stdout = child.stdout.take().context("git stdout was not piped")?;
    let mut out = Vec::new();
    // Blocking drain, unblocked by the child closing stdout on exit. The watchdog's
    // SIGTERM/SIGKILL is what makes a hung child exit; a git wedged in uninterruptible
    // (D-state) I/O survives even SIGKILL, so this drain and the wait below can block
    // until the kernel returns, pinning the walk thread and its permit. That residual
    // is unreachable in userspace (no signal reaps a D-state process) and matches the
    // async `reap_group_on_timeout`, which likewise only warns and gives up there.
    let read_result = stdout.read_to_end(&mut out);
    // The drain has returned, but that only means all stdout write ends are closed —
    // NOT that the child has exited. A group member, or the leader itself, can close
    // stdout and keep running; standing the watchdog down on the drain alone (as the
    // old code did) would then let `child.wait()` block forever on that live child,
    // past the deadline, pinning the walk thread and its permit (finding P1-a, #174).
    // So stand the watchdog down only once the child has ACTUALLY terminated, detected
    // WITHOUT reaping (waitid + WNOWAIT) so the leader's pid stays unreaped and its
    // pgid un-recycled until the watchdog finishes and we join it below. Past the
    // deadline the watchdog owns the teardown, so we stop polling and let it run the
    // full SIGTERM -> grace -> SIGKILL; joining it before `child.wait()` keeps every
    // `kill(-pgid)` firing while the pid is still unreaped and guarantees a
    // stdout-closing-then-hanging member has been SIGKILLed rather than left running.
    loop {
        if child_terminated_without_reaping(pgid) {
            let _ = done_tx.send(());
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let killed = watchdog.join().unwrap_or(false);
    let status = child.wait().context("git wait failed")?;
    let err = err_reader.join().unwrap_or_default();
    let _ = writer.join();
    read_result.context("failed to read git stdout")?;
    // The watchdog runs off a wall clock that can race a child finishing right at the
    // deadline. A child that exited on its own (success) is not a timeout even if the
    // watchdog fired late; only a child that did not exit successfully is a genuine
    // timeout, which keeps a walk completing at its budget from a spurious 504.
    if killed && !status.success() {
        return Err(crate::git::smart_http::GitServiceTimeout.into());
    }
    if !status.success() {
        anyhow::bail!("git {label} failed: {}", String::from_utf8_lossy(&err));
    }
    Ok(out)
}

/// Non-Unix fallback for [`run_bounded_git`]. Windows and other non-Unix targets
/// have no process-group teardown (`process_group(0)` / `kill(-pgid)` are Unix-only),
/// so this bounds a single child on its own: threads feed stdin and drain stderr
/// while the main thread drains stdout, and a watchdog thread kills the child at the
/// deadline (which closes stdout and unblocks the drain). The child is shared with
/// the watchdog behind a mutex that the main thread does NOT hold while draining, so
/// the watchdog can always acquire it to kill. Best-effort — it reaps only the direct
/// child, not a descendant group — which is why the hardened, group-aware path above
/// is gated to Unix, the only target the served node actually runs on (the Windows
/// release binary is best-effort / `continue-on-error` in CI). Kept in lockstep with
/// the Unix version's signature and result semantics so every caller compiles on all
/// targets (#174).
#[cfg(not(unix))]
pub(crate) fn run_bounded_git(
    git_bin: &str,
    args: &[&str],
    repo_path: &Path,
    stdin_bytes: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::sync::mpsc::RecvTimeoutError;

    let label = args.first().copied().unwrap_or("git");
    let mut child = std::process::Command::new(git_bin)
        .args(args)
        .current_dir(repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn git {label}"))?;

    let mut stdin = child.stdin.take();
    let input = stdin_bytes.to_vec();
    let writer = std::thread::spawn(move || {
        if let Some(mut s) = stdin.take() {
            let _ = s.write_all(&input);
        }
    });
    let mut stderr = child.stderr.take().context("git stderr was not piped")?;
    let err_reader = std::thread::spawn(move || {
        let mut err = Vec::new();
        let _ = stderr.read_to_end(&mut err);
        err
    });
    let mut stdout = child.stdout.take().context("git stdout was not piped")?;

    // Share the child with the watchdog. The main thread drains stdout WITHOUT
    // holding this lock, so the watchdog can always acquire it to kill on timeout;
    // killing closes stdout and unblocks the drain below.
    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let watchdog = {
        let child = child.clone();
        std::thread::spawn(move || -> bool {
            let wait = deadline.saturating_duration_since(Instant::now());
            match done_rx.recv_timeout(wait) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => false,
                Err(RecvTimeoutError::Timeout) => {
                    if let Ok(mut c) = child.lock() {
                        let _ = c.kill();
                    }
                    true
                }
            }
        })
    };

    let mut out = Vec::new();
    let read_result = stdout.read_to_end(&mut out);
    // The drain has returned (child exited or was killed), so taking the lock here
    // cannot deadlock against the watchdog.
    let status = child
        .lock()
        .expect("git child mutex poisoned")
        .wait()
        .context("git wait failed")?;
    let _ = done_tx.send(());
    let killed = watchdog.join().unwrap_or(false);
    let err = err_reader.join().unwrap_or_default();
    let _ = writer.join();
    read_result.context("failed to read git stdout")?;
    if killed && !status.success() {
        return Err(crate::git::smart_http::GitServiceTimeout.into());
    }
    if !status.success() {
        anyhow::bail!("git {label} failed: {}", String::from_utf8_lossy(&err));
    }
    Ok(out)
}

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
fn assert_all_refs_are_commits(repo_path: &Path, git_bin: &str, deadline: Instant) -> Result<()> {
    let refs_out = run_bounded_git(
        git_bin,
        &["for-each-ref", "--format=%(refname)"],
        repo_path,
        b"",
        deadline,
    )?;
    let refs_stdout = String::from_utf8_lossy(&refs_out);
    let refnames: Vec<&str> = refs_stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if refnames.is_empty() {
        return Ok(());
    }

    // Peel every ref in one `git cat-file --batch-check` pass: one `<refname>^{}`
    // query per line, one output line per input line, in order. cat-file echoes the
    // full query on a `<query> missing` line, so output scales with refname length;
    // run_bounded_git drains stdout concurrently with the stdin write, so the pipe
    // cannot deadlock, and the whole peel is bounded by the shared walk deadline.
    let queries = refnames
        .iter()
        .map(|r| format!("{r}^{{}}"))
        .collect::<Vec<_>>()
        .join("\n");
    let peel_out = run_bounded_git(
        git_bin,
        &["cat-file", "--batch-check=%(objecttype)"],
        repo_path,
        queries.as_bytes(),
        deadline,
    )?;

    let peel_stdout = String::from_utf8_lossy(&peel_out);
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
fn blob_paths(repo_path: &Path, git_bin: &str, timeout: Duration) -> Result<Vec<(String, String)>> {
    // One deadline spans the whole walk (the ref check, the HEAD probe, rev-list,
    // and every per-commit ls-tree), so a slow or hung walk is bounded as a unit
    // rather than granting each git child a fresh timeout.
    let deadline = Instant::now() + timeout;
    assert_all_refs_are_commits(repo_path, git_bin, deadline)?;

    // Enumerate every reachable commit, not just ref tips. `--all` walks all refs;
    // append HEAD so a detached HEAD (reachable by rev-list/upload-pack but in no
    // ref) is still classified. When HEAD does not resolve (unborn branch on an
    // empty repo) `--all` alone yields nothing, which is correct: no objects exist.
    // The HEAD probe is a bounded `git rev-parse --verify HEAD` (a clean exit means
    // HEAD resolves), replacing the previously unbounded `store::head_commit` child.
    let head_resolves = run_bounded_git(
        git_bin,
        &["rev-parse", "--verify", "HEAD"],
        repo_path,
        b"",
        deadline,
    )
    .is_ok();
    let mut rev_args = vec!["rev-list", "--all"];
    if head_resolves {
        rev_args.push("HEAD");
    }
    let commits_out = run_bounded_git(git_bin, &rev_args, repo_path, b"", deadline)?;
    let commits_stdout = String::from_utf8_lossy(&commits_out);
    let mut out: HashSet<(String, String)> = HashSet::new();
    for commit in commits_stdout.lines() {
        let commit = commit.trim();
        if commit.is_empty() {
            continue;
        }
        let listing_out = run_bounded_git(
            git_bin,
            &["ls-tree", "-rz", commit],
            repo_path,
            b"",
            deadline,
        )?;
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
        let Ok(listing_stdout) = std::str::from_utf8(&listing_out) else {
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
#[cfg(test)]
pub fn withheld_blob_oids(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    withheld_blob_oids_bounded(
        repo_path,
        "git",
        WALK_TIMEOUT,
        rules,
        is_public,
        owner_did,
        caller,
    )
}

/// [`withheld_blob_oids`] with an injectable `git_bin` and walk `timeout`. Served
/// handlers call this with the operator-configured git binary and
/// `GITLAWB_GIT_SERVICE_TIMEOUT_SECS`, so the whole walk is bounded by the same
/// budget as the other served-git ops and a fake `git` can drive its teardown in
/// tests. The `git_bin`-less wrapper above keeps the fixed [`WALK_TIMEOUT`] for the
/// classification tests that run against real git.
pub fn withheld_blob_oids_bounded(
    repo_path: &Path,
    git_bin: &str,
    timeout: Duration,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    let pairs = blob_paths(repo_path, git_bin, timeout)?;
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
#[cfg(test)]
pub fn replicable_blob_set(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> Result<HashSet<String>> {
    allowed_blob_set_for_caller(repo_path, rules, is_public, owner_did, None)
}

/// [`replicable_blob_set`] with an injectable `git_bin` and walk `timeout`, for the
/// fail-closed full-scan pin path on the receive-pack side.
pub fn replicable_blob_set_bounded(
    repo_path: &Path,
    git_bin: &str,
    timeout: Duration,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> Result<HashSet<String>> {
    allowed_blob_set_for_caller_bounded(
        repo_path, git_bin, timeout, rules, is_public, owner_did, None,
    )
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
#[cfg(test)]
pub fn allowed_blob_set_for_caller(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    allowed_blob_set_for_caller_bounded(
        repo_path,
        "git",
        WALK_TIMEOUT,
        rules,
        is_public,
        owner_did,
        caller,
    )
}

/// [`allowed_blob_set_for_caller`] with an injectable `git_bin` and walk `timeout`,
/// for the `GET /ipfs/{cid}` gate.
pub fn allowed_blob_set_for_caller_bounded(
    repo_path: &Path,
    git_bin: &str,
    timeout: Duration,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    let pairs = blob_paths(repo_path, git_bin, timeout)?;
    let mut allowed = HashSet::new();
    for (oid, path) in &pairs {
        if visibility_check(rules, is_public, owner_did, caller, path) == Decision::Allow {
            allowed.insert(oid.clone());
        }
    }
    Ok(allowed)
}

/// The reachable-commit enumeration for the LENIENT walks (the `/ipfs/{cid}` tree
/// gate and the commit/tag reachability set): bounded `git rev-list --all [HEAD]`
/// under the caller's shared `deadline`, deliberately WITHOUT
/// `assert_all_refs_are_commits`. That guard fail-closes a repo's whole walk when
/// any ref peels to a non-commit (an annotated tag of a tree is pushable through
/// receive-pack), which would 404 every reachable tree/commit/tag CID here for a
/// legitimate reader. `rev-list --all` skips such refs cleanly, so the commit set
/// stays complete; an object reachable only via such a ref is simply excluded —
/// correctly fail-closed. Fails closed on a rev-list error.
///
/// Safe ONLY for a caller whose output feeds a fail-closed allow-list where absence
/// = withhold: a tolerant walk there over-withholds, never leaks. NOT safe for a
/// serve/replication filter, where a missed reachable object under-withholds —
/// those go through `blob_paths`, which runs the guard first.
fn reachable_commit_oids(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
) -> Result<Vec<String>> {
    // The HEAD probe is a bounded `git rev-parse --verify HEAD` (a clean exit means
    // HEAD resolves), matching `blob_paths`. When HEAD does not resolve (unborn
    // branch on an empty repo) `--all` alone yields nothing, which is correct.
    let head_resolves = run_bounded_git(
        git_bin,
        &["rev-parse", "--verify", "HEAD"],
        repo_path,
        b"",
        deadline,
    )
    .is_ok();
    let mut rev_args = vec!["rev-list", "--all"];
    if head_resolves {
        rev_args.push("HEAD");
    }
    let out = run_bounded_git(git_bin, &rev_args, repo_path, b"", deadline)?;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Every `(oid, "/repo/relative/path", kind)` triple reachable from the given
/// `commits` — the shared ls-tree seam the tree walk filters (`kind == "tree"`).
/// One bounded `git ls-tree -rzt` per commit under the caller's shared `deadline`:
/// `-rzt` is byte-identical to `-rz` for blob records and additionally emits the
/// tree object for each directory at its own path. `kind` is git's object-type
/// string ("blob", "tree", or "commit" for a gitlink). The commit's ROOT tree is
/// not emitted by `ls-tree` (it lists entries *under* a tree); `tree_paths` adds
/// it. Triples are de-duplicated across commits and paths carry a leading "/" to
/// match the glob form of visibility rules ("/secret/**").
///
/// Fails closed: if any tree walk fails — or a path is not valid UTF-8 — it
/// returns an error so the caller aborts rather than producing a partial
/// (under-withheld) set.
fn object_paths(
    repo_path: &Path,
    git_bin: &str,
    commits: &[String],
    deadline: Instant,
) -> Result<HashSet<(String, String, String)>> {
    let mut out: HashSet<(String, String, String)> = HashSet::new();
    for commit in commits {
        let listing_out = run_bounded_git(
            git_bin,
            &["ls-tree", "-rzt", commit],
            repo_path,
            b"",
            deadline,
        )?;
        // `-z` NUL-delimits records and emits paths raw; plain `git ls-tree -r`
        // C-quotes any path with non-ASCII or special bytes (e.g. café.txt becomes
        // "secret/caf\303\251.txt"), and that quoted literal would not match a
        // visibility rule like "/secret/**", under-withholding the object. The TAB
        // field separator survives `-z`, so the per-record parse is unchanged.
        //
        // Parse strictly: a lossy decode would replace an invalid byte in a denied
        // path (e.g. a non-UTF-8 directory name) with U+FFFD, and the mangled string
        // would no longer match its deny rule — the same under-withholding class, one
        // layer down. Fail closed instead so the caller aborts rather than leaks.
        let Ok(listing_stdout) = std::str::from_utf8(&listing_out) else {
            anyhow::bail!(
                "git ls-tree -rzt {commit} returned a non-UTF-8 path; \
                 refusing to produce a partial (under-withheld) set"
            );
        };
        for record in listing_stdout.split('\0') {
            // "<mode> <kind> <oid>\t<path>"
            let Some((meta, path)) = record.split_once('\t') else {
                continue;
            };
            let mut parts = meta.split_whitespace();
            let _mode = parts.next();
            let kind = parts.next();
            let oid = parts.next();
            if let (Some(kind), Some(oid)) = (kind, oid) {
                out.insert((oid.to_string(), format!("/{path}"), kind.to_string()));
            }
        }
    }
    Ok(out)
}

/// Root tree oid of every reachable commit, at "/". `ls-tree` never emits a commit's
/// own root tree (it lists entries *under* a tree), so it is added explicitly here.
/// Resolved in ONE bounded `git log --no-walk --format=%T --stdin` pass over the
/// shared commit set — not a per-commit `rev-parse` — so a tree-set walk costs the
/// same subprocess order as the blob walk. The commit oids go on STDIN, not argv: a
/// long history has tens of thousands of reachable commits, and passing them all as
/// arguments overflows ARG_MAX so `git log` fails to spawn — which the caller treats
/// as a walk error and fail-closed 404s an authorized reader of a reachable/root
/// tree (#173 P2). `run_bounded_git` drains stdout concurrently with the stdin
/// write, so a large history cannot deadlock the pipes. A commit whose root tree git
/// cannot resolve fails the pass (bail), failing closed.
fn root_tree_pairs(
    repo_path: &Path,
    git_bin: &str,
    commits: &[String],
    deadline: Instant,
) -> Result<HashSet<(String, String)>> {
    if commits.is_empty() {
        return Ok(HashSet::new());
    }
    let mut buf = String::with_capacity(commits.len() * 65);
    for c in commits {
        buf.push_str(c);
        buf.push('\n');
    }
    let out = run_bounded_git(
        git_bin,
        &["log", "--no-walk=unsorted", "--format=%T", "--stdin"],
        repo_path,
        buf.as_bytes(),
        deadline,
    )?;
    let mut set = HashSet::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let oid = line.trim();
        if !oid.is_empty() {
            set.insert((oid.to_string(), "/".to_string()));
        }
    }
    Ok(set)
}

/// Every `(tree_oid, "/path")` pair reachable in `repo_path`: the `kind == "tree"`
/// slice of [`object_paths`] (subtree trees at their directory paths) PLUS every
/// reachable commit's root tree at "/" (see [`root_tree_pairs`]). Computes the
/// reachable-commit set ONCE (leniently — see [`reachable_commit_oids`]; the tree
/// allowed-set feeds ONLY the `/ipfs/{cid}` tree gate, where absence = fail-closed
/// 404) and drives both the ls-tree walk and the root-tree pass from it, so the two
/// cannot diverge and neither re-enumerates. The tree analog of [`blob_paths`],
/// bounded by the same shared `deadline`.
fn tree_paths(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
) -> Result<HashSet<(String, String)>> {
    let commits = reachable_commit_oids(repo_path, git_bin, deadline)?;
    let mut out: HashSet<(String, String)> = object_paths(repo_path, git_bin, &commits, deadline)?
        .into_iter()
        .filter(|(_, _, kind)| kind == "tree")
        .map(|(oid, path, _)| (oid, path))
        .collect();
    out.extend(root_tree_pairs(repo_path, git_bin, &commits, deadline)?);
    Ok(out)
}

/// The OIDs from a `(oid, "/path")` listing that visibility ALLOWS `caller` at some
/// path — the shared inner loop of the blob and tree allowed-sets. An oid reachable
/// at an allowed path is kept even when also reachable at a denied one.
fn allowed_set_from_pairs<'a>(
    pairs: impl IntoIterator<Item = &'a (String, String)>,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> HashSet<String> {
    pairs
        .into_iter()
        .filter(|(_, path)| {
            visibility_check(rules, is_public, owner_did, caller, path) == Decision::Allow
        })
        .map(|(oid, _)| oid.clone())
        .collect()
}

/// Reachable tree OIDs that visibility ALLOWS `caller` at some path — the tree
/// analog of [`allowed_blob_set_for_caller`]. `GET /ipfs/{cid}` gates tree objects
/// with this so the CID surface matches `get_tree`: a tree reachable only at a
/// withheld path is absent from the set and 404'd; the root tree ("/") and any tree
/// on the path to an allowed subtree are present. Fails closed on a
/// dangling/unreachable tree (never enumerated by the reachable walk, so never in
/// the set — the #126 geometry, for trees). A tree reachable at an allowed path is
/// included even when also reachable at a withheld one (its structure is visible to
/// this caller elsewhere).
#[cfg(test)]
pub fn allowed_tree_set_for_caller(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    allowed_tree_set_for_caller_bounded(
        repo_path,
        "git",
        WALK_TIMEOUT,
        rules,
        is_public,
        owner_did,
        caller,
    )
}

/// [`allowed_tree_set_for_caller`] with an injectable `git_bin` and walk `timeout`,
/// for the `GET /ipfs/{cid}` tree gate. One deadline spans the whole walk (the HEAD
/// probe, rev-list, every per-commit ls-tree, and the root-tree pass), matching
/// `blob_paths`, so a slow or hung walk is bounded as a unit while the handler holds
/// its /ipfs walk permit (#174 F5).
pub fn allowed_tree_set_for_caller_bounded(
    repo_path: &Path,
    git_bin: &str,
    timeout: Duration,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Result<HashSet<String>> {
    let deadline = Instant::now() + timeout;
    Ok(allowed_set_from_pairs(
        &tree_paths(repo_path, git_bin, deadline)?,
        rules,
        is_public,
        owner_did,
        caller,
    ))
}

/// Object bound for the annotated-tag reachability walk (#173, jatmn tag fan-out).
/// A path-scoped pinned-CID request drives this walk while holding one per-request
/// and one per-IP walk slot, so the total tag work must be finite regardless of how
/// many tag refs the repo has. 8192 is far past any real repo's annotated-tag count
/// (the Linux kernel has a few hundred), yet finite: a repo beyond it fails closed
/// (Err), matching this function's fail-closed-on-any-git-error contract, rather than
/// truncating silently (which would under-withhold a still-reachable tag object).
const MAX_TAG_OBJECTS: usize = 8192;

/// Walk the annotated-tag chains rooted at `seeds`, inserting every tag object they
/// pass through into `set`. A tag whose target is itself a tag (tag-of-a-tag)
/// discovers the inner tag, which is walked in a later round.
///
/// #173 (jatmn): the tag inspection is BATCHED, not one process per tag. Each round
/// feeds every not-yet-inspected tag oid to a SINGLE `git cat-file --batch` child on
/// stdin and reads back framed `<oid> <type> <size>\n<contents>\n` records, so the
/// number of child processes is bounded by the tag-chain DEPTH (rounds), not the tag
/// COUNT. Oids go on stdin, never argv, so a large tag set cannot overflow ARG_MAX.
/// The child runs through [`run_bounded_git`], which drains stdout concurrently with
/// the stdin write (subsuming #173's F4 writer-thread drain — a round large enough to
/// fill both pipes cannot deadlock) and tears the child down at `deadline`, so a hung
/// cat-file cannot pin the caller's /ipfs walk permit (#174 F5). Total tag objects
/// inspected are capped at `max_tag_objects`; exceeding it is an error (fail closed),
/// not a silent truncation. Takes the bound as a parameter so a test can drive a tiny
/// value while the caller passes the real `MAX_TAG_OBJECTS`.
fn walk_tag_chain(
    repo_path: &Path,
    git_bin: &str,
    seeds: Vec<String>,
    set: &mut HashSet<String>,
    max_tag_objects: usize,
    deadline: Instant,
) -> Result<()> {
    // Tag oids known but not yet inspected. Seeds may repeat / already be present;
    // the `set.insert` gate below is what actually dedups and terminates cycles.
    let mut pending: Vec<String> = seeds;
    let mut inspected: usize = 0;

    while !pending.is_empty() {
        // Inspect only oids new to `set`; a re-seen oid was already walked.
        let round: Vec<String> = pending
            .drain(..)
            .filter(|oid| set.insert(oid.clone()))
            .collect();
        if round.is_empty() {
            break;
        }
        inspected += round.len();
        if inspected > max_tag_objects {
            anyhow::bail!(
                "annotated-tag walk exceeded the object bound ({max_tag_objects}); refusing to serve"
            );
        }

        // One bounded child for the whole round: feed all oids on stdin, read the
        // framed records from the returned stdout.
        let mut buf = String::with_capacity(round.len() * 65);
        for oid in &round {
            buf.push_str(oid);
            buf.push('\n');
        }
        let stdout = run_bounded_git(
            git_bin,
            &["cat-file", "--batch"],
            repo_path,
            buf.as_bytes(),
            deadline,
        )?;

        // Parse one record per requested oid: `<oid> <type> <size>\n<size bytes>\n`.
        // A `<oid> missing\n` record has no size/body and is anomalous here (every
        // oid came from a ref tip or a prior tag body), so fail closed.
        let mut i = 0usize;
        for _ in 0..round.len() {
            let hdr_end = stdout[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| i + p)
                .context("git cat-file --batch: truncated record header")?;
            let header = std::str::from_utf8(&stdout[i..hdr_end])
                .context("git cat-file --batch: non-utf8 record header")?;
            i = hdr_end + 1;
            let mut fields = header.split(' ');
            let _oid = fields.next().unwrap_or("");
            let ty = fields.next().unwrap_or("");
            if ty == "missing" || fields.clone().next().is_none() {
                anyhow::bail!("git cat-file --batch: object {header:?} missing or malformed");
            }
            let size: usize = fields
                .next()
                .unwrap_or("")
                .parse()
                .context("git cat-file --batch: bad record size")?;
            let body_end = i
                .checked_add(size)
                .filter(|&e| e <= stdout.len())
                .context("git cat-file --batch: truncated record body")?;
            // Only a tag object can point at an inner tag; walk its header.
            if ty == "tag" {
                let body = std::str::from_utf8(&stdout[i..body_end])
                    .context("git cat-file --batch: non-utf8 tag body")?;
                let mut target = None;
                let mut is_tag = false;
                for line in body.lines() {
                    if let Some(oid) = line.strip_prefix("object ") {
                        target = Some(oid.trim().to_string());
                    } else if line == "type tag" {
                        is_tag = true;
                    } else if line.is_empty() {
                        break; // end of header
                    }
                }
                if is_tag {
                    if let Some(t) = target {
                        pending.push(t);
                    }
                }
            }
            // Skip body plus its trailing newline to the next record.
            i = body_end + 1;
        }
    }
    Ok(())
}

/// The reachable-commit/tag gate set for the `/ipfs/{cid}` resolver (#173, F2):
/// every reachable commit oid UNION every reachable annotated-tag OBJECT oid. A
/// DANGLING commit/tag (referenced by no ref, directly or via a tag chain) is in
/// neither part, so the resolver denies it under a path-scoped rule instead of
/// leaking its message; a reachable one still serves.
#[cfg(test)]
pub fn reachable_commit_tag_oids(repo_path: &Path) -> Result<HashSet<String>> {
    reachable_commit_tag_oids_bounded(repo_path, "git", WALK_TIMEOUT)
}

/// [`reachable_commit_tag_oids`] with an injectable `git_bin` and walk `timeout`,
/// for the `GET /ipfs/{cid}` commit/tag gate. One deadline spans the whole walk.
///
/// Reachable commits come from bounded `git rev-list --all` (+ HEAD for the
/// detached case). Unlike the blob allowed-set, this does NOT run
/// `assert_all_refs_are_commits`: that guard fail-closes a repo's whole walk when
/// any ref peels to a non-commit (an annotated tag of a tree is pushable through
/// receive-pack), which would 404 every reachable commit/tag CID here for a
/// legitimate reader. The guard exists to stop blob/tree UNDER-withholding; it is
/// unnecessary for reachability, since a dangling object is absent from
/// `rev-list --all` and the ref walk below regardless of odd refs — so dropping it
/// recovers availability without admitting any dangling object (no leak).
///
/// Reachable tag OBJECTS: `rev-list --all` dereferences annotated tags to commits,
/// so the tag objects are absent from it. Collect them by walking every ref tip and
/// peeling each tag's chain, so a nested tag-of-a-tag's INNER tag object (reachable
/// and pinnable, but not itself a ref tip) is included too. Fails closed on any git
/// error.
pub fn reachable_commit_tag_oids_bounded(
    repo_path: &Path,
    git_bin: &str,
    timeout: Duration,
) -> Result<HashSet<String>> {
    let deadline = Instant::now() + timeout;
    // Reachable commits — no ref-commit assertion (see docstring). The HEAD probe
    // doubles as the seed source for the tag-valued detached HEAD below:
    // `rev-parse --verify HEAD` returns the tag oid UNPEELED when HEAD names a tag
    // object. Failing to resolve HEAD (unborn/absent) is not fatal — there is
    // simply no HEAD to walk or seed.
    let head_oid: Option<String> = run_bounded_git(
        git_bin,
        &["rev-parse", "--verify", "HEAD"],
        repo_path,
        b"",
        deadline,
    )
    .ok()
    .map(|out| String::from_utf8_lossy(&out).trim().to_string())
    .filter(|s| !s.is_empty());
    let mut rev_args = vec!["rev-list", "--all"];
    if head_oid.is_some() {
        rev_args.push("HEAD");
    }
    let rev = run_bounded_git(git_bin, &rev_args, repo_path, b"", deadline)?;
    let mut set: HashSet<String> = String::from_utf8_lossy(&rev)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    // Ref tips that are annotated tag objects seed the tag-chain walk.
    let refs = run_bounded_git(
        git_bin,
        &["for-each-ref", "--format=%(objectname) %(objecttype)"],
        repo_path,
        b"",
        deadline,
    )?;
    let mut worklist: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(&refs).lines() {
        let mut it = line.split_whitespace();
        if let (Some(oid), Some("tag")) = (it.next(), it.next()) {
            worklist.push(oid.to_string());
        }
    }
    // A detached/direct HEAD may name an annotated tag object with no ref at that tag
    // (#173 review, finding 3): `rev-list --all HEAD` above peels it to its commit and
    // `for-each-ref` has no tag row, so the tag OBJECT would be omitted and its pinned
    // CID would 404 for an authorized reader. Seed a tag-valued HEAD into the tag-chain
    // walk; a `commit` HEAD adds nothing. A cat-file failure here only skips the seed
    // (over-withholds that one tag — fail-closed), matching the original's tolerance.
    if let Some(head_oid) = head_oid {
        if let Ok(ty) = run_bounded_git(
            git_bin,
            &["cat-file", "-t", &head_oid],
            repo_path,
            b"",
            deadline,
        ) {
            if String::from_utf8_lossy(&ty).trim() == "tag" {
                worklist.push(head_oid);
            }
        }
    }
    // Peel every tag object's chain into `set`, adding each tag object it passes
    // through. Bounded and batched (#173, jatmn tag fan-out): see `walk_tag_chain`.
    walk_tag_chain(
        repo_path,
        git_bin,
        worklist,
        &mut set,
        MAX_TAG_OBJECTS,
        deadline,
    )?;
    Ok(set)
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
#[cfg(test)]
pub fn withheld_blob_recipients(
    repo_path: &Path,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> Result<HashMap<String, BTreeSet<String>>> {
    withheld_blob_recipients_bounded(repo_path, "git", WALK_TIMEOUT, rules, is_public, owner_did)
}

/// [`withheld_blob_recipients`] with an injectable `git_bin` and walk `timeout`, for
/// the receive-pack encrypt-then-pin path.
pub fn withheld_blob_recipients_bounded(
    repo_path: &Path,
    git_bin: &str,
    timeout: Duration,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> Result<HashMap<String, BTreeSet<String>>> {
    // One history walk feeds both the withheld set and the recipient mapping.
    let pairs = blob_paths(repo_path, git_bin, timeout)?;
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

    /// Write an executable fake `git` shell script into `dir` and return its path,
    /// so a test can drive the walk's process-group teardown without a real git and
    /// without mutating the process-global PATH (the crate's only injection seam).
    #[cfg(unix)]
    fn write_fake_git(dir: &Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fakegit");
        std::fs::write(&p, body).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p.to_str().unwrap().to_string()
    }

    /// #174 U3: the withheld-blob walk is bounded at the shared `blob_paths` seam, so
    /// a hung git child cannot pin the caller's permit past the deadline. A fake git
    /// that hangs on `rev-list` must make `blob_paths` return `GitServiceTimeout`
    /// within the watchdog budget (not block for the child's lifetime), and the
    /// child's process group must be reaped (its recorded leader PID gone). Every
    /// caller (upload-pack serve, receive-pack replication) funnels through
    /// `blob_paths`, so this seam-level proof covers both permit pools. Neutralize
    /// the watchdog SIGTERM and this hangs past the recv budget (RED).
    #[cfg(unix)]
    #[test]
    fn blob_paths_times_out_and_reaps_a_hung_walk() {
        use std::time::Duration;
        let tmp = TempDir::new().unwrap();
        // Fast on every stage except rev-list, which records its own (group-leader)
        // PID and then hangs. `sleep 30` bounds the worst case if the watchdog is
        // ever broken, so a regression cannot wedge the suite for 300s.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-list) echo $$ > revlist.pid ; sleep 30 ;;\n  rev-parse) echo deadbeef ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);

        // Run the walk on a thread with a short budget; the recv_timeout succeeding
        // is itself proof the walk did not block on the hung child.
        let (tx, rx) = mpsc::channel();
        let path = tmp.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(blob_paths(&path, &git_bin, Duration::from_millis(200)));
        });
        let result = rx.recv_timeout(Duration::from_secs(10)).expect(
            "blob_paths must return within the watchdog budget, not hang on a stuck git child",
        );
        let err = result.expect_err("a hung rev-list must abort the walk with an error");
        assert!(
            err.downcast_ref::<crate::git::smart_http::GitServiceTimeout>()
                .is_some(),
            "a hung walk must abort with GitServiceTimeout (mapped to 504), got: {err}"
        );

        // The recorded process-group leader must be gone: the watchdog reaps the
        // whole group before blob_paths returns, so no orphaned git lingers.
        let pid: i32 = std::fs::read_to_string(tmp.path().join("revlist.pid"))
            .expect("the fake git must have recorded its rev-list PID")
            .trim()
            .parse()
            .expect("recorded PID must parse");
        let mut gone = false;
        for _ in 0..200 {
            // SAFETY: kill(2) with signal 0 only probes existence; ESRCH (-1) means
            // the process is gone. Borrows no Rust memory.
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            gone,
            "the hung git child (pid {pid}) must be reaped, not orphaned, after the walk aborts"
        );
    }

    /// #174 (F1 status-gate, vetted by execution): a child that exits SUCCESSFULLY is
    /// never reported as a timeout even when the watchdog fires, so a walk finishing
    /// right at its deadline is not a spurious 504. The fake only exits when signalled
    /// and exits 0 on SIGTERM, so with a deadline already elapsed the watchdog always
    /// reaches its kill path (killed == true) yet the child's status is success.
    /// Drop the `!status.success()` guard and this returns GitServiceTimeout (RED).
    #[cfg(unix)]
    #[test]
    fn run_bounded_git_success_at_the_deadline_is_not_a_timeout() {
        use std::time::{Duration, Instant};
        let tmp = TempDir::new().unwrap();
        let body = "#!/bin/sh\ntrap 'exit 0' TERM\nsleep 30 &\nwait\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let out = run_bounded_git(
            &git_bin,
            &["rev-list"],
            tmp.path(),
            b"",
            Instant::now() + Duration::from_millis(100),
        );
        assert!(
            out.is_ok(),
            "a child that exited successfully must not be reported as a timeout even if the watchdog fired: {out:?}"
        );
    }

    /// #174 (F3, vetted by execution): a child that IGNORES SIGTERM is still reaped
    /// via the watchdog's SIGKILL escalation, so it cannot pin the walk thread or its
    /// permit. The fake traps SIGTERM and keeps sleeping; run_bounded_git must still
    /// return (via SIGKILL at the grace step) with a timeout error and the group must
    /// be gone. (A truly uninterruptible D-state child, which no signal can reap, is
    /// the documented residual this teardown, like the async twin, cannot cover.)
    #[cfg(unix)]
    #[test]
    fn run_bounded_git_reaps_a_sigterm_ignoring_child_via_sigkill() {
        use std::time::{Duration, Instant};
        let tmp = TempDir::new().unwrap();
        let body = "#!/bin/sh\ntrap '' TERM\necho $$ > pid\nwhile true; do sleep 1; done\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let (tx, rx) = std::sync::mpsc::channel();
        let path = tmp.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(run_bounded_git(
                &git_bin,
                &["rev-list"],
                &path,
                b"",
                Instant::now() + Duration::from_millis(100),
            ));
        });
        let out = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("run_bounded_git must return via SIGKILL even for a SIGTERM-ignoring child");
        assert!(
            out.is_err(),
            "a SIGTERM-ignoring child killed by SIGKILL is a timeout, not a success: {out:?}"
        );
        let pid: i32 = std::fs::read_to_string(tmp.path().join("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut gone = false;
        for _ in 0..300 {
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            gone,
            "the SIGTERM-ignoring child (pid {pid}) must be reaped via SIGKILL, not left running"
        );
    }

    /// #174 finding 3 (jatmn/CodeRabbit): a group MEMBER that ignores SIGTERM must
    /// still be SIGKILLed even when the group LEADER exits cleanly on SIGTERM. The
    /// leader traps SIGTERM to exit 0, but first spawns a descendant (`sh -c`, so its
    /// `$$` is its OWN pid — a `( )` subshell's `$$` is the parent's) that ignores
    /// SIGTERM and closes its inherited stdout/stderr. When the watchdog SIGTERMs the
    /// group, the leader exits, its stdout closes, the main drain unblocks, and the
    /// leader is reaped — the exact window a `reaped`-gated watchdog stands down in,
    /// before escalating to SIGKILL. The descendant must be dead when run_bounded_git
    /// returns; a teardown that stands down on leader-reap leaves it running (RED).
    #[cfg(unix)]
    #[test]
    fn run_bounded_git_sigkills_a_sigterm_ignoring_descendant_after_leader_exits() {
        use std::time::{Duration, Instant};
        let tmp = TempDir::new().unwrap();
        // Both loops are bounded (~30s) so a broken teardown cannot leak a permanent
        // orphan or wedge the suite; the assertion fires well before then.
        let body = "#!/bin/sh\n\
case \"$1\" in\n\
  rev-list)\n\
    sh -c 'trap \"\" TERM; echo $$ > desc.pid; exec 1>&- 2>&-; i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done' &\n\
    trap 'exit 0' TERM\n\
    i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done ;;\n\
  *) : ;;\n\
esac\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let (tx, rx) = std::sync::mpsc::channel();
        let path = tmp.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(run_bounded_git(
                &git_bin,
                &["rev-list"],
                &path,
                b"",
                Instant::now() + Duration::from_millis(100),
            ));
        });
        let _ = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("run_bounded_git must return within the watchdog budget");

        // Wait for the descendant to record its OWN pid, then assert it is gone.
        let desc_pid_path = tmp.path().join("desc.pid");
        let mut desc: Option<i32> = None;
        for _ in 0..200 {
            if let Some(p) = std::fs::read_to_string(&desc_pid_path)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                desc = Some(p);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let desc = desc.expect("the fake leader must have spawned and recorded a descendant");
        let mut gone = false;
        for _ in 0..300 {
            if unsafe { libc::kill(desc, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Kill it regardless so a RED run leaks no orphan.
        unsafe { libc::kill(desc, libc::SIGKILL) };
        assert!(
            gone,
            "a SIGTERM-ignoring descendant (pid {desc}) must be SIGKILLed even after the leader exits cleanly, not orphaned"
        );
    }

    /// #174 U1 (P1-a, RED-before/GREEN-after): the group LEADER closes its own
    /// stdout/stderr BEFORE the deadline and then keeps running. On the pre-fix code
    /// the stdout drain returns EOF early, `done_tx.send` stands the watchdog down
    /// before it ever fires (`recv` gets `Ok` -> `false`, no kill), and `child.wait()`
    /// then blocks on the still-alive leader — pinning the walk thread and its read/
    /// write permit past the deadline, bypassing GITLAWB_GIT_SERVICE_TIMEOUT_SECS.
    /// This is distinct from the descendant case above: there the leader sleeps until
    /// the deadline so the watchdog DOES time out; here the drain-EOF races ahead of
    /// the deadline. The fix keeps the watchdog armed until the child is actually
    /// reaped, so the deadline SIGTERM still fires and the call returns within budget.
    /// A pre-fix build blocks on `child.wait()` past the recv budget (RED).
    #[cfg(unix)]
    #[test]
    fn run_bounded_git_reaps_a_leader_that_closes_stdout_then_hangs() {
        use std::time::{Duration, Instant};
        let tmp = TempDir::new().unwrap();
        // rev-list records its (leader) pid, closes stdout+stderr so the drain EOFs
        // immediately, then sleeps without trapping TERM. `sleep 30` bounds the worst
        // case so a RED run cannot wedge the suite; the recv budget fires first.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-list) echo $$ > leader.pid; exec 1>&- 2>&-; sleep 30 ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let (tx, rx) = std::sync::mpsc::channel();
        let path = tmp.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(run_bounded_git(
                &git_bin,
                &["rev-list"],
                &path,
                b"",
                Instant::now() + Duration::from_millis(100),
            ));
        });
        let out = rx.recv_timeout(Duration::from_secs(10)).expect(
            "run_bounded_git must return within the watchdog budget when the leader closes stdout then hangs, not block on child.wait()",
        );
        assert!(
            out.is_err(),
            "a leader killed at the deadline (no TERM trap) is a timeout, not a success: {out:?}"
        );
        let pid: i32 = std::fs::read_to_string(tmp.path().join("leader.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut gone = false;
        for _ in 0..300 {
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // Kill it regardless so a RED run leaks no orphan.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        assert!(
            gone,
            "the hung leader (pid {pid}) must be killed and reaped at the deadline, not left running"
        );
    }

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

    /// #173 (jatmn round 8, F4 — load-bearing): a repo with enough annotated tags that
    /// one `cat-file --batch` round fills BOTH pipes (stdin > 64 KiB of oids while the
    /// child blocks on a full stdout) must not deadlock. The old order wrote the whole
    /// round to stdin before draining stdout and hung indefinitely, stranding a blocking-
    /// pool thread; `run_bounded_git`'s concurrent writer/drain completes. Driven with a
    /// completion timeout: GREEN finishes in well under a second, RED (old order) hangs
    /// and the recv_timeout fires. ~3000 tags is well past the ~2030-oid deadlock
    /// threshold (41 bytes/oid, 64 KiB pipes) and under MAX_TAG_OBJECTS (8192).
    /// Bulk-created via one fast-import stream so the fixture cost is one git process,
    /// not 3000 `git tag -a` spawns.
    #[test]
    fn walk_tag_chain_large_batch_does_not_deadlock() {
        use std::io::Write;
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
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("f.txt"), b"x\n").unwrap();
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "init"], &work);
        let head = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        // Bulk-create ~3000 annotated tags via one fast-import stream.
        const N: usize = 3000;
        let mut stream = String::new();
        for i in 0..N {
            let msg = format!("annotated tag {i}\n");
            stream.push_str(&format!("tag t{i}\n"));
            stream.push_str(&format!("from {head}\n"));
            stream.push_str("tagger t <t@t> 1700000000 +0000\n");
            stream.push_str(&format!("data {}\n", msg.len()));
            stream.push_str(&msg);
        }
        let mut fi = Command::new("git")
            .args(["fast-import", "--quiet"])
            .current_dir(&work)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        fi.stdin
            .take()
            .unwrap()
            .write_all(stream.as_bytes())
            .unwrap();
        assert!(fi.wait().unwrap().success(), "fast-import failed");

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

        // Drive the walk on a worker thread with a completion timeout. The old
        // write-all-before-drain order hangs here; the fix completes near-instantly.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(reachable_commit_tag_oids(&bare).map(|s| s.len()));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(20)) {
            Ok(Ok(n)) => assert!(
                n >= N,
                "the walk must resolve every annotated tag object (got {n}, expected >= {N})"
            ),
            Ok(Err(e)) => panic!("walk errored: {e}"),
            Err(_) => panic!("walk_tag_chain deadlocked on a large tag batch (F4 regression)"),
        }
    }

    /// #173 review (finding 3): an annotated tag reachable ONLY through a tag-valued
    /// detached HEAD (raw HEAD naming a tag object, with no ref at that tag) must still
    /// enter `reachable_commit_tag_oids`. `rev-list --all HEAD` peels such a HEAD to its
    /// commit and `for-each-ref` has no tag row, so without a HEAD tag-seed the tag
    /// OBJECT is omitted and its pinned CID would 404 for an authorized reader. RED
    /// before the HEAD tag-seed (the tag oid is absent); GREEN after.
    #[test]
    fn reachable_commit_tag_oids_includes_tag_valued_detached_head() {
        use std::io::Write;
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let run = |args: &[&str], dir: &Path| -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("a.txt"), b"hi\n").unwrap();
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        run(&["add", "."], &work);
        run(&["commit", "-qm", "seed"], &work);
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
        let commit = run(&["rev-parse", "HEAD"], &bare);

        // An annotated tag OBJECT in the bare ODB, with NO ref pointing at it.
        let tag_body = format!(
            "object {commit}\ntype commit\ntag htag\ntagger t <t@t> 0 +0000\n\nHEAD-only tag\n"
        );
        let tag_oid = {
            let mut child = Command::new("git")
                .args(["hash-object", "-t", "tag", "-w", "--stdin"])
                .current_dir(&bare)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(tag_body.as_bytes())
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success());
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(run(&["cat-file", "-t", &tag_oid], &bare), "tag");
        // Raw-write HEAD directly to the tag object (the only way this state arises;
        // update-ref / checkout both refuse a non-commit HEAD).
        std::fs::write(bare.join("HEAD"), format!("{tag_oid}\n")).unwrap();

        let set = reachable_commit_tag_oids(&bare).unwrap();
        assert!(
            set.contains(&tag_oid),
            "a tag reachable only via a tag-valued detached HEAD must be in the reachable set"
        );
        assert!(
            set.contains(&commit),
            "the commit the HEAD tag peels to stays reachable (no regression)"
        );
    }

    /// #173: `reachable_commit_tag_oids` on an empty repo (unborn HEAD) must return an
    /// empty set, not error — exercising the `rev-parse HEAD` fail branch of the
    /// detached-HEAD tag seed (there is simply no HEAD to seed).
    #[test]
    fn reachable_commit_tag_oids_handles_unborn_head() {
        let td = TempDir::new().unwrap();
        let bare = td.path().join("empty.git");
        let ok = Command::new("git")
            .args(["init", "-q", "--bare", bare.to_str().unwrap()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "git init --bare failed");
        let set = reachable_commit_tag_oids(&bare).unwrap();
        assert!(
            set.is_empty(),
            "an empty repo (unborn HEAD) yields an empty reachable set with no error"
        );
    }

    #[test]
    fn object_paths_emits_trees_and_blob_paths_is_the_blob_slice() {
        let (_td, bare, secret_oid, public_oid) = fixture();
        let deadline = Instant::now() + WALK_TIMEOUT;
        // The lenient enumeration; on this clean fixture it matches the strict one.
        let commits = reachable_commit_oids(&bare, "git", deadline).unwrap();
        let objs = object_paths(&bare, "git", &commits, deadline).unwrap();

        // Blob records survive the `-rzt` change, at their paths (unchanged).
        assert!(objs.contains(&(secret_oid.clone(), "/secret/b.txt".into(), "blob".into())));
        assert!(objs.contains(&(public_oid.clone(), "/public/a.txt".into(), "blob".into())));

        // The #135 addition: subtree tree objects at their directory paths.
        assert!(
            objs.iter().any(|(_, p, k)| k == "tree" && p == "/secret"),
            "the /secret subtree tree must be emitted at its dir path"
        );
        assert!(
            objs.iter().any(|(_, p, k)| k == "tree" && p == "/public"),
            "the /public subtree tree must be emitted at its dir path"
        );

        // blob_paths must equal the blob slice of object_paths exactly — compared as
        // SETS (both walks dedup via HashSet; the collected order is nondeterministic).
        let bp: HashSet<(String, String)> = blob_paths(&bare, "git", WALK_TIMEOUT)
            .unwrap()
            .into_iter()
            .collect();
        let bp_from_obj: HashSet<(String, String)> = objs
            .iter()
            .filter(|(_, _, k)| k == "blob")
            .map(|(o, p, _)| (o.clone(), p.clone()))
            .collect();
        assert_eq!(
            bp, bp_from_obj,
            "blob_paths output must be byte-identical to object_paths' blob slice"
        );
    }

    #[test]
    fn allowed_tree_set_gates_withheld_subtree_tree() {
        let (_td, bare, _s, _p) = fixture();
        let oid = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&bare)
                .output()
                .unwrap();
            assert!(out.status.success(), "rev-parse {rev}");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let secret_tree = oid("HEAD:secret");
        let public_tree = oid("HEAD:public");
        let root_tree = oid("HEAD^{tree}");
        let reader = "did:key:z6MkReader";
        let rules = [rule("/secret/**", &[reader])];

        // anon: the withheld /secret tree is excluded; root ("/") and /public are in.
        let anon = allowed_tree_set_for_caller(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            !anon.contains(&secret_tree),
            "withheld /secret subtree tree excluded for anon"
        );
        assert!(anon.contains(&root_tree), "root tree included (path /)");
        assert!(anon.contains(&public_tree), "/public subtree tree included");

        // listed reader: sees the /secret tree (caller-aware, not a blanket deny).
        let rd = allowed_tree_set_for_caller(&bare, &rules, true, OWNER, Some(reader)).unwrap();
        assert!(
            rd.contains(&secret_tree),
            "listed reader sees the /secret tree"
        );

        // owner: sees every reachable tree.
        let ow = allowed_tree_set_for_caller(&bare, &rules, true, OWNER, Some(OWNER)).unwrap();
        assert!(
            ow.contains(&secret_tree) && ow.contains(&public_tree) && ow.contains(&root_tree),
            "owner sees all reachable trees"
        );
    }

    #[test]
    fn allowed_tree_set_excludes_dangling_tree() {
        use std::io::Write;
        let (_td, bare, secret_oid, _p) = fixture();
        // A DANGLING tree: written to the ODB but referenced by no commit. Uses a
        // UNIQUE entry name so its oid is content-distinct from every reachable tree
        // (a content-identical tree would dedup to a reachable oid — that is T2, not
        // danglingness). The reachable-only walk never enumerates it -> fail closed.
        let mut child = Command::new("git")
            .args(["mktree"])
            .current_dir(&bare)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.as_mut().unwrap(),
            "100644 blob {secret_oid}\tdangling-only-unreferenced.txt"
        )
        .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git mktree");
        let dangling = String::from_utf8_lossy(&out.stdout).trim().to_string();

        let rules = [rule("/secret/**", &[])];
        for caller in [None, Some(OWNER)] {
            let set = allowed_tree_set_for_caller(&bare, &rules, true, OWNER, caller).unwrap();
            assert!(
                !set.contains(&dangling),
                "dangling tree must never be in the reachable allowed-set (caller={caller:?})"
            );
        }
    }

    #[test]
    fn allowed_tree_set_includes_tree_shared_across_allowed_and_denied_paths() {
        // T2 (content-dedup): the SAME tree oid reachable at both an allowed and a
        // withheld path is INCLUDED for anon (allowed-wins) — its structure is
        // visible to the caller at the allowed path. Mirrors the blob analog
        // `same_blob_at_allowed_and_denied_path_is_not_withheld`.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        std::fs::create_dir_all(work.join("pub/sub")).unwrap();
        std::fs::create_dir_all(work.join("sec/sub")).unwrap();
        std::fs::write(work.join("pub/sub/f.txt"), b"same bytes\n").unwrap();
        std::fs::write(work.join("sec/sub/f.txt"), b"same bytes\n").unwrap();
        let run = |args: &[&str]| {
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
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        run(&["add", "."]);
        run(&["commit", "-qm", "seed"]);
        let oid = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let pub_sub = oid("HEAD:pub/sub");
        let sec_sub = oid("HEAD:sec/sub");
        assert_eq!(pub_sub, sec_sub, "identical content dedups to one tree oid");

        // Withhold /sec from anon; the shared oid is still reachable at /pub/sub.
        let rules = [rule("/sec/**", &[])];
        let anon = allowed_tree_set_for_caller(&work, &rules, true, OWNER, None).unwrap();
        assert!(
            anon.contains(&pub_sub),
            "a tree reachable at an allowed path is included even when also at a withheld path"
        );
    }

    #[test]
    fn allowed_tree_set_includes_root_trees_of_all_reachable_commits() {
        // The batched root-tree pass (root_tree_pairs) must return EVERY reachable
        // commit's root tree, not just HEAD's — two commits with distinct root trees
        // both land in the set. Guards the git-log-over-N-commits root derivation.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let run = |args: &[&str]| {
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
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        let oid = |rev: &str| {
            let out = Command::new("git")
                .args(["rev-parse", rev])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        std::fs::write(work.join("a.txt"), b"one\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-qm", "c1"]);
        let root1 = oid("HEAD^{tree}");
        std::fs::write(work.join("b.txt"), b"two\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-qm", "c2"]);
        let root2 = oid("HEAD^{tree}");
        assert_ne!(root1, root2, "the two commits have distinct root trees");

        // Public repo, no rules: every reachable tree is allowed for anon.
        let set = allowed_tree_set_for_caller(&work, &[], true, OWNER, None).unwrap();
        assert!(
            set.contains(&root1) && set.contains(&root2),
            "root trees of BOTH reachable commits are in the set (batched root pass)"
        );
    }

    #[test]
    fn root_tree_pairs_returns_every_root_tree_at_scale() {
        // Parity + liveness at scale for root_tree_pairs (#173 P2): feed every
        // reachable commit oid to `git log --format=%T --stdin` and collect each
        // commit's root tree. With N commits that is ~N*41 bytes of oids in and
        // ~N*41 bytes of %T out — past the ~64 KiB pipe buffer in both directions —
        // so this exercises the large-bidirectional-IO path the 2-commit test above
        // cannot, and asserts parity: every distinct root tree comes back.
        //
        // NOTE: this is NOT a deadlock guard. `git log --stdin` reads its whole
        // revision list to EOF before emitting any %T, so the naive "write all of
        // stdin, then drain stdout" form does not deadlock at any scale for this
        // invocation. `run_bounded_git`'s concurrent writer/drain is cheap defensive
        // isolation, not load-bearing, and this test does not claim otherwise. The
        // 30s watchdog is a general liveness bound so a future regression that
        // genuinely hangs fails fast here rather than stalling the suite.
        const N: usize = 2500;
        let td = TempDir::new().unwrap();
        let bare = td.path().join("many.git");
        assert!(Command::new("git")
            .args(["init", "-q", "--bare", bare.to_str().unwrap()])
            .status()
            .unwrap()
            .success());

        // fast-import a linear chain of N commits, each adding a distinct file so
        // every root tree is distinct (dedup cannot shrink the output). One
        // subprocess, ~1s — far cheaper than N `git commit` spawns.
        let mut stream = String::new();
        for i in 0..N {
            let (b, cm) = (2 * i + 1, 2 * i + 2);
            let content = format!("v{i}");
            let msg = format!("c{i}");
            stream.push_str(&format!(
                "blob\nmark :{b}\ndata {}\n{content}\n",
                content.len()
            ));
            stream.push_str(&format!(
                "commit refs/heads/main\nmark :{cm}\ncommitter t <t@t> 0 +0000\ndata {}\n{msg}\n",
                msg.len()
            ));
            if i > 0 {
                stream.push_str(&format!("from :{}\n", 2 * (i - 1) + 2));
            }
            stream.push_str(&format!("M 100644 :{b} f{i}\n\n"));
        }
        let mut fi = Command::new("git")
            .args(["fast-import", "--quiet"])
            .current_dir(&bare)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            fi.stdin
                .take()
                .unwrap()
                .write_all(stream.as_bytes())
                .unwrap();
        }
        assert!(fi.wait().unwrap().success(), "fast-import failed");

        let commits = reachable_commit_oids(&bare, "git", Instant::now() + WALK_TIMEOUT).unwrap();
        assert_eq!(commits.len(), N, "all {N} commits reachable");

        // Call root_tree_pairs directly (private, same module) under a liveness
        // watchdog, then assert it returned every distinct root tree.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                root_tree_pairs(&bare, "git", &commits, Instant::now() + WALK_TIMEOUT)
                    .map(|s| s.len()),
            );
        });
        match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(Ok(len)) => assert_eq!(len, N, "every distinct root tree returned"),
            Ok(Err(e)) => panic!("root_tree_pairs errored: {e}"),
            Err(_) => panic!("root_tree_pairs did not return within 30s"),
        }
    }

    /// #173 (jatmn tag fan-out): the batched `git cat-file --batch` tag walk must
    /// return the SAME reachable set as the old per-tag `cat-file tag` loop — every
    /// commit, the outer tag object, AND the inner tag object of a tag-of-a-tag chain
    /// (the inner tag is reachable but is not itself a ref tip, so it is only found by
    /// peeling the outer tag's target). Behavior-preservation proof for the rewrite.
    #[test]
    fn reachable_commit_tag_oids_includes_nested_tag_objects() {
        let (_td, bare, _secret, _public) = fixture();
        let run = |args: &[&str]| -> String {
            let out = Command::new("git")
                .args(args)
                .current_dir(&bare)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        run(&["config", "user.email", "t@t"]);
        run(&["config", "user.name", "t"]);
        // v1 -> commit, v2 -> v1 (tag-of-a-tag), plus a couple of sibling tags so the
        // round batches more than one oid. Capture v1's oid, then DELETE the v1 ref so
        // the inner tag object survives in the ODB but is NOT a ref tip: it is then
        // reachable ONLY by peeling v2's target chain. That makes the peel load-bearing
        // (breaking the inner-tag enqueue drops v1 from the set), unlike leaving v1 as
        // its own ref where `for-each-ref` would seed it directly.
        run(&["tag", "-a", "-m", "inner", "v1", "HEAD"]);
        run(&["tag", "-a", "-m", "outer", "v2", "v1"]);
        run(&["tag", "-a", "-m", "s1", "s1", "HEAD"]);
        run(&["tag", "-a", "-m", "s2", "s2", "HEAD"]);
        let commit = run(&["rev-parse", "HEAD"]);
        let v1 = run(&["rev-parse", "v1"]);
        let v2 = run(&["rev-parse", "v2"]);
        let s1 = run(&["rev-parse", "s1"]);
        let s2 = run(&["rev-parse", "s2"]);
        run(&["tag", "-d", "v1"]);

        let set = reachable_commit_tag_oids(&bare).unwrap();
        assert!(set.contains(&commit), "the commit must be reachable");
        assert!(
            set.contains(&v2),
            "the outer tag object (ref tip) must be present"
        );
        assert!(
            set.contains(&v1),
            "the INNER tag object of a tag-of-a-tag must be present (peeled from v2, no ref)"
        );
        assert!(set.contains(&s1), "sibling tag s1 must be present");
        assert!(set.contains(&s2), "sibling tag s2 must be present");
    }

    /// #173 (jatmn tag fan-out): the object bound is load-bearing. A repo whose tag
    /// count exceeds the bound must FAIL CLOSED (Err), not return a truncated set that
    /// would under-withhold a still-reachable tag. Drives `walk_tag_chain` with a tiny
    /// injected bound (the public fn uses the real `MAX_TAG_OBJECTS`); with the bound
    /// check removed this would collect all tags and return Ok.
    #[test]
    fn walk_tag_chain_fails_closed_over_object_bound() {
        let (_td, bare, _secret, _public) = fixture();
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
        let mut seeds = Vec::new();
        for n in 0..5 {
            let name = format!("t{n}");
            run(&["tag", "-a", "-m", &name, &name, "HEAD"]);
            let oid = Command::new("git")
                .args(["rev-parse", &name])
                .current_dir(&bare)
                .output()
                .unwrap();
            seeds.push(String::from_utf8_lossy(&oid.stdout).trim().to_string());
        }

        // Within a generous bound: the walk succeeds and collects the tags.
        let mut ok_set = HashSet::new();
        walk_tag_chain(
            &bare,
            "git",
            seeds.clone(),
            &mut ok_set,
            8192,
            Instant::now() + WALK_TIMEOUT,
        )
        .unwrap();
        assert!(
            seeds.iter().all(|s| ok_set.contains(s)),
            "all 5 tags collected under a generous bound"
        );

        // Under a bound of 2 with 5 tags: fail closed (Err), not a partial set.
        let mut small_set = HashSet::new();
        let result = walk_tag_chain(
            &bare,
            "git",
            seeds,
            &mut small_set,
            2,
            Instant::now() + WALK_TIMEOUT,
        );
        assert!(
            result.is_err(),
            "a tag count exceeding the object bound must fail closed (Err), not truncate"
        );
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

        let all_blobs = crate::git::push_delta::all_blob_oids(
            &work,
            "git",
            std::time::Instant::now() + std::time::Duration::from_secs(600),
        )
        .unwrap();
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
