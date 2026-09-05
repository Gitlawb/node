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

/// A (oid, path) pair for a git object reachable in the repo walk.
type ObjectPath = (String, String);

/// Four sets derived from one walk: allowed blobs, allowed trees, all blob OIDs,
/// all tree OIDs.
type BlobTreeSets = (
    HashSet<String>,
    HashSet<String>,
    HashSet<String>,
    HashSet<String>,
);

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
pub(crate) fn run_bounded_git_raw(
    git_bin: &str,
    args: &[&str],
    repo_path: &Path,
    stdin_bytes: &[u8],
    deadline: Instant,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
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
    Ok((status, out, err))
}

/// Bounded git returning only stdout, `bail!`ing on any nonzero exit. The thin
/// wrapper the walk callers use. Probes that must distinguish exit classes —
/// `git cat-file` absence vs an object-store access failure — call
/// [`run_bounded_git_raw`] and classify the status/stderr themselves.
#[cfg(unix)]
pub(crate) fn run_bounded_git(
    git_bin: &str,
    args: &[&str],
    repo_path: &Path,
    stdin_bytes: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    let label = args.first().copied().unwrap_or("git");
    let (status, out, err) = run_bounded_git_raw(git_bin, args, repo_path, stdin_bytes, deadline)?;
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
pub(crate) fn run_bounded_git_raw(
    git_bin: &str,
    args: &[&str],
    repo_path: &Path,
    stdin_bytes: &[u8],
    deadline: Instant,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
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
    Ok((status, out, err))
}

/// Non-Unix thin wrapper matching the Unix [`run_bounded_git`] semantics.
#[cfg(not(unix))]
pub(crate) fn run_bounded_git(
    git_bin: &str,
    args: &[&str],
    repo_path: &Path,
    stdin_bytes: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>> {
    let label = args.first().copied().unwrap_or("git");
    let (status, out, err) = run_bounded_git_raw(git_bin, args, repo_path, stdin_bytes, deadline)?;
    if !status.success() {
        anyhow::bail!("git {label} failed: {}", String::from_utf8_lossy(&err));
    }
    Ok(out)
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
/// Fails closed: if commit enumeration, the non-commit ref walk, or any tree walk
/// fails, returns an error so the caller aborts the serve/pin rather than producing
/// a partial (under-withheld) set. Two phases:
///   1. `git rev-list --all` over commits + per-commit `ls-tree -rz` — captures every
///      commit-reachable blob with its path.
///   2. `git for-each-ref` over non-commit ref targets — captures every direct
///      ref-to-blob / ref-to-tree with an EMPTY path (the deny-side caller
///      `withheld_from_pairs` withholds empty-path entries by OID).
///
/// Phase 2 closes the round-3 fail-open leak where a blob only reachable via an
/// annotated tag was served but not withheld.
///
/// P1 (reviewer round 9): a ref whose target is a TREE (direct,
/// peeled from an annotated tag, or reached through a recursive
/// tag-peel) leaves the tree's CHILDREN invisible to phase 2. The
/// tree's blob children are what `git rev-list --objects --all`
/// serves (and what the deny-side `rev_list_keep` enumerates), so
/// without this walk the served set and the withheld set disagree:
/// a blob only reachable as a child of a `mktree` tree published
/// as a tag is served, not withheld. `walk_tree_oids_bounded` is
/// the bounded recursive `ls-tree` walker that closes this leak;
/// every reachable blob and tree OID is inserted with an empty
/// path, and `withheld_from_pairs` withholds by OID.
const MAX_TREE_WALK_DEPTH: usize = 64;
/// Round 10 P2: cap on `ls-tree` child-process invocations across a
/// single walk. The previous wall-clock bound could not bound a
/// wide shallow tree that spawns one `ls-tree` per subtree well
/// inside the depth cap; expiry was the only stop. With
/// `MAX_TREE_WALK_INVOCATIONS` the walker fails closed at a
/// structural cost ceiling, not at the scheduler's mercy.
const MAX_TREE_WALK_INVOCATIONS: usize = 50_000;

/// Walk a tree OID recursively via bounded `git ls-tree -z` and
/// insert every reachable blob and tree OID into `out` with an
/// empty path. The empty path is the deny-side convention for
/// "withhold this OID regardless of path" (see
/// `withheld_from_pairs`); the served set never sees a tree
/// tip's child blobs, so the empty-path OID is the only correct
/// shape for the phase-2 catch-all.
///
/// Bounded by `deadline`, `MAX_TREE_WALK_DEPTH`, and
/// `MAX_TREE_WALK_INVOCATIONS` so a malicious or malformed tree
/// cannot exhaust the walk. The invocation cap closes the
/// "wide shallow tree spawns one ls-tree per subtree" hole the
/// previous wall-clock-only bound left (round 10 P2).
fn walk_tree_oids_bounded(
    repo_path: &Path,
    git_bin: &str,
    root_tree_oid: &str,
    deadline: Instant,
    blobs: &mut HashSet<(String, String)>,
    trees: &mut HashSet<(String, String)>,
) -> Result<()> {
    // Round 10 P2: memo of already-walked tree OIDs so a tree
    // reachable from N ref tips is walked once, not N times.
    // Without this, a ref with two tags pointing at the same
    // tree paid for the ls-tree child process twice.
    let mut walked: HashSet<String> = HashSet::new();
    // Round 10 P2: a structural invocation cap. The wall-clock
    // deadline cannot bound a wide shallow tree that spawns one
    // `ls-tree` per subtree well inside the depth cap; this
    // counter is the cost ceiling that actually closes the hole.
    let mut invocations: usize = 0;
    walk_tree_oids_inner(
        repo_path,
        git_bin,
        root_tree_oid,
        0,
        deadline,
        blobs,
        trees,
        &mut walked,
        &mut invocations,
    )
}

// Round 10 P2 threaded the `walked` memo and the `invocations`
// counter through the recursion, taking the signature from 6 to
// 8 args. A `WalkState` struct would be cleaner; for one
// recursive call site the `allow` is the smaller change.
#[allow(clippy::too_many_arguments)]
fn walk_tree_oids_inner(
    repo_path: &Path,
    git_bin: &str,
    tree_oid: &str,
    depth: usize,
    deadline: Instant,
    blobs: &mut HashSet<(String, String)>,
    trees: &mut HashSet<(String, String)>,
    walked: &mut HashSet<String>,
    invocations: &mut usize,
) -> Result<()> {
    if depth > MAX_TREE_WALK_DEPTH {
        anyhow::bail!(
            "tree walk exceeded {MAX_TREE_WALK_DEPTH} levels (rooted at {tree_oid}); \
             refusing to recurse into a malicious or malformed tree chain"
        );
    }
    // Memo: a tree reachable from multiple ref tips or from
    // multiple parents (rare but legal in git) is walked once.
    if !walked.insert(tree_oid.to_string()) {
        return Ok(());
    }
    if *invocations >= MAX_TREE_WALK_INVOCATIONS {
        anyhow::bail!(
            "tree walk exceeded {MAX_TREE_WALK_INVOCATIONS} ls-tree invocations \
             (rooted at {tree_oid}); refusing to recurse into a wide or \
             densely-referenced tree graph"
        );
    }
    *invocations += 1;
    // The tree itself enters the withheld set keyed on OID. The
    // filtered pack serves trees by OID, so omitting the tree
    // would let a withheld subtree leak its parent.
    trees.insert((tree_oid.to_string(), String::new()));
    let ls = run_bounded_git(
        git_bin,
        &["ls-tree", "-z", tree_oid],
        repo_path,
        b"",
        deadline,
    )?;
    let stdout = match std::str::from_utf8(&ls) {
        Ok(s) => s,
        Err(_) => {
            // Non-UTF-8: fail closed. A lossy decode would let an
            // invalid-byte filename in a denied path fall through
            // (U+FFFD vs the rule's bytes), the same under-withhold
            // class phase 1 closes at :526. The child OIDs of this
            // tree would otherwise stay out of the withheld set while
            // `rev-list --objects --all` still serves them to an
            // anonymous clone. Bail to keep the walk and the
            // phase-1 path on the same classification.
            anyhow::bail!(
                "git ls-tree -z {tree_oid} returned a non-UTF-8 path; \
                 refusing to produce a partial (under-withheld) set"
            );
        }
    };
    for record in stdout.split('\0') {
        if record.is_empty() {
            continue;
        }
        // P1 (reviewer round 9): same byte-preservation rule as
        // `tree_structurally_safe` — `record` is NOT trimmed, so a
        // directory named `secret ` (trailing space) carries the
        // whitespace into the parse. Here the path portion is
        // unused (we walk by OID) but the kind+oid parsing is
        // sensitive to the meta+filename split being intact.
        let Some((meta, _filename)) = record.split_once('\t') else {
            continue;
        };
        let mut parts = meta.split_whitespace();
        let _mode = parts.next();
        let Some(kind) = parts.next() else { continue };
        let Some(child_oid) = parts.next() else {
            continue;
        };
        match kind {
            "blob" => {
                blobs.insert((child_oid.to_string(), String::new()));
            }
            "tree" => {
                walk_tree_oids_inner(
                    repo_path,
                    git_bin,
                    child_oid,
                    depth + 1,
                    deadline,
                    blobs,
                    trees,
                    walked,
                    invocations,
                )?;
            }
            _ => {
                // Submodule commits (kind="commit") are covered
                // by the rev-list walk above; their blobs are
                // reachable through the commit-tip path.
            }
        }
    }
    Ok(())
}
fn blob_paths(repo_path: &Path, git_bin: &str, timeout: Duration) -> Result<Vec<(String, String)>> {
    // One deadline spans the whole walk (the HEAD probe, rev-list, every
    // per-commit ls-tree, and the for-each-ref phase 2), so a slow or hung walk
    // is bounded as a unit rather than granting each git child a fresh timeout.
    //
    // #218 review round 2 (non-commit ref acceptance): the previous code
    // called `assert_all_refs_are_commits` here, which bailed on
    // any ref that didn't peel to a commit (tag-of-tree,
    // tag-of-blob). The encrypted recovery path also needs to
    // tolerate non-commit refs, for the same reason `all_object_paths`
    // does: `git rev-list --all` already silently skips them, and
    // the recovery path's classification is over the
    // commit-reachable object set.
    let deadline = Instant::now() + timeout;

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

    // Phase 2: enumerate non-commit ref targets through the shared
    // extractor below (typed blob/tree sets; tag objects ignored here —
    // `blob_paths` feeds the deny side, which classifies by OID).
    let nc = non_commit_ref_sets(repo_path, git_bin, deadline)?;
    out.extend(nc.blobs);
    out.extend(nc.trees);
    Ok(out.into_iter().collect())
}

/// Non-commit ref targets, enumerated with their types plus the tag
/// objects that name them. `git rev-list --all` SILENTLY SKIPS refs
/// whose tip is not a commit (annotated tag-of-blob, tag-of-tree, raw
/// blobref) — a real Git shape that `git push` allows through
/// `receive-pack`. The deny-set caller (`smart_http.rs:611-635`
/// `rev_list_keep`) enumerates with `git rev-list --objects --all`,
/// which DOES include those non-commit targets, so without this phase
/// the served set and the withheld set disagree: a blob only reachable
/// via an annotated tag is served, not withheld. Each
/// non-commit-reachable blob/tree enters with an EMPTY path — the
/// deny-side caller (`withheld_from_pairs`, see below) treats
/// empty paths as "withhold this exact OID", which is exactly
/// the right policy for a tag-of-blob we cannot path-match.
///
/// A similar `git for-each-ref` invocation lives at
/// `reachable_commit_tag_oids_bounded` (for the tag-chain seed),
/// so this is reusing a primitive the file already exercises.
///
/// #218 review round 8 P1: the referent must be PEELED. `%(objecttype)`
/// reports the type of the ref's OWN object, which for an annotated tag
/// is `tag` — so a format of only `%(objectname) %(objecttype)` never
/// shows the blob/tree the tag wraps, and a blob reachable ONLY through
/// an annotated tag escaped the withheld set while `rev_list_keep`
/// (`git rev-list --objects --all`, which DOES peel tags) still served
/// it. `%(*objectname) %(*objecttype)` are for-each-ref's peeled atoms:
/// empty for a ref whose tip is not a tag, one-level-peeled for a tag.
///
/// Peel depth: measured against git 2.50, the `*` atoms peel the WHOLE
/// chain — a tag-of-a-tag-of-a-tag-of-a-blob reports the blob, not the
/// inner tag — so the `tag` peeled-type arm below does not fire on stock
/// git today. P3 (reviewer round 9): the `tag` arm IS live on git
/// 2.43 (the round's own fixture reports a peeled type of `tag`
/// for nested tags), so each nested tag costs two extra git
/// children (`rev-parse ^{}` and `cat-file -t`) with no ceiling on
/// ref count. Both children are bounded by the walk's shared
/// deadline, and both are reached only for a tag whose referent is
/// still a tag — never on the common one-line-per-ref path. The
/// `rev-parse ^{}` is recursive by definition and resolves the
/// full chain in a single call, so a `tag peeled_oid tag` line on
/// git 2.43 peels through every nested tag in one round trip.
///
/// `tag_oids` collects every annotated-tag OBJECT at a ref tip (plus
/// the tip of a nested-tag chain): structural metadata the sweep pins
/// like commits. Deeper inner tag objects are not collected — the
/// serve path still resolves them through `reachable_commit_tag_oids`,
/// and the sweep's windowed enumeration must stay proportional to
/// refs, not chains.
pub(crate) struct NonCommitRefSets {
    pub blobs: HashSet<ObjectPath>,
    pub trees: HashSet<ObjectPath>,
    pub tag_oids: Vec<String>,
}

pub(crate) fn non_commit_ref_sets(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
) -> Result<NonCommitRefSets> {
    let mut blobs: HashSet<ObjectPath> = HashSet::new();
    let mut trees: HashSet<ObjectPath> = HashSet::new();
    let mut tag_oids: Vec<String> = Vec::new();
    let refs_out = run_bounded_git(
        git_bin,
        &[
            "for-each-ref",
            "--format=%(objectname) %(objecttype) %(*objectname) %(*objecttype)",
        ],
        repo_path,
        b"",
        deadline,
    )?;
    let refs_stdout = String::from_utf8_lossy(&refs_out);
    for line in refs_stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Two tokens for a non-tag tip (the peeled atoms expand to
        // empty and are eaten by the trim/split), four for a tag tip.
        // Anything else is a malformed line; fail closed so the caller
        // aborts rather than silently under-withhold.
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (oid, kind, peeled) = match fields.as_slice() {
            [oid, kind] => (*oid, *kind, None),
            [oid, kind, peeled_oid, peeled_kind] => {
                (*oid, *kind, Some((*peeled_oid, *peeled_kind)))
            }
            _ => anyhow::bail!("malformed for-each-ref line: {line:?}"),
        };
        // An annotated tag object at the tip is structural metadata
        // (pinned like a commit by sweep candidates); its referent is
        // classified by the arms below.
        if kind == "tag" {
            tag_oids.push(oid.to_string());
        }
        // Commit tips are already covered by the rev-list walk above.
        // Direct blob tips (lightweight tag of a blob, raw blobref) are
        // inserted as-is.
        if kind == "blob" {
            blobs.insert((oid.to_string(), String::new()));
        }
        // P1 (reviewer round 9): direct TREE tips must walk their
        // children. A bare `mktree` published as a raw ref tip (or
        // a lightweight tag of a tree) leaves the tree's blobs
        // visible to `git rev-list --objects --all` (and therefore
        // to the deny-side `rev_list_keep`) but invisible to phase
        // 2 if phase 2 only inserts the tree OID. Walk it.
        if kind == "tree" {
            walk_tree_oids_bounded(repo_path, git_bin, oid, deadline, &mut blobs, &mut trees)?;
        }
        if let Some((peeled_oid, peeled_kind)) = peeled {
            match peeled_kind {
                // The annotated-tag-of-blob shape: the referent is what
                // `rev-list --objects --all` serves, so it is what must
                // enter the withheld set (round-8 P1).
                "blob" => {
                    blobs.insert((peeled_oid.to_string(), String::new()));
                }
                // P1 (reviewer round 9): annotated-tag-of-tree must
                // walk the tree the same way a direct tree tip does.
                "tree" => {
                    walk_tree_oids_bounded(
                        repo_path, git_bin, peeled_oid, deadline, &mut blobs, &mut trees,
                    )?;
                }
                // A tag peeling to a commit contributes nothing new:
                // `rev-list --all` peels tag chains to their commit and the
                // phase-1 tree walk above already classified its objects.
                "commit" => {}
                // A peeled type of `tag` means this git peeled only one
                // level (see the format comment above; stock git 2.50 peels
                // the whole chain and never lands here, but git 2.43
                // reports a peeled type of `tag` for nested tags, so the
                // arm IS live in production — see the depth bound below).
                // Finish the peel with `^{}`, which is recursive by
                // definition, and type the final referent. Fail closed
                // on either child erroring — an unclassifiable ref target
                // must abort the walk, not silently under-withhold.
                //
                // P3 (reviewer round 9): bound the depth of any further
                // recursion with `MAX_TREE_WALK_DEPTH` so a malformed
                // tag chain cannot blow up the walk. Stock git 2.50
                // peels the whole chain and never lands here for a
                // blob/tree, but the recursive `rev-parse ^{}` already
                // bounds by the walk's shared deadline.
                "tag" => {
                    let full = run_bounded_git(
                        git_bin,
                        &["rev-parse", &format!("{oid}^{{}}")],
                        repo_path,
                        b"",
                        deadline,
                    )?;
                    let full_oid = String::from_utf8_lossy(&full).trim().to_string();
                    let ty_out = run_bounded_git(
                        git_bin,
                        &["cat-file", "-t", &full_oid],
                        repo_path,
                        b"",
                        deadline,
                    )?;
                    let ty = String::from_utf8_lossy(&ty_out).trim().to_string();
                    match ty.as_str() {
                        "blob" => {
                            blobs.insert((full_oid, String::new()));
                        }
                        "tree" => {
                            walk_tree_oids_bounded(
                                repo_path, git_bin, &full_oid, deadline, &mut blobs, &mut trees,
                            )?;
                        }
                        _ => {}
                    }
                }
                other => {
                    anyhow::bail!("for-each-ref peeled {oid} to unexpected object type {other:?}")
                }
            }
        }
    }
    Ok(NonCommitRefSets {
        blobs,
        trees,
        tag_oids,
    })
}

/// All reachable blob and tree OIDs with their paths, derived from one bounded
/// walk. Returns `(blob_paths, tree_paths)` where each is a `Vec<ObjectPath>`.
/// Used to derive both allowed blobs and allowed trees from a single walk, so
/// the two sets are consistent and the walk cost is paid only once.
///
/// #218 (Reviewer-2 P1): the previous phase 1 used `git ls-tree -rz <commit>`,
/// which under `-r` recurses into blobs and never emits tree entries; trees
/// only showed up in the phase-2 catch-all with an empty path, and the
/// fail-closed filter in `allowed_blob_tree_sets_bounded` then denied every
/// tree. The sweep could not repair a single tree, so a non-flat repo's git
/// graph was un-reconstructible from the pinned object set. The fix is
/// `-r -t` (recursive, show trees too): every reachable tree and blob comes
/// back with its directory/file path, so the visibility check has something
/// to gate on. The root tree of each commit is appended separately at path
/// `/`, because `ls-tree` of a commit only enumerates its children. Trees
/// reachable only via a non-commit ref (annotated tag of a tree, notes) still
/// arrive in phase 2 with no path, and the fail-closed filter still denies
/// them — that is the right outcome for objects whose visibility cannot be
/// determined.
/// One page of the repo's commit history in oldest-first topo order:
/// `skip` commits already covered, at most `max_count` more. Output — not
/// traversal — is what the page bounds: rev-list still walks skipped
/// commits internally (CPU only, no allocation), while only the window is
/// materialized and ls-tree'd. A short page (fewer than `max_count`) means
/// the history is fully covered; an empty page on a non-empty repo means
/// the cursor ran past a rewritten history and the caller must reset it.
/// Deterministic for a fixed graph; a force-pushed history may repeat or
/// skip commits across pages, which is safe (absence only ever withholds,
/// never publishes). Oldest-first (not newest-first) so fresh tips extend
/// the uncovered tail instead of hiding behind the cursor.
/// Non-commit refs are silently skipped by rev-list itself, exactly as in
/// the full walk; their targets are enumerated separately by
/// [`non_commit_ref_sets`].
///
/// Ordering subtlety: `--reverse` reverses AFTER `--skip`/`--max-count`
/// limit, so it cannot page oldest-first directly. Instead the page is
/// computed from the end of the newest-first order: a `--count` call
/// sizes the history (one number out, no allocation), then
/// `--skip = remaining - take` selects the oldest `take` uncovered
/// commits, reversed in code. The count traversal is CPU-only and fast;
/// both calls include HEAD under the same condition so a detached HEAD
/// is covered exactly once.
pub(crate) fn rev_list_commit_window(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
    skip: usize,
    max_count: usize,
) -> Result<Vec<String>> {
    let head_resolves = run_bounded_git(
        git_bin,
        &["rev-parse", "--verify", "HEAD"],
        repo_path,
        b"",
        deadline,
    )
    .is_ok();
    let mut count_args = vec!["rev-list", "--all", "--count"];
    if head_resolves {
        count_args.push("HEAD");
    }
    let count_out = run_bounded_git(git_bin, &count_args, repo_path, b"", deadline)?;
    let total: usize = String::from_utf8_lossy(&count_out)
        .trim()
        .parse()
        .unwrap_or(0);
    let remaining = total.saturating_sub(skip);
    if remaining == 0 {
        return Ok(Vec::new());
    }
    let take = remaining.min(max_count);
    let skip_arg = (remaining - take).to_string();
    let take_arg = take.to_string();
    let mut rev_args = vec![
        "rev-list",
        "--all",
        "--topo-order",
        "--skip",
        skip_arg.as_str(),
        "--max-count",
        take_arg.as_str(),
    ];
    if head_resolves {
        rev_args.push("HEAD");
    }
    let out = run_bounded_git(git_bin, &rev_args, repo_path, b"", deadline)?;
    let mut window: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    window.reverse();
    Ok(window)
}

/// Path-annotated blob/tree enumeration for an EXPLICIT commit list: one
/// bounded `git ls-tree -r -t -z` per commit. The git-invocation cost is
/// exactly the list length, so a caller that pages commits (the sweep's
/// discovery window) pays per pass only for its window, never the history.
///
/// Argument is the already-trimmed, non-empty commit list (not raw
/// rev-list output): the caller owns ordering and paging, this function
/// only walks. Fail-closed like the full walk: a non-UTF-8 listing or a
/// child error aborts rather than producing a partial set.
fn ls_tree_sets_for_commits(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
    commits: &[String],
) -> Result<(HashSet<ObjectPath>, HashSet<ObjectPath>)> {
    let mut blob_set: HashSet<ObjectPath> = HashSet::new();
    let mut tree_set: HashSet<ObjectPath> = HashSet::new();
    // Phase 1: enumerate trees AND blobs with their paths via
    // `git ls-tree -r -t <commit>`. `-t` is the tree counterpart of `-r`:
    // without it, recursive listings emit only blob entries. Each line is
    // `<mode> SP <type> SP <oid> TAB <path>`, with NUL between records.
    for commit in commits {
        // #218 review P1b: the root tree of each commit is no longer
        // assigned the synthetic path "/". A path-based check on "/"
        // would let the root tree slip into the allowed set even when
        // its serialized bytes name a denied subtree entry — a
        // tree's bytes expose the names of its direct entries plus
        // the OIDs of their children, which IS the metadata a
        // `/secret/**` deny is meant to withhold. The structural
        // entry-level check is in `allowed_blob_tree_sets_bounded`,
        // which enumerates root trees itself (so we don't need to
        // thread a third return value through this signature).
        // ls-tree -r -t below still enumerates every reachable
        // blob/subtree tree at its real path; only the root tree's
        // gate is restructured.
        let listing_out = run_bounded_git(
            git_bin,
            &["ls-tree", "-r", "-t", "-z", commit],
            repo_path,
            b"",
            deadline,
        )?;
        let Ok(listing_stdout) = std::str::from_utf8(&listing_out) else {
            anyhow::bail!(
                "git ls-tree -r -t -z {commit} returned a non-UTF-8 path; \
                 refusing to produce a partial (under-withheld) set"
            );
        };
        for record in listing_stdout.split('\0') {
            let Some((meta, path)) = record.split_once('\t') else {
                continue;
            };
            let mut parts = meta.split_whitespace();
            let _mode = parts.next();
            let kind = parts.next();
            let oid = parts.next();
            match kind {
                Some("blob") => {
                    if let Some(oid) = oid {
                        blob_set.insert((oid.to_string(), format!("/{path}")));
                    }
                }
                Some("tree") => {
                    if let Some(oid) = oid {
                        tree_set.insert((oid.to_string(), format!("/{path}")));
                    }
                }
                _ => {}
            }
        }
    }
    Ok((blob_set, tree_set))
}

fn all_object_paths(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
) -> Result<(Vec<ObjectPath>, Vec<ObjectPath>)> {
    // #218 review P1 (non-commit ref acceptance): the previous code
    // called `assert_all_refs_are_commits` here, which bailed on any
    // ref that didn't peel to a commit (tag-of-tree, tag-of-blob).
    // `git rev-list --all` already silently skips non-commit refs
    // (they contribute nothing to a commit-reachable walk), so the
    // assertion rejected repos for what was actually a supported
    // Git shape (`ipfs_cid_tree_served_despite_non_commit_ref` is the
    // in-repo example). The commit-reachable object set is exactly
    // what the sweep needs to classify, so the all-refs gate is
    // removed here. Unclassifiable ref targets still fail closed at
    // a later layer: the cat-file catch-all enumerates them with no
    // path, and the path-based allow filter drops empty-path entries.
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
    let commits: Vec<String> = commits_stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let (mut blob_set, mut tree_set) =
        ls_tree_sets_for_commits(repo_path, git_bin, deadline, &commits)?;
    // OID-only indexes for the phase 2 membership check below. Without
    // these the catch-all branch does O(O×P) `blob_set.iter().any(...)`
    // scans, which on a 50k-object repo runs hundreds of millions of
    // string compares per pass (round 10 P2). Rebuilt here in O(P) from
    // the extracted walk so the OID is O(1) lookup, not O(P).
    let mut blob_oids: HashSet<String> = blob_set.iter().map(|(oid, _)| oid.clone()).collect();
    let mut tree_oids: HashSet<String> = tree_set.iter().map(|(oid, _)| oid.clone()).collect();
    // Phase 2: enumerate ALL reachable objects via cat-file --batch-all-objects.
    // This catches dangling objects and objects reachable only through non-commit
    // refs (tags, notes) that ls-tree misses. Objects found only here have no
    // path, so they are inserted into the OID sets without a path. The allow
    // filter in allowed_blob_tree_sets_bounded explicitly denies empty-path
    // entries (unknown provenance), ensuring they never reach a public pin backend.
    let batch_out = run_bounded_git(
        git_bin,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype)",
        ],
        repo_path,
        b"",
        deadline,
    )?;
    let batch_stdout = String::from_utf8_lossy(&batch_out);
    for line in batch_stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let oid = match parts.next() {
            Some(o) => o,
            None => continue,
        };
        let kind = parts.next();
        match kind {
            // Only insert if not already present (ls-tree gives path, this
            // catch-all has no path; prefer the path-annotated entry).
            // Round 10 P2: O(1) OID index lookup, not O(O×P) path-pair scan.
            Some("blob") if !blob_oids.contains(oid) => {
                blob_oids.insert(oid.to_string());
                blob_set.insert((oid.to_string(), String::new()));
            }
            Some("tree") if !tree_oids.contains(oid) => {
                tree_oids.insert(oid.to_string());
                tree_set.insert((oid.to_string(), String::new()));
            }
            _ => {}
        }
    }
    Ok((
        blob_set.into_iter().collect(),
        tree_set.into_iter().collect(),
    ))
}

/// One discovery window's complete enumeration: the window commits plus
/// every blob/tree pair and tag object reachable from them or from
/// non-commit refs. The sweep classifies and replicates from exactly this
/// set — never from a full-ODB listing — so per-pass git invocations and
/// retained sets scale with the window, not the history. Unwalked commits
/// are simply absent (fail-closed: absence withholds, never publishes);
/// dangling objects are absent by construction (no batch-all catch-all).
/// Non-commit ref targets (direct blob/tree refs, annotated tags) ride
/// along every window via [`non_commit_ref_sets`] — they have no commit
/// position to page by, and the for-each-ref pass is O(refs), not
/// O(objects).
pub(crate) struct WindowEnumeration {
    pub commits: Vec<String>,
    pub blob_pairs: Vec<ObjectPath>,
    pub tree_pairs: Vec<ObjectPath>,
    pub tag_oids: Vec<String>,
}

/// Enumerate one commit window: path-annotated pairs for exactly these
/// commits plus the (window-independent) non-commit ref targets. The
/// caller pages commits with [`rev_list_commit_window`]; this function
/// never lists commits itself, so it cannot accidentally materialize
/// the history it was given to bound.
pub(crate) fn enumerate_commit_window(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
    commits: &[String],
) -> Result<WindowEnumeration> {
    let (blob_set, tree_set) = ls_tree_sets_for_commits(repo_path, git_bin, deadline, commits)?;
    let nc = non_commit_ref_sets(repo_path, git_bin, deadline)?;
    let mut blob_pairs: Vec<ObjectPath> = blob_set.into_iter().collect();
    let mut tree_pairs: Vec<ObjectPath> = tree_set.into_iter().collect();
    blob_pairs.extend(nc.blobs);
    tree_pairs.extend(nc.trees);
    Ok(WindowEnumeration {
        commits: commits.to_vec(),
        blob_pairs,
        tree_pairs,
        tag_oids: nc.tag_oids,
    })
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

/// THE visibility decision for one `blob_paths` pair, for BOTH of that walk's
/// consumers — the deny side (`withheld_from_pairs`, what the smart-http serve
/// filter excludes) and the allow side (`allowed_blob_set_for_caller_bounded`,
/// what the `GET /ipfs/{cid}` gate hands over).
///
/// Empty-path entries (round-3 P1): produced by `blob_paths` phase 2 for
/// non-commit-reachable blobs (annotated tag of blob, direct blobref).
/// The object is reachable in the repo graph but has NO commit path, so
/// the path-based visibility check `visibility_check(rules, ..., "")` is
/// meaningless — no rule's glob can match the empty path. The safe
/// policy: empty-path entries are withheld from every caller except the
/// owner. The owner is the only identity that intentionally creates
/// such refs (an annotated-tag-of-blob is a deliberate push through
/// receive-pack, not a clone artifact), so the owner is the only reader
/// the system can meaningfully bind a privacy decision to. Everyone
/// else — anonymous, named non-owner, or any non-owner DID — is
/// withheld. Without this branch, the round-3 phase-2 entries would
/// land in `allowed` (the path-based check returns `Allow` for a public
/// repo with no matching rule), and the secret blob would be served.
///
/// #218 review round 8 P1 — why this is a shared function rather than a branch
/// inside `withheld_from_pairs`: the empty-path policy lived on the deny side
/// ONLY, while `allowed_blob_set_for_caller_bounded` consumed the same pairs and
/// called `visibility_check(..., "")` directly. On a public repo that returns
/// `Allow` (no glob matches ""), so the two consumers disagreed about the very
/// same OID: the serve filter withheld the tag-only blob while `/ipfs/{cid}`
/// admitted it and served the bytes — the leak phase 2 exists to close, reopened
/// one layer over. A single decision function makes that divergence
/// unrepresentable: any future change to the empty-path policy moves both gates
/// at once.
fn pair_decision(
    path: &str,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    caller: Option<&str>,
) -> Decision {
    if path.is_empty() {
        // Round-3 P1: empty-path entries (non-commit-reachable
        // blobs from `blob_paths` phase 2) cannot be classified
        // by the path-based rules. Withhold from every caller
        // except the owner; the owner is the only identity that
        // could have created the ref tip.
        match caller {
            Some(c) if crate::api::did_matches(owner_did, c) => Decision::Allow,
            _ => Decision::Deny,
        }
    } else {
        visibility_check(rules, is_public, owner_did, caller, path)
    }
}

/// Withheld set from an already-computed (oid, "/path") listing: a blob is
/// withheld only when visibility denies the caller at *every* path it appears
/// at. Split out so a caller that already walked `blob_paths` (e.g.
/// `withheld_blob_recipients`) reuses the listing instead of walking history
/// again. Per-pair policy is [`pair_decision`], shared with the allow side.
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
        match pair_decision(path, rules, is_public, owner_did, caller) {
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
///
/// #218 review round 8 P1: the per-pair policy is [`pair_decision`], the SAME
/// function the deny side runs. It previously called `visibility_check` directly,
/// which on a `blob_paths` phase-2 empty-path entry is a check no glob can match
/// and therefore an `Allow` on any public repo — so this gate served the exact
/// OID the serve filter had just withheld. The two consumers of one walk must
/// not be able to disagree; see `pair_decision`'s comment for the full argument.
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
        if pair_decision(path, rules, is_public, owner_did, caller) == Decision::Allow {
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
/// those go through `blob_paths`, which now runs a `for-each-ref` phase 2 that
/// enumerates non-commit ref targets and inserts them with empty path
/// (round-3 fix for the annotated-tag-of-blob leak; the previous `assert_all_refs_are_commits`
/// guard was removed in commit 91d0578, leaving that path fail-open).
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

/// Root tree OIDs of every reachable commit, enumerated with one
/// bounded `git log --no-walk --format=%T --stdin` pass over the
/// shared commit set. The commit oids go on STDIN, not argv: a
/// long history has tens of thousands of reachable commits, and
/// passing them all as arguments overflows ARG_MAX so `git log`
/// fails to spawn — which the caller treats as a walk error and
/// fail-closed 404s an authorized reader of a reachable/root tree
/// (#173 P2). `run_bounded_git` drains stdout concurrently with the
/// stdin write, so a large history cannot deadlock the pipes.
/// `ls-tree` never emits a commit's own root tree, so this is
/// where the root trees get explicitly enumerated.
fn root_tree_oids(
    repo_path: &Path,
    git_bin: &str,
    commits: &[String],
    deadline: Instant,
) -> Result<HashSet<String>> {
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
            set.insert(oid.to_string());
        }
    }
    Ok(set)
}

/// #218 review P1b (recursive at every depth): the structural
/// safety check for a tree. A tree is safe to publish iff, at the
/// path it is reached, every direct entry in its serialized bytes
/// is independently safe: the entry's filename is allowed at
/// `path/filename` AND, if the entry is a tree, the child tree is
/// itself structurally safe at `path/filename`.
///
/// The recursion bottoms out at blob entries (a blob's safety is a
/// single path check) and at the leaf-most tree (whose children are
/// all blobs or the same path is denied). The check is per
/// `(oid, path)`: a tree reachable at multiple paths is admitted if
/// it is structurally safe at *any* allowed path (mirroring the
/// existing "blob reachable at any allowed path is admitted" rule).
/// `admitted` memoizes trees proven safe at some path so the
/// recursion short-circuits on cycles and on the same tree
/// reachable at multiple allowed paths.
///
/// The prior round only checked root trees; the per-depth version
/// is what the reviewer called for after the `/public/secret/**`
/// case showed the root-only check admitted `/public` (its path is
/// allowed) while `/public` still contained a `secret/` entry
/// naming the denied subtree. The recursive check at every depth
/// denies `/public` here because its `secret/` entry's child tree
/// (`/public/secret`'s subtree) is denied at `/public/secret`.
struct TreeCheckCtx<'a> {
    repo_path: &'a Path,
    git_bin: &'a str,
    rules: &'a [VisibilityRule],
    is_public: bool,
    owner_did: &'a str,
    caller: Option<&'a str>,
}

fn tree_structurally_safe(
    ctx: &TreeCheckCtx,
    tree_oid: &str,
    path: &str,
    admitted: &mut HashSet<String>,
    deadline: Instant,
) -> Result<bool> {
    if admitted.contains(tree_oid) {
        return Ok(true);
    }
    // One-level listing of the tree's direct entries. `-z` is NUL-separated
    // so paths with special bytes survive the parse intact (a `café.txt`
    // filename with a non-UTF-8 byte would otherwise be lossy-decoded and
    // could miss its deny rule). Non-UTF-8 → fail closed.
    let out = run_bounded_git(
        ctx.git_bin,
        &["ls-tree", "-z", tree_oid],
        ctx.repo_path,
        b"",
        deadline,
    )?;
    let stdout = match std::str::from_utf8(&out) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    for record in stdout.split('\0') {
        // P1 (reviewer round 9): do NOT `record.trim()`. `ls-tree -z`
        // emits NUL-separated records whose filename portion can
        // carry trailing whitespace, and a directory like `secret `
        // must reach `visibility_check` verbatim so the deny rule
        // matches it. Trimming collapsed `secret ` → `secret` and
        // let the allow side admit the parent tree, so the tree's
        // children leaked through `/ipfs/{cid}`. The trailing
        // whitespace test pins the contract.
        if record.is_empty() {
            continue;
        }
        let Some((meta, filename)) = record.split_once('\t') else {
            return Ok(false);
        };
        let mut parts = meta.split_whitespace();
        let _mode = parts.next();
        let Some(kind) = parts.next() else {
            return Ok(false);
        };
        let Some(child_oid) = parts.next() else {
            return Ok(false);
        };
        let entry_path = if path == "/" {
            format!("/{filename}")
        } else {
            format!("{path}/{filename}")
        };
        if visibility_check(
            ctx.rules,
            ctx.is_public,
            ctx.owner_did,
            ctx.caller,
            &entry_path,
        ) != Decision::Allow
        {
            return Ok(false);
        }
        if kind == "tree"
            && !tree_structurally_safe(ctx, child_oid, &entry_path, admitted, deadline)?
        {
            return Ok(false);
        }
    }
    admitted.insert(tree_oid.to_string());
    Ok(true)
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
    // Subtree trees at their directory paths; the root tree is
    // enumerated separately via `root_tree_oids` so the structural
    // post-pass can apply without overlapping with the empty-path
    // cat-file catch-all sentinel (#218 review P1b).
    let mut out: HashSet<(String, String)> = HashSet::new();
    for (oid, path, kind) in object_paths(repo_path, git_bin, &commits, deadline)? {
        if kind == "tree" {
            out.insert((oid, path));
        }
    }
    Ok(out)
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
    // #218 review P1b (recursive at every depth): the path-based
    // pass admits a tree at any path the policy allows, but that
    // admit can be wrong if the tree's serialized bytes name a denied
    // subtree entry. Re-evaluate each path-admitted tree structurally
    // at the same path, and admit it only if every direct entry is
    // safe at `path/filename` and (for tree entries) the child tree is
    // itself structurally safe there. The `admitted` set memoizes
    // trees proven safe at some path so the recursion short-circuits
    // on cycles and on the same tree reachable at multiple paths
    // (the "blob reachable at any allowed path" rule, applied to
    // trees).
    let tree_pairs = tree_paths(repo_path, git_bin, deadline)?;
    let ctx = TreeCheckCtx {
        repo_path,
        git_bin,
        rules,
        is_public,
        owner_did,
        caller,
    };
    let mut admitted: HashSet<String> = HashSet::new();
    for (oid, path) in &tree_pairs {
        // `tree_paths` only emits non-empty paths (root trees are
        // enumerated below), so the empty-path case is not reachable
        // here. P3 (reviewer round 9): the previous comment described
        // a caller-aware empty-path carve-out that the surrounding
        // code never produced, so the call degenerated to the same
        // decision `visibility_check` would make. Reverting the
        // routing through `pair_decision` removes the dead code and
        // its comment. `visibility_check` is still the policy surface
        // for the root tree pass below.
        if visibility_check(rules, is_public, owner_did, caller, path) == Decision::Allow {
            tree_structurally_safe(&ctx, oid, path, &mut admitted, deadline)?;
        }
    }
    // Root trees of reachable commits: they have no path in
    // `tree_paths` (ls-tree emits descendants only), so evaluate
    // them at "/" — the root tree is admitted iff every direct
    // entry is safe at the root and (for tree entries) the child
    // tree is itself structurally safe. The check is recursive, so
    // a denied subtree propagates up to the root.
    let commits = reachable_commit_oids(repo_path, git_bin, deadline)?;
    for root_oid in root_tree_oids(repo_path, git_bin, &commits, deadline)? {
        if visibility_check(rules, is_public, owner_did, caller, "/") != Decision::Allow {
            continue;
        }
        tree_structurally_safe(&ctx, &root_oid, "/", &mut admitted, deadline)?;
    }
    Ok(admitted)
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

/// Both the allowed blob set and the allowed tree set, derived from ONE bounded
/// walk so the two are consistent and the walk cost is paid only once. Returns
/// `(allowed_blobs, allowed_trees, all_blob_oids, all_tree_oids)`.
///
/// A blob or tree is "allowed" if visibility permits it at *some* reachable
/// path; a tree reachable at both an allowed and denied path is allowed (its
/// metadata is public elsewhere). Commits and tags are not classified here —
/// the caller decides per type whether the allow-set applies.
pub fn allowed_blob_tree_sets_bounded(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> Result<BlobTreeSets> {
    let (blob_pairs, tree_pairs) = all_object_paths(repo_path, git_bin, deadline)?;
    let commits = reachable_commit_oids(repo_path, git_bin, deadline)?;
    classify_object_pairs(
        repo_path,
        git_bin,
        deadline,
        rules,
        is_public,
        owner_did,
        &blob_pairs,
        &tree_pairs,
        &commits,
    )
}

/// Windowed twin of [`allowed_blob_tree_sets_bounded`]: enumerate exactly
/// these commits (plus the window-independent non-commit ref targets)
/// and classify the result. Same policy, bounded listing — the sweep's
/// re-derivations call this with the scan window so no authorization
/// stage re-materializes the history the scan just bounded.
pub(crate) fn allowed_blob_tree_sets_for_commits(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    commits: &[String],
) -> Result<BlobTreeSets> {
    let window = enumerate_commit_window(repo_path, git_bin, deadline, commits)?;
    classify_object_pairs(
        repo_path,
        git_bin,
        deadline,
        rules,
        is_public,
        owner_did,
        &window.blob_pairs,
        &window.tree_pairs,
        &window.commits,
    )
}

/// Shared allow/deny classification over an explicit pair listing: the
/// allow loops, the structural tree checks, and the root-tree pass. The
/// full walk ([`allowed_blob_tree_sets_bounded`]) and the windowed sweep
/// ([`enumerate_commit_window`] + this) run the SAME policy over
/// different listings, so a policy change cannot drift between them.
/// `root_commits` are the commits whose root trees are evaluated at "/":
/// the full reachable set for the whole-repo walk, the window for a
/// windowed walk. Commits and tags are not classified here — the caller
/// decides per type whether the allow-set applies.
///
/// #218 review P1b: enumerate every given commit's root tree OID so
/// the structural entry-level check can be applied to each: one
/// `git rev-parse <commit>^{tree}` per commit (via [`root_tree_oids`]),
/// all bounded by `deadline`.
/// Nine arguments: the walk seam (`repo_path`, `git_bin`, `deadline`),
/// the policy tuple (`rules`, `is_public`, `owner_did`), and the three
/// listing inputs (`blob_pairs`, `tree_pairs`, `root_commits`). A params
/// struct would only rename values the two callers already hold
/// separately.
#[allow(clippy::too_many_arguments)]
pub(crate) fn classify_object_pairs(
    repo_path: &Path,
    git_bin: &str,
    deadline: Instant,
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
    blob_pairs: &[ObjectPath],
    tree_pairs: &[ObjectPath],
    root_commits: &[String],
) -> Result<BlobTreeSets> {
    let all_blob_oids: HashSet<String> = blob_pairs.iter().map(|(oid, _)| oid.clone()).collect();
    let all_tree_oids: HashSet<String> = tree_pairs.iter().map(|(oid, _)| oid.clone()).collect();
    let mut allowed_blobs = HashSet::new();
    for (oid, path) in blob_pairs {
        // #218 review round 9 (guidance #1): the empty-path
        // decision is now in `pair_decision` so this consumer and
        // `withheld_from_pairs` / `allowed_blob_set_for_caller_bounded`
        // cannot disagree. For this caller (the sweep's anonymous
        // allow-set), `pair_decision("", ..., None)` is Deny —
        // identical to the previous `!path.is_empty()` skip, but
        // the path is now annotated with the explicit
        // "unclassifiable → deny" reasoning rather than a silent
        // skip. If the policy is ever relaxed (e.g. to allow
        // owner-only paths), it lands in one place.
        if pair_decision(path, rules, is_public, owner_did, None) == Decision::Allow {
            allowed_blobs.insert(oid.clone());
        }
    }
    // #218 review P1b (recursive at every depth): the path-based pass
    // admits a tree at any path the policy allows, but a tree's
    // serialized bytes name its direct entries plus their OIDs — so a
    // path-admitted tree whose entries point at a denied subtree
    // would leak that subtree's existence. Re-evaluate each
    // path-admitted tree structurally at the same path: admit it
    // only if every direct entry is safe at `path/filename` and
    // (for tree entries) the child tree is itself structurally safe
    // there. The `admitted` set memoizes trees proven safe at some
    // path so the recursion short-circuits on cycles and on the
    // same tree reachable at multiple allowed paths.
    let ctx = TreeCheckCtx {
        repo_path,
        git_bin,
        rules,
        is_public,
        owner_did,
        caller: None,
    };
    let mut allowed_trees: HashSet<String> = HashSet::new();
    for (oid, path) in tree_pairs {
        // #218 review round 9 (guidance #1): route through
        // `pair_decision` so this tree allow-set and the blob
        // allow-set above share the empty-path policy. The
        // structural check (`tree_structurally_safe`) only runs
        // for trees the path-based decision admits; an
        // unclassifiable empty-path tree is not in `allowed_trees`
        // for an anonymous caller (the sweep's policy).
        if pair_decision(path, rules, is_public, owner_did, None) != Decision::Allow {
            continue;
        }
        if tree_structurally_safe(&ctx, oid, path, &mut allowed_trees, deadline)? {
            allowed_trees.insert(oid.clone());
        }
    }
    // Root trees of `root_commits`: they have no path in
    // `tree_pairs` (ls-tree emits descendants only), so evaluate
    // them at "/" — the root tree is admitted iff every direct
    // entry is safe at the root and (for tree entries) the child
    // tree is itself structurally safe. The check is recursive, so
    // a denied subtree propagates up to the root.
    for root_oid in root_tree_oids(repo_path, git_bin, root_commits, deadline)? {
        if visibility_check(rules, is_public, owner_did, None, "/") != Decision::Allow {
            continue;
        }
        if tree_structurally_safe(&ctx, &root_oid, "/", &mut allowed_trees, deadline)? {
            allowed_trees.insert(root_oid);
        }
    }

    Ok((allowed_blobs, allowed_trees, all_blob_oids, all_tree_oids))
}

/// Objects safe to replicate, failing closed on blobs (#99) and denied trees
/// (#172). A candidate replicates iff:
/// - it is a commit (structural metadata, always safe), OR
/// - it is a blob AND is in `allowed_blobs` (reachable and visibility-allowed), OR
/// - it is a tree AND is in `allowed_trees` (reachable and visibility-allowed).
///
/// This drops withheld blobs, withheld trees, and dangling/unreachable objects.
/// Used on the full-scan pin path, where the candidate set can contain objects
/// the reachable-only withheld set cannot cover; the delta path keeps
/// `replicable_objects`.
pub fn replicable_objects_fail_closed(
    candidates: Vec<String>,
    allowed_blobs: &HashSet<String>,
    all_blob_oids: &HashSet<String>,
    allowed_trees: &HashSet<String>,
    all_tree_oids: &HashSet<String>,
) -> Vec<String> {
    candidates
        .into_iter()
        .filter(|oid| {
            if all_blob_oids.contains(oid) {
                // Blobs: fail closed — only allowed blobs pass.
                allowed_blobs.contains(oid)
            } else if all_tree_oids.contains(oid) {
                // Trees: fail closed — only allowed trees pass (#172).
                // A denied tree exposes child filenames and blob OIDs even
                // though the secret content itself is excluded.
                allowed_trees.contains(oid)
            } else {
                // Commits/tags: structural metadata, always safe.
                true
            }
        })
        .collect()
}

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
    Ok(recipients_from_pairs(&pairs, rules, is_public, owner_did))
}

/// Withheld-to-recipients mapping over an explicit pair listing: the same
/// withheld computation and owner-plus-readers mapping as
/// [`withheld_blob_recipients_bounded`], shared so the windowed sweep
/// (which walks only its commit window) applies the identical recipient
/// policy as the full-history receive-pack path. Least-privilege: a
/// reader of one private subtree is not a recipient of an object that
/// only lives elsewhere; an unclassifiable empty-path object grants a
/// recovery copy to the owner only.
pub(crate) fn recipients_from_pairs(
    pairs: &[(String, String)],
    rules: &[VisibilityRule],
    is_public: bool,
    owner_did: &str,
) -> HashMap<String, BTreeSet<String>> {
    let withheld = withheld_from_pairs(pairs, rules, is_public, owner_did, None);
    if withheld.is_empty() {
        return HashMap::new();
    }
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for r in rules {
        for d in &r.reader_dids {
            candidates.insert(d.clone());
        }
    }
    let mut out: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (oid, path) in pairs {
        if !withheld.contains(oid) {
            continue;
        }
        let entry = out.entry(oid.clone()).or_default();
        entry.insert(owner_did.to_string());
        for did in &candidates {
            // Same shared per-pair policy as the deny/allow gates (round-8 P1):
            // an empty-path (phase-2, unclassifiable) blob grants a recovery
            // copy to the owner only, never to a rule's named reader whose
            // grant was written against a path this object does not have.
            if pair_decision(path, rules, is_public, owner_did, Some(did)) == Decision::Allow {
                entry.insert(did.clone());
            }
        }
    }
    out
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
            // `{err:#}` prints the whole anyhow chain. Plain `{err}` shows only the top
            // context ("failed to spawn git for-each-ref") and drops the underlying io
            // error, which left a real beta-lane CI failure undiagnosable.
            "a hung walk must abort with GitServiceTimeout (mapped to 504), got: {err:#}"
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
        //
        // The deadline below is deliberately far larger than the work it bounds: the
        // watchdog tears the whole group down at the deadline, so a deadline tight
        // enough to race `/bin/sh` reaching its first statement kills the leader
        // BEFORE it records its pid, and the `leader.pid` read below then fails with
        // NotFound. That is a harness race, not a product failure, and it is exactly
        // what a loaded CI runner reproduced (test (beta), 2026-08-04). Sizing it at
        // 2s keeps the property under test intact, since the pre-fix build blocks on
        // `child.wait()` for the child's full `sleep 30` and still trips the 10s recv
        // budget below (RED), while leaving a 20x margin over the ~100ms that a
        // healthy start actually needs.
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
                Instant::now() + Duration::from_secs(2),
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

    /// Write `bytes` to the bare repo's object store and return
    /// the resulting loose blob OID. Used by the consumer matrix
    /// test to give each ref shape its OWN blob so a missing
    /// phase-2 arm is observable (sharing one blob across all
    /// three shapes meant every consumer was green under every
    /// combination of arms, P2 reviewer round 9).
    fn make_blob(bare: &Path, bytes: &[u8]) -> String {
        use std::io::Write;
        use std::process::Stdio;
        let out = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(bare)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().unwrap().write_all(bytes)?;
                c.wait_with_output()
            })
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
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

        // anon: the withheld /secret subtree tree is excluded (#172). The
        // root tree is ALSO excluded (#218 review P1b): its serialized
        // bytes name the `/secret` entry and the OID of its child
        // subtree, so publishing it would leak the same metadata the
        // `/secret/**` deny is meant to withhold. The structural
        // entry-level check in `allowed_tree_set_for_caller_bounded`
        // gates the root tree on every direct entry being safe.
        // `/public` (allowed path) is still in.
        let anon = allowed_tree_set_for_caller(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            !anon.contains(&secret_tree),
            "withheld /secret subtree tree excluded for anon"
        );
        assert!(
            !anon.contains(&root_tree),
            "root tree excluded for anon: its serialized bytes name /secret and the \
             secret subtree OID, which is the metadata the /secret/** deny must withhold"
        );
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

        // Call root_tree_oids directly (private, same module) under a
        // liveness watchdog, then assert it returned every distinct
        // root tree. (#218 review P1b: the previous shape returned
        // `(oid, "/")` pairs so the path-based filter would admit
        // root trees on the synthetic "/". The new shape is a plain
        // oid set; the structural post-pass in
        // `allowed_tree_set_for_caller_bounded` and
        // `allowed_blob_tree_sets_bounded` is what actually admits
        // them.)
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(
                root_tree_oids(&bare, "git", &commits, Instant::now() + WALK_TIMEOUT)
                    .map(|s| s.len()),
            );
        });
        match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(Ok(len)) => assert_eq!(len, N, "every distinct root tree returned"),
            Ok(Err(e)) => panic!("root_tree_oids errored: {e}"),
            Err(_) => panic!("root_tree_oids did not return within 30s"),
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
        let allowed_trees: HashSet<String> = HashSet::new();
        let all_trees: HashSet<String> = HashSet::new();
        let candidates = vec![
            "commit1".to_string(),
            "tree1".to_string(),
            "b_pub".to_string(),
            "b_secret".to_string(),
            "b_dangling".to_string(),
        ];
        let got = replicable_objects_fail_closed(
            candidates,
            &allowed,
            &all_blobs,
            &allowed_trees,
            &all_trees,
        );
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
        let allowed_trees: HashSet<String> = HashSet::new();
        let all_trees: HashSet<String> = HashSet::new();
        let replicable = replicable_objects_fail_closed(
            candidates,
            &allowed,
            &all_blobs,
            &allowed_trees,
            &all_trees,
        );
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

    /// #218 review round 10 (P1): `walk_tree_oids_inner` previously
    /// returned `Ok(())` on a non-UTF-8 `ls-tree -z` listing,
    /// inserting only the tree OID and skipping the child blob/tree
    /// OIDs. A direct tree ref (or an annotated tag peeling to a
    /// tree) is valid Git input; `git rev-list --objects --all`
    /// still enumerates the tree and every descendant. The
    /// keep-side therefore removed the tree from the served set but
    /// passed the child blob OIDs to `pack-objects`, exposing their
    /// bytes to an anonymous clone. Phase 1 already bails on the
    /// same input at `:526`; this test pins the walk on the same
    /// fail-closed outcome for direct tree refs and peeled
    /// tag-of-tree refs (the two non-commit shapes that round 9
    /// added tolerance for).
    #[cfg(unix)]
    #[test]
    fn fails_closed_on_non_utf8_tree_tip() {
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
        // Direct tree ref: a ref whose target is the TREE OID, not a commit.
        // `git update-ref refs/tags/direct-tree <tree_oid>` writes that.
        let tree_oid = String::from_utf8_lossy(
            &Command::new("git")
                .args(["write-tree"])
                .current_dir(&work)
                .output()
                .unwrap()
                .stdout,
        )
        .trim()
        .to_string();
        run(&["update-ref", "refs/tags/direct-tree", &tree_oid], &work);
        // Peeled tag-of-tree: an annotated tag whose target is the same tree.
        // The walker has to peel the tag before it reaches the tree.
        run(
            &["tag", "-a", "-m", "tagged", "tag-of-tree", &tree_oid],
            &work,
        );
        // Push both to the bare clone so the walker exercises the
        // post-clone refs.
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

        // Direct-tree case: the ref's target is the tree OID. The
        // walker must fail closed (Err) so the keep-side withholds
        // the whole subtree by name, never serving the child blob.
        let rules = [rule("/s\u{fffd}cret/**", &[])];
        let direct = withheld_blob_oids(&bare, &rules, true, OWNER, None);
        assert!(
            direct.is_err(),
            "a direct-tree ref with a non-UTF-8 child must fail closed (Err), \
             not return Ok with a partial withheld set (review round 10 P1)"
        );

        // Peeled-tag case: the direct-tree ref is deleted first so this
        // call walks ONLY the annotated tag ref. Otherwise both calls
        // would share one clone, the walk would fail closed on the direct
        // ref first, and the peel arm would never run in either call —
        // a regression in the tag-of-tree shape would not be caught
        // (review round 11 P3). With only the tag ref left, an Err
        // proves the walker peeled the tag to the tree and hit the
        // non-UTF-8 child through that path.
        run(&["update-ref", "-d", "refs/tags/direct-tree"], &bare);
        let peeled = withheld_blob_oids(&bare, &rules, true, OWNER, None);
        assert!(
            peeled.is_err(),
            "a peeled annotated-tag-of-tree with a non-UTF-8 child must \
             fail closed (Err), not return Ok with a partial withheld set"
        );
    }

    /// Build a linear history of `n` commits (one root-level file each)
    /// in a workdir repo and return (tempdir, bare clone, commit oids
    /// oldest-first). Cloned --bare so the walk exercises post-clone refs.
    fn linear_history(n: usize) -> (TempDir, std::path::PathBuf, Vec<String>) {
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
        std::fs::create_dir_all(&work).unwrap();
        run(&["init", "-q", "-b", "main"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        let mut oids = Vec::new();
        for i in 0..n {
            std::fs::write(work.join(format!("f{i:03}.txt")), format!("bytes {i}\n")).unwrap();
            run(&["add", "."], &work);
            run(&["commit", "-qm", &format!("commit {i}")], &work);
            let out = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&work)
                .output()
                .unwrap();
            oids.push(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
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
        (td, bare, oids)
    }

    /// The discovery cursor pages oldest-first with a stable order: five
    /// linear commits windowed two at a time yield [0,1], [2,3], [4], and
    /// a short page means the history is covered.
    #[test]
    fn commit_window_pages_oldest_first_with_stable_order() {
        let (_td, bare, oids) = linear_history(5);
        let deadline = Instant::now() + WALK_TIMEOUT;
        let w0 = rev_list_commit_window(&bare, "git", deadline, 0, 2).unwrap();
        let w1 = rev_list_commit_window(&bare, "git", deadline, 2, 2).unwrap();
        let w2 = rev_list_commit_window(&bare, "git", deadline, 4, 2).unwrap();
        assert_eq!(w0, oids[0..2], "first window is the two oldest commits");
        assert_eq!(w1, oids[2..4], "second window continues in order");
        assert_eq!(w2, oids[4..5], "short page covers the tail");
        let w3 = rev_list_commit_window(&bare, "git", deadline, 6, 2).unwrap();
        assert!(
            w3.is_empty(),
            "a cursor past the history end reads empty (caller resets)"
        );
    }

    /// Write a `git` wrapper that logs every argv line to `count_file`
    /// then execs the real git. `run_bounded_git` spawns `git_bin` by
    /// path, so no PATH mutation is needed and parallel tests are
    /// unaffected: the wrapper is transparent apart from the log.
    #[cfg(unix)]
    fn counting_git(dir: &Path, count_file: &Path) -> String {
        use std::os::unix::fs::PermissionsExt;
        let real: String = {
            let out = Command::new("sh")
                .args(["-c", "command -v git"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let p = dir.join("counting-git");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"$@\" >> {}\nexec {} \"$@\"\n",
                count_file.display(),
                real
            ),
        )
        .unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p.to_str().unwrap().to_string()
    }

    /// Count argv lines starting with `argv0` in a counting-wrapper log.
    #[cfg(unix)]
    fn count_invocations(count_file: &Path, argv0: &str) -> usize {
        std::fs::read_to_string(count_file)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.split_whitespace().next() == Some(argv0))
            .count()
    }

    /// Per-pass git invocations scale with the WINDOW, not the history:
    /// six commits enumerated two at a time cost two ls-trees, and six
    /// more commits leave that count unchanged. The full-history
    /// enumeration costs one ls-tree per commit. This is the property
    /// that makes hourly sweep passes bounded on large histories.
    #[cfg(unix)]
    #[test]
    fn windowed_enumeration_bounds_git_invocations() {
        let (td, bare, oids) = linear_history(6);
        let count_file = td.path().join("invocations.log");
        let git = counting_git(td.path(), &count_file);
        let deadline = Instant::now() + WALK_TIMEOUT;

        let window = rev_list_commit_window(&bare, &git, deadline, 0, 2).unwrap();
        assert_eq!(window, oids[0..2]);
        std::fs::write(&count_file, "").unwrap();
        let _ = enumerate_commit_window(&bare, &git, deadline, &window).unwrap();
        assert_eq!(
            count_invocations(&count_file, "ls-tree"),
            2,
            "one ls-tree per window commit, nothing per history commit"
        );

        // Full-history enumeration on the same repo for contrast.
        std::fs::write(&count_file, "").unwrap();
        let full = rev_list_commit_window(&bare, &git, deadline, 0, 100).unwrap();
        assert_eq!(full.len(), 6);
        let _ = enumerate_commit_window(&bare, &git, deadline, &full).unwrap();
        assert_eq!(
            count_invocations(&count_file, "ls-tree"),
            6,
            "unwindowed enumeration pays per history commit"
        );

        // Grow the history: the windowed cost must not move.
        {
            let work = td.path().join("work2");
            let _ = std::fs::remove_dir_all(&work);
            let run = |args: &[&str], dir: &Path| {
                assert!(Command::new("git")
                    .args(args)
                    .current_dir(dir)
                    .status()
                    .unwrap()
                    .success());
            };
            run(
                &[
                    "clone",
                    "-q",
                    bare.to_str().unwrap(),
                    work.to_str().unwrap(),
                ],
                td.path(),
            );
            run(&["config", "user.email", "t@t"], &work);
            run(&["config", "user.name", "t"], &work);
            for i in 6..12 {
                std::fs::write(work.join(format!("g{i:03}.txt")), format!("more {i}\n")).unwrap();
                run(&["add", "."], &work);
                run(&["commit", "-qm", &format!("commit {i}")], &work);
            }
            run(&["push", "-q", "origin", "main"], &work);
        }
        let window2 = rev_list_commit_window(&bare, &git, deadline, 0, 2).unwrap();
        std::fs::write(&count_file, "").unwrap();
        let _ = enumerate_commit_window(&bare, &git, deadline, &window2).unwrap();
        assert_eq!(
            count_invocations(&count_file, "ls-tree"),
            2,
            "doubling the history must not move the windowed invocation count"
        );
    }

    /// Windowed classification agrees with the full walk: the union of
    /// per-window allow sets equals the whole-history allow sets, a
    /// denied blob is denied in every window (fail-closed per window,
    /// not just in union), a dangling blob is absent from the windowed
    /// sets entirely (no batch-all catch-all feeds them), and an
    /// annotated tag object is collected for structural pinning.
    #[test]
    fn windowed_union_matches_full_with_denied_dangling_and_tag() {
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
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::create_dir_all(work.join("secret")).unwrap();
        run(&["init", "-q", "-b", "main"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);
        // Four commits so two windows of two cover the history.
        for i in 0..4 {
            std::fs::write(
                work.join(format!("public/p{i}.txt")),
                format!("public {i}\n"),
            )
            .unwrap();
            run(&["add", "."], &work);
            run(&["commit", "-qm", &format!("commit {i}")], &work);
        }
        std::fs::write(work.join("secret/s.txt"), b"TOP SECRET\n").unwrap();
        run(&["add", "."], &work);
        run(&["commit", "-qm", "add secret"], &work);
        let secret_blob = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD:secret/s.txt"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
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
        // Created AFTER the clone: `git clone` packs only reachable
        // objects, so a dangling blob or tag seeded pre-clone would
        // never arrive. `make_blob` writes straight into the bare
        // object store, which is exactly the dangling shape.
        // Annotated tags need a committer identity, and the bare
        // clone carries no config (CI has no global git identity),
        // so configure it here like the workdir above.
        run(&["config", "user.email", "t@t"], &bare);
        run(&["config", "user.name", "t"], &bare);
        let dangling = make_blob(&bare, b"dangling, referenced by nothing\n");
        // An annotated tag of a blob: exercises the peel arm and the
        // tag-object collection.
        let tagged_blob = make_blob(&bare, b"tagged blob\n");
        run(
            &["tag", "-a", "-m", "tagged", "tagref", &tagged_blob],
            &bare,
        );
        let tag_oid = {
            let out = Command::new("git")
                .args(["rev-parse", "tagref"])
                .current_dir(&bare)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        let deadline = Instant::now() + WALK_TIMEOUT;
        let rules = [rule("/secret/**", &[])];
        // Full-history reference THROUGH the batch-all catch-all: the
        // only path that enumerates the dangling blob.
        let (full_blob_pairs, full_tree_pairs) = all_object_paths(&bare, "git", deadline).unwrap();
        assert!(
            full_blob_pairs.contains(&(dangling.clone(), String::new())),
            "the full walk must contain the dangling blob (empty path) for this comparison to mean anything"
        );
        let full_commits = rev_list_commit_window(&bare, "git", deadline, 0, 100).unwrap();
        assert_eq!(full_commits.len(), 5);
        let full_sets = classify_object_pairs(
            &bare,
            "git",
            deadline,
            &rules,
            true,
            OWNER,
            &full_blob_pairs,
            &full_tree_pairs,
            &full_commits,
        )
        .unwrap();
        assert!(
            !full_sets.0.contains(&secret_blob),
            "reference: denied blob is denied in the full walk"
        );
        assert!(
            !full_sets.0.contains(&dangling),
            "reference: dangling blob is denied (not allowed) in the full walk"
        );

        // Two windows of two plus the one-commit tail.
        let mut union_allowed_blobs: HashSet<String> = HashSet::new();
        let mut union_allowed_trees: HashSet<String> = HashSet::new();
        let mut union_all_blobs: HashSet<String> = HashSet::new();
        let mut union_tags: HashSet<String> = HashSet::new();
        let mut skip = 0usize;
        loop {
            let window = rev_list_commit_window(&bare, "git", deadline, skip, 2).unwrap();
            if window.is_empty() {
                break;
            }
            let e = enumerate_commit_window(&bare, "git", deadline, &window).unwrap();
            let sets = classify_object_pairs(
                &bare,
                "git",
                deadline,
                &rules,
                true,
                OWNER,
                &e.blob_pairs,
                &e.tree_pairs,
                &window,
            )
            .unwrap();
            // Fail-closed per window, not just in union.
            assert!(
                !sets.0.contains(&secret_blob),
                "denied blob must be denied in every window"
            );
            assert!(
                !sets.2.contains(&dangling),
                "dangling blob must be absent from every window"
            );
            union_allowed_blobs.extend(sets.0);
            union_allowed_trees.extend(sets.1);
            union_all_blobs.extend(sets.2);
            union_tags.extend(e.tag_oids);
            skip += window.len();
            if window.len() < 2 {
                break;
            }
        }
        assert_eq!(
            union_allowed_blobs, full_sets.0,
            "windowed allow sets union to the full allow set"
        );
        assert_eq!(
            union_allowed_trees, full_sets.1,
            "windowed tree allow sets union to the full tree allow set"
        );
        // The windowed all-blob set is the full one MINUS the dangling
        // blob: the full walk's batch-all catch-all enumerates it (then
        // denies it), the windowed walk never lists it at all — absent
        // by construction rather than filtered.
        let mut full_minus_dangling: HashSet<String> =
            full_blob_pairs.iter().map(|(oid, _)| oid.clone()).collect();
        assert!(
            full_minus_dangling.remove(&dangling),
            "the full walk must contain the dangling blob for this comparison to mean anything"
        );
        assert_eq!(
            union_all_blobs, full_minus_dangling,
            "windowed enumeration matches full enumeration except dangling objects"
        );
        assert!(
            union_tags.contains(&tag_oid),
            "the annotated tag object must be collected for structural pinning"
        );
        // Owner recovery sees the denied blob through the windowed pairs.
        let mut window_pairs: Vec<(String, String)> = Vec::new();
        for w in [0, 2, 4] {
            let window = rev_list_commit_window(&bare, "git", deadline, w, 2).unwrap();
            if window.is_empty() {
                break;
            }
            let e = enumerate_commit_window(&bare, "git", deadline, &window).unwrap();
            window_pairs.extend(e.blob_pairs);
            window_pairs.extend(e.tree_pairs);
        }
        let recips = recipients_from_pairs(&window_pairs, &rules, true, OWNER);
        assert!(
            recips.get(&secret_blob).is_some_and(|s| s.contains(OWNER)),
            "denied blob must reach the owner recovery set through windowed pairs"
        );
    }

    /// #218 review round 9 (guidance #2 — preserve Git path bytes):
    /// a path with a TRAILING SPACE is a real, valid Git shape
    /// (`git` stores raw bytes, no POSIX/NTFS rule applies). The
    /// visibility pipeline must see the bytes verbatim: a `/secret/**`
    /// rule has to match a path of `secret /f.txt` (the parent
    /// directory is `secret ` with one trailing space, not the
    /// directory `secret` followed by `/f.txt`).
    ///
    /// Pre-fix regression: any `record.trim()` on the `ls-tree -z`
    /// field would have stripped the trailing space and let the blob
    /// leak. The current parser at `blob_paths` does NOT `.trim()`
    /// the path — the test pins that invariant at the cargo-test
    /// level so a future refactor that reintroduces a trim fails
    /// the suite, not the production walk.
    #[cfg(unix)]
    #[test]
    fn withholds_secret_blob_at_path_with_trailing_space() {
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        // Create a parent directory whose name has a trailing space.
        // `git` permits this; some filesystems do too on Linux.
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(work.join("secret ")).unwrap();
        std::fs::write(work.join("public.txt"), b"public\n").unwrap();
        std::fs::write(
            work.join("secret /f.txt"),
            b"TOP SECRET (trailing-space path)\n",
        )
        .unwrap();
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
        let secret_oid = oid("secret /f.txt");
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

        // The rule matches the trailing-space parent (a normal
        // /secret/** won't catch it). Use the explicit pattern
        // that includes the space.
        let rules = [rule("/secret /**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "secret blob at a path with a trailing-space parent directory must be withheld \
             (the rule was /secret /** with the literal trailing space)"
        );
        assert!(
            !withheld.contains(&public_oid),
            "public blob must NOT be withheld"
        );
    }

    /// #218 review round 9 (guidance #2 — preserve Git path bytes):
    /// `ls-tree -z` is NUL-delimited, and the record's
    /// `<metadata>\t<path>\0` shape has no leading whitespace
    /// outside the field separator. If a future parser
    /// inadvertently eats leading whitespace from the field
    /// (e.g. a `path.trim_start()`), a path beginning with a space
    /// would be re-shaped into the same one with the space gone
    /// — a quiet leak class symmetric with the trailing-space
    /// case above.
    ///
    /// The contract: leading whitespace in the field is part of
    /// the filename (rare but possible; the field is bytes, not a
    /// POSIX path) and must be preserved.
    ///
    /// The test creates a *directory* whose name has a leading
    /// space (` secret/`), then a file at ` secret/f.txt`. The
    /// leading space is inside a directory name, not at the
    /// top-level (where the `git update-index --cacheinfo`
    /// path-separator would eat it). The full path is
    /// `/ secret/f.txt` and the rule is `/ secret/**` with a
    /// literal leading space. A `path.trim_start()` on the
    /// post-`/` portion would collapse this to `/secret/**`
    /// and the rule would no longer match.
    #[cfg(unix)]
    #[test]
    fn withholds_secret_blob_at_path_with_leading_space() {
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
        // A directory with a leading space in its name. The
        // working tree on Linux permits this; some shells don't,
        // so we materialise via `std::fs` not via a shell glob.
        std::fs::create_dir_all(work.join(" secret")).unwrap();
        std::fs::write(work.join("public.txt"), b"public\n").unwrap();
        std::fs::write(
            work.join(" secret").join("f.txt"),
            b"TOP SECRET (leading-space dir)\n",
        )
        .unwrap();
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
        let secret_oid = oid(" secret/f.txt");
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

        // The rule matches the leading-space directory (a normal
        // /secret/** won't catch it). Use the explicit pattern
        // that includes the space.
        let rules = [rule("/ secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&secret_oid),
            "secret blob at a path inside a LEADING-SPACE directory must be withheld \
             (the rule was / secret/** with the literal leading space); a trim_start() on the \
             post-/ portion would leak it"
        );
        assert!(
            !withheld.contains(&public_oid),
            "public blob must NOT be withheld"
        );
    }

    /// Write a blob into `bare`'s object store that NO commit reaches, and
    /// return its OID.
    ///
    /// #218 review round 8 P2 (why this exists): the phase-2 ref tests used to
    /// hang the ref on `fixture()`'s `secret` blob, which is COMMITTED at
    /// `secret/b.txt`. Phase 1's per-commit `ls-tree` therefore already yielded
    /// `(secret, "/secret/b.txt")`, the `/secret/**` rule already denied it, and
    /// the `withheld.contains(&secret)` assertion passed with phase 2 deleted
    /// outright — the tests bound nothing. A blob written straight to the object
    /// store is absent from every commit's tree, so phase 1 cannot see it and the
    /// ONLY way it reaches the withheld set is the `for-each-ref` phase. That is
    /// also the exact shape of the leak: `rev_list_keep`'s
    /// `git rev-list --objects --all` DOES follow a ref to such a blob (verified
    /// against stock git), so an under-withheld one ships in the clone pack.
    ///
    /// `hash-object -w --stdin` is the minimal way to produce it; committing the
    /// content and then orphaning the commit reaches the same state by a longer
    /// route, and would additionally leave the content in a reflog the walk does
    /// not read.
    #[cfg(test)]
    fn orphan_blob(bare: &Path, content: &str) -> String {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(bare)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git hash-object failed");
        let oid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(!oid.is_empty(), "git hash-object produced no OID");
        oid
    }

    #[test]
    fn skips_a_ref_pointing_at_a_blob() {
        // #218 review round 1: a ref pointing at a blob is a valid Git
        // shape (tag-of-blob, blobref). The pre-fix
        // `assert_all_refs_are_commits` guard bailed on this and
        // failed the whole walk closed; round 1 drops the guard.
        // #218 review round 3 P1: the round-1 fix was correct for
        // the allow-list sweep (empty paths dropped at
        // visibility_pack.rs:1396, :1423) but it left the deny-set
        // path fail-OPEN — a blob only reachable via a non-commit
        // ref tip would be served (the `git rev-list --objects --all`
        // enumeration in `smart_http::rev_list_keep` includes
        // non-commit targets) but NOT withheld (the deny set comes
        // from `blob_paths`, which only walks commits). Round 3
        // adds a `for-each-ref` phase 2 to `blob_paths` that
        // enumerates non-commit ref targets and inserts them with
        // empty path; the deny-side caller withholds empty-path
        // entries by OID.
        //
        // #218 review round 8 P2 (non-vacuity): the blob under test is
        // `orphan_blob`'s, reachable ONLY through the ref written below —
        // no commit's tree names it, so phase 1 contributes nothing for it
        // and the assertion binds phase 2 alone. Verified by mutation:
        // neutralizing the phase-2 filter turns this RED.
        let (_td, bare, _secret, _public) = fixture();
        let orphan = orphan_blob(&bare, "TOP SECRET, ref-only\n");
        std::fs::write(bare.join("refs/heads/blobref"), format!("{orphan}\n")).unwrap();
        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None)
            .expect("a ref pointing at a non-commit object no longer fails the whole walk");
        assert!(
            withheld.contains(&orphan),
            "a blob reachable ONLY via a direct ref-to-blob must be withheld — no \
             commit path names it, so nothing but the for-each-ref phase can put it \
             in the deny set, while `git rev-list --objects --all` already serves it"
        );
    }

    /// #218 review round 8 P1 (the allow side of the same pair): the
    /// `GET /ipfs/{cid}` gate consumes the SAME `blob_paths` listing through
    /// `allowed_blob_set_for_caller_bounded`. Before the shared `pair_decision`,
    /// that consumer ran `visibility_check(..., "")` on a phase-2 entry, and on a
    /// public repo no glob matches the empty path so the answer was `Allow` — the
    /// serve filter withheld the OID while the IPFS gate handed the bytes over.
    /// The two sides must agree: an anonymous caller is denied, the owner is not.
    #[test]
    fn ref_only_blob_is_denied_on_the_allow_side_too() {
        let (_td, bare, _secret, _public) = fixture();
        let orphan = orphan_blob(&bare, "TOP SECRET, ref-only, allow side\n");
        std::fs::write(bare.join("refs/heads/blobref"), format!("{orphan}\n")).unwrap();
        // A PUBLIC repo with a rule that cannot match an empty path: the
        // pre-fix path-based check returned Allow here.
        let rules = [rule("/secret/**", &[])];

        let anon = allowed_blob_set_for_caller(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            !anon.contains(&orphan),
            "the allow side must NOT admit a ref-only blob to an anonymous caller — \
             the serve filter withholds this exact OID, and a disagreement means \
             `GET /ipfs/{{cid}}` serves what the clone pack refused"
        );

        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None).unwrap();
        assert!(
            withheld.contains(&orphan) && !anon.contains(&orphan),
            "deny side and allow side must reach the SAME verdict for one OID"
        );

        // The owner is the one identity the empty-path policy admits, so the
        // test also proves the shared decision is owner-only rather than
        // deny-everything (which would pass the assertion above vacuously).
        let owner_set = allowed_blob_set_for_caller(&bare, &rules, true, OWNER, Some(OWNER))
            .expect("owner walk must succeed");
        assert!(
            owner_set.contains(&orphan),
            "the owner — the only identity that could have created the ref tip — \
             must still be able to read a ref-only blob"
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
    fn skips_an_annotated_tag_of_a_blob() {
        // #218 review round 1: an annotated tag of a blob is a
        // valid Git shape (pushable through receive-pack). The
        // pre-fix `assert_all_refs_are_commits` guard bailed on
        // this and failed the whole walk closed; round 1 drops
        // the guard. #218 review round 3 P1: same shape as
        // `skips_a_ref_pointing_at_a_blob` — the deny set must
        // include the blob. The annotated tag `blobtag` peels to
        // the blob, not a commit; `git rev-list --all` skips the
        // tag; the phase-2 `for-each-ref` in `blob_paths`
        // enumerates the tag and inserts the referent with an
        // empty path; the deny-side caller withholds by OID.
        //
        // #218 review round 8 P1 (peeling) + P2 (non-vacuity): this is the
        // shape the ref walk MISSED before the peeled atoms were added.
        // `%(objecttype)` of an annotated tag is `tag`, so the blob/tree arms
        // never saw the referent and the tag contributed nothing; the OLD test
        // passed anyway only because its blob was also committed at
        // `secret/b.txt` and phase 1 withheld it. The blob here is
        // `orphan_blob`'s — reachable through the tag and nothing else — so
        // the assertion now fails without BOTH the phase and its peel.
        // Verified by mutation: neutralizing the phase-2 filter turns this RED.
        let (_td, bare, _secret, _public) = fixture();
        let orphan = orphan_blob(&bare, "TOP SECRET, tag-only\n");
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
        run(&["tag", "-a", "-m", "blobtag", "blobtag", &orphan]);

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None)
            .expect("an annotated tag of a blob no longer fails the whole walk");
        assert!(
            withheld.contains(&orphan),
            "a blob reachable only via an ANNOTATED tag must be withheld — the ref's \
             own object type is `tag`, so only the peeled referent puts it in the deny \
             set, while `git rev-list --objects --all` (which DOES peel tags) serves it"
        );
    }

    /// #218 review round 8 P1: the peel must survive a NESTED annotated tag
    /// (tag -> tag -> blob). Stock git's `%(*objectname)` peels the whole chain,
    /// so this covers the shipped behavior; the fake-git twin below covers a git
    /// that peels only one level.
    #[test]
    fn skips_a_nested_annotated_tag_of_a_blob() {
        let (_td, bare, _secret, _public) = fixture();
        let orphan = orphan_blob(&bare, "TOP SECRET, nested-tag-only\n");
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
        run(&["tag", "-a", "-m", "inner", "blobtag-inner", &orphan]);
        run(&["tag", "-a", "-m", "outer", "blobtag-outer", "blobtag-inner"]);
        // Only the outer tag stays a ref, so the blob is reachable exclusively
        // through a two-level tag chain.
        run(&["tag", "-d", "blobtag-inner"]);

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, None)
            .expect("a nested annotated tag of a blob must not fail the walk closed");
        assert!(
            withheld.contains(&orphan),
            "a blob behind a tag-of-a-tag must be withheld: `rev-list --objects --all` \
             peels the whole chain and serves it, so the deny set has to as well"
        );
    }

    /// #218 review round 8 P1: drives the one-level-peel fallback that stock git
    /// (2.50) never reaches. A fake git answers `for-each-ref` with a peeled type
    /// of `tag` — the shape `push_delta.rs`'s ref-type guard documents — and the
    /// walk must finish the peel via `rev-parse <oid>^{}` + `cat-file -t` and
    /// withhold the final blob, rather than bail and 500 the clone.
    #[cfg(unix)]
    #[test]
    fn peels_a_tag_whose_peeled_target_is_still_a_tag() {
        let tmp = TempDir::new().unwrap();
        let outer = "1111111111111111111111111111111111111111";
        let inner = "2222222222222222222222222222222222222222";
        let blob = "3333333333333333333333333333333333333333";
        // rev-parse: HEAD probe must FAIL (exit 1) so the walk skips it, but the
        // `^{}` full peel must answer with the blob. `rev-list` lists no commits,
        // so phase 1 contributes nothing and the OID can only arrive via phase 2.
        let body = format!(
            "#!/bin/sh\ncase \"$1\" in\n  \
             rev-parse) case \"$2\" in --verify) exit 1 ;; *) echo {blob} ;; esac ;;\n  \
             rev-list) : ;;\n  \
             for-each-ref) echo {outer} tag {inner} tag ;;\n  \
             cat-file) echo blob ;;\n  \
             *) : ;;\nesac\nexit 0\n"
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        let rules = [rule("/secret/**", &[])];
        let withheld = withheld_blob_oids_bounded(
            tmp.path(),
            &git_bin,
            Duration::from_secs(10),
            &rules,
            true,
            OWNER,
            None,
        )
        .expect("a still-a-tag peel must be resolved, not bailed on");
        assert!(
            withheld.contains(blob),
            "under a git that peels only one level, the walk must finish the peel \
             itself and withhold the final blob"
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

    /// #218 review round 9 (guidance #1 — single fail-closed
    /// classification contract): for every non-commit ref shape the
    /// parser can produce, the FOUR consumers of `(oid, path)` —
    /// smart-HTTP deny set (`withheld_blob_oids_bounded`),
    /// `/ipfs/{cid}` allow set
    /// (`allowed_blob_set_for_caller_bounded`), reconciliation
    /// object set (`allowed_blob_tree_sets_bounded`), and encrypted
    /// recovery (`withheld_blob_recipients_bounded`) — must agree
    /// on the OID's classification for every caller identity.
    /// Drift between consumers is a leak.
    ///
    /// The matrix is the canonical record: a regression in
    /// `pair_decision`, a re-introduced `!path.is_empty()` skip
    /// guard, or a wire-shape mismatch between the consumers fails
    /// one row of the table at the cargo-test level, with a name
    /// that points at the offending consumer.
    #[test]
    fn ref_classification_is_consistent_across_consumers() {
        // Build a single bare repo with one secret blob reachable
        // through every non-commit ref shape the parser produces:
        //   * direct blob ref (lightweight tag of a blob)
        //   * direct tree ref (lightweight tag of a tree)
        //   * annotated tag of a blob
        //   * annotated tag of a tree
        //   * nested tag (tag-of-tag-of-blob)
        // The blob OID and tree OID are distinct so the consumers
        // can disambiguate. The blob is NOT committed anywhere, so
        // phase 1 (`rev-list --all` + `ls-tree`) does not see it —
        // every entry in the `(oid, path)` set arrives through
        // phase 2 (`for-each-ref`) with an empty path.
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
        // Init the bare first so the orphaned blobs can be written
        // into its object store before any commit exists.
        run(&["init", "-q", "--bare", bare.to_str().unwrap()], td.path());
        // An annotated tag is a tag OBJECT, with a tagger header,
        // and `git tag -a` refuses to create one without a
        // configured user.email/user.name — even on a bare repo.
        // The bare is where the test's refs live, so set the
        // tagger identity there directly.
        run(&["config", "user.email", "t@t"], &bare);
        run(&["config", "user.name", "t"], &bare);
        run(&["init", "-q"], &work);
        run(&["config", "user.email", "t@t"], &work);
        run(&["config", "user.name", "t"], &work);

        // P2 (reviewer round 9): each ref shape must carry its
        // OWN blob, not all share one OID. Sharing one blob
        // meant deleting any single phase-2 classification arm
        // left every consumer green. The tree here is reused
        // because both the direct-tree and annotated-tree
        // branches share a `mktree`, but each leaf blob is
        // unique to its ref shape.
        //
        // Direct blob ref: hash-object, then update-ref to a ref
        // tip that points at the loose blob (not a commit).
        // `withheld_blob_oids` walks the BARE repo, so the ref
        // must be created on the bare — `update-ref` on the work
        // tree would put it in a refs file the walk never reads.
        let direct_blob = make_blob(&bare, b"DIRECT BLOB\n");
        run(
            &["update-ref", "refs/tags/direct-blob", &direct_blob],
            &bare,
        );

        // Direct tree ref: a tree object, then a ref tip pointing
        // at the tree. `git mktree` materialises the tree. The
        // tree contains `direct_blob` as its single entry; the
        // tree's OID is the only thing the ref points at, so the
        // blob is reachable ONLY through the tree walk.
        let tree_oid = {
            use std::io::Write;
            use std::process::Stdio;
            let out = Command::new("git")
                .args(["mktree"])
                .current_dir(&bare)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .and_then(|mut c| {
                    c.stdin
                        .take()
                        .unwrap()
                        .write_all(format!("100644 blob {direct_blob}\ttree-blob\n").as_bytes())?;
                    c.wait_with_output()
                })
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        run(&["update-ref", "refs/tags/direct-tree", &tree_oid], &bare);

        // Annotated tag of a blob: each annotated tag wraps its
        // OWN blob so a missing peel-arm is observable.
        let annotated_blob = make_blob(&bare, b"ANNOTATED BLOB\n");
        run(
            &[
                "tag",
                "-a",
                "-m",
                "annotated-blob",
                "tagged-blob",
                &annotated_blob,
            ],
            &bare,
        );

        // Annotated tag of a tree: the tree's children are
        // `annotated_blob` (NOT `direct_blob`), so a missing
        // tree-walk arm under the annotated-tag-of-tree path
        // would let `annotated_blob` leak.
        let annotated_tree = {
            use std::io::Write;
            use std::process::Stdio;
            let out = Command::new("git")
                .args(["mktree"])
                .current_dir(&bare)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .and_then(|mut c| {
                    c.stdin.take().unwrap().write_all(
                        format!("100644 blob {annotated_blob}\ttree-blob\n").as_bytes(),
                    )?;
                    c.wait_with_output()
                })
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        run(
            &[
                "tag",
                "-a",
                "-m",
                "annotated-tree",
                "tagged-tree",
                &annotated_tree,
            ],
            &bare,
        );

        // Nested tag (tag-of-tag-of-blob): a tag of a tag, with
        // its own unique blob so a missing recursive-peel arm
        // is observable.
        let nested_blob = make_blob(&bare, b"NESTED BLOB\n");
        run(
            &[
                "tag",
                "-a",
                "-m",
                "nested-blob",
                "tagged-nested-blob",
                &nested_blob,
            ],
            &bare,
        );
        run(
            &["tag", "-a", "-m", "outer", "outer", "tagged-nested-blob"],
            &bare,
        );

        // P2 (reviewer round 9): the rule carries a reader DID
        // so the encrypted-recovery consumer 4 can observe a
        // non-owner recipient. The previous `caller.unwrap_or("??")`
        // always matched against `"??"`, which is not in
        // `reader_dids`, so the assertion held for any
        // implementation. With a real reader DID in the rule
        // and `caller = Some(reader)`, the assertion now
        // exercises the actual contract.
        const READER: &str = "did:key:z6MkReaderrrrrrrrrrrrrrrrrrrrrrrrr";
        let rules = [rule("/secret/**", &[READER])];

        // P2 (reviewer round 9): consumer 4 (encrypted-recovery
        // recipients) is a single invariant — "owner is in the
        // recipients, reader/anon is not" — that does NOT vary
        // per ref shape. Hoist it OUT of the per-shape loop so
        // deleting a phase-2 arm (which would only fail
        // consumer 1 for one of the three ref shapes) cannot
        // make consumer 4 silently pass.
        //
        // Run all four consumers, but only consumer 1 runs
        // once per ref shape; consumers 2, 3, 4 run once per
        // caller. Consumers 2 and 3 use the direct_blob (the
        // simplest unclassifiable target); consumer 4 uses the
        // direct_blob so the assertion targets one specific
        // OID and the recipient map is unambiguous.
        for caller in [None, Some(READER), Some(OWNER)] {
            let label = format!("caller={caller:?}");

            // 1. Smart-HTTP deny set: per ref shape, the OID
            //    must be withheld iff the caller is not the
            //    owner. The cross-shape assertion: each shape
            //    independently withholds (or admits, for the
            //    owner) its OWN OID, so a missing peel-arm
            //    would let a different shape's blob through.
            let withheld = withheld_blob_oids(&bare, &rules, true, OWNER, caller).unwrap();
            for (label_inner, oid) in [
                ("direct-blob", &direct_blob),
                ("annotated-blob", &annotated_blob),
                ("nested-tag-blob", &nested_blob),
            ] {
                let in_withheld = withheld.contains(oid);
                let expected = !matches!(caller, Some(c) if c == OWNER);
                assert_eq!(
                    in_withheld, expected,
                    "[{label}] smart-HTP deny for {label_inner}: expected withheld={expected}, got {in_withheld}"
                );
            }
            // Direct tree and annotated tree: the smart-HTP deny
            // set names this function "blob OIDs" but in fact
            // `blob_paths` enumerates ANY non-commit ref target,
            // so a tree is in the set the same way a blob is. The
            // `pair_decision` empty-path policy applies uniformly:
            // withheld for non-owners, Allow for the owner. The
            // structural consumer `allowed_blob_tree_sets_bounded`
            // is the one that splits blobs and trees — the smart
            // HTP gate treats both as opaque withheld OIDs.
            let expected = !matches!(caller, Some(c) if c == OWNER);
            assert_eq!(
                withheld.contains(&tree_oid),
                expected,
                "[{label}] smart-HTP deny for the unclassifiable tree: expected withheld={expected}"
            );
            assert_eq!(
                withheld.contains(&annotated_tree),
                expected,
                "[{label}] smart-HTP deny for the annotated tag's tree: expected withheld={expected}"
            );

            // 2. /ipfs/{cid} allow set: the direct_blob must be
            //    in the allow set iff the caller is the owner
            //    (owner-only carve-out for unclassifiable ref
            //    targets). This consumer is caller-invariant;
            //    hoist the shape variation out of the per-shape
            //    loop so a regression in only this consumer is
            //    visible to the test.
            let allowed = allowed_blob_set_for_caller(&bare, &rules, true, OWNER, caller).unwrap();
            let expected = matches!(caller, Some(c) if c == OWNER);
            assert_eq!(
                allowed.contains(&direct_blob),
                expected,
                "[{label}] /ipfs/{{cid}} allow set for the unclassifiable blob: \
                 expected in set = {expected}"
            );

            // 3. Reconciliation object set: same allow-set shape
            //    as /ipfs/{cid} (with caller = None baked in), so
            //    the unclassifiable blob is DENIED — the sweep
            //    never pins it. This is the cross-consumer
            //    assertion: the /ipfs/{cid} gate and the sweep
            //    agree on what the anonymous allow set contains.
            use std::time::Instant;
            let (rec_allowed_blobs, _rec_allowed_trees, _, _) = allowed_blob_tree_sets_bounded(
                &bare,
                "git",
                Instant::now() + WALK_TIMEOUT,
                &rules,
                true,
                OWNER,
            )
            .unwrap();
            assert!(
                !rec_allowed_blobs.contains(&direct_blob),
                "[{label}] reconciliation allow-set (caller = None) must NOT include \
                 the unclassifiable blob; the sweep never pins an empty-path blob to anon"
            );
        }

        // Consumer 4: encrypted-recovery recipients. The owner
        // sees `direct_blob` in the recipients (the owner
        // encrypts+pins for self). The anon caller must NOT
        // see it. The reader caller is in `reader_dids` and
        // also must NOT see it (the rule's allow shape is
        // "owner only for the unclassifiable ref" — the
        // reader DID is irrelevant to the empty-path decision;
        // the previous `caller.unwrap_or("??")` always passed
        // because `"??"` is not in any list, so the assertion
        // was vacuous). Use `Some(reader)` to exercise the
        // actual contract.
        let recipients = withheld_blob_recipients(&bare, &rules, true, OWNER).unwrap();

        // P2 (reviewer round 9): the recipient set is
        // CALLER-INVARIANT — it enumerates every identity
        // (owner + every rule's reader DID) that the
        // path-decision allows for THIS OID. Whether a given
        // caller can decrypt the seal is a separate question
        // answered at seal time (the seal checks membership in
        // the recipient set). The test asserts the recipient
        // set shape, not the seal-time check, because the
        // seal is a separate code path tested elsewhere.
        //
        // The contract the test pins:
        //   - The owner is in the recipient set (the owner
        //     encrypts+pins for self).
        //   - The empty-string anon sentinel is NOT in the
        //     recipient set (anon does not decrypt anything
        //     from the seal; the empty path is owner-only).
        //   - A reader DID listed on a rule whose path does
        //     not match the empty path is NOT in the recipient
        //     set (the pair_decision empty-path allow shape
        //     is owner-only; the reader is on a path-scoped
        //     rule that does not match the empty path, so the
        //     seal cannot leak `direct_blob` to the reader
        //     through the empty path).
        let direct_recipients = recipients.get(&direct_blob).cloned().unwrap_or_default();
        assert!(
            direct_recipients.contains(OWNER),
            "owner must be in encrypted-recovery recipients for direct_blob; \
             got {direct_recipients:?}"
        );
        assert!(
            !direct_recipients.iter().any(|d| d.is_empty()),
            "the empty-string anon sentinel must not be a recipient of direct_blob; \
             got {direct_recipients:?}"
        );
        assert!(
            !direct_recipients.iter().any(|d| d == READER),
            "a reader DID on a path-scoped rule that does not match the empty path must \
             not be a recipient of direct_blob (empty-path allow shape is owner-only); \
             got {direct_recipients:?}"
        );
    }
}
