use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// Owns the served-git admission permits (global + per-source) for the lifetime of
/// the work they admitted, so admission is released only when that work is truly
/// done — not the instant the handler future drops on a client disconnect.
///
/// A move-only wrapper: no methods beyond construction and `Drop`. The handler
/// MOVEs its permits in and keeps no copy (a retained copy would drop early and
/// release admission the moment the future is dropped, defeating the guard). It is
/// threaded into `drive_git_child`, whose [`KillGroupOnDrop`] moves it into the
/// detached reaper on disconnect, so both permits drop only after the process group
/// is confirmed reaped (`kill(-pgid,0)==ESRCH`) rather than while the group is still
/// alive holding PIDs past the concurrency cap (#174 P1-a, plain-spawn residual).
///
/// The `be0cdd6` path-scoped upload-pack walk already applies this discipline by
/// moving its permits into the `spawn_blocking`; this generalizes it to the plain
/// (non-path-scoped) `info_refs` / `run_git_service` spawn paths and, via the
/// hand-back contract on `drive_git_child`, across both stages of the filtered
/// (`upload_pack_excluding`) pack build (F1).
pub struct AdmissionGuard {
    // Boxed so the concrete permit types stay private to the caller (repos.rs) — the
    // guard only needs to hold them and drop them, never inspect them. `Send +
    // 'static` so the guard can move into the detached reaper task.
    _global: Option<Box<dyn Send + 'static>>,
    _caller: Option<Box<dyn Send + 'static>>,
}

impl AdmissionGuard {
    /// Take ownership of the global permit and an optional per-caller permit. Both are
    /// erased to `Box<dyn Send>` — the guard's only job is to hold them until it drops.
    pub fn new(global: impl Send + 'static, caller: Option<impl Send + 'static>) -> Self {
        Self {
            _global: Some(Box::new(global)),
            _caller: caller.map(|c| Box::new(c) as Box<dyn Send + 'static>),
        }
    }
}

/// Handle `GET /:owner/:repo/info/refs?service=git-upload-pack`
/// or `?service=git-receive-pack`
///
/// This is the ref advertisement — the first step of a clone or push.
///
/// `git_bin` is injectable purely so the process-group teardown can be driven by a
/// fake `git` in tests (production passes `"git"`). `timeout` bounds the whole child
/// interaction: previously the advertisement ran a bare `Command::output()` with no
/// deadline and no teardown, so a hung git pinned its concurrency slot indefinitely
/// and a client disconnect orphaned the child (#174). It now shares
/// [`drive_git_child`]'s timeout + `process_group(0)` + [`KillGroupOnDrop`] teardown.
pub async fn info_refs(
    git_bin: &str,
    service: &str,
    repo_path: &Path,
    timeout: Duration,
    admission: Option<AdmissionGuard>,
) -> Result<Response> {
    validate_service(service)?;

    let mut command = Command::new(git_bin);
    command
        .arg(service_to_command(service))
        .arg("--stateless-rpc")
        .arg("--advertise-refs")
        .arg(repo_path);
    // No request body — advertise-refs does not read stdin.
    let (stdout, admission) =
        drive_git_child(command, Bytes::new(), timeout, "advertise-refs", admission).await?;
    // Single-stage op: the advertisement's group is reaped by now; release admission
    // rather than holding it across the pure response framing below.
    drop(admission);

    let content_type = format!("application/x-{service}-advertisement");

    // Prepend the pkt-line service announcement
    let pkt_service = pkt_line(&format!("# service={service}\n"));
    let flush = b"0000";
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_service);
    body.extend_from_slice(flush);
    body.extend_from_slice(&stdout);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-cache")
        .header("X-Gitlawb-Node", "v0.1.0")
        .body(Body::from(body))?)
}

/// Handle `POST /:owner/:repo/git-upload-pack`
///
/// Serves pack data for a clone or fetch. This is stateless — the entire
/// negotiation happens in a single request/response.
pub async fn upload_pack(
    git_bin: &str,
    repo_path: &Path,
    request_body: Bytes,
    timeout: Duration,
    admission: Option<AdmissionGuard>,
) -> Result<Response> {
    let output = run_git_service(
        git_bin,
        "git-upload-pack",
        repo_path,
        request_body,
        timeout,
        admission,
    )
    .await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(output))?)
}

/// Handle `POST /:owner/:repo/git-receive-pack`
///
/// Accepts a push. The caller MUST verify HTTP Signature auth before
/// calling this function.
pub async fn receive_pack(
    git_bin: &str,
    repo_path: &Path,
    request_body: Bytes,
    timeout: Duration,
    admission: Option<AdmissionGuard>,
) -> Result<Response> {
    let output = run_git_service(
        git_bin,
        "git-receive-pack",
        repo_path,
        request_body,
        timeout,
        admission,
    )
    .await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-receive-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(output))?)
}

/// Sends SIGTERM to a child's whole process group on drop, unless disarmed first.
///
/// A served `git upload-pack`/`receive-pack` forks helpers such as `pack-objects`.
/// If the request future is dropped (client disconnect) or returns early, dropping
/// the tokio `Child` does not signal `git`; it lingers until EPIPE, and its
/// `pack-objects` child can reparent to PID 1 and never be reaped — a zombie that
/// accumulates until `fork()` fails with EAGAIN (#53). Spawning the child in its
/// own process group and signalling that group here tears the whole tree down at
/// the source. SIGTERM (not SIGKILL) lets `git` run its cleanup — notably removing
/// `.git/*.lock` files mid-`receive-pack` — before it exits, so an aborted push
/// can't leave a stale lock that blocks the next one. The guard is disarmed once
/// `wait_with_output()` returns, so a request that completed cleanly never signals.
#[cfg(unix)]
struct KillGroupOnDrop {
    // Holds the child + its pgid while armed. The interaction drives the child through
    // `child_mut()`; the success/timeout paths call `disarm` once they have reaped it.
    // On drop — a client disconnect that drops the whole request future — the guard
    // launches a detached reaper that OWNS the child and runs the full
    // SIGTERM -> grace -> SIGKILL -> reap sequence (`reap_group_on_timeout`), as strong
    // as the timeout path, so a SIGTERM-ignoring group member is SIGKILLed and reaped
    // rather than left running until EPIPE to accumulate past the concurrency cap
    // (#174 P1-c). Owning the tokio `Child` in the reaper (rather than a raw
    // `waitpid(-pgid)`) keeps a single reaper of the leader, so it never races tokio's
    // own SIGCHLD-driven orphan reaper.
    child: Option<tokio::process::Child>,
    pgid: Option<i32>,
    // The global + per-source admission permits for this op, if any. repos.rs moves
    // its permits in here (directly on the plain spawn paths, via the stage threading
    // on the filtered rev-list/pack-objects ones) so admission is released only when
    // the group is confirmed reaped, on every exit: complete, timeout, or
    // client-disconnect (#174 P1-a, F1). `None` when the op carries no admission
    // (e.g. the smart_http test harness).
    admission: Option<AdmissionGuard>,
}

#[cfg(unix)]
impl KillGroupOnDrop {
    /// The child, while armed. The interaction drives stdin/stdout/`wait` through this.
    fn child_mut(&mut self) -> &mut tokio::process::Child {
        self.child.as_mut().expect("child present while armed")
    }

    /// Disarm on the success/timeout path: the body has already reaped the child (its
    /// `wait()` returned, or `reap_group_on_timeout` ran), so drop the handle and clear
    /// the pgid, leaving the guard's Drop a no-op. Returns the admission guard: the
    /// group is already reaped on both callers of this, so the success path hands it
    /// back to drive_git_child's caller (a multi-stage build carries it to the next
    /// stage) and the timeout path drops it there and then.
    fn disarm(&mut self) -> Option<AdmissionGuard> {
        self.pgid = None;
        self.child = None;
        self.admission.take()
    }
}

#[cfg(unix)]
impl Drop for KillGroupOnDrop {
    fn drop(&mut self) {
        // Move any admission guard out first so it travels with the reaper (or drops
        // here on the no-child / no-runtime fallback), never before the group is gone.
        let admission = self.admission.take();
        let (Some(mut child), Some(pgid)) = (self.child.take(), self.pgid) else {
            // Nothing to reap (already disarmed); dropping `admission` here is correct —
            // the group is already gone.
            return;
        };
        // A sync Drop cannot await, so launch a detached reaper that owns the child and
        // runs the same teardown as the timeout path (TERM -> grace -> SIGKILL -> reap
        // the whole group). Owning the tokio `Child` means this task is the sole reaper
        // of the leader, so it cannot race tokio's orphan reaper. Prefer the current
        // runtime handle; if dropped outside a runtime, fall back to a best-effort
        // synchronous SIGTERM so the group is at least signalled.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    reap_group_on_timeout(&mut child).await;
                    // Release admission only now: the group is ESRCH-confirmed gone (or
                    // hit the ~4s D-state hard cap, past which nothing in userspace can
                    // free the PIDs anyway). Holding the permits until here is what
                    // stops disconnect-spam from admitting replacements while the prior
                    // group is still alive (#174 P1-a). `admission` is moved in and
                    // dropped when this closure ends.
                    drop(admission);
                });
            }
            Err(_) => {
                // SAFETY: kill(2) takes only integers and borrows no Rust memory;
                // ESRCH on an already-gone group is ignored.
                unsafe {
                    libc::kill(-pgid, libc::SIGTERM);
                }
                // No runtime to await the reap; drop admission best-effort after the
                // synchronous signal (the fallback path is not on the hot request path).
                drop(admission);
            }
        }
    }
}

/// Error returned when [`run_git_service`] aborts a git op on its timeout.
///
/// Carried through the `anyhow` chain so the HTTP handler can `downcast_ref` it
/// and map to 504 Gateway Timeout, distinct from the generic 500 git error.
#[derive(Debug, thiserror::Error)]
#[error("git service timed out")]
pub struct GitServiceTimeout;

/// On a served-git timeout, tear the process group down AND reap the leader
/// before returning, so a caller that releases a write lock (receive-pack) can't
/// race a still-live git touching the same repo. SIGTERM first (lets git remove
/// its `.git/*.lock` files), escalate to SIGKILL if the leader lingers past a
/// grace, then reap. Bounded, so a git that ignores SIGTERM can't block the
/// response unboundedly.
#[cfg(unix)]
async fn reap_group_on_timeout(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else {
        // Never got a pid; nothing to signal, best-effort reap.
        let _ = child.wait().await;
        return;
    };
    let pgid = pid as i32;
    // SAFETY: kill(2) takes only integers and borrows no Rust memory; ESRCH on an
    // already-gone group is ignored.
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    // Wait for the WHOLE group to exit before returning — not just the leader but
    // grandchildren (index-pack / pack-objects) that reparent to init and can
    // still be touching the repo, so a caller releasing a write lock can't race
    // them. Reap our direct child along the way (`try_wait`, else it lingers as a
    // zombie) and poll the group's liveness with `kill(-pgid, 0)` (ESRCH once
    // every member is gone). SIGTERM grace, then SIGKILL, then a hard cap so a
    // stuck process can never block the response unboundedly.
    for step in 0..400u32 {
        let _ = child.try_wait();
        if unsafe { libc::kill(-pgid, 0) } != 0 {
            return; // ESRCH: every group member has exited
        }
        if step == 200 {
            // ~2s SIGTERM grace elapsed; force the group down. `step == 200` fires
            // exactly once in the 0..400 loop, so no re-entry guard is needed.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // ~4s hard cap. Only reached if a group member survives SIGKILL, which means
    // it is wedged in uninterruptible (D-state) I/O — a fsync on stuck storage, a
    // hung mount — that no signal interrupts until the kernel returns. Nothing in
    // userspace can kill it; blocking here (or holding the write lock) would just
    // re-create the "hung git pins the repo" problem this bounds. Reap best-effort
    // (tokio's orphan reaper collects it once the syscall unblocks) and return;
    // git-level quarantine/ref-locking still guards the brief window before the
    // D-state process finishes.
    tracing::warn!(
        pid,
        "served git survived SIGKILL past the teardown cap (uninterruptible I/O?); \
         releasing without a confirmed group reap"
    );
    let _ = child.try_wait();
}

/// Run a stateless-rpc git service and return its stdout.
///
/// `git_bin` is the git executable to spawn; production callers pass `"git"`
/// (resolved via `PATH`). It is injectable purely so the process-group teardown
/// wiring (`process_group(0)` + [`KillGroupOnDrop`]) can be driven end-to-end by
/// a fake `git` in tests without mutating the process-global `PATH`.
///
/// `timeout` bounds the whole child interaction; on expiry the op is aborted with
/// [`GitServiceTimeout`] and its process group is torn down.
async fn run_git_service(
    git_bin: &str,
    service: &str,
    repo_path: &Path,
    input: Bytes,
    timeout: Duration,
    admission: Option<AdmissionGuard>,
) -> Result<Vec<u8>> {
    let mut command = Command::new(git_bin);
    command
        .arg(service_to_command(service))
        .arg("--stateless-rpc")
        .arg(repo_path);
    let (out, admission) = drive_git_child(command, input, timeout, service, admission).await?;
    // Single-stage op: the child group is already reaped when drive_git_child
    // returns, so releasing admission here keeps the permits held exactly for the
    // process lifetime, no longer.
    drop(admission);
    Ok(out)
}

/// Drive a spawned git child under `timeout` with process-group teardown, returning
/// its stdout together with the admission guard. Shared core for
/// [`run_git_service`], [`info_refs`], and the filtered-pack stages: the caller
/// passes a `Command` with its args set; this adds piped stdio and `process_group(0)`.
/// On the deadline the whole group is torn down and reaped before returning
/// [`GitServiceTimeout`]; on a dropped future (client disconnect) the
/// [`KillGroupOnDrop`] guard fires. `input` is written to the child's stdin (empty
/// for the advertise-refs path, which has no request body); `what` labels errors.
///
/// Admission contract: on success the guard is handed BACK so a multi-stage caller
/// (the filtered-pack build) can carry one admission across consecutive children
/// instead of releasing it between stages. On every Err return (timeout, spawn
/// failure, interaction error, non-zero exit) the guard is dropped internally, and
/// only after the child is reaped: an Err cannot carry the guard, and by then the
/// group is confirmed gone, so releasing admission there is correct.
async fn drive_git_child(
    mut command: Command,
    input: Bytes,
    timeout: Duration,
    what: &str,
    admission: Option<AdmissionGuard>,
) -> Result<(Vec<u8>, Option<AdmissionGuard>)> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Run git in its own process group so the whole tree (git + pack-objects)
    // can be signalled together on disconnect rather than orphaning a grandchild.
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn()?;

    // Own the pipes so the child stays reap-able: wait_with_output would consume it,
    // but on a timeout we must actively reap the group first (see
    // reap_group_on_timeout), and on a disconnect the guard's detached reaper does.
    // Take the pipes before the child moves into the guard below.
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().context("git stdout was not piped")?;
    let mut stderr = child.stderr.take().context("git stderr was not piped")?;

    // Arm the group-kill guard for the lifetime of the request. With process_group(0)
    // the child is its own group leader, so pgid == its pid. On a client disconnect
    // (the whole future is dropped mid-request) the guard's Drop launches a detached
    // reaper that OWNS the child and runs the full TERM/grace/SIGKILL/reap — as strong
    // as the timeout path below (#174 P1-c). The guard owns the child; the interaction
    // drives it through `child_mut()`.
    #[cfg(unix)]
    let pgid = child.id().map(|id| id as i32);
    #[cfg(unix)]
    let mut group_guard = KillGroupOnDrop {
        child: Some(child),
        pgid,
        admission,
    };
    // On non-unix there is no process-group teardown; the `admission` parameter
    // itself stays live for the child's whole interaction (nothing moves it until
    // the match below), so the success path hands it back like the unix path and
    // the timeout path drops it after the child is waited on.

    let mut out = Vec::new();
    let mut err = Vec::new();

    // Bound the whole child interaction: a git that neither finishes nor
    // disconnects would otherwise pin the pid forever. Write stdin, drain stdout
    // and stderr, and wait for the child all concurrently (draining while writing
    // avoids a pipe deadlock on a large body), under one deadline.
    let interact = async {
        // Don't early-return on a write error: the join still waits on the child,
        // so an error is surfaced only after the child has been waited on.
        let write = async {
            match stdin.take() {
                Some(mut s) => s.write_all(&input).await,
                None => Ok(()),
            }
        };
        #[cfg(unix)]
        let child_ref = group_guard.child_mut();
        #[cfg(not(unix))]
        let child_ref = &mut child;
        let (write_result, r_out, r_err, status) = tokio::join!(
            write,
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err),
            child_ref.wait(),
        );
        r_out?;
        r_err?;
        Ok::<_, anyhow::Error>((write_result, status?))
    };

    let timed = tokio::time::timeout(timeout, interact).await;
    let (write_result, status, admission) = match timed {
        Ok(result) => {
            // The join runs all arms to completion, so the child is reaped: disarm
            // before surfacing any interaction error (a read/wait error), else the
            // guard's drop would reap an already-reaped child / signal a reused pgid.
            // Disarming hands the admission guard back; it rides to the Ok return
            // below, and every error return between here and there drops it, always
            // AFTER the reap, the earliest provably-free point.
            #[cfg(unix)]
            let admission = group_guard.disarm();
            let (write_result, status) = result?;
            (write_result, status, admission)
        }
        Err(_elapsed) => {
            // Timeout: tear the whole group down and reap it before returning so a
            // caller releasing a write lock can't race a still-live git. Then disarm
            // the (now redundant) guard so its drop can't hit a reused pgid. The
            // returned admission guard drops here, AFTER the group is confirmed reaped.
            #[cfg(unix)]
            {
                reap_group_on_timeout(group_guard.child_mut()).await;
                drop(group_guard.disarm());
            }
            #[cfg(not(unix))]
            {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                drop(admission);
            }
            return Err(GitServiceTimeout.into());
        }
    };

    // Surface git's own failure (its stderr, which the handler may classify as a
    // 400) before any stdin-write error: when git rejects a malformed body it
    // exits non-zero and closes stdin, so the write's EPIPE would otherwise mask
    // the real cause. `admission` drops on these error returns; the child is
    // already reaped by the completed join above.
    if !status.success() {
        let stderr = String::from_utf8_lossy(&err);
        bail!("{what} failed: {stderr}");
    }

    write_result.context("failed to write to git stdin")?;

    Ok((out, admission))
}

fn service_to_command(service: &str) -> &str {
    match service {
        "git-upload-pack" => "upload-pack",
        "git-receive-pack" => "receive-pack",
        _ => service,
    }
}

fn validate_service(service: &str) -> Result<()> {
    match service {
        "git-upload-pack" | "git-receive-pack" => Ok(()),
        other => bail!("unknown git service: {other}"),
    }
}

/// Encode a string as a git pkt-line.
/// Format: 4-byte hex length (including the 4 bytes itself) + data
fn pkt_line(data: &str) -> Vec<u8> {
    let len = data.len() + 4;
    format!("{len:04x}{data}").into_bytes()
}

/// Run `rev-list --objects --all` under `timeout` and return the reachable object
/// ids minus the withheld blobs. Runs under [`drive_git_child`] (async, with the
/// `tokio::time::timeout` + `process_group(0)` + [`KillGroupOnDrop`] teardown), so a
/// hung/slow enumeration is duration-bounded and reaped on client disconnect just
/// like the pack-objects stage. A bare blocking `Command::output()` inside a
/// `spawn_blocking` is uncancellable, so a hung rev-list would pin the endpoint's
/// concurrency permit for the whole hang (#174). `git_bin` is injectable for the
/// same fake-git testing reason as `run_git_service`.
async fn rev_list_keep(
    git_bin: &str,
    repo_path: &Path,
    withheld: &HashSet<String>,
    timeout: Duration,
    admission: Option<AdmissionGuard>,
) -> Result<(Vec<String>, Option<AdmissionGuard>)> {
    let mut command = Command::new(git_bin);
    command
        .args(["rev-list", "--objects", "--all"])
        .current_dir(repo_path);
    // The filtered-serve caller's admission rides through drive_git_child so a
    // disconnect mid-enumeration keeps the permits held until the rev-list group is
    // reaped; on success the guard comes back for the pack-objects stage (F1).
    let (stdout, admission) =
        drive_git_child(command, Bytes::new(), timeout, "rev-list", admission).await?;
    let mut keep = Vec::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        let oid = line.split_whitespace().next().unwrap_or("");
        if oid.is_empty() || withheld.contains(oid) {
            continue;
        }
        keep.push(oid.to_string());
    }
    Ok((keep, admission))
}

/// Build a packfile containing every object reachable from all refs EXCEPT the
/// given blob OIDs. Commits and trees are always included, so SHAs stay intact;
/// only the named blobs are dropped.
///
/// Both git stages — the `rev-list` enumeration and the streaming `pack-objects`
/// build — run under [`drive_git_child`] sharing one deadline, so a hung/slow git at
/// either stage is duration-bounded and its process group is reaped on client
/// disconnect. An outer `tokio::time::timeout` around a `spawn_blocking` cannot
/// cancel the blocking thread, so neither stage may live off the async side
/// (#174, KTD5).
///
/// `admission` carries the filtered-serve permits across BOTH stages: stage 1 hands
/// it back on success, stage 2 takes it, and the caller receives it after stage 2 so
/// release happens only once the last child group is reaped. On a disconnect the
/// guard rides the active stage's detached reaper instead of dropping with the
/// future (F1). A stage that fails or times out (including a stage 2 whose
/// remaining budget has saturated to zero) drops the guard inside drive_git_child,
/// after that stage's reap.
pub async fn build_filtered_pack(
    git_bin: &str,
    repo_path: &Path,
    withheld: &HashSet<String>,
    timeout: Duration,
    admission: Option<AdmissionGuard>,
) -> Result<(Vec<u8>, Option<AdmissionGuard>)> {
    // One deadline spans both git stages so a slow rev-list eats into the pack
    // budget rather than granting each stage a fresh `timeout` (2x the permit hold).
    let deadline = Instant::now() + timeout;
    let (keep, admission) = rev_list_keep(
        git_bin,
        repo_path,
        withheld,
        deadline.saturating_duration_since(Instant::now()),
        admission,
    )
    .await?;
    let mut data = keep.join("\n").into_bytes();
    data.push(b'\n');
    let mut command = Command::new(git_bin);
    command
        .args(["pack-objects", "--stdout"])
        .current_dir(repo_path);
    drive_git_child(
        command,
        Bytes::from(data),
        deadline.saturating_duration_since(Instant::now()),
        "pack-objects",
        admission,
    )
    .await
}

/// Serve a clone/fetch with the withheld blobs removed from the response pack.
///
/// The framing is git protocol v0 (`NAK` then the pack), matching the v0 ref
/// advertisement that `info_refs` emits (it runs `git upload-pack
/// --advertise-refs` without `GIT_PROTOCOL=version=2`, so clients negotiate v0).
/// If `info_refs` ever advertises v2, this serve path must learn v2 framing too.
///
/// Because the pack deliberately omits blobs that the sent trees still
/// reference, the pack is not closed under reachability. A stock full clone
/// rejects it at fetch time ("remote did not send all necessary objects"); only
/// a partial clone (the client passes `--filter`, marking a promisor remote)
/// accepts the pack with the private blobs absent. Tree and commit SHAs stay
/// intact either way. The clean partial-clone client UX is a separate follow-up
/// (git-remote-gitlawb); the security guarantee (private bytes never leave the
/// node) holds regardless of client.
///
/// Negotiation is intentionally ignored: rather than honoring the client's
/// `want`/`have` lines, this always sends a self-contained pack of every object
/// across all refs minus the withheld blobs, and replies `NAK`. A fresh clone
/// and an incremental fetch are both correct (the client de-duplicates objects
/// it already has); the cost is that a fetch re-sends the full object set
/// instead of a thin delta. Honoring negotiation for smaller fetch packs is an
/// optimization follow-up, not a correctness requirement.
pub async fn upload_pack_excluding(
    git_bin: &str,
    repo_path: &Path,
    request_body: Bytes,
    withheld: &HashSet<String>,
    timeout: Duration,
    admission: Option<AdmissionGuard>,
) -> Result<Response> {
    // Both filtered-pack stages run async under drive_git_child (duration-bounded,
    // process group reaped on disconnect, #174), and `admission` threads through
    // them so the caller's permits release only after the active stage's group is
    // reaped, never the instant a disconnect drops this future (F1). `git_bin` is
    // injectable for the same fake-git testing reason as `run_git_service`
    // (production passes the configured git binary).
    let (pack, admission) =
        build_filtered_pack(git_bin, repo_path, withheld, timeout, admission).await?;
    // Both git stages are done and their groups reaped; release admission before the
    // pure in-memory response framing below.
    drop(admission);

    // The client lists its capabilities on the first `want` line. Honor
    // side-band-64k when offered (every modern smart-HTTP client offers it);
    // otherwise stream the raw pack after NAK.
    let sideband = memmem(&request_body, b"side-band-64k");

    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line("NAK\n"));
    if sideband {
        // Band 1 carries pack data, chunked under the pkt-line size limit.
        for chunk in pack.chunks(65515) {
            let mut framed = Vec::with_capacity(chunk.len() + 1);
            framed.push(0x01);
            framed.extend_from_slice(chunk);
            let len = framed.len() + 4;
            body.extend_from_slice(format!("{len:04x}").as_bytes());
            body.extend_from_slice(&framed);
        }
        body.extend_from_slice(b"0000");
    } else {
        body.extend_from_slice(&pack);
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-git-upload-pack-result")
        .header("Cache-Control", "no-cache")
        .body(Body::from(body))?)
}

/// True if `needle` occurs anywhere in `haystack`. Small substring scan used to
/// detect a client capability token in the upload-pack request body.
fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    /// List OIDs in a pack by writing it to a temp dir and running verify-pack.
    pub(super) fn pack_object_ids(pack: &[u8]) -> std::collections::HashSet<String> {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.pack");
        std::fs::write(&path, pack).unwrap();
        // index-pack creates the matching .idx next to the pack.
        let ok = Command::new("git")
            .args(["index-pack", path.to_str().unwrap()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "index-pack failed");
        let out = Command::new("git")
            .args(["verify-pack", "-v", path.to_str().unwrap()])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|t| t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|s| s.to_string())
            .collect()
    }

    #[tokio::test]
    async fn filtered_serve_excludes_withheld_blob() {
        // Build a bare repo, capture the secret + public blob OIDs.
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let g = |args: &[&str], dir: &std::path::Path| {
            assert!(Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
        };
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"pub\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"SECRET\n").unwrap();
        g(&["init", "-q"], &work);
        g(&["config", "user.email", "t@t"], &work);
        g(&["config", "user.name", "t"], &work);
        g(&["add", "."], &work);
        g(&["commit", "-qm", "init"], &work);
        let oid = |p: &str| {
            let o = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{p}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let secret = oid("secret/b.txt");
        let public = oid("public/a.txt");
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

        let mut withheld = std::collections::HashSet::new();
        withheld.insert(secret.clone());

        let (pack, _admission) =
            build_filtered_pack("git", &bare, &withheld, Duration::from_secs(30), None)
                .await
                .unwrap();
        let ids = pack_object_ids(&pack);
        assert!(ids.contains(&public), "public blob must be in the pack");
        assert!(
            !ids.contains(&secret),
            "secret blob must NOT be in the pack"
        );
    }

    #[tokio::test]
    async fn client_clone_lacks_withheld_blob_bytes() {
        use axum::body::to_bytes;
        let td = TempDir::new().unwrap();
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        let g = |args: &[&str], dir: &std::path::Path| {
            assert!(Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success());
        };
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"pub\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"SECRET\n").unwrap();
        g(&["init", "-q"], &work);
        g(&["config", "user.email", "t@t"], &work);
        g(&["config", "user.name", "t"], &work);
        g(&["add", "."], &work);
        g(&["commit", "-qm", "init"], &work);
        let oid = |p: &str| {
            let o = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{p}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let secret_oid = oid("secret/b.txt");
        let public_oid = oid("public/a.txt");
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

        let mut withheld = std::collections::HashSet::new();
        withheld.insert(secret_oid.clone());

        // A realistic v0 request advertises side-band-64k, so the serve frames
        // the pack in band 1 (the path real clients exercise).
        let req = Bytes::from_static(
            b"0098want 0000000000000000000000000000000000000000 \
              side-band-64k ofs-delta agent=git/2\n00000009done\n",
        );
        let resp =
            upload_pack_excluding("git", &bare, req, &withheld, Duration::from_secs(30), None)
                .await
                .unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let ids = pack_object_ids(&extract_pack(&body));
        assert!(
            ids.contains(&public_oid),
            "public blob must be present in served pack"
        );
        assert!(
            !ids.contains(&secret_oid),
            "withheld blob must be absent from served pack"
        );
    }

    /// Strip the v0 upload-pack framing (NAK line + sideband-64k bands),
    /// returning the raw pack. Mirrors how a client de-frames the band-1 stream.
    fn extract_pack(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= body.len() {
            let len =
                usize::from_str_radix(std::str::from_utf8(&body[i..i + 4]).unwrap_or("0000"), 16)
                    .unwrap_or(0);
            if len == 0 {
                i += 4;
                continue;
            }
            let chunk = &body[i + 4..i + len];
            // band 1 = pack data; skip the NAK line and any other bands.
            if chunk.first() == Some(&0x01) {
                out.extend_from_slice(&chunk[1..]);
            }
            i += len;
        }
        out
    }

    // Shared harness for the real-git server tests: a minimal smart-HTTP server
    // backed by the real info_refs + upload_pack_excluding.

    #[derive(Clone)]
    struct FilterState {
        repo: std::path::PathBuf,
        withheld: HashSet<String>,
    }

    async fn refs_handler(
        axum::extract::State(st): axum::extract::State<std::sync::Arc<FilterState>>,
        axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
    ) -> Response {
        let service = q.get("service").cloned().unwrap_or_default();
        info_refs("git", &service, &st.repo, Duration::from_secs(30), None)
            .await
            .unwrap()
    }

    async fn pack_handler(
        axum::extract::State(st): axum::extract::State<std::sync::Arc<FilterState>>,
        body: Bytes,
    ) -> Response {
        upload_pack_excluding(
            "git",
            &st.repo,
            body,
            &st.withheld,
            Duration::from_secs(30),
            None,
        )
        .await
        .unwrap()
    }

    /// Spawn the server for `bare`, withholding `withheld`. Returns the clone URL
    /// and the server task (abort it when done).
    async fn spawn_filter_server(
        bare: std::path::PathBuf,
        withheld: HashSet<String>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::routing::{get, post};
        let state = std::sync::Arc::new(FilterState {
            repo: bare,
            withheld,
        });
        let app = axum::Router::new()
            .route("/repo.git/info/refs", get(refs_handler))
            .route("/repo.git/git-upload-pack", post(pack_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://127.0.0.1:{port}/repo.git"), handle)
    }

    fn run_git(args: &[&str], dir: &std::path::Path) {
        assert!(Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
    }

    /// Build a work repo (public/a.txt, secret/b.txt) and a bare clone of it.
    /// Returns (work, bare, secret_blob_oid, public_blob_oid).
    fn fixture_with_secret(
        td: &TempDir,
    ) -> (std::path::PathBuf, std::path::PathBuf, String, String) {
        let work = td.path().join("work");
        let bare = td.path().join("bare.git");
        std::fs::create_dir_all(work.join("secret")).unwrap();
        std::fs::create_dir_all(work.join("public")).unwrap();
        std::fs::write(work.join("public/a.txt"), b"pub\n").unwrap();
        std::fs::write(work.join("secret/b.txt"), b"SECRET\n").unwrap();
        run_git(&["init", "-q"], &work);
        run_git(&["config", "user.email", "t@t"], &work);
        run_git(&["config", "user.name", "t"], &work);
        run_git(&["add", "."], &work);
        run_git(&["commit", "-qm", "init"], &work);
        let oid = |p: &str| {
            let o = Command::new("git")
                .args(["rev-parse", &format!("HEAD:{p}")])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        let secret_oid = oid("secret/b.txt");
        let public_oid = oid("public/a.txt");
        run_git(
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        (work, bare, secret_oid, public_oid)
    }

    /// Enumerate exactly the objects a repo physically has (no promisor lazy
    /// fetch), so tests assert on what bytes actually crossed the wire.
    fn local_object_ids(repo: &std::path::Path) -> String {
        let out = Command::new("git")
            .args(["cat-file", "--batch-all-objects", "--batch-check"])
            .current_dir(repo)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// End-to-end: a real `git` client clones through `info_refs` +
    /// `upload_pack_excluding` and ends up without the withheld blob's bytes
    /// while still seeing its tree entry (SHA). Uses a partial clone
    /// (`--filter`) because a pack that omits a referenced blob is only
    /// accepted by a promisor-aware client; a stock full clone is refused at
    /// fetch time by the connectivity check.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_git_partial_clone_omits_withheld_blob() {
        let td = TempDir::new().unwrap();
        let (_work, bare, secret_oid, public_oid) = fixture_with_secret(&td);

        let (url, server) = spawn_filter_server(bare, HashSet::from([secret_oid.clone()])).await;

        let dest = td.path().join("clone");
        let dest_s = dest.to_str().unwrap().to_string();
        let out = tokio::task::spawn_blocking(move || {
            Command::new("git")
                .args([
                    "-c",
                    "protocol.version=2",
                    "clone",
                    "--filter=blob:none",
                    "--no-checkout",
                    "-q",
                    &url,
                    &dest_s,
                ])
                .output()
                .unwrap()
        })
        .await
        .unwrap();

        assert!(
            out.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // The public blob is present in the clone, the withheld blob is not.
        let local = local_object_ids(&dest);
        assert!(
            local.contains(&public_oid),
            "public blob should be present in the clone"
        );
        assert!(
            !local.contains(&secret_oid),
            "withheld blob bytes must be absent from the clone"
        );

        // The tree entry (and SHA) for the private file is still visible.
        let tree = Command::new("git")
            .args(["ls-tree", "-r", "HEAD"])
            .current_dir(&dest)
            .output()
            .unwrap();
        let tree = String::from_utf8_lossy(&tree.stdout);
        assert!(
            tree.contains(&secret_oid) && tree.contains("secret/b.txt"),
            "the private path and its blob SHA must remain visible: {tree}"
        );

        server.abort();
    }

    /// End-to-end: an incremental `git fetch` after a partial clone still works
    /// and still withholds the private blob. The serve path ignores the client's
    /// have/want negotiation and always sends a self-contained pack of all refs
    /// minus the withheld blobs (it replies NAK, so the client treats it as "no
    /// common commits" and accepts the full set). This is correct, just not
    /// bandwidth-optimal; thin-pack/negotiation is an optimization follow-up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_git_fetch_after_partial_clone_still_withholds() {
        let td = TempDir::new().unwrap();
        let (work, bare, secret_oid, _public_oid) = fixture_with_secret(&td);
        let branch = {
            let o = Command::new("git")
                .args(["symbolic-ref", "--short", "HEAD"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };

        let (url, server) =
            spawn_filter_server(bare.clone(), HashSet::from([secret_oid.clone()])).await;

        // Partial-clone the initial state.
        let dest = td.path().join("clone");
        let dest_s = dest.to_str().unwrap().to_string();
        let url_c = url.clone();
        let out = tokio::task::spawn_blocking(move || {
            Command::new("git")
                .args([
                    "-c",
                    "protocol.version=2",
                    "clone",
                    "--filter=blob:none",
                    "--no-checkout",
                    "-q",
                    &url_c,
                    &dest_s,
                ])
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Add a new public commit on the server side.
        std::fs::write(work.join("public/c.txt"), b"v2\n").unwrap();
        run_git(&["add", "."], &work);
        run_git(&["commit", "-qm", "c2"], &work);
        let new_oid = {
            let o = Command::new("git")
                .args(["rev-parse", "HEAD:public/c.txt"])
                .current_dir(&work)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };
        run_git(&["push", "-q", bare.to_str().unwrap(), &branch], &work);

        // Incremental fetch: the client has c1 and asks for the update.
        let dest_f = dest.clone();
        let out = tokio::task::spawn_blocking(move || {
            Command::new("git")
                .args(["-c", "protocol.version=2", "fetch", "-q", "origin"])
                .current_dir(&dest_f)
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            out.status.success(),
            "fetch failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // The new commit's blob arrived; the withheld blob is still absent.
        let local = local_object_ids(&dest);
        assert!(
            local.contains(&new_oid),
            "the new commit's blob must be fetched"
        );
        assert!(
            !local.contains(&secret_oid),
            "withheld blob must remain absent after fetch"
        );

        server.abort();
    }

    // ── #53 regression: served-git process-group teardown ──────────────────
    //
    // run_git_service runs git in its own process group and SIGTERMs that group
    // when the request future is dropped (client disconnect) or returns early, so
    // git AND its pack-objects child die together instead of orphaning a zombie.
    // These exercise the KillGroupOnDrop guard that wires that up.

    #[cfg(unix)]
    fn alive(pid: i32) -> bool {
        // kill(pid, 0) probes existence: returns 0 while the pid exists, -1 once
        // it's gone (ESRCH). Same-uid here, so EPERM never applies.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_group_guard_terminates_child_on_drop() {
        let child = tokio::process::Command::new("sleep")
            .arg("300")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;

        {
            // The guard owns the child; on drop its detached reaper TERM/grace/KILL/
            // reaps the group (a plain sleep dies on the first SIGTERM).
            let _guard = KillGroupOnDrop {
                child: Some(child),
                pgid: Some(pid),
                admission: None,
            };
        }

        let mut gone = false;
        for _ in 0..300 {
            if !alive(pid) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        assert!(
            gone,
            "child must be terminated and reaped via its process group on guard drop"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_group_guard_reaps_grandchild_on_drop() {
        // The #53 scenario: git forks pack-objects. A group kill must reach the
        // grandchild, not just the direct child. sh (the group leader) backgrounds
        // a sleep (standing in for pack-objects) and prints its pid.
        use tokio::io::AsyncReadExt;
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 300 & echo \"$!\"; wait")
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;

        // Read the backgrounded grandchild's pid from the first stdout line, before
        // the child moves into the guard.
        let mut stdout = child.stdout.take().unwrap();
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let n = stdout.read(&mut byte).await.unwrap();
            if n == 0 || byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        let grandchild: i32 = String::from_utf8(buf).unwrap().trim().parse().unwrap();
        assert!(alive(grandchild), "grandchild should be running");

        {
            // The guard owns the child; on drop the detached reaper group-kills sh AND
            // the sleep grandchild.
            let _guard = KillGroupOnDrop {
                child: Some(child),
                pgid: Some(pid),
                admission: None,
            };
        }

        let mut gone = false;
        for _ in 0..300 {
            if !alive(grandchild) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        unsafe {
            libc::kill(grandchild, libc::SIGKILL);
        }
        assert!(
            gone,
            "grandchild must be terminated by the group signal (#53)"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn kill_group_guard_disarmed_does_not_kill() {
        // A request that completed cleanly disarms the guard; dropping it must not
        // signal anything.
        let child = tokio::process::Command::new("sleep")
            .arg("300")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;

        {
            let mut guard = KillGroupOnDrop {
                child: Some(child),
                pgid: Some(pid),
                admission: None,
            };
            guard.disarm();
        } // disarmed -> no reaper, no kill

        // Give any erroneously-spawned reaper a chance to run, then assert alive.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(alive(pid), "disarmed guard must not kill the child");

        // Clean up the still-running child (disarm dropped the handle, so reap by pid).
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
        }
    }

    // ── #62 PR1: end-to-end teardown wiring through run_git_service ─────────
    //
    // The kill_group_guard_* tests above build a KillGroupOnDrop by hand and
    // never call run_git_service, so deleting `process_group(0)` (spawn site) or
    // the guard-arming, or the post-reap disarm, would leave them green. These
    // drive the REAL run_git_service via an injected fake `git` (the `git_bin`
    // seam) and assert the production spawn path actually wires the teardown up.
    // Faithful to the real invocation: run_git_service spawns
    // `<git_bin> <cmd> --stateless-rpc <repo_path>` in its own process group.

    /// SIGKILLs the given pids on drop (ignoring all kill errors, e.g. ESRCH for
    /// an already-dead pid) so a panicking assertion can't leak the fake `git` or
    /// its grandchild onto the test runner.
    #[cfg(unix)]
    struct ReapOnPanic(Vec<i32>);

    #[cfg(unix)]
    impl Drop for ReapOnPanic {
        fn drop(&mut self) {
            for &pid in &self.0 {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    /// Write an executable fake `git` (named `git`) into `dir`; return its path.
    #[cfg(unix)]
    fn write_fake_git(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("git");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Read a two-line `leader\ngrandchild` pidfile once both lines are present.
    #[cfg(unix)]
    fn read_two_pids(pidfile: &std::path::Path) -> Option<(i32, i32)> {
        let s = std::fs::read_to_string(pidfile).ok()?;
        let mut lines = s.lines();
        let leader: i32 = lines.next()?.trim().parse().ok()?;
        let grandchild: i32 = lines.next()?.trim().parse().ok()?;
        Some((leader, grandchild))
    }

    /// Retry policy for the fake-git spawn race, shared by `fake_git_run_with_pids`
    /// and the drop test's inline loop (which can't use the helper — it must keep
    /// the winning future pending). `nth` retry waits `n * STEP_MS` ms.
    #[cfg(unix)]
    const FAKE_GIT_RETRY_ATTEMPTS: u64 = 12;
    #[cfg(unix)]
    const FAKE_GIT_BACKOFF_STEP_MS: u64 = 100;

    /// Run a fake-git-based `run` under the parallel test runner, retrying if the
    /// fake transiently fails to record its pids. Under `cargo test --workspace`
    /// fork-storm load a freshly-written fake `git` can fail to exec (ETXTBSY: a
    /// concurrent worker forked while its write fd was still open) or be killed by
    /// the service timeout before it is scheduled to write its pidfile; both leave
    /// no pids. These misses are *correlated* (bursty) under fork pressure, so each
    /// retry backs off (growing) to let a spike subside rather than burning every
    /// attempt inside one. `pidfile` is removed before each attempt. Returns the
    /// successful attempt's outcome together with the recorded pids; a genuine
    /// never-spawns bug still fails loudly after the cap. Retried attempts don't
    /// leak in practice: a miss almost always means the fake never exec'd (nothing
    /// to clean up), and a spawn that got far enough is reaped by the timeout/drop
    /// path before this returns.
    #[cfg(unix)]
    async fn fake_git_run_with_pids<R, F, Fut>(
        pidfile: &std::path::Path,
        mut run: F,
    ) -> (R, (i32, i32))
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        for i in 0..FAKE_GIT_RETRY_ATTEMPTS {
            let _ = std::fs::remove_file(pidfile);
            let outcome = run().await;
            // A successful run writes its pids before it returns, so a short poll
            // catches them (allowing only for fs-visibility lag).
            for _ in 0..50 {
                if let Some(p) = read_two_pids(pidfile) {
                    return (outcome, p);
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            // Miss: back off before retrying so a bursty fork-pressure spike
            // subsides (see the doc note on correlated ETXTBSY/EAGAIN failures).
            tokio::time::sleep(std::time::Duration::from_millis(
                FAKE_GIT_BACKOFF_STEP_MS * (i + 1),
            ))
            .await;
        }
        panic!(
            "fake git failed to spawn and record its pids after {FAKE_GIT_RETRY_ATTEMPTS} \
             attempts (persistent failure, not a transient parallel-runner miss)"
        );
    }

    /// True when `err` is the transient ETXTBSY exec race a freshly-written fake
    /// `git` hits under fork-storm load — a concurrent worker forked while this
    /// file's write fd was still open, so `execve` sees it as busy (the same race
    /// `fake_git_run_with_pids` retries). Deliberately narrow: only this raw-OS
    /// error is retried, so a wrong error *type* (e.g. a missing async bound
    /// surfacing as anything other than `GitServiceTimeout`) still fails loudly at
    /// the caller's assertion instead of being swallowed. `spawn()?` propagates the
    /// `io::Error` with no context, so it survives as the anyhow root.
    #[cfg(unix)]
    fn is_transient_exec_race(err: &anyhow::Error) -> bool {
        // ETXTBSY == 26 on Linux and the BSDs/macOS; std has no stable ErrorKind.
        err.downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            == Some(26)
    }

    /// Drive `build_filtered_pack` under a per-attempt watchdog, retrying ONLY the
    /// transient ETXTBSY exec race and returning the terminal error for the caller
    /// to classify. Every attempt keeps its own outer `tokio::time::timeout`, so a
    /// MISSING async bound — the regression the `build_filtered_pack_times_out_*`
    /// tests guard — still trips the watchdog loudly on every attempt: the retry
    /// can only absorb a fast exec failure, never a hang (a hang never returns, so
    /// it can never reach the retry decision).
    #[cfg(unix)]
    async fn build_filtered_pack_or_exec_race_retry(
        git_bin: &str,
        repo_path: &std::path::Path,
        withheld: &HashSet<String>,
        stage_timeout: Duration,
    ) -> anyhow::Error {
        for i in 0..FAKE_GIT_RETRY_ATTEMPTS {
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                build_filtered_pack(git_bin, repo_path, withheld, stage_timeout, None),
            )
            .await
            .expect(
                "build_filtered_pack must return within the watchdog — the git stage \
                 must be timeout-bounded, not an uncancellable spawn_blocking",
            );
            // `match` rather than `expect_err`: the Ok arm carries an
            // AdmissionGuard, which has no Debug impl for expect_err to print.
            let err = match result {
                Ok(_) => panic!("a hung git stage must return an error, not hang"),
                Err(e) => e,
            };
            if is_transient_exec_race(&err) {
                // Fresh-fake-git ETXTBSY: back off (growing) so a bursty fork-pressure
                // spike subsides before retrying, per fake_git_run_with_pids.
                tokio::time::sleep(Duration::from_millis(FAKE_GIT_BACKOFF_STEP_MS * (i + 1))).await;
                continue;
            }
            return err;
        }
        panic!(
            "fake git kept hitting ETXTBSY after {FAKE_GIT_RETRY_ATTEMPTS} attempts \
             (persistent exec failure, not a transient parallel-runner miss)"
        );
    }

    // Dropping the request future mid-flight (client disconnect) must SIGTERM the
    // whole group so git AND its pack-objects grandchild die together. Goes RED
    // if `process_group(0)` or the guard-arming is removed: without its own
    // group, kill(-pgid) hits no group and the grandchild survives.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_tears_down_group_when_future_dropped() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // Fork a grandchild (stands in for pack-objects), record leader+grandchild
        // pids, then hang so run_git_service parks in wait_with_output.
        let body = format!(
            "#!/bin/sh\nsleep 300 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nwait\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        // Retry under fork-storm load: a freshly-written fake `git` can transiently
        // fail to exec (ETXTBSY) or exit before recording its pids; both leave no
        // pids and are independent per attempt (see fake_git_run_with_pids). The
        // winning attempt's future is kept PENDING so the drop below exercises the
        // client-disconnect teardown. Dropping a losing attempt's future makes its
        // guard reap anything that spawned, so retries don't leak.
        let (fut, grandchild) = {
            let mut attempt = 0u64;
            loop {
                attempt += 1;
                let _ = std::fs::remove_file(&pidfile);
                let mut fut = Box::pin(run_git_service(
                    git_bin.to_str().unwrap(),
                    "git-upload-pack",
                    tmp.path(),
                    Bytes::new(),
                    Duration::from_secs(60),
                    None,
                ));

                // Advance the future a slice at a time until the fake records its
                // pids. `Ok(_)` means run_git_service returned before the pidfile
                // appeared (spawn error / early exit); stop polling then, since
                // re-polling a completed future panics with `async fn resumed after
                // completion`. Read the pidfile first so a fake that wrote its pids
                // and then exited is still captured.
                let mut pids = None;
                for _ in 0..500 {
                    let finished =
                        tokio::time::timeout(std::time::Duration::from_millis(10), &mut fut)
                            .await
                            .is_ok();
                    if let Some(p) = read_two_pids(&pidfile) {
                        pids = Some(p);
                        break;
                    }
                    if finished {
                        break;
                    }
                }
                // Only the grandchild needs panic-cleanup: dropping the future makes
                // tokio reap the fake leader, and carrying the reaped leader pid
                // risks SIGKILLing a recycled pid under parallel test load.
                match pids {
                    Some((_leader, g)) => break (fut, g),
                    None => {
                        // Transient spawn miss: drop the still-armed future so its
                        // guard reaps anything that spawned, then back off (growing)
                        // so a bursty fork-pressure spike subsides before retrying.
                        drop(fut);
                        assert!(
                            attempt < FAKE_GIT_RETRY_ATTEMPTS,
                            "fake git failed to spawn and record its pids after \
                             {FAKE_GIT_RETRY_ATTEMPTS} attempts (persistent failure, \
                             not a transient parallel-runner miss)"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(
                            FAKE_GIT_BACKOFF_STEP_MS * attempt,
                        ))
                        .await;
                    }
                }
            }
        };
        let _cleanup = ReapOnPanic(vec![grandchild]);
        assert!(
            alive(grandchild),
            "grandchild should be running before the drop"
        );

        // Client disconnect: drop the request future. The armed KillGroupOnDrop
        // must SIGTERM the whole group.
        drop(fut);

        let mut gone = false;
        for _ in 0..500 {
            if !alive(grandchild) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            gone,
            "grandchild must be torn down via the process group on future-drop \
             (proves run_git_service sets process_group(0) and arms the guard)"
        );
    }

    /// #174 U2 (P1-c, RED-before/GREEN-after): on a client disconnect the teardown must
    /// be as strong as the timeout path — a group member that IGNORES SIGTERM is still
    /// SIGKILLed and reaped, not left running to accumulate past the concurrency cap.
    /// The old `KillGroupOnDrop::drop` sent a lone SIGTERM with no escalation or reap,
    /// so a SIGTERM-ignoring descendant survived the disconnect (RED). The fix launches
    /// a detached reaper owning the child that runs the full TERM/grace/SIGKILL/reap.
    /// This is distinct from the well-behaved-grandchild test above, whose `sleep` dies
    /// on the first SIGTERM.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_sigkills_a_sigterm_ignoring_child_on_disconnect() {
        let tmp = tempfile::TempDir::new().unwrap();
        let descfile = tmp.path().join("desc.pid");
        // Leader (dies on the group SIGTERM) spawns a descendant that traps SIGTERM,
        // records its own pid, and loops ~30s (bounded so a RED run leaks no permanent
        // orphan; the assertion fires well before then).
        let body = format!(
            "#!/bin/sh\n\
             sh -c 'trap \"\" TERM; echo $$ > \"{}\"; i=0; while [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done' &\n\
             wait\n",
            descfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        let mut fut = Box::pin(run_git_service(
            git_bin.to_str().unwrap(),
            "git-upload-pack",
            tmp.path(),
            Bytes::new(),
            Duration::from_secs(60),
            None,
        ));
        // Drive the future a slice at a time until the descendant records its pid.
        let mut desc: Option<i32> = None;
        for _ in 0..500 {
            let _ = tokio::time::timeout(Duration::from_millis(10), &mut fut).await;
            if let Some(p) = std::fs::read_to_string(&descfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                desc = Some(p);
                break;
            }
        }
        let desc = desc.expect("the fake leader must have spawned and recorded a descendant");
        let _cleanup = ReapOnPanic(vec![desc]);
        assert!(alive(desc), "descendant should be running before the drop");

        // Client disconnect: drop the request future. The guard's detached reaper must
        // escalate SIGTERM -> SIGKILL and reap the SIGTERM-ignoring descendant.
        drop(fut);

        let mut gone = false;
        for _ in 0..500 {
            if !alive(desc) {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Kill regardless so a RED run leaks no orphan.
        unsafe {
            libc::kill(desc, libc::SIGKILL);
        }
        assert!(
            gone,
            "a SIGTERM-ignoring descendant (pid {desc}) must be SIGKILLed and reaped on \
             disconnect, not left running (old KillGroupOnDrop sent SIGTERM only)"
        );
    }

    // #174 (SC3): the info/refs advertisement is now duration-bounded — previously
    // it ran a bare `Command::output()` with no deadline, so a hung git pinned its
    // concurrency slot forever. A hung fake git must abort with GitServiceTimeout
    // (which the handler maps to 504). The outer watchdog turns a missing timeout
    // into a loud failure instead of hanging the suite. info_refs shares
    // drive_git_child, so its disconnect/group-teardown is the same code proven by
    // run_git_service_tears_down_group_when_future_dropped above.
    #[cfg(unix)]
    #[tokio::test]
    async fn info_refs_times_out_a_hung_advertisement() {
        let tmp = tempfile::TempDir::new().unwrap();
        // A fake git that hangs forever instead of advertising refs.
        let git_bin = write_fake_git(tmp.path(), "#!/bin/sh\nsleep 300\n");

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            info_refs(
                git_bin.to_str().unwrap(),
                "git-upload-pack",
                tmp.path(),
                Duration::from_millis(200),
                None,
            ),
        )
        .await
        .expect("info_refs must return within the watchdog — its own timeout must fire");
        let err = result.expect_err("a hung advertisement must return an error, not hang");
        assert!(
            err.downcast_ref::<GitServiceTimeout>().is_some(),
            "a hung advertisement must abort with GitServiceTimeout (-> 504), got: {err}"
        );
    }

    // #174 (SC3, KTD5): the filtered-pack build's streaming pack-objects stage is
    // duration-bounded on the ASYNC side. The old build ran the whole thing in a
    // spawn_blocking, so an outer tokio timeout could not cancel the blocking thread
    // and a disconnect orphaned the git child. A fake git that returns objects fast
    // on rev-list but hangs on pack-objects must now abort with GitServiceTimeout;
    // the watchdog turns a missing bound into a loud failure. The stage runs under
    // drive_git_child, so its disconnect/group-teardown is the same code proven by
    // run_git_service_tears_down_group_when_future_dropped.
    #[cfg(unix)]
    #[tokio::test]
    async fn build_filtered_pack_times_out_a_hung_pack_objects() {
        let tmp = tempfile::TempDir::new().unwrap();
        // rev-list returns one oid fast; pack-objects hangs forever.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-list) echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef ;;\n  pack-objects) sleep 300 ;;\n  *) exit 1 ;;\nesac\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let withheld = HashSet::new();

        // Retry only the transient ETXTBSY exec race (see the helper); the
        // per-attempt watchdog keeps the missing-bound regression loud.
        let err = build_filtered_pack_or_exec_race_retry(
            git_bin.to_str().unwrap(),
            tmp.path(),
            &withheld,
            Duration::from_millis(200),
        )
        .await;
        assert!(
            err.downcast_ref::<GitServiceTimeout>().is_some(),
            "a hung pack-objects must abort with GitServiceTimeout, got: {err}"
        );
    }

    // #174 (SC3, KTD5): the filtered-pack build's rev-list ENUMERATION stage is now
    // duration-bounded on the ASYNC side too. It previously ran inside a
    // spawn_blocking via a bare `Command::output()`, which an outer tokio timeout
    // cannot cancel, so a hung/slow rev-list pinned the endpoint's concurrency permit
    // for the whole hang. A fake git that hangs on rev-list must now abort with
    // GitServiceTimeout; the watchdog turns a missing bound into a loud failure.
    // rev-list runs under drive_git_child, so its disconnect/group-teardown is the
    // same code proven by run_git_service_tears_down_group_when_future_dropped.
    #[cfg(unix)]
    #[tokio::test]
    async fn build_filtered_pack_times_out_a_hung_rev_list() {
        let tmp = tempfile::TempDir::new().unwrap();
        // rev-list hangs forever; pack-objects would return fast if it were reached.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-list) sleep 300 ;;\n  pack-objects) printf '' ;;\n  *) exit 1 ;;\nesac\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let withheld = HashSet::new();

        // Retry only the transient ETXTBSY exec race (see the helper); the
        // per-attempt watchdog keeps the missing-bound regression loud.
        let err = build_filtered_pack_or_exec_race_retry(
            git_bin.to_str().unwrap(),
            tmp.path(),
            &withheld,
            Duration::from_millis(200),
        )
        .await;
        assert!(
            err.downcast_ref::<GitServiceTimeout>().is_some(),
            "a hung rev-list must abort with GitServiceTimeout, got: {err}"
        );
    }

    // ── F1: filtered-serve admission threaded through both pack stages ──────
    //
    // The handler-level disconnect regression lives in api/repos.rs
    // (upload_pack_filtered_permit_held_through_group_reap_after_disconnect); these
    // exercise the guard contract at the smart_http seam: held through a
    // mid-rev-list disconnect, handed back on success, and recovered (post-reap)
    // on every error return.

    /// F1: a client disconnect mid-REV-LIST (stage 1 of the filtered build) must
    /// keep the threaded admission held until the rev-list group is reaped, and
    /// stage 2 (pack-objects) must never spawn, since the dropped future cannot
    /// advance to it.
    #[cfg(unix)]
    #[tokio::test]
    async fn build_filtered_pack_holds_admission_through_rev_list_reap_on_disconnect() {
        let tmp = tempfile::TempDir::new().unwrap();
        let descfile = tmp.path().join("desc.pid");
        let packfile = tmp.path().join("pack.ran");
        // rev-list: SIGTERM-trapping descendant records its pid and loops (bounded
        // so a broken fix leaks no permanent orphan); the leader waits, keeping the
        // interaction pending. pack-objects: records that it ran (it must never run).
        let body = format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
               rev-list)\n\
                 sh -c 'trap \"\" TERM; echo $$ > \"{desc}\"; i=0; while [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done' &\n\
                 wait ;;\n\
               pack-objects) : > \"{pack}\" ;;\n\
               *) : ;;\n\
             esac\n\
             exit 0\n",
            desc = descfile.display(),
            pack = packfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let guard = AdmissionGuard::new(sem.clone().try_acquire_owned().unwrap(), None::<()>);
        let withheld = HashSet::new();

        let mut fut = Box::pin(build_filtered_pack(
            git_bin.to_str().unwrap(),
            tmp.path(),
            &withheld,
            Duration::from_secs(60),
            Some(guard),
        ));
        // Drive until the rev-list descendant records its pid.
        let mut desc: Option<i32> = None;
        for _ in 0..500 {
            let _ = tokio::time::timeout(Duration::from_millis(10), &mut fut).await;
            if let Some(p) = std::fs::read_to_string(&descfile)
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
            {
                desc = Some(p);
                break;
            }
        }
        let desc = desc.expect("the fake rev-list must have spawned its descendant");
        let _cleanup = ReapOnPanic(vec![desc]);
        assert_eq!(
            sem.available_permits(),
            0,
            "admission held while rev-list runs"
        );

        // Client disconnect mid-enumeration.
        drop(fut);

        // Load-bearing: the permit must stay held while the SIGTERM-ignoring group
        // member is still alive (check before the reaper's ~2s SIGKILL escalation).
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            alive(desc),
            "the SIGTERM-ignoring descendant must still be alive during the hold window"
        );
        assert_eq!(
            sem.available_permits(),
            0,
            "on disconnect mid-rev-list the admission must be held until the group is \
             reaped, not released the instant the future drops (F1)"
        );

        let mut freed = false;
        for _ in 0..400 {
            if sem.available_permits() == 1 {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            freed,
            "the reaper must release admission once the rev-list group is gone"
        );
        assert!(
            !packfile.exists(),
            "pack-objects must never spawn after a disconnect mid-rev-list"
        );
    }

    /// F1 success path: a filtered serve that completes hands the guard back
    /// through both stages and releases admission when the serve returns. No leak,
    /// no double-release.
    #[tokio::test]
    async fn upload_pack_excluding_releases_admission_after_success() {
        let td = TempDir::new().unwrap();
        let (_work, bare, secret_oid, _public_oid) = fixture_with_secret(&td);
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let guard = AdmissionGuard::new(sem.clone().try_acquire_owned().unwrap(), None::<()>);
        let withheld = HashSet::from([secret_oid]);
        let resp = upload_pack_excluding(
            "git",
            &bare,
            Bytes::from_static(b"0000"),
            &withheld,
            Duration::from_secs(30),
            Some(guard),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            sem.available_permits(),
            1,
            "admission must be released once the filtered serve returns"
        );
    }

    /// F1 error path: a rev-list that exits non-zero fails the build AND recovers
    /// the threaded admission: drive_git_child drops the guard only after the
    /// completed join has reaped the child, and the error return must not leak it.
    #[cfg(unix)]
    #[tokio::test]
    async fn build_filtered_pack_releases_admission_after_rev_list_failure() {
        let tmp = tempfile::TempDir::new().unwrap();
        let body =
            "#!/bin/sh\ncase \"$1\" in\n  rev-list) echo boom >&2; exit 2 ;;\n  *) : ;;\nesac\nexit 0\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let withheld = HashSet::new();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

        for i in 0..FAKE_GIT_RETRY_ATTEMPTS {
            let guard = AdmissionGuard::new(sem.clone().try_acquire_owned().unwrap(), None::<()>);
            let result = build_filtered_pack(
                git_bin.to_str().unwrap(),
                tmp.path(),
                &withheld,
                Duration::from_secs(30),
                Some(guard),
            )
            .await;
            let err = match result {
                Ok(_) => panic!("a non-zero rev-list exit must fail the build"),
                Err(e) => e,
            };
            // Load-bearing on EVERY attempt: even a transient spawn-failure return
            // must recover the permit (the guard drops before the Err surfaces).
            assert_eq!(
                sem.available_permits(),
                1,
                "the admission permit must be recovered on the error return, not leaked"
            );
            if is_transient_exec_race(&err) {
                tokio::time::sleep(Duration::from_millis(FAKE_GIT_BACKOFF_STEP_MS * (i + 1))).await;
                continue;
            }
            assert!(
                err.to_string().contains("rev-list failed"),
                "the failure must surface rev-list's own error, got: {err}"
            );
            return;
        }
        panic!(
            "fake git kept hitting ETXTBSY after {FAKE_GIT_RETRY_ATTEMPTS} attempts \
             (persistent exec failure, not a transient parallel-runner miss)"
        );
    }

    /// F1: a pack-objects stage that times out (stage 2 of the filtered build,
    /// guard threaded through) recovers the admission after the reap: the timeout
    /// Err cannot carry the guard, so drive_git_child must drop it post-reap.
    #[cfg(unix)]
    #[tokio::test]
    async fn build_filtered_pack_recovers_admission_after_pack_objects_timeout() {
        let tmp = tempfile::TempDir::new().unwrap();
        // rev-list returns one oid fast (guard handed back); pack-objects hangs.
        let body = "#!/bin/sh\ncase \"$1\" in\n  rev-list) echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef ;;\n  pack-objects) sleep 300 ;;\n  *) exit 1 ;;\nesac\n";
        let git_bin = write_fake_git(tmp.path(), body);
        let withheld = HashSet::new();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

        for i in 0..FAKE_GIT_RETRY_ATTEMPTS {
            let guard = AdmissionGuard::new(sem.clone().try_acquire_owned().unwrap(), None::<()>);
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                build_filtered_pack(
                    git_bin.to_str().unwrap(),
                    tmp.path(),
                    &withheld,
                    Duration::from_millis(200),
                    Some(guard),
                ),
            )
            .await
            .expect(
                "build_filtered_pack must return within the watchdog; the git stage \
                 must be timeout-bounded",
            );
            let err = match result {
                Ok(_) => panic!("a hung pack-objects must fail the build"),
                Err(e) => e,
            };
            assert_eq!(
                sem.available_permits(),
                1,
                "admission must be recovered after the stage-2 timeout reap, not leaked"
            );
            if is_transient_exec_race(&err) {
                tokio::time::sleep(Duration::from_millis(FAKE_GIT_BACKOFF_STEP_MS * (i + 1))).await;
                continue;
            }
            assert!(
                err.downcast_ref::<GitServiceTimeout>().is_some(),
                "a hung pack-objects must abort with GitServiceTimeout, got: {err}"
            );
            return;
        }
        panic!(
            "fake git kept hitting ETXTBSY after {FAKE_GIT_RETRY_ATTEMPTS} attempts \
             (persistent exec failure, not a transient parallel-runner miss)"
        );
    }

    /// F1 zero-budget contract: build_filtered_pack hands pack-objects
    /// `deadline.saturating_duration_since(now)`, which saturates to ZERO once
    /// rev-list has consumed the whole budget. A zero-budget stage must still route
    /// the guard through the timeout's reap-then-drop rather than leak it: the
    /// child spawns, the deadline fires immediately, the group is reaped, and only
    /// then does the guard drop.
    #[cfg(unix)]
    #[tokio::test]
    async fn drive_git_child_zero_budget_drops_admission_after_reap() {
        let tmp = tempfile::TempDir::new().unwrap();
        let git_bin = write_fake_git(tmp.path(), "#!/bin/sh\nsleep 300\n");
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

        for i in 0..FAKE_GIT_RETRY_ATTEMPTS {
            let guard = AdmissionGuard::new(sem.clone().try_acquire_owned().unwrap(), None::<()>);
            let mut command = tokio::process::Command::new(git_bin.to_str().unwrap());
            command
                .args(["pack-objects", "--stdout"])
                .current_dir(tmp.path());
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                drive_git_child(
                    command,
                    Bytes::new(),
                    Duration::ZERO,
                    "pack-objects",
                    Some(guard),
                ),
            )
            .await
            .expect("a zero-budget stage must abort via its own deadline, not hang");
            let err = match result {
                Ok(_) => panic!("a zero-budget stage must return an error"),
                Err(e) => e,
            };
            assert_eq!(
                sem.available_permits(),
                1,
                "the guard must drop after the zero-budget timeout reap, not leak"
            );
            if is_transient_exec_race(&err) {
                tokio::time::sleep(Duration::from_millis(FAKE_GIT_BACKOFF_STEP_MS * (i + 1))).await;
                continue;
            }
            assert!(
                err.downcast_ref::<GitServiceTimeout>().is_some(),
                "a zero-budget stage must abort with GitServiceTimeout, got: {err}"
            );
            return;
        }
        panic!(
            "fake git kept hitting ETXTBSY after {FAKE_GIT_RETRY_ATTEMPTS} attempts \
             (persistent exec failure, not a transient parallel-runner miss)"
        );
    }

    // A request that runs to completion must DISARM the guard after reaping, so
    // no stray group SIGTERM fires. The fake exits non-zero (surfacing as Err)
    // but leaves a grandchild alive; the grandchild must survive. Goes RED if the
    // post-reap disarm is removed: the guard would then fire on return and, since
    // the grandchild still holds the group open, sweep it.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_disarms_on_completion_leaving_group_alive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // The grandchild is long-lived with stdio redirected to /dev/null:
        // /dev/null so it doesn't inherit (and hold open) run_git_service's stdout
        // pipe (which would block wait_with_output until it exits); long-lived so
        // the "still alive" assertion below can't race the sleep exiting on its own
        // under a starved scheduler. ReapOnPanic cleans it up.
        let body = format!(
            "#!/bin/sh\nsleep 300 >/dev/null 2>&1 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nexit 1\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        // wait_with_output already reaped the fake leader, so only the grandchild
        // needs panic-cleanup — SIGKILLing the reaped leader pid could hit a
        // recycled pid under parallel test load. Retry the run so a transient spawn
        // miss under fork-storm load doesn't fail the test (see fake_git_run_with_pids).
        let (result, (_leader, grandchild)) = fake_git_run_with_pids(&pidfile, || {
            run_git_service(
                git_bin.to_str().unwrap(),
                "git-upload-pack",
                tmp.path(),
                Bytes::new(),
                Duration::from_secs(60),
                None,
            )
        })
        .await;
        let _cleanup = ReapOnPanic(vec![grandchild]);

        assert!(result.is_err(), "non-zero git exit must surface as Err");
        // A mutant that left the guard armed fires SIGTERM on return; poll a short
        // window so a killed grandchild is reliably observed dead — a single
        // alive() check can race the SIGTERM+reap and miss it.
        for _ in 0..30 {
            assert!(
                alive(grandchild),
                "grandchild must survive: run_git_service must disarm the guard after \
                 reaping, not fire a group SIGTERM on the completion path"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // The SUCCESS path (exit 0, Ok) must disarm too — the disarm test above only
    // exercises the exit-1/Err branch. Goes RED if disarm is gated on failure
    // (e.g. moved inside the `!status.success()` branch): the guard would then
    // fire after a clean completion and sweep the still-live grandchild.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_disarms_on_success_leaving_group_alive() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // Long-lived, stdio to /dev/null (same reasons as the exit-1 test).
        let body = format!(
            "#!/bin/sh\nsleep 300 >/dev/null 2>&1 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nexit 0\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        // Retry the run so a transient spawn miss under fork-storm load doesn't
        // fail the test (see fake_git_run_with_pids).
        let (result, (_leader, grandchild)) = fake_git_run_with_pids(&pidfile, || {
            run_git_service(
                git_bin.to_str().unwrap(),
                "git-upload-pack",
                tmp.path(),
                Bytes::new(),
                Duration::from_secs(60),
                None,
            )
        })
        .await;
        let _cleanup = ReapOnPanic(vec![grandchild]);

        assert!(result.is_ok(), "zero-exit git must surface as Ok");
        // Poll a short window (see the exit-1 test): a mutant that disarms only on
        // failure fires the guard on this success path, and a single alive() check
        // can race the SIGTERM+reap.
        for _ in 0..30 {
            assert!(
                alive(grandchild),
                "grandchild must survive: run_git_service must disarm on the success \
                 path too, not fire a group SIGTERM after a clean completion"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // A git that hangs (never finishes, never disconnects) must be bounded: it
    // returns GitServiceTimeout (the handler maps that to 504) and its process
    // group is torn down. Goes RED if the timeout wrap is removed — the OUTER
    // bound below then fires instead of run_git_service's own, so the test fails
    // loudly rather than hanging CI.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_times_out_and_tears_down_a_hung_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // Fork a grandchild, then hang forever.
        let body = format!(
            "#!/bin/sh\nsleep 300 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nwait\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        // Outer bound well above git_timeout: if run_git_service's own timeout is
        // broken it hangs, and this fires instead so we assert-fail, not hang.
        // fake_git_run_with_pids retries a transient spawn/schedule miss under
        // fork-storm load and returns the pidfile the fake recorded.
        let git_timeout = Duration::from_millis(1000);
        let (outcome, (_leader, grandchild)) = fake_git_run_with_pids(&pidfile, || {
            tokio::time::timeout(
                Duration::from_secs(5),
                run_git_service(
                    git_bin.to_str().unwrap(),
                    "git-upload-pack",
                    tmp.path(),
                    Bytes::new(),
                    git_timeout,
                    None,
                ),
            )
        })
        .await;

        assert!(
            outcome.is_ok(),
            "run_git_service must return via its own timeout, not hang"
        );
        let err = outcome
            .unwrap()
            .expect_err("a hung git must surface as Err");
        assert!(
            err.downcast_ref::<GitServiceTimeout>().is_some(),
            "the error must be GitServiceTimeout (maps to 504), got: {err:#}"
        );

        // The hung git's group must be torn down (the armed guard fires on the
        // timeout return), not leaked.
        let _cleanup = ReapOnPanic(vec![grandchild]);
        let mut gone = false;
        for _ in 0..500 {
            if !alive(grandchild) {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            gone,
            "a timed-out git's process group must be torn down, not leaked"
        );
    }

    // On timeout, run_git_service must REAP the group before returning, so a
    // caller releasing a write lock (receive-pack) can't race a still-live git.
    // The fake traps SIGTERM and lingers ~1s (git-cleanup stand-in): with the
    // reap the call waits for it to exit, so the leader is dead by the time we
    // return; without it, the call returns while the fake is still mid-trap.
    // Goes RED if the timeout arm's reap is removed.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_reaps_the_group_before_returning_on_timeout() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pidfile = tmp.path().join("pids");
        // Leader traps SIGTERM and exits after ~1s. The grandchild (a sub-shell)
        // IGNORES SIGTERM entirely (`trap "" TERM`) and sleeps far past the ~4s reap
        // cap, so nothing but the untrappable SIGKILL escalation can kill it within
        // the cap. That makes the escalation load-bearing: neuter the SIGKILL and
        // this test goes RED. (A grandchild that merely trapped-and-slept UNDER the
        // cap would self-exit and hide a broken escalation.) "Wait for the whole
        // group" (leader AND grandchild) is observable because both must be dead
        // before run_git_service returns.
        let body = format!(
            "#!/bin/sh\ntrap 'sleep 1; exit 0' TERM\nsh -c 'trap \"\" TERM; sleep 300' >/dev/null 2>&1 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"{}\"\nwait\n",
            pidfile.display()
        );
        let git_bin = write_fake_git(tmp.path(), &body);

        // fake_git_run_with_pids retries a transient spawn/schedule miss under
        // fork-storm load and returns the pids the fake recorded; the outer 10s
        // bound fires only if run_git_service's own timeout is broken (so we
        // assert-fail rather than hang), well above the git_timeout plus the
        // SIGKILL-escalation reap of the SIGTERM-ignoring grandchild.
        let git_timeout = Duration::from_millis(300);
        let (outcome, (leader, grandchild)) = fake_git_run_with_pids(&pidfile, || {
            tokio::time::timeout(
                Duration::from_secs(10),
                run_git_service(
                    git_bin.to_str().unwrap(),
                    "git-upload-pack",
                    tmp.path(),
                    Bytes::new(),
                    git_timeout,
                    None,
                ),
            )
        })
        .await;
        assert!(outcome.is_ok(), "must return via its own timeout, not hang");
        assert!(outcome.unwrap().is_err(), "a hung git must surface as Err");

        // The WHOLE group (leader AND the lingering grandchild) must be gone by the
        // time we get here.
        let _cleanup = ReapOnPanic(vec![grandchild]);
        assert!(
            !alive(leader) && !alive(grandchild),
            "run_git_service must reap the whole git process group (leader AND \
             grandchildren) before returning on a timeout, so a write-lock release \
             can't race a still-live git"
        );
    }

    // The timeout bounds git-receive-pack too, not just upload-pack: on the push
    // path a hung git also holds the repo's write lock, so an unbounded receive-pack
    // pins the repo until the process dies. run_git_service must return
    // Err(GitServiceTimeout) for the receive-pack service exactly as it does for
    // upload-pack. Goes RED if the internal timeout is removed (the fake never
    // exits, so the outer bound trips and the outcome is not Ok).
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_times_out_a_hung_receive_pack() {
        let tmp = tempfile::TempDir::new().unwrap();
        let git_bin = write_fake_git(tmp.path(), "#!/bin/sh\nsleep 300\n");
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            run_git_service(
                git_bin.to_str().unwrap(),
                "git-receive-pack",
                tmp.path(),
                Bytes::new(),
                Duration::from_millis(200),
                None,
            ),
        )
        .await;
        assert!(
            outcome.is_ok(),
            "receive-pack must return via its own timeout, not hang"
        );
        let err = outcome
            .unwrap()
            .expect_err("a hung receive-pack must surface as Err");
        assert!(
            err.downcast_ref::<GitServiceTimeout>().is_some(),
            "a hung receive-pack must time out as GitServiceTimeout (maps to 504); \
             got: {err:#}"
        );
    }

    // A malformed request: git exits non-zero with a recognizable pkt-line error
    // on stderr AND does not read stdin, so a body larger than the pipe buffer
    // makes the write EPIPE. run_git_service must surface git's stderr (which the
    // handler classifies as a 400), not the EPIPE write error (a generic 500).
    // Goes RED if the stdin-write check runs before the exit-status check.
    #[cfg(unix)]
    #[tokio::test]
    async fn run_git_service_surfaces_git_stderr_over_a_stdin_epipe() {
        let tmp = tempfile::TempDir::new().unwrap();
        let git_bin = write_fake_git(
            tmp.path(),
            "#!/bin/sh\necho 'fatal: bad line length character: 0000' >&2\nexit 128\n",
        );

        // Larger than a pipe buffer (~64 KiB) so the write blocks then EPIPEs when
        // the fake exits without draining stdin, exercising the ordering.
        let big = Bytes::from(vec![0u8; 256 * 1024]);
        let result = run_git_service(
            git_bin.to_str().unwrap(),
            "git-upload-pack",
            tmp.path(),
            big,
            Duration::from_secs(60),
            None,
        )
        .await;

        let err = result.expect_err("non-zero git must surface as Err");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("bad line length"),
            "run_git_service must surface git's stderr (a classifiable 400), not the \
             stdin-write EPIPE (a generic 500); got: {msg}"
        );
    }
}
