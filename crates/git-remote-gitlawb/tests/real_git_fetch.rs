//! #117 end-to-end: drive a REAL `git fetch` through the built helper against a
//! REAL `git upload-pack --stateless-rpc`, so the stateful-to-stateless bridging
//! is proven by execution, not reasoned. The unit tests in `main.rs` use a
//! pre-scripted Cursor and a canned HTTP mock, which cannot tell whether real git
//! (a stateful client over `connect`) actually parses the stateless-RPC server's
//! ACK responses and converges. That is the one load-bearing bet in the fix, and
//! only this test can falsify it.
//!
//! The in-test shim replicates the node's v0 smart-HTTP serving
//! (`gitlawb-node/src/git/smart_http.rs`): the info/refs advertisement wrapped in
//! the `# service=` pkt-line + flush, and each POST piped to
//! `git upload-pack --stateless-rpc`. The node crate's own tests already require
//! git, so committing this always-on is consistent with the suite.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// git pkt-line: 4-byte hex length (incl. the 4 bytes) + data.
fn pkt(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:04x}", data.len() + 4).into_bytes();
    out.extend_from_slice(data);
    out
}

/// A server+clone fixture rooted in a single RAII temp dir (#192, F3). The
/// `TempDir` removes the whole tree on drop — including while unwinding from a
/// failed assertion, timeout, or panic — so a failing test never leaves real git
/// repos behind, and the randomized root name cannot collide with or poison a
/// later run the way the old pid/counter names could.
struct Repos {
    server: PathBuf,
    clone: PathBuf,
    _tmp: tempfile::TempDir,
}

/// Run git in `dir` with deterministic identity/config, asserting success.
fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "protocol.version=2",
        ])
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn git {args:?}: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Run `git upload-pack --stateless-rpc [--advertise-refs] <repo>`, optionally
/// feeding `input` on stdin. Returns raw stdout (the wire bytes).
fn upload_pack(repo: &Path, advertise: bool, input: &[u8]) -> Vec<u8> {
    let mut cmd = Command::new("git");
    cmd.arg("upload-pack").arg("--stateless-rpc");
    if advertise {
        cmd.arg("--advertise-refs");
    }
    cmd.arg(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn git upload-pack");
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        // drop closes stdin
    });
    let out = child.wait_with_output().expect("wait upload-pack");
    writer.join().ok();
    assert!(
        out.status.success(),
        "git upload-pack failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[derive(Clone, Copy)]
enum ShimMode {
    /// Faithful v0 serving: pipe each POST to `git upload-pack --stateless-rpc`.
    Normal,
    /// The withheld-blob shape: ignore negotiation and answer the FIRST POST with
    /// a full self-contained pack (as `upload_pack_excluding` does on the node).
    WithheldFirstPost,
}

struct Shim {
    base_url: String,
    posts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Shim {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Nudge the accept loop with a throwaway connection so it observes `stop`.
        if let Ok(addr) = self
            .base_url
            .trim_start_matches("http://")
            .parse::<std::net::SocketAddr>()
        {
            let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Start a minimal smart-HTTP shim serving `repo` on 127.0.0.1. Handles the
/// upload-pack advertisement (GET) and pack negotiation (POST), counting POSTs.
fn start_shim(repo: PathBuf, mode: ShimMode) -> Shim {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let posts = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let posts_t = posts.clone();
    let stop_t = stop.clone();
    let handle = std::thread::spawn(move || {
        while !stop_t.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    handle_conn(stream, &repo, mode, &posts_t);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    Shim {
        base_url,
        posts,
        stop,
        handle: Some(handle),
    }
}

fn handle_conn(stream: TcpStream, repo: &Path, mode: ShimMode, posts: &AtomicUsize) {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut reader = BufReader::new(stream);

    // Request line.
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    // Headers.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }

    // Body.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok();
    }

    let (content_type, payload) = if method == "GET" && target.contains("/info/refs") {
        // v0 advertisement, wrapped exactly as the node's info_refs does.
        let adv = upload_pack(repo, true, b"");
        let mut wrapped = pkt(b"# service=git-upload-pack\n");
        wrapped.extend_from_slice(b"0000");
        wrapped.extend_from_slice(&adv);
        ("application/x-git-upload-pack-advertisement", wrapped)
    } else if method == "POST" && target.ends_with("/git-upload-pack") {
        let n = posts.fetch_add(1, Ordering::SeqCst);
        let out = match mode {
            ShimMode::Normal => upload_pack(repo, false, &body),
            ShimMode::WithheldFirstPost if n == 0 => full_pack_response(repo),
            ShimMode::WithheldFirstPost => upload_pack(repo, false, &body),
        };
        ("application/x-git-upload-pack-result", out)
    } else {
        write_response(reader.into_inner(), "404 Not Found", "text/plain", b"no");
        return;
    };

    write_response(reader.into_inner(), "200 OK", content_type, &payload);
}

/// The `upload_pack_excluding` shape: NAK plus a full self-contained pack,
/// negotiation ignored. Built by asking a real upload-pack for the tip with no
/// haves (want + done), which yields exactly `NAK` + the full pack.
fn full_pack_response(repo: &Path) -> Vec<u8> {
    let head = String::from_utf8(git(repo, &["rev-parse", "HEAD"])).unwrap();
    let head = head.trim();
    let mut req =
        pkt(format!("want {head} multi_ack_detailed side-band-64k ofs-delta\n").as_bytes());
    req.extend_from_slice(b"0000");
    req.extend_from_slice(&pkt(b"done\n"));
    upload_pack(repo, false, &req)
}

fn write_response(mut stream: TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Run `git fetch` in `clone` through the helper, with a hard timeout so a
/// regression to the deadlock fails fast instead of hanging the suite.
fn fetch_with_helper(clone: &Path, node_url: &str) -> (bool, std::process::Output) {
    let helper_bin = PathBuf::from(env!("CARGO_BIN_EXE_git-remote-gitlawb"));
    let helper_dir = helper_bin.parent().unwrap().to_path_buf();
    let path_env = match std::env::var_os("PATH") {
        Some(p) => {
            let mut dirs = vec![helper_dir.clone()];
            dirs.extend(std::env::split_paths(&p));
            std::env::join_paths(dirs).unwrap()
        }
        None => helper_dir.clone().into_os_string(),
    };

    let mut cmd = Command::new("git");
    cmd.args(["-c", "protocol.version=2"])
        .arg("-C")
        .arg(clone)
        .args(["fetch", "origin", "main"])
        .env("PATH", path_env)
        // Pin the C locale so git's diagnostics (asserted on by the withheld-path
        // test, e.g. `expected ACK/NAK`) are the untranslated English strings on a
        // machine/CI with git-l10n installed and LANG set to a translated locale.
        .env("LC_ALL", "C")
        .env("GITLAWB_NODE", node_url)
        .env("GITLAWB_KEY", "/nonexistent-key-for-anon-fetch");
    run_bounded(cmd, Duration::from_secs(30))
}

/// A synthetic non-success `ExitStatus` used only on the unix timeout path, where
/// `reap_group` has already consumed the child and the later `wait` returns ECHILD.
/// The timeout branch already reports `completed == false`, so the exact status is
/// not load-bearing; a killed/nonzero placeholder preserves the `Output` contract.
#[cfg(unix)]
fn exited_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    // Encode "terminated by SIGKILL" (signal 9), matching the group teardown.
    std::process::ExitStatus::from_raw(libc::SIGKILL)
}

#[cfg(not(unix))]
fn exited_status() -> std::process::ExitStatus {
    // Non-unix has no ECHILD analog: a Windows `wait` is handle-based, so even
    // after the job terminate (or the `reap_tree` fallback) has taken down the
    // leader on the timeout path, the later `wait` in `run_bounded` succeeds again
    // against the still-open handle. This stays unreachable in practice; spawn a
    // trivially-failing process to synthesize a nonzero status without an unstable
    // constructor.
    Command::new("cmd")
        .args(["/C", "exit 1"])
        .status()
        .expect("synthesize exit status")
}

/// Tear down the child's whole process group on the timeout path (INV-22).
///
/// With `process_group(0)` the child is its own group leader, so pgid == child pid.
/// SIGTERM the group, poll for ESRCH (every member gone) with a SIGKILL escalation
/// after a short grace, then a hard cap so a wedged process can never block the
/// caller unboundedly. Finally reap the leader so it does not linger as a zombie.
/// This closes ALL inherited pipe write-ends (leader AND the git-remote-gitlawb
/// descendant) so the reader joins in `run_bounded` return promptly.
#[cfg(unix)]
fn reap_group(child: &mut std::process::Child) {
    let pgid = child.id() as i32;
    // SAFETY: kill(2) takes only integers and borrows no Rust memory; ESRCH on an
    // already-gone group is ignored below via the kill(-pgid, 0) probe.
    unsafe {
        libc::kill(-pgid, libc::SIGTERM);
    }
    for step in 0..100u32 {
        // SAFETY: kill(-pgid, 0) only probes group liveness; no memory is touched.
        // A nonzero return means ESRCH — every member of the group has exited.
        if unsafe { libc::kill(-pgid, 0) } != 0 {
            break;
        }
        if step == 20 {
            // ~200ms SIGTERM grace elapsed; force the group down. Fires exactly once.
            // SAFETY: same as above — integer-only kill, no borrowed memory.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // ~1s hard cap total; reap the leader (best-effort) so it is not left a zombie.
    let _ = child.wait();
}

/// Fallback tree teardown for the non-unix timeout path (INV-22): the leader-only
/// counterpart used only when the Job Object could not be established at spawn.
///
/// The Job Object below is the correct primitive on Windows (it owns the tree
/// regardless of leader liveness), so this is now a best-effort fallback rather
/// than the main path. `taskkill /T /F` walks the parent-pid tree from the leader
/// and force-kills every member reachable through it, closing the inherited pipe
/// write-ends so the reader joins in `run_bounded` return instead of waiting out
/// the helper's ~300s HTTP timeout. taskkill ships in System32 on every supported
/// Windows and needs no `unsafe`. Its known limit is exactly why the job exists:
/// /T resolves the parent-pid tree at invocation time and cannot reach a
/// descendant once its leader has already exited. The `child.kill()` below is a
/// further leader-only fallback for the taskkill-unavailable case; finally reap
/// the leader so it does not linger, mirroring `reap_group`'s contract.
#[cfg(not(unix))]
fn reap_tree(child: &mut std::process::Child) {
    let _ = Command::new("taskkill")
        .args(["/T", "/F", "/PID", &child.id().to_string()])
        .output();
    let _ = child.kill();
    let _ = child.wait();
}

/// Windows analog of the unix process group: a Job Object that owns the whole
/// fetch tree so `git fetch` plus the `git-remote-gitlawb` helper it spawns can be
/// torn down together on BOTH the timeout and clean-exit paths (INV-22). The unix
/// path relies on `process_group(0)` + `reap_group`; Windows has no fork-style
/// group, so the tree is bounded by assigning the leader to a job and terminating
/// the job. Unlike `taskkill /T`, a job owns its members regardless of leader
/// liveness, which is what closes the clean-exit gap: once `git fetch` exits, the
/// parent-pid tree no longer reaches the still-blocked helper, but the job still
/// does.
///
/// The handle is held in this RAII owner so `Drop` closes it. Configured with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, closing the last handle also kills any
/// member not already terminated, a safety net for a stray the explicit
/// `TerminateJobObject` did not cover.
#[cfg(windows)]
struct JobHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for JobHandle {
    fn drop(&mut self) {
        // SAFETY: CloseHandle takes a single handle value and borrows no Rust
        // memory. With KILL_ON_JOB_CLOSE, closing the last handle also kills any
        // still-assigned member, the safety net for a member not explicitly torn
        // down. Closing an already-closed-elsewhere job is not possible here since
        // this owner holds the sole handle for its whole lifetime.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Create a Job Object, configure `KILL_ON_JOB_CLOSE`, and assign the freshly
/// spawned `child` to it, mirroring the unix `cmd.process_group(0)` at spawn.
/// Returns `None` if any step fails, in which case the caller falls back to the
/// leader-only `reap_tree` tree walk.
///
/// Honest caveat: this assigns the child right after `spawn` rather than via
/// `CREATE_SUSPENDED` + resume (which std cannot do without exposing the main
/// thread handle), so there is a tiny window between the process starting and the
/// assignment landing. In this harness the child is `git`, which spawns the
/// `git-remote-gitlawb` helper only after it parses config and reads the
/// advertisement, so the assignment reliably lands before the helper exists and
/// the helper is created inside the job. `KILL_ON_JOB_CLOSE` covers any stray that
/// somehow raced ahead.
#[cfg(windows)]
fn assign_job(child: &std::process::Child) -> Option<JobHandle> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    // SAFETY: CreateJobObjectW(null, null) creates a new unnamed, unsecured job and
    // returns its handle (or null on failure); the two null pointers are the
    // documented "default attributes / no name" arguments and no Rust memory is
    // borrowed.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return None;
    }
    // Own the handle now so an early return below still closes it via Drop.
    let owner = JobHandle(job);

    // SAFETY: `zeroed()` is a valid all-zero bit pattern for this plain-old-data
    // struct (only integers and nested POD, no references or non-null invariants).
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: passes a pointer to a fully-initialized, correctly-sized
    // JOBOBJECT_EXTENDED_LIMIT_INFORMATION together with its byte length; the call
    // copies out of the buffer and retains no reference to it.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return None; // `owner` drops here -> CloseHandle.
    }

    // SAFETY: assigns the child's OS process handle to the job. Both arguments are
    // raw handle values and no Rust memory is borrowed; the `Child` owns the
    // process handle and outlives this call, so `as_raw_handle` is valid here.
    let ok = unsafe { AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) };
    if ok == 0 {
        return None;
    }
    Some(owner)
}

/// Terminate every member of the job (INV-22): the Windows analog of `reap_group`
/// signalling `-pgid`, invoked on both the timeout and clean-exit teardown paths.
#[cfg(windows)]
fn terminate_job(job: &JobHandle) {
    // SAFETY: TerminateJobObject takes the job handle and an integer exit code and
    // borrows no Rust memory. Terminating an already-empty or already-terminated
    // job is a harmless no-op, so this is safe to call on the clean-exit path where
    // the descendant may already be gone.
    unsafe {
        windows_sys::Win32::System::JobObjects::TerminateJobObject(job.0, 1);
    }
}

/// Spawn `cmd`, draining stdout and stderr CONCURRENTLY on reader threads while
/// enforcing `timeout`. Returns `(completed_before_deadline, Output)` (#192, F2).
///
/// The concurrent drain is the whole point: polling `try_wait` without reading lets
/// a child that writes more than an OS pipe buffer (~64 KiB) block on the full pipe
/// before it exits, so the deadline would trip on pipe backpressure and report a
/// false "deadlock signature" even while the child is making progress. Draining
/// continuously makes the deadline measure a real hang only.
fn run_bounded(mut cmd: Command, timeout: Duration) -> (bool, std::process::Output) {
    // Run the child in its own process group so the whole fetch tree (git plus the
    // git-remote-gitlawb helper it spawns) can be torn down together on the timeout
    // path. Without this, killing only the leader leaves the helper alive, holding
    // the stderr pipe write-end until its own ~300s HTTP timeout, so the reader
    // joins below block far past the deadline instead of returning promptly (INV-22).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn child");

    // Windows analog of the unix `process_group(0)` above: Windows has no way to
    // set a group before spawn, so assign the freshly spawned leader to a Job
    // Object now. The job owns the whole fetch tree and is terminated on both
    // teardown paths below (INV-22). `None` if the job could not be established, in
    // which case teardown falls back to the taskkill tree walk.
    #[cfg(windows)]
    let job = assign_job(&child);

    let mut out_pipe = child.stdout.take().expect("stdout piped");
    let mut err_pipe = child.stderr.take().expect("stderr piped");
    let out_reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_pipe.read_to_end(&mut b);
        b
    });
    let err_reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_pipe.read_to_end(&mut b);
        b
    });

    let deadline = Instant::now() + timeout;
    let completed = loop {
        if child.try_wait().unwrap().is_some() {
            break true;
        }
        if Instant::now() >= deadline {
            // Tear down the WHOLE tree, not just the leader: the git-remote-gitlawb
            // helper is a descendant that inherited the stdout/stderr pipe write-ends,
            // so killing only `child` leaves those ends open and the reader joins wait
            // on the helper's ~300s HTTP timeout instead of returning at the deadline.
            // Taking down every member (the unix group signal, the windows job
            // terminate) closes every write-end so the readers finish promptly
            // (INV-22, mirrors gitlawb-node/src/git/smart_http.rs).
            #[cfg(unix)]
            reap_group(&mut child);
            // Windows: terminate the whole job (every assigned member); the taskkill
            // tree walk stays only as the fallback when the job was not established.
            #[cfg(windows)]
            match &job {
                Some(job) => {
                    terminate_job(job);
                    let _ = child.wait();
                }
                None => reap_tree(&mut child),
            }
            // Any other non-unix target keeps the leader-only tree walk.
            #[cfg(all(not(unix), not(windows)))]
            reap_tree(&mut child);
            break false; // timed out: the real deadlock signature
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    // Collect the leader's status. On the timeout path `reap_group` already reaped
    // it, so `wait` returns ECHILD; tolerate that and report the killed status the
    // loop observed. On the clean path `try_wait` above already reaped it, so this
    // returns the cached real status.
    let status = child.wait().unwrap_or_else(|_| {
        debug_assert!(!completed, "clean-exit path must still be reapable here");
        exited_status()
    });

    // A leader that exits on its own does NOT guarantee the pipes are closed: a
    // descendant (the git-remote-gitlawb helper mid-HTTP request) can outlive the
    // leader while still holding the inherited stdout/stderr write-ends, so the
    // reader joins below would block on its ~300s HTTP timeout, past the deadline
    // this function promises (#192 F2, INV-22). The timeout path already tore the
    // group down; on the clean path, close it here too. A process-group ID stays
    // reserved while any member is alive, so signalling the group is safe as long as
    // `kill(-pgid, 0)` still reports a live member; once the group is empty the pipes
    // are closed anyway and the leader's reaped pid may have been recycled, so skip.
    #[cfg(unix)]
    if completed {
        let pgid = child.id() as i32;
        // SAFETY: kill(-pgid, 0) only probes group liveness; it borrows no memory.
        if unsafe { libc::kill(-pgid, 0) } == 0 {
            reap_group(&mut child);
        }
    }

    // Windows clean-exit sibling of the unix reap above, and the core of this fix
    // (jatmn's [P2]): a leader (`git fetch`) that exits cleanly does NOT let
    // `taskkill /T` reach a still-blocked helper descendant, because the parent-pid
    // tree no longer connects them once the leader is gone. So on the clean path the
    // reader joins below would stall on the helper's ~300s HTTP timeout past the
    // bound this function promises. Terminating the job kills every member
    // regardless of leader liveness, so the joins return at the leader's exit. This
    // runs whether or not the descendant is still alive; terminating an
    // already-empty job is a harmless no-op (INV-22).
    #[cfg(windows)]
    if completed {
        if let Some(job) = &job {
            terminate_job(job);
        }
    }

    let stdout = out_reader.join().expect("stdout reader");
    let stderr = err_reader.join().expect("stderr reader");
    (
        completed,
        std::process::Output {
            status,
            stdout,
            stderr,
        },
    )
}

// ---------------------------------------------------------------------------
// Self-exec fixtures (#192 review, portability of the run_bounded tests).
//
// The harness tests below need child processes with controlled behavior: a bulk
// writer and a pipe-holding descendant tree. Spawning `sh` for these breaks the
// shipped x86_64-pc-windows-msvc target, where neither `sh` nor `seq` is a
// guaranteed dependency; the one executable guaranteed present on every target
// is this test binary itself. Each fixture is an `#[ignore]`d test that no-ops
// unless its GL_TEST_FIXTURE mode is set, so normal `cargo test` runs skip them
// and even an explicit `--ignored` run without the env var does nothing.
// `fixture_command` builds the re-invocation: the positional libtest filter
// plus `--exact` selects exactly one test, `--ignored` opts into it, and
// `--nocapture` keeps libtest from interposing on the streams.
// ---------------------------------------------------------------------------

/// Build a Command that re-invokes this test binary to run one fixture test.
fn fixture_command(fixture_test: &str, mode: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
    cmd.args([fixture_test, "--exact", "--ignored", "--nocapture"])
        .env("GL_TEST_FIXTURE", mode);
    cmd
}

/// Fixture: write ~136 KiB of numbered lines to BOTH stdout and stderr, then
/// exit 0. Direct handle writes (not println!) so libtest output capture cannot
/// swallow the bytes. The harness noise libtest prints ("running 1 test", the
/// result line) also lands on stdout; the caller's >64 KiB assertions are
/// insensitive to it.
#[test]
#[ignore = "self-exec fixture: only runs under GL_TEST_FIXTURE=emit"]
fn fixture_emit_large_output() {
    if std::env::var("GL_TEST_FIXTURE").ok().as_deref() != Some("emit") {
        return;
    }
    let mut payload = Vec::with_capacity(160 * 1024);
    for i in 1..=25_000u32 {
        writeln!(payload, "{i}").expect("write to Vec");
    }
    std::io::stdout().write_all(&payload).expect("write stdout");
    std::io::stderr().write_all(&payload).expect("write stderr");
}

/// Fixture: sleep 10s while holding whatever stdio handles were inherited.
#[test]
#[ignore = "self-exec fixture: only runs under GL_TEST_FIXTURE=sleep"]
fn fixture_sleep() {
    if std::env::var("GL_TEST_FIXTURE").ok().as_deref() != Some("sleep") {
        return;
    }
    std::thread::sleep(Duration::from_secs(10));
}

/// Fixture: spawn a grandchild (`fixture_sleep`) whose stdio is inherited, so a
/// DESCENDANT holds the caller's pipe write-ends, then stay alive 10s so the
/// leader is long-lived too. This mirrors the retired
/// `sh -c "sleep 10 & exec sleep 10"` shape: one leader plus one descendant,
/// both holding the pipes well past any deadline the caller sets.
#[test]
#[ignore = "self-exec fixture: only runs under GL_TEST_FIXTURE=hold"]
fn fixture_hold_pipe_with_descendant() {
    if std::env::var("GL_TEST_FIXTURE").ok().as_deref() != Some("hold") {
        return;
    }
    // Stdio is inherited by default, so the grandchild holds the same pipe
    // write-ends the caller handed this leader.
    let mut grandchild = fixture_command("fixture_sleep", "sleep")
        .spawn()
        .expect("spawn grandchild fixture");
    std::thread::sleep(Duration::from_secs(10));
    // Reap on the natural-exit path (both sleeps are 10s, so this returns almost
    // immediately). Under the harness the whole tree is killed at the deadline,
    // long before this line runs.
    let _ = grandchild.wait();
}

/// Build a server repo with a shared history deep enough to force multi-round
/// negotiation (>~32 haves), plus a clone of it, then advance the server so the
/// fetch has something to negotiate. Returns (server, clone).
fn build_divergent_repos(shared_commits: usize) -> Repos {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = tmp.path().join("server");
    std::fs::create_dir_all(&server).unwrap();
    git(&server, &["init", "-q"]);
    std::fs::write(server.join("base.txt"), b"base").unwrap();
    git(&server, &["add", "."]);
    git(&server, &["commit", "-q", "-m", "base"]);
    // A deep shared history the clone will offer as haves.
    for i in 0..shared_commits {
        git(
            &server,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("shared-{i}"),
            ],
        );
    }

    let clone = tmp.path().join("clone");
    // Clone over file:// so the clone shares the full history.
    let status = Command::new("git")
        .args(["clone", "-q"])
        .arg(&server)
        .arg(&clone)
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "clone failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    // Advance the server so the fetch must transfer new objects.
    for i in 0..3 {
        git(
            &server,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("server-{i}"),
            ],
        );
    }

    // Point the clone's origin at the gitlawb:// scheme so git invokes the helper.
    git(
        &clone,
        &[
            "remote",
            "set-url",
            "origin",
            "gitlawb://did:key:zTESTOWNER/myrepo",
        ],
    );
    Repos {
        server,
        clone,
        _tmp: tmp,
    }
}

/// Matrix item 7, bridging half: a real multi-round `git fetch` through the
/// helper against a real `git upload-pack --stateless-rpc` completes, is observed
/// at >=2 POSTs (the executable form of the trigger; a fixture that resolved in
/// one round would fail this), and produces a correct object graph.
#[test]
fn real_git_multi_round_fetch_completes() {
    // `repos` owns the RAII temp dir; keep it in scope so cleanup runs on drop,
    // including while unwinding from any assertion below (#192, F3).
    let repos = build_divergent_repos(50);
    let (server, clone) = (repos.server.clone(), repos.clone.clone());
    let shim = start_shim(server.clone(), ShimMode::Normal);

    let (completed, out) = fetch_with_helper(&clone, &shim.base_url);
    let posts = shim.posts.load(Ordering::SeqCst);

    assert!(
        completed,
        "git fetch did not complete within the timeout (deadlock signature). stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "git fetch failed. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        posts >= 2,
        "fixture did not force multi-round negotiation (observed {posts} POST(s)); the bridging path was not exercised"
    );

    // The fetched tip is present and the clone's object graph is intact.
    let server_head = String::from_utf8(git(&server, &["rev-parse", "HEAD"])).unwrap();
    let fetched = String::from_utf8(git(&clone, &["rev-parse", "FETCH_HEAD"])).unwrap();
    assert_eq!(
        server_head.trim(),
        fetched.trim(),
        "FETCH_HEAD must match the server tip"
    );
    git(&clone, &["fsck", "--full"]);
    // No manual cleanup: `repos` drops here (or on unwind) and removes the tree.
}

/// #192 (F3): a panic (any unwind) mid-test still removes the repos. The old
/// success-only `cleanup()` ran after the assertions, so a failing test leaked real
/// git repos; the RAII `TempDir` drops during unwind instead. Load-bearing: the
/// path exists inside the closure and must be gone once the panic has unwound past
/// the guard — a non-RAII cleanup would leave it behind.
#[test]
fn repos_are_cleaned_up_on_unwind() {
    let captured = Arc::new(std::sync::Mutex::new(None::<PathBuf>));
    let c = captured.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let repos = build_divergent_repos(1);
        assert!(
            repos._tmp.path().exists(),
            "temp dir exists during the test"
        );
        *c.lock().unwrap() = Some(repos._tmp.path().to_path_buf());
        panic!("simulated mid-test failure");
    }));
    assert!(result.is_err(), "the closure panicked as designed");
    let path = captured
        .lock()
        .unwrap()
        .take()
        .expect("captured the temp path");
    assert!(
        !path.exists(),
        "the RAII temp dir must be removed on unwind, not leaked: {}",
        path.display()
    );
}

/// #192 (F2): `run_bounded` must DRAIN a child that emits more than an OS pipe
/// buffer, not deadlock. A child writing ~136 KiB to BOTH stdout and stderr and
/// then exiting must complete within the deadline. Under a `try_wait`-only harness
/// (no concurrent drain) the child blocks on the full pipe, the deadline trips, and
/// `completed` is false — the exact false "deadlock signature" F2 fixes. Reverting
/// the concurrent drain to poll-then-read turns this test RED (completed=false).
#[test]
fn run_bounded_drains_large_output_without_deadlock() {
    // The emit fixture writes ~136 KiB per stream, well past a ~64 KiB pipe
    // buffer (self-exec, not `sh -c seq`: portable to the shipped windows target).
    let cmd = fixture_command("fixture_emit_large_output", "emit");
    let (completed, out) = run_bounded(cmd, Duration::from_secs(10));
    assert!(
        completed,
        "a child emitting >64 KiB must be drained and complete, not deadlock (F2)"
    );
    assert!(out.status.success(), "the child exited cleanly");
    assert!(
        out.stdout.len() > 64 * 1024 && out.stderr.len() > 64 * 1024,
        "both streams exceeded a pipe buffer (stdout={}, stderr={})",
        out.stdout.len(),
        out.stderr.len()
    );
}

/// Matrix item 7, withheld half (the Withheld-Path Decision gate): the node's
/// `upload_pack_excluding` answers the FIRST POST with NAK plus a full pack,
/// mid-negotiation. Drive that shape through REAL git and record whether it
/// accepts a pack where it expected an ACK continuation. If real git rejects it,
/// this test captures the break mode that the decision's remedy addresses.
#[test]
fn real_git_withheld_shaped_first_post() {
    // `repos` owns the RAII temp dir; keep it in scope so cleanup runs on drop,
    // including while unwinding from any assertion below (#192, F3).
    let repos = build_divergent_repos(50);
    let (server, clone) = (repos.server.clone(), repos.clone.clone());
    let shim = start_shim(server.clone(), ShimMode::WithheldFirstPost);

    let (completed, out) = fetch_with_helper(&clone, &shim.base_url);
    let posts = shim.posts.load(Ordering::SeqCst);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    // The helper itself must not hang or panic regardless of git's verdict.
    assert!(
        completed,
        "helper hung on a withheld-shaped response (should forward-and-terminate, not deadlock). stderr:\n{stderr}"
    );

    if out.status.success() {
        // Real git accepted the mid-negotiation pack: the withheld multi-round
        // path works end to end with no extra handling.
        let server_head = String::from_utf8(git(&server, &["rev-parse", "HEAD"])).unwrap();
        let fetched = String::from_utf8(git(&clone, &["rev-parse", "FETCH_HEAD"])).unwrap();
        assert_eq!(server_head.trim(), fetched.trim());
        git(&clone, &["fsck", "--full"]);
    } else {
        // Real git rejected the mid-negotiation pack. This is a genuine outcome,
        // not a helper defect (the helper forwarded and terminated cleanly). The
        // Withheld-Path Decision's remedy owns the fix; this branch documents the
        // observed break so a regression in the assumption is visible in CI.
        //
        // Guard the path this test claims to record (INV-21): the nonzero exit is
        // only the withheld rejection if the helper actually reached the shim and
        // sent the withheld-shaped POST. A failure BEFORE the first POST — a broken
        // advertisement, helper lookup, or connection — must not masquerade as the
        // expected rejection, or a regression that never hits the shim would pass.
        assert!(
            posts >= 1,
            "fetch failed with 0 POSTs to the shim: a pre-POST failure (broken \
             advertisement / helper lookup / connection) is NOT the withheld \
             rejection this test records. git stderr:\n{stderr}"
        );
        // Bind to the SPECIFIC #191 break, not any nonzero exit. Real git rejects
        // the NAK+pack mid-negotiation with `fatal: git fetch-pack: expected
        // ACK/NAK, got '...'`. A truncated/corrupt response or a later HTTP failure
        // after the first POST would also exit nonzero with posts>=1; asserting the
        // signature keeps those from masquerading as the recorded rejection.
        assert!(
            stderr.contains("expected ACK/NAK"),
            "nonzero exit with posts>=1 but not the recorded #191 rejection \
             (`expected ACK/NAK`): a different failure must not pass as the \
             withheld-path break. git stderr:\n{stderr}"
        );
        eprintln!(
            "WITHHELD-PATH NOTE (#117): real git did NOT accept a NAK+pack mid-negotiation \
             (observed {posts} POST(s)). Per the Withheld-Path Decision this routes to a node-side \
             follow-up or an accepted withheld=full-clone limitation, not helper code. git stderr:\n{stderr}"
        );
    }

    // No manual cleanup: `repos` drops here (or on unwind) and removes the tree.
}

/// #192 (F1, INV-22): on the timeout path `run_bounded` must tear down the WHOLE
/// process tree, not just the leader. The hold fixture spawns a grandchild that
/// inherits the pipe write-ends and sleeps 10s, and the leader stays alive 10s
/// too. With a 1s deadline the timeout fires; if only the leader were killed,
/// the surviving grandchild would keep the pipes open and the reader joins would
/// block for its full ~10s lifetime. Tearing down every member closes every
/// write-end, so `run_bounded` returns promptly. This runs on every target, so
/// the unix group signal and the windows job terminate are each covered on the
/// platform where they compile. Reverting either teardown to a leader-only
/// `child.kill()` turns this RED there (elapsed ~10s, the assert below fires).
#[test]
fn run_bounded_reaps_descendants_holding_the_pipe() {
    // A long-lived leader plus a pipe-holding descendant (the self-exec
    // replacement for `sh -c "sleep 10 & exec sleep 10"`).
    let cmd = fixture_command("fixture_hold_pipe_with_descendant", "hold");

    let start = Instant::now();
    let (completed, _out) = run_bounded(cmd, Duration::from_secs(1));
    let elapsed = start.elapsed();

    assert!(
        !completed,
        "the leader outlived the 1s deadline, so run_bounded must report a timeout"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "reader joins blocked on a surviving descendant instead of the deadline: \
         elapsed={elapsed:?} (expected <4s; a leader-only kill leaves the \
         grandchild fixture holding the pipes for its full lifetime)"
    );
}

/// Fixture: spawn a detached grandchild (`fixture_sleep`) that inherits the stdio
/// pipes, then the LEADER returns immediately. This is the leader-exits-first
/// shape (#192 F2): the leader is gone almost at once, well before any deadline,
/// but the descendant keeps the caller's pipe write-ends open for its full
/// lifetime. Dropping the `Child` handle neither kills nor waits it, so the
/// grandchild stays alive holding the pipes.
// Leaving the grandchild unreaped is the point: the leader exits without waiting
// it, so a descendant outlives the leader still holding the inherited pipes.
#[allow(clippy::zombie_processes)]
#[test]
#[ignore = "self-exec fixture: only runs under GL_TEST_FIXTURE=exit_holder"]
fn fixture_exit_leaving_pipe_holder() {
    if std::env::var("GL_TEST_FIXTURE").ok().as_deref() != Some("exit_holder") {
        return;
    }
    // Stdio is inherited by default, so the grandchild holds the same pipe
    // write-ends the caller handed this leader. Do not wait on it: the leader
    // returns now, leaving the grandchild alive and holding the pipes.
    let _detached = fixture_command("fixture_sleep", "sleep")
        .spawn()
        .expect("spawn grandchild fixture");
}

/// Leader-exits-first companion to `run_bounded_reaps_descendants_holding_the_pipe`
/// (#192 F2). The leader spawns a pipe-holding descendant and returns immediately,
/// so `try_wait` sees it gone and the loop breaks `completed` well before the
/// deadline. The descendant still holds the reader pipes, so without closing the
/// group (unix) / terminating the job (windows) on the clean-exit path the reader
/// joins block on the descendant's full lifetime (~10s here; the real helper's
/// ~300s HTTP timeout). Reverting the clean-path teardown in `run_bounded` turns
/// this RED (elapsed ~10s).
///
/// Runs on both platforms so a future Windows CI lane exercises the Job Object
/// clean-exit teardown, which is exactly the case `taskkill /T` cannot cover: once
/// the leader exits, the parent-pid tree no longer reaches the descendant, but the
/// job still owns it. On this Linux box it runs the unix process-group path and
/// passes; the Windows teardown here runs once issue #228's Windows CI lane exists.
#[test]
fn run_bounded_bounds_join_when_leader_exits_leaving_a_pipe_holder() {
    let cmd = fixture_command("fixture_exit_leaving_pipe_holder", "exit_holder");

    let start = Instant::now();
    // A 30s deadline the leader never approaches: it exits almost immediately, so
    // this exercises the clean-exit path, not the timeout path.
    let (completed, _out) = run_bounded(cmd, Duration::from_secs(30));
    let elapsed = start.elapsed();

    assert!(
        completed,
        "the leader exited well within the 30s deadline, so run_bounded must report \
         completion rather than a timeout"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "reader joins blocked on a descendant that outlived the leader: \
         elapsed={elapsed:?} (expected <5s; the clean-exit path must close the \
         process group (unix) / terminate the job (windows) so the grandchild's \
         held pipes do not stall the joins)"
    );
}
