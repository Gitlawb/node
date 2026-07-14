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
        .env("GITLAWB_NODE", node_url)
        .env("GITLAWB_KEY", "/nonexistent-key-for-anon-fetch");
    run_bounded(cmd, Duration::from_secs(30))
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
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");

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
            let _ = child.kill(); // closes the pipes so the readers finish
            break false; // timed out: the real deadlock signature
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    // The child has exited (or been killed), so the pipes are closed and the reader
    // threads run to completion. Reap the child and collect the drained output.
    let status = child.wait().expect("reap child");
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
/// buffer, not deadlock. A child writing ~140 KiB to BOTH stdout and stderr and
/// then exiting must complete within the deadline. Under a `try_wait`-only harness
/// (no concurrent drain) the child blocks on the full pipe, the deadline trips, and
/// `completed` is false — the exact false "deadlock signature" F2 fixes. Reverting
/// the concurrent drain to poll-then-read turns this test RED (completed=false).
#[test]
fn run_bounded_drains_large_output_without_deadlock() {
    // seq 1..=25000 is ~140 KiB on each stream — well past a ~64 KiB pipe buffer.
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("seq 1 25000; seq 1 25000 1>&2");
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
        eprintln!(
            "WITHHELD-PATH NOTE (#117): real git did NOT accept a NAK+pack mid-negotiation \
             (observed {posts} POST(s)). Per the Withheld-Path Decision this routes to a node-side \
             follow-up or an accepted withheld=full-clone limitation, not helper code. git stderr:\n{stderr}"
        );
    }

    // No manual cleanup: `repos` drops here (or on unwind) and removes the tree.
}
