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

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("gitlawb-u7-{}-{}-{}", tag, std::process::id(), n));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

    let mut child = Command::new("git")
        .args(["-c", "protocol.version=2"])
        .arg("-C")
        .arg(clone)
        .args(["fetch", "origin", "main"])
        .env("PATH", path_env)
        .env("GITLAWB_NODE", node_url)
        .env("GITLAWB_KEY", "/nonexistent-key-for-anon-fetch")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn git fetch");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(_status) = child.try_wait().unwrap() {
            let out = child.wait_with_output().unwrap();
            return (true, out);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            return (false, out); // timed out: the deadlock signature
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Build a server repo with a shared history deep enough to force multi-round
/// negotiation (>~32 haves), plus a clone of it, then advance the server so the
/// fetch has something to negotiate. Returns (server, clone).
fn build_divergent_repos(shared_commits: usize) -> (PathBuf, PathBuf) {
    let server = unique_dir("server");
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

    let clone = unique_dir("clone");
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
    (server, clone)
}

/// Matrix item 7, bridging half: a real multi-round `git fetch` through the
/// helper against a real `git upload-pack --stateless-rpc` completes, is observed
/// at >=2 POSTs (the executable form of the trigger; a fixture that resolved in
/// one round would fail this), and produces a correct object graph.
#[test]
fn real_git_multi_round_fetch_completes() {
    let (server, clone) = build_divergent_repos(50);
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

    cleanup(&[server, clone]);
}

/// Matrix item 7, withheld half (the Withheld-Path Decision gate): the node's
/// `upload_pack_excluding` answers the FIRST POST with NAK plus a full pack,
/// mid-negotiation. Drive that shape through REAL git and record whether it
/// accepts a pack where it expected an ACK continuation. If real git rejects it,
/// this test captures the break mode that the decision's remedy addresses.
#[test]
fn real_git_withheld_shaped_first_post() {
    let (server, clone) = build_divergent_repos(50);
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

    cleanup(&[server, clone]);
}

fn cleanup(dirs: &[PathBuf]) {
    for d in dirs {
        let _ = std::fs::remove_dir_all(d);
    }
}
