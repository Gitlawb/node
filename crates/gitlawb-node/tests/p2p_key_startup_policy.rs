//! Which p2p key-storage failures stop the node, and which leave HTTP up.
//!
//! The two domains are decided by different code at different phases, so the
//! only honest proof is at the process boundary: spawn the real binary and
//! watch what it does. A helper's returned error says nothing about whether
//! `main` treated it as fatal.
//!
//! Every row also asserts the key tree is byte-identical afterwards. A refusal
//! that mutates storage on its way out is its own defect, and a returned error
//! cannot show that.
//!
//! No database: `DATABASE_URL` points at a closed port on purpose, so a row
//! that reaches the degraded server proves the outcome is observable without
//! Postgres. That is what makes the port-zero no-I/O guarantee testable at all.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Wall clock, never an iteration count: a fixed loop count starves on a slow
/// or loaded machine and turns a real pass into a flake.
const DEADLINE: Duration = Duration::from_secs(15);

/// Kills the child on every exit path, including a panicking assertion.
///
/// Without this a failing row leaves a node behind that retries its database
/// connection forever, holding the row's tempdir open. The first run of this
/// file did exactly that, and the leak is invisible until something else in
/// the suite gets slow.
struct ChildGuard(Child);

impl ChildGuard {
    /// The tracing subscriber writes to STDOUT; only anyhow's final error
    /// print goes to stderr. A row that watches one stream sees half the
    /// story, so both are read.
    fn take_stdout(&mut self) -> std::process::ChildStdout {
        self.0.stdout.take().expect("stdout piped")
    }

    fn take_stderr(&mut self) -> std::process::ChildStderr {
        self.0.stderr.take().expect("stderr piped")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `(path, is_dir, is_symlink, mode, len)` for everything under `root`, sorted.
/// Taken before and after each row so a refusal that creates, chmods, or
/// deletes anything fails the row.
fn snapshot(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            out.push(format!(
                "{} dir={} link={} mode={:04o} len={}",
                p.display(),
                md.is_dir(),
                md.is_symlink(),
                md.permissions().mode() & 0o7777,
                if md.is_file() { md.len() } else { 0 }
            ));
            if md.is_dir() && !md.is_symlink() {
                walk(&p, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}

struct Row {
    /// Sandbox the row owns: HOME, repos, cwd and the key tree all live here.
    home: tempfile::TempDir,
}

impl Row {
    /// The only directory the no-mutation assertions watch.
    fn tree(&self) -> PathBuf {
        self.home.path().join("keytree")
    }
}

impl Row {
    fn new() -> Row {
        let home = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod home");
        // Created here, before any row takes its `before` snapshot, so the
        // no-mutation assertions measure what the NODE did and not what this
        // harness set up.
        std::fs::create_dir_all(home.path().join("repos")).expect("repos dir");
        // The p2p key tree lives in its own subdirectory so the no-mutation
        // assertions can watch exactly it. HOME also holds `.gitlawb`, which
        // the node creates for its NODE identity on every start; measuring the
        // whole home would read that legitimate write as a p2p storage
        // mutation.
        let tree = home.path().join("keytree");
        std::fs::create_dir(&tree).expect("key tree");
        std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700))
            .expect("chmod key tree");
        Row { home }
    }

    fn spawn(&self, p2p_key: &str, p2p_port: &str, cwd: &Path) -> ChildGuard {
        let repos = self.home.path().join("repos");
        Command::new(env!("CARGO_BIN_EXE_gitlawb-node"))
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            // The subscriber is built from the default env filter, so with a
            // cleared environment the node logs nothing at all and every
            // assertion here reads as a timeout with empty output. The rows
            // are about which log lines appear, so the filter is part of the
            // fixture, not incidental setup.
            .env("RUST_LOG", "info")
            .env("HOME", self.home.path())
            .env("GITLAWB_REPOS_DIR", &repos)
            .env("GITLAWB_HOST", "127.0.0.1")
            // Ephemeral: the real port is read back from the ready log.
            .env("GITLAWB_PORT", "0")
            // A closed port, so the node stays on the degraded path for the
            // whole row instead of ever reaching a database.
            .env("DATABASE_URL", "postgres://127.0.0.1:1/nonexistent")
            .env("GITLAWB_P2P_PORT", p2p_port)
            .env("GITLAWB_P2P_KEY", p2p_key)
            .env("GITLAWB_METRICS_ADDR", "")
            .current_dir(cwd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map(ChildGuard)
            .expect("spawn gitlawb-node")
    }
}

/// Read the child's stderr until `needle` appears, the stream ends, or the
/// deadline passes. Returns everything read.
///
/// The read runs on its own thread feeding a channel, and the deadline is
/// enforced with `recv_timeout`. Checking elapsed time between blocking
/// `read_line` calls does NOT work: a child that goes quiet blocks the read
/// forever and the check never runs, so the deadline looks present and cannot
/// fire. The first version of this file did that and hung for minutes on a row
/// that was supposed to fail in fifteen seconds.
fn read_until(child: &mut ChildGuard, needle: &str) -> (bool, String) {
    let stdout = child.take_stdout();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut acc = String::new();
    let start = Instant::now();
    loop {
        if acc.contains(needle) {
            return (true, acc);
        }
        let left = match DEADLINE.checked_sub(start.elapsed()) {
            Some(d) if !d.is_zero() => d,
            _ => return (false, acc),
        };
        match rx.recv_timeout(left) {
            Ok(line) => acc.push_str(&line),
            // Sender gone: the stream ended. One last check, then give up.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return (acc.contains(needle), acc)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return (false, acc),
        }
    }
}

fn wait_for_exit(child: &mut ChildGuard) -> (std::process::ExitStatus, String) {
    // Both streams: the refusal reason is anyhow's stderr print, while
    // "binding HTTP listener" is a tracing line on stdout, and the fatal rows
    // assert on one of each.
    let mut out = String::new();
    let mut o = child.take_stdout();
    let mut e = child.take_stderr();
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = o.read_to_string(&mut buf);
        buf
    });
    let _ = e.read_to_string(&mut out);
    let status = child.0.wait().expect("wait");
    out.push_str(&reader.join().unwrap_or_default());
    (status, out)
}

/// Strip ANSI escapes: the subscriber colourises even when piped, which would
/// otherwise sit between `addr=` and the value.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A lexically invalid value must stop the process before the listener binds.
fn assert_fatal_before_bind(row: &Row, key: &str, cwd: &Path) {
    let before = snapshot(&row.tree());
    let mut child = row.spawn(key, "7546", cwd);
    let (status, err) = wait_for_exit(&mut child);

    assert!(
        !status.success(),
        "key={key:?} must exit non-zero\n--- stderr ---\n{err}"
    );
    assert!(
        err.contains("invalid configuration"),
        "key={key:?} must fail as invalid configuration\n--- stderr ---\n{err}"
    );
    assert!(
        !err.contains("binding HTTP listener"),
        "key={key:?} must be refused BEFORE the listener binds\n--- stderr ---\n{err}"
    );
    assert_eq!(
        snapshot(&row.tree()),
        before,
        "key={key:?}: a configuration refusal must not touch the key tree"
    );
}

/// A live storage fault must leave HTTP serving with p2p off, and must not
/// mutate the tree on its way to that verdict.
fn assert_degrades_with_http_up(row: &Row, key: &str, cwd: &Path, label: &str) {
    let before = snapshot(&row.tree());
    let mut child = row.spawn(key, "7546", cwd);
    let (found, log) = read_until(&mut child, "degraded HTTP server ready");
    assert!(
        found,
        "{label}: the node must bind and serve while p2p is off\n--- stderr ---\n{log}"
    );
    assert!(
        log.contains("failed to load p2p identity key"),
        "{label}: the p2p failure must be logged\n--- stderr ---\n{log}"
    );

    let clean = strip_ansi(&log);
    let addr = clean
        .lines()
        .find(|l| l.contains("degraded HTTP server ready"))
        .and_then(|l| l.rsplit("addr=").next())
        .map(|a| {
            a.trim()
                .trim_start_matches("Some(")
                .trim_matches(|c| c == '"' || c == ')')
        })
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .unwrap_or_else(|| panic!("{label}: could not parse the bound address from {clean}"));

    // A served response, any status: the degraded server answers 503, which is
    // still proof the port is up and answering.
    let mut sock = std::net::TcpStream::connect(addr).expect("connect to the degraded server");
    sock.set_read_timeout(Some(DEADLINE)).unwrap();
    sock.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("send request");
    let mut resp = String::new();
    let _ = sock.read_to_string(&mut resp);
    assert!(
        resp.starts_with("HTTP/1.1 "),
        "{label}: the degraded server must answer, got {resp:?}"
    );

    drop(child);
    assert_eq!(
        snapshot(&row.tree()),
        before,
        "{label}: a storage refusal must not mutate the key tree"
    );
}

#[test]
fn lexically_invalid_key_paths_stop_the_node_before_it_binds() {
    for key in [
        "p2p.key",
        "./p2p.key",
        "a/../p2p.key",
        "../p2p.key",
        "/p2p.key",
        "keys/",
        "~/",
        "~//etc/p2p.key",
        "~/../x/p2p.key",
    ] {
        let row = Row::new();
        let cwd = row.home.path().to_path_buf();
        assert_fatal_before_bind(&row, key, &cwd);
    }
}

#[test]
fn live_storage_faults_leave_http_up_with_p2p_off() {
    // Symlinked final parent.
    {
        let row = Row::new();
        let real = row.tree().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = row.tree().join("keys");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let key = link.join("p2p.key");
        let cwd = row.home.path().to_path_buf();
        assert_degrades_with_http_up(&row, key.to_str().unwrap(), &cwd, "symlinked parent");
    }

    // Regular file where the key directory should be.
    {
        let row = Row::new();
        let file = row.tree().join("keys");
        std::fs::write(&file, b"not a directory").unwrap();
        let key = file.join("p2p.key");
        let cwd = row.home.path().to_path_buf();
        assert_degrades_with_http_up(&row, key.to_str().unwrap(), &cwd, "regular-file parent");
    }

    // Unreadable parent: an inspection error, the purest instance of a live
    // fault that used to be reported as invalid configuration.
    {
        let row = Row::new();
        let parent = row.tree().join("locked");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
        let key = parent.join("keys").join("p2p.key");
        let cwd = row.home.path().to_path_buf();
        assert_degrades_with_http_up(&row, key.to_str().unwrap(), &cwd, "unreadable parent");
        // Restore so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700));
    }

    // World-writable non-sticky ancestor: already the degrade class today, kept
    // so the row set covers both sides of the policy.
    {
        let row = Row::new();
        let anc = row.tree().join("open");
        std::fs::create_dir(&anc).unwrap();
        std::fs::set_permissions(&anc, std::fs::Permissions::from_mode(0o777)).unwrap();
        let key = anc.join("keys").join("p2p.key");
        let cwd = row.home.path().to_path_buf();
        assert_degrades_with_http_up(&row, key.to_str().unwrap(), &cwd, "world-writable ancestor");
    }
}

#[test]
fn port_zero_does_no_key_storage_io_at_all() {
    // A lexically invalid path that would be fatal with p2p enabled.
    {
        let row = Row::new();
        let before = snapshot(&row.tree());
        let cwd = row.home.path().to_path_buf();
        let mut child = row.spawn("p2p.key", "0", &cwd);
        let (found, log) = read_until(&mut child, "p2p disabled");
        assert!(
            found,
            "port zero must bypass key handling entirely\n--- stderr ---\n{log}"
        );
        drop(child);
        assert_eq!(
            snapshot(&row.tree()),
            before,
            "port zero must not touch the key tree"
        );
    }

    // A hostile tree that would degrade with p2p enabled.
    {
        let row = Row::new();
        let real = row.tree().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = row.tree().join("keys");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let before = snapshot(&row.tree());
        let cwd = row.home.path().to_path_buf();
        let key: PathBuf = link.join("p2p.key");
        let mut child = row.spawn(key.to_str().unwrap(), "0", &cwd);
        let (found, log) = read_until(&mut child, "p2p disabled");
        assert!(
            found,
            "port zero must bypass a hostile tree too\n--- stderr ---\n{log}"
        );
        drop(child);
        assert_eq!(
            snapshot(&row.tree()),
            before,
            "port zero must not touch a hostile key tree"
        );
    }
}
