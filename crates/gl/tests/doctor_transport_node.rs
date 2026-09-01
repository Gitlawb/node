//! `gl doctor` must diagnose the node the git transport will actually use.
//!
//! `gl`'s `--node` defaults to the public node while `git-remote-gitlawb` falls
//! back to a local one, and an explicit `--node` outranks the environment. So the
//! two disagree whenever GITLAWB_NODE is unset, blank, or overridden, and doctor's
//! own `node` row describes a URL `git clone` and `git push` never contact.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

/// Substring that marks the divergence clause. Present only when gl and the git
/// transport resolve different nodes.
const DIVERGENCE: &str = "git push/clone will use";

struct Run {
    stdout: String,
    code: Option<i32>,
}

impl Run {
    /// The single output line carrying the divergence clause, so an assertion
    /// cannot be satisfied by an unrelated row that happens to print the same URL.
    fn divergence_line(&self) -> Option<&str> {
        self.stdout.lines().find(|l| l.contains(DIVERGENCE))
    }
}

fn doctor(env_node: Option<&str>, gl_node: &str) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gl"));
    cmd.args(["doctor", "--node", gl_node])
        .arg("--dir")
        .arg(dir.path().join("gitlawb"))
        // Keep the run off the network: doctor also probes iCaptcha and the
        // GitHub release API, neither of which this test is about.
        .env("GITLAWB_ICAPTCHA_URL", "http://127.0.0.1:1");
    match env_node {
        Some(v) => cmd.env("GITLAWB_NODE", v),
        None => cmd.env_remove("GITLAWB_NODE"),
    };
    let out = cmd.output().unwrap();
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code(),
    }
}

/// GITLAWB_NODE unset: the helper falls back to the local node, gl targets the
/// public one, so the row must name the local node as the transport target.
#[test]
fn unset_env_reports_the_transport_node() {
    let r = doctor(None, "http://127.0.0.1:1");
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
    assert!(
        line.contains(gitlawb_core::DEFAULT_LOCAL_NODE),
        "divergence row must name the helper's node, got: {line}"
    );
}

/// A blank value is not a configured node. The helper must fall back exactly as
/// it does when the variable is absent, and doctor must say so.
#[test]
fn blank_env_is_treated_as_unset() {
    for blank in ["", "   ", "\t"] {
        let r = doctor(Some(blank), "http://127.0.0.1:1");
        let line = r
            .divergence_line()
            .unwrap_or_else(|| panic!("no divergence row for {blank:?}, got:\n{}", r.stdout));
        assert!(
            line.contains(gitlawb_core::DEFAULT_LOCAL_NODE),
            "blank env must resolve to the local default, got: {line}"
        );
    }
}

/// An explicit `--node` outranks the environment, so the transport still goes
/// somewhere gl never probes. This state produced no row at all before.
#[test]
fn explicit_node_flag_overriding_env_is_still_reported() {
    let r = doctor(Some("http://127.0.0.1:2"), "http://127.0.0.1:1");
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
    assert!(
        line.contains("127.0.0.1:2"),
        "row must name the env-configured transport node, got: {line}"
    );
}

/// No divergence when both resolve the same node: one row, no clause.
#[test]
fn agreeing_env_and_flag_produce_no_divergence_row() {
    let r = doctor(Some("http://127.0.0.1:1"), "http://127.0.0.1:1");
    assert!(
        r.divergence_line().is_none(),
        "gl and the transport agree; expected no divergence row, got:\n{}",
        r.stdout
    );
}

/// The bug this check exists to prevent, one level down: something answering 200
/// on the transport port is not proof a gitlawb node is there. Reporting it as a
/// healthy transport is the same false green doctor already shipped once.
#[test]
fn a_non_gitlawb_200_is_not_a_healthy_transport() {
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(1) {
            let Ok(mut s) = stream else { continue };
            // Read the request first. Writing the response without draining the
            // request leaves the client seeing a reset rather than a 200, which
            // silently turns this test into a probe of the unreachable path.
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let body = b"<html>not a node</html>";
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(body);
            let _ = s.flush();
        }
    });
    let r = doctor(
        Some(&format!("http://127.0.0.1:{port}")),
        "http://127.0.0.1:1",
    );
    let line = r
        .divergence_line()
        .unwrap_or_else(|| panic!("no divergence row, got:\n{}", r.stdout));
    // Positive assertion: only the identity check can produce this text, so the
    // test cannot pass by the probe quietly failing instead.
    assert!(
        line.contains("not a gitlawb node"),
        "a non-gitlawb 200 must be called out, not reported reachable, got: {line}"
    );
}

/// Control characters from an attacker-influenceable node URL must not reach the
/// terminal raw, including inside the paste-ready remedy line.
///
/// Scoped to the rows this check owns. The unchanged `node` row at doctor.rs:180,
/// :199 and :206 still interpolates the raw URL and is a separate pre-existing
/// leak, so asserting over the whole of stdout would fail for a reason this
/// change did not introduce and cannot fix without touching adjacent code.
#[test]
fn control_characters_in_the_node_url_are_stripped() {
    let r = doctor(None, "http://127.0.0.1:1/\u{1b}[31m\u{7}\u{202e}");
    let owned: String = r
        .stdout
        .lines()
        .filter(|l| l.contains(DIVERGENCE) || l.trim_start().starts_with("GITLAWB_NODE:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        owned.contains(DIVERGENCE),
        "expected the divergence row and its remedy, got:\n{}",
        r.stdout
    );
    assert!(
        !owned.contains('\u{1b}') && !owned.contains('\u{7}') && !owned.contains('\u{202e}'),
        "raw control characters reached stdout:\n{owned:?}"
    );
}

/// #357's tiering: an unset variable is advisory (gl still works), a variable the
/// user set to something unusable is a real failure. Nothing pinned this, and the
/// difference decides whether a stock install exits non-zero once #391 lands.
#[test]
fn unset_env_warns_while_a_broken_configured_node_fails() {
    let stock = doctor(None, "http://127.0.0.1:1");
    let line = stock.divergence_line().unwrap();
    assert!(
        line.trim_start().starts_with('\u{26a0}'),
        "an unset variable must stay advisory on a stock install, got: {line}"
    );

    let misconfigured = doctor(Some("http://127.0.0.1:2"), "http://127.0.0.1:1");
    let line = misconfigured.divergence_line().unwrap();
    assert!(
        line.trim_start().starts_with('\u{2717}'),
        "a configured but unusable node must fail, got: {line}"
    );
}

/// #357's constraint: doctor must not start failing a stock install just because
/// it now says more. Nothing pinned this before.
#[test]
fn doctor_still_exits_zero() {
    let r = doctor(None, "http://127.0.0.1:1");
    assert_eq!(
        r.code,
        Some(0),
        "doctor must keep exiting 0, got:\n{}",
        r.stdout
    );
}
