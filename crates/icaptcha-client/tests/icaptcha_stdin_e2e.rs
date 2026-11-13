//! #345 end-to-end: `obtain_proof` must not block or crash when stdin is an
//! open, silent non-TTY and the challenge can't be solved deterministically.
//!
//! The unit seam can't fake a process stdin, so the parent spawns this test
//! binary with a held-open pipe as stdin and the child runs the real
//! `obtain_proof` against a mocked iCaptcha service over HTTP. Before the fix
//! the child blocked in `read_line` forever (unsolvable type) or panicked /
//! submitted a wrapped answer (overflowing arithmetic). After the fix it
//! exits promptly with the "cannot solve" error.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use icaptcha_client::{obtain_proof, IcaptchaCfg};

const CHILD_ENV: &str = "ICAPTCHA_STDIN_E2E_CHILD";
const URL_ENV: &str = "ICAPTCHA_STDIN_E2E_URL";
const CHILD_TIMEOUT: Duration = Duration::from_secs(15);

/// Child entry point: fetch the challenge from the mock service and run the
/// full solve loop. Both scenarios must reach the same clean error.
fn run_child() {
    let url = std::env::var(URL_ENV).expect("child needs the mock url");
    let cfg = IcaptchaCfg {
        url,
        did: "did:key:zTEST".to_string(),
        level: 1,
        api_key: None,
    };
    let err = obtain_proof(&cfg, None).expect_err("the challenge is unsolvable");
    assert!(
        err.to_string().contains("cannot solve iCaptcha challenge"),
        "expected the unsolvable-challenge error, got: {err}"
    );
    println!("child-finished-cleanly");
}

/// Spawn the child with a held-open, empty pipe as stdin, wait with a
/// deadline, and assert it printed the clean-exit marker.
fn run_scenario(prompt_type: &str, prompt: &str, expect_answer_calls: usize) {
    let mut server = mockito::Server::new();
    let challenge = server
        .mock("POST", "/v1/challenge")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(format!(
            r#"{{"challengeId":"c1","type":"{prompt_type}","difficulty":1,"prompt":"{prompt}","token":"tok-1"}}"#
        ))
        .expect(1)
        .create();
    // No answer may be submitted: an unsolvable prompt must produce no
    // request to /v1/answer (a wrapped wrong answer would still hit it).
    let answer = server
        .mock("POST", "/v1/answer")
        .expect(expect_answer_calls)
        .create();

    let exe = std::env::current_exe().expect("current test binary");
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        "obtain_proof_does_not_block_on_silent_non_tty_stdin",
        "--nocapture",
    ])
    .env(CHILD_ENV, "1")
    .env(URL_ENV, server.url())
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    // The solver client honors proxy env; force direct connections so the
    // loopback mock is always reachable regardless of the runner's env.
    for var in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "REQUEST_METHOD",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("NO_PROXY", "*");
    let mut child = cmd.spawn().expect("spawn child");

    // Hold the write end open with no data: exactly the shape that hung.
    let _held_stdin = child.stdin.take();

    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        match child.try_wait().expect("poll child") {
            Some(_) => break,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            None => {
                let _ = child.kill();
                panic!("obtain_proof blocked on an open, silent non-TTY stdin");
            }
        }
    }
    let out = child.wait_with_output().expect("collect child output");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "child failed: status {:?}\nstdout: {stdout}\nstderr: {stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains("child-finished-cleanly"),
        "child body did not run to completion: {stdout}"
    );
    assert!(
        !stderr.contains("panicked"),
        "child panicked instead of returning a clean error: {stderr}"
    );
    challenge.assert();
    answer.assert();
}

#[test]
fn obtain_proof_does_not_block_on_silent_non_tty_stdin() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_child();
        return;
    }

    // An unsolvable challenge type falls through to the interactive prompt,
    // which must decline the non-TTY stdin instead of blocking on read_line.
    run_scenario("anagram", "listen", 0);

    // An arithmetic prompt whose evaluation overflows i64 must also end at
    // the unsolvable error: no panic, and no wrapped answer submitted.
    run_scenario("arithmetic", "What is 9223372036854775807 + 1?", 0);
}
