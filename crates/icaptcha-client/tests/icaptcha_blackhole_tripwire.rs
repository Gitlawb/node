//! Tripwire: a committed negative case that locks the blackhole mechanism.
//!
//! The guard against non-loopback egress works because `obtain_proof` builds a
//! stock `reqwest::blocking::Client` that inherits the process's proxy env vars.
//! If the builder later gains `.no_proxy()` or a custom connector, the guard
//! disarms silently and every existing test stays green (no live call is made
//! during the normal mock-consumed run because the mock is on loopback and
//! `NO_PROXY` covers it — the blackhole isn't even exercised).
//!
//! This test asserts that a non-loopback destination fails *while the blackhole
//! is armed*. The destination is a local HTTP server on `127.0.0.2`, a loopback
//! alias that `NO_PROXY` does NOT cover.  With the blackhole active the proxy
//! intercepts the connection and blocks it; without the blackhole the request
//! would reach the server directly and succeed, turning this test RED.
//!
//! Design constraints (see issue #211):
//!   - An unresolvable host would keep the request failing even when the guard
//!     is disarmed (DNS failure masquerading as the blackhole), so we must use
//!     a reachable address.
//!   - A real external host would make a live network call the moment the guard
//!     disarms, and on any runner that cannot reach that host the connect error
//!     again masquerades as the blackhole.  A local loopback alias avoids both
//!     problems — it is always reachable when unblocked and never reaches the
//!     real network.
//!   - This depends on reqwest's `NO_PROXY` matching by exact IP (holds in the
//!     pinned reqwest/hyper-util; recheck on upgrade) and on the OS routing
//!     `127/8` as loopback (default on Linux; macOS may need an explicit alias).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use icaptcha_client::{obtain_proof, Challenge, IcaptchaCfg};

mod support;

/// A minimal HTTP server that responds to iCaptcha challenge and answer
/// requests on a loopback alias NOT covered by NO_PROXY.
///
/// When the blackhole is working, the proxy should intercept these requests
/// and `obtain_proof` should fail.  When the blackhole is disarmed, the
/// requests reach this server and the flow succeeds.
fn serve_icaptcha(listener: TcpListener) {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0; 4096];
            if stream.read(&mut buf).is_err() {
                continue;
            }
            let request = String::from_utf8_lossy(&buf);
            let body = if request.contains("/v1/answer") {
                r#"{"status":"passed","proof":"PROOF-TRIP"}"#
            } else {
                r#"{"challengeId":"c1","type":"anagram","difficulty":1,"prompt":"listen","token":"tok-1"}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
}

#[test]
fn obtain_proof_fails_when_blackhole_blocks_non_loopback_destination() {
    // Start a listener on 127.0.0.2, a loopback alias NOT listed in NO_PROXY.
    let listener = TcpListener::bind("127.0.0.2:0")
        .expect("bind on 127.0.0.2 (requires OS support for 127/8 loopback)");
    let port = listener.local_addr().unwrap().port();
    serve_icaptcha(listener);

    support::arm_blackhole("http://127.0.0.1:1");

    let cfg = IcaptchaCfg {
        url: format!("http://127.0.0.2:{port}"),
        did: "did:key:zTEST".to_string(),
        level: 1,
        api_key: None,
    };

    let solve = |_c: &Challenge| Some("silent".to_string());
    let solver: &dyn Fn(&Challenge) -> Option<String> = &solve;

    let result = obtain_proof(&cfg, Some(solver));

    // The blackhole should block the connection via the proxy, producing a
    // connect-level failure.  Narrowing the assertion to a reqwest connect
    // error defends against fixture bugs that would otherwise make any error
    // (e.g. deserialization of a truncated body) vacuously pass.
    let err = result.expect_err(
        "blackhole tripwire: obtain_proof succeeded against 127.0.0.2, \
         meaning the proxy blackhole did not intercept the request; \
         the no-live-call guard is disarmed",
    );
    assert!(
        err.chain().any(|c| c
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|e| e.is_connect())),
        "expected a connect/proxy error, got: {err:#}",
    );
}
