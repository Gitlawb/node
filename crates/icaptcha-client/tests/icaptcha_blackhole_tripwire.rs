//! Tripwire: a committed negative case that locks the blackhole mechanism.
//!
//! The guard against non-loopback egress works because `obtain_proof` builds a
//! stock `reqwest::blocking::Client` that inherits the process's proxy env vars.
//! If the builder later gains `.no_proxy()` or a custom connector, the guard
//! disarms silently and every existing test stays green (no live call is made
//! during the normal mock-consumed run because the mock is on loopback and
//! `NO_PROXY` covers it — the blackhole isn't even exercised).
//!
//! This test asserts that a destination the blackhole's `NO_PROXY` does NOT
//! cover fails *while the blackhole is armed*.  The destination is a local HTTP
//! server on `[::1]` (IPv6 loopback), which `NO_PROXY` (`127.0.0.1, localhost`)
//! does not list.  With the blackhole active the proxy intercepts the
//! connection and blocks it; without the blackhole the request would reach the
//! server directly and succeed, turning this test RED.
//!
//! A positive control (disarmed blackhole) runs first, proving the fixture is
//! valid and `[::1]` is reachable.
//!
//! Design constraints (see issue #211):
//!   - An unresolvable host would keep the request failing even when the guard
//!     is disarmed (DNS failure masquerading as the blackhole), so we must use
//!     a reachable address.
//!   - A real external host would make a live network call the moment the guard
//!     disarms, and on any runner that cannot reach that host the connect error
//!     again masquerades as the blackhole.  A local loopback address avoids both
//!     problems — it is always reachable when unblocked and never reaches the
//!     real network.
//!   - The address must NOT be covered by `NO_PROXY`, yet must exist on every
//!     platform.  An arbitrary `127/8` alias is not portable: macOS only binds
//!     `127.0.0.1` by default.  `[::1]` (IPv6 loopback) is present by default
//!     on Linux, macOS, and Windows, and `NO_PROXY` only lists `127.0.0.1` and
//!     `localhost`, so the blackhole still intercepts it.
//!   - This depends on hyper-util's proxy matcher having no implicit loopback
//!     bypass — a host is only proxied-around when literally listed in
//!     `NO_PROXY` (verified in the pinned hyper-util; recheck on upgrade).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use icaptcha_client::{obtain_proof, Challenge, IcaptchaCfg};

mod support;

/// A minimal HTTP server that responds to iCaptcha challenge and answer
/// requests on the IPv6 loopback address NOT covered by NO_PROXY.
///
/// When the blackhole is working, the proxy should intercept these requests
/// and `obtain_proof` should fail.  When the blackhole is disarmed, the
/// requests reach this server and the flow succeeds.
fn serve_icaptcha(listener: TcpListener) {
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Read until the first \n (end of request line) so TCP
            // segmentation cannot split the path out of a single read.
            let mut buf = [0u8; 4096];
            let mut n = 0usize;
            while n < buf.len() {
                match stream.read(&mut buf[n..]) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        n += read;
                        if buf[..n].contains(&b'\n') {
                            break;
                        }
                    }
                }
            }
            if n == 0 {
                continue;
            }
            let request = String::from_utf8_lossy(&buf[..n]);
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

fn make_cfg(url: &str) -> IcaptchaCfg {
    IcaptchaCfg {
        url: url.to_string(),
        did: "did:key:zTEST".to_string(),
        level: 1,
        api_key: None,
    }
}

#[test]
fn obtain_proof_blackhole_tripwire() {
    // Bind to [::1], IPv6 loopback, which NO_PROXY (127.0.0.1, localhost)
    // does not cover.  Unlike an arbitrary 127/8 alias, IPv6 loopback is
    // present by default on Linux, macOS, and Windows, so the fixture is
    // portable across platforms.  Fail loudly if it cannot be bound: a
    // silent skip would report this tripwire as green while exercising
    // none of the negative control, recreating the very gap it exists to
    // close.
    let listener = TcpListener::bind(("::1", 0)).expect(
        "cannot bind [::1] for the blackhole tripwire. IPv6 loopback (::1) \
         is present by default on Linux, macOS, and Windows. This test fails \
         rather than silently skipping so a platform without it cannot count \
         the negative control as passed.",
    );
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://[::1]:{port}");
    serve_icaptcha(listener);

    // ── Positive control: disarmed blackhole → obtain_proof succeeds ──────
    let _disarmed_guard = support::disarm_proxy_env();

    let solve: &dyn Fn(&Challenge) -> Option<String> = &|_c| Some("silent".to_string());
    let cfg = make_cfg(&url);
    let proof = obtain_proof(&cfg, Some(solve))
        .expect("positive control: obtain_proof should succeed when the proxy is disarmed");
    assert_eq!(
        proof, "PROOF-TRIP",
        "positive control: unexpected proof value"
    );
    drop(_disarmed_guard);

    // ── Negative control: armed blackhole → obtain_proof fails with connect error ──
    let _armed_guard = support::arm_blackhole("http://127.0.0.1:1");

    let result = obtain_proof(&cfg, Some(solve));

    let err = result.expect_err(
        "blackhole tripwire: obtain_proof succeeded against [::1], \
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
