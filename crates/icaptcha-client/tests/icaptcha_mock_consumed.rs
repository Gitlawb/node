//! INV-19 guard: the icaptcha flow must actually call the service (consuming the
//! mock), not short-circuit or make a live call. If a future change let
//! `obtain_proof` skip the network (e.g. a stray `cfg(test)` relaxation, which
//! INV-19/INV-20 warn is inert across crates), the `.assert()` calls below go
//! RED because the mocked endpoints were never hit.
//!
//! The mock-consumed assertions alone only prove the mock was hit; they cannot
//! see a request that ALSO leaks the DID / answer / API key to `DEFAULT_URL` or
//! any other origin (a different host the mock never observes). To make the
//! "no live call" half of the guard load-bearing, the test blackholes every
//! non-loopback destination via a proxy observer: `NO_PROXY` lets the loopback
//! mock through while every proxy variable routes any other host through a TCP
//! listener that counts connections.  Zero observed connections (accepted
//! during the `obtain_proof` call) proves no leak reached the network on the
//! exercised synchronous path.
//!
//! The observer design counts every accepted connection regardless of whether
//! the caller propagates the transport error, so it catches leaks that a
//! closed-port blackhole (which only surfaces propagating errors) would miss.
//! Because the accept loop runs in a detached thread, a leak whose TCP
//! handshake completes after the counter is read is not observed — this is a
//! known limitation of the single-threaded test harness, not a gap in the
//! guard itself.
//!
//! SCOPE: The observer only witnesses leaks issued on the path this test drives
//! (a single passing round, 200 on both endpoints, no PoW, no Continue/Failed,
//! no non-2xx response).  A leak living on an error or retry branch makes no
//! connection during the run and the zero-count assertion stays green.  The
//! guarantee covers only the exercised happy path and proxy-honoring transports;
//! a future `.no_proxy()` or raw `TcpStream` bypasses the observer entirely.
//!
//! `ALL_PROXY` alone is NOT enough: reqwest honors the scheme-specific
//! `HTTPS_PROXY` / `https_proxy` (and the http equivalents) OVER `ALL_PROXY`, so
//! a runner with a working `HTTPS_PROXY` in its environment would route an https
//! leak to `DEFAULT_URL` (which is https) through that proxy while the loopback
//! mock is still consumed and this test stayed green.  So we blackhole the
//! scheme-specific variables too.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use icaptcha_client::{obtain_proof, Challenge, IcaptchaCfg};

mod support;

/// A TCP listener that counts every accepted connection.
///
/// Acts as the proxy target: any leaked connection to a non-loopback
/// destination will be routed through this listener and increment the
/// counter.  The test then asserts zero connections (those accepted
/// during the synchronous `obtain_proof` call).
struct ProxyObserver {
    _listener: Arc<TcpListener>,
    port: u16,
    count: Arc<AtomicUsize>,
}

impl ProxyObserver {
    fn bind() -> Self {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").expect("bind proxy observer"));
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let l = Arc::clone(&listener);
        std::thread::spawn(move || {
            for stream in l.incoming() {
                if stream.is_ok() {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        ProxyObserver {
            _listener: listener,
            port,
            count,
        }
    }

    fn port(&self) -> u16 {
        self.port
    }
}

#[test]
fn obtain_proof_consumes_the_mocked_service_and_makes_no_live_call() {
    let observer = ProxyObserver::bind();
    let _guard = support::arm_blackhole(&format!("http://127.0.0.1:{}", observer.port()));

    let mut server = mockito::Server::new();

    let challenge = server
        .mock("POST", "/v1/challenge")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"challengeId":"c1","type":"anagram","difficulty":1,"prompt":"listen","token":"tok-1"}"#,
        )
        .expect(1)
        .create();

    let answer = server
        .mock("POST", "/v1/answer")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"passed","proof":"PROOF-XYZ"}"#)
        .expect(1)
        .create();

    let cfg = IcaptchaCfg {
        url: server.url(),
        did: "did:key:zTEST".to_string(),
        level: 1,
        api_key: None,
    };

    let solve = |_c: &Challenge| Some("silent".to_string());
    let solver: &dyn Fn(&Challenge) -> Option<String> = &solve;

    // Connections accepted during obtain_proof are counted by the
    // detached accept thread.  We read the counter after the call
    // returns; a leak whose TCP handshake completes after this read
    // is outside the assertion's window (see module-level doc).
    let count_before = observer.count.load(Ordering::SeqCst);

    let proof = obtain_proof(&cfg, Some(solver))
        .expect("obtain_proof should complete against the mocked service");
    assert_eq!(proof, "PROOF-XYZ");

    challenge.assert();
    answer.assert();

    let leak_count = observer.count.load(Ordering::SeqCst) - count_before;

    assert_eq!(
        leak_count, 0,
        "proxy observer caught leaked connections; \
         the blackhole failed to contain egress"
    );
}
