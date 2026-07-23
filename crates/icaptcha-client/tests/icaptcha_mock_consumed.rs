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
//! listener that counts connections. Zero observed connections proves the
//! blackhole held and no leak reached the network.
//!
//! Unlike a closed-port blackhole (which only catches propagating errors), the
//! observer catches fire-and-forget leaks whose transport error is discarded.
//!
//! SCOPE: The observer only witnesses leaks issued on the path this test drives
//! (a single passing round, 200 on both endpoints, no PoW, no Continue/Failed,
//! no non-2xx response). A leak living on an error or retry branch makes no
//! connection during the run and the zero-count assertion stays green. The
//! guarantee covers only the exercised happy path and proxy-honoring transports;
//! a future `.no_proxy()` or raw `TcpStream` bypasses the observer entirely.
//!
//! `ALL_PROXY` alone is NOT enough: reqwest honors the scheme-specific
//! `HTTPS_PROXY` / `https_proxy` (and the http equivalents) OVER `ALL_PROXY`, so
//! a runner with a working `HTTPS_PROXY` in its environment would route an https
//! leak to `DEFAULT_URL` (which is https) through that proxy while the loopback
//! mock is still consumed and this test stayed green. So we blackhole the
//! scheme-specific variables too. No restore is needed: this file has a single
//! `#[test]`, so it runs in its own process and the override never races a
//! sibling test.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

use icaptcha_client::{obtain_proof, Challenge, IcaptchaCfg};

mod support;

/// A TCP listener that counts every accepted connection.
///
/// Acts as the proxy target: any leaked connection to a non-loopback
/// destination will be routed through this listener and increment the
/// counter.  The test asserts zero connections, catching even
/// fire-and-forget leaks whose errors are discarded.
///
/// Synchronization: a `flush()` call connects to the listener and waits
/// for the accept thread to process it, ensuring all prior connections
/// have been counted before returning.
struct ProxyObserver {
    _listener: Arc<TcpListener>,
    port: u16,
    count: Arc<AtomicUsize>,
    ack_rx: mpsc::Receiver<()>,
}

impl ProxyObserver {
    /// Bind to a random port on loopback and start the accept loop.
    fn bind() -> Self {
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").expect("bind proxy observer"));
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let (ack_tx, ack_rx) = mpsc::channel();
        let c = Arc::clone(&count);
        let l = Arc::clone(&listener);
        std::thread::spawn(move || {
            for stream in l.incoming() {
                if stream.is_ok() {
                    c.fetch_add(1, Ordering::SeqCst);
                    let _ = ack_tx.send(());
                }
            }
        });
        ProxyObserver {
            _listener: listener,
            port,
            count,
            ack_rx,
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    /// Block until all connections made up to this point have been counted
    /// by the accept thread, then return the count of non-flush connections.
    ///
    /// We connect to ourselves to flush the accept backlog: the accept thread
    /// picks up the flush connection, increments the count, and sends an ack.
    /// Subtracting the flush connection from the total yields the leak count.
    fn flush(&self) -> usize {
        while self.ack_rx.try_recv().is_ok() {}

        if let Ok(stream) = std::net::TcpStream::connect(format!("127.0.0.1:{}", self.port)) {
            drop(stream);
        }
        let _ = self
            .ack_rx
            .recv_timeout(std::time::Duration::from_millis(100));

        self.count.load(Ordering::SeqCst).saturating_sub(1)
    }
}

#[test]
fn obtain_proof_consumes_the_mocked_service_and_makes_no_live_call() {
    // Start the proxy observer before setting env vars so the accept loop is
    // ready when reqwest builds its client.
    let observer = ProxyObserver::bind();
    support::arm_blackhole(&format!("http://127.0.0.1:{}", observer.port()));

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

    let proof = obtain_proof(&cfg, Some(solver))
        .expect("obtain_proof should complete against the mocked service");
    assert_eq!(proof, "PROOF-XYZ");

    challenge.assert();
    answer.assert();

    // Observer catch: flush any pending connections from the accept backlog,
    // then assert zero. The flush synchronizes with the accept thread so a
    // connection that arrived just before obtain_proof returned has been
    // counted before we read.
    assert_eq!(
        observer.flush(),
        0,
        "proxy observer caught leaked connections; \
         the blackhole failed to contain egress"
    );
}
