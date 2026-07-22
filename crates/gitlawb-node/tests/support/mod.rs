//! Shared support for the real-node deny harness: the deny assertion (U4), the
//! RFC-9421 signing client (U2), and (via `gitlawb_node::test_harness`) the
//! node spawner (U3).

pub mod assert;
// U2 fixture state matrix + per-gate-class probe generators; driven by U3.
#[allow(dead_code)]
pub mod probe;
// U1 deny-bearing route registry; fields consumed by U2/U3 as they land.
#[allow(dead_code)]
pub mod routes;
pub mod signing;

/// A reqwest client with a bounded request timeout, so a wedged git subprocess or
/// route fails the suite rather than hanging it until CI kills the job (#195, F1).
/// The two real-node probes that drive git subprocesses use this; the inline
/// twins at the upload-pack and registry-sweep sites use the same pattern.
#[allow(dead_code)]
pub fn bounded_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap()
}
