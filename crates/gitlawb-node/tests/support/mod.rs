//! Shared support for the real-node deny harness: the deny assertion (U4), the
//! RFC-9421 signing client (U2), and (via `gitlawb_node::test_harness`) the
//! node spawner (U3).

pub mod assert;
// U1 deny-bearing route registry; fields consumed by U2/U3 as they land.
#[allow(dead_code)]
pub mod routes;
pub mod signing;
