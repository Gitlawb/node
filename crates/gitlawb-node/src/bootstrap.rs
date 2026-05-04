//! Embedded seed list of public Gitlawb network nodes.
//!
//! This module parses `bootstrap-peers.json` (embedded at compile time) and
//! merges its contents into the runtime config so a fresh `docker compose up`
//! joins the network without any manual peer configuration.
//!
//! Operators can opt out by setting `GITLAWB_BOOTSTRAP_DISABLE_SEEDS=true` in
//! their environment — useful for isolated dev networks or testing.
//!
//! Add a node to the canonical list via PR to `bootstrap-peers.json`.

use std::str::FromStr;

use libp2p::Multiaddr;
use serde::Deserialize;
use tracing::{info, warn};

use crate::config::Config;

const EMBEDDED_PEERS_JSON: &str = include_str!("../../../bootstrap-peers.json");
const SUPPORTED_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
struct BootstrapList {
    version: u32,
    #[serde(default)]
    peers: Vec<BootstrapPeer>,
}

#[derive(Debug, Deserialize)]
struct BootstrapPeer {
    name: String,
    #[allow(dead_code)]
    operator: Option<String>,
    #[allow(dead_code)]
    did: Option<String>,
    http_url: Option<String>,
    p2p_multiaddr: Option<String>,
    #[allow(dead_code)]
    added: Option<String>,
}

/// Counts of newly-added entries returned by `merge_into_vecs`.
#[derive(Debug, Default, PartialEq, Eq)]
struct MergeCounts {
    http: usize,
    p2p: usize,
}

/// Returns true when `GITLAWB_BOOTSTRAP_DISABLE_SEEDS` is set to a truthy value.
fn seeds_disabled() -> bool {
    std::env::var("GITLAWB_BOOTSTRAP_DISABLE_SEEDS")
        .ok()
        .filter(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .is_some()
}

/// Parse the seed list from a JSON string, rejecting unsupported versions.
fn parse_seed_list(json: &str) -> Result<BootstrapList, String> {
    let list: BootstrapList = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if list.version != SUPPORTED_VERSION {
        return Err(format!(
            "unsupported bootstrap-peers.json version: {} (expected {})",
            list.version, SUPPORTED_VERSION
        ));
    }
    Ok(list)
}

/// Pure merge: appends entries from `list` to the two vectors, deduping.
/// Returns counts of entries actually added (i.e. not already present).
fn merge_into_vecs(
    list: BootstrapList,
    http_peers: &mut Vec<String>,
    p2p_bootstrap: &mut Vec<String>,
) -> MergeCounts {
    let mut counts = MergeCounts::default();

    for peer in list.peers {
        if let Some(url) = peer
            .http_url
            .as_ref()
            .filter(|u| !u.is_empty() && !http_peers.contains(u))
        {
            http_peers.push(url.clone());
            counts.http += 1;
        }

        if let Some(addr_str) = peer.p2p_multiaddr.as_ref().filter(|s| !s.is_empty()) {
            match Multiaddr::from_str(addr_str) {
                Ok(_) => {
                    if !p2p_bootstrap.contains(addr_str) {
                        p2p_bootstrap.push(addr_str.clone());
                        counts.p2p += 1;
                    }
                }
                Err(e) => warn!(
                    name = %peer.name,
                    addr = %addr_str,
                    err = %e,
                    "invalid p2p_multiaddr in bootstrap-peers.json — skipping"
                ),
            }
        }
    }

    counts
}

/// Merge the embedded seed list into the runtime config.
///
/// - Appends any `http_url` to `config.bootstrap_peers` (used by gossip_task)
/// - Appends any valid `p2p_multiaddr` to `config.p2p_bootstrap` (used by libp2p)
/// - Dedupes against entries already present (env / CLI takes precedence)
/// - No-op when `GITLAWB_BOOTSTRAP_DISABLE_SEEDS` is set to a truthy value
pub fn merge_seeds(config: &mut Config) {
    if seeds_disabled() {
        info!("bootstrap seed list disabled via GITLAWB_BOOTSTRAP_DISABLE_SEEDS");
        return;
    }

    let list = match parse_seed_list(EMBEDDED_PEERS_JSON) {
        Ok(l) => l,
        Err(e) => {
            warn!(err = %e, "failed to load embedded bootstrap-peers.json — skipping");
            return;
        }
    };

    let counts = merge_into_vecs(list, &mut config.bootstrap_peers, &mut config.p2p_bootstrap);

    if counts.http > 0 || counts.p2p > 0 {
        info!(
            http_peers = counts.http,
            p2p_peers = counts.p2p,
            "merged bootstrap seed list into config"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_v1_list() {
        let json = r#"{
            "version": 1,
            "updated": "2026-04-29",
            "peers": [
                {
                    "name": "alpha",
                    "operator": "Alice",
                    "did": "did:key:z6MkAlice",
                    "http_url": "https://alpha.example.com",
                    "p2p_multiaddr": "/ip4/1.2.3.4/tcp/7546",
                    "added": "2026-04-29"
                }
            ]
        }"#;
        let list = parse_seed_list(json).expect("should parse");
        assert_eq!(list.version, 1);
        assert_eq!(list.peers.len(), 1);
        assert_eq!(list.peers[0].name, "alpha");
    }

    #[test]
    fn parse_rejects_unknown_version() {
        let json = r#"{ "version": 99, "peers": [] }"#;
        let err = parse_seed_list(json).expect_err("should reject");
        assert!(err.contains("unsupported"));
    }

    #[test]
    fn parse_rejects_malformed_json() {
        let err = parse_seed_list("{ not json").expect_err("should reject");
        assert!(!err.is_empty());
    }

    #[test]
    fn parse_accepts_empty_peers_array() {
        let json = r#"{ "version": 1, "peers": [] }"#;
        let list = parse_seed_list(json).expect("should parse");
        assert!(list.peers.is_empty());
    }

    #[test]
    fn parse_treats_missing_peers_as_empty() {
        let json = r#"{ "version": 1 }"#;
        let list = parse_seed_list(json).expect("should parse");
        assert!(list.peers.is_empty());
    }

    #[test]
    fn merge_appends_new_http_and_p2p() {
        let list = parse_seed_list(
            r#"{
                "version": 1,
                "peers": [
                    {
                        "name": "alpha",
                        "http_url": "https://alpha.example.com",
                        "p2p_multiaddr": "/ip4/1.2.3.4/tcp/7546"
                    }
                ]
            }"#,
        )
        .unwrap();

        let mut http = Vec::new();
        let mut p2p = Vec::new();
        let counts = merge_into_vecs(list, &mut http, &mut p2p);

        assert_eq!(counts, MergeCounts { http: 1, p2p: 1 });
        assert_eq!(http, vec!["https://alpha.example.com"]);
        assert_eq!(p2p, vec!["/ip4/1.2.3.4/tcp/7546"]);
    }

    #[test]
    fn merge_dedupes_existing_entries() {
        let list = parse_seed_list(
            r#"{
                "version": 1,
                "peers": [
                    { "name": "alpha", "http_url": "https://alpha.example.com" }
                ]
            }"#,
        )
        .unwrap();

        let mut http = vec!["https://alpha.example.com".to_string()];
        let mut p2p = Vec::new();
        let counts = merge_into_vecs(list, &mut http, &mut p2p);

        assert_eq!(counts.http, 0, "should not double-add");
        assert_eq!(http.len(), 1);
    }

    #[test]
    fn merge_skips_invalid_p2p_multiaddr() {
        let list = parse_seed_list(
            r#"{
                "version": 1,
                "peers": [
                    {
                        "name": "bad",
                        "http_url": "https://bad.example.com",
                        "p2p_multiaddr": "this is not a multiaddr"
                    }
                ]
            }"#,
        )
        .unwrap();

        let mut http = Vec::new();
        let mut p2p = Vec::new();
        let counts = merge_into_vecs(list, &mut http, &mut p2p);

        assert_eq!(counts.http, 1, "http still added");
        assert_eq!(counts.p2p, 0, "invalid p2p skipped");
        assert!(p2p.is_empty());
    }

    #[test]
    fn merge_skips_empty_strings() {
        let list = parse_seed_list(
            r#"{
                "version": 1,
                "peers": [
                    { "name": "blank", "http_url": "", "p2p_multiaddr": "" }
                ]
            }"#,
        )
        .unwrap();

        let mut http = Vec::new();
        let mut p2p = Vec::new();
        let counts = merge_into_vecs(list, &mut http, &mut p2p);

        assert_eq!(counts, MergeCounts::default());
    }

    #[test]
    fn merge_handles_null_optional_fields() {
        let list = parse_seed_list(
            r#"{
                "version": 1,
                "peers": [
                    {
                        "name": "alpha",
                        "operator": null,
                        "did": null,
                        "http_url": "https://alpha.example.com",
                        "p2p_multiaddr": null,
                        "added": null
                    }
                ]
            }"#,
        )
        .unwrap();

        let mut http = Vec::new();
        let mut p2p = Vec::new();
        let counts = merge_into_vecs(list, &mut http, &mut p2p);

        assert_eq!(counts, MergeCounts { http: 1, p2p: 0 });
    }

    #[test]
    fn embedded_seed_list_parses_successfully() {
        // Regression: the canonical bootstrap-peers.json shipped in the repo
        // must always be valid, since it's compiled into the binary.
        parse_seed_list(EMBEDDED_PEERS_JSON)
            .expect("embedded bootstrap-peers.json must always parse");
    }
}
