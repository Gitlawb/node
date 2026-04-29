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

#[derive(Debug, Deserialize)]
struct BootstrapList {
    version: u32,
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

/// Merge the embedded seed list into the runtime config.
///
/// - Appends any `http_url` to `config.bootstrap_peers` (used by gossip_task)
/// - Appends any valid `p2p_multiaddr` to `config.p2p_bootstrap` (used by libp2p)
/// - Dedupes against entries already present (env / CLI takes precedence)
/// - No-op when `GITLAWB_BOOTSTRAP_DISABLE_SEEDS` is set to a truthy value
pub fn merge_seeds(config: &mut Config) {
    if std::env::var("GITLAWB_BOOTSTRAP_DISABLE_SEEDS")
        .ok()
        .filter(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .is_some()
    {
        info!("bootstrap seed list disabled via GITLAWB_BOOTSTRAP_DISABLE_SEEDS");
        return;
    }

    let list: BootstrapList = match serde_json::from_str(EMBEDDED_PEERS_JSON) {
        Ok(l) => l,
        Err(e) => {
            warn!(err = %e, "failed to parse embedded bootstrap-peers.json — skipping");
            return;
        }
    };

    if list.version != 1 {
        warn!(
            version = list.version,
            "unknown bootstrap-peers.json version — skipping"
        );
        return;
    }

    let mut added_http = 0;
    let mut added_p2p = 0;

    for peer in list.peers {
        if let Some(url) = peer
            .http_url
            .as_ref()
            .filter(|u| !u.is_empty() && !config.bootstrap_peers.contains(u))
        {
            config.bootstrap_peers.push(url.clone());
            added_http += 1;
        }

        if let Some(addr_str) = peer.p2p_multiaddr.as_ref().filter(|s| !s.is_empty()) {
            match Multiaddr::from_str(addr_str) {
                Ok(_) => {
                    if !config.p2p_bootstrap.contains(addr_str) {
                        config.p2p_bootstrap.push(addr_str.clone());
                        added_p2p += 1;
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

    if added_http > 0 || added_p2p > 0 {
        info!(
            http_peers = added_http,
            p2p_peers = added_p2p,
            "merged bootstrap seed list into config"
        );
    }
}
