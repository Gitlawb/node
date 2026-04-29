//! DID resolution — look up a node by its gitlawb DID.
//!
//! First checks the local peers table (HTTP-layer peer discovery),
//! then queries the Kademlia DHT via the libp2p swarm.
//!
//! Routes:
//!   GET /api/v1/resolve/{did}

use axum::extract::{Path, State};
use axum::Json;

use crate::error::Result;
use crate::state::AppState;

/// GET /api/v1/resolve/{did}
///
/// Resolves a gitlawb DID to an HTTP URL and p2p multiaddr.
/// Checks local peer cache first, then falls back to Kademlia DHT lookup.
pub async fn resolve_did(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // 1. Check local peers table
    if let Ok(peers) = state.db.list_peers().await {
        if let Some(peer) = peers.into_iter().find(|p| p.did == did) {
            return Ok(Json(serde_json::json!({
                "did": did,
                "http_url": peer.http_url,
                "source": "local_peers",
                "last_seen": peer.last_seen,
                "reachable": peer.last_ping_ok,
            })));
        }
    }

    // 2. Fall back to Kademlia DHT lookup
    if let Some(p2p) = &state.p2p {
        if let Some(record) = p2p.get_did(did.clone()).await {
            return Ok(Json(serde_json::json!({
                "did": record.did,
                "http_url": record.http_url,
                "peer_id": record.peer_id,
                "p2p_port": record.p2p_port,
                "source": "kademlia_dht",
                "timestamp": record.timestamp,
            })));
        }
    }

    // Not found
    Ok(Json(serde_json::json!({
        "did": did,
        "http_url": null,
        "source": null,
        "error": "DID not found in local peers or Kademlia DHT",
    })))
}
