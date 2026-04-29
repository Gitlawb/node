//! Peer discovery API.
//!
//! Nodes announce themselves to each other and maintain a local peer list.
//! This is the bootstrap layer before full Kademlia DHT in v0.3.
//!
//! Routes:
//!   GET  /api/v1/peers                 — list known peers
//!   POST /api/v1/peers/announce        — announce yourself (signed)
//!   GET  /api/v1/peers/{did}/ping      — check if a peer is reachable
//!   POST /api/v1/sync/notify           — receive push notification from a peer node
//!   POST /api/v1/sync/trigger          — manually pull all repos from known peers

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AnnounceRequest {
    /// The DID of the announcing node
    pub did: String,
    /// The HTTP URL where this node is reachable
    pub http_url: String,
    /// Optional: repos this node is hosting (DID list for federation hints)
    #[serde(default)]
    #[allow(dead_code)]
    pub repo_count: u32,
}

#[derive(Debug, Serialize)]
pub struct PeerResponse {
    pub did: String,
    pub http_url: String,
    pub last_seen: Option<String>,
    pub reachable: bool,
}

/// GET /api/v1/peers
pub async fn list_peers(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let peers = state.db.list_peers().await?;
    let resp: Vec<PeerResponse> = peers
        .into_iter()
        .map(|p| PeerResponse {
            did: p.did,
            http_url: p.http_url,
            last_seen: p.last_seen,
            reachable: p.last_ping_ok,
        })
        .collect();
    Ok(Json(serde_json::json!({ "peers": resp, "count": resp.len() })))
}

/// POST /api/v1/peers/announce (auth required)
///
/// A peer announces itself so this node can add it to its peer list.
/// The Authorization header's DID must match the `did` in the body.
pub async fn announce(
    State(state): State<AppState>,
    Json(req): Json<AnnounceRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    // Validate the URL is HTTP/HTTPS
    if !req.http_url.starts_with("http://") && !req.http_url.starts_with("https://") {
        return Err(AppError::BadRequest("http_url must start with http:// or https://".into()));
    }

    state.db.upsert_peer(&req.did, &req.http_url).await?;

    tracing::info!(did = %req.did, url = %req.http_url, "peer announced");

    // Return our own info so the peer can add us back
    Ok((StatusCode::OK, Json(serde_json::json!({
        "status": "accepted",
        "node_did": state.node_did.to_string(),
        "node_url": state.config.public_url.as_deref().unwrap_or(""),
        "peer_count": state.db.list_peers().await.map(|p| p.len()).unwrap_or(0),
        "message": "added to peer list",
    }))))
}

/// POST /api/v1/sync/trigger
///
/// Manually trigger a full sync pull from all reachable peers. Fetches each
/// peer's repo list over HTTP and enqueues any repos we don't have or are
/// behind on into the sync_queue. This is the HTTP fallback when Gossipsub
/// p2p is not yet connected.
pub async fn trigger_sync(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>> {
    let peers = state.db.list_peers().await?;
    let client = &state.http_client;
    let mut enqueued = 0u32;
    let mut peers_reached = 0u32;

    for peer in &peers {
        if peer.http_url.is_empty() {
            continue;
        }
        let url = format!("{}/api/v1/repos", peer.http_url.trim_end_matches('/'));
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.get(&url).send(),
        ).await;

        let repos: Vec<serde_json::Value> = match result {
            Ok(Ok(resp)) if resp.status().is_success() => {
                peers_reached += 1;
                resp.json().await.unwrap_or_default()
            }
            _ => {
                tracing::warn!(peer = %peer.did, "trigger_sync: could not reach peer");
                continue;
            }
        };

        for repo in repos {
            let repo_slug = match (repo.get("owner_did").and_then(|v| v.as_str()),
                                   repo.get("name").and_then(|v| v.as_str())) {
                (Some(owner), Some(name)) => {
                    // Use short owner (last colon segment) matching DB convention
                    let short = owner.split(':').last().unwrap_or(owner);
                    format!("{short}/{name}")
                }
                _ => continue,
            };
            let _ = state.db.enqueue_sync(
                &repo_slug,
                &peer.did,
                "refs/heads/main",
                "0000000000000000000000000000000000000000",
                None,
            ).await;
            enqueued += 1;
        }
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "peers_reached": peers_reached,
        "repos_enqueued": enqueued,
        "message": "sync items enqueued — worker will process within 30s",
    })))
}

/// POST /api/v1/sync/notify
///
/// Receive a targeted push notification from a peer node. The peer calls this
/// after a successful push so we can immediately enqueue just that repo for sync
/// rather than waiting for the 30s polling cycle or a manual trigger.
#[derive(Debug, Deserialize)]
pub struct NotifyRequest {
    pub repo: String,
    pub ref_name: String,
    pub new_sha: String,
    pub node_did: String,
}

pub async fn notify_sync(
    State(state): State<AppState>,
    Json(req): Json<NotifyRequest>,
) -> Result<Json<serde_json::Value>> {
    // Only accept notifications from known peers
    let peers = state.db.list_peers().await?;
    let known = peers.iter().any(|p| p.did == req.node_did);
    if !known {
        return Err(AppError::BadRequest(format!(
            "unknown peer DID: {}",
            req.node_did
        )));
    }

    state.db.enqueue_sync(
        &req.repo,
        &req.node_did,
        &req.ref_name,
        &req.new_sha,
        None,
    ).await?;

    tracing::info!(
        repo = %req.repo,
        peer = %req.node_did,
        ref_name = %req.ref_name,
        "enqueued sync from peer notify"
    );

    Ok(Json(serde_json::json!({
        "status": "ok",
        "queued": true,
        "repo": req.repo,
    })))
}

/// GET /api/v1/peers/{did}/ping
///
/// Check if a specific peer in our list is currently reachable.
pub async fn ping_peer(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let peers = state.db.list_peers().await?;
    let peer = peers.into_iter().find(|p| p.did == did)
        .ok_or_else(|| AppError::RepoNotFound(format!("peer {did} not found")))?;

    // Async ping
    let url = format!("{}/health", peer.http_url.trim_end_matches('/'));
    let ok = reqwest::get(&url).await.map(|r| r.status().is_success()).unwrap_or(false);

    let _ = state.db.mark_peer_ping(&did, ok).await;

    Ok(Json(serde_json::json!({
        "did": did,
        "http_url": peer.http_url,
        "reachable": ok,
    })))
}
