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

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use gitlawb_core::did::Did;
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedDid;
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

/// Whether a peer `http_url` is a public http(s) endpoint safe to register.
/// Rejects non-http(s) schemes, loopback/unspecified/private/link-local IPs,
/// and `localhost` / `.local` / `.internal` hostnames. Used at announce time
/// and by the boot-time prune of already-poisoned rows.
pub fn is_public_http_url(raw: &str) -> bool {
    let url = match reqwest::Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let mut host = match url.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };
    // Drop a single trailing dot (FQDN root): `localhost.` resolves the same as
    // `localhost`, so normalize before the suffix/equality checks below.
    if let Some(stripped) = host.strip_suffix('.') {
        host = stripped.to_string();
    }
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return false;
    }
    // host_str() keeps brackets on IPv6 literals (e.g. "[::1]"); strip them
    // before parsing as an IP.
    let ip_candidate = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_candidate.parse::<std::net::IpAddr>() {
        // Reject loopback/unspecified on the literal as given — catches `::1`
        // and `::` before the IPv4-folding below (`::1`.to_ipv4() would
        // otherwise map to a non-loopback `0.0.0.1`).
        if ip.is_loopback() || ip.is_unspecified() {
            return false;
        }
        // Fold IPv4-mapped/compatible IPv6 (`::ffff:127.0.0.1`, `::127.0.0.1`)
        // down to IPv4 so the v4 range checks catch loopback/private addresses
        // smuggled in via an IPv6 literal, then re-check loopback/unspecified.
        let ip = match ip {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .or_else(|| v6.to_ipv4())
                .map(std::net::IpAddr::V4)
                .unwrap_or(ip),
            v4 => v4,
        };
        if ip.is_loopback() || ip.is_unspecified() {
            return false;
        }
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                // RFC1918 private, link-local, or CGNAT (100.64.0.0/10).
                if v4.is_private()
                    || v4.is_link_local()
                    || (o[0] == 100 && (o[1] & 0xc0) == 64)
                {
                    return false;
                }
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                // fc00::/7 (unique-local) or fe80::/10 (link-local)
                if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 {
                    return false;
                }
            }
        }
    }
    true
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
    Ok(Json(
        serde_json::json!({ "peers": resp, "count": resp.len() }),
    ))
}

/// POST /api/v1/peers/announce (auth required)
///
/// A peer announces itself so this node can add it to its peer list.
/// The Authorization header's DID must match the `did` in the body.
pub async fn announce(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Json(req): Json<AnnounceRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    let announced_did: Did = req
        .did
        .parse()
        .map_err(|e: gitlawb_core::Error| AppError::BadRequest(e.to_string()))?;
    if let Some(Extension(auth)) = auth {
        if auth.0 != announced_did.to_string() {
            return Err(AppError::BadRequest(
                "Signature keyid must match announced DID".into(),
            ));
        }
    } else {
        tracing::warn!(
            did = %announced_did,
            "accepted unsigned peer announce; set GITLAWB_REQUIRE_SIGNED_PEER_WRITES=true after all peers upgrade"
        );
    }

    // Validate the URL is a public http(s) endpoint. The announce route is
    // reachable unauthenticated (until all peers sign), so without this an
    // attacker can register loopback/private "peers" (localhost:5432, etc.)
    // and turn our outbound sync-notify fan-out into an SSRF probe — and bury
    // the real peers under junk so node-origin repos stop replicating.
    if !is_public_http_url(&req.http_url) {
        return Err(AppError::BadRequest(
            "http_url must be a public http(s) URL (no loopback, private, or .internal/.local hosts)".into(),
        ));
    }

    // Reject self-announcements: a peer row whose http_url is our own public
    // URL makes the HTTP-notify path fan out to ourselves. Seen in prod when
    // misconfigured dev nodes announce with their upstream's URL.
    // prune_self_peers clears stale rows at boot; this stops new ones.
    if let Some(self_url) = state.config.public_url.as_deref() {
        if req.http_url.trim_end_matches('/') == self_url.trim_end_matches('/') {
            return Err(AppError::BadRequest(
                "http_url is this node's own public URL; refusing to register self as peer".into(),
            ));
        }
    }
    if announced_did.to_string() == state.node_did.to_string() {
        return Err(AppError::BadRequest(
            "did is this node's own DID; refusing to register self as peer".into(),
        ));
    }

    state.db.upsert_peer(&req.did, &req.http_url).await?;

    tracing::info!(did = %req.did, url = %req.http_url, "peer announced");

    // Return our own info so the peer can add us back
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "accepted",
            "node_did": state.node_did.to_string(),
            "node_url": state.config.public_url.as_deref().unwrap_or(""),
            "peer_count": state.db.list_peers().await.map(|p| p.len()).unwrap_or(0),
            "message": "added to peer list",
        })),
    ))
}

/// POST /api/v1/sync/trigger
///
/// Manually trigger a full sync pull from all reachable peers. Fetches each
/// peer's repo list over HTTP and enqueues any repos we don't have or are
/// behind on into the sync_queue. This is the HTTP fallback when Gossipsub
/// p2p is not yet connected.
pub async fn trigger_sync(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    let peers = state.db.list_peers().await?;
    let client = &state.http_client;
    let mut enqueued = 0u32;
    let mut peers_reached = 0u32;

    for peer in &peers {
        if peer.http_url.is_empty() {
            continue;
        }
        let url = format!("{}/api/v1/repos", peer.http_url.trim_end_matches('/'));
        // 30s with the body read inside the timeout: 5s only covered the
        // response headers, so canonical nodes serving large unpaginated repo
        // lists (and transpacific round trips) aborted mid-body.
        let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let resp = client.get(&url).send().await?;
            if !resp.status().is_success() {
                return Err(anyhow::anyhow!("peer returned status {}", resp.status()));
            }
            let repos: Vec<serde_json::Value> = resp.json().await?;
            Ok::<_, anyhow::Error>(repos)
        })
        .await;

        let repos = match result {
            Ok(Ok(repos)) => {
                peers_reached += 1;
                repos
            }
            Ok(Err(e)) => {
                tracing::warn!(peer = %peer.did, err = %e, "trigger_sync: peer fetch failed");
                continue;
            }
            Err(_) => {
                tracing::warn!(peer = %peer.did, "trigger_sync: peer timed out");
                continue;
            }
        };

        for repo in repos {
            let repo_slug = match (
                repo.get("owner_did").and_then(|v| v.as_str()),
                repo.get("name").and_then(|v| v.as_str()),
            ) {
                (Some(owner), Some(name)) => {
                    // Use short owner (last colon segment) matching DB convention
                    let short = owner.split(':').next_back().unwrap_or(owner);
                    format!("{short}/{name}")
                }
                _ => continue,
            };
            let _ = state
                .db
                .enqueue_sync(
                    &repo_slug,
                    &peer.did,
                    "refs/heads/main",
                    "0000000000000000000000000000000000000000",
                    None,
                )
                .await;
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
    // Optional fields — older senders only included the four above. New
    // senders include these so received_ref_updates has full provenance
    // even when the libp2p mesh isn't delivering and the HTTP fallback
    // is the only path that fired.
    #[serde(default)]
    pub pusher_did: Option<String>,
    #[serde(default)]
    pub old_sha: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub cert_id: Option<String>,
}

pub async fn notify_sync(
    State(state): State<AppState>,
    auth: Option<Extension<AuthenticatedDid>>,
    Json(req): Json<NotifyRequest>,
) -> Result<Json<serde_json::Value>> {
    if let Some(Extension(auth)) = auth {
        if auth.0 != req.node_did {
            return Err(AppError::BadRequest(
                "Signature keyid must match notification node_did".into(),
            ));
        }
    } else {
        tracing::warn!(
            did = %req.node_did,
            "accepted unsigned sync notify; set GITLAWB_REQUIRE_SIGNED_PEER_WRITES=true after all peers upgrade"
        );
    }

    // Only accept notifications from known peers
    let peers = state.db.list_peers().await?;
    let known = peers.iter().any(|p| p.did == req.node_did);
    if !known {
        return Err(AppError::BadRequest(format!(
            "unknown peer DID: {}",
            req.node_did
        )));
    }

    state
        .db
        .enqueue_sync(&req.repo, &req.node_did, &req.ref_name, &req.new_sha, None)
        .await?;

    // Mirror the gossipsub-receive handler: insert the same record we'd
    // get from the libp2p path, so /api/v1/events/ref-updates reflects
    // pushes that arrive over either transport.
    let now = chrono::Utc::now().to_rfc3339();
    let update = crate::db::ReceivedRefUpdate {
        id: uuid::Uuid::new_v4().to_string(),
        node_did: req.node_did.clone(),
        pusher_did: req.pusher_did.clone().unwrap_or_default(),
        repo: req.repo.clone(),
        ref_name: req.ref_name.clone(),
        old_sha: req.old_sha.clone().unwrap_or_default(),
        new_sha: req.new_sha.clone(),
        timestamp: req.timestamp.clone().unwrap_or_else(|| now.clone()),
        cert_id: req.cert_id.clone(),
        received_at: now,
        from_peer: format!("http:{}", req.node_did),
    };
    if let Err(e) = state.db.insert_ref_update(&update).await {
        tracing::warn!(err = %e, repo = %req.repo, "failed to insert ref-update from sync notify");
    }

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
    let peer = peers
        .into_iter()
        .find(|p| p.did == did)
        .ok_or_else(|| AppError::RepoNotFound(format!("peer {did} not found")))?;

    // Async ping
    let url = format!("{}/health", peer.http_url.trim_end_matches('/'));
    // Use the shared no-redirect client: bare `reqwest::get` follows redirects,
    // so a peer could answer with `302 -> http://127.0.0.1/` and turn the ping
    // into an SSRF probe.
    let ok = state
        .http_client
        .get(&url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let _ = state.db.mark_peer_ping(&did, ok).await;

    Ok(Json(serde_json::json!({
        "did": did,
        "http_url": peer.http_url,
        "reachable": ok,
    })))
}

#[cfg(test)]
mod tests {
    use super::is_public_http_url;

    #[test]
    fn accepts_public_https_and_http() {
        assert!(is_public_http_url("https://node.gitlawb.com"));
        assert!(is_public_http_url("https://manila.gitlawb.com/"));
        assert!(is_public_http_url("http://203.0.113.10:7545"));
    }

    #[test]
    fn rejects_loopback_private_and_internal() {
        for bad in [
            "http://localhost:7545",
            "http://127.0.0.1:5432/",
            "http://localhost:22/",
            "http://0.0.0.0:7545",
            "http://10.0.0.5:7545",
            "http://192.168.1.10/",
            "http://172.16.0.1:7545",
            "http://169.254.1.1/",
            "http://[::1]:7545",
            "http://gitlawb-node.internal:7545",
            "http://my-node.local/",
            "ftp://node.gitlawb.com",
            "not-a-url",
            "",
            // Trailing-dot FQDN of an internal host.
            "http://localhost./",
            // CGNAT (100.64.0.0/10).
            "http://100.64.0.1:7545",
            "http://100.127.255.255/",
            // IPv4-mapped / IPv4-compatible IPv6 smuggling private/loopback v4.
            "http://[::ffff:127.0.0.1]:7545",
            "http://[::ffff:10.0.0.1]/",
            "http://[::ffff:192.168.1.1]:7545",
            "http://[::127.0.0.1]/",
        ] {
            assert!(!is_public_http_url(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn accepts_public_outside_cgnat_range() {
        // 100.0.0.0/10 boundary: .63 and .128 are public, only 100.64-127 is CGNAT.
        assert!(is_public_http_url("http://100.63.255.255:7545"));
        assert!(is_public_http_url("http://100.128.0.1/"));
    }
}
