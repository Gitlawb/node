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

/// Extract an IPv4 address embedded in an IPv6 literal across the transition
/// formats that carry one: IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible
/// (`::a.b.c.d`), 6to4 (`2002:WWXX:YYZZ::/16`), and the NAT64 well-known prefix
/// (`64:ff9b::/96`). Returns `None` for native IPv6. Callers fold the result
/// back through the v4 range checks so loopback/private addresses smuggled in
/// via any of these encodings are rejected, not just the mapped/compatible pair.
///
/// INCOMPLETE-NAT64 CONTRACT: non-well-known NAT64 prefixes (e.g. the RFC 8215
/// local-use `64:ff9b:1::/48`) are deliberately **not** decoded here — their v4
/// sits at a prefix-length-dependent offset (RFC 6052 §2.2) — so they return
/// `None`. Any caller that needs them blocked must reject the wider
/// `64:ff9b::/32` itself; `is_public_http_url` does this in its native-v6 arm.
fn embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
        return Some(v4);
    }
    let s = v6.segments();
    // 6to4 (2002::/16) embeds W.X.Y.Z in the next two segments.
    if s[0] == 0x2002 {
        let [a, b] = s[1].to_be_bytes();
        let [c, d] = s[2].to_be_bytes();
        return Some(std::net::Ipv4Addr::new(a, b, c, d));
    }
    // NAT64 well-known prefix (64:ff9b::/96) embeds the IPv4 in the low 32 bits.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        let [a, b] = s[6].to_be_bytes();
        let [c, d] = s[7].to_be_bytes();
        return Some(std::net::Ipv4Addr::new(a, b, c, d));
    }
    None
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
        // Fold any IPv6 literal that embeds an IPv4 address (mapped, compatible,
        // 6to4, NAT64) down to that IPv4 so the v4 range checks catch
        // loopback/private addresses smuggled in via an IPv6 encoding, then
        // re-check loopback/unspecified.
        let ip = match ip {
            std::net::IpAddr::V6(v6) => embedded_ipv4(v6).map(std::net::IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        if ip.is_loopback() || ip.is_unspecified() {
            return false;
        }
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                // RFC1918 private, link-local, CGNAT (100.64.0.0/10), or the
                // RFC1122 "this host" block 0.0.0.0/8 (never a valid destination;
                // 0.0.0.0 itself is already caught by the is_unspecified check).
                if v4.is_private()
                    || v4.is_link_local()
                    || (o[0] == 100 && (o[1] & 0xc0) == 64)
                    || o[0] == 0
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
                // Any NAT64 address (64:ff9b::/32) that is not the cleanly
                // decodable well-known /96 — e.g. the RFC 8215 local-use
                // 64:ff9b:1::/48 — carries a translated target whose embedded v4
                // sits at a prefix-length-dependent offset (RFC 6052 §2.2).
                // Rather than risk a wrong decode across every prefix length we
                // reject the whole NAT64 space here. The well-known /96 was
                // already folded to its v4 above and never reaches this arm.
                if s[0] == 0x0064 && s[1] == 0xff9b {
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
                    // Use short owner (did:key-only normalization) matching DB convention
                    let short = crate::db::normalize_owner_key(owner);
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
            // RFC1122 "this host" block 0.0.0.0/8 beyond 0.0.0.0 itself,
            // including the upper boundary (1.0.0.0 is public, tested below).
            "http://0.0.0.1:7545",
            "http://0.1.2.3/",
            "http://0.255.255.255/",
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
            // 6to4 (2002::/16) embedding loopback/private v4.
            "http://[2002:7f00:1::]:7545",
            "http://[2002:a00:1::]/",
            "http://[2002:c0a8:101::]/",
            // NAT64 well-known prefix (64:ff9b::/96) embedding loopback/private v4.
            "http://[64:ff9b::7f00:1]/",
            "http://[64:ff9b::a00:1]:7545",
            // NAT64 local-use prefix (64:ff9b:1::/48, RFC 8215) — rejected
            // outright rather than decoded, so the whole NAT64 space is closed.
            "http://[64:ff9b:1::7f00:1]/",
            "http://[64:ff9b:1::a00:1]:7545",
            "http://[64:ff9b:1:a00::]/",
            // Local-use NAT64 wrapping a *public* v4 (203.0.113.10) is still
            // rejected: the block is prefix-based, not payload-based.
            "http://[64:ff9b:1::cb00:710a]/",
        ] {
            assert!(!is_public_http_url(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn accepts_6to4_and_nat64_wrapping_public_v4() {
        // Fold-and-recheck stays consistent with the mapped/compatible handling:
        // a transition address that wraps a public v4 is allowed, only the
        // private/loopback-wrapping forms above are rejected. 203.0.113.10.
        assert!(is_public_http_url("http://[2002:cb00:710a::]/"));
        assert!(is_public_http_url("http://[64:ff9b::cb00:710a]/"));
    }

    #[test]
    fn accepts_public_outside_cgnat_range() {
        // 100.0.0.0/10 boundary: .63 and .128 are public, only 100.64-127 is CGNAT.
        assert!(is_public_http_url("http://100.63.255.255:7545"));
        assert!(is_public_http_url("http://100.128.0.1/"));
    }

    #[test]
    fn accepts_first_address_above_this_host_block() {
        // 1.0.0.0 is the first address above the rejected 0.0.0.0/8 block;
        // pins the `o[0] == 0` check against an off-by-one into 1.x.
        assert!(is_public_http_url("http://1.0.0.0/"));
    }

    // ── #82: /sync/trigger signature gate + per-IP brake on the peer-sync routes ──
    //
    // These drive the FULL production router (crate::server::build_router) so the
    // route wiring, layer order, and config-mode branching are all under test.
    // The positive-path and DID-agnostic cases mount the handler directly because
    // signed_request_as injects only an AuthenticatedDid extension (not a real
    // RFC-9421 signature), which require_signature rejects on the full router.
    use crate::rate_limit::{IpRateLimiter, RateLimiter, TrustedProxy};
    use crate::state::AppState;
    use crate::test_support::{signed_request_as, test_state};
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{header, Method, Request, StatusCode};
    use axum::routing::post;
    use axum::{middleware, Extension, Router};
    use gitlawb_core::http_sig::sign_request;
    use gitlawb_core::identity::Keypair;
    use sqlx::PgPool;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn unsigned_post(uri: &str, body: &str, peer: &str) -> Request<Body> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    fn require_signed_peer_writes(state: &mut AppState) {
        let mut cfg = (*state.config).clone();
        cfg.require_signed_peer_writes = true;
        state.config = Arc::new(cfg);
    }

    const NOTIFY_BODY: &str = r#"{"repo":"demo","ref_name":"refs/heads/main","new_sha":"0000000000000000000000000000000000000000","node_did":"PEER_DID"}"#;

    // ── trigger: mandatory signature ──────────────────────────────────────────

    #[sqlx::test]
    async fn sync_trigger_rejects_unsigned_in_default_mode(pool: PgPool) {
        // The hole: with require_signed_peer_writes=false (default), an anonymous
        // caller reaches the fan-out. Must be 401 regardless of the flag.
        let state = test_state(pool).await;
        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(unsigned_post(
                "/api/v1/sync/trigger",
                "{}",
                "203.0.113.1:5000",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test]
    async fn sync_trigger_rejects_unsigned_in_signed_writes_mode(pool: PgPool) {
        // The signature requirement must not depend on the flag.
        let mut state = test_state(pool).await;
        require_signed_peer_writes(&mut state);
        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(unsigned_post(
                "/api/v1/sync/trigger",
                "{}",
                "203.0.113.2:5000",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test]
    async fn sync_trigger_admits_signed_caller(pool: PgPool) {
        // must-not-over-throttle: a signed caller reaches the handler and (with no
        // peers seeded) gets 200, not 429. Direct-mount because a real signature
        // cannot be forged through the full router in tests.
        let state = test_state(pool).await;
        let did = Keypair::generate().did().to_string();
        let app = Router::new()
            .route("/api/v1/sync/trigger", post(super::trigger_sync))
            .layer(middleware::from_fn(crate::rate_limit::rate_limit_by_ip))
            .layer(Extension(IpRateLimiter {
                limiter: RateLimiter::new(60, Duration::from_secs(3600)),
                trust: TrustedProxy::None,
            }))
            .with_state(state);
        let mut req =
            signed_request_as(&did, Method::POST, "/api/v1/sync/trigger", Body::from("{}"));
        req.extensions_mut().insert(ConnectInfo(
            "203.0.113.3:5000".parse::<SocketAddr>().unwrap(),
        ));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── trigger: IP brake ─────────────────────────────────────────────────────

    #[sqlx::test]
    async fn sync_trigger_ip_flood_is_throttled(pool: PgPool) {
        // The brake is outermost, so an over-limit request 429s before it ever
        // reaches require_signature — an unsigned request suffices to prove it.
        let mut state = test_state(pool).await;
        state.sync_trigger_rate_limiter = RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let peer = "203.0.113.4:5000";
        // Exhaust the single-request budget up front.
        assert!(
            state
                .sync_trigger_rate_limiter
                .check(&peer.parse::<SocketAddr>().unwrap().ip().to_string())
                .await
        );
        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(unsigned_post("/api/v1/sync/trigger", "{}", peer))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[sqlx::test]
    async fn sync_trigger_brake_is_did_agnostic(pool: PgPool) {
        // Why per-IP, not per-DID: a DID farm (fresh did:key per request) does not
        // bypass an IP-keyed brake. Two DISTINCT DIDs from one IP, brake limit 1 →
        // the second is 429. A per-DID limiter would give each DID its own bucket.
        let state = test_state(pool).await;
        let app = Router::new()
            .route("/api/v1/sync/trigger", post(super::trigger_sync))
            .layer(middleware::from_fn(crate::rate_limit::rate_limit_by_ip))
            .layer(Extension(IpRateLimiter {
                limiter: RateLimiter::new(1, Duration::from_secs(3600)),
                trust: TrustedProxy::None,
            }))
            .with_state(state);
        let peer = "203.0.113.5:5000".parse::<SocketAddr>().unwrap();
        let mk = |did: &str| {
            let mut r =
                signed_request_as(did, Method::POST, "/api/v1/sync/trigger", Body::from("{}"));
            r.extensions_mut().insert(ConnectInfo(peer));
            r
        };
        let first = app
            .clone()
            .oneshot(mk(&Keypair::generate().did().to_string()))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = app
            .oneshot(mk(&Keypair::generate().did().to_string()))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[sqlx::test]
    async fn sync_trigger_forged_forwarded_header_cannot_bypass(pool: PgPool) {
        // TrustedProxy::None keys on the socket peer, so rotating X-Forwarded-For
        // from one socket peer does not refill the bucket. limit 1: first request
        // consumes it (then 401 unsigned), second from the same socket → 429
        // regardless of a different XFF value.
        let mut state = test_state(pool).await;
        state.sync_trigger_rate_limiter = RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let router = crate::server::build_router(state);
        let mut a = unsigned_post("/api/v1/sync/trigger", "{}", "203.0.113.6:5000");
        a.headers_mut()
            .insert("x-forwarded-for", "1.1.1.1".parse().unwrap());
        assert_eq!(
            router.clone().oneshot(a).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let mut b = unsigned_post("/api/v1/sync/trigger", "{}", "203.0.113.6:5000");
        b.headers_mut()
            .insert("x-forwarded-for", "2.2.2.2".parse().unwrap());
        assert_eq!(
            router.oneshot(b).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[sqlx::test]
    async fn sync_trigger_rate_limit_zero_disables_but_signature_holds(pool: PgPool) {
        // 0 disables the brake (RateLimiter::check early-returns), proving the two
        // halves are independent: no 429 even under a flood, but the signature gate
        // still 401s every unsigned request.
        let mut state = test_state(pool).await;
        state.sync_trigger_rate_limiter = RateLimiter::new(0, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let router = crate::server::build_router(state);
        for _ in 0..3 {
            let resp = router
                .clone()
                .oneshot(unsigned_post(
                    "/api/v1/sync/trigger",
                    "{}",
                    "203.0.113.7:5000",
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }

    // ── notify: braked, but signature behavior unchanged ──────────────────────

    async fn seed_peer(state: &AppState) -> String {
        let did = Keypair::generate().did().to_string();
        state
            .db
            .upsert_peer(&did, "https://peer.example.com")
            .await
            .unwrap();
        did
    }

    #[sqlx::test]
    async fn sync_notify_unsigned_flood_is_throttled(pool: PgPool) {
        // notify still accepts an unsigned known-peer notification (rolling-upgrade
        // compat), but a flood from one IP is now braked. brake limit 1: first
        // enqueues (200), second from the same IP → 429.
        let mut state = test_state(pool).await;
        state.peer_write_rate_limiter = RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let peer_did = seed_peer(&state).await;
        let body = NOTIFY_BODY.replace("PEER_DID", &peer_did);
        let router = crate::server::build_router(state);
        let first = router
            .clone()
            .oneshot(unsigned_post(
                "/api/v1/sync/notify",
                &body,
                "203.0.113.8:5000",
            ))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = router
            .oneshot(unsigned_post(
                "/api/v1/sync/notify",
                &body,
                "203.0.113.8:5000",
            ))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[sqlx::test]
    async fn sync_notify_distinct_ips_are_not_collaterally_throttled(pool: PgPool) {
        // must-not-over-throttle: per-IP keying means one peer's volume does not
        // throttle another. brake limit 1, two DIFFERENT source IPs → both 200.
        let mut state = test_state(pool).await;
        state.peer_write_rate_limiter = RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let peer_did = seed_peer(&state).await;
        let body = NOTIFY_BODY.replace("PEER_DID", &peer_did);
        let router = crate::server::build_router(state);
        for ip in ["203.0.113.20:5000", "203.0.113.21:5000"] {
            let resp = router
                .clone()
                .oneshot(unsigned_post("/api/v1/sync/notify", &body, ip))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "distinct IP {ip} must not be throttled"
            );
        }
    }

    #[sqlx::test]
    async fn notify_flood_does_not_exhaust_trigger_bucket(pool: PgPool) {
        // Separate buckets: draining peer_write via an unsigned notify flood must
        // NOT throttle the signed trigger caller from the same IP. After the notify
        // bucket is spent, an unsigned trigger from that IP hits its own (unspent)
        // bucket and is rejected by the SIGNATURE gate (401), not the brake (429).
        let mut state = test_state(pool).await;
        state.peer_write_rate_limiter = RateLimiter::new(1, Duration::from_secs(3600));
        state.sync_trigger_rate_limiter = RateLimiter::new(60, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let peer_did = seed_peer(&state).await;
        let body = NOTIFY_BODY.replace("PEER_DID", &peer_did);
        let router = crate::server::build_router(state);
        let ip = "203.0.113.9:5000";
        assert_eq!(
            router
                .clone()
                .oneshot(unsigned_post("/api/v1/sync/notify", &body, ip))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            router
                .clone()
                .oneshot(unsigned_post("/api/v1/sync/notify", &body, ip))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS,
            "peer_write bucket should now be exhausted for this IP"
        );
        let trigger = router
            .oneshot(unsigned_post("/api/v1/sync/trigger", "{}", ip))
            .await
            .unwrap();
        assert_eq!(
            trigger.status(),
            StatusCode::UNAUTHORIZED,
            "trigger must hit its own bucket (401 from the sig gate), not the drained peer_write bucket (429)"
        );
    }

    #[sqlx::test]
    async fn announce_still_accepts_unsigned_in_default_mode(pool: PgPool) {
        // must-not-over-reach: adding the brake must not tighten announce's
        // rolling-upgrade behavior — an unsigned announce with a public URL still
        // succeeds (it only gains the brake, which a single request is under).
        let state = test_state(pool).await;
        let did = Keypair::generate().did().to_string();
        let body = format!(r#"{{"did":"{did}","http_url":"https://peer.example.com"}}"#);
        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(unsigned_post(
                "/api/v1/peers/announce",
                &body,
                "203.0.113.10:5000",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Build a request carrying a REAL RFC 9421 signature (not just an injected
    // extension), so it passes require_signature on the full production router.
    fn real_signed_trigger(peer: &str) -> Request<Body> {
        let kp = Keypair::generate();
        let body = b"{}";
        let s = sign_request(&kp, "POST", "/api/v1/sync/trigger", body);
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/sync/trigger")
            .header(header::CONTENT_TYPE, "application/json")
            .header("content-digest", s.content_digest)
            .header("signature-input", s.signature_input)
            .header("signature", s.signature)
            .body(Body::from(body.to_vec()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        req
    }

    #[sqlx::test]
    async fn sync_trigger_admits_real_signature_through_full_router(pool: PgPool) {
        // The positive path through the REAL gate: a validly-signed trigger passes
        // require_signature on the full router and reaches the handler (no peers
        // seeded → 200), in BOTH config modes.
        let state = test_state(pool.clone()).await;
        let resp = crate::server::build_router(state)
            .oneshot(real_signed_trigger("203.0.113.30:5000"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a real signature must reach the handler (default mode)"
        );

        let mut state = test_state(pool).await;
        require_signed_peer_writes(&mut state);
        let resp = crate::server::build_router(state)
            .oneshot(real_signed_trigger("203.0.113.30:5001"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a real signature must reach the handler (signed-writes mode)"
        );
    }

    #[sqlx::test]
    async fn announce_flood_is_throttled(pool: PgPool) {
        // The peer_write brake covers /peers/announce too (co-benefit): limit 1,
        // first unsigned announce from an IP is 200, the second from that IP 429.
        let mut state = test_state(pool).await;
        state.peer_write_rate_limiter = RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let did = Keypair::generate().did().to_string();
        let body = format!(r#"{{"did":"{did}","http_url":"https://peer.example.com"}}"#);
        let router = crate::server::build_router(state);
        let ip = "203.0.113.31:5000";
        assert_eq!(
            router
                .clone()
                .oneshot(unsigned_post("/api/v1/peers/announce", &body, ip))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            router
                .oneshot(unsigned_post("/api/v1/peers/announce", &body, ip))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS,
            "announce must be braked by the peer_write limiter"
        );
    }

    #[sqlx::test]
    async fn sync_trigger_429_body_is_generic_not_push(pool: PgPool) {
        // The shared 429 middleware now serves the sync routes, so its body must
        // not claim "push" (RED before the message was genericized).
        let mut state = test_state(pool).await;
        state.sync_trigger_rate_limiter = RateLimiter::new(1, Duration::from_secs(3600));
        state.push_limiter_trust = TrustedProxy::None;
        let peer = "203.0.113.32:5000";
        assert!(
            state
                .sync_trigger_rate_limiter
                .check(&peer.parse::<SocketAddr>().unwrap().ip().to_string())
                .await
        );
        let router = crate::server::build_router(state);
        let resp = router
            .oneshot(unsigned_post("/api/v1/sync/trigger", "{}", peer))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("rate limit exceeded"), "429 body: {s:?}");
        assert!(
            !s.contains("push"),
            "a 429 on a sync route must not say 'push': {s:?}"
        );
    }
}
