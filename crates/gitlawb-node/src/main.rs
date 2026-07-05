mod api;
mod arweave;
mod auth;
mod bootstrap;
mod cert;
mod config;
mod db;
mod encrypted_pin;
mod error;
mod git;
mod graphql;
mod icaptcha;
mod ipfs_pin;
mod metrics;
mod operator;
mod p2p;
mod pinata;
mod rate_limit;
mod server;
mod state;
mod sync;
#[cfg(test)]
mod test_support;
mod visibility;
mod webhooks;

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;

use config::Config;
use db::Db;
use state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("gitlawb_node=debug".parse().unwrap())
                .add_directive("tower_http=info".parse().unwrap()),
        )
        .init();

    let mut config = Config::parse();

    // Merge the embedded seed list of public network nodes into the runtime
    // bootstrap peers. Operators can opt out via GITLAWB_BOOTSTRAP_DISABLE_SEEDS.
    bootstrap::merge_seeds(&mut config);

    if !config.public_read {
        warn!(
            "GITLAWB_PUBLIC_READ=false is reserved; per-repository private-read enforcement is not wired in alpha"
        );
    }

    // Load or generate the node's identity keypair
    let keypair = load_or_create_keypair(&config)?;
    let node_did = keypair.did();

    // One-time metrics init. Must run before any handler that calls into
    // `metrics::record_*` so the registry exists when the first event fires.
    // Safe to call even when GITLAWB_METRICS_ADDR is unset — those helpers
    // are simply no-ops until something reads from the registry.
    metrics::init(env!("CARGO_PKG_VERSION"), &node_did.to_string());

    info!("╔══════════════════════════════════════════╗");
    info!(
        "║         gitlawb node v{}             ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("╚══════════════════════════════════════════╝");
    info!(did = %node_did, "node identity");
    info!(addr = %config.bind_addr(), "listening");

    // Process-wide shutdown signal. One sender lives in AppState (cloned
    // into every handler); main() keeps a clone and flips it on SIGINT
    // or SIGTERM. Tasks that hold a watch::Receiver get notified at
    // their next await point.
    let (shutdown_tx, _shutdown_rx_for_main) = watch::channel(false);

    // Connect to PostgreSQL database
    let db = Arc::new(
        Db::connect(&config.database_url)
            .await
            .context("failed to connect to database")?,
    );

    // Prune peer rows that point back at this node (stale self-loop entries)
    if let Some(public_url) = config.public_url.as_deref() {
        match db.prune_self_peers(public_url).await {
            Ok(0) => {}
            Ok(n) => info!(removed = n, public_url, "pruned self-loop peer rows"),
            Err(e) => warn!(err = %e, "prune_self_peers failed (non-fatal)"),
        }
    }

    // Prune peer rows with non-public hosts (loopback/private/internal) that
    // were injected via the unauthenticated announce route — they poison the
    // sync-notify fan-out (SSRF + crowding out real peers).
    match db.prune_non_public_peers().await {
        Ok(0) => {}
        Ok(n) => info!(removed = n, "pruned non-public (poisoned) peer rows"),
        Err(e) => warn!(err = %e, "prune_non_public_peers failed (non-fatal)"),
    }

    // Ensure repos directory exists
    std::fs::create_dir_all(&config.repos_dir).context("failed to create repos directory")?;

    // Start libp2p swarm (if p2p_port > 0)
    let p2p_handle = if config.p2p_port > 0 {
        let bootstrap_addrs = config
            .p2p_bootstrap
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let shutdown_rx = shutdown_tx.subscribe();
        match p2p::start(
            &node_did.to_string(),
            config.p2p_port,
            bootstrap_addrs,
            Arc::clone(&db),
            config.auto_sync,
            shutdown_rx,
        )
        .await
        {
            Ok(handle) => {
                info!(port = config.p2p_port, peer_id = %handle.local_peer_id, "libp2p swarm started");
                Some(Arc::new(handle))
            }
            Err(e) => {
                tracing::warn!(err = %e, "failed to start libp2p swarm — continuing without p2p");
                None
            }
        }
    } else {
        info!("p2p disabled (p2p_port = 0)");
        None
    };

    // Shared no-redirect HTTP client. See build_http_client for the SSRF rationale.
    let http_client = Arc::new(build_http_client()?);

    let (ref_update_tx, _) = tokio::sync::broadcast::channel::<state::RefUpdateBroadcast>(256);
    let (task_event_tx, _) = tokio::sync::broadcast::channel::<state::TaskEventBroadcast>(256);

    let graphql_schema = Arc::new(graphql::build_schema(
        Arc::clone(&db),
        ref_update_tx.clone(),
        task_event_tx.clone(),
    ));

    let machine_id = std::env::var("FLY_MACHINE_ID").ok();
    if let Some(ref mid) = machine_id {
        info!("  fly machine: {mid}");
    }

    // Initialize Tigris S3 client if bucket is configured
    let tigris = if !config.tigris_bucket.is_empty() {
        match git::tigris::TigrisClient::new(&config.tigris_bucket).await {
            Ok(client) => {
                info!(bucket = %config.tigris_bucket, "tigris storage enabled");
                Some(client)
            }
            Err(e) => {
                tracing::warn!(err = %e, "failed to initialize Tigris client — using local-only storage");
                None
            }
        }
    } else {
        info!("tigris storage disabled (no bucket configured)");
        None
    };

    let repo_store =
        git::repo_store::RepoStore::new(config.repos_dir.clone(), tigris, db.pool().clone());

    // Per-DID limiter for the creation endpoints. Keyed on the authenticated
    // DID (attacker-varied), so bound its key set to cap memory.
    let rate_limiter =
        rate_limit::RateLimiter::new_bounded(10, std::time::Duration::from_secs(3600), 200_000);

    // Push-path flood brake: max git-receive-pack requests per client IP per
    // hour (counts both the info/refs advertisement and the push POST). Sized
    // for heavy agent automation while still stopping flood traffic (the June
    // 2026 attack pushed several times per second per IP). GITLAWB_PUSH_RATE_LIMIT
    // overrides; 0 disables. Bounded key set — the key is a client-influenced IP.
    let push_limit = std::env::var("GITLAWB_PUSH_RATE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(600);
    let push_rate_limiter = rate_limit::RateLimiter::new_bounded(
        push_limit,
        std::time::Duration::from_secs(3600),
        200_000,
    );
    if push_limit == 0 {
        tracing::warn!("GITLAWB_PUSH_RATE_LIMIT=0 — per-IP push rate limiting disabled");
    }

    // Which forwarded header the edge is trusted to set. Default None (trust
    // nothing, key on the socket peer). Fly nodes set GITLAWB_TRUSTED_PROXY=fly;
    // a node behind Caddy/NGINX sets it to x-forwarded-for.
    let push_limiter_trust = rate_limit::TrustedProxy::from_env_value(
        &std::env::var("GITLAWB_TRUSTED_PROXY").unwrap_or_default(),
    );
    tracing::info!(trust = ?push_limiter_trust, push_limit, "push rate limiter configured");

    // Initialize the iCaptcha proof gate (inert unless ICAPTCHA_MODE is set).
    icaptcha::init().await;

    let state = AppState {
        config: Arc::new(config.clone()),
        db,
        node_did: node_did.clone(),
        node_keypair: Arc::new(keypair),
        p2p: p2p_handle,
        http_client,
        ref_update_tx,
        task_event_tx,
        graphql_schema,
        machine_id,
        repo_store,
        rate_limiter,
        push_rate_limiter,
        push_limiter_trust,
        shutdown_tx: shutdown_tx.clone(),
    };

    // Periodic peer-count poll for the metrics gauge. If p2p is disabled
    // we still set the gauge to 0 so dashboards don't show "no data".
    {
        let p2p_for_metrics = state.p2p.clone();
        let mut shutdown_rx = state.subscribe_shutdown();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let count = match &p2p_for_metrics {
                            Some(h) => h.status().await.map(|s| s.connected_peers).unwrap_or(0),
                            None => 0,
                        };
                        metrics::set_peers_connected(count as i64);
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            return;
                        }
                    }
                }
            }
        });
    }

    // Spawn a task that flips the shutdown signal on SIGINT or SIGTERM.
    // On Unix, both signals are handled. On Windows, only Ctrl-C is
    // supported by tokio::signal::ctrl_c.
    {
        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal as unix_signal, SignalKind};
                let mut sigterm =
                    unix_signal(SignalKind::terminate()).expect("install SIGTERM handler");
                let mut sigint =
                    unix_signal(SignalKind::interrupt()).expect("install SIGINT handler");
                tokio::select! {
                    _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
                    _ = sigint.recv()  => info!("SIGINT received, shutting down"),
                }
            }
            #[cfg(not(unix))]
            {
                use tokio::signal;
                let _ = signal::ctrl_c().await;
                info!("Ctrl-C received, shutting down");
            }
            tx.send(true).ok();
        });
    }

    // Periodic cleanup of expired rate limit entries + consumed-proof ledger
    {
        let rl = state.rate_limiter.clone();
        let push_rl = state.push_rate_limiter.clone();
        let db = state.db.clone();
        let mut shutdown_rx = state.subscribe_shutdown();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {
                        rl.cleanup().await;
                        push_rl.cleanup().await;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        if let Err(e) = db.sweep_expired_proofs(now).await {
                            tracing::warn!(err = %e, "failed to sweep expired iCaptcha proofs");
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    let router = server::build_router(state.clone());
    let listener = TcpListener::bind(config.bind_addr())
        .await
        .with_context(|| format!("failed to bind to {}", config.bind_addr()))?;

    info!("✓ node started — did:{}", node_did);
    info!("  repos dir: {}", config.repos_dir.display());
    info!(
        "  database:  PostgreSQL ({})",
        &config.database_url.split('@').next_back().unwrap_or("?")
    );

    // Optional Prometheus metrics listener on a separate port.
    let metrics_handle = if !config.metrics_addr.is_empty() {
        match spawn_metrics_server(&config.metrics_addr, state.clone()).await {
            Ok(handle) => {
                info!(addr = %config.metrics_addr, "metrics endpoint listening");
                Some(handle)
            }
            Err(e) => {
                warn!(err = %e, addr = %config.metrics_addr, "failed to start metrics endpoint — continuing without");
                None
            }
        }
    } else {
        info!("metrics endpoint disabled (GITLAWB_METRICS_ADDR not set)");
        None
    };

    // Publish our DID record to the Kademlia DHT shortly after startup
    if let Some(p2p) = &state.p2p {
        let did_record = p2p::DidRecord {
            did: node_did.to_string(),
            http_url: config.public_url.clone().unwrap_or_default(),
            peer_id: p2p.local_peer_id.to_string(),
            p2p_port: config.p2p_port,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        let p2p_clone = Arc::clone(p2p);
        let mut shutdown_rx = state.subscribe_shutdown();
        tokio::spawn(async move {
            // Small delay so Kademlia can find peers first
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                _ = shutdown_rx.changed() => return,
            }
            p2p_clone.put_did(did_record).await;
            info!("DID record published to Kademlia DHT");
        });
    }

    // Spawn background gossip: announce to bootstrap peers, then ping known peers periodically
    {
        let gossip_state = state.clone();
        let bootstrap_peers = config.bootstrap_peers.clone();
        let shutdown_rx = state.subscribe_shutdown();
        tokio::spawn(async move {
            gossip_task(gossip_state, bootstrap_peers, shutdown_rx).await;
        });
    }

    // Start multi-node sync worker if auto_sync is enabled
    if config.auto_sync {
        sync::start(
            Arc::clone(&state.db),
            Arc::clone(&state.config),
            Arc::clone(&state.node_keypair),
            state.subscribe_shutdown(),
        );
        info!("auto-sync worker started");
    }

    // On-chain operator setup: verify stake + spawn heartbeat loop
    if !state.config.contract_node_staking.is_empty()
        && !state.config.operator_private_key.is_empty()
    {
        match build_operator_client(&state.config, &state.node_did.to_string()) {
            Ok(client) => match operator::startup_check(&client).await {
                Ok(_) => {
                    let arc_client = Arc::new(client);
                    arc_client.spawn_heartbeat_loop(state.subscribe_shutdown());
                }
                Err(e) => {
                    if state.config.operator_strict_mode {
                        return Err(e.context("strict-mode operator check failed"));
                    }
                    tracing::warn!(err = %e, "operator startup check failed — continuing without heartbeat loop");
                }
            },
            Err(e) => {
                if state.config.operator_strict_mode {
                    return Err(e.context("strict-mode: failed to build operator client"));
                }
                tracing::warn!(err = %e, "operator client could not be built — continuing without PoS");
            }
        }
    } else {
        info!("on-chain PoS disabled (GITLAWB_CONTRACT_NODE_STAKING or GITLAWB_OPERATOR_PRIVATE_KEY unset)");
    }

    // axum's `with_graceful_shutdown` waits for in-flight requests to
    // complete (up to the configured grace) once the future resolves.
    let shutdown_signal_for_axum = state.subscribe_shutdown();
    let grace = std::time::Duration::from_secs(config.shutdown_grace_secs);
    info!(grace_secs = config.shutdown_grace_secs, "axum server ready");

    // `into_make_service_with_connect_info` exposes the socket peer address as
    // `ConnectInfo<SocketAddr>` so the push limiter can key on the real client
    // when no trusted proxy header applies (see `rate_limit::client_key`).
    let serve_result = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let mut rx = shutdown_signal_for_axum;
        // Wait until the watcher flips to true, then return so axum
        // can begin draining.
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                // Sender dropped — treat as shutdown.
                break;
            }
        }
    })
    .await;

    // Server has stopped accepting new connections and drained in-flight
    // requests. Tear the rest of the system down.
    info!("HTTP server stopped, beginning process shutdown");
    if let Some(h) = metrics_handle {
        h.abort();
    }
    let _ = grace; // recorded for operators in the log above; not enforced
    serve_result?;
    info!("clean exit");
    Ok(())
}

/// Spawn a small axum router that exposes only `GET /metrics` on its own
/// listener. Returns the JoinHandle so `main()` can abort it on shutdown.
/// This is deliberately separate from the main router so the metrics port
/// can be firewalled differently from the API port — bind to localhost
/// or a private interface only.
async fn spawn_metrics_server(addr: &str, state: AppState) -> Result<tokio::task::JoinHandle<()>> {
    use axum::{response::IntoResponse, routing::get, Router};

    async fn metrics_handler() -> impl IntoResponse {
        match metrics::encode() {
            Ok(body) => (
                axum::http::StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                body,
            ),
            Err(e) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                format!("metrics encode error: {e}"),
            ),
        }
    }

    let mut shutdown_rx = state.subscribe_shutdown();
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind metrics listener to {addr}"))?;
    let app = Router::new().route("/metrics", get(metrics_handler));

    let handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                while !*shutdown_rx.borrow_and_update() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
        {
            warn!(err = %e, "metrics server exited with error");
        }
    });
    Ok(handle)
}

fn build_operator_client(
    config: &config::Config,
    node_did: &str,
) -> Result<operator::OperatorClient> {
    use alloy::primitives::Address;
    use std::str::FromStr;

    let contract_address = Address::from_str(&config.contract_node_staking)
        .with_context(|| format!("invalid contract address: {}", config.contract_node_staking))?;

    let cfg = operator::OperatorConfig {
        rpc_url: config.chain_rpc_url.clone(),
        private_key: config.operator_private_key.clone(),
        contract_address,
        node_did: node_did.to_string(),
        heartbeat_interval: std::time::Duration::from_secs(config.heartbeat_interval_hours * 3600),
        strict_mode: config.operator_strict_mode,
    };
    Ok(operator::OperatorClient::new(cfg))
}

/// Announce to bootstrap peers on startup, then periodically ping all known peers.
async fn gossip_task(
    state: AppState,
    bootstrap_peers: Vec<String>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // If shutdown arrives during the initial delay, exit before announcing.
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
        _ = shutdown_rx.changed() => {
            if *shutdown_rx.borrow() {
                info!("gossip: shutdown during startup delay, exiting");
                return;
            }
        }
    }

    // Reuse the shared no-redirect client for every gossip outbound call (the
    // bootstrap announce POST and the periodic peer /health ping). Peer URLs are
    // attacker-influenceable, so a 3xx to a private address must not be followed.
    // Do NOT fall back to reqwest::Client::new(): its default follows redirects
    // and would reintroduce the SSRF closed here (#93).
    let client = state.http_client.clone();
    let my_did = state.node_did.to_string();
    let my_url = state.config.public_url.clone().unwrap_or_default();

    // Announce ourselves to each bootstrap peer
    for peer_url in &bootstrap_peers {
        // Cooperative shutdown between peers — a slow peer shouldn't
        // block the node exiting.
        if *shutdown_rx.borrow() {
            info!("gossip: shutdown signalled during peer announce, exiting");
            return;
        }
        let path = "/api/v1/peers/announce";
        let announce_url = format!("{}{}", peer_url.trim_end_matches('/'), path);
        let body = serde_json::json!({
            "did": my_did.clone(),
            "http_url": my_url.clone(),
        });
        let body_bytes = match serde_json::to_vec(&body) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(err = %e, "failed to serialize peer announce body");
                continue;
            }
        };
        let signed = sign_request(state.node_keypair.as_ref(), "POST", path, &body_bytes);
        // Per-request timeout inside the loop; do not let one hung peer
        // block others. The request itself is a normal tokio future so
        // it's cancel-safe on shutdown.
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client
                .post(&announce_url)
                .header("Content-Type", "application/json")
                .header("Content-Digest", signed.content_digest)
                .header("Signature-Input", signed.signature_input)
                .header("Signature", signed.signature)
                .body(body_bytes)
                .send(),
        )
        .await
        {
            Ok(Ok(resp)) => {
                if resp.status().is_success() {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        // Add them back to our peer list
                        if let (Some(their_did), Some(their_url)) = (
                            json.get("node_did").and_then(|v| v.as_str()),
                            json.get("node_url").and_then(|v| v.as_str()),
                        ) {
                            if !their_url.is_empty() {
                                let _ = state.db.upsert_peer(their_did, their_url).await;
                                tracing::info!(did = %their_did, url = %their_url, "bootstrap peer added");
                            }
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(url = %announce_url, err = %e, "failed to announce to bootstrap peer")
            }
            Err(_) => tracing::warn!(url = %announce_url, "bootstrap peer announce timed out (5s)"),
        }
    }

    // Periodic ping every 5 minutes — exit on shutdown.
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let peers = match state.db.list_peers().await {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                for peer in peers {
                    let ok = ping_peer_health(&client, &peer.http_url).await;
                    let _ = state.db.mark_peer_ping(&peer.did, ok).await;
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("gossip task: shutdown signal received, exiting");
                    return;
                }
            }
        }
    }
}

/// Build the shared node HTTP client used for every outbound fan-out (sync
/// trigger, profile/repo fetches, gossip announce + peer pings).
///
/// No redirects: peer URLs are attacker-influenceable, so a `3xx` to a private
/// address must not be followed (SSRF guard, #78/#93). Do NOT replace with
/// `reqwest::Client::new()` — its default follows redirects. Kept as a named
/// builder so tests bind the redirect guarantee to the real client the node
/// runs, not a hand-rolled equivalent.
fn build_http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Ping a peer's `/health` endpoint and report whether it answered 2xx.
///
/// Takes the client by reference so callers supply the shared, no-redirect
/// `state.http_client`. Peer URLs are attacker-influenceable, so a `3xx` to a
/// private address must not be followed. Do NOT call this with a bare
/// `reqwest::Client::new()`: its default follows redirects and would
/// reintroduce the SSRF this guards against (#93).
async fn ping_peer_health(client: &reqwest::Client, http_url: &str) -> bool {
    let url = format!("{}/health", http_url.trim_end_matches('/'));
    client
        .get(&url)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

fn load_or_create_keypair(config: &Config) -> Result<Keypair> {
    let key_path = config.resolved_key_path();

    if key_path.exists() {
        let pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("failed to read key from {}", key_path.display()))?;
        let kp = Keypair::from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid PEM key: {e}"))?;
        info!(path = %key_path.display(), "loaded existing identity");
        Ok(kp)
    } else {
        let kp = Keypair::generate();
        let pem = kp
            .to_pem()
            .map_err(|e| anyhow::anyhow!("failed to serialize key: {e}"))?;

        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&key_path, pem.as_bytes())?;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        std::fs::write(&key_path, pem.as_bytes())?;

        info!(path = %key_path.display(), did = %kp.did(), "generated new node identity");
        Ok(kp)
    }
}

#[cfg(test)]
mod gossip_ssrf_tests {
    use super::ping_peer_health;

    // Build the client exactly as production does (super::build_http_client) so
    // these tests bind the redirect guarantee to the real shared client the
    // node runs. A regression that makes build_http_client follow redirects
    // fails ping_peer_health_does_not_follow_redirect.
    fn production_http_client() -> reqwest::Client {
        super::build_http_client().expect("failed to build production http client")
    }

    // A peer answering `/health` with a 302 toward an internal address must not
    // be followed: the redirect target must never be requested (#93).
    #[tokio::test]
    async fn ping_peer_health_does_not_follow_redirect() {
        let mut server = mockito::Server::new_async().await;
        let internal = server
            .mock("GET", "/internal-metadata")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;
        let _health = server
            .mock("GET", "/health")
            .with_status(302)
            .with_header("location", &format!("{}/internal-metadata", server.url()))
            .create_async()
            .await;

        let ok = ping_peer_health(&production_http_client(), &server.url()).await;

        assert!(!ok, "a 302 must not count as a healthy peer");
        // expect(0) is enforced only at assert time; this fails if the redirect
        // was followed to the internal target.
        internal.assert_async().await;
    }

    #[tokio::test]
    async fn ping_peer_health_reports_success_on_200() {
        let mut server = mockito::Server::new_async().await;
        let _health = server
            .mock("GET", "/health")
            .with_status(200)
            .create_async()
            .await;

        let ok = ping_peer_health(&production_http_client(), &server.url()).await;

        assert!(ok, "a 200 /health must count as a healthy peer");
    }

    // A transport error (nothing listening) must map to unhealthy, never a
    // spurious healthy — the .unwrap_or(false) arm.
    #[tokio::test]
    async fn ping_peer_health_reports_unhealthy_on_connection_error() {
        let ok = ping_peer_health(&production_http_client(), "http://127.0.0.1:1").await;
        assert!(!ok, "a connection error must count as an unhealthy peer");
    }
}
