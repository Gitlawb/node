// Crate builds as both a library (`gitlawb_node`) and the `gitlawb-node` binary.
// The library exposes the boot surface (build_router, AppState, Config,
// migrations) so the out-of-crate deny-harness integration crate can spawn a
// real node; `src/main.rs` is a thin shim over `run()`. Modules the harness
// reaches are `pub`; the rest stay crate-private.
pub mod api;
mod arweave;
pub mod auth;
mod bootstrap;
mod cert;
pub mod config;
pub mod db;
mod encrypted_pin;
pub mod error;
pub mod git;
mod graphql;
mod icaptcha;
mod ipfs_pin;
mod metrics;
mod operator;
mod p2p;
mod pinata;
mod rate_limit;
pub mod server;
pub mod state;
mod sync;
#[cfg(feature = "test-harness")]
#[doc(hidden)]
pub mod test_harness;
#[cfg(test)]
mod test_support;
mod visibility;
mod webhooks;

use anyhow::{anyhow, Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;

pub use config::Config;
use db::Db;
pub use state::AppState;

#[derive(Clone)]
struct DegradedState {
    node_did: String,
    db_startup: Arc<DbStartupStatus>,
}

/// Two independent counters with no cross-field invariant — atomics, not a
/// lock, so the retry loop and the degraded handlers never contend.
#[derive(Default)]
struct DbStartupStatus {
    attempts: AtomicU64,
    next_retry_secs: AtomicU64,
}

/// Boot and run the node to completion. The `gitlawb-node` binary is a thin
/// `#[tokio::main]` shim over this; keeping the body here (not in `main.rs`)
/// lets the library own the full module tree so integration tests can link it.
pub async fn run() -> Result<()> {
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
    // The boot sweep spares young `.recovering.` claims (they may gate a
    // live round); this one delayed re-sweep clears any spared orphan once
    // it has aged past the liveness floor, ~12s into uptime, so aged claim
    // residue cannot linger beside a healthy final (F2). Fire-and-forget.
    spawn_delayed_claim_resweep(config.resolved_key_path());
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
    // Process-wide shutdown signal. One sender lives in AppState (cloned
    // into every handler); main() keeps a clone and flips it on SIGINT
    // or SIGTERM. Tasks that hold a watch::Receiver get notified at
    // their next await point.
    let (shutdown_tx, _shutdown_rx_for_main) = watch::channel(false);
    spawn_shutdown_signal(shutdown_tx.clone());

    info!(did = %node_did, "node identity");
    info!(addr = %config.bind_addr(), "binding HTTP listener");

    // Bind HTTP once, before dependency initialization, and keep this socket
    // for the life of the process. The degraded server accepts on a dup of the
    // same socket, so the degraded→full handoff never closes the port: while
    // the full server initializes, connections queue in the shared backlog
    // instead of being refused.
    let listener = TcpListener::bind(config.bind_addr())
        .await
        .with_context(|| format!("failed to bind to {}", config.bind_addr()))?;
    let full_std_listener = listener.into_std()?;
    let degraded_listener = TcpListener::from_std(
        full_std_listener
            .try_clone()
            .context("failed to clone HTTP listener for degraded server")?,
    )?;

    // Metrics must stay observable during a database outage — the degraded
    // window is exactly when dashboards need data — so this listener starts
    // before the DB connects.
    let metrics_handle = if !config.metrics_addr.is_empty() {
        match spawn_metrics_server(&config.metrics_addr, shutdown_tx.subscribe()).await {
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

    let db_startup = Arc::new(DbStartupStatus::default());
    let (db_ready_tx, db_ready_rx) = watch::channel(false);
    let mut degraded_handle = tokio::spawn(run_degraded_server(
        degraded_listener,
        node_did.to_string(),
        Arc::clone(&db_startup),
        db_ready_rx,
        shutdown_tx.subscribe(),
    ));

    // Connect to PostgreSQL database. A transient outage or bad secret should
    // not crash-loop the process and hammer the database provider; permanent
    // misconfiguration surfaces through error-level logs and the /ready check.
    let db = tokio::select! {
        db = connect_db_with_retry(&config, Arc::clone(&db_startup), shutdown_tx.subscribe()) => {
            match db {
                Some(db) => db,
                None => {
                    // Shutdown requested while waiting for the database. The
                    // degraded server only serves one-shot 503s — abort it
                    // rather than drain, so a slow client can't stall exit.
                    degraded_handle.abort();
                    return Ok(());
                }
            }
        }
        degraded = &mut degraded_handle => {
            if *shutdown_tx.borrow() {
                return Ok(());
            }
            return match degraded {
                Ok(Ok(())) => Err(anyhow!("degraded HTTP server stopped before database became ready")),
                Ok(Err(err)) => Err(err.context("degraded HTTP server failed")),
                Err(err) => Err(anyhow!("degraded HTTP server task failed: {err}")),
            };
        }
    };

    // Flip the degraded server into graceful shutdown, but do NOT await the
    // drain: one slow in-flight request must not delay the full server, and
    // the shared socket means there is no port gap to cover. The drain
    // finishes (and logs) in the background.
    db_ready_tx.send(true).ok();
    tokio::spawn(async move {
        match degraded_handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => warn!(err = %err, "degraded HTTP server exited with error"),
            Err(err) => warn!(err = %err, "degraded HTTP server task failed"),
        }
    });
    info!(addr = %config.bind_addr(), "database ready; starting full HTTP server");

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

    // Per-client-IP flood brake for the creation endpoints. The per-DID limiter
    // above is bypassed by a DID farm (one throwaway did:key per repo), which is
    // exactly how the recurring spam-repo floods get past both it and the
    // iCaptcha gate. Keyed on the resolved client IP so a single-source flood is
    // capped regardless of how many identities it mints. Sized well above any
    // legitimate per-IP creation rate; GITLAWB_CREATE_RATE_LIMIT overrides, 0
    // disables. Bounded key set — the key is a client-influenced IP.
    let create_limit = std::env::var("GITLAWB_CREATE_RATE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(120);
    let create_ip_rate_limiter = rate_limit::RateLimiter::new_bounded(
        create_limit,
        std::time::Duration::from_secs(3600),
        200_000,
    );
    if create_limit == 0 {
        tracing::warn!("GITLAWB_CREATE_RATE_LIMIT=0 — per-IP creation rate limiting disabled");
    }

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

    // Peer-sync flood brakes, keyed on the resolved client IP (per-DID is useless
    // here — a did:key farm self-registers). Two buckets so an unsigned notify
    // flood can't drain the signed trigger caller's quota (#82). Bounded key sets
    // (the key is a client-influenced IP); 0 disables each.
    let sync_trigger_rate_limiter = rate_limit::RateLimiter::new_bounded(
        config.sync_trigger_rate_limit,
        std::time::Duration::from_secs(3600),
        200_000,
    );
    let peer_write_rate_limiter = rate_limit::RateLimiter::new_bounded(
        config.peer_write_rate_limit,
        std::time::Duration::from_secs(3600),
        200_000,
    );
    if config.sync_trigger_rate_limit == 0 {
        tracing::warn!(
            "GITLAWB_SYNC_TRIGGER_RATE_LIMIT=0 — /sync/trigger IP rate limiting disabled"
        );
    }
    if config.peer_write_rate_limit == 0 {
        tracing::warn!("GITLAWB_PEER_WRITE_RATE_LIMIT=0 — peer-write IP rate limiting disabled");
    }

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
        create_ip_rate_limiter,
        push_rate_limiter,
        push_limiter_trust,
        sync_trigger_rate_limiter,
        peer_write_rate_limiter,
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

    // Periodic cleanup of expired rate limit entries + consumed-proof ledger
    {
        let rl = state.rate_limiter.clone();
        let create_ip_rl = state.create_ip_rate_limiter.clone();
        let push_rl = state.push_rate_limiter.clone();
        let sync_trigger_rl = state.sync_trigger_rate_limiter.clone();
        let peer_write_rl = state.peer_write_rate_limiter.clone();
        let db = state.db.clone();
        let mut shutdown_rx = state.subscribe_shutdown();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(300)) => {
                        rl.cleanup().await;
                        create_ip_rl.cleanup().await;
                        push_rl.cleanup().await;
                        sync_trigger_rl.cleanup().await;
                        peer_write_rl.cleanup().await;
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
    // Re-register the socket bound at startup — same fd, so there was never a
    // moment with the port closed between the degraded and full servers.
    let listener = TcpListener::from_std(full_std_listener)
        .context("failed to re-register HTTP listener with the runtime")?;

    info!("✓ node started — did:{}", node_did);
    info!("  repos dir: {}", config.repos_dir.display());
    info!(
        "  database:  PostgreSQL ({})",
        &config.database_url.split('@').next_back().unwrap_or("?")
    );

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

    // axum's `with_graceful_shutdown` begins draining in-flight requests once
    // the shutdown watch flips. That drain is otherwise unbounded, so we bound
    // it by `grace`: the closure fires `armed_tx` the instant it observes the
    // signal, and `drive_serve_with_grace` abandons the drain if it has not
    // finished `grace` after that moment. The clock starts at the signal, not at
    // server start, so total uptime is never bounded.
    let shutdown_signal_for_axum = state.subscribe_shutdown();
    let grace = std::time::Duration::from_secs(config.shutdown_grace_secs);
    info!(grace_secs = config.shutdown_grace_secs, "axum server ready");

    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();

    // `into_make_service_with_connect_info` exposes the socket peer address as
    // `ConnectInfo<SocketAddr>` so the push limiter can key on the real client
    // when no trusted proxy header applies (see `rate_limit::client_key`).
    let serve = axum::serve(
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
        // Start the grace clock at the signal, right before axum drains.
        let _ = armed_tx.send(());
    });

    // Race the drain against the grace deadline (see `drive_serve_with_grace`):
    // the clock starts when the closure above arms `armed_rx`, i.e. at the
    // signal, and the drain is abandoned if it outlasts `grace`.
    let (serve_result, grace_expired) = drive_serve_with_grace(serve, armed_rx, grace).await;

    if grace_expired {
        warn!(
            grace_secs = config.shutdown_grace_secs,
            "shutdown grace expired; abandoning in-flight requests"
        );
    }

    // Server has stopped accepting new connections and drained in-flight
    // requests (or the grace deadline fired). Tear the rest of the system down.
    info!("HTTP server stopped, beginning process shutdown");
    if let Some(h) = metrics_handle {
        h.abort();
    }
    serve_result?;
    info!("clean exit");
    Ok(())
}

/// Drive the HTTP `serve` future to completion, bounding the post-signal drain
/// by `grace`. `armed` resolves the instant the shutdown signal fires (the serve
/// future's graceful-shutdown closure sends on it), so the grace clock starts at
/// the signal, not at server start — total uptime is never bounded. Returns the
/// serve result plus whether the deadline fired (which abandons in-flight
/// requests so teardown can proceed).
async fn drive_serve_with_grace<F>(
    serve: F,
    armed: tokio::sync::oneshot::Receiver<()>,
    grace: std::time::Duration,
) -> (std::io::Result<()>, bool)
where
    F: std::future::IntoFuture<Output = std::io::Result<()>>,
{
    let serve = serve.into_future();
    tokio::select! {
        result = serve => (result, false),
        _ = async {
            // Park until the signal arms the clock, then bound the drain.
            let _ = armed.await;
            tokio::time::sleep(grace).await;
        } => (Ok(()), true),
    }
}

fn spawn_shutdown_signal(tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal as unix_signal, SignalKind};
            let mut sigterm =
                unix_signal(SignalKind::terminate()).expect("install SIGTERM handler");
            let mut sigint = unix_signal(SignalKind::interrupt()).expect("install SIGINT handler");
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

async fn connect_db_with_retry(
    config: &Config,
    db_startup: Arc<DbStartupStatus>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Option<Arc<Db>> {
    let initial_retry_secs = config.db_retry_initial_secs;
    let max_retry_secs = config.db_retry_max_secs.max(initial_retry_secs);
    let acquire_timeout = std::time::Duration::from_secs(config.db_acquire_timeout_secs);
    let attempt_timeout = std::time::Duration::from_secs(config.db_connect_timeout_secs);
    let mut attempts = 0_u64;

    loop {
        if *shutdown_rx.borrow() {
            return None;
        }

        attempts = attempts.saturating_add(1);
        db_startup.attempts.store(attempts, Ordering::Relaxed);

        // Bound the whole attempt, not just the pool connect: migrations
        // block on a cross-instance advisory lock, and an unbounded wait
        // there would wedge this loop — no retries, no logs, no recovery.
        // Timing out and retrying is safe; migrations are idempotent.
        let attempt = match tokio::time::timeout(
            attempt_timeout,
            Db::connect(
                &config.database_url,
                config.db_max_connections,
                acquire_timeout,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "connect + migrate attempt exceeded {}s (GITLAWB_DB_CONNECT_TIMEOUT_SECS); \
                 is another instance holding the migration lock?",
                attempt_timeout.as_secs()
            )),
        };

        match attempt {
            Ok(db) => {
                info!(attempts, "database connection established");
                return Some(Arc::new(db));
            }
            Err(err) => {
                // A bad DATABASE_URL or rejected credentials won't heal on
                // their own. Still retry (exiting would crash-loop and hammer
                // the provider — and take liveness down with it), but log at
                // error level and skip straight to the maximum backoff; the
                // /ready health check is what surfaces this to deploys.
                let permanent = is_likely_permanent_db_error(&err);
                let retry_secs = if permanent {
                    max_retry_secs
                } else {
                    database_retry_delay_secs(initial_retry_secs, max_retry_secs, attempts)
                };
                db_startup
                    .next_retry_secs
                    .store(retry_secs, Ordering::Relaxed);
                if permanent {
                    tracing::error!(
                        attempts,
                        retry_secs,
                        err = %err,
                        "database rejected our configuration (bad DATABASE_URL or credentials?) — retrying, but operator action is likely required"
                    );
                } else {
                    warn!(
                        attempts,
                        retry_secs,
                        err = %err,
                        "database unavailable during startup; retrying"
                    );
                }

                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(retry_secs)) => {}
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return None;
                        }
                    }
                }
            }
        }
    }
}

/// Errors that indicate misconfiguration rather than a transient outage: a
/// malformed DATABASE_URL, or a server that answered and rejected us —
/// Postgres error class 28xxx (invalid authorization) or 3D000 (database
/// does not exist). Best-effort: an error that anyhow can't downcast back to
/// sqlx just counts as transient.
fn is_likely_permanent_db_error(err: &anyhow::Error) -> bool {
    match err.downcast_ref::<sqlx::Error>() {
        Some(sqlx::Error::Configuration(_)) => true,
        Some(sqlx::Error::Database(db)) => db
            .code()
            .map(|c| c.starts_with("28") || c.starts_with("3D"))
            .unwrap_or(false),
        _ => false,
    }
}

fn database_retry_delay_secs(initial_secs: u64, max_secs: u64, attempts: u64) -> u64 {
    // The exponent bound only keeps the u32 cast safe — max_secs is the real
    // (operator-configurable) cap, and saturating math handles overflow.
    let exponent = attempts.saturating_sub(1).min(63) as u32;
    initial_secs
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(max_secs)
}

async fn run_degraded_server(
    listener: TcpListener,
    node_did: String,
    db_startup: Arc<DbStartupStatus>,
    mut db_ready_rx: watch::Receiver<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let addr = listener.local_addr().ok();
    let router = build_degraded_router(node_did, db_startup);
    info!(?addr, "degraded HTTP server ready");

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            // wait_for resolves on predicate-true or sender-drop; either way
            // this phase is over.
            tokio::select! {
                _ = db_ready_rx.wait_for(|ready| *ready) => {}
                _ = shutdown_rx.wait_for(|stop| *stop) => {}
            }
        })
        .await?;

    Ok(())
}

fn build_degraded_router(node_did: String, db_startup: Arc<DbStartupStatus>) -> Router {
    let state = DegradedState {
        node_did,
        db_startup,
    };
    // Everything answers 503 with the same body — including /health and
    // /ready, so peer pings (which treat any 2xx /health as alive) and
    // uptime monitors correctly see a node that cannot serve traffic.
    // `/` additionally carries the node identity for probing peers.
    Router::new()
        .route("/", get(degraded_node_info))
        .fallback(degraded_unavailable)
        .with_state(state)
}

/// One source of truth for the degraded 503 body, sharing the error
/// vocabulary with error.rs so clients see the same code/message for
/// "database unavailable" regardless of which phase produced it.
fn degraded_body(db_startup: &DbStartupStatus) -> serde_json::Value {
    serde_json::json!({
        "status": "degraded",
        "database": "initializing",
        "error": error::DB_UNAVAILABLE_CODE,
        "message": error::DB_UNAVAILABLE_MESSAGE,
        "db_attempts": db_startup.attempts.load(Ordering::Relaxed),
        "db_next_retry_secs": db_startup.next_retry_secs.load(Ordering::Relaxed),
    })
}

async fn degraded_node_info(State(state): State<DegradedState>) -> impl IntoResponse {
    let mut body = degraded_body(&state.db_startup);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("name".into(), "gitlawb-node".into());
        obj.insert("version".into(), env!("CARGO_PKG_VERSION").into());
        obj.insert("did".into(), state.node_did.clone().into());
    }
    (StatusCode::SERVICE_UNAVAILABLE, Json(body))
}

async fn degraded_unavailable(State(state): State<DegradedState>) -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(degraded_body(&state.db_startup)),
    )
}

/// Spawn a small axum router that exposes only `GET /metrics` on its own
/// listener. Returns the JoinHandle so `main()` can abort it on shutdown.
/// This is deliberately separate from the main router so the metrics port
/// can be firewalled differently from the API port — bind to localhost
/// or a private interface only.
async fn spawn_metrics_server(
    addr: &str,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>> {
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

/// Persist a just-created identity key, removing the file if the write failed
/// (#194, F1). `create_new` makes the inode appear before the PEM is flushed, so a
/// failed `write_all` (ENOSPC/EIO/quota) leaves an empty or partial PEM behind;
/// every later start would then take the `exists()` branch and re-parse that
/// corrupt file forever, exiting `invalid PEM key` instead of regenerating. Remove
/// it on failure so the next start starts clean.
fn write_key_or_cleanup(path: &std::path::Path, write_result: std::io::Result<()>) -> Result<()> {
    write_result.map_err(|e| {
        // Best-effort: if removal also fails there is nothing more to do, and the
        // original write error is the one worth surfacing.
        let _ = std::fs::remove_file(path);
        anyhow::Error::new(e).context(format!("failed to write key to {}", path.display()))
    })
}

/// Verify an identity key file is not world/group-readable (#194, F2). A `chmod`
/// that failed or silently no-op'd (read-only mount, ACL mismatch) must not leave
/// a readable private key in use, so this is checked after any tightening attempt
/// and fails closed rather than logging a normal "loaded identity" path.
#[cfg(unix)]
fn ensure_key_mode_0600(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("stat identity key {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        anyhow::bail!(
            "identity key {} has mode {mode:o}, expected 0600 — refusing to use a \
             world/group-readable private key",
            path.display()
        );
    }
    Ok(())
}

/// Secure a just-created, still-EMPTY key file before any PEM byte is written
/// (#194, U2): tighten to 0600, then verify with `ensure_key_mode_0600`. The
/// pair matters: `create_new`'s requested 0600 is narrowed by the process
/// umask (0277 lands 0400), so the tighten repairs that first; the verify
/// alone would falsely fail closed. On a mode-ignoring mount (vfat: chmod
/// silently no-ops returning Ok) the tighten changes nothing and the verify
/// fails CLOSED, so the private key never hits a group/other-readable file.
/// On failure the empty file is removed so a retry is not wedged on
/// `AlreadyExists`; removal is safe precisely because nothing has been
/// written yet (the split-phase rule protects only files holding PEM bytes).
/// `verify_fault` is the fault-injection hook (`Ok` in production).
#[cfg(unix)]
fn tighten_and_verify_created(
    path: &std::path::Path,
    verify_fault: fn() -> std::io::Result<()>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(anyhow::Error::new)
        .and_then(|()| verify_fault().map_err(anyhow::Error::new))
        .and_then(|()| ensure_key_mode_0600(path))
        .map_err(|e| {
            let _ = std::fs::remove_file(path);
            e.context(format!(
                "could not secure just-created identity key {} to 0600",
                path.display()
            ))
        })
}

/// Fsync the parent directory of `final_path` so the namespace change (a link
/// or a create into it) is durable before success is reported (#194). Unix-only:
/// opening a directory as a file is not portable. An empty or missing parent
/// resolves to `"."`.
#[cfg(unix)]
fn fsync_parent_dir(final_path: &std::path::Path) -> anyhow::Result<()> {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::File::open(dir)
        .with_context(|| format!("open key directory {} to fsync", dir.display()))?
        .sync_all()
        .with_context(|| format!("fsync key directory {}", dir.display()))?;
    Ok(())
}

/// Outcome of an atomic key publish.
enum KeyPublish {
    /// We created the key file; it now holds the complete PEM.
    Won,
    /// Another concurrent start already created it; ours was discarded.
    Lost,
}

/// Wall-clock budget for reading a key another start may still be publishing.
/// On the atomic hard-link path (`publish_key_atomically`) a *present* key file
/// is always complete, so a read there succeeds on the first try. On the
/// hard-link fallback (`publish_key_fallback`) the final NAME becomes visible
/// while the PEM is still being written, so a losing/concurrent reader can
/// observe an empty/partial final; this deadline is the window it rides out
/// until the winner's write completes. Cross-host cache lag is a secondary
/// reason a present key may not read on the first attempt. It is a wall-clock
/// budget, NOT a fixed retry count, so a slow/stalled filesystem cannot starve a
/// losing start after an arbitrarily short (~100ms) window (#194).
const KEY_RACE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// Minimum age (metadata mtime) before a `.recovering.` claim is sweepable
/// by a healthy boot (#194, G1). LIVENESS CONTRACT: a live recovery
/// HEARTBEATS every claim it holds (`spawn_claim_heartbeat`), refreshing
/// each mtime every quarter of this floor until release, so a live round's
/// claims NEVER age out, however long the round runs on a slow shared
/// volume. An AGED claim therefore means its recoverer stopped heartbeating
/// (crashed or killed): orphaned residue, claimable and sweepable (the
/// demotion waiter, by contrast, keys on claim-file ABSENCE, not age; see
/// `wait_for_recovery_claims`). A YOUNG
/// claim means live or recently dead, an ambiguity bounded by one floor
/// (the price of never stealing a live round). The 2x margin over
/// `KEY_RACE_DEADLINE` absorbs clock skew between writers on network
/// mounts. The gate matters because live claims are load-bearing: a
/// demoted publisher's `wait_for_recovery_claims` waits on them, and a third
/// start sweeping a live claim would cancel that wait mid-recovery, letting
/// the publisher re-load the pre-quarantine key while the recoverer
/// quarantines and republishes: two-sided divergence. An unreadable mtime is
/// treated as YOUNG (skip removal; fail safe).
///
/// The same floor also gates which `.recovering.` claims are CLAIMABLE
/// (`list_recovery_claimables`), so a claim-crash state (a content-bad
/// final whose only claimable is a claim) becomes recoverable only after
/// this floor passes. That delay is bounded (~2x the deadline) and is the
/// price of never stealing a live recovery round.
const CLAIM_SWEEP_MIN_AGE: std::time::Duration = KEY_RACE_DEADLINE.saturating_mul(2);

/// Retention window for forensic residue beside a healthy final: both
/// `.{stem}.superseded.` files and plain `.{stem}.quarantined.` files. A
/// superseded quarantine is kept for operator inspection after a lost
/// round, and a plain quarantine lingers as crash forensics (unparseable
/// bytes) or as aged history (a parseable key already past the adoption
/// floor, never resurrected); with no expiry either class accumulates
/// forever (every lost round or crash adds one file beside the final). 24
/// hours is a generous post-mortem window while keeping growth bounded:
/// once a file in either class is older than this, the healthy-boot sweep
/// removes it (behind the same durability gate as every other removal in
/// `sweep_stale_markers`). The window is orders of magnitude above the
/// adoption floor (`CLAIM_SWEEP_MIN_AGE`), so no quarantine this sweep can
/// touch was still adoptable. An unreadable mtime reads as young (kept;
/// fail safe).
const SUPERSEDED_RETENTION: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// How long the crash signature (a content-bad final beside a claimable)
/// must persist across consecutive observations before boot classifies a
/// crash (#194, G3). A single ~2ms poll sits well inside a LIVE fallback
/// publisher's mid-write window once chmod/stat/scheduling latency on shared
/// volumes is real, so a shorter grace lets a concurrent starter classify a
/// live publish as a crash and churn quarantines and identities. 250ms is
/// far above that latency yet far under the <2s recovery budget the tests
/// pin (250ms of persistence plus claim, quarantine, and regenerate stays
/// well under 2s). Any successful load or signature-free observation resets
/// the clock.
///
/// Honest trade-off: on mounts where a live first publish's pre-write window
/// (the fallback's `create_new` through `write_all`) can itself exceed this
/// floor, a concurrent starter can still classify that live publish as
/// crashed. Every such path converges (the demotion commit check, the
/// post-claim re-parse, the no-clobber restore, the quarantine adoption), so
/// the cost is churn, not divergence; raising the floor trades that
/// probability against recovery latency after a real crash.
const CRASH_SIGNATURE_MIN_PERSIST: std::time::Duration = std::time::Duration::from_millis(250);

/// Bounded number of temp-file names a publish will try before giving up.
/// Attempt 0 is the deterministic `.{stem}.tmp.{pid}.0`, so a stale temp left
/// by a crashed prior start with the same PID (a restarted container is
/// commonly PID 1 again) is skipped rather than wedging the restart (#194).
/// 64 names is far more than any plausible pile-up of stale temps plus live
/// concurrent publishers. Also bounds the fallback publish-marker names,
/// which follow the same stale-name discipline (#194, U1).
const KEY_TEMP_ATTEMPTS: u32 = 64;

/// A key-load failure caused by the file's CONTENT (an empty or unparseable
/// PEM) rather than IO or permissions (#194, U2). Used as the anyhow error's
/// root so the boot loop can classify a failure as crash-recoverable via
/// `is_key_content_error` WITHOUT changing the message text operators and
/// tests rely on ("invalid PEM key"). Every other load failure (stat,
/// tighten, mode verification, read IO) stays a plain anyhow error and is
/// never recovered from.
#[derive(Debug)]
struct KeyContentError(String);

impl std::fmt::Display for KeyContentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyContentError {}

/// True when `err` is a content-class load failure (see `KeyContentError`).
fn is_key_content_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<KeyContentError>().is_some()
}

/// Load an already-provisioned identity key. On Unix, defensively tighten looser
/// permissions to 0600 (do NOT reject a loose key — that would break existing
/// deployments; just narrow them), then verify the mode is actually 0600.
fn load_existing_key(path: &std::path::Path) -> Result<Keypair> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o777 != 0o600 {
                // Do NOT silently ignore a failed tighten (#194, F2): surface it
                // so a key we cannot secure is not read and used exposed.
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| {
                        format!("could not tighten identity key {} to 0600", path.display())
                    })?;
            }
        }
        // Verify the key is actually 0600 before using it — a chmod that
        // succeeded-but-no-op'd (some mounts) still leaves it exposed.
        ensure_key_mode_0600(path)?;
    }
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read key from {}", path.display()))?;
    // Content-class failure (#194, U2): an empty file reads Ok("") and is
    // rejected here too, so this one arm classifies both the zero-length and
    // the unparseable case. The message text is unchanged.
    let kp = Keypair::from_pem(&pem)
        .map_err(|e| anyhow::Error::new(KeyContentError(format!("invalid PEM key: {e}"))))?;
    info!(path = %path.display(), "loaded existing identity");
    Ok(kp)
}

/// `".{stem}.publishing."`: the single source of truth for the publish
/// marker name class (#194, U1). Every production site that constructs a
/// marker name or prefix goes through here; the test module keeps raw
/// literals on purpose, as a guard against prefix drift.
fn publishing_prefix(stem: &str) -> String {
    format!(".{stem}.publishing.")
}

/// `".{stem}.recovering."`: the single source of truth for the recovery
/// claim name class (#194, F3). Same policy as `publishing_prefix`.
fn recovering_prefix(stem: &str) -> String {
    format!(".{stem}.recovering.")
}

/// `".{stem}.quarantined."`: the single source of truth for the quarantine
/// name class. Same policy as `publishing_prefix`. Class distinction (N2/N4):
/// a `.quarantined.` file is possibly-current residue, the crashed round's
/// own key, adoptable while young; a `.superseded.` file
/// (`superseded_prefix`) is provably outcompeted and forensics only.
fn quarantined_prefix(stem: &str) -> String {
    format!(".{stem}.quarantined.")
}

/// `".{stem}.superseded."`: the single source of truth for the SUPERSEDED
/// quarantine class (N2/N4). A quarantine moves into this class when its key
/// provably LOST its round: a restore republish returned Lost (a concurrent
/// winner durably published meanwhile), or a sibling quarantine won the
/// adoption. Superseded files are forensics only: never adoptable
/// (`find_adoptable_quarantine` scans `.quarantined.` alone), never part of
/// the boot crash signature, and swept only once older than
/// `SUPERSEDED_RETENTION` (bounded forensics); every consumer matches its
/// own prefix class, so this class is inert by construction.
fn superseded_prefix(stem: &str) -> String {
    format!(".{stem}.superseded.")
}

/// Rename `quarantine` into the superseded class
/// (`.{stem}.superseded.{pid}.{n}`), probing bounded fresh names per the
/// KEY_TEMP_ATTEMPTS discipline (skip an existing name, never clobber it).
/// A NotFound source means the quarantine resolved concurrently and there is
/// nothing left to reclassify. Best-effort: if every attempt fails the file
/// stays a plain quarantine, still adoptable while young, and a warn names
/// that hazard.
fn supersede_quarantine(final_path: &std::path::Path, quarantine: &std::path::Path) {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let prefix = superseded_prefix(stem);
    for n in 0..KEY_TEMP_ATTEMPTS {
        let dest = dir.join(format!("{prefix}{}.{n}", std::process::id()));
        if dest.exists() {
            continue;
        }
        match std::fs::rename(quarantine, &dest) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => continue,
        }
    }
    warn!(
        quarantine = %quarantine.display(),
        "could not rename an outcompeted quarantine into the superseded class; \
         it remains adoptable while young"
    );
}

/// Rename every YOUNG parseable `.{stem}.quarantined.*` sibling other than
/// `adopted` into the superseded class (N4). The adoption decided this round
/// in favor of the adopted key, so any other young parseable quarantine is
/// provably outcompeted; left adoptable, it would resurrect a different
/// historical DID the next time the final goes missing. Unparseable entries
/// stay plain quarantines (crash forensics, never adoptable anyway), and so
/// do AGED parseable ones (already outside the adoption bound; unreadable
/// mtime reads as aged, matching `find_adoptable_quarantine`). Best-effort
/// throughout.
fn supersede_sibling_quarantines(final_path: &std::path::Path, adopted: &std::path::Path) {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let prefix = quarantined_prefix(stem);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.filter_map(|e| e.ok()) {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(&prefix))
        {
            continue;
        }
        let path = entry.path();
        if path == *adopted {
            continue;
        }
        let Ok(mtime) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        let age = now.duration_since(mtime).unwrap_or_default();
        if age >= CLAIM_SWEEP_MIN_AGE {
            continue;
        }
        let parseable =
            std::fs::read_to_string(&path).is_ok_and(|pem| Keypair::from_pem(&pem).is_ok());
        if parseable {
            supersede_quarantine(final_path, &path);
        }
    }
}

/// The newest `.{stem}.quarantined.*` entry beside `final_path` YOUNGER than
/// `CLAIM_SWEEP_MIN_AGE` whose bytes parse as a keypair, with those bytes: a
/// COMPLETED key the CURRENT round's crashed or failed recovery left
/// stranded, adoptable by the generate arm of `load_or_create_keypair_with`
/// (F1). The age bound is the point: a stranded current round's quarantine
/// is seconds old, so continuity across a just-crashed restore is preserved,
/// while a HISTORICAL parseable quarantine (forensics kept after a Lost
/// restore, or any prior round) is never resurrected; without the bound, a
/// final that goes missing later silently revives an old identity, and the
/// operator procedure "delete identity.pem for a fresh DID" is defeated by
/// whatever quarantine still sits beside it. Once the floor passes, that
/// procedure mints a genuinely fresh identity. An unreadable mtime reads as
/// too old (skip; fail safe against resurrection). Candidates are tried
/// newest mtime first (the most recent quarantine is the most recently live
/// identity); unparseable entries are skipped, staying on disk as forensics.
/// Directory-read and non-UTF-8 policy match `list_publish_markers`.
fn find_adoptable_quarantine(
    final_path: &std::path::Path,
) -> Option<(std::path::PathBuf, String, Keypair)> {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let prefix = quarantined_prefix(stem);
    let entries = std::fs::read_dir(dir).ok()?;
    let now = std::time::SystemTime::now();
    let mut quarantines: Vec<(std::path::PathBuf, std::time::SystemTime)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .filter_map(|e| {
            // The adoption age bound (see the doc comment): an unreadable
            // mtime is skipped outright, and a future mtime (clock skew)
            // reads as age zero, matching the sweep's young side.
            let mtime = e.metadata().and_then(|m| m.modified()).ok()?;
            let age = now.duration_since(mtime).unwrap_or_default();
            (age < CLAIM_SWEEP_MIN_AGE).then_some((e.path(), mtime))
        })
        .collect();
    // Newest first.
    quarantines.sort_by_key(|q| std::cmp::Reverse(q.1));
    for (path, _) in quarantines {
        let Ok(pem) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(kp) = Keypair::from_pem(&pem) {
            return Some((path, pem, kp));
        }
    }
    None
}

/// The publish markers (`.{stem}.publishing.*`) beside `final_path`, sorted:
/// U1's crash signature for a fallback publish interrupted mid-window (#194,
/// U2). An unreadable directory reads as no markers, so recovery stays off
/// and the load error surfaces unchanged (the loud-fail default); entries
/// with non-UTF-8 names cannot be our markers and are skipped.
fn list_publish_markers(final_path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let prefix = publishing_prefix(stem);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut markers: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .map(|e| e.path())
        .collect();
    markers.sort();
    markers
}

/// The publish markers AND recovery claims (`.{stem}.publishing.*` plus
/// `.{stem}.recovering.*`) beside `final_path`, sorted: the full claimable
/// set for crash recovery (#194, F3). Claims count because a recoverer's
/// claim IS a renamed marker: a recoverer that crashes between its claim
/// rename and the quarantine leaves a content-bad final with a claim and
/// ZERO markers, and a signature keyed on markers alone would leave that
/// state unrecoverable forever. Directory-read and non-UTF-8 policy match
/// `list_publish_markers`.
///
/// A `.recovering.` claim counts only once older than `CLAIM_SWEEP_MIN_AGE`
/// (same age gate and rationale as the G1 sweep): a fresh claim may gate a
/// LIVE recovery round, and a second starter that claims it mid-round steals
/// the round from the recoverer that owns it. Because both the crash
/// signature (`boot_load_key`) and the claim loop
/// (`recover_crashed_publish`) read this one list, the gate holds at a
/// single point. An unreadable claim mtime reads as young, so the claim is
/// skipped (fail safe, matching the sweep). `.publishing.` markers stay
/// unconditionally claimable: claiming a live publisher's marker only fails
/// its commit check, a safe demotion.
fn list_recovery_claimables(final_path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let publishing = publishing_prefix(stem);
    let recovering = recovering_prefix(stem);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut claimables: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let Some(name) = name.to_str() else {
                return false;
            };
            if name.starts_with(&publishing) {
                return true;
            }
            if !name.starts_with(&recovering) {
                return false;
            }
            // F2 age gate (see the doc comment): only an ORPHANED claim is
            // claimable; a fresh one may gate a live round.
            e.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|mtime| std::time::SystemTime::now().duration_since(mtime).ok())
                .is_some_and(|age| age >= CLAIM_SWEEP_MIN_AGE)
        })
        .map(|e| e.path())
        .collect();
    claimables.sort();
    claimables
}

/// Load a key another concurrent start may still be publishing, polling until it
/// parses or `KEY_RACE_DEADLINE` elapses. An already-provisioned key parses on
/// the first attempt with no sleep.
fn load_racing_key(path: &std::path::Path) -> Result<Keypair> {
    match boot_load_key(path, false, || Ok(())) {
        BootLoad::Loaded(kp) => Ok(*kp),
        BootLoad::CrashSignature(e) | BootLoad::Failed(e) => Err(e),
    }
}

/// Outcome of `boot_load_key` (#194, U2). The tri-state exists so the boot
/// loop can tell "content failure WITH the crash signature observed" (a
/// recovery candidate) from every other failure; folding both into one error
/// would let a concurrent recoverer's marker sweep turn a recoverable boot
/// into a loud failure.
enum BootLoad {
    /// Boxed to keep the variants' sizes comparable (clippy:
    /// large_enum_variant); the enum lives only across a boot-time match.
    Loaded(Box<Keypair>),
    /// Content-class failure observed while a `.publishing.` marker or a
    /// `.recovering.` claim was present, continuously for
    /// `CRASH_SIGNATURE_MIN_PERSIST`; returned without riding the rest of
    /// the deadline.
    CrashSignature(anyhow::Error),
    /// Any other failure, after the full deadline.
    Failed(anyhow::Error),
}

/// `load_racing_key` for the boot loop (#194, U2). With `crash_exit` set, a
/// content-class failure (`KeyContentError`) observed while a `.publishing.`
/// marker or a `.recovering.` claim is present, continuously for
/// `CRASH_SIGNATURE_MIN_PERSIST` of consecutive observations, returns
/// `CrashSignature` instead of riding the deadline: claimable plus
/// unreadable content is the crash signature recovery exists for, and the
/// caller's atomic claim renames arbitrate the (rare) race against a live
/// fallback publisher still inside its window. Claims count toward the
/// signature for F3 (see `list_recovery_claimables`). The persistence window
/// (#194, G3) exists so a reader that catches a live publisher's mid-write
/// window is not classified as a crash: chmod/stat/scheduling latency on
/// shared volumes routinely stretches that window past any small fixed poll
/// count, while a real crash state persists across every poll, so the
/// signature clock starts at its first observation and any successful load
/// or signature-free observation resets it. Every other failure keeps the
/// full wall-clock deadline. `load_fault` is the injection hook (a no-op
/// `Ok` in production); an injected `Err` is taken as that attempt's result
/// and is NOT content-class.
fn boot_load_key(
    path: &std::path::Path,
    crash_exit: bool,
    load_fault: fn() -> std::io::Result<()>,
) -> BootLoad {
    let deadline = std::time::Instant::now() + KEY_RACE_DEADLINE;
    let mut last_err;
    let mut signature_since: Option<std::time::Instant> = None;
    loop {
        match load_fault()
            .map_err(anyhow::Error::new)
            .and_then(|()| load_existing_key(path))
        {
            Ok(kp) => return BootLoad::Loaded(Box::new(kp)),
            Err(e) => last_err = e,
        }
        let signature = crash_exit
            && is_key_content_error(&last_err)
            && !list_recovery_claimables(path).is_empty();
        if signature {
            let since = *signature_since.get_or_insert_with(std::time::Instant::now);
            if since.elapsed() >= CRASH_SIGNATURE_MIN_PERSIST {
                return BootLoad::CrashSignature(last_err);
            }
        } else {
            signature_since = None;
        }
        if std::time::Instant::now() >= deadline {
            return BootLoad::Failed(last_err);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Wait until NO `.{stem}.recovering.*` claim FILE remains beside
/// `final_path`, polling on `load_racing_key`'s cadence (~2ms), bounded by
/// `CLAIM_SWEEP_MIN_AGE` plus a one-second margin (#194, U3; F3; N3). Why
/// the wait exists: a fallback winner that failed its commit check was
/// demoted by a recovering peer, and that peer is mid-round — it
/// quarantines the (old) final, republishes a fresh key, and only then
/// clears its claim. A demoted winner that re-loaded before the claim
/// cleared could observe the pre-quarantine key and diverge from what the
/// peer ends up publishing; waiting for claim clearance makes the follow-up
/// load observe the settled state.
///
/// The waiter keys purely on ABSENCE, never on age. Age stays the liveness
/// rule for the SWEEP (`sweep_stale_markers`) and CLAIMABILITY
/// (`list_recovery_claimables`), but an aged claim is not proof its
/// recoverer is gone: with the heartbeat spawn failed AND both mtime stamp
/// rungs failing on a hostile volume, a LIVE recoverer's claim can sit
/// mtime-frozen while the round is still settling disk, and a waiter that
/// read it as orphaned residue would let the demoted publisher load a
/// pre-settlement key while that recoverer settles disk differently:
/// two-sided divergence under compounded failure. A file that is GONE is
/// unambiguous: the round settled (release) or a sweep decided the claim
/// was orphaned; either way the follow-up load observes a settled state.
///
/// So: `Ok` only when the claim files are gone. Bound expiry with ANY claim
/// file still present (young or aged) returns an `Err` naming the file(s):
/// the round cannot be proven settled, and the caller must fail closed
/// instead of loading. Consequence: an aged ORPHAN claim (its recoverer
/// long dead) now fails a concurrently-demoted publisher loudly until a
/// healthy boot's sweep or the delayed re-sweep
/// (`spawn_delayed_claim_resweep`) clears it — a bounded,
/// operator-visible degradation, priced against the silent divergence the
/// age rule risked. An unreadable directory reads as no claims, matching
/// `list_publish_markers`' policy.
fn wait_for_recovery_claims(final_path: &std::path::Path) -> Result<()> {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let prefix = recovering_prefix(stem);
    let bound = CLAIM_SWEEP_MIN_AGE + std::time::Duration::from_secs(1);
    let deadline = std::time::Instant::now() + bound;
    loop {
        let present: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|n| n.starts_with(&prefix))
                    })
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        if present.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "recovery round did not settle within the {bound:?} wait bound: \
                 recovery claim(s) {present:?} still present beside {}",
                final_path.display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Best-effort sweep of stale `.{stem}.publishing.*` markers,
/// `.{stem}.recovering.*` claims, and expired `.{stem}.superseded.*` /
/// `.{stem}.quarantined.*` forensics beside a healthy final, run on both
/// healthy-boot arms of `load_or_create_keypair_with` (#194, U4). Without it
/// a marker orphaned by a crash between its durability fsync and the final's
/// `create_new`, or a claim left by a crashed recovery, outlives every
/// healthy boot and later misclassifies a real corruption of a good key as
/// an interrupted first write (quarantine-and-regenerate instead of the loud
/// error a corrupted good key deserves).
///
/// DURABILITY PRECONDITION (critical, the reason this is not a bare unlink
/// loop): a loadable final is not necessarily durable — a racing fallback
/// winner's `write_all` is visible via the page cache before its `sync_all`,
/// so sweeping on loadability alone could remove a marker ahead of the
/// content it vouches for and let a power loss recreate exactly the
/// marker-less partial final the bracket exists to prevent. The sweeper
/// therefore makes the content durable ITSELF before touching any marker:
/// open the final read-only, `sync_all` it, then `fsync_parent_dir` (Unix).
/// If either step fails the sweep is skipped entirely — every marker stays
/// in place, at most a warn. Only after both succeed is every matching entry
/// removed (each best-effort), followed by a best-effort dir fsync. On
/// non-Unix the dir-fsync halves are skipped like every other dir fsync here
/// (reasoned, not run: no non-Unix target is exercised by these tests).
///
/// Sweeping a FOREIGN marker is safe once durability holds: the swept
/// publisher's own disposal tolerates NotFound on every arm; a live
/// publisher still before its final `create_new` hits AlreadyExists and
/// routes to Lost regardless of its marker; and the content the marker
/// vouched for is durable by the sweeper's own hand. `sweep_sync` is the
/// `RecoverySeam` test hook, run before the final's `sync_all` with an `Err`
/// taken as that sync's result; production passes a no-op `Ok`.
///
/// SWEEP ASYMMETRY (#194, G1): `.publishing.` markers are removed
/// unconditionally, but `.recovering.` claims only once older than
/// `CLAIM_SWEEP_MIN_AGE`. Sweeping a LIVE publisher's marker is safe (it
/// only fails that publisher's commit check, forcing a safe
/// demotion-and-reload), while sweeping a LIVE recoverer's claim is not: a
/// demoted publisher's `wait_for_recovery_claims` waits on that claim until
/// the recovery resolves, and removing it early lets the publisher re-load
/// the pre-quarantine key while the recoverer quarantines and republishes:
/// two-sided divergence. An unreadable claim mtime reads as young, so the
/// claim is kept (fail safe; the next boot past the age floor sweeps it).
fn sweep_stale_markers(final_path: &std::path::Path, sweep_sync: fn() -> std::io::Result<()>) {
    let durable = std::fs::File::open(final_path)
        .and_then(|f| sweep_sync().and_then(|()| f.sync_all()))
        .map_err(anyhow::Error::new);
    #[cfg(unix)]
    let durable = durable.and_then(|()| fsync_parent_dir(final_path));
    if let Err(e) = durable {
        warn!(
            path = %final_path.display(),
            err = %e,
            "skipping stale publish-marker sweep: could not make the final key durable"
        );
        return;
    }
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let publishing = publishing_prefix(stem);
    let recovering = recovering_prefix(stem);
    let superseded = superseded_prefix(stem);
    let quarantined = quarantined_prefix(stem);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(&publishing) {
            let _ = std::fs::remove_file(entry.path());
        } else if name.starts_with(&recovering) {
            // G1 age gate: only an orphaned claim (older than
            // CLAIM_SWEEP_MIN_AGE) is sweepable; see the doc comment.
            let orphaned = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|mtime| std::time::SystemTime::now().duration_since(mtime).ok())
                .is_some_and(|age| age >= CLAIM_SWEEP_MIN_AGE);
            if orphaned {
                let _ = std::fs::remove_file(entry.path());
            }
        } else if name.starts_with(&superseded) || name.starts_with(&quarantined) {
            // Forensic residue expires after SUPERSEDED_RETENTION (the
            // operator's inspection window); without an expiry every lost
            // round's superseded file, and every crash's plain quarantine
            // (unparseable forensics, or parseable history already far past
            // the adoption floor), accumulates forever. Unreadable mtime
            // reads as young (kept; fail safe), matching the claim gate
            // above.
            let expired = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|mtime| std::time::SystemTime::now().duration_since(mtime).ok())
                .is_some_and(|age| age >= SUPERSEDED_RETENTION);
            if expired {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    #[cfg(unix)]
    {
        let _ = fsync_parent_dir(final_path);
    }
}

/// Fire-and-forget companion to the boot sweep's young-claim sparing (F2):
/// one delayed re-sweep of `key_path`, `CLAIM_SWEEP_MIN_AGE` plus a
/// two-second margin into uptime. The boot-time sweep must SPARE a young
/// `.recovering.` claim (it may gate a live round), but a spared orphan is
/// never re-examined in-process, and once it ages on disk a LATER content
/// failure of the good final would match the crash signature (content-bad
/// beside an aged claimable) and silently regenerate where marker-less
/// corruption must fail loudly. By the time this fires, any claim the boot
/// sweep spared has aged past the liveness floor, so `sweep_stale_markers`
/// clears it and aged residue cannot coexist with a long-healthy final. The
/// node never waits on this task; failures stay at warn (the sweep itself
/// warns internally when it skips).
fn spawn_delayed_claim_resweep(key_path: std::path::PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(CLAIM_SWEEP_MIN_AGE + std::time::Duration::from_secs(2)).await;
        let sweep_path = key_path.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || sweep_stale_markers(&sweep_path, || Ok(()))).await
        {
            warn!(
                path = %key_path.display(),
                err = %e,
                "delayed identity-claim re-sweep task failed"
            );
        }
    })
}

/// Compile-time fault-injection seam for `publish_key_atomically`, extending
/// the `before_link` closure precedent: every hook is a no-op `Ok` in
/// production (`PublishFaults::NONE`); tests swap in a hook returning `Err` to
/// force that step to fail deterministically. Plain `fn` pointers, not a
/// runtime/env knob: production code only ever passes `NONE`.
#[derive(Clone, Copy)]
struct PublishFaults {
    /// Runs before the `hard_link`; an `Err` is taken as the link result and
    /// the real link is never attempted.
    link: fn() -> std::io::Result<()>,
    /// Runs before the fallback's `create_new` open of the FINAL path; an `Err`
    /// is taken as the open result (a non-`AlreadyExists` open error), so the
    /// publish surfaces it chained with `link_err`.
    fallback_create: fn() -> std::io::Result<()>,
    /// Runs before the fallback's publish-marker `create_new` (each name
    /// attempt); an `Err` is taken as the create result (a non-`AlreadyExists`
    /// open error), so the publish surfaces it chained with `link_err` (#194,
    /// U1).
    marker_create: fn() -> std::io::Result<()>,
    /// Runs before the fsync of the marker's parent directory; an `Err` is
    /// taken as that fsync's result. This fsync is warn-and-continue, so an
    /// injected `Err` must NOT fail the publish (#194, U1).
    #[cfg(unix)]
    marker_fsync: fn() -> std::io::Result<()>,
    /// Runs before the fallback's `write_all`; an `Err` is taken as the write
    /// result.
    fallback_write: fn() -> std::io::Result<()>,
    /// Runs before the fallback's file `sync_all`; an `Err` is taken as the
    /// fsync result.
    fallback_fsync: fn() -> std::io::Result<()>,
    /// Runs between the tighten and the 0600 verification of the just-created
    /// TEMP file; an `Err` is taken as the verification result. Simulates a
    /// mode-ignoring mount (vfat: chmod no-ops returning Ok), which cannot be
    /// reproduced on ext4.
    #[cfg(unix)]
    temp_mode_verify: fn() -> std::io::Result<()>,
    /// Same, for the FINAL file created on the hard-link fallback path.
    #[cfg(unix)]
    fallback_mode_verify: fn() -> std::io::Result<()>,
}

impl PublishFaults {
    /// The production value: no fault injected at any step.
    const NONE: Self = Self {
        link: || Ok(()),
        fallback_create: || Ok(()),
        marker_create: || Ok(()),
        #[cfg(unix)]
        marker_fsync: || Ok(()),
        fallback_write: || Ok(()),
        fallback_fsync: || Ok(()),
        #[cfg(unix)]
        temp_mode_verify: || Ok(()),
        #[cfg(unix)]
        fallback_mode_verify: || Ok(()),
    };
}

/// Publish `pem` to `final_path` atomically: write the full bytes to a sibling
/// temp file, then `hard_link` the temp into place. `hard_link` is atomic and
/// fails if `final_path` already exists, which on the hard-link path gives
/// these guarantees at once:
///   (a) the final path only ever appears with COMPLETE content — a concurrent
///       reader never observes an empty/half-written key, unlike a
///       `create_new`+`write_all` that exposes an empty inode before the PEM is
///       flushed (#194);
///   (b) a lost race never clobbers the winner — exactly one publisher links;
///   (c) a crashed publisher leaves only the temp, never a partial final that
///       would wedge every later start on `invalid PEM key`;
///   (d) durability: the PEM bytes are fsynced before the name appears and the
///       namespace change is fsynced (on Unix) before success is reported, so a
///       power crash cannot leave a durable-but-truncated final key (#194).
///
/// If the link fails for any reason other than `AlreadyExists` (a filesystem
/// without hard-link support, or a transient link error), the publish falls
/// back to `create_new(0o600)` directly on the final path
/// (`publish_key_fallback`). The fallback keeps (b): `create_new` still admits
/// exactly one winner and a lost race loads the existing key. It weakens (a)
/// and (d): the final name is visible while the PEM is being written, a
/// window concurrent readers ride out via `load_racing_key`'s wall-clock
/// deadline; and the final name can become durable before the PEM bytes are
/// fsynced, so a power loss can additionally leave a durable empty/truncated
/// final. Guarantee (c) now holds on the fallback too, via the marker
/// protocol (#194, U2/U4): a crash inside the non-atomic window leaves
/// marker+final together, and the next boot claims the marker, quarantines
/// the partial final, and regenerates instead of wedging. On
/// dir-fsync-hostile mounts the marker dir fsync is warn-and-continue (see
/// `publish_key_fallback`), so there the recovery guarantee narrows to
/// non-power-loss (SIGKILL-class) crashes: a power loss can drop the
/// undurable marker name and leave the partial final to the loud
/// invalid-PEM error instead. Honest residual on
/// top of the U3 list below: that recovery runs at the next boot, not at
/// crash time, so the partial final persists until then. In every unrecovered
/// case the failure mode is the same LOUD invalid-PEM (or mode) error at the
/// next start, never a silently used key.
///
/// Against the boot-time crash RECOVERY race (#194, U3) the fallback's marker
/// protocol restores (b)-style convergence: removing the publish marker is
/// the winner's commit check, and recovery claims a round by renaming EVERY
/// marker and stale claim beside the final (a live winner's own marker is
/// necessarily among them), so exactly one side takes the round. A winner
/// that loses its marker demotes itself, waits for every `.recovering.`
/// claim FILE to clear (bounded by `CLAIM_SWEEP_MIN_AGE` plus a margin; see
/// `wait_for_recovery_claims`), and re-loads the settled key as Lost; if
/// any claim file survives the bound the publish fails closed with a loud
/// error instead of loading. A recovery that finds the final completed
/// after claiming re-loads it instead of quarantining. Honest residuals: a
/// winner stalled past `KEY_RACE_DEADLINE` that loads in the sub-ms window
/// before a recoverer's claim exists degrades to a re-load, and a
/// crash-interrupted recovery whose orphaned claim outlives the bounded
/// wait fails the demoted publish loudly until a sweep clears the claim:
/// loud error or re-load, never silent two-sided divergence.
///
/// `before_link` is a no-op in production; tests use it to widen the
/// post-write / pre-link window deterministically. `before_commit` runs
/// between the fallback final's dir fsync and the marker-removal commit
/// check — a no-op in production; tests use it to interleave a concurrent
/// recovery into that window (#194, U3). `faults` is the compile-time
/// fault-injection seam (`PublishFaults::NONE` in production).
fn publish_key_atomically(
    final_path: &std::path::Path,
    pem: &[u8],
    before_link: &dyn Fn(),
    before_commit: &dyn Fn(),
    faults: PublishFaults,
) -> Result<KeyPublish> {
    use std::io::Write;
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");

    // Pick the temp name with a bounded per-call retry, not a process-global
    // counter: a counter is only unique within one process (two containers
    // sharing a volume can both run as PID 1), and a crash between the temp
    // write and its cleanup leaves the old name behind, so a single
    // deterministic name would fail `create_new` on every restart until an
    // operator deleted it (#194). `AlreadyExists` means either such a stale
    // temp or a live concurrent publisher's temp; the two are indistinguishable,
    // so never delete a temp this call did not create (unlinking a live one
    // between its write and its hard_link would fail that healthy start), just
    // skip to the next name. Consequence: a crashed start leaks at most one
    // 0600 temp file, which later starts skip.
    let mut opened = None;
    for attempt in 0..KEY_TEMP_ATTEMPTS {
        let tmp = dir.join(format!(".{stem}.tmp.{}.{attempt}", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&tmp) {
            Ok(f) => {
                opened = Some((tmp, f));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("create temp key {}", tmp.display())),
        }
    }
    let Some((tmp, mut f)) = opened else {
        anyhow::bail!(
            "all {KEY_TEMP_ATTEMPTS} temp key names .{stem}.tmp.{}.* in {} are taken; \
             remove the stale temp files and restart",
            std::process::id(),
            dir.display()
        );
    };
    // Secure the empty temp BEFORE the PEM bytes hit it: on a mode-ignoring
    // mount this fails closed with nothing sensitive on disk, and the
    // hard_link later carries the verified 0600 inode to the final name
    // (#194, U2).
    #[cfg(unix)]
    tighten_and_verify_created(&tmp, faults.temp_mode_verify)?;
    // On a failed write OR fsync, remove the temp so nothing partial is ever
    // linked (#194). The fsync makes the PEM bytes durable BEFORE the name can
    // appear: without it a power crash after the link could leave a durable
    // final name over truncated bytes, wedging every later start.
    write_key_or_cleanup(&tmp, f.write_all(pem).and_then(|()| f.sync_all()))?;
    drop(f);

    before_link();

    let linked = (faults.link)().and_then(|()| std::fs::hard_link(&tmp, final_path));
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            // Fsync the parent directory so the link (and the temp unlink) are
            // durable before success is reported (#194). Skipped on non-Unix,
            // where opening a directory fails. On fsync failure do NOT remove
            // the final file: it is complete and data-synced, a concurrent
            // loser may already have loaded it, and a later start loads it via
            // the exists() path.
            #[cfg(unix)]
            fsync_parent_dir(final_path)?;
            Ok(KeyPublish::Won)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(KeyPublish::Lost),
        Err(e) => publish_key_fallback(final_path, pem, e, before_commit, faults),
    }
}

/// Fallback publish for a key directory whose filesystem cannot hard-link
/// (Unsupported/EPERM on some network and overlay mounts, or a transient link
/// error): create the FINAL path directly with `create_new(true).mode(0o600)`
/// (the INV-23 creation pattern) and write the PEM into it. `AlreadyExists`
/// still routes to the lost-race path, so no-clobber holds. Error handling
/// splits at the first PEM byte. PRE-write failures (marker create, final
/// create, tighten/mode-verify) remove the just-created EMPTY final and
/// dispose the marker: nothing recoverable exists yet, and those arms
/// complete within `CRASH_SIGNATURE_MIN_PERSIST` of the final's creation,
/// so no recovery can have claimed the round. POST-write failures
/// (`write_all` or the file `sync_all`) remove NOTHING: the partial final
/// and its marker are left in place together and the error surfaces naming
/// the handoff. That pair is exactly the crash state boot-time recovery
/// handles (claim, quarantine, regenerate), while an unlink here is a
/// stat-then-unlink race against a recovery that already claimed this round
/// and republished a live key at the name, and a marker disposed beside a
/// kept partial final recreates the marker-less wedge the bracket below
/// exists to prevent. The complete-but-unsynced `sync_all`-failure state is
/// safe too: a later healthy load fsyncs the final ITSELF before sweeping
/// the marker (`sweep_stale_markers`' durability gate), and a crash before
/// then re-enters recovery via the surviving marker. A failed parent-DIR
/// fsync also keeps the final but DOES dispose the marker (the content is
/// complete and data-synced, and a lost directory entry just disappears ->
/// clean regen, no wedge). Every error context chains `link_err` so a
/// two-step failure is diagnosable.
///
/// The whole non-atomic window is bracketed by a durable publish marker
/// (`.{stem}.publishing.{pid}.{attempt}`, empty, same dir as the final): the
/// marker is created and its NAME fsynced BEFORE the final can exist, and it
/// is removed only once the final is complete-and-durable (success) or the
/// exit leaves nothing needing vouching (pre-write error / lost race /
/// dir-fsync failure); on a post-write error the marker intentionally
/// OUTLIVES the attempt to vouch for the partial final beside it. On success
/// the removal doubles as the COMMIT CHECK (#194, U3): a removal that fails
/// means a recovering peer claimed this round, and the publish demotes
/// itself to Lost (see the success arm). A crash inside the window therefore
/// leaves marker+final together, so a later boot can tell "partial final from
/// a crashed fallback publish" from a key an operator corrupted (#194, U1).
/// Two constraints:
///   - Disposal ORDER on the pre-write arms is pinned: the empty final's
///     removal is ISSUED BEFORE the marker's. Cleanup is deliberately NOT a
///     Drop guard: a drop guard can run ahead of the final's disposal on an
///     early exit, and it would also fire on the post-write error exits,
///     whose whole point is that the marker survives.
///   - The marker dir fsync is warn-and-continue, not a hard gate: on
///     dir-fsync-hostile mounts a hard failure would turn "wedge once, then
///     recover" into "never provisions". Without that durability the marker
///     still survives SIGKILL-class crashes (the fs state persists); only the
///     power-loss protection narrows.
fn publish_key_fallback(
    final_path: &std::path::Path,
    pem: &[u8],
    link_err: std::io::Error,
    before_commit: &dyn Fn(),
    faults: PublishFaults,
) -> Result<KeyPublish> {
    use std::io::Write;
    warn!(
        path = %final_path.display(),
        err = %link_err,
        "hard_link failed; publishing identity key via direct create_new fallback"
    );
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");

    // Create the publish marker BEFORE the final name can exist, probing
    // bounded per-call names exactly like the temp-name loop and for the same
    // reasons: a stale marker left by a crashed same-PID start must not wedge
    // the restart, and a stale marker is indistinguishable from a live
    // concurrent publisher's, so never delete a name this call did not
    // create; just skip to the next one (#194, U1).
    let marker_prefix = publishing_prefix(stem);
    let mut marker = None;
    for attempt in 0..KEY_TEMP_ATTEMPTS {
        let candidate = dir.join(format!("{marker_prefix}{}.{attempt}", std::process::id()));
        match (faults.marker_create)().and_then(|()| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
        }) {
            Ok(f) => {
                drop(f);
                marker = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "create publish marker {} in hard_link fallback (link failed: {link_err})",
                        candidate.display()
                    )
                })
            }
        }
    }
    let Some(marker) = marker else {
        anyhow::bail!(
            "all {KEY_TEMP_ATTEMPTS} publish marker names {marker_prefix}{}.* in {} are \
             taken; remove the stale marker files and restart (link failed: {link_err})",
            std::process::id(),
            dir.display()
        );
    };
    // Marker disposal is explicit at every disposing exit, never a Drop
    // guard; see the order constraint in the doc comment (the post-write
    // error exits deliberately keep the marker).
    let dispose_marker = || {
        let _ = std::fs::remove_file(&marker);
    };
    // Make the marker NAME durable before the final can exist, so no crash
    // can leave a partial final without its marker. Warn-and-continue on
    // failure per the doc comment's degradation constraint.
    #[cfg(unix)]
    {
        if let Err(e) = (faults.marker_fsync)()
            .map_err(anyhow::Error::new)
            .and_then(|()| fsync_parent_dir(final_path))
        {
            warn!(
                marker = %marker.display(),
                err = %e,
                "publish marker dir fsync failed; continuing with reduced power-loss protection"
            );
        }
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = match (faults.fallback_create)().and_then(|()| opts.open(final_path)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost race: the existing final is the winner's complete key, not
            // ours to bracket; drop our marker and defer to it.
            dispose_marker();
            return Ok(KeyPublish::Lost);
        }
        Err(e) => {
            // The final was never created here, so there is no final removal
            // to order ahead of the marker's.
            dispose_marker();
            return Err(e).with_context(|| {
                format!(
                    "create identity key {} in hard_link fallback (link failed: {link_err})",
                    final_path.display()
                )
            });
        }
    };
    // Secure the empty final BEFORE the PEM bytes hit it (#194, U2). The
    // helper's fail-closed removal is what keeps a retry from wedging on
    // AlreadyExists, and is safe here for the same reason as on every
    // pre-write arm: the file is still empty, so the post-write
    // keep-everything rule below does not apply yet. The helper removes the
    // final before returning Err, so the pinned final-before-marker disposal
    // order holds. By-name removal stays right on this and the other
    // pre-write arms (create/mode-verify): they run within
    // CRASH_SIGNATURE_MIN_PERSIST of the final's creation, so no recovery
    // can have claimed this round yet.
    #[cfg(unix)]
    {
        if let Err(e) = tighten_and_verify_created(final_path, faults.fallback_mode_verify)
            .with_context(|| {
                format!("secure identity key in hard_link fallback (link failed: {link_err})")
            })
        {
            dispose_marker();
            return Err(e);
        }
    }
    // A failed write LEAVES the partial final and its marker in place and
    // only surfaces the error: marker+final together is exactly the crash
    // state the next boot recovers from (claim, quarantine, regenerate).
    // Any removal here would be a stat-then-unlink race against a recovery
    // that already claimed this round and republished a live key at the
    // name, and disposing the marker while the partial final stays would
    // recreate the marker-less wedge the bracket exists to prevent, so this
    // exit removes nothing and disposes nothing. Not write_key_or_cleanup,
    // whose by-name removal stays right for the primary path's TEMP file
    // (a private name no recovery can race).
    if let Err(e) = (faults.fallback_write)().and_then(|()| f.write_all(pem)) {
        return Err(anyhow::Error::new(e)
            .context(format!(
                "failed to write key to {}; the partial final and its publish marker \
                 are left in place for boot-time crash recovery",
                final_path.display()
            ))
            .context(format!(
                "hard_link fallback publish to {} (link failed: {link_err})",
                final_path.display()
            )));
    }
    // A failed file fsync takes the same keep-everything exit as the failed
    // write: the bytes were accepted but may not be durable, and marker+
    // final left together is the recoverable crash state (the next boot's
    // load either parses the complete content, after which the sweep's
    // durability gate fsyncs the final BEFORE removing the marker, or
    // content-fails beside the marker and recovers). A DISTINCT context is
    // kept so an operator debugging ENOSPC/EIO can tell "durability failed"
    // (bytes accepted, not synced) from the write-rejected case above. Only
    // the parent-DIR fsync below keeps the final while disposing the marker
    // (a lost directory entry just disappears -> clean regen).
    if let Err(e) = (faults.fallback_fsync)().and_then(|()| f.sync_all()) {
        return Err(anyhow::Error::new(e).context(format!(
            "fsync identity key {} in hard_link fallback (durability failed; the \
             final and its publish marker are left in place for boot-time crash \
             recovery; link failed: {link_err})",
            final_path.display()
        )));
    }
    drop(f);
    // Fsync the parent directory so the new name is durable before success is
    // reported, as on the hard-link path. Same policy on failure: the final is
    // complete and data-synced, so it is NOT removed; the marker is still
    // disposed of best-effort.
    #[cfg(unix)]
    {
        if let Err(e) = fsync_parent_dir(final_path) {
            dispose_marker();
            return Err(e);
        }
    }
    // Success: the final is complete and durable. Removing our OWN marker is
    // the COMMIT CHECK (#194, U3): recovery claims a round by renaming EVERY
    // marker beside the final, so our marker is necessarily among any
    // claimed round and a successful removal proves no recovery can ever
    // claim it, linearizing this winner ahead of any recoverer. Any failure
    // (NotFound after a peer's claim rename, or any other error) means
    // ownership of the round cannot be proven: a recovering peer may have
    // quarantined our final and republished, so returning Won could report
    // key A while disk holds key B. Demote to Lost instead. Demotion is safe
    // ONLY for a SETTLED round (N3): the caller's Lost arm re-loads the
    // final, and that load observes the recoverer's outcome only once the
    // recoverer's claims have cleared, so the demoted publish first waits
    // them out. An UNSETTLED round past the wait bound (any claim file
    // still present) fails the publish closed with a loud error instead:
    // loading there could return a pre-settlement key while the still-live
    // recoverer settles disk on a different identity.
    before_commit();
    match std::fs::remove_file(&marker) {
        Ok(()) => {
            // Best-effort fsync so the marker's removal tends to be durable.
            #[cfg(unix)]
            {
                let _ = fsync_parent_dir(final_path);
            }
            Ok(KeyPublish::Won)
        }
        Err(e) => {
            warn!(
                marker = %marker.display(),
                err = %e,
                "fallback publish lost its marker before commit; a recovering peer owns \
                 this round, demoting the publish to lost"
            );
            wait_for_recovery_claims(final_path).with_context(|| {
                format!(
                    "fallback publish of {} was demoted by a recovering peer, and the \
                     recovery round did not settle within the wait bound; failing the \
                     publish closed instead of loading a possibly pre-settlement key \
                     (marker removal failed: {e})",
                    final_path.display()
                )
            })?;
            Ok(KeyPublish::Lost)
        }
    }
}

/// Compile-time test seam for the load-side crash recovery in
/// `load_or_create_keypair_with` (#194, U2), following the `PublishFaults`
/// precedent: production passes `RecoverySeam::NONE` (every hook a no-op).
#[derive(Clone, Copy)]
struct RecoverySeam<'a> {
    /// Runs before every load attempt of the boot loader; an `Err` is taken as
    /// that attempt's result. The injected failure is NOT content-class, so it
    /// deterministically exercises the transient-failure (never-recover) policy.
    load_fault: fn() -> std::io::Result<()>,
    /// Runs at the top of each generate+publish pass, so a test can mutate
    /// on-disk state between a completed recovery and the retry publish.
    before_publish: &'a dyn Fn(),
    /// Runs inside `sweep_stale_markers` before the final's `sync_all`; an
    /// `Err` is taken as that sync's result, so a test can fail the sweep's
    /// durability gate deterministically (#194, U4).
    sweep_sync: fn() -> std::io::Result<()>,
    /// Runs inside `recover_crashed_publish` between the claim renames and
    /// the post-claim re-parse of the final, so a test can interleave a
    /// concurrent publisher's resolution into exactly that window (#194, F2).
    before_reparse: &'a dyn Fn(),
    /// Runs immediately before the post-claim RE-parse load inside
    /// `recover_crashed_publish`; an `Err` is taken as that load's result.
    /// The injected failure is NOT content-class, so it deterministically
    /// exercises the transient-reparse (release-and-fail-loudly) policy
    /// (#194, G2a). Narrower than `load_fault`, which only reaches
    /// `boot_load_key`'s attempts, never this re-parse.
    reparse_fault: fn() -> std::io::Result<()>,
    /// Runs inside `recover_crashed_publish` between the quarantine's
    /// completed-parse and the restore of the completed key to the final
    /// name, so a test can interleave a concurrent starter's publish into
    /// exactly the quarantine-to-restore window (#194, G2b follow-up).
    before_restore: &'a dyn Fn(),
    /// Faults threaded into the restore's republish of a completed
    /// quarantined key, so a test can force the restore onto its link-hostile
    /// degradation tier (production: `PublishFaults::NONE`).
    restore_faults: PublishFaults,
    /// Runs inside `recover_crashed_publish` between the post-claim re-parse
    /// and the quarantine rename, so a test can land a publisher's completed
    /// write in exactly the re-parse-to-rename window (#194, G2b).
    before_quarantine: &'a dyn Fn(),
}

impl RecoverySeam<'_> {
    /// The production value: no fault, no hook.
    const NONE: RecoverySeam<'static> = RecoverySeam {
        load_fault: || Ok(()),
        before_publish: &|| {},
        sweep_sync: || Ok(()),
        before_reparse: &|| {},
        reparse_fault: || Ok(()),
        before_restore: &|| {},
        restore_faults: PublishFaults::NONE,
        before_quarantine: &|| {},
    };
}

fn load_or_create_keypair(config: &Config) -> Result<Keypair> {
    load_or_create_keypair_with(
        &config.resolved_key_path(),
        &|| {},
        &|| {},
        PublishFaults::NONE,
        RecoverySeam::NONE,
    )
}

/// Outcome of `recover_crashed_publish` (#194, U2).
enum Recovery {
    /// The round was claimed and the corrupt final quarantined (or removed);
    /// the caller regenerates. Holds every claim file this recovery created
    /// plus their heartbeat (`ClaimSet`), released once the follow-up
    /// publish resolves (or on any error exit).
    Claimed(ClaimSet),
    /// The marker vanished before it could be claimed (the publisher — or a
    /// competing recoverer — resolved the window concurrently): the single
    /// follow-up load's result is final, success or error, no recovery.
    /// Boxed to keep the variants' sizes comparable (clippy:
    /// large_enum_variant); the enum lives only across a boot-time match.
    Reloaded(Box<Result<Keypair>>),
}

/// The per-process nonce embedded in recovery-claim names
/// (`.{stem}.recovering.{pid}.{nonce}.{n}`). The pid alone is NOT unique
/// across recoverers on a shared volume: two containers each running as
/// PID 1 (the same restart topology `KEY_TEMP_ATTEMPTS`' stale-name
/// discipline already handles) can recover the same directory concurrently
/// and derive identical destination names, and `rename` REPLACES an
/// existing destination, so the second recoverer's claim rename would
/// clobber the first's LIVE claim inode (the claim loop's `exists()` probe
/// is check-then-act, not an arbiter). Both would then track the same
/// path, and the first release would unlink the other's live claim,
/// early-waking the demoted publisher that claim gates. The nonce makes
/// the two name sequences disjoint. Std-only seeding: boot-time nanos
/// XORed with this static's address (ASLR-shifted per process), folded to
/// 32 bits; uniqueness is probabilistic-by-construction, which suffices
/// because a collision needs the same pid AND the same nonce against the
/// same directory at the same time. Threads within one process share the
/// nonce; intra-process claim arbitration remains the per-source rename
/// (production calls this once, at boot).
fn claim_nonce() -> u32 {
    static NONCE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *NONCE.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mixed = nanos ^ (&NONCE as *const _ as u64);
        (mixed ^ (mixed >> 32)) as u32
    })
}

/// Production primary stamp for `refresh_claim_mtime`: set the file's mtime
/// to now via `set_modified`.
fn set_mtime_now(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::options()
        .write(true)
        .open(path)?
        .set_modified(std::time::SystemTime::now())
}

/// Stamp `claim`'s mtime fresh, for the G1 age gate (see the call site in
/// `recover_crashed_publish`). `primary_stamp` is `set_mtime_now` in
/// production (injectable, the file's fn-pointer seam style; some
/// filesystems reject explicit timestamps while honoring write-driven
/// updates). If the primary fails, fall back to appending one byte, which
/// updates the mtime on effectively every filesystem, plus a best-effort
/// data sync. The claim is then no longer empty, which is safe: claims
/// vouch for no content and every consumer matches them by NAME only
/// (`list_recovery_claimables`, `sweep_stale_markers`,
/// `wait_for_recovery_claims`); nothing reads a claim's bytes. Errs only
/// when BOTH rungs fail, carrying both failures in the message.
fn refresh_claim_mtime(
    claim: &std::path::Path,
    primary_stamp: fn(&std::path::Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let primary_err = match primary_stamp(claim) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    std::fs::File::options()
        .append(true)
        .open(claim)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(b".")?;
            let _ = f.sync_data();
            Ok(())
        })
        .map_err(|fallback_err| {
            std::io::Error::new(
                fallback_err.kind(),
                format!(
                    "set_modified failed ({primary_err}) and the write fallback \
                     failed ({fallback_err})"
                ),
            )
        })
}

/// Handle to a live recovery's claim-heartbeat thread. Dropping it stops
/// the beat and joins the thread, so every exit path (release, error, or
/// unwind) reclaims it; the join is bounded because the thread checks the
/// stop flag at least every ~250ms (the sleep granule in
/// `spawn_claim_heartbeat`).
#[derive(Debug)]
struct ClaimHeartbeat {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ClaimHeartbeat {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Spawn the claim heartbeat: a thread refreshing every claim's mtime every
/// `CLAIM_SWEEP_MIN_AGE / 4` until stopped, sleeping in ~250ms granules so
/// the joining release is prompt. This is what makes the G1 age-as-orphan
/// rule sound (see `CLAIM_SWEEP_MIN_AGE`'s liveness contract): without it a
/// recoverer stalled longer than the floor between claim and settlement
/// reads as an orphan to the sweep and to claimability, so a healthy boot
/// can remove the still-live claim (early-releasing the demoted waiter to
/// a pre-settlement load) or a competing recoverer can steal the round:
/// divergence returns on slow shared volumes. The demotion waiter itself is
/// age-blind (it keys on claim-file absence; see
/// `wait_for_recovery_claims`), so a frozen mtime alone fails a demoted
/// publisher closed rather than releasing it early. Best-effort:
/// a failed spawn warns and degrades to the single claim-time stamp (the
/// pre-heartbeat exposure, churn not divergence); a failed refresh warns and
/// retries at the next beat.
fn spawn_claim_heartbeat(files: Vec<std::path::PathBuf>) -> Option<ClaimHeartbeat> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = std::sync::Arc::clone(&stop);
    let spawned = std::thread::Builder::new()
        .name("identity-claim-heartbeat".into())
        .spawn(move || {
            let beat = CLAIM_SWEEP_MIN_AGE / 4;
            let granule = std::time::Duration::from_millis(250);
            'beat: loop {
                let mut slept = std::time::Duration::ZERO;
                while slept < beat {
                    if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                        break 'beat;
                    }
                    std::thread::sleep(granule);
                    slept += granule;
                }
                for claim in &files {
                    if thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                        break 'beat;
                    }
                    if let Err(e) = refresh_claim_mtime(claim, set_mtime_now) {
                        warn!(
                            claim = %claim.display(),
                            err = %e,
                            "claim heartbeat could not refresh a live claim's mtime; if \
                             this persists past the liveness floor the claim reads as \
                             orphaned (bounded to churn, not divergence)"
                        );
                    }
                }
            }
        });
    match spawned {
        Ok(handle) => Some(ClaimHeartbeat {
            stop,
            handle: Some(handle),
        }),
        Err(e) => {
            warn!(
                err = %e,
                "could not spawn the claim heartbeat; falling back to the single \
                 claim-time stamp: a recovery stalled past the liveness floor may \
                 read as orphaned (bounded to churn, not divergence)"
            );
            None
        }
    }
}

/// The claim files a recovery holds, plus the heartbeat keeping them young
/// (see `spawn_claim_heartbeat`). Carried through `Recovery::Claimed` so the
/// boot loop's follow-up publish keeps the round visibly live until
/// `release_recovery_claims`; dropping the set (any path) stops and joins
/// the heartbeat via `ClaimHeartbeat`'s `Drop`.
#[derive(Debug)]
struct ClaimSet {
    files: Vec<std::path::PathBuf>,
    heartbeat: Option<ClaimHeartbeat>,
}

impl ClaimSet {
    /// No claims, no heartbeat: the boot loop's initial state.
    fn empty() -> Self {
        ClaimSet {
            files: Vec::new(),
            heartbeat: None,
        }
    }

    /// Wrap freshly created claim files and start their heartbeat
    /// (best-effort; `None` on spawn failure).
    fn with_heartbeat(files: Vec<std::path::PathBuf>) -> Self {
        let heartbeat = spawn_claim_heartbeat(files.clone());
        ClaimSet { files, heartbeat }
    }
}

/// Best-effort removal of the claim files a recovery created, plus a
/// best-effort dir fsync. Stops and joins the claim heartbeat FIRST (via
/// `ClaimHeartbeat`'s `Drop`; bounded by its ~250ms flag granule), so no
/// beat can restamp a claim after its removal. Claims vouch for NO on-disk
/// content (unlike
/// publish markers, whose disposal order against the final is pinned): they
/// only gate a demoted publisher's bounded wait and recovery arbitration.
/// Release therefore needs no ordering against the final, the markers, or
/// anything else: any exit may drop the claims at any point once their owner
/// stops recovering, and the worst a lost claim can cause is a waiter
/// re-loading early, which the load path copes with (#194, F1/F3).
fn release_recovery_claims(final_path: &std::path::Path, claims: &mut ClaimSet) {
    drop(claims.heartbeat.take());
    for claim in &claims.files {
        let _ = std::fs::remove_file(claim);
    }
    claims.files.clear();
    #[cfg(unix)]
    {
        let _ = fsync_parent_dir(final_path);
    }
}

/// Claim-and-quarantine for a boot whose load returned `CrashSignature`: a
/// content-class failure beside a `.publishing.` marker or `.recovering.`
/// claim, the signature of a fallback publish (or a recovery) crashed
/// inside its window (#194, U2/F2/F3). Claims the WHOLE round: every marker
/// and every pre-existing claim is renamed to a fresh claim of our own
/// (`.{stem}.recovering.{pid}.{n}`, bounded fresh-name probing per item, the
/// KEY_TEMP_ATTEMPTS discipline; a NotFound on an individual rename means
/// that item resolved concurrently and is skipped). Claiming everything is
/// what makes the publisher's commit check sound: a live fallback publisher
/// still inside its window necessarily has its own marker among the
/// claimables, so its marker removal fails and it demotes (F2); claiming
/// only one marker would let a stale marker's claim steal a live round.
///
/// If NO rename lands, the round resolved concurrently: one immediate
/// re-load decides, with no recovery. If at least one lands, this recovery
/// owns the round, and it RE-PARSES the final once before touching it: a
/// publisher that completed inside the claim window has already resolved the
/// round, so a parseable final is returned as `Reloaded` and the claims are
/// released, never quarantining a good key. A TRANSIENT (non-content)
/// re-parse failure releases the claims and surfaces the error loudly with
/// nothing destroyed (#194, G2a). Only if the final still content-fails does
/// the recovery quarantine it by rename (preserving bytes and mode for
/// post-mortem; falling back to removal only if every quarantine name
/// fails); a quarantine whose bytes then PARSE is a publisher that completed
/// in the re-parse-to-rename window and is restored to the final name
/// (#194, G2b; see the inline comment). Otherwise recovery consumes any
/// remaining markers best-effort and hands control back to regenerate.
/// Every error exit after claiming releases
/// the claims first (see `release_recovery_claims`; a leaked claim would
/// ride later demoted publishers through the full wait bound and fail
/// their publish closed until a sweep cleared it, F1). `seam` carries
/// the test hooks for the claim-to-re-parse and re-parse-to-quarantine
/// windows (`before_reparse`, `reparse_fault`, `before_quarantine`; all
/// no-ops in production).
fn recover_crashed_publish(
    final_path: &std::path::Path,
    load_err: anyhow::Error,
    seam: RecoverySeam<'_>,
) -> Result<Recovery> {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let claimables = list_recovery_claimables(final_path);
    if claimables.is_empty() {
        return Ok(Recovery::Reloaded(Box::new(load_racing_key(final_path))));
    }

    // CLAIM every marker and foreign claim by rename. Each rename admits
    // exactly one winner; NotFound means that item resolved concurrently (a
    // publisher committed, or a competing recoverer claimed it) and is
    // skipped. Names are never reused or clobbered: the monotonic counter
    // plus the exists() probe keeps every destination fresh, bounded per
    // item like the temp/marker/quarantine probes.
    let claim_prefix = recovering_prefix(stem);
    let mut claims: Vec<std::path::PathBuf> = Vec::new();
    let mut next_name = 0u32;
    for item in &claimables {
        for _ in 0..KEY_TEMP_ATTEMPTS {
            // The name carries a per-process nonce beside the pid: pid alone
            // is not unique across recoverers (two PID-1 containers on one
            // shared volume), and a colliding destination would let one
            // recoverer's rename clobber the other's live claim; see
            // `claim_nonce`.
            let dest = dir.join(format!(
                "{claim_prefix}{}.{:08x}.{next_name}",
                std::process::id(),
                claim_nonce()
            ));
            next_name = next_name.wrapping_add(1);
            if dest.exists() {
                continue;
            }
            match std::fs::rename(item, &dest) {
                Ok(()) => {
                    // The rename preserves the SOURCE's mtime, but the G1
                    // sweep gate reads the CLAIM file's mtime: a claim made
                    // from an aged stale marker would be born already past
                    // CLAIM_SWEEP_MIN_AGE, and a concurrent healthy boot
                    // could sweep this LIVE claim mid-round, early-waking
                    // the demoted publisher it gates. The age gate needs
                    // claim-time freshness, so stamp it now (two rungs; see
                    // refresh_claim_mtime). Only if both rungs fail is the
                    // live claim left exposed to the age-gated sweep, so
                    // warn naming that hazard and continue: the exposure is
                    // bounded to churn, not divergence, by the post-claim
                    // re-parse and the restore's no-clobber republish.
                    if let Err(e) = refresh_claim_mtime(&dest, set_mtime_now) {
                        warn!(
                            claim = %dest.display(),
                            err = %e,
                            "could not refresh a recovery claim's mtime by any rung: a \
                             concurrent healthy boot's age-gated sweep may remove this \
                             LIVE claim mid-round and early-wake the demoted publisher \
                             it gates (bounded to churn, not divergence, by the \
                             post-claim re-parse, the restore's no-clobber republish, \
                             and the demoted publisher's waiter failing closed on an \
                             unsettled round)"
                        );
                    }
                    claims.push(dest);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                // Any other rename failure: probe the next fresh name, up to
                // the per-item bound; an unclaimable item is left for the
                // best-effort marker consumption below (or a later sweep).
                Err(_) => continue,
            }
        }
    }
    if claims.is_empty() {
        // Every item vanished before it could be claimed: the round resolved
        // concurrently; one immediate re-load decides, with no recovery.
        return Ok(Recovery::Reloaded(Box::new(load_racing_key(final_path))));
    }
    // CLAIM HEARTBEAT: from here until release these claims are load-bearing
    // (they gate demoted publishers and arbitrate the round), and the G1 age
    // rule reads aged-out as orphaned, so keep them visibly live for as long
    // as this recovery actually runs; see spawn_claim_heartbeat.
    let mut claims = ClaimSet::with_heartbeat(claims);

    // POST-CLAIM RE-PARSE (#194, F2): between the crash-signature
    // observation and the renames above, a live publisher may have completed
    // its final. Now that the round is claimed no publisher can commit
    // anymore, so one parse decides: a readable final means the round is
    // already resolved, so release the claims and defer to it, never
    // quarantining a good key. Only a CONTENT-class failure proceeds to the
    // quarantine (#194, G2a): a transient (IO/permissions) failure of a
    // PRESENT final proves nothing about the content, and quarantining on it
    // would destroy a possibly good key, so the claims are released and the
    // error surfaces loudly with nothing destroyed. A NotFound is neither: a
    // vanished final means a competing recoverer disposed of it
    // concurrently, there is nothing a quarantine could destroy, and the
    // quarantine loop's own NotFound arm resolves it into a clean
    // regenerate, so it falls through like the content class.
    (seam.before_reparse)();
    match (seam.reparse_fault)()
        .map_err(anyhow::Error::new)
        .and_then(|()| load_existing_key(final_path))
    {
        Ok(kp) => {
            release_recovery_claims(final_path, &mut claims);
            return Ok(Recovery::Reloaded(Box::new(Ok(kp))));
        }
        Err(e)
            if is_key_content_error(&e)
                || e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            // Still the crashed content, or vanished concurrently: fall
            // through to the quarantine.
        }
        Err(e) => {
            release_recovery_claims(final_path, &mut claims);
            return Err(e.context(format!(
                "transient failure re-parsing identity key {} after claiming crash \
                 recovery; claims released, nothing quarantined",
                final_path.display()
            )));
        }
    }

    // QUARANTINE the final under a bounded name probe (the KEY_TEMP_ATTEMPTS
    // discipline: a stale quarantine from a crashed same-PID start must not
    // wedge this one). The warn precedes the move and carries stable
    // operator-greppable fields; the destination it names is the first free
    // candidate, which the rename below tries first. `before_quarantine` is
    // the test seam for the re-parse-to-rename window (#194, G2b; a no-op in
    // production).
    (seam.before_quarantine)();
    let dest_for = |n: u32| {
        dir.join(format!(
            "{}{}.{n}",
            quarantined_prefix(stem),
            std::process::id()
        ))
    };
    let start = (0..KEY_TEMP_ATTEMPTS)
        .find(|&n| !dest_for(n).exists())
        .unwrap_or(0);
    warn!(
        path = %final_path.display(),
        claimables = ?claimables,
        claims = ?claims.files,
        quarantine = %dest_for(start).display(),
        "crash-interrupted identity key publish: quarantining the unreadable key and \
         regenerating the identity"
    );
    let mut quarantined = false;
    let mut quarantined_at: Option<std::path::PathBuf> = None;
    for n in start..KEY_TEMP_ATTEMPTS {
        let dest = dest_for(n);
        if dest.exists() {
            continue;
        }
        match std::fs::rename(final_path, &dest) {
            Ok(()) => {
                quarantined = true;
                quarantined_at = Some(dest);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // The final vanished concurrently; nothing left to quarantine.
                quarantined = true;
                break;
            }
            Err(_) => continue,
        }
    }
    if !quarantined {
        // Every rename failed: removal still unblocks the regeneration
        // (mirroring the publish paths' removal policy); only if even that
        // fails is the boot left to its loud error, with the claims
        // released first, so the dead round cannot stall later publishers
        // (#194, F1).
        if let Err(e) = std::fs::remove_file(final_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                release_recovery_claims(final_path, &mut claims);
                return Err(load_err.context(format!(
                    "could not quarantine or remove corrupt identity key {} during crash \
                     recovery: {e}",
                    final_path.display()
                )));
            }
        }
    }

    // POST-QUARANTINE COMPLETED-WRITE CHECK (#194, G2b): the re-parse above
    // and the quarantine rename are not atomic, so a publisher that
    // completed its write inside the re-parse-to-rename window has its
    // VALID key swept into the quarantine. The rename preserved the bytes
    // (and the 0600 inode), so parse them: a parseable quarantine means that
    // publisher already resolved the round, and its key is restored to the
    // final name instead of being replaced by a regeneration, which would
    // diverge from the Won the publisher already reported. The restore is a
    // REPUBLISH of the quarantined PEM through publish_key_atomically, which
    // holds no-clobber on EVERY tier: the hard-link tier refuses an existing
    // final, and so does the fallback's create_new on link-hostile mounts (a
    // plain rename here would clobber a final a fresh start published into
    // the freed name on exactly those mounts). Won means the completed key
    // is durably back at the final; the quarantine is then removed, because
    // its bytes are an exact copy of what now lives at the final, so keeping
    // it buys no forensics. The keypair returned is the one already parsed
    // from the quarantined bytes, not a re-read of the final, which could
    // race a writer that lands after our republish. Won also supersedes
    // every OTHER young parseable quarantine sibling (they lost this round
    // to the restored key, the N4 rule adoption-Won already applies); left
    // adoptable, a later missing final would resurrect a different
    // historical DID. Lost means someone else
    // durably published meanwhile: the quarantined key provably LOST its
    // round, so it is renamed into the superseded class (bytes preserved as
    // forensics, never adoptable; a young parseable quarantine left in the
    // adoptable class here would let the operator's delete-final-for-a-
    // fresh-DID procedure resurrect the losing key, N2) and the boot defers
    // to the settled final. A publish error keeps the quarantine ADOPTABLE
    // (the next boot's F1 adoption is the remedy for a failed restore),
    // releases the claims, and surfaces loudly, nothing destroyed. An
    // unparseable quarantine is the expected crash state and falls through
    // to regenerate.
    if let Some(quarantine) = &quarantined_at {
        let completed = std::fs::read_to_string(quarantine)
            .ok()
            .and_then(|pem| Keypair::from_pem(&pem).ok().map(|kp| (pem, kp)));
        if let Some((pem, kp)) = completed {
            (seam.before_restore)();
            match publish_key_atomically(
                final_path,
                pem.as_bytes(),
                &|| {},
                &|| {},
                seam.restore_faults,
            ) {
                Ok(KeyPublish::Won) => {
                    // Mirror-arm invariant (N4): the restore decided this
                    // round in favor of the restored key, so any OTHER
                    // young parseable quarantine sibling provably lost it;
                    // supersede each, exactly like adoption-Won, or a later
                    // missing final resurrects a different historical DID.
                    // ORDER: siblings first, THEN consume the chosen
                    // quarantine, so a crash in the gap leaves the siblings
                    // already superseded, never adoptable beside a final
                    // that already holds the winner.
                    supersede_sibling_quarantines(final_path, quarantine);
                    let _ = std::fs::remove_file(quarantine);
                    #[cfg(unix)]
                    {
                        let _ = fsync_parent_dir(final_path);
                    }
                    release_recovery_claims(final_path, &mut claims);
                    return Ok(Recovery::Reloaded(Box::new(Ok(kp))));
                }
                Ok(KeyPublish::Lost) => {
                    supersede_quarantine(final_path, quarantine);
                    release_recovery_claims(final_path, &mut claims);
                    return Ok(Recovery::Reloaded(Box::new(load_racing_key(final_path))));
                }
                Err(e) => {
                    release_recovery_claims(final_path, &mut claims);
                    return Err(e.context(format!(
                        "could not restore the completed identity key to {} during crash \
                         recovery; quarantine kept at {}",
                        final_path.display(),
                        quarantine.display()
                    )));
                }
            }
        }
    }

    // Consume any remaining markers (a multi-crash pile-up, or an item the
    // claim probe could not rename) best-effort, and best-effort fsync the
    // directory so the transition tends to be durable.
    for marker in list_publish_markers(final_path) {
        let _ = std::fs::remove_file(&marker);
    }
    #[cfg(unix)]
    {
        let _ = fsync_parent_dir(final_path);
    }
    Ok(Recovery::Claimed(claims))
}

/// Body of `load_or_create_keypair` with the test seams threaded in (#194,
/// U2): `before_link`, `before_commit`, and `faults` pass through to
/// `publish_key_atomically` (production: no-op / `NONE`), `seam` is the
/// load-side recovery seam (production: `RecoverySeam::NONE`).
///
/// Load-or-generate with AT MOST ONE crash recovery per start: a load
/// failure recovers (claim the round, quarantine the final, regenerate)
/// only when it is content-class (`KeyContentError`), a `.publishing.`
/// marker or `.recovering.` claim exists (the crash signature, persisting
/// for `CRASH_SIGNATURE_MIN_PERSIST`), and no recovery has run yet this start. Every
/// other failure surfaces unchanged. The Lost arm participates in the same
/// policy; a recovery fired there loops back for one retry publish, and any
/// failure on that second pass surfaces unchanged.
fn load_or_create_keypair_with(
    key_path: &std::path::Path,
    before_link: &dyn Fn(),
    before_commit: &dyn Fn(),
    faults: PublishFaults,
    seam: RecoverySeam<'_>,
) -> Result<Keypair> {
    // The claim set (files plus heartbeat) of a fired recovery. Held while
    // the follow-up
    // generate+publish runs, so a stalled winner our claims demoted can still
    // observe them while waiting (U3 relies on this), and released on EVERY
    // exit after that, success, Lost, and error alike (#194, F1): a leaked
    // claim rides every later demoted publisher through the full wait bound
    // and fails its publish closed until a sweep clears the orphan.
    // Release order against the final or the markers does not matter; see
    // release_recovery_claims.
    let mut claims = ClaimSet::empty();
    let mut recovery_allowed = true;

    // N1 invariant: EVERY arm that returns a successfully resolved keypair
    // (loaded, reloaded, adopted, or generated) must run the durability-gated
    // stale-marker sweep before returning, by funneling through this closure.
    // A healthy return that skips the sweep leaves unclaimable markers or
    // aged orphan claims beside a good final, and a LATER content failure of
    // that final would pair with the leftover residue and misclassify plain
    // corruption as a recoverable crash. Route any future healthy return
    // through here too, so no arm can forget the sweep.
    let finish_healthy = |kp: Keypair| -> Result<Keypair> {
        sweep_stale_markers(key_path, seam.sweep_sync);
        Ok(kp)
    };

    // At most two passes: the second exists only so a Lost-arm recovery can
    // retry the generate+publish once.
    for _pass in 0..2 {
        // Fast path for the common already-provisioned case (still race-safe: a
        // concurrently-publishing winner is handled by the retry in
        // boot_load_key).
        if key_path.exists() {
            match boot_load_key(key_path, recovery_allowed, seam.load_fault) {
                BootLoad::Loaded(kp) => {
                    release_recovery_claims(key_path, &mut claims);
                    return finish_healthy(*kp);
                }
                // Only emitted while recovery is still allowed (crash_exit is
                // gated on it).
                BootLoad::CrashSignature(e) => {
                    match recover_crashed_publish(key_path, e, seam)? {
                        Recovery::Claimed(c) => {
                            claims = c;
                            recovery_allowed = false;
                            // Fall through to regenerate and publish.
                        }
                        Recovery::Reloaded(result) => return (*result).and_then(&finish_healthy),
                    }
                }
                BootLoad::Failed(e) => {
                    release_recovery_claims(key_path, &mut claims);
                    return Err(e);
                }
            }
        }

        (seam.before_publish)();

        // ADOPTION SCAN (F1): with no loadable final, a COMPLETED key may be
        // stranded in a quarantine: the recoverer's restore republish
        // errored, or the recoverer crashed between its quarantine rename
        // and the restore. Generating here would mint a fresh DID over a
        // still-live identity, so a YOUNG parseable quarantine (the current
        // round's; see find_adoptable_quarantine's age bound) is republished
        // and adopted instead: adoption preserves identity continuity across
        // a crashed or failed restore. An unparseable quarantine is the
        // expected crash state and stays on disk as forensics, as does an
        // AGED parseable one (history, never resurrected); only when no
        // quarantine qualifies does the boot fall through to generate. The republish holds no-clobber on every tier, so Lost
        // means a concurrent starter durably published meanwhile: the
        // quarantine provably LOST its round, so it moves to the superseded
        // class and the boot defers to the winner, exactly like the G2b
        // restore's Lost arm. A
        // republish error surfaces loudly with the quarantine kept: minting
        // a fresh identity over an adoptable one is the failure F1 exists to
        // prevent.
        if let Some((quarantine, pem, kp)) = find_adoptable_quarantine(key_path) {
            match publish_key_atomically(key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
                Ok(KeyPublish::Won) => {
                    // N4: any OTHER young parseable quarantine sibling lost
                    // this round to the adopted key; move each into the
                    // superseded class so a later missing final cannot
                    // resurrect a different historical DID. Unparseable
                    // siblings stay plain quarantines as crash forensics.
                    // ORDER: siblings first, THEN consume the chosen
                    // quarantine, so a crash in the gap leaves the siblings
                    // already superseded, never adoptable beside a final
                    // that already holds the winner.
                    supersede_sibling_quarantines(key_path, &quarantine);
                    // The quarantine's bytes are an exact copy of what now
                    // durably lives at the final, so keeping it buys no
                    // forensics (the G2b restore's removal rationale).
                    let _ = std::fs::remove_file(&quarantine);
                    #[cfg(unix)]
                    {
                        let _ = fsync_parent_dir(key_path);
                    }
                    release_recovery_claims(key_path, &mut claims);
                    info!(
                        path = %key_path.display(),
                        did = %kp.did(),
                        "adopted a completed identity stranded in quarantine"
                    );
                    return finish_healthy(kp);
                }
                Ok(KeyPublish::Lost) => {
                    // Mirror-arm invariant (N2): EVERY Lost outcome
                    // supersedes the losing bytes. This quarantine just
                    // provably LOST its round to the concurrent winner;
                    // left adoptable, the operator's delete-final-for-a-
                    // fresh-DID procedure would resurrect it within the age
                    // floor, exactly the hazard the restore's Lost arm
                    // already closes.
                    supersede_quarantine(key_path, &quarantine);
                    let result = load_racing_key(key_path);
                    release_recovery_claims(key_path, &mut claims);
                    return result.and_then(&finish_healthy);
                }
                Err(e) => {
                    release_recovery_claims(key_path, &mut claims);
                    return Err(e.context(format!(
                        "could not republish the completed identity key stranded at {}; \
                         quarantine kept",
                        quarantine.display()
                    )));
                }
            }
        }

        let kp = Keypair::generate();
        // Every error exit below this point may hold a fired recovery's
        // claims; release them before propagating (#194, F1). The bare `?`
        // this replaces leaked the claim files on a failed retry publish.
        let pem = match kp.to_pem() {
            Ok(pem) => pem,
            Err(e) => {
                release_recovery_claims(key_path, &mut claims);
                return Err(anyhow::anyhow!("failed to serialize key: {e}"));
            }
        };

        if let Some(parent) = key_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                release_recovery_claims(key_path, &mut claims);
                return Err(e.into());
            }
        }

        // Publish atomically: the final path only ever appears complete, and a
        // lost race loads the winner's key rather than overwriting it.
        let published = match publish_key_atomically(
            key_path,
            pem.as_bytes(),
            before_link,
            before_commit,
            faults,
        ) {
            Ok(published) => published,
            Err(e) => {
                release_recovery_claims(key_path, &mut claims);
                return Err(e);
            }
        };
        match published {
            KeyPublish::Won => {
                release_recovery_claims(key_path, &mut claims);
                info!(path = %key_path.display(), did = %kp.did(), "generated new node identity");
                return finish_healthy(kp);
            }
            KeyPublish::Lost => {
                match boot_load_key(key_path, recovery_allowed, seam.load_fault) {
                    BootLoad::Loaded(kp) => {
                        release_recovery_claims(key_path, &mut claims);
                        return finish_healthy(*kp);
                    }
                    // Only emitted while recovery is still allowed (crash_exit
                    // is gated on it).
                    BootLoad::CrashSignature(e) => {
                        match recover_crashed_publish(key_path, e, seam) {
                            Ok(Recovery::Claimed(c)) => {
                                claims = c;
                                recovery_allowed = false;
                                continue; // Second pass: regenerate and publish.
                            }
                            Ok(Recovery::Reloaded(result)) => {
                                release_recovery_claims(key_path, &mut claims);
                                return (*result).and_then(&finish_healthy);
                            }
                            Err(err) => {
                                release_recovery_claims(key_path, &mut claims);
                                return Err(err);
                            }
                        }
                    }
                    BootLoad::Failed(e) => {
                        release_recovery_claims(key_path, &mut claims);
                        return Err(e);
                    }
                }
            }
        }
    }
    unreachable!("the boot loop returns within two passes");
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

#[cfg(all(test, unix))]
mod identity_key_tests {
    use super::{
        load_or_create_keypair, load_or_create_keypair_with, load_racing_key,
        publish_key_atomically, Config, KeyPublish, Keypair, PublishFaults, RecoverySeam,
        KEY_TEMP_ATTEMPTS,
    };
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt;

    // #194 (P2): the racing loader must wait out a SLOW winner on a meaningful
    // wall-clock deadline, not give up after an arbitrary ~100ms window. Simulate
    // a winner that only publishes the key after 250ms (past the old 100ms budget)
    // and assert the loader waits it out instead of failing with `invalid PEM key`.
    // RED with the old `for _ in 0..50` (2ms) fixed-count loop.
    #[test]
    fn load_racing_key_waits_out_a_slow_winner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let writer_path = key_path.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(250));
            publish_key_atomically(
                &writer_path,
                pem.as_bytes(),
                &|| {},
                &|| {},
                PublishFaults::NONE,
            )
            .expect("publish");
        });

        let started = std::time::Instant::now();
        let kp = load_racing_key(&key_path)
            .expect("racing load must wait out the slow winner, not fail");
        let waited = started.elapsed();
        writer.join().expect("writer joins");

        assert!(
            waited >= std::time::Duration::from_millis(200),
            "loader should have waited for the ~250ms-slow winner, only waited {waited:?}"
        );
        assert!(
            !format!("{}", kp.did()).is_empty(),
            "loaded the published key"
        );
    }

    // #194 (P2): the atomic publish preserves the single-winner no-clobber
    // guarantee — a second publish of a DIFFERENT key must lose and leave the
    // winner's key untouched — and it cleans up its temp files.
    #[test]
    fn publish_wins_then_second_publish_loses_without_clobbering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem_a = Keypair::generate().to_pem().expect("pem a");
        let pem_b = Keypair::generate().to_pem().expect("pem b");
        assert_ne!(pem_a.as_str(), pem_b.as_str(), "fixtures must differ");

        let out = publish_key_atomically(
            &key_path,
            pem_a.as_bytes(),
            &|| {},
            &|| {},
            PublishFaults::NONE,
        )
        .expect("publish a");
        assert!(matches!(out, KeyPublish::Won), "first publish wins");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().as_str(),
            pem_a.as_str(),
            "final holds the full PEM"
        );

        let out = publish_key_atomically(
            &key_path,
            pem_b.as_bytes(),
            &|| {},
            &|| {},
            PublishFaults::NONE,
        )
        .expect("publish b");
        assert!(matches!(out, KeyPublish::Lost), "second publish loses");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().as_str(),
            pem_a.as_str(),
            "the winner's key must NOT be clobbered by a losing publish"
        );

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files must be cleaned up, found {leftovers:?}"
        );
    }

    // #194 (P2, the core of jatmn's option b): while a winner is between writing
    // its temp and linking it into place, a reader watching the FINAL path must
    // see it absent or COMPLETE — never empty/partial. RED with a
    // create_new(final)+write approach, which exposes an empty final for the whole
    // write window.
    #[test]
    fn publish_never_exposes_a_partial_final() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = std::sync::Arc::new(dir.path().join("identity.pem"));
        let pem = Keypair::generate().to_pem().expect("pem");

        let wp = key_path.clone();
        let writer = std::thread::spawn(move || {
            // Hold the post-write / pre-link window open for 200ms.
            publish_key_atomically(
                &wp,
                pem.as_bytes(),
                &|| {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                },
                &|| {},
                PublishFaults::NONE,
            )
            .expect("publish");
        });

        // Poll until the final path appears (bounded by a generous deadline:
        // the publish now fsyncs the temp and the directory, so under parallel
        // suite load the link can land well after the writer's 200ms hold).
        // Every observation of an existing final must parse; the first
        // complete observation ends the test, since a linked-complete final
        // cannot become partial afterwards. The partial assertion still runs
        // BEFORE the break, so a publish that exposes an empty/partial final
        // during the write window is caught on the first poll that sees it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_complete = false;
        while std::time::Instant::now() < deadline {
            if key_path.exists() {
                let body = std::fs::read_to_string(&*key_path).unwrap_or_default();
                assert!(
                    Keypair::from_pem(&body).is_ok(),
                    "final key observed in a partial/empty state: {body:?}"
                );
                saw_complete = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        writer.join().expect("writer joins");
        assert!(
            saw_complete,
            "reader should have observed the completed key within the deadline"
        );
    }

    // #194: a temp file left by a crash between the temp write and its cleanup
    // must not wedge the restart. A restarted container commonly runs as PID 1
    // again, so the first name tried collides with the stale one; the publish
    // must skip it and still win with the complete PEM. RED with a single
    // deterministic temp name: `create_new` fails AlreadyExists and the node
    // never starts until an operator deletes the temp.
    #[test]
    fn publish_recovers_from_a_stale_crashed_temp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        // The crashed prior start's leftover: the deterministic attempt-0 name,
        // 0600, holding a partial write.
        let stale = dir
            .path()
            .join(format!(".identity.pem.tmp.{}.0", std::process::id()));
        std::fs::write(&stale, b"partial-").expect("seed stale temp");
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o600))
            .expect("stale temp perms");

        let out = publish_key_atomically(
            &key_path,
            pem.as_bytes(),
            &|| {},
            &|| {},
            PublishFaults::NONE,
        )
        .expect("publish must recover from a stale temp, not wedge the start");
        assert!(matches!(out, KeyPublish::Won), "publish wins");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().as_str(),
            pem.as_str(),
            "final holds the complete PEM, not the stale partial"
        );
    }

    // #194: temp-name probing is bounded. With every candidate name taken the
    // publish must return a clear error naming the directory and prefix (not
    // hang or spin) and must not create the final path. Together with the
    // stale-temp test this runs the exhaustion branch both ways.
    #[test]
    fn publish_errors_when_all_temp_names_are_taken() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        for attempt in 0..KEY_TEMP_ATTEMPTS {
            let tmp = dir.path().join(format!(
                ".identity.pem.tmp.{}.{attempt}",
                std::process::id()
            ));
            std::fs::write(&tmp, b"taken").expect("seed taken temp");
        }

        let err = match publish_key_atomically(
            &key_path,
            pem.as_bytes(),
            &|| {},
            &|| {},
            PublishFaults::NONE,
        ) {
            Err(e) => e,
            Ok(_) => panic!("publish must fail when every temp name is taken"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!(".identity.pem.tmp.{}", std::process::id()))
                && msg.contains(&dir.path().display().to_string()),
            "the error must name the temp prefix and directory: {msg}"
        );
        assert!(
            !key_path.exists(),
            "an exhausted publish must not create or modify the final key"
        );
    }

    // A freshly created identity key must be 0600 immediately, with no
    // world-readable disclosure window (the atomic create_new(...).mode(0o600)
    // guarantee). This is the RED-then-GREEN anchor for the perms fix: the old
    // fs::write + set_permissions sequence left a 0644 window.
    #[test]
    fn created_key_is_mode_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let config = Config::parse_from([
            "gitlawb-node",
            "--key-path",
            key_path.to_str().expect("utf8 path"),
        ]);

        let _kp = load_or_create_keypair(&config).expect("create keypair");

        let mode = std::fs::metadata(&key_path)
            .expect("key file exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "identity key must be 0600, got {:o}",
            mode & 0o777
        );
    }

    // A lost create race (file already present) must load the existing key
    // rather than overwrite it, and must not error on AlreadyExists. Loading an
    // existing loose-permission key tightens it to 0600 defensively.
    #[test]
    fn existing_key_is_loaded_and_tightened() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let config = Config::parse_from([
            "gitlawb-node",
            "--key-path",
            key_path.to_str().expect("utf8 path"),
        ]);

        let first = load_or_create_keypair(&config).expect("create keypair");
        // Loosen perms to simulate a legacy/loose on-disk key.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen perms");

        let second = load_or_create_keypair(&config).expect("load keypair");
        assert_eq!(
            first.did(),
            second.did(),
            "reloading must return the same identity, not a new one"
        );

        let mode = std::fs::metadata(&key_path)
            .expect("key file exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "load path must tighten loose perms to 0600, got {:o}",
            mode & 0o777
        );
    }

    // The create-race arm the single-threaded tests skip (they enter via the
    // `exists()` fast path). N concurrent starts on ONE fresh path must converge
    // on a single identity: the atomic publish links exactly one winner and the
    // losers hit `AlreadyExists` and load the winner's key rather than overwriting
    // it. RED: replace the atomic publish with a plain `fs::write` and each thread
    // returns its own freshly generated key, so the DIDs diverge.
    #[test]
    fn concurrent_starts_converge_on_one_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let config = std::sync::Arc::new(Config::parse_from([
            "gitlawb-node",
            "--key-path",
            key_path.to_str().expect("utf8 path"),
        ]));

        let n = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let c = config.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    // Release all threads at once to maximize the race.
                    b.wait();
                    format!("{}", load_or_create_keypair(&c).expect("keypair").did())
                })
            })
            .collect();
        let dids: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().expect("thread joins"))
            .collect();

        let first = &dids[0];
        assert!(
            dids.iter().all(|d| d == first),
            "all concurrent starts must converge on one identity, got: {dids:?}"
        );
    }

    /// #194 (F1): a failed write of a just-created key file removes it, so a later
    /// start regenerates instead of re-parsing an empty/partial PEM forever and
    /// wedging on `invalid PEM key`. RED without the `remove_file` in
    /// `write_key_or_cleanup`: the partial file survives the error.
    #[test]
    fn failed_write_removes_the_partial_key_file() {
        use super::write_key_or_cleanup;
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        std::fs::write(&key_path, b"partial-pem").expect("seed partial file");
        assert!(key_path.exists());

        let err = std::io::Error::other("simulated ENOSPC");
        let r = write_key_or_cleanup(&key_path, Err(err));
        assert!(r.is_err(), "the write error must propagate");
        assert!(
            !key_path.exists(),
            "a failed first write must not leave a partial key file to wedge later starts"
        );
    }

    /// A successful write leaves the file in place (the common case).
    #[test]
    fn successful_write_keeps_the_key_file() {
        use super::write_key_or_cleanup;
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        std::fs::write(&key_path, b"good-pem").expect("seed file");
        assert!(write_key_or_cleanup(&key_path, Ok(())).is_ok());
        assert!(
            key_path.exists(),
            "a successful write leaves the file in place"
        );
    }

    /// #194 (F2): a loose (world/group-readable) key that cannot be tightened is
    /// rejected fail-closed rather than read and used exposed; a 0600 key is
    /// accepted. RED without `ensure_key_mode_0600`: a 0644 key is used silently.
    #[test]
    fn loose_key_mode_is_rejected_not_used() {
        use super::ensure_key_mode_0600;
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        std::fs::write(&key_path, b"key").expect("seed file");

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen perms");
        let err = ensure_key_mode_0600(&key_path)
            .expect_err("a world/group-readable key must be rejected")
            .to_string();
        assert!(
            err.contains("644"),
            "the failure must name the exposed mode: {err}"
        );

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("tighten perms");
        assert!(
            ensure_key_mode_0600(&key_path).is_ok(),
            "a 0600 key must be accepted"
        );
    }

    /// Shared body for the link-failure fallback tests: with the link step
    /// forced to fail with `kind`, the publish must fall back to a direct
    /// `create_new(0o600)` on the final path and win; the key must be 0600 and
    /// round-trip through the normal loader. RED without the fallback: the
    /// link error propagates and the start fails.
    fn assert_link_failure_falls_back(faults: PublishFaults) {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");

        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults)
            .expect("a failed hard_link must fall back to a direct publish, not fail the start");
        assert!(matches!(out, KeyPublish::Won), "fallback publish wins");

        let mode = std::fs::metadata(&key_path)
            .expect("key file exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "fallback-published key must be 0600, got {:o}",
            mode & 0o777
        );
        let loaded = super::load_existing_key(&key_path)
            .expect("fallback-published key loads via the normal loader");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "fallback publish must round-trip the same identity"
        );
    }

    // A key directory whose filesystem rejects hard links with EPERM (some
    // network/overlay mounts) must not brick a new node.
    #[test]
    fn permission_denied_link_falls_back_to_direct_create() {
        assert_link_failure_falls_back(PublishFaults {
            link: || Err(std::io::ErrorKind::PermissionDenied.into()),
            ..PublishFaults::NONE
        });
    }

    // A filesystem without hard-link support at all (Unsupported).
    #[test]
    fn unsupported_link_falls_back_to_direct_create() {
        assert_link_failure_falls_back(PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        });
    }

    // Link failure with the final ALREADY present must route to the lost-race
    // path: the fallback's create_new hits AlreadyExists, the existing key is
    // loaded, and it is never clobbered.
    #[test]
    fn link_failure_with_existing_final_loses_without_clobbering() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let winner = Keypair::generate();
        let pem_winner = winner.to_pem().expect("pem winner");
        let out = publish_key_atomically(
            &key_path,
            pem_winner.as_bytes(),
            &|| {},
            &|| {},
            PublishFaults::NONE,
        )
        .expect("winner publishes");
        assert!(matches!(out, KeyPublish::Won), "winner publish wins");

        let pem_loser = Keypair::generate().to_pem().expect("pem loser");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::PermissionDenied.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem_loser.as_bytes(), &|| {}, &|| {}, faults)
            .expect("an existing final must read as a lost race, not an error");
        assert!(
            matches!(out, KeyPublish::Lost),
            "fallback loses to the existing key"
        );
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().as_str(),
            pem_winner.as_str(),
            "the existing key must NOT be clobbered by the fallback"
        );
        let loaded = load_racing_key(&key_path).expect("lost race loads the winner");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", winner.did()),
            "the lost race must return the winner's identity"
        );
    }

    // Two concurrent publishers, both with the link step failing: the
    // fallback's create_new must admit exactly one winner and the loser must
    // converge on the winner's key (no-clobber survives the fallback path).
    #[test]
    fn concurrent_fallback_publishers_converge_on_one_winner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = std::sync::Arc::new(dir.path().join("identity.pem"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let kp = key_path.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    let me = Keypair::generate();
                    let pem = me.to_pem().expect("pem");
                    let faults = PublishFaults {
                        link: || Err(std::io::ErrorKind::Unsupported.into()),
                        ..PublishFaults::NONE
                    };
                    // Release both threads at once to maximize the race.
                    b.wait();
                    match publish_key_atomically(&kp, pem.as_bytes(), &|| {}, &|| {}, faults)
                        .expect("fallback publish")
                    {
                        KeyPublish::Won => (true, format!("{}", me.did())),
                        KeyPublish::Lost => (
                            false,
                            format!(
                                "{}",
                                load_racing_key(&kp).expect("loser loads winner").did()
                            ),
                        ),
                    }
                })
            })
            .collect();
        let results: Vec<(bool, String)> = handles
            .into_iter()
            .map(|h| h.join().expect("thread joins"))
            .collect();

        let winners = results.iter().filter(|(won, _)| *won).count();
        assert_eq!(
            winners, 1,
            "exactly one fallback create_new must win, got {results:?}"
        );
        assert_eq!(
            results[0].1, results[1].1,
            "the loser must converge on the winner's identity: {results:?}"
        );
    }

    // A failed fallback WRITE leaves the partial final AND its marker in
    // place: the pair is exactly the crash state boot-time recovery handles
    // (claim, quarantine, regenerate), while an unlink here is a
    // stat-then-unlink race against a recovery that already claimed this
    // round and republished a live key at the name, and a marker disposed
    // beside a kept partial final recreates the marker-less wedge the
    // bracket exists to prevent. The error must surface the write failure
    // AND the original link error, so a two-step failure is diagnosable.
    #[test]
    fn failed_fallback_write_leaves_the_partial_final_for_recovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_write: || Err(std::io::Error::other("injected write failure")),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("a failed fallback write must error the start"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("injected write failure"),
            "the error must surface the write failure: {msg}"
        );
        let link_display = std::io::Error::from(std::io::ErrorKind::Unsupported).to_string();
        assert!(
            msg.contains(&link_display),
            "the error must chain the original link failure ({link_display}): {msg}"
        );
        assert!(
            key_path.exists(),
            "a failed fallback write must leave the partial final for boot-time recovery"
        );
        assert!(
            std::fs::read(&key_path)
                .expect("read partial final")
                .is_empty(),
            "the write fault fires before any byte lands, so the partial final is empty"
        );
    }

    // A non-AlreadyExists error from the fallback's create_new open of the
    // final path must surface, chained with the original link error, so a
    // two-step failure (link failed, then the direct create also failed) is
    // diagnosable. RED without the gate wired: the injected open error never
    // reaches the real open, so the publish succeeds instead of erroring.
    #[test]
    fn failed_fallback_create_surfaces_the_open_error_and_chains_link_err() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_create: || Err(std::io::Error::other("injected fallback create failure")),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("a failed fallback create must error the start"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("injected fallback create failure"),
            "the error must surface the fallback create failure: {msg}"
        );
        let link_display = std::io::Error::from(std::io::ErrorKind::Unsupported).to_string();
        assert!(
            msg.contains(&link_display),
            "the error must chain the original link failure ({link_display}): {msg}"
        );
        assert!(
            !key_path.exists(),
            "a failed fallback create must not leave the final key"
        );
    }

    // A failed fallback FILE fsync takes the same keep-everything exit as
    // the failed write: the final (complete but possibly non-durable bytes)
    // and its marker stay in place for boot-time recovery. The
    // complete-but-unsynced state is safe because a later healthy load
    // fsyncs the final ITSELF before sweeping the marker
    // (sweep_stale_markers' durability gate), and a crash before then
    // re-enters recovery via the surviving marker.
    #[test]
    fn failed_fallback_fsync_leaves_the_final_for_recovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_fsync: || Err(std::io::Error::other("injected fsync failure")),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("a failed fallback fsync must error the start"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("injected fsync failure"),
            "the error must surface the fsync failure: {msg}"
        );
        assert!(
            key_path.exists(),
            "an fsync failure must leave the final in place for boot-time recovery"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("read final"),
            pem.as_bytes(),
            "the fsync fault fires after write_all, so the final holds the full PEM"
        );
    }

    // #194: the fallback path can leave a durable empty/truncated final if a
    // crash lands between the name becoming durable and the PEM fsync (the
    // reconditioned KEY_RACE_DEADLINE / publish_key_atomically doc). This
    // observes the promised behavior at the next start: such a residue must
    // fail LOUDLY (an invalid-PEM parse error, or a mode rejection), never
    // parse as Ok and never be replaced by a freshly generated key. This is a
    // characterization/observation test of behavior that already exists, not a
    // RED-first guard: it passes on current code.
    #[test]
    fn fallback_crash_residue_fails_loudly_not_silently() {
        use super::{ensure_key_mode_0600, load_existing_key};
        let dir = tempfile::tempdir().expect("tempdir");

        // (1) an empty final at 0600 (durable name, no PEM bytes yet).
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, b"").expect("seed empty final");
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600))
            .expect("0600 empty");
        let err = match load_existing_key(&empty) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an empty final must fail loudly, not parse as Ok"),
        };
        assert!(
            err.contains("invalid PEM"),
            "an empty final must surface a parse error, got: {err}"
        );

        // (2) a truncated/garbage non-PEM final at 0600.
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, b"-----BEGIN nonsense truncated").expect("seed garbage final");
        std::fs::set_permissions(&garbage, std::fs::Permissions::from_mode(0o600))
            .expect("0600 garbage");
        let err = match load_existing_key(&garbage) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a truncated final must fail loudly, not parse as Ok"),
        };
        assert!(
            err.contains("invalid PEM"),
            "a truncated final must surface a parse error, got: {err}"
        );

        // (3) mode-rejection path: an empty final at 0400. The loader tightens a
        // loose mode where the mount allows it, so the reachable rejection is
        // `ensure_key_mode_0600` failing closed on a mode it cannot narrow (a
        // mode-ignoring mount); assert that branch directly on a 0400 file.
        let loose = dir.path().join("loose.pem");
        std::fs::write(&loose, b"").expect("seed loose final");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o400))
            .expect("0400 loose");
        let err = ensure_key_mode_0600(&loose)
            .expect_err("a non-0600 final must be rejected, not used exposed")
            .to_string();
        assert!(
            err.contains("400"),
            "the mode rejection must name the exposed mode, got: {err}"
        );
    }

    /// Env var carrying `mask:site` for `umask_worker_publish_lands_0600`.
    const UMASK_WORKER_ENV: &str = "GITLAWB_TEST_UMASK_CASE";

    /// Spawns this test binary again, running only the ignored umask worker
    /// with `mask:site` in the environment. The umask is process-global, so
    /// setting it in the shared test process narrows every concurrent test's
    /// file and tempdir creation modes (observed: a parallel test's fresh
    /// tempdir landing dr-x------ and its file create failing EACCES). A
    /// child process that runs nothing but the one case confines the mask.
    fn run_umask_case(mask: &str, site: &str) {
        let exe = std::env::current_exe().expect("test binary path");
        let out = std::process::Command::new(exe)
            .args([
                "identity_key_tests::umask_worker_publish_lands_0600",
                "--exact",
                "--ignored",
            ])
            .env(UMASK_WORKER_ENV, format!("{mask}:{site}"))
            .output()
            .expect("spawn umask worker");
        let stdout = String::from_utf8_lossy(&out.stdout);
        // status alone is not enough: a drifted worker name would match zero
        // tests and still exit 0, a vacuous green.
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "umask {mask} {site} worker did not pass:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// In-child body of the umask tests: never runs in the shared suite
    /// process (ignored without the spawning tests' env var). Publishes under
    /// the given umask and asserts the key lands 0600 and round-trips. The
    /// mode assertion runs BEFORE the loader call, which would otherwise
    /// tighten a loose key itself and mask a publish-site regression.
    #[test]
    #[ignore = "umask worker: spawned in a child process by the umask_* tests"]
    fn umask_worker_publish_lands_0600() {
        let Ok(spec) = std::env::var(UMASK_WORKER_ENV) else {
            // A manual `--ignored` sweep without the env var: nothing to do.
            return;
        };
        let (mask_str, site) = spec.split_once(':').expect("spec is mask:site");
        let mask = libc::mode_t::from_str_radix(mask_str, 8).expect("octal mask");
        let faults = match site {
            "hardlink" => PublishFaults::NONE,
            "fallback" => PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                ..PublishFaults::NONE
            },
            other => panic!("unknown umask worker site {other:?}"),
        };

        // The tempdir is created BEFORE the mask narrows, as a deploy's key
        // directory predates the process umask; 0277 would land the dir
        // itself 0400. No restore: this process exists only for this case.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");
        unsafe { libc::umask(mask) };

        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults)
            .expect("publish must succeed: the tighten repairs the umask-narrowed create mode");
        assert!(matches!(out, KeyPublish::Won), "publish wins");

        let mode = std::fs::metadata(&key_path)
            .expect("key file exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "under umask {mask:o} the published key must land 0600, got {:o}",
            mode & 0o777
        );
        let loaded = super::load_existing_key(&key_path).expect("loader accepts the key");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "publish under umask {mask:o} must round-trip the same identity"
        );
    }

    /// #194 (U2): `create_new`'s requested 0600 is narrowed by the process
    /// umask, so 0277 lands the file 0400; the tighten half of the
    /// tighten-then-verify pair must repair it to 0600 (the verify alone
    /// would falsely fail closed). Hard-link site. Pre-state note: before
    /// U2 this publish already SUCCEEDED but left the key 0400 on disk, so
    /// the mode assertion is what was RED.
    #[test]
    fn umask_0277_hardlink_publish_is_repaired_to_0600() {
        run_umask_case("277", "hardlink");
    }

    /// Same repair, at the fallback creation site (link forced to fail).
    #[test]
    fn umask_0277_fallback_publish_is_repaired_to_0600() {
        run_umask_case("277", "fallback");
    }

    /// #194 (U2): a permissive umask stays healthy: 0600 is already 0600 under
    /// 0077, the tighten is a no-op, and the verify must not disturb a clean
    /// publish. (`created_key_is_mode_0600` pins the suite's ambient umask;
    /// these pin the boundary values explicitly.) Split per-umask so a
    /// 0000-specific regression is not masked by a 0077 failure.
    #[test]
    fn permissive_umask_0077_still_publishes_0600() {
        run_umask_case("077", "hardlink");
    }

    /// #194 (U2): the fully permissive umask 0000 stays healthy too — 0600 is
    /// already 0600, the tighten is a no-op, and the verify must not disturb a
    /// clean publish.
    #[test]
    fn permissive_umask_0000_still_publishes_0600() {
        run_umask_case("000", "hardlink");
    }

    /// #194 (U2): on a mode-ignoring mount (vfat: chmod silently no-ops) the
    /// 0600 verification of the just-created TEMP file must fail the publish
    /// CLOSED, BEFORE any PEM byte is written. Afterwards the key directory
    /// must be empty: the final never appeared, and the empty temp was
    /// removed so a retry is not wedged. The error must name the temp file
    /// and surface the verify failure.
    #[test]
    fn forced_temp_mode_verify_failure_fails_closed_before_any_pem_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let faults = PublishFaults {
            temp_mode_verify: || Err(std::io::Error::other("injected mode-ignoring mount")),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("an unverifiable temp mode must fail the publish closed"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("injected mode-ignoring mount") && msg.contains(".identity.pem.tmp."),
            "the error must surface the verify failure and name the temp file: {msg}"
        );
        assert!(!key_path.exists(), "the final key must never appear");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no PEM byte may hit disk and the empty temp must be removed: {leftovers:?}"
        );
    }

    /// #194 (U2): the same fail-closed check at the FALLBACK creation site
    /// (link fault + verify fault). The just-created EMPTY final must be
    /// removed, no PEM byte may have hit it, the error must chain the
    /// original link failure, and a subsequent retry on a healthy mount must
    /// publish cleanly rather than wedge on AlreadyExists.
    #[test]
    fn forced_fallback_mode_verify_failure_removes_the_empty_final() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_mode_verify: || Err(std::io::Error::other("injected mode-ignoring mount")),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("an unverifiable final mode must fail the publish closed"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("injected mode-ignoring mount") && msg.contains("identity.pem"),
            "the error must surface the verify failure and name the final: {msg}"
        );
        let link_display = std::io::Error::from(std::io::ErrorKind::Unsupported).to_string();
        assert!(
            msg.contains(&link_display),
            "the error must chain the original link failure ({link_display}): {msg}"
        );
        assert!(
            !key_path.exists(),
            "the empty final must be removed so a retry is not wedged"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        assert!(
            leftovers.is_empty(),
            "nothing may remain on disk after the fail-closed publish: {leftovers:?}"
        );

        // The removal is what un-wedges the retry: after a remount (or on a
        // start whose chmod works) the same path must publish cleanly.
        let retry_faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, retry_faults)
            .expect("a retry after the fail-closed publish must not be wedged");
        assert!(matches!(out, KeyPublish::Won), "retry wins cleanly");
        let loaded = super::load_existing_key(&key_path).expect("retried key loads");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "the retry must publish the intended identity"
        );
    }

    /// Lists leftover `.{stem}.publishing.*` marker files in `dir` (#194, U1).
    fn publishing_markers(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().contains(".publishing."))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// #194 (U1): a successful fallback publish (link forced to fail) must win,
    /// round-trip the key through the normal loader, and leave NO publish
    /// marker behind: the marker exists only for the non-atomic window.
    #[test]
    fn fallback_publish_succeeds_and_leaves_no_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults)
            .expect("fallback publish");
        assert!(matches!(out, KeyPublish::Won), "fallback publish wins");
        let loaded = super::load_existing_key(&key_path).expect("published key loads");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "fallback publish must round-trip the same identity"
        );
        let markers = publishing_markers(dir.path());
        assert!(
            markers.is_empty(),
            "a successful fallback publish must remove its marker, found {markers:?}"
        );
    }

    /// #194 (U1): a fallback that loses the create race (final already present)
    /// must still behave as today (existing key loaded, never clobbered) and
    /// must remove its own marker on the lost-race exit.
    #[test]
    fn lost_fallback_race_leaves_no_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let winner = Keypair::generate();
        let pem_winner = winner.to_pem().expect("pem winner");
        let out = publish_key_atomically(
            &key_path,
            pem_winner.as_bytes(),
            &|| {},
            &|| {},
            PublishFaults::NONE,
        )
        .expect("winner publishes");
        assert!(matches!(out, KeyPublish::Won), "winner publish wins");

        let pem_loser = Keypair::generate().to_pem().expect("pem loser");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::PermissionDenied.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem_loser.as_bytes(), &|| {}, &|| {}, faults)
            .expect("an existing final must read as a lost race, not an error");
        assert!(matches!(out, KeyPublish::Lost), "fallback loses");
        let loaded = load_racing_key(&key_path).expect("lost race loads the winner");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", winner.did()),
            "the lost race must return the winner's identity"
        );
        let markers = publishing_markers(dir.path());
        assert!(
            markers.is_empty(),
            "a lost fallback race must remove its own marker, found {markers:?}"
        );
    }

    /// Shared body for the PRE-write fallback error arms (#194, U1): with the
    /// link fault plus one injected fallback fault, the error must surface as
    /// today, the final must be absent (nothing recoverable exists before the
    /// first PEM byte, so those arms remove it), and no publish marker may
    /// remain. The POST-write arms (write/fsync) have the opposite contract;
    /// see `assert_post_write_failure_leaves_marker_and_final`.
    fn assert_fallback_error_leaves_no_marker_or_final(faults: PublishFaults, injected: &str) {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("the injected fallback fault must error the publish"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(injected),
            "the error must surface the injected fault: {msg}"
        );
        assert!(
            !key_path.exists(),
            "the final must be absent per the existing removal policy"
        );
        let markers = publishing_markers(dir.path());
        assert!(
            markers.is_empty(),
            "an errored fallback must dispose its marker, found {markers:?}"
        );
    }

    #[test]
    fn failed_fallback_create_leaves_no_marker() {
        assert_fallback_error_leaves_no_marker_or_final(
            PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                fallback_create: || Err(std::io::Error::other("injected fallback create failure")),
                ..PublishFaults::NONE
            },
            "injected fallback create failure",
        );
    }

    /// Shared body for the POST-write fallback error arms (write/fsync): the
    /// error must surface the injected fault AND name the boot-time recovery
    /// handoff, the final must SURVIVE, and its `.publishing.` marker must
    /// SURVIVE beside it: marker+final together is the recoverable crash
    /// state, and marker-less partial final is the permanent wedge.
    fn assert_post_write_failure_leaves_marker_and_final(faults: PublishFaults, injected: &str) {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("the injected fallback fault must error the publish"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(injected),
            "the error must surface the injected fault: {msg}"
        );
        assert!(
            msg.contains("left in place for boot-time crash recovery"),
            "the error must name the recovery handoff: {msg}"
        );
        assert!(
            key_path.exists(),
            "the final must survive a post-write failure for boot-time recovery"
        );
        let markers = publishing_markers(dir.path());
        assert_eq!(
            markers.len(),
            1,
            "the marker must survive to vouch for the partial final, found {markers:?}"
        );
    }

    #[test]
    fn failed_fallback_write_leaves_the_marker_and_final() {
        assert_post_write_failure_leaves_marker_and_final(
            PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                fallback_write: || Err(std::io::Error::other("injected write failure")),
                ..PublishFaults::NONE
            },
            "injected write failure",
        );
    }

    #[test]
    fn failed_fallback_fsync_leaves_the_marker_and_final() {
        assert_post_write_failure_leaves_marker_and_final(
            PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                fallback_fsync: || Err(std::io::Error::other("injected fsync failure")),
                ..PublishFaults::NONE
            },
            "injected fsync failure",
        );
    }

    // The handoff the post-write arms promise must actually work: take the
    // exact state a failed fallback write leaves behind (partial final plus
    // its marker) and run a fresh boot over it. The boot must classify the
    // crash signature, claim the marker, quarantine the partial final, and
    // regenerate: no wedge, no leftover marker or claim.
    #[test]
    fn post_write_failure_state_is_recoverable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_write: || Err(std::io::Error::other("injected write failure")),
            ..PublishFaults::NONE
        };
        if publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults).is_ok() {
            panic!("the injected write fault must error the publish");
        }
        assert!(
            key_path.exists() && publishing_markers(dir.path()).len() == 1,
            "precondition: the failed publish leaves final plus marker"
        );

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("the left-behind crash state must recover, not wedge the start");

        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "the partial final must be quarantined: {quarantined:?}"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "recovery must consume the publish marker"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the recovery claim must be released"
        );
    }

    #[test]
    fn failed_fallback_mode_verify_leaves_no_marker() {
        assert_fallback_error_leaves_no_marker_or_final(
            PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                fallback_mode_verify: || Err(std::io::Error::other("injected mode-ignoring mount")),
                ..PublishFaults::NONE
            },
            "injected mode-ignoring mount",
        );
    }

    /// #194 (U1): marker-name probing is bounded like the temp names. With
    /// every candidate marker name taken the fallback must fail loudly, naming
    /// the stale prefix and directory, and must never create the final.
    #[test]
    fn marker_name_exhaustion_errors_loudly_and_never_creates_the_final() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        for attempt in 0..KEY_TEMP_ATTEMPTS {
            let stale = dir.path().join(format!(
                ".identity.pem.publishing.{}.{attempt}",
                std::process::id()
            ));
            std::fs::write(&stale, b"").expect("seed stale marker");
        }

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("the fallback must fail when every marker name is taken"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(&format!(".identity.pem.publishing.{}", std::process::id()))
                && msg.contains(&dir.path().display().to_string()),
            "the error must name the marker prefix and directory: {msg}"
        );
        assert!(
            !key_path.exists(),
            "an exhausted marker probe must not create the final key"
        );
    }

    /// #194 (U1): a failed marker DIR fsync must NOT fail the publish
    /// (warn-and-continue): on dir-fsync-hostile mounts a hard gate would turn
    /// "wedge once then recover" into "never provisions". The publish must
    /// still win, the key must load, and the marker must still be removed.
    #[test]
    fn marker_fsync_failure_does_not_fail_the_publish() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            marker_fsync: || Err(std::io::Error::other("injected marker dir fsync failure")),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults)
            .expect("a marker dir fsync failure must not fail the publish");
        assert!(matches!(out, KeyPublish::Won), "publish still wins");
        let loaded = super::load_existing_key(&key_path).expect("published key loads");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "publish must round-trip the same identity"
        );
        let markers = publishing_markers(dir.path());
        assert!(
            markers.is_empty(),
            "the marker must still be removed, found {markers:?}"
        );
    }

    /// #194 (U1): the primary hard-link path must never touch the marker
    /// machinery. The `marker_create` hook is poisoned, so if the primary path
    /// ever created a marker the publish would error; it must win untouched
    /// and leave no `.publishing.` file.
    #[test]
    fn primary_hardlink_publish_never_creates_a_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");

        let faults = PublishFaults {
            marker_create: || Err(std::io::Error::other("marker created on the primary path")),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults)
            .expect("the primary path must never reach the marker machinery");
        assert!(matches!(out, KeyPublish::Won), "primary publish wins");
        let loaded = super::load_existing_key(&key_path).expect("published key loads");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "primary publish must round-trip the same identity"
        );
        let markers = publishing_markers(dir.path());
        assert!(
            markers.is_empty(),
            "the primary path must never create a marker, found {markers:?}"
        );
    }

    /// Seed the on-disk signature of a fallback publish crashed mid-write
    /// (#194, U2): a 0600 final holding `content` (empty or truncated) beside
    /// a `.publishing.` marker carrying a foreign (crashed) process's pid.
    /// Returns the final's path.
    fn seed_crash_state(dir: &std::path::Path, content: &[u8]) -> std::path::PathBuf {
        let key_path = dir.join("identity.pem");
        std::fs::write(&key_path, content).expect("seed crashed final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 crashed final");
        std::fs::write(dir.join(".identity.pem.publishing.99999.0"), b"")
            .expect("seed publish marker");
        key_path
    }

    /// Set `path`'s mtime `spec` into the past via GNU `touch -d` (std::fs
    /// cannot set arbitrary mtimes; spawning coreutils is test-only).
    fn set_mtime_past(path: &std::path::Path, spec: &str) {
        let status = std::process::Command::new("touch")
            .arg("-d")
            .arg(spec)
            .arg(path)
            .status()
            .expect("run touch -d");
        assert!(status.success(), "touch -d must succeed to age {path:?}");
    }

    /// Set `path`'s mtime an hour into the past, far beyond
    /// `CLAIM_SWEEP_MIN_AGE`.
    fn age_beyond_claim_sweep(path: &std::path::Path) {
        set_mtime_past(path, "1 hour ago");
    }

    /// File names in `dir` containing `needle` (marker/claim/quarantine sweeps).
    fn names_containing(dir: &std::path::Path, needle: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(needle))
            .collect();
        names.sort();
        names
    }

    fn key_config(key_path: &std::path::Path) -> Config {
        Config::parse_from([
            "gitlawb-node",
            "--key-path",
            key_path.to_str().expect("utf8 path"),
        ])
    }

    // #194 (U2): a `.publishing.` marker beside an EMPTY final is the crash
    // signature of an interrupted fallback publish; boot must claim the
    // marker, quarantine the empty final, and regenerate instead of wedging
    // on `invalid PEM key` forever. RED before U2: load_or_create_keypair
    // errors with `invalid PEM key`.
    #[test]
    fn recovery_regenerates_after_crash_leaves_empty_final() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");

        let started = std::time::Instant::now();
        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a crash-marked empty final must recover, not wedge the start");
        let elapsed = started.elapsed();
        // The crash signature short-circuits after two ~2ms polls; 2s is
        // generous for CI machines yet far under the 5s KEY_RACE_DEADLINE a
        // deadline-riding load would burn before recovery could even start.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "recovery must short-circuit on the crash signature, not ride \
             KEY_RACE_DEADLINE: took {elapsed:?}"
        );

        let mode = std::fs::metadata(&key_path)
            .expect("regenerated final exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "regenerated final must be 0600");
        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "recovery must consume the publish marker(s)"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the recovery claim must be removed after the publish resolves"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "exactly one quarantine file must exist: {quarantined:?}"
        );
        let bytes = std::fs::read(dir.path().join(&quarantined[0])).expect("read quarantine");
        assert!(
            bytes.is_empty(),
            "the quarantine must preserve the crashed final's (empty) content"
        );
    }

    // #194 (U2): same recovery for a final holding a truncated PEM, and the
    // quarantine (a rename) must preserve the truncated bytes exactly for
    // post-mortem inspection.
    #[test]
    fn recovery_quarantines_truncated_final_preserving_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pem = Keypair::generate().to_pem().expect("pem");
        let truncated = &pem.as_bytes()[..pem.len() / 2];
        let key_path = seed_crash_state(dir.path(), truncated);

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a crash-marked truncated final must recover, not wedge the start");

        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "exactly one quarantine file must exist: {quarantined:?}"
        );
        let bytes = std::fs::read(dir.path().join(&quarantined[0])).expect("read quarantine");
        assert_eq!(
            bytes, truncated,
            "the quarantine must hold exactly the truncated input bytes"
        );
    }

    // #194 (U2): quarantine-name probing is bounded like the temp and marker
    // names. With EVERY candidate quarantine name taken, recovery must fall
    // back to REMOVING the corrupt final (not rename it, not clobber a stale
    // quarantine) and still regenerate successfully. Sentinel bytes in each
    // stale quarantine prove no rename landed. Load-bearing by mutation
    // check: with the remove_file fallback disabled, the corrupt final
    // survives, the retry publish loses to it, and the boot fails loudly.
    #[test]
    fn quarantine_exhaustion_falls_back_to_removal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        for n in 0..KEY_TEMP_ATTEMPTS {
            let stale = dir.path().join(format!(
                ".identity.pem.quarantined.{}.{n}",
                std::process::id()
            ));
            std::fs::write(&stale, b"sentinel").expect("seed stale quarantine");
        }

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("an exhausted quarantine probe must fall back to removal, not wedge");

        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            KEY_TEMP_ATTEMPTS as usize,
            "the final must be removed, not quarantined under a fresh name: {quarantined:?}"
        );
        for name in &quarantined {
            let bytes = std::fs::read(dir.path().join(name)).expect("read stale quarantine");
            assert_eq!(
                bytes, b"sentinel",
                "no stale quarantine may be clobbered by a rename: {name}"
            );
        }
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "recovery must consume the publish marker(s)"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the recovery claim must be released after the publish resolves"
        );
    }

    // #194 (U2/F1): with every quarantine name taken AND removal blocked,
    // recovery must surface the loud chained error, never a silent success.
    // The dir turns read-only via the before_reparse seam (after the claim
    // rename lands; a dir made read-only up front would fail the claim step
    // and never reach the quarantine arm at all). The same read-only dir
    // necessarily blocks the claim release too, so phase two restores
    // permissions and proves the leftover claim is itself recoverable (F3):
    // the next boot claims it, removes the final, and regenerates cleanly.
    #[test]
    fn quarantine_and_removal_both_blocked_errors_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        for n in 0..KEY_TEMP_ATTEMPTS {
            let stale = dir.path().join(format!(
                ".identity.pem.quarantined.{}.{n}",
                std::process::id()
            ));
            std::fs::write(&stale, b"sentinel").expect("seed stale quarantine");
        }
        let lock_path = dir.path().to_path_buf();
        let lock_dir = move || {
            std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o555))
                .expect("read-only key dir inside the claim window");
        };
        let seam = RecoverySeam {
            before_reparse: &lock_dir,
            ..RecoverySeam::NONE
        };

        let result =
            load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam);

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("restore key dir");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("a blocked quarantine AND removal must fail loudly, not resolve"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not quarantine or remove")
                && msg.contains(&key_path.display().to_string())
                && msg.contains("invalid PEM key"),
            "the error must chain the recovery failure and the load failure: {msg}"
        );
        assert!(
            key_path.exists(),
            "the corrupt final must survive for post-mortem when nothing can dispose of it"
        );

        // Phase two: the claim left behind (the read-only dir blocked its
        // release too) must make the state recoverable, not wedge it. F2
        // makes a fresh claim invisible to recovery (it could gate a LIVE
        // round), so age the leftovers past the floor first, standing in for
        // the bounded wait a real next boot would incur.
        for name in names_containing(dir.path(), ".recovering.") {
            age_beyond_claim_sweep(&dir.path().join(name));
        }
        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("the leftover claim must be claimable by the next boot, not a wedge");
        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the follow-up boot must consume and release every claim"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            KEY_TEMP_ATTEMPTS as usize,
            "the follow-up boot must also fall back to removal: {quarantined:?}"
        );
    }

    // MUST-NOT (#194, U2): an unparseable final WITHOUT a marker is operator
    // corruption, not a crash signature; it must keep today's loud fail
    // bit-for-bit: same `invalid PEM key` message, final left on disk with
    // identical bytes, no quarantine, no regeneration. Rides the full
    // KEY_RACE_DEADLINE (~5s), as today. Pre-implementation this must PASS;
    // after GREEN it is the mutation guard for the marker-presence check.
    #[test]
    fn bad_final_without_marker_still_fails_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let garbage: &[u8] = b"-----BEGIN nonsense truncated";
        std::fs::write(&key_path, garbage).expect("seed garbage final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 garbage final");

        let err = match load_or_create_keypair(&key_config(&key_path)) {
            Err(e) => e,
            Ok(_) => panic!("a marker-less corrupt final must fail loudly, never regenerate"),
        };
        assert!(
            err.to_string().contains("invalid PEM key"),
            "the load failure must surface unchanged: {err:#}"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("final still on disk"),
            garbage,
            "the corrupt final must be left untouched"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "no quarantine may be created without a marker"
        );
    }

    // MUST-NOT (#194, U2): a VALID final beside a stale marker loads
    // unchanged: same identity, same bytes, no quarantine. (U4 adds marker
    // hygiene; U2 may leave the stale marker in place.)
    #[test]
    fn valid_final_with_stale_marker_loads_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let existing = Keypair::generate();
        let pem = existing.to_pem().expect("pem");
        let key_path = seed_crash_state(dir.path(), pem.as_bytes());

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a valid final with a stale marker must load");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", existing.did()),
            "the pre-existing identity must be preserved, not regenerated"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("final still on disk"),
            pem.as_bytes(),
            "the valid final's bytes must be untouched"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "a valid final must never be quarantined"
        );
    }

    // MUST-NOT (#194, U2): a TRANSIENT (non-content) load failure must never
    // recover, even with a marker present: loud error, no quarantine, final
    // and marker untouched. The seam's load fault injects the transient class
    // deterministically. Rides the full KEY_RACE_DEADLINE (~5s). RED if
    // recovery keys on any-error instead of content-class.
    #[test]
    fn transient_error_with_marker_never_recovers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pem = Keypair::generate().to_pem().expect("pem");
        let key_path = seed_crash_state(dir.path(), pem.as_bytes());
        let seam = RecoverySeam {
            load_fault: || Err(std::io::Error::other("injected transient load failure")),
            ..RecoverySeam::NONE
        };

        let err =
            match load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            {
                Err(e) => e,
                Ok(_) => panic!("a transient-class load failure must stay loud, never recover"),
            };
        assert!(
            format!("{err:#}").contains("injected transient load failure"),
            "the transient failure must surface: {err:#}"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("final still on disk"),
            pem.as_bytes(),
            "the final must be untouched by a transient failure"
        );
        assert_eq!(
            names_containing(dir.path(), ".publishing."),
            vec![".identity.pem.publishing.99999.0".to_string()],
            "the marker must be untouched"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "a transient failure must never quarantine"
        );
    }

    // #194 (U2): recovery runs AT MOST ONCE per start. After the first
    // recovery completes, the seam re-plants a crash state (marker + empty
    // final) before the retry publish; the second load failure must surface
    // as an error, not recover again. Exactly one quarantine, from the first
    // pass. Rides the full KEY_RACE_DEADLINE (~5s) on the second load.
    #[test]
    fn recovery_runs_at_most_once_per_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let replanted = std::sync::atomic::AtomicBool::new(false);
        let replant_path = key_path.clone();
        let replant_marker = dir.path().join(".identity.pem.publishing.88888.0");
        let before_publish = move || {
            if !replanted.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::fs::write(&replant_marker, b"").expect("re-plant marker");
                std::fs::write(&replant_path, b"").expect("re-plant empty final");
                std::fs::set_permissions(&replant_path, std::fs::Permissions::from_mode(0o600))
                    .expect("0600 re-planted final");
            }
        };
        let seam = RecoverySeam {
            before_publish: &before_publish,
            ..RecoverySeam::NONE
        };

        let err =
            match load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            {
                Err(e) => e,
                Ok(_) => {
                    panic!("a second crash state in the same start must error, not recover again")
                }
            };
        assert!(
            err.to_string().contains("invalid PEM key"),
            "the second load failure must surface unchanged: {err:#}"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "exactly one quarantine, from the first recovery: {quarantined:?}"
        );
    }

    // #194 (U2): two concurrent boots against the same crash state must admit
    // exactly ONE recoverer (the atomic claim rename arbitrates); both end on
    // the SAME identity, one quarantine, no markers or claims left behind.
    // Modeled on concurrent_starts_converge_on_one_identity.
    #[test]
    fn claim_race_admits_exactly_one_recoverer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let config = std::sync::Arc::new(key_config(&key_path));

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let c = config.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    format!(
                        "{}",
                        load_or_create_keypair(&c).expect("recovering start").did()
                    )
                })
            })
            .collect();
        let dids: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().expect("thread joins"))
            .collect();

        assert_eq!(
            dids[0], dids[1],
            "both concurrent recovering starts must converge on one identity"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "exactly one recoverer must quarantine: {quarantined:?}"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "no recovery claims may remain"
        );
    }

    // #194 (U2): the Lost arm participates in recovery. The publisher's link
    // is forced to fail (fallback path) and the crash state (foreign marker +
    // empty final) appears between the temp write and the link, so the
    // publish loses to the crashed final; the Lost-arm load must then take
    // the recovery path and regenerate.
    #[test]
    fn lost_race_load_failure_takes_recovery_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let planted = std::sync::atomic::AtomicBool::new(false);
        let plant_path = key_path.clone();
        let plant_marker = dir.path().join(".identity.pem.publishing.77777.0");
        let before_link = move || {
            if !planted.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::fs::write(&plant_marker, b"").expect("plant marker");
                std::fs::write(&plant_path, b"").expect("plant empty final");
                std::fs::set_permissions(&plant_path, std::fs::Permissions::from_mode(0o600))
                    .expect("0600 planted final");
            }
        };
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };

        let kp = load_or_create_keypair_with(
            &key_path,
            &before_link,
            &|| {},
            faults,
            RecoverySeam::NONE,
        )
        .expect("a lost race onto a crash-state final must recover, not fail the start");

        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "exactly one quarantine file must exist: {quarantined:?}"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "no recovery claims may remain"
        );
    }

    // #194 (U3): THE divergence race. A fallback winner whose final is already
    // durable but which stalls before removing its marker can have its round
    // stolen by a recovering peer: the peer claims the winner's marker,
    // quarantines the winner's final, and republishes key B. The winner's
    // OWN-MARKER removal is the commit check; losing it must demote the winner
    // to Lost so it converges on B, never returning Won with key A while disk
    // holds B. RED before U3: the publish returns Won with the quarantined key
    // A while the final holds B (two-sided divergence).
    #[test]
    fn stalled_winner_demotes_when_recovery_claims_its_round() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp_b = Keypair::generate();
        let pem_b = kp_b.to_pem().expect("pem b");

        let fired = std::sync::atomic::AtomicBool::new(false);
        let steal_dir = dir.path().to_path_buf();
        let steal_path = key_path.clone();
        let before_commit = move || {
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            // A full concurrent recovery inside A's stall window (post
            // final-fsync, pre commit check), step for step what
            // recover_crashed_publish does: claim A's marker by rename,
            // quarantine A's final, republish key B, clear the claim.
            let markers = names_containing(&steal_dir, ".publishing.");
            assert_eq!(
                markers.len(),
                1,
                "A's window must be bracketed: {markers:?}"
            );
            let claim = steal_dir.join(".identity.pem.recovering.55555");
            std::fs::rename(steal_dir.join(&markers[0]), &claim).expect("claim A's marker");
            std::fs::rename(
                &steal_path,
                steal_dir.join(".identity.pem.quarantined.55555.0"),
            )
            .expect("quarantine A's final");
            let out = publish_key_atomically(
                &steal_path,
                pem_b.as_bytes(),
                &|| {},
                &|| {},
                PublishFaults::NONE,
            )
            .expect("peer republishes key B");
            assert!(matches!(out, KeyPublish::Won), "peer's republish wins");
            std::fs::remove_file(&claim).expect("clear the claim");
        };
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };

        let kp = load_or_create_keypair_with(
            &key_path,
            &|| {},
            &before_commit,
            faults,
            RecoverySeam::NONE,
        )
        .expect("a demoted winner must converge, not fail the start");

        let on_disk = super::load_existing_key(&key_path).expect("final parses");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", kp_b.did()),
            "the demoted winner must converge on the recovering peer's key B"
        );
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp_b.did()),
            "the final must hold key B"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "no recovery claims may remain"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "exactly one live identity: A's old final stays quarantined: {quarantined:?}"
        );
    }

    // #194 (U3): with no interference the commit check is invisible. The
    // winner removes its own marker, returns Won, and behaves exactly as U1's
    // success test: the key round-trips and no marker is left. Also pins that
    // the pre-commit seam runs on the fallback success path.
    #[test]
    fn winner_commits_first_without_interference() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");

        let fired = std::sync::atomic::AtomicBool::new(false);
        let before_commit = || {
            fired.store(true, std::sync::atomic::Ordering::SeqCst);
        };
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &before_commit, faults)
            .expect("uncontended fallback publish");
        assert!(
            matches!(out, KeyPublish::Won),
            "the uncontended winner commits and wins"
        );
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the pre-commit seam must run on the fallback success path"
        );
        let loaded = super::load_existing_key(&key_path).expect("published key loads");
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "the committed publish must round-trip the same identity"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no marker may remain after commit"
        );
    }

    // #194 (U3): a recovery attempt arriving AFTER the winner committed finds
    // no marker to claim and must abort into a plain re-load: no quarantine,
    // the winner's identity returned. Honest scope: recover_crashed_publish
    // is invoked directly with a synthetic load error, the way the boot loop
    // would after observing a (by now resolved) crash signature; the final on
    // disk is GOOD here, so the vanished-marker arm's re-load succeeds.
    #[test]
    fn late_recovery_aborts_after_winner_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp = Keypair::generate();
        let pem = kp.to_pem().expect("pem");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, &|| {}, faults)
            .expect("winner publishes and commits");
        assert!(matches!(out, KeyPublish::Won), "winner commits");

        let recovery = super::recover_crashed_publish(
            &key_path,
            anyhow::anyhow!("synthetic post-commit crash signature"),
            RecoverySeam::NONE,
        )
        .expect("a late recovery must not error");
        let loaded = match recovery {
            super::Recovery::Reloaded(result) => {
                result.expect("the vanished-marker arm re-loads the winner's key")
            }
            super::Recovery::Claimed(claims) => {
                panic!("no marker exists to claim after commit, got claims {claims:?}")
            }
        };
        assert_eq!(
            format!("{}", loaded.did()),
            format!("{}", kp.did()),
            "late recovery must resolve to the committed winner's identity"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "a committed final must never be quarantined"
        );
    }

    // #194 (U3, reshaped by F3 and the absence-keyed waiter): a demoted
    // winner whose round is SETTLED (no `.recovering.` claim file remains,
    // the recoverer released before the demoted publish reached its wait)
    // must resolve Lost immediately: the waiter keys purely on claim-file
    // absence, so an empty directory clears it on the first poll. The
    // marker is stolen WITHOUT a real recovery (final left in place), so
    // the follow-up load resolves the winner's OWN key: the
    // demotion-is-safe property. waiter_holds_for_live_young_claims covers
    // the hold side; frozen_claim_fails_the_waiter_closed covers a claim
    // that never clears.
    #[test]
    fn demoted_winner_resolves_fast_when_claims_are_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");

        let fired = std::sync::atomic::AtomicBool::new(false);
        let steal_dir = dir.path().to_path_buf();
        let before_commit = move || {
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let markers = names_containing(&steal_dir, ".publishing.");
            assert_eq!(
                markers.len(),
                1,
                "A's window must be bracketed: {markers:?}"
            );
            // The demoting peer already resolved AND released its claims:
            // only the stolen marker remains as evidence of the demotion.
            std::fs::remove_file(steal_dir.join(&markers[0])).expect("steal A's marker");
        };
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };

        let started = std::time::Instant::now();
        let kp = load_or_create_keypair_with(
            &key_path,
            &|| {},
            &before_commit,
            faults,
            RecoverySeam::NONE,
        )
        .expect("a demoted winner with no claims left must still resolve a key");
        let waited = started.elapsed();

        assert!(
            waited < std::time::Duration::from_secs(4),
            "an absent claim must not hold the demoted winner, waited {waited:?}"
        );
        let on_disk = super::load_existing_key(&key_path).expect("final parses");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", on_disk.did()),
            "with the final untouched the demoted winner must resolve its own key"
        );
    }

    // Q3: a demoted winner facing a claim whose mtime is FROZEN (its
    // recoverer's heartbeat never span up and both stamp rungs failed on a
    // hostile volume, or it is a long-crashed recovery's orphan) must fail
    // the publish CLOSED, never resolve a key: the waiter keys purely on
    // claim-file PRESENCE, so a claim that never leaves the directory rides
    // the full bound and errors, whatever its age. Before this fix the
    // waiter read an aged claim as orphaned residue and returned Ok, and
    // the demoted publisher loaded a possibly pre-settlement key while an
    // mtime-frozen LIVE recoverer could still settle disk differently. RED
    // before the fix: the aged claim clears the wait as Ok and the demoted
    // winner resolves its own key.
    #[test]
    fn frozen_claim_fails_the_waiter_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");

        let fired = std::sync::atomic::AtomicBool::new(false);
        let steal_dir = dir.path().to_path_buf();
        let final_bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let final_at_demotion = final_bytes.clone();
        let observe_path = key_path.clone();
        let before_commit = move || {
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let markers = names_containing(&steal_dir, ".publishing.");
            assert_eq!(
                markers.len(),
                1,
                "A's window must be bracketed: {markers:?}"
            );
            std::fs::remove_file(steal_dir.join(&markers[0])).expect("steal A's marker");
            let claim = steal_dir.join(".identity.pem.recovering.44444");
            std::fs::write(&claim, b"").expect("plant frozen claim");
            // Freeze the claim's mtime far in the past: no heartbeat, no
            // stamp, only the file itself, which never leaves the directory.
            age_beyond_claim_sweep(&claim);
            *final_at_demotion.lock().expect("final bytes lock") =
                std::fs::read(&observe_path).expect("final is complete at the commit check");
        };
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };

        let result = load_or_create_keypair_with(
            &key_path,
            &|| {},
            &before_commit,
            faults,
            RecoverySeam::NONE,
        );

        let err = match result {
            Err(e) => e,
            Ok(_) => {
                panic!("a claim still present at the wait bound must fail closed, not resolve")
            }
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(".identity.pem.recovering.44444"),
            "the error must name the surviving claim file: {msg}"
        );
        assert!(
            msg.contains("settle"),
            "the error must name the unsettled round: {msg}"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("final still on disk"),
            *final_bytes.lock().expect("final bytes lock"),
            "the failed-closed publish must leave the final untouched"
        );
    }

    // F3: the waiter's hold must follow the CLAIM_SWEEP_MIN_AGE-plus-margin
    // bound, not KEY_RACE_DEADLINE: a live claim's round is allowed the
    // full bound to finish, so a demoted winner that gives up at the 5s
    // deadline can re-load the pre-quarantine key while a slow-mount
    // recovery is still mid-round. Plant a claim, hold it in place for ~7s
    // (past the old deadline), then remove it mid-wait: the waiter must
    // still be holding past 5s (the file is present) and return shortly
    // after the removal (absence is the release), well under the bound. RED
    // before F3: the waiter expires at KEY_RACE_DEADLINE and the elapsed
    // floor fails.
    #[test]
    fn waiter_holds_for_live_young_claims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");

        let fired = std::sync::atomic::AtomicBool::new(false);
        let steal_dir = dir.path().to_path_buf();
        let before_commit = move || {
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let markers = names_containing(&steal_dir, ".publishing.");
            assert_eq!(
                markers.len(),
                1,
                "A's window must be bracketed: {markers:?}"
            );
            std::fs::remove_file(steal_dir.join(&markers[0])).expect("steal A's marker");
            std::fs::write(steal_dir.join(".identity.pem.recovering.55555"), b"")
                .expect("plant fresh (live) claim");
        };
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };

        // Model the live round resolving mid-wait: once the claim appears,
        // keep it live for 7s (past the old 5s deadline, under the ~11s
        // bound), then clear it as a finishing recoverer would.
        let claim_path = dir.path().join(".identity.pem.recovering.55555");
        let remover_path = claim_path.clone();
        let remover = std::thread::spawn(move || {
            while !remover_path.exists() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            std::thread::sleep(std::time::Duration::from_secs(7));
            std::fs::remove_file(&remover_path).expect("clear the live claim mid-wait");
        });

        let started = std::time::Instant::now();
        let kp = load_or_create_keypair_with(
            &key_path,
            &|| {},
            &before_commit,
            faults,
            RecoverySeam::NONE,
        )
        .expect("a demoted winner behind a live claim must still resolve a key");
        let waited = started.elapsed();
        remover.join().expect("remover joins");

        assert!(
            waited > super::KEY_RACE_DEADLINE + std::time::Duration::from_millis(1500),
            "a young claim must hold the waiter past the old deadline, waited {waited:?}"
        );
        assert!(
            waited < std::time::Duration::from_secs(10),
            "the waiter must release on the claim's removal, not ride the full \
             bound: waited {waited:?}"
        );
        let on_disk = super::load_existing_key(&key_path).expect("final parses");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", on_disk.did()),
            "with the final untouched the demoted winner must resolve its own key"
        );
    }

    // N3: a demoted fallback winner whose wait bound expires while a claim
    // still persists has NOT observed a settled round: loading the final
    // there can return a pre-settlement key into run() while the
    // still-live recoverer settles disk on a different identity, the exact
    // divergence the protocol forbids. The publish must fail closed (a loud
    // Err naming the unsettled round), never resolve Lost and load. A
    // refresher thread keeps the claim young past the full wait bound,
    // modeling a recovery round still heartbeating (live but stuck) beyond
    // it; frozen_claim_fails_the_waiter_closed covers the mtime-frozen
    // side, which the absence-keyed waiter treats identically. RED before
    // N3: the waiter expires silently and the demoted winner returns its
    // own key.
    #[test]
    fn unsettled_round_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");

        let fired = std::sync::atomic::AtomicBool::new(false);
        let steal_dir = dir.path().to_path_buf();
        let final_bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let final_at_demotion = final_bytes.clone();
        let observe_path = key_path.clone();
        let before_commit = move || {
            if fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let markers = names_containing(&steal_dir, ".publishing.");
            assert_eq!(
                markers.len(),
                1,
                "A's window must be bracketed: {markers:?}"
            );
            std::fs::remove_file(steal_dir.join(&markers[0])).expect("steal A's marker");
            std::fs::write(steal_dir.join(".identity.pem.recovering.55555"), b"")
                .expect("plant live claim");
            *final_at_demotion.lock().expect("final bytes lock") =
                std::fs::read(&observe_path).expect("final is complete at the commit check");
        };
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            ..PublishFaults::NONE
        };

        // Keep the claim YOUNG for the waiter's whole bound, modeling a
        // recovery round that heartbeats but never settles. The
        // absence-keyed waiter fails closed on presence regardless of age
        // (frozen_claim_fails_the_waiter_closed pins the frozen-mtime
        // side); the refresher keeps this test honest about the LIVE-round
        // shape it models.
        let claim_path = dir.path().join(".identity.pem.recovering.55555");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_refresher = stop.clone();
        let refresher_path = claim_path.clone();
        let refresher = std::thread::spawn(move || {
            while !refresher_path.exists() {
                if stop_refresher.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            while !stop_refresher.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = std::fs::File::options()
                    .write(true)
                    .open(&refresher_path)
                    .and_then(|f| f.set_modified(std::time::SystemTime::now()));
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });

        let result = load_or_create_keypair_with(
            &key_path,
            &|| {},
            &before_commit,
            faults,
            RecoverySeam::NONE,
        );
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        refresher.join().expect("refresher joins");

        let err = match result {
            Err(e) => e,
            Ok(_) => {
                panic!("an unsettled round past the wait bound must fail closed, not resolve a key")
            }
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains(".identity.pem.recovering.55555"),
            "the error must name the unsettled claim file: {msg}"
        );
        assert!(
            msg.contains("settle"),
            "the error must name the unsettled round: {msg}"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("final still on disk"),
            *final_bytes.lock().expect("final bytes lock"),
            "the failed-closed publish must leave the final untouched"
        );
    }

    // #194 (U4): a HEALTHY load must sweep stale `.publishing.` markers and
    // `.recovering.` claims, or they linger to misclassify a much-later real
    // corruption of a good key as an interrupted first write. The claim is
    // AGED past CLAIM_SWEEP_MIN_AGE: only orphaned claims are sweepable
    // (#194, G1; healthy_load_spares_young_claims covers the young side).
    // RED before U4: all three files survive the load.
    #[test]
    fn healthy_load_sweeps_stale_markers_and_claims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let existing = Keypair::generate();
        let pem = existing.to_pem().expect("pem");
        let key_path = seed_crash_state(dir.path(), pem.as_bytes());
        std::fs::write(dir.path().join(".identity.pem.publishing.88888.1"), b"")
            .expect("seed second stale marker");
        let claim = dir.path().join(".identity.pem.recovering.77777");
        std::fs::write(&claim, b"").expect("seed stale recovery claim");
        age_beyond_claim_sweep(&claim);

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a valid final with stale markers must load");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", existing.did()),
            "the pre-existing identity must be preserved, not regenerated"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "a healthy load must sweep stale publish markers"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "a healthy load must sweep stale recovery claims"
        );
    }

    // #194 (G1) MUST-NOT: the healthy-boot sweep must SPARE a young
    // `.recovering.` claim. A live recoverer's claims exist only within one
    // bounded recovery round, and a demoted publisher's
    // wait_for_recovery_claims waits on them; a third start sweeping a live
    // claim cancels that wait early, so the publisher re-loads the
    // pre-quarantine key while the recoverer proceeds to quarantine and
    // republish: two-sided divergence. Only a claim older than
    // CLAIM_SWEEP_MIN_AGE (an orphan of a crashed recovery) may go.
    // `.publishing.` markers keep the unconditional sweep: sweeping a live
    // publisher's marker only fails its commit check, a safe demotion. RED
    // before G1: the young claim is swept too.
    #[test]
    fn healthy_load_spares_young_claims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let existing = Keypair::generate();
        let pem = existing.to_pem().expect("pem");
        let key_path = seed_crash_state(dir.path(), pem.as_bytes());
        let young = dir.path().join(".identity.pem.recovering.11111");
        std::fs::write(&young, b"").expect("seed young (possibly live) claim");
        let old = dir.path().join(".identity.pem.recovering.22222");
        std::fs::write(&old, b"").expect("seed orphaned claim");
        age_beyond_claim_sweep(&old);

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a valid final must load regardless of claim ages");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", existing.did()),
            "the pre-existing identity must be preserved"
        );
        assert!(
            young.exists(),
            "a young claim may belong to a LIVE recovery and must survive the sweep"
        );
        assert!(
            !old.exists(),
            "an orphaned claim past CLAIM_SWEEP_MIN_AGE must be swept"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "publish markers keep the unconditional sweep"
        );
    }

    // F2 (function level): the boot sweep SPARES a young claim (it may gate
    // a live round), so orphaned residue can outlive a healthy boot; once
    // the claim ages past CLAIM_SWEEP_MIN_AGE a SECOND sweep over the same
    // final must clear it, or the residue later pairs with a real content
    // failure of the good final and misclassifies marker-less corruption as
    // a crash. GREEN at introduction (the sweep is already age-correct);
    // load-bearing by mutation check: inverting the sweep's age gate turns
    // it RED. spawn_delayed_claim_resweep is the boot wiring that provides
    // the second sweep in-process.
    #[test]
    fn second_sweep_clears_aged_orphan_claims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");
        std::fs::write(&key_path, pem.as_bytes()).expect("seed valid final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 final");
        let claim = dir.path().join(".identity.pem.recovering.33333");
        std::fs::write(&claim, b"").expect("seed young claim");

        super::sweep_stale_markers(&key_path, || Ok(()));
        assert!(
            claim.exists(),
            "the first sweep must spare the young (possibly live) claim"
        );

        age_beyond_claim_sweep(&claim);
        super::sweep_stale_markers(&key_path, || Ok(()));
        assert!(
            !claim.exists(),
            "a second sweep must clear the claim once it ages into an orphan"
        );
    }

    // M4: `.superseded.` forensic files never expired, so every lost round
    // accumulated one beside the final forever. The healthy sweep must
    // remove a superseded file older than SUPERSEDED_RETENTION (the
    // operator's inspection window) while a YOUNG one survives; the sweep's
    // durability gate already ran before any removal. RED before M4: the
    // aged file survives every healthy boot.
    #[test]
    fn superseded_residue_is_retention_swept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");
        std::fs::write(&key_path, pem.as_bytes()).expect("seed valid final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 final");
        let aged = dir.path().join(".identity.pem.superseded.99999.0");
        std::fs::write(&aged, b"old forensics").expect("seed aged superseded file");
        set_mtime_past(&aged, "2 days ago");
        let young = dir.path().join(".identity.pem.superseded.99999.1");
        std::fs::write(&young, b"fresh forensics").expect("seed young superseded file");

        load_or_create_keypair(&key_config(&key_path)).expect("healthy load");

        assert!(
            !aged.exists(),
            "a superseded file past the retention window must be swept"
        );
        assert!(
            young.exists(),
            "a superseded file inside the retention window must survive"
        );
    }

    // Q2: plain `.quarantined.` residue also never expired: an unparseable
    // quarantine (crash forensics) and an aged parseable one (past the
    // adoption floor, so pure history) sat beside a healthy final forever.
    // The healthy sweep must remove a `.quarantined.` entry older than
    // SUPERSEDED_RETENTION, while a YOUNG unparseable one (fresh crash
    // forensics) and a parseable one past the adoption floor but inside
    // retention (recent history, an operator may still want it) survive.
    // RED before Q2: the aged unparseable quarantine survives every
    // healthy boot.
    #[test]
    fn old_quarantine_forensics_are_retention_swept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");
        std::fs::write(&key_path, pem.as_bytes()).expect("seed valid final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 final");
        let aged_garbage = dir.path().join(".identity.pem.quarantined.99999.0");
        std::fs::write(&aged_garbage, b"-----BEGIN nonsense").expect("seed aged forensics");
        set_mtime_past(&aged_garbage, "2 days ago");
        let young_garbage = dir.path().join(".identity.pem.quarantined.99999.1");
        std::fs::write(&young_garbage, b"-----BEGIN nonsense").expect("seed young forensics");
        let recent_parseable = dir.path().join(".identity.pem.quarantined.99999.2");
        std::fs::write(
            &recent_parseable,
            Keypair::generate().to_pem().expect("pem").as_bytes(),
        )
        .expect("seed recent parseable quarantine");
        // Past the adoption floor (CLAIM_SWEEP_MIN_AGE) but well inside the
        // 24h retention window.
        set_mtime_past(&recent_parseable, "1 hour ago");

        load_or_create_keypair(&key_config(&key_path)).expect("healthy load");

        assert!(
            !aged_garbage.exists(),
            "a quarantine past the retention window must be swept"
        );
        assert!(
            young_garbage.exists(),
            "young crash forensics must survive the healthy sweep"
        );
        assert!(
            recent_parseable.exists(),
            "a quarantine past the adoption floor but inside retention must survive"
        );
    }

    // F2 (wiring): the delayed boot re-sweep must actually fire and sweep.
    // Paused tokio time drives the real CLAIM_SWEEP_MIN_AGE-plus-margin
    // sleep instantly; the claim is pre-aged on disk because paused time
    // advances the tokio clock, not SystemTime mtimes. This covers "the
    // spawned task runs the sweep after the delay";
    // second_sweep_clears_aged_orphan_claims covers the age semantics.
    #[tokio::test(start_paused = true)]
    async fn delayed_resweep_clears_aged_orphan_claims() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");
        std::fs::write(&key_path, pem.as_bytes()).expect("seed valid final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 final");
        let claim = dir.path().join(".identity.pem.recovering.66666");
        std::fs::write(&claim, b"").expect("seed claim");
        age_beyond_claim_sweep(&claim);

        super::spawn_delayed_claim_resweep(key_path.clone())
            .await
            .expect("the re-sweep task must complete");

        assert!(
            !claim.exists(),
            "the delayed re-sweep must clear the aged orphan claim"
        );
        assert!(
            super::load_existing_key(&key_path).is_ok(),
            "the final must survive the re-sweep intact"
        );
    }

    // The G1 age gate reads the CLAIM file's mtime, but a claim is made by
    // RENAMING a marker, and rename preserves the source's mtime: a claim
    // made from an hours-old stale marker would be born already past
    // CLAIM_SWEEP_MIN_AGE, so a concurrent healthy boot's sweep could remove
    // the LIVE claim mid-round and early-wake the demoted publisher it
    // gates. Recovery must therefore stamp each claim's mtime fresh at
    // claim time. RED before the fix: the claim inherits the aged mtime.
    #[test]
    fn claim_freshness_is_stamped_at_claim_time() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let marker = dir.path().join(".identity.pem.publishing.99999.0");
        age_beyond_claim_sweep(&marker);

        let recovery = super::recover_crashed_publish(
            &key_path,
            anyhow::anyhow!("synthetic crash signature"),
            RecoverySeam::NONE,
        )
        .expect("recovery over an aged marker must not error");
        let mut claims = match recovery {
            super::Recovery::Claimed(claims) => claims,
            super::Recovery::Reloaded(_) => {
                panic!("an aged marker beside an empty final must be claimed")
            }
        };
        assert!(
            !claims.files.is_empty(),
            "the aged marker must produce a claim"
        );
        for claim in &claims.files {
            let mtime = std::fs::metadata(claim)
                .expect("stat claim")
                .modified()
                .expect("claim mtime");
            let age = std::time::SystemTime::now()
                .duration_since(mtime)
                .unwrap_or_default();
            assert!(
                age < super::CLAIM_SWEEP_MIN_AGE,
                "a claim must be born fresh, not inherit the aged marker mtime \
                 through the rename: age {age:?} at {claim:?}"
            );
        }
        super::release_recovery_claims(&key_path, &mut claims);
    }

    // The G1 freshness stamp must survive a failing set_modified: some
    // filesystems reject explicit timestamps while honoring write-driven
    // mtime updates, and a claim left with its inherited aged mtime for the
    // whole round is exposed to a concurrent healthy boot's age-gated sweep.
    // The ladder's fallback appends a byte, which bumps the mtime on
    // effectively every filesystem (claims are matched by name only, so a
    // non-empty claim is safe). RED with the fallback rung absent: the
    // claim keeps the aged mtime.
    #[test]
    fn stamp_fallback_bumps_mtime_by_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let claim = dir.path().join(".identity.pem.recovering.99999.deadbeef.0");
        std::fs::write(&claim, b"").expect("seed claim");
        age_beyond_claim_sweep(&claim);

        super::refresh_claim_mtime(&claim, |_| Err(std::io::ErrorKind::Unsupported.into()))
            .expect("the write fallback must stamp the mtime when the primary fails");

        let mtime = std::fs::metadata(&claim)
            .expect("stat claim")
            .modified()
            .expect("claim mtime");
        let age = std::time::SystemTime::now()
            .duration_since(mtime)
            .unwrap_or_default();
        assert!(
            age < super::CLAIM_SWEEP_MIN_AGE,
            "the fallback write must leave the claim fresh, age {age:?}"
        );
    }

    // M3: claim liveness is age < CLAIM_SWEEP_MIN_AGE, but a single
    // claim-time stamp lets a recoverer stalled longer than the floor
    // between claim and settlement read as an orphan to the sweep and to
    // claimability: the delayed re-sweep or a healthy boot removes the
    // still-live claim (early-releasing any demoted publisher's
    // absence-keyed wait to a pre-settlement load), or a competing
    // recoverer steals the round: divergence returns on slow shared
    // volumes. A live
    // recovery must HEARTBEAT its claims so they never age out while it
    // runs. The park holds recovery inside the claim-to-settlement window
    // (before_quarantine) just past the floor while the test samples the
    // claim's age throughout. RED before M3: the single stamp ages past the
    // floor mid-park. The ~12s wall cost is the test's point: the floor is
    // real time.
    #[test]
    fn heartbeat_keeps_live_claims_young() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");

        let park_dir = dir.path().to_path_buf();
        let before_quarantine = move || {
            let deadline = std::time::Instant::now()
                + super::CLAIM_SWEEP_MIN_AGE
                + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(900));
                let claims = names_containing(&park_dir, ".recovering.");
                assert!(!claims.is_empty(), "the parked round's claim must persist");
                for name in &claims {
                    let mtime = std::fs::metadata(park_dir.join(name))
                        .and_then(|m| m.modified())
                        .expect("claim mtime");
                    let age = std::time::SystemTime::now()
                        .duration_since(mtime)
                        .unwrap_or_default();
                    assert!(
                        age < super::CLAIM_SWEEP_MIN_AGE,
                        "a LIVE recovery's claim must stay young mid-round: age {age:?}"
                    );
                }
            }
        };
        let seam = RecoverySeam {
            before_quarantine: &before_quarantine,
            ..RecoverySeam::NONE
        };

        let started = std::time::Instant::now();
        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("the parked recovery must still resolve a key");
        let elapsed = started.elapsed();

        // The recovery finished: claims released (the on-disk leak
        // evidence) and the heartbeat joined (the elapsed ceiling bounds
        // release plus join after the ~12s park).
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the finished recovery must release its claims"
        );
        assert!(
            elapsed < super::CLAIM_SWEEP_MIN_AGE + std::time::Duration::from_secs(8),
            "release and heartbeat join must be prompt after the park: took {elapsed:?}"
        );
        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the on-disk key"
        );
    }

    // Claim destinations must carry a per-process nonce beyond the pid:
    // `.{stem}.recovering.{pid}.{nonce}.{n}`. The pid alone is not unique
    // across recoverers on a shared volume (two PID-1 containers), so two
    // concurrent recoverers could derive the SAME destination name, and the
    // second's claim rename would replace the first's live claim inode (the
    // exists() probe is a check-then-act, not an arbiter); the first release
    // would then unlink the other's LIVE claim and early-wake the demoted
    // publisher it gates. The cross-process collision itself cannot be
    // executed from one test process (one pid, one nonce), so this test
    // fences the mechanism: every claim name must carry the process nonce
    // field between the pid and the counter. RED under pid-only naming.
    #[test]
    fn same_pid_recoverers_get_unique_claim_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");

        let recovery = super::recover_crashed_publish(
            &key_path,
            anyhow::anyhow!("synthetic crash signature"),
            RecoverySeam::NONE,
        )
        .expect("recovery over a crash state must not error");
        let mut claims = match recovery {
            super::Recovery::Claimed(claims) => claims,
            super::Recovery::Reloaded(_) => {
                panic!("a marker beside an empty final must be claimed")
            }
        };
        assert!(!claims.files.is_empty(), "the marker must produce a claim");
        let pid_prefix = format!(".identity.pem.recovering.{}.", std::process::id());
        for claim in &claims.files {
            let name = claim
                .file_name()
                .and_then(|n| n.to_str())
                .expect("claim name is utf8");
            let rest = name
                .strip_prefix(&pid_prefix)
                .unwrap_or_else(|| panic!("claim {name:?} must start with {pid_prefix:?}"));
            let fields: Vec<&str> = rest.split('.').collect();
            assert_eq!(
                fields.len(),
                2,
                "claim {name:?} must end in {{nonce}}.{{counter}}, got {rest:?}"
            );
            assert_eq!(
                fields[0],
                format!("{:08x}", super::claim_nonce()),
                "the field between pid and counter must be the process nonce"
            );
            assert!(
                fields[1].parse::<u32>().is_ok(),
                "the final field must be the claim counter, got {:?}",
                fields[1]
            );
        }
        super::release_recovery_claims(&key_path, &mut claims);
    }

    // A final that VANISHES between the claim renames and the post-claim
    // re-parse (a competing recoverer disposed of it concurrently) must join
    // the content class and regenerate, not surface as a loud transient
    // error: there is nothing a quarantine could destroy, and the quarantine
    // loop's own NotFound arm resolves it cleanly. Locks the NotFound arm of
    // the re-parse match (anyhow's downcast_ref::<io::Error> sees the
    // NotFound through the with_context layers). RED with NotFound routed
    // into the transient arm (mutation check): the boot fails loudly.
    #[test]
    fn vanished_final_at_reparse_still_regenerates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let vanish_path = key_path.clone();
        let before_reparse = move || {
            std::fs::remove_file(&vanish_path).expect("vanish the final inside the claim window");
        };

        let kp = load_or_create_keypair_with(
            &key_path,
            &|| {},
            &|| {},
            PublishFaults::NONE,
            RecoverySeam {
                before_reparse: &before_reparse,
                ..RecoverySeam::NONE
            },
        )
        .expect("a final vanished at the re-parse must regenerate, not fail the start");

        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "a vanished final leaves nothing to quarantine"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "no recovery claims may remain"
        );
    }

    // #194 (U4): the generate path must sweep too. A crash between the
    // marker's durability fsync and the final's `create_new` leaves a durable
    // marker with NO final; only the Won arm of a later boot can ever clean
    // that state, since no load will ever succeed beside it. RED before U4
    // (the marker survives); RED again under a load-arm-only implementation
    // (mutation check: with the Won-arm call site removed this test must
    // fail while healthy_load_sweeps_stale_markers_and_claims stays green).
    #[test]
    fn generate_path_sweeps_stale_markers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        std::fs::write(dir.path().join(".identity.pem.publishing.66666.0"), b"")
            .expect("seed stale marker without a final");

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a stale marker with no final must not block generation");

        let on_disk = super::load_existing_key(&key_path).expect("published key loads");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the generated identity must be on disk"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "a Won publish on a healthy boot must sweep the stale marker"
        );
    }

    // #194 (U4) MUST-NOT: the sweep must never remove a marker ahead of the
    // content it vouches for. With the seam failing the sweep's durability
    // sync, the load still succeeds but the marker SURVIVES. Vacuously green
    // before U4 (no sweep exists, so the marker trivially survives); its
    // load-bearing proof is the mutation check: with the durability gate
    // removed (sweep unconditionally) this test must fail.
    #[test]
    fn sweep_durability_gate_leaves_markers_on_sync_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let existing = Keypair::generate();
        let pem = existing.to_pem().expect("pem");
        let key_path = seed_crash_state(dir.path(), pem.as_bytes());
        let seam = RecoverySeam {
            sweep_sync: || Err(std::io::Error::other("injected sweep sync failure")),
            ..RecoverySeam::NONE
        };

        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("a failed sweep durability sync must not fail the load");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", existing.did()),
            "the identity must still load when the sweep is skipped"
        );
        assert_eq!(
            names_containing(dir.path(), ".publishing."),
            vec![".identity.pem.publishing.99999.0".to_string()],
            "the marker must survive when the sweep cannot make the final durable"
        );
    }

    // #194 (U4): the sweep's removals are best-effort; unremovable markers
    // must never fail an otherwise healthy load. The key directory is made
    // read-only (0555): the durability gate still passes (the file sync_all
    // and the dir fsync both open read-only) but every remove_file fails
    // EACCES. Vacuously green before U4 (no sweep exists); load-bearing once
    // the sweep runs, since a sweep that surfaced removal errors would fail
    // this load.
    #[test]
    fn sweep_failure_tolerated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let existing = Keypair::generate();
        let pem = existing.to_pem().expect("pem");
        let key_path = seed_crash_state(dir.path(), pem.as_bytes());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555))
            .expect("read-only key dir");

        let result = load_or_create_keypair(&key_config(&key_path));

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("restore key dir");
        let kp = result.expect("unremovable markers must not fail the load");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", existing.did()),
            "the identity must load despite the failed sweep removals"
        );
        assert_eq!(
            names_containing(dir.path(), ".publishing."),
            vec![".identity.pem.publishing.99999.0".to_string()],
            "the unremovable marker survives, harmlessly"
        );
    }

    // #194 (F1): a claimed recovery whose retry publish FAILS must release
    // its `.recovering.` claim before surfacing the error. A leaked claim
    // makes every later demoted fallback publisher ride the full wait
    // bound in wait_for_recovery_claims and fail its publish closed until
    // some healthy boot sweeps it. RED before F1: the bare `?` on the
    // publish call returns with the claim still on disk.
    #[test]
    fn claim_released_when_post_recovery_publish_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_create: || Err(std::io::Error::other("injected fallback create failure")),
            ..PublishFaults::NONE
        };

        let err = match load_or_create_keypair_with(
            &key_path,
            &|| {},
            &|| {},
            faults,
            RecoverySeam::NONE,
        ) {
            Err(e) => e,
            Ok(_) => panic!("the forced publish failure must surface, not resolve a key"),
        };
        assert!(
            format!("{err:#}").contains("injected fallback create failure"),
            "the publish failure must propagate: {err:#}"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "a failed retry publish must release the recovery claim, not leak it"
        );
    }

    // #194 (F2): a stale marker must not let recovery steal a LIVE fallback
    // publisher's round. Deterministic construction: publisher A parks at
    // its commit check (final complete and durable, own marker M present,
    // stale marker S beside it); the real recovery runs, and its
    // before-reparse seam (inside the window between the claim step and the
    // post-claim re-parse) unparks A and waits for A to finish, landing A's
    // commit exactly in the claim window. Under F2 recovery claims EVERY
    // claimable, so A's removal of M fails and A demotes; the re-parse then
    // sees A's completed key and recovery aborts to Reloaded. Everyone
    // converges on one on-disk identity. RED before F2: recovery claims only
    // the lexicographically-first stale S, A's commit on M succeeds, and A
    // returns Won with key A while recovery quarantines A's final and
    // republishes key B: the two-sided divergence R4 forbids.
    #[test]
    fn stale_marker_cannot_steal_a_live_publishers_round() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        // Sorts before any real-pid marker (pids never start with '0').
        std::fs::write(dir.path().join(".identity.pem.publishing.00000.0"), b"")
            .expect("seed stale marker");

        let (parked_tx, parked_rx) = std::sync::mpsc::channel::<()>();
        let (unpark_tx, unpark_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<String>();
        let p_path = key_path.clone();
        let publisher = std::thread::spawn(move || {
            let before_commit = move || {
                parked_tx.send(()).expect("signal parked");
                unpark_rx
                    .recv()
                    .expect("wait inside the recovery's claim window");
            };
            let faults = PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                ..PublishFaults::NONE
            };
            let kp = load_or_create_keypair_with(
                &p_path,
                &|| {},
                &before_commit,
                faults,
                RecoverySeam::NONE,
            )
            .expect("the publisher must resolve a key, demoted or not");
            done_tx
                .send(format!("{}", kp.did()))
                .expect("report the publisher's identity");
        });
        parked_rx
            .recv()
            .expect("publisher reaches its commit check");

        // The concurrent recovery, via the REAL recovery path. Its
        // before-reparse hook unparks A inside the window between the claim
        // step and the post-claim re-parse: A's marker is already claimed,
        // so A's commit check fails and A demotes, then waits out the LIVE
        // claims until this recovery releases them. (The hook must not park
        // recovery until A finishes: A's waiter holds while the claim
        // files are present, until release, so that cycle would correctly
        // fail A closed; the pre-heartbeat, age-keyed version only
        // unblocked because the live claims aged out mid-round, the exact
        // divergence window M3 and the absence-keyed waiter close.)
        let before_reparse = || {
            unpark_tx.send(()).expect("unpark the publisher");
        };
        let recovery = super::recover_crashed_publish(
            &key_path,
            anyhow::anyhow!("synthetic crash signature"),
            RecoverySeam {
                before_reparse: &before_reparse,
                ..RecoverySeam::NONE
            },
        )
        .expect("recovery must not error");
        let recovered_did = match recovery {
            super::Recovery::Reloaded(result) => format!(
                "{}",
                result
                    .expect("the post-claim re-parse resolves the completed key")
                    .did()
            ),
            super::Recovery::Claimed(mut recovery_claims) => {
                // The boot loop's follow-through: regenerate, publish, release.
                let kp_b = Keypair::generate();
                let pem_b = kp_b.to_pem().expect("pem b");
                let out = publish_key_atomically(
                    &key_path,
                    pem_b.as_bytes(),
                    &|| {},
                    &|| {},
                    PublishFaults::NONE,
                )
                .expect("recovery's republish");
                assert!(matches!(out, KeyPublish::Won), "recovery's republish wins");
                super::release_recovery_claims(&key_path, &mut recovery_claims);
                format!("{}", kp_b.did())
            }
        };
        publisher.join().expect("publisher joins");

        let p_did = done_rx.recv().expect("the publisher reported its identity");
        let disk_did = format!(
            "{}",
            super::load_existing_key(&key_path)
                .expect("final parses")
                .did()
        );
        assert_eq!(
            p_did, disk_did,
            "the publisher must never resolve an identity that diverges from disk"
        );
        assert_eq!(
            recovered_did, disk_did,
            "recovery must converge on the same on-disk identity"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "a completed publisher's final must not be quarantined"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "no recovery claims may remain"
        );
    }

    // #194 (F3): a recoverer crashed between its claim rename and the
    // quarantine leaves a content-bad final beside a stale `.recovering.`
    // claim and ZERO `.publishing.` markers: the claim IS the renamed
    // marker. The claim must count toward the crash signature and be
    // claimable itself, or no later boot can ever recover: the permanent
    // wedge this protocol exists to eliminate. RED before F3: the signature
    // counts only `.publishing.` names, so the boot rides the deadline and
    // fails loudly forever.
    #[test]
    fn claim_crash_state_is_recoverable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        std::fs::write(&key_path, b"").expect("seed crashed final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 crashed final");
        let claim = dir.path().join(".identity.pem.recovering.99999.0");
        std::fs::write(&claim, b"").expect("seed stale recovery claim");
        // F2 age gate: only a claim past CLAIM_SWEEP_MIN_AGE is claimable; a
        // fresh one may gate a LIVE round (live_claims_are_not_claimable is
        // the must-not side). Age the orphan so this stays the positive case.
        age_beyond_claim_sweep(&claim);

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a claim-crash state must recover, not wedge every later boot");

        let on_disk = super::load_existing_key(&key_path).expect("regenerated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the returned identity must match the regenerated on-disk key"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "exactly one quarantine file must exist: {quarantined:?}"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the stale claim must be consumed and the fresh claim released"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
    }

    // F2 MUST-NOT: a FRESH `.recovering.` claim may gate a LIVE recovery
    // round (claim, quarantine, republish), and a second starter claiming it
    // mid-round steals that round: the recoverer's own re-parse and restore
    // then race the thief's quarantine-and-regenerate. A fresh claim must
    // therefore never count as claimable: with no `.publishing.` marker
    // beside it the claimable set is empty, no crash signature fires, and
    // the load fails loudly with the claim untouched. The positive case (an
    // ORPHANED claim past CLAIM_SWEEP_MIN_AGE) is
    // claim_crash_state_is_recoverable. Rides the full KEY_RACE_DEADLINE
    // (~5s), as every loud-fail load does. RED before F2: the fresh claim is
    // claimed and recovery proceeds.
    #[test]
    fn live_claims_are_not_claimable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        std::fs::write(&key_path, b"").expect("seed crashed final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 crashed final");
        let claim = dir.path().join(".identity.pem.recovering.99999.0");
        std::fs::write(&claim, b"").expect("seed fresh (possibly live) claim");

        let err = match load_or_create_keypair(&key_config(&key_path)) {
            Err(e) => e,
            Ok(_) => panic!("a fresh claim must never be stolen; the load must fail loudly"),
        };

        assert!(
            err.to_string().contains("invalid PEM key"),
            "the load failure must surface unchanged: {err:#}"
        );
        assert!(
            claim.exists(),
            "the possibly-live claim must survive untouched"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "no quarantine may be created off a live claim"
        );
    }

    // F1: a COMPLETED key stranded in a quarantine (the recoverer's restore
    // republish errored, or the recoverer crashed between its quarantine
    // rename and the restore) must be ADOPTED by the next boot: the final is
    // absent, so without adoption the boot mints a fresh DID and the node's
    // durable identity silently changes. The generate arm scans for
    // parseable quarantines and republishes the stranded bytes instead. RED
    // before F1: a fresh identity is minted and the quarantine is stranded
    // forever.
    #[test]
    fn stranded_quarantine_is_adopted_not_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let stranded = Keypair::generate();
        let pem = stranded.to_pem().expect("pem");
        std::fs::write(
            dir.path().join(".identity.pem.quarantined.99999.0"),
            pem.as_bytes(),
        )
        .expect("seed stranded quarantine");

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a stranded completed key must be adopted, not fail the boot");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", stranded.did()),
            "the stranded identity must be adopted, never replaced by a fresh DID"
        );
        let on_disk = super::load_existing_key(&key_path).expect("republished final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", stranded.did()),
            "the final must hold the adopted key"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "the quarantine must be consumed once its bytes are durably republished"
        );
    }

    // F1 MUST-NOT (age bound): adoption exists for the CURRENT round only (a
    // recoverer that crashed or failed seconds ago), so a parseable
    // quarantine AGED past CLAIM_SWEEP_MIN_AGE is history, not a stranded
    // round: kept forensics after a Lost restore, or an old identity the
    // operator already moved past. Adopting it would resurrect a dead DID
    // whenever the final later goes missing. The aged quarantine must
    // survive untouched as forensics while boot generates fresh. RED before
    // the age bound: the aged quarantine is adopted.
    #[test]
    fn aged_quarantine_is_never_adopted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let stranded = Keypair::generate();
        let pem = stranded.to_pem().expect("pem");
        let quarantine = dir.path().join(".identity.pem.quarantined.99999.0");
        std::fs::write(&quarantine, pem.as_bytes()).expect("seed aged quarantine");
        age_beyond_claim_sweep(&quarantine);

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("an aged quarantine must not block a fresh generation");

        assert_ne!(
            format!("{}", kp.did()),
            format!("{}", stranded.did()),
            "an aged quarantine is history and must never be resurrected"
        );
        assert_eq!(
            std::fs::read(&quarantine).expect("quarantine still on disk"),
            pem.as_bytes(),
            "the aged quarantine must survive byte-for-byte as forensics"
        );
    }

    // F1 (operator procedure): deleting identity.pem is the documented way
    // to mint a fresh DID. With an old parseable quarantine sitting beside
    // the final as forensics, the post-delete boot must GENERATE a new
    // identity, not adopt the quarantined one; unbounded adoption silently
    // defeats the procedure. RED before the age bound: the old quarantine's
    // DID comes back.
    #[test]
    fn operator_fresh_identity_procedure_works() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let first = load_or_create_keypair(&key_config(&key_path)).expect("provision identity");
        let old = Keypair::generate();
        let old_pem = old.to_pem().expect("pem");
        let quarantine = dir.path().join(".identity.pem.quarantined.88888.0");
        std::fs::write(&quarantine, old_pem.as_bytes()).expect("seed forensic quarantine");
        age_beyond_claim_sweep(&quarantine);

        // The operator action: delete the final to get a fresh DID.
        std::fs::remove_file(&key_path).expect("operator deletes the final");

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-delete boot must provision a fresh identity");

        assert_ne!(
            format!("{}", kp.did()),
            format!("{}", old.did()),
            "the old quarantined identity must not be resurrected"
        );
        assert_ne!(
            format!("{}", kp.did()),
            format!("{}", first.did()),
            "the operator must get a genuinely fresh DID"
        );
    }

    // N2: a quarantine kept by a LOST restore is provably outcompeted (a
    // concurrent winner durably published while its key sat quarantined),
    // yet it is young and parseable: exactly what adoption prefers. Left in
    // the `.quarantined.` class, the operator's
    // delete-identity.pem-for-a-fresh-DID procedure resurrects the LOSING
    // key instead of minting fresh. The Lost restore must rename its kept
    // quarantine into the `.superseded.` class: bytes preserved as
    // forensics, never adoptable. RED before N2: the post-delete boot
    // adopts and returns the losing key A.
    #[test]
    fn lost_restore_quarantine_is_never_adopted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let completed = Keypair::generate();
        let pem_a = completed.to_pem().expect("pem a");
        let kp_b = Keypair::generate();
        let pem_b = kp_b.to_pem().expect("pem b");

        // restore_never_clobbers_a_concurrent_winner's construction: A's
        // completed key is swept into quarantine, B takes the freed name
        // inside the quarantine-to-restore window, and the link-hostile
        // restore republish of A loses to B.
        let heal_path = key_path.clone();
        let pem_a_disk = pem_a.clone();
        let before_quarantine = move || {
            std::fs::write(&heal_path, pem_a_disk.as_bytes())
                .expect("complete the final inside the re-parse-to-rename window");
        };
        let steal_path = key_path.clone();
        let pem_b_disk = pem_b.clone();
        let before_restore = move || {
            let out = publish_key_atomically(
                &steal_path,
                pem_b_disk.as_bytes(),
                &|| {},
                &|| {},
                PublishFaults::NONE,
            )
            .expect("concurrent starter republishes key B at the freed name");
            assert!(
                matches!(out, KeyPublish::Won),
                "B's publish wins the free name"
            );
        };
        let seam = RecoverySeam {
            before_quarantine: &before_quarantine,
            before_restore: &before_restore,
            restore_faults: PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                ..PublishFaults::NONE
            },
            ..RecoverySeam::NONE
        };
        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("the losing restore must converge on B");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", kp_b.did()),
            "the recovering boot must converge on the concurrent winner's key B"
        );

        // The operator action: delete the final for a fresh DID.
        std::fs::remove_file(&key_path).expect("operator deletes the final");
        let fresh = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-delete boot must provision an identity");
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", completed.did()),
            "the key that LOST its round must never be resurrected by adoption"
        );
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", kp_b.did()),
            "the operator must get a genuinely fresh DID"
        );
        // A's bytes survive as forensics, in the never-adoptable class.
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "no adoptable quarantine may survive a lost restore"
        );
        let superseded = names_containing(dir.path(), ".superseded.");
        assert_eq!(
            superseded.len(),
            1,
            "the losing key must be kept once, superseded: {superseded:?}"
        );
        assert_eq!(
            std::fs::read(dir.path().join(&superseded[0])).expect("superseded readable"),
            pem_a.as_bytes(),
            "the superseded file must preserve the losing key's bytes as forensics"
        );
    }

    // N4: adoption decides its round in favor of ONE quarantine, but a
    // crashed pile-up can leave several young parseable quarantines side by
    // side. Adopting the newest while leaving the siblings adoptable means
    // a later missing final resurrects a DIFFERENT historical DID. On Won,
    // adoption must rename every other young parseable sibling into the
    // `.superseded.` class (bytes intact, never adoptable). RED before N4:
    // the sibling stays `.quarantined.` and the post-delete boot adopts it.
    #[test]
    fn adoption_supersedes_sibling_quarantines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let older = Keypair::generate();
        let older_pem = older.to_pem().expect("pem");
        let q_old = dir.path().join(".identity.pem.quarantined.99999.0");
        std::fs::write(&q_old, older_pem.as_bytes()).expect("seed older quarantine");
        // A strictly newer mtime on the second quarantine, so newest-first
        // adoption is deterministic.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let newer = Keypair::generate();
        let q_new = dir.path().join(".identity.pem.quarantined.99999.1");
        std::fs::write(&q_new, newer.to_pem().expect("pem").as_bytes())
            .expect("seed newer quarantine");

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("adoption must resolve the stranded round");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", newer.did()),
            "adoption must prefer the newest quarantine"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "the adopted quarantine is consumed and the sibling must be superseded"
        );
        let superseded = names_containing(dir.path(), ".superseded.");
        assert_eq!(
            superseded.len(),
            1,
            "exactly the outcompeted sibling is superseded: {superseded:?}"
        );
        assert_eq!(
            std::fs::read(dir.path().join(&superseded[0])).expect("superseded readable"),
            older_pem.as_bytes(),
            "the superseded sibling must preserve its bytes as forensics"
        );

        // The sibling must not come back as a different historical DID once
        // the final goes missing: the post-delete boot mints fresh.
        std::fs::remove_file(&key_path).expect("operator deletes the final");
        let fresh = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-delete boot must provision an identity");
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", older.did()),
            "the superseded sibling must never be resurrected"
        );
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", newer.did()),
            "the operator must get a genuinely fresh DID"
        );
    }

    // Q1: both Won arms now supersede the sibling quarantines BEFORE
    // consuming the chosen one, so a crash in the gap leaves the
    // POST-SUPERSEDE image: final present, siblings already superseded,
    // only the chosen quarantine (the winner's own bytes) still adoptable.
    // No seam reaches the reordered gap, so this test pins the two crash
    // images directly rather than interposing. First the post-fix image: a
    // later missing final may re-adopt only the winner's own key, never a
    // different historical DID. Then the PRE-fix image (chosen consumed
    // first, sibling still plain): a concrete demonstration that the old
    // ordering's crash gap left the sibling adoptable, resurrecting a
    // different DID after delete-final. The ordering itself is not
    // runtime-observable without a production seam; see the fix report.
    #[test]
    fn crash_between_won_and_sibling_supersede_leaves_no_adoptable() {
        // POST-fix crash image: crash fell between the sibling supersede
        // and the chosen quarantine's removal.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let winner = Keypair::generate();
        let winner_pem = winner.to_pem().expect("pem");
        let sibling = Keypair::generate();
        let sibling_pem = sibling.to_pem().expect("pem");
        std::fs::write(&key_path, winner_pem.as_bytes()).expect("seed final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 final");
        std::fs::write(
            dir.path().join(".identity.pem.superseded.99999.0"),
            sibling_pem.as_bytes(),
        )
        .expect("seed superseded sibling");
        let chosen = dir.path().join(".identity.pem.quarantined.99999.1");
        std::fs::write(&chosen, winner_pem.as_bytes()).expect("seed un-consumed chosen");

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-supersede crash image must boot healthy");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", winner.did()),
            "the final's key wins the crash-image boot"
        );

        std::fs::remove_file(&key_path).expect("final goes missing");
        let readopted = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-delete boot must provision an identity");
        assert_ne!(
            format!("{}", readopted.did()),
            format!("{}", sibling.did()),
            "a crash in the supersede-then-consume gap must leave no sibling adoptable"
        );
        assert_eq!(
            format!("{}", readopted.did()),
            format!("{}", winner.did()),
            "only the winner's own quarantined bytes may be re-adopted"
        );

        // PRE-fix crash image (the old ordering's gap): chosen already
        // consumed, sibling still in the plain adoptable class. This is the
        // hazard: the sibling IS adopted once the final goes missing.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        std::fs::write(&key_path, winner_pem.as_bytes()).expect("seed final");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("0600 final");
        std::fs::write(
            dir.path().join(".identity.pem.quarantined.99999.0"),
            sibling_pem.as_bytes(),
        )
        .expect("seed still-plain sibling");
        std::fs::remove_file(&key_path).expect("final goes missing");
        let resurrected = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-delete boot must provision an identity");
        assert_eq!(
            format!("{}", resurrected.did()),
            format!("{}", sibling.did()),
            "the pre-fix image demonstrably resurrects the sibling's DID"
        );
    }

    // M1, the N2 mirror on the ADOPTION arm: a quarantine whose adoption
    // republish LOSES (a concurrent winner durably published first) is
    // provably outcompeted, yet the adoption-Lost arm used to leave it in
    // the adoptable class while restore-Lost superseded its kept
    // quarantine. Within the age floor, the operator's
    // delete-identity.pem-for-a-fresh-DID procedure then resurrects the key
    // that just LOST its round. EVERY Lost outcome must supersede the
    // losing bytes. RED before M1: A survives as `.quarantined.` and the
    // post-delete boot adopts A.
    #[test]
    fn adoption_lost_supersedes_the_losing_quarantine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let stranded = Keypair::generate();
        let pem_a = stranded.to_pem().expect("pem a");
        let quarantine = dir.path().join(".identity.pem.quarantined.99999.0");
        std::fs::write(&quarantine, pem_a.as_bytes()).expect("seed young quarantine A");

        // A concurrent starter durably publishes C at the free final name
        // before the adoption scan (before_publish runs at the top of the
        // pass), so the adoption republish of A returns Lost.
        let winner = Keypair::generate();
        let winner_pem = winner.to_pem().expect("pem c");
        let race_path = key_path.clone();
        let before_publish = move || {
            if race_path.exists() {
                return;
            }
            let out = publish_key_atomically(
                &race_path,
                winner_pem.as_bytes(),
                &|| {},
                &|| {},
                PublishFaults::NONE,
            )
            .expect("concurrent winner publishes C");
            assert!(
                matches!(out, KeyPublish::Won),
                "C's publish takes the free name"
            );
        };
        let seam = RecoverySeam {
            before_publish: &before_publish,
            ..RecoverySeam::NONE
        };
        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("the adoption-Lost arm must defer to the winner");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", winner.did()),
            "the boot must converge on the concurrent winner's key C"
        );

        // A's bytes survive as forensics, in the never-adoptable class.
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "no adoptable quarantine may survive a lost adoption"
        );
        let superseded = names_containing(dir.path(), ".superseded.");
        assert_eq!(
            superseded.len(),
            1,
            "the losing quarantine must be superseded: {superseded:?}"
        );
        assert_eq!(
            std::fs::read(dir.path().join(&superseded[0])).expect("superseded readable"),
            pem_a.as_bytes(),
            "the superseded file must preserve A's bytes as forensics"
        );

        // The operator action: delete the final for a fresh DID; A must not
        // come back.
        std::fs::remove_file(&key_path).expect("operator deletes the final");
        let fresh = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-delete boot must provision an identity");
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", stranded.did()),
            "the key that LOST its adoption round must never be resurrected"
        );
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", winner.did()),
            "the operator must get a genuinely fresh DID"
        );
    }

    // F1 MUST-NOT: an UNPARSEABLE quarantine is the expected crash state and
    // stays as forensics; boot must fall through to a fresh generation, not
    // wedge on it or delete it.
    #[test]
    fn unparseable_quarantine_falls_through_to_generate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let garbage: &[u8] = b"-----BEGIN nonsense truncated";
        let quarantine = dir.path().join(".identity.pem.quarantined.99999.0");
        std::fs::write(&quarantine, garbage).expect("seed unparseable quarantine");

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("an unparseable quarantine must not block generation");

        let on_disk = super::load_existing_key(&key_path).expect("generated final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp.did()),
            "the generated identity must be on disk"
        );
        assert_eq!(
            std::fs::read(&quarantine).expect("quarantine still on disk"),
            garbage,
            "the unparseable quarantine must survive byte-for-byte as forensics"
        );
    }

    // #194 (grace): the crash signature must persist beyond a single
    // observation. A reader that catches a live fallback publisher's
    // mid-write window sees content-bad-plus-marker ONCE; if the state heals
    // before the next poll, no CrashSignature may fire, since a single
    // observation classifying a crash would let a crash-free boot hijack the
    // publisher's round and churn a quarantine. The load-fault hook heals
    // the state on the second attempt; the boot must LOAD the healed key.
    // RED before the grace: the first observation returns CrashSignature
    // immediately. (G3 widened the grace from two polls to a
    // CRASH_SIGNATURE_MIN_PERSIST window; signature_requires_sustained_observation
    // covers the widened floor.)
    #[test]
    fn mid_write_reader_does_not_hijack_before_grace() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::OnceLock;
        static CALLS: AtomicU32 = AtomicU32::new(0);
        static STATE: OnceLock<(std::path::PathBuf, std::path::PathBuf, String)> = OnceLock::new();
        fn heal_on_second_attempt() -> std::io::Result<()> {
            if CALLS.fetch_add(1, Ordering::SeqCst) == 1 {
                let (marker, final_path, pem) = STATE.get().expect("state seeded");
                std::fs::remove_file(marker)?;
                std::fs::write(final_path, pem.as_bytes())?;
            }
            Ok(())
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let marker = dir.path().join(".identity.pem.publishing.99999.0");
        let pem = Keypair::generate().to_pem().expect("pem");
        let expected = format!("{}", Keypair::from_pem(&pem).expect("fixture parses").did());
        STATE
            .set((marker, key_path.clone(), pem.to_string()))
            .expect("state seeded once");

        match super::boot_load_key(&key_path, true, heal_on_second_attempt) {
            super::BootLoad::Loaded(kp) => {
                assert_eq!(
                    format!("{}", kp.did()),
                    expected,
                    "the healed key must be the one loaded"
                );
            }
            super::BootLoad::CrashSignature(e) => {
                panic!("a single mid-write observation must not classify a crash: {e:#}")
            }
            super::BootLoad::Failed(e) => panic!("the healed key must load: {e:#}"),
        }
    }

    // #194 (G3): the crash signature must persist for
    // CRASH_SIGNATURE_MIN_PERSIST of consecutive observations before boot
    // classifies a crash. A few-millisecond glimpse of claimable+content-bad
    // is exactly what a reader sees inside a LIVE publisher's mid-write
    // window once chmod/stat/scheduling latency on shared volumes exceeds
    // one ~2ms poll, and classifying on it hijacks a live round into a
    // quarantine churn. Construction: the crash state persists for THREE
    // observations (~6ms, far under the persistence floor) and then heals;
    // boot must LOAD the healed key. RED before G3: the two-poll grace fires
    // CrashSignature on the second observation, before the heal.
    #[test]
    fn signature_requires_sustained_observation() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::OnceLock;
        static CALLS: AtomicU32 = AtomicU32::new(0);
        static STATE: OnceLock<(std::path::PathBuf, std::path::PathBuf, String)> = OnceLock::new();
        fn heal_before_persistence() -> std::io::Result<()> {
            if CALLS.fetch_add(1, Ordering::SeqCst) == 3 {
                let (marker, final_path, pem) = STATE.get().expect("state seeded");
                std::fs::remove_file(marker)?;
                std::fs::write(final_path, pem.as_bytes())?;
            }
            Ok(())
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let marker = dir.path().join(".identity.pem.publishing.99999.0");
        let pem = Keypair::generate().to_pem().expect("pem");
        let expected = format!("{}", Keypair::from_pem(&pem).expect("fixture parses").did());
        STATE
            .set((marker, key_path.clone(), pem.to_string()))
            .expect("state seeded once");

        match super::boot_load_key(&key_path, true, heal_before_persistence) {
            super::BootLoad::Loaded(kp) => {
                assert_eq!(
                    format!("{}", kp.did()),
                    expected,
                    "the healed key must be the one loaded"
                );
            }
            super::BootLoad::CrashSignature(e) => panic!(
                "a signature cleared inside the persistence window must not classify \
                 a crash: {e:#}"
            ),
            super::BootLoad::Failed(e) => panic!("the healed key must load: {e:#}"),
        }
    }

    // #194 (F2, window-1): a publisher that completes between recovery's
    // claim step and its re-parse must win the round retroactively. The
    // post-claim re-parse sees the completed key, so recovery releases its
    // claims and aborts to Reloaded: no quarantine of a good key, no claim
    // left behind, the completed identity returned. RED before F2: no
    // re-parse exists, so recovery quarantines the just-completed key and
    // regenerates over it.
    #[test]
    fn post_claim_reparse_aborts_to_reload() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let completed = Keypair::generate();
        let pem = completed.to_pem().expect("pem");
        let heal_path = key_path.clone();
        let before_reparse = move || {
            std::fs::write(&heal_path, pem.as_bytes())
                .expect("complete the final inside the claim window");
        };
        let seam = RecoverySeam {
            before_reparse: &before_reparse,
            ..RecoverySeam::NONE
        };

        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("recovery must abort to the completed key");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", completed.did()),
            "the identity completed inside the window must be the one returned"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "a key completed before the re-parse must never be quarantined"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the aborting recovery must release its claims"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "the claimed markers must not reappear"
        );
    }

    // N1: EVERY arm of load_or_create_keypair_with that returns a
    // successfully resolved keypair must run the stale-marker sweep first,
    // including the post-claim-reparse Reloaded arm and the adoption-Lost
    // re-load. Residue that lands after the claim step (or beside a missing
    // final) otherwise persists past a healthy return, and a LATER content
    // failure of the good final would pair with it and misclassify plain
    // corruption as a recoverable crash. RED before N1: both arms return
    // without sweeping and the planted marker and aged claim survive.
    #[test]
    fn reloaded_and_adoption_paths_sweep_before_returning() {
        // Scenario 1: the post-claim-reparse Reloaded arm
        // (post_claim_reparse_aborts_to_reload's construction), with fresh
        // residue planted inside the claim window.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let completed = Keypair::generate();
        let pem = completed.to_pem().expect("pem");
        let heal_path = key_path.clone();
        let residue_dir = dir.path().to_path_buf();
        let before_reparse = move || {
            std::fs::write(&heal_path, pem.as_bytes())
                .expect("complete the final inside the claim window");
            std::fs::write(residue_dir.join(".identity.pem.publishing.31337.0"), b"")
                .expect("plant stale marker inside the claim window");
            let claim = residue_dir.join(".identity.pem.recovering.31337");
            std::fs::write(&claim, b"").expect("plant orphan claim");
            age_beyond_claim_sweep(&claim);
        };
        let seam = RecoverySeam {
            before_reparse: &before_reparse,
            ..RecoverySeam::NONE
        };
        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("the healed final must load");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", completed.did()),
            "the reloaded identity must be the healed key"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "the Reloaded return must sweep stale publish markers"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the Reloaded return must sweep aged orphan claims"
        );

        // Scenario 2: the adoption-Lost re-load. A young adoptable
        // quarantine loses its republish to a final that appears
        // concurrently (before_publish), and the follow-up load returns
        // the winner; the same residue must not survive that return.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let stranded = Keypair::generate();
        std::fs::write(
            dir.path().join(".identity.pem.quarantined.99999.0"),
            stranded.to_pem().expect("pem").as_bytes(),
        )
        .expect("seed young quarantine");
        std::fs::write(dir.path().join(".identity.pem.publishing.31337.0"), b"")
            .expect("seed stale marker");
        let claim = dir.path().join(".identity.pem.recovering.31337");
        std::fs::write(&claim, b"").expect("seed orphan claim");
        age_beyond_claim_sweep(&claim);
        let winner = Keypair::generate();
        let winner_pem = winner.to_pem().expect("pem");
        let race_path = key_path.clone();
        let before_publish = move || {
            if race_path.exists() {
                return;
            }
            let out = publish_key_atomically(
                &race_path,
                winner_pem.as_bytes(),
                &|| {},
                &|| {},
                PublishFaults::NONE,
            )
            .expect("concurrent winner publishes");
            assert!(matches!(out, KeyPublish::Won), "the winner takes the name");
        };
        let seam = RecoverySeam {
            before_publish: &before_publish,
            ..RecoverySeam::NONE
        };
        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("the adoption-Lost re-load must resolve the winner");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", winner.did()),
            "the adoption-Lost arm must defer to the concurrent winner"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "the adoption-Lost return must sweep stale publish markers"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the adoption-Lost return must sweep aged orphan claims"
        );
    }

    // #194 (G2a) MUST-NOT: a TRANSIENT (non-content) failure of the
    // post-claim RE-parse proves nothing about the final's content, so
    // recovery must release its claims and surface the error loudly,
    // destroying nothing: quarantining on it would destroy a possibly good
    // key, the protocol's own must-not. The reparse_fault seam injects the
    // transient class deterministically (load_fault only reaches
    // boot_load_key's attempts, never this re-parse). RED before G2a: any
    // re-parse error is treated as still-crashed and the final is
    // quarantined.
    #[test]
    fn transient_reparse_error_releases_claims_and_fails_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let seam = RecoverySeam {
            reparse_fault: || Err(std::io::Error::other("injected transient reparse failure")),
            ..RecoverySeam::NONE
        };

        let err =
            match load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            {
                Err(e) => e,
                Ok(_) => panic!("a transient re-parse failure must stay loud, never resolve"),
            };
        assert!(
            format!("{err:#}").contains("injected transient reparse failure"),
            "the transient failure must surface: {err:#}"
        );
        assert_eq!(
            std::fs::read(&key_path).expect("final still on disk"),
            b"",
            "the final's bytes must be untouched"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "a transient re-parse failure must never quarantine"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the failing recovery must release its claims, not leak them"
        );
    }

    // #194 (G2b): a publisher that completes its write AFTER the re-parse
    // observation and BEFORE the quarantine rename has its VALID key swept
    // into quarantine; the rename preserves the bytes, so recovery must
    // parse the quarantined bytes, detect the completed key, restore it to
    // the final name, release its claims, and return that identity: no
    // regeneration, no divergence from the Won the publisher already
    // reported. The before_quarantine seam lands the completed write in
    // exactly that window (before_reparse fires too early: the re-parse
    // would catch it). RED before G2b: the completed key stays quarantined
    // and a fresh identity is regenerated over it.
    #[test]
    fn completed_key_is_restored_from_quarantine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let completed = Keypair::generate();
        let pem = completed.to_pem().expect("pem");
        let heal_path = key_path.clone();
        let before_quarantine = move || {
            std::fs::write(&heal_path, pem.as_bytes())
                .expect("complete the final inside the re-parse-to-rename window");
        };
        let seam = RecoverySeam {
            before_quarantine: &before_quarantine,
            ..RecoverySeam::NONE
        };

        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("recovery must restore the completed key, not fail or regenerate");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", completed.did()),
            "the completed identity must be the one returned, never a regeneration"
        );
        let on_disk = super::load_existing_key(&key_path).expect("restored final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", completed.did()),
            "the final must hold the restored key"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "the quarantine must be removed once its key is republished at the final"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the aborting recovery must release its claims"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "the claimed markers must not reappear"
        );
    }

    // M2, the N4 mirror on the RESTORE arm: the G2b restore decides its
    // round in favor of the restored key, but it used to remove only the
    // quarantine it consumed. A second young parseable quarantine (an
    // earlier crash's residue) stayed adoptable, so a later missing final
    // resurrected a DIFFERENT historical DID. On Won the restore must
    // supersede every other young parseable sibling, exactly like
    // adoption-Won. RED before M2: Q_old stays `.quarantined.` and the
    // post-delete boot adopts it.
    #[test]
    fn restore_won_supersedes_siblings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let older = Keypair::generate();
        let older_pem = older.to_pem().expect("pem");
        let q_old = dir.path().join(".identity.pem.quarantined.11111.0");
        std::fs::write(&q_old, older_pem.as_bytes()).expect("seed sibling quarantine");

        // completed_key_is_restored_from_quarantine's construction: the
        // publisher completes inside the re-parse-to-rename window, so its
        // key is swept into a fresh quarantine and restored from there.
        let completed = Keypair::generate();
        let pem = completed.to_pem().expect("pem");
        let heal_path = key_path.clone();
        let before_quarantine = move || {
            std::fs::write(&heal_path, pem.as_bytes())
                .expect("complete the final inside the re-parse-to-rename window");
        };
        let seam = RecoverySeam {
            before_quarantine: &before_quarantine,
            ..RecoverySeam::NONE
        };
        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("recovery must restore the completed key");
        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", completed.did()),
            "the restored identity must be the completed key"
        );

        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "the restore-Won round must leave no adoptable quarantine behind"
        );
        let superseded = names_containing(dir.path(), ".superseded.");
        assert_eq!(
            superseded.len(),
            1,
            "exactly the outcompeted sibling is superseded: {superseded:?}"
        );
        assert_eq!(
            std::fs::read(dir.path().join(&superseded[0])).expect("superseded readable"),
            older_pem.as_bytes(),
            "the superseded sibling must preserve its bytes as forensics"
        );

        // The sibling must not come back once the final goes missing.
        std::fs::remove_file(&key_path).expect("operator deletes the final");
        let fresh = load_or_create_keypair(&key_config(&key_path))
            .expect("the post-delete boot must provision an identity");
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", older.did()),
            "the superseded sibling must never be resurrected"
        );
        assert_ne!(
            format!("{}", fresh.did()),
            format!("{}", completed.did()),
            "the operator must get a genuinely fresh DID"
        );
    }

    // R1: the post-quarantine restore must hold no-clobber on EVERY tier. A
    // completed key A is swept into quarantine (G2b), a concurrent starter
    // publishes a fresh key B at the freed final name inside the
    // quarantine-to-restore window (before_restore), and the restore's link
    // tier is forced onto its link-hostile degradation (restore_faults.link).
    // The restore must defer to B (keep A's bytes as forensics, converge
    // on B), never replace B with A: B's owner already holds B in memory, so
    // a clobber leaves that node's memory and disk diverged. RED before the
    // fix: the old restore ladder degraded to a plain rename(quarantine ->
    // final), which clobbered B with A. Since N2, the kept forensics live in
    // the SUPERSEDED class (A provably lost the round, so it must never be
    // adoptable); lost_restore_quarantine_is_never_adopted covers that side.
    #[test]
    fn restore_never_clobbers_a_concurrent_winner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = seed_crash_state(dir.path(), b"");
        let completed = Keypair::generate();
        let pem_a = completed.to_pem().expect("pem a");
        let kp_b = Keypair::generate();
        let pem_b = kp_b.to_pem().expect("pem b");

        let heal_path = key_path.clone();
        let before_quarantine = move || {
            std::fs::write(&heal_path, pem_a.as_bytes())
                .expect("complete the final inside the re-parse-to-rename window");
        };
        let steal_path = key_path.clone();
        let pem_b_disk = pem_b.clone();
        let before_restore = move || {
            let out = publish_key_atomically(
                &steal_path,
                pem_b_disk.as_bytes(),
                &|| {},
                &|| {},
                PublishFaults::NONE,
            )
            .expect("concurrent starter republishes key B at the freed name");
            assert!(
                matches!(out, KeyPublish::Won),
                "B's publish wins the free name"
            );
        };
        let seam = RecoverySeam {
            before_quarantine: &before_quarantine,
            before_restore: &before_restore,
            restore_faults: PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                ..PublishFaults::NONE
            },
            ..RecoverySeam::NONE
        };

        let kp = load_or_create_keypair_with(&key_path, &|| {}, &|| {}, PublishFaults::NONE, seam)
            .expect("the restore must converge on B, not fail the start");

        assert_eq!(
            format!("{}", kp.did()),
            format!("{}", kp_b.did()),
            "the recovering boot must converge on the concurrent winner's key B"
        );
        let on_disk = super::load_existing_key(&key_path).expect("final parses");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp_b.did()),
            "key B must survive at the final name on every restore tier"
        );
        let superseded = names_containing(dir.path(), ".superseded.");
        assert_eq!(
            superseded.len(),
            1,
            "the losing restore must keep A's bytes as superseded forensics: {superseded:?}"
        );
        assert!(
            names_containing(dir.path(), ".quarantined.").is_empty(),
            "the losing key must not stay in the adoptable quarantine class"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "the recovery must release its claims"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
    }

    // Regression guard: a fallback publisher whose round was claimed by a
    // recovery (its inode quarantined away, a live key B republished at the
    // name) must NOT let its own failure cleanup unlink B. The post-write
    // error arms now remove nothing at all (any unlink there is a
    // stat-then-unlink race against the recoverer), which this interleave
    // pins. It runs inside the fallback_fsync fault (before_commit never
    // fires on the error arms), step for step what a claiming recovery does:
    // claim A's marker, quarantine A's final by rename, republish B, clear
    // the claim; then the injected Err forces A's fsync-failure arm. RED if
    // any by-name removal returns to that arm: A deletes B, destroying the
    // live identity whose owner already returned Won.
    #[test]
    fn failed_publisher_cleanup_spares_a_republished_final() {
        thread_local! {
            static STEAL: std::cell::RefCell<
                Option<(std::path::PathBuf, std::path::PathBuf, String)>,
            > = const { std::cell::RefCell::new(None) };
        }
        fn steal_round_then_fail_fsync() -> std::io::Result<()> {
            STEAL.with(|s| {
                if let Some((dir, key_path, pem_b)) = s.borrow_mut().take() {
                    let markers = names_containing(&dir, ".publishing.");
                    assert_eq!(
                        markers.len(),
                        1,
                        "A's window must be bracketed: {markers:?}"
                    );
                    let claim = dir.join(".identity.pem.recovering.55555");
                    std::fs::rename(dir.join(&markers[0]), &claim).expect("claim A's marker");
                    std::fs::rename(&key_path, dir.join(".identity.pem.quarantined.55555.0"))
                        .expect("quarantine A's inode away");
                    let out = publish_key_atomically(
                        &key_path,
                        pem_b.as_bytes(),
                        &|| {},
                        &|| {},
                        PublishFaults::NONE,
                    )
                    .expect("recoverer republishes key B");
                    assert!(matches!(out, KeyPublish::Won), "recoverer's republish wins");
                    std::fs::remove_file(&claim).expect("clear the claim");
                }
            });
            Err(std::io::Error::other("injected fsync failure"))
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let kp_b = Keypair::generate();
        let pem_b = kp_b.to_pem().expect("pem b");
        STEAL.with(|s| {
            *s.borrow_mut() = Some((dir.path().to_path_buf(), key_path.clone(), (*pem_b).clone()));
        });
        let pem_a = Keypair::generate().to_pem().expect("pem a");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_fsync: steal_round_then_fail_fsync,
            ..PublishFaults::NONE
        };

        let err = match publish_key_atomically(&key_path, pem_a.as_bytes(), &|| {}, &|| {}, faults)
        {
            Err(e) => e,
            Ok(_) => panic!("A's failed fsync must still error A's publish"),
        };
        assert!(
            format!("{err:#}").contains("injected fsync failure"),
            "the fsync failure must surface: {err:#}"
        );
        let on_disk = super::load_existing_key(&key_path)
            .expect("the republished final must survive A's cleanup");
        assert_eq!(
            format!("{}", on_disk.did()),
            format!("{}", kp_b.did()),
            "A's error-arm cleanup must spare the recoverer's key B"
        );
        let quarantined = names_containing(dir.path(), ".quarantined.");
        assert_eq!(
            quarantined.len(),
            1,
            "A's quarantined inode stays where the recoverer put it: {quarantined:?}"
        );
        assert!(
            names_containing(dir.path(), ".recovering.").is_empty(),
            "no recovery claims may remain"
        );
        assert!(
            names_containing(dir.path(), ".publishing.").is_empty(),
            "no publish markers may remain"
        );
    }
}

#[cfg(test)]
mod shutdown_grace_tests {
    use super::drive_serve_with_grace;
    use std::time::{Duration, Instant};

    // The must-not case: the drain (serve future) never completes but the signal
    // has fired. The grace deadline must fire, report `grace_expired = true`, and
    // return promptly so teardown proceeds — not hang forever. RED: a helper that
    // just awaits `serve` (ignoring grace) hangs this test past its bound.
    #[tokio::test]
    async fn hung_drain_is_abandoned_after_grace() {
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();
        let _ = armed_tx.send(()); // signal already fired
        let serve = std::future::pending::<std::io::Result<()>>(); // never drains
        let start = Instant::now();

        let (result, grace_expired) =
            drive_serve_with_grace(serve, armed_rx, Duration::from_millis(50)).await;

        assert!(grace_expired, "a drain outlasting grace must be abandoned");
        assert!(
            result.is_ok(),
            "abandon path returns Ok so teardown proceeds"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "must not wait indefinitely for the hung drain"
        );
    }

    // Normal drain: the serve future completes before grace, so the real serve
    // result is propagated and `grace_expired` is false.
    #[tokio::test]
    async fn completed_drain_keeps_result_and_does_not_expire() {
        let (_armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = std::future::ready(Ok::<(), std::io::Error>(()));

        let (result, grace_expired) =
            drive_serve_with_grace(serve, armed_rx, Duration::from_secs(3600)).await;

        assert!(
            !grace_expired,
            "a completed drain must not report grace expiry"
        );
        assert!(result.is_ok());
    }

    // The grace clock starts at the SIGNAL, not at call time. With the signal
    // unsent, a finite drain longer than `grace` still completes normally — total
    // uptime is never bounded by grace. RED: drop `armed.await` from the grace
    // branch and the deadline fires at 10ms, expiring before the 80ms drain.
    #[tokio::test]
    async fn grace_clock_starts_at_signal_not_call() {
        let (_armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();
        // Signal never fires; drain finishes after > grace.
        let serve = async {
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok::<(), std::io::Error>(())
        };

        let (result, grace_expired) =
            drive_serve_with_grace(serve, armed_rx, Duration::from_millis(10)).await;

        assert!(
            !grace_expired,
            "grace must not fire while the shutdown signal is unsent"
        );
        assert!(result.is_ok());
    }

    // Real-socket contract: at grace expiry the server abandons a request still
    // in flight; the client never receives a 503 (or any late error response),
    // it just observes the connection going away or no response at all. Wires a
    // real `axum::serve` future through `drive_serve_with_grace` exactly as the
    // production path does. RED: asserting the client reads back an
    // "HTTP/1.1 503" status line fails (no response bytes ever arrive).
    #[tokio::test]
    async fn real_socket_in_flight_request_abandoned_without_503() {
        use axum::routing::get;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // The slow handler signals once the request is in flight, then outlasts
        // the grace by a wide margin.
        let entered = Arc::new(tokio::sync::Notify::new());
        let entered_tx = entered.clone();
        let app = axum::Router::new().route(
            "/slow",
            get(move || {
                let entered_tx = entered_tx.clone();
                async move {
                    entered_tx.notify_one();
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    "done"
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Mirror the production wiring: axum drains on a watch flip, and the
        // graceful-shutdown closure arms the grace clock at the signal.
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
            while !*shutdown_rx.borrow_and_update() {
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
            let _ = armed_tx.send(());
        });

        let driver = tokio::spawn(drive_serve_with_grace(
            serve,
            armed_rx,
            Duration::from_millis(250),
        ));

        // Put a request in flight on the slow route and wait until the handler
        // is actually running, so the drain has something to abandon.
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /slow HTTP/1.1\r\nhost: test\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .expect("slow handler must start before the shutdown signal fires");

        // Fire the shutdown signal; the in-flight request now outlasts grace.
        let signal_at = Instant::now();
        shutdown_tx.send(true).unwrap();

        let (result, grace_expired) = tokio::time::timeout(Duration::from_secs(5), driver)
            .await
            .expect("driver must return soon after grace expiry, not hang on the drain")
            .expect("driver task must not panic");
        assert!(
            grace_expired,
            "an in-flight request outlasting grace must be abandoned"
        );
        assert!(
            result.is_ok(),
            "abandon path returns Ok so teardown proceeds"
        );
        assert!(
            signal_at.elapsed() < Duration::from_secs(5),
            "must return within a bounded window past the grace"
        );

        // The client must never see a 503 status line: the request is abandoned
        // at the transport, not answered. Read whatever arrives before a bounded
        // window; a clean close (EOF) and no bytes at all both satisfy the
        // contract.
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut buf)).await;
        assert!(
            !buf.starts_with(b"HTTP/1.1 503"),
            "abandoned in-flight request must not be answered with a 503; got: {:?}",
            String::from_utf8_lossy(&buf)
        );
    }
}
