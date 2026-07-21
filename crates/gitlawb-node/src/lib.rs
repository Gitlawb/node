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
    let prefix = format!(".{stem}.publishing.");
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
    /// Content-class failure observed while a `.publishing.` marker was
    /// present; returned immediately, without riding the deadline.
    CrashSignature(anyhow::Error),
    /// Any other failure, after the full deadline.
    Failed(anyhow::Error),
}

/// `load_racing_key` for the boot loop (#194, U2). With `crash_exit` set, a
/// content-class failure (`KeyContentError`) observed while a `.publishing.`
/// marker is present returns `CrashSignature` IMMEDIATELY instead of riding
/// the deadline: marker plus unreadable content is the crash signature
/// recovery exists for, and the caller's atomic claim rename arbitrates the
/// (rare) race against a live fallback publisher still inside its window.
/// Every other failure keeps the full wall-clock deadline. `load_fault` is
/// the injection hook (a no-op `Ok` in production); an injected `Err` is
/// taken as that attempt's result and is NOT content-class.
fn boot_load_key(
    path: &std::path::Path,
    crash_exit: bool,
    load_fault: fn() -> std::io::Result<()>,
) -> BootLoad {
    let deadline = std::time::Instant::now() + KEY_RACE_DEADLINE;
    let mut last_err;
    loop {
        match load_fault()
            .map_err(anyhow::Error::new)
            .and_then(|()| load_existing_key(path))
        {
            Ok(kp) => return BootLoad::Loaded(Box::new(kp)),
            Err(e) => last_err = e,
        }
        if crash_exit && is_key_content_error(&last_err) && !list_publish_markers(path).is_empty() {
            return BootLoad::CrashSignature(last_err);
        }
        if std::time::Instant::now() >= deadline {
            return BootLoad::Failed(last_err);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
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
/// exactly one winner and a lost race loads the existing key. It weakens (a),
/// (c), and (d): the final name is visible while the PEM is being written, a
/// window concurrent readers ride out via `load_racing_key`'s wall-clock
/// deadline; a crash mid-write leaves a partial final that fails loudly
/// (`invalid PEM key`) at the next start rather than being cleaned up; and the
/// final name can become durable before the PEM bytes are fsynced, so a power
/// loss can additionally leave a durable empty/truncated final. In every case
/// the failure mode is the same LOUD invalid-PEM (or mode) error at the next
/// start, never a silently used key.
///
/// `before_link` is a no-op in production; tests use it to widen the
/// post-write / pre-link window deterministically. `faults` is the
/// compile-time fault-injection seam (`PublishFaults::NONE` in production).
fn publish_key_atomically(
    final_path: &std::path::Path,
    pem: &[u8],
    before_link: &dyn Fn(),
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
        Err(e) => publish_key_fallback(final_path, pem, e, faults),
    }
}

/// Fallback publish for a key directory whose filesystem cannot hard-link
/// (Unsupported/EPERM on some network and overlay mounts, or a transient link
/// error): create the FINAL path directly with `create_new(true).mode(0o600)`
/// (the INV-23 creation pattern) and write the PEM into it. `AlreadyExists`
/// still routes to the lost-race path, so no-clobber holds. Error handling: a
/// failed `write_all` OR file `sync_all` removes the final (#194 F1) — the
/// `create_new` already made the final NAME durable, so a name left over
/// non-durable content lets a later crash leave a truncated final that wedges
/// every later start; removal lets the next start regenerate. Only a failed
/// parent-DIR fsync keeps the final (the content is complete and data-synced,
/// and a lost directory entry just disappears -> clean regen, no wedge). Every
/// error context chains `link_err` so a two-step failure is diagnosable.
///
/// The whole non-atomic window is bracketed by a durable publish marker
/// (`.{stem}.publishing.{pid}.{attempt}`, empty, same dir as the final): the
/// marker is created and its NAME fsynced BEFORE the final can exist, and it
/// is removed only once the final is complete-and-durable (success) or
/// disposed of (error / lost race). A crash inside the window therefore
/// leaves marker+final together, so a later boot can tell "partial final from
/// a crashed fallback publish" from a key an operator corrupted (#194, U1).
/// Two constraints:
///   - Disposal ORDER is pinned: wherever the error policy removes the final,
///     that removal is ISSUED BEFORE the marker's. Cleanup is deliberately
///     NOT a Drop guard: a drop guard can run ahead of the final's disposal
///     on an early exit, and a crash between the reordered unlinks would
///     recreate exactly the marker-less partial final this bracket exists to
///     prevent.
///   - The marker dir fsync is warn-and-continue, not a hard gate: on
///     dir-fsync-hostile mounts a hard failure would turn "wedge once, then
///     recover" into "never provisions". Without that durability the marker
///     still survives SIGKILL-class crashes (the fs state persists); only the
///     power-loss protection narrows.
fn publish_key_fallback(
    final_path: &std::path::Path,
    pem: &[u8],
    link_err: std::io::Error,
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
    let mut marker = None;
    for attempt in 0..KEY_TEMP_ATTEMPTS {
        let candidate = dir.join(format!(
            ".{stem}.publishing.{}.{attempt}",
            std::process::id()
        ));
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
            "all {KEY_TEMP_ATTEMPTS} publish marker names .{stem}.publishing.{}.* in {} are \
             taken; remove the stale marker files and restart (link failed: {link_err})",
            std::process::id(),
            dir.display()
        );
    };
    // Marker disposal is explicit at every exit, never a Drop guard; see the
    // order constraint in the doc comment.
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
    // AlreadyExists, and is safe here for the same reason as everywhere: the
    // file is still empty, so the split-phase keep-the-final rule below does
    // not apply yet. The helper removes the final before returning Err, so
    // the pinned final-before-marker disposal order holds.
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
    // A failed write removes the final (partial content cannot parse and would
    // wedge every later start). The helper removes the final before returning
    // Err, so the pinned final-before-marker disposal order holds.
    if let Err(e) = write_key_or_cleanup(
        final_path,
        (faults.fallback_write)().and_then(|()| f.write_all(pem)),
    )
    .with_context(|| {
        format!(
            "hard_link fallback publish to {} (link failed: {link_err})",
            final_path.display()
        )
    }) {
        dispose_marker();
        return Err(e);
    }
    // Fsync the file, and REMOVE the final on failure too (#194 F1). Unlike the
    // hard-link path (which fsyncs a TEMP, so the final NAME only ever appears
    // over a durable inode), the fallback's `create_new` already made the final
    // name durable, so a bytes-accepted-but-not-durable final would let a later
    // crash leave a truncated file that `load_or_create_keypair` parses forever
    // via the existing-file path instead of regenerating -> permanent startup
    // wedge. Removing it mirrors the hard-link temp policy and lets the next
    // start regenerate. A DISTINCT context is kept so an operator debugging
    // ENOSPC/EIO can tell "durability failed" (bytes accepted, not synced) from
    // the write-rejected case above. Only the parent-DIR fsync below keeps the
    // final on failure (a lost directory entry just disappears -> clean regen).
    // Final removal is issued first, marker disposal second (pinned order).
    if let Err(e) = (faults.fallback_fsync)().and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(final_path);
        dispose_marker();
        return Err(anyhow::Error::new(e).context(format!(
            "fsync identity key {} in hard_link fallback (durability failed, \
             removed; link failed: {link_err})",
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
    // Success: the final is complete and durable, so the bracket closes.
    // Remove the marker, then best-effort fsync the removal so it tends to be
    // durable too. (A later unit turns this removal into a commit check; U1
    // keeps it best-effort.)
    dispose_marker();
    #[cfg(unix)]
    {
        let _ = fsync_parent_dir(final_path);
    }
    Ok(KeyPublish::Won)
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
}

impl RecoverySeam<'_> {
    /// The production value: no fault, no hook.
    const NONE: RecoverySeam<'static> = RecoverySeam {
        load_fault: || Ok(()),
        before_publish: &|| {},
    };
}

fn load_or_create_keypair(config: &Config) -> Result<Keypair> {
    load_or_create_keypair_with(
        &config.resolved_key_path(),
        &|| {},
        PublishFaults::NONE,
        RecoverySeam::NONE,
    )
}

/// Outcome of `recover_crashed_publish` (#194, U2).
enum Recovery {
    /// A marker was claimed and the corrupt final quarantined (or removed);
    /// the caller regenerates. Holds the claim file's path, removed only
    /// after the follow-up publish resolves.
    Claimed(std::path::PathBuf),
    /// The marker vanished before it could be claimed (the publisher — or a
    /// competing recoverer — resolved the window concurrently): the single
    /// follow-up load's result is final, success or error, no recovery.
    /// Boxed to keep the variants' sizes comparable (clippy:
    /// large_enum_variant); the enum lives only across a boot-time match.
    Reloaded(Box<Result<Keypair>>),
}

/// Claim-and-quarantine for a boot whose load returned `CrashSignature`: a
/// content-class failure beside a `.publishing.` marker — U1's signature of
/// a fallback publish crashed inside its non-atomic window (#194, U2).
/// Atomically claims ONE marker (rename to `.{stem}.recovering.{pid}`, so N
/// racing recoverers admit exactly one), quarantines the corrupt final by
/// rename (preserving bytes and mode for post-mortem; falls back to removal
/// only if every quarantine name fails), consumes any remaining markers
/// best-effort, and hands control back to regenerate. The caller observed a
/// marker, so finding none here (or losing the claim rename) means the
/// window was resolved concurrently: one immediate re-load decides, with no
/// recovery.
fn recover_crashed_publish(
    final_path: &std::path::Path,
    load_err: anyhow::Error,
) -> Result<Recovery> {
    let dir = final_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let stem = final_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("identity.pem");
    let markers = list_publish_markers(final_path);
    let Some(first_marker) = markers.first() else {
        return Ok(Recovery::Reloaded(Box::new(load_racing_key(final_path))));
    };

    // CLAIM one marker atomically. rename admits exactly one winner: a
    // competing recoverer (or the publisher finishing and removing its
    // marker) leaves NotFound, which means the window resolved concurrently;
    // one immediate re-load decides, with no recovery.
    let claim = dir.join(format!(".{stem}.recovering.{}", std::process::id()));
    match std::fs::rename(first_marker, &claim) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Recovery::Reloaded(Box::new(load_racing_key(final_path))));
        }
        Err(e) => {
            return Err(load_err.context(format!(
                "could not claim publish marker {} for crash recovery: {e}",
                first_marker.display()
            )));
        }
    }

    // QUARANTINE the final under a bounded name probe (the KEY_TEMP_ATTEMPTS
    // discipline: a stale quarantine from a crashed same-PID start must not
    // wedge this one). The warn precedes the move and carries stable
    // operator-greppable fields; the destination it names is the first free
    // candidate, which the rename below tries first.
    let dest_for = |n: u32| dir.join(format!(".{stem}.quarantined.{}.{n}", std::process::id()));
    let start = (0..KEY_TEMP_ATTEMPTS)
        .find(|&n| !dest_for(n).exists())
        .unwrap_or(0);
    warn!(
        path = %final_path.display(),
        markers = ?markers,
        claim = %claim.display(),
        quarantine = %dest_for(start).display(),
        "crash-interrupted identity key publish: quarantining the unreadable key and \
         regenerating the identity"
    );
    let mut quarantined = false;
    for n in start..KEY_TEMP_ATTEMPTS {
        let dest = dest_for(n);
        if dest.exists() {
            continue;
        }
        match std::fs::rename(final_path, &dest) {
            Ok(()) => {
                quarantined = true;
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
        // fails is the boot left to its loud error.
        if let Err(e) = std::fs::remove_file(final_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(anyhow::Error::new(e).context(format!(
                    "could not quarantine or remove corrupt identity key {} during crash \
                     recovery",
                    final_path.display()
                )));
            }
        }
    }

    // Consume any remaining markers (a multi-crash pile-up) best-effort, and
    // best-effort fsync the directory so the transition tends to be durable.
    for marker in list_publish_markers(final_path) {
        let _ = std::fs::remove_file(&marker);
    }
    #[cfg(unix)]
    {
        let _ = fsync_parent_dir(final_path);
    }
    Ok(Recovery::Claimed(claim))
}

/// Body of `load_or_create_keypair` with the test seams threaded in (#194,
/// U2): `before_link` and `faults` pass through to `publish_key_atomically`
/// (production: no-op / `NONE`), `seam` is the load-side recovery seam
/// (production: `RecoverySeam::NONE`).
///
/// Load-or-generate with AT MOST ONE crash recovery per start: a load
/// failure recovers — claim a marker, quarantine the final, regenerate —
/// only when it is content-class (`KeyContentError`), a `.publishing.`
/// marker exists (U1's crash signature), and no recovery has run yet this
/// start. Every other failure surfaces unchanged. The Lost arm participates
/// in the same policy; a recovery fired there loops back for one retry
/// publish, and any failure on that second pass surfaces unchanged.
fn load_or_create_keypair_with(
    key_path: &std::path::Path,
    before_link: &dyn Fn(),
    faults: PublishFaults,
    seam: RecoverySeam<'_>,
) -> Result<Keypair> {
    // The claim file of a fired recovery. Removed (best-effort) only at exits
    // AFTER the follow-up publish resolves (Won or Lost), so a stalled winner
    // our claim demoted can still observe it while waiting; U3 relies on
    // this. The pre-publish error exits inside recover_crashed_publish
    // deliberately leave it in place.
    let mut claim: Option<std::path::PathBuf> = None;
    let remove_claim = |claim: &Option<std::path::PathBuf>| {
        if let Some(c) = claim {
            let _ = std::fs::remove_file(c);
        }
    };
    let mut recovery_allowed = true;

    // At most two passes: the second exists only so a Lost-arm recovery can
    // retry the generate+publish once.
    for _pass in 0..2 {
        // Fast path for the common already-provisioned case (still race-safe: a
        // concurrently-publishing winner is handled by the retry in
        // boot_load_key).
        if key_path.exists() {
            match boot_load_key(key_path, recovery_allowed, seam.load_fault) {
                BootLoad::Loaded(kp) => {
                    remove_claim(&claim);
                    return Ok(*kp);
                }
                // Only emitted while recovery is still allowed (crash_exit is
                // gated on it).
                BootLoad::CrashSignature(e) => match recover_crashed_publish(key_path, e)? {
                    Recovery::Claimed(c) => {
                        claim = Some(c);
                        recovery_allowed = false;
                        // Fall through to regenerate and publish.
                    }
                    Recovery::Reloaded(result) => return *result,
                },
                BootLoad::Failed(e) => {
                    remove_claim(&claim);
                    return Err(e);
                }
            }
        }

        (seam.before_publish)();
        let kp = Keypair::generate();
        let pem = kp
            .to_pem()
            .map_err(|e| anyhow::anyhow!("failed to serialize key: {e}"))?;

        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Publish atomically: the final path only ever appears complete, and a
        // lost race loads the winner's key rather than overwriting it.
        match publish_key_atomically(key_path, pem.as_bytes(), before_link, faults)? {
            KeyPublish::Won => {
                remove_claim(&claim);
                info!(path = %key_path.display(), did = %kp.did(), "generated new node identity");
                return Ok(kp);
            }
            KeyPublish::Lost => {
                match boot_load_key(key_path, recovery_allowed, seam.load_fault) {
                    BootLoad::Loaded(kp) => {
                        remove_claim(&claim);
                        return Ok(*kp);
                    }
                    // Only emitted while recovery is still allowed (crash_exit
                    // is gated on it).
                    BootLoad::CrashSignature(e) => match recover_crashed_publish(key_path, e) {
                        Ok(Recovery::Claimed(c)) => {
                            claim = Some(c);
                            recovery_allowed = false;
                            continue; // Second pass: regenerate and publish.
                        }
                        Ok(Recovery::Reloaded(result)) => {
                            remove_claim(&claim);
                            return *result;
                        }
                        Err(err) => {
                            remove_claim(&claim);
                            return Err(err);
                        }
                    },
                    BootLoad::Failed(e) => {
                        remove_claim(&claim);
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
            publish_key_atomically(&writer_path, pem.as_bytes(), &|| {}, PublishFaults::NONE)
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

        let out = publish_key_atomically(&key_path, pem_a.as_bytes(), &|| {}, PublishFaults::NONE)
            .expect("publish a");
        assert!(matches!(out, KeyPublish::Won), "first publish wins");
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap().as_str(),
            pem_a.as_str(),
            "final holds the full PEM"
        );

        let out = publish_key_atomically(&key_path, pem_b.as_bytes(), &|| {}, PublishFaults::NONE)
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

        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, PublishFaults::NONE)
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

        let err =
            match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, PublishFaults::NONE) {
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

        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults)
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
            PublishFaults::NONE,
        )
        .expect("winner publishes");
        assert!(matches!(out, KeyPublish::Won), "winner publish wins");

        let pem_loser = Keypair::generate().to_pem().expect("pem loser");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::PermissionDenied.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem_loser.as_bytes(), &|| {}, faults)
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
                    match publish_key_atomically(&kp, pem.as_bytes(), &|| {}, faults)
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

    // A failed fallback WRITE removes the final: partial content cannot parse
    // and would wedge every later start on `invalid PEM key`. The error must
    // surface the write failure AND the original link error, so a two-step
    // failure is diagnosable.
    #[test]
    fn failed_fallback_write_removes_the_partial_final() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_write: || Err(std::io::Error::other("injected write failure")),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults) {
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
            !key_path.exists(),
            "a failed fallback write must remove the partial final"
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
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults) {
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

    // A failed fallback FILE fsync must REMOVE the final: create_new has already
    // made the final NAME durable, so a name left over non-durable content lets a
    // later crash leave a truncated final that load_or_create_keypair parses
    // forever (existing-file path) instead of regenerating -> permanent startup
    // wedge (#194 F1, jatmn). The fallback now mirrors the hard-link temp policy
    // (write_key_or_cleanup removes on write OR fsync failure); removal makes the
    // next start regenerate cleanly. Only the parent-DIR fsync keeps on failure.
    #[test]
    fn failed_fallback_fsync_removes_the_unsynced_final() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::Unsupported.into()),
            fallback_fsync: || Err(std::io::Error::other("injected fsync failure")),
            ..PublishFaults::NONE
        };
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults) {
            Err(e) => e,
            Ok(_) => panic!("a failed fallback fsync must error the start"),
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("injected fsync failure"),
            "the error must surface the fsync failure: {msg}"
        );
        assert!(
            !key_path.exists(),
            "an fsync failure on the fallback must remove the un-synced final so \
             the next start regenerates instead of wedging on a truncated file"
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

        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults)
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
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults) {
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
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults) {
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
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, retry_faults)
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
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults)
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
            PublishFaults::NONE,
        )
        .expect("winner publishes");
        assert!(matches!(out, KeyPublish::Won), "winner publish wins");

        let pem_loser = Keypair::generate().to_pem().expect("pem loser");
        let faults = PublishFaults {
            link: || Err(std::io::ErrorKind::PermissionDenied.into()),
            ..PublishFaults::NONE
        };
        let out = publish_key_atomically(&key_path, pem_loser.as_bytes(), &|| {}, faults)
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

    /// Shared body for the fallback error-arm marker tests (#194, U1): with the
    /// link fault plus one injected fallback fault, the error must surface as
    /// today, the final must be absent (today's removal policy for every one of
    /// these arms), and no publish marker may remain.
    fn assert_fallback_error_leaves_no_marker_or_final(faults: PublishFaults, injected: &str) {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("identity.pem");
        let pem = Keypair::generate().to_pem().expect("pem");

        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults) {
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

    #[test]
    fn failed_fallback_write_leaves_no_marker() {
        assert_fallback_error_leaves_no_marker_or_final(
            PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                fallback_write: || Err(std::io::Error::other("injected write failure")),
                ..PublishFaults::NONE
            },
            "injected write failure",
        );
    }

    #[test]
    fn failed_fallback_fsync_leaves_no_marker() {
        assert_fallback_error_leaves_no_marker_or_final(
            PublishFaults {
                link: || Err(std::io::ErrorKind::Unsupported.into()),
                fallback_fsync: || Err(std::io::Error::other("injected fsync failure")),
                ..PublishFaults::NONE
            },
            "injected fsync failure",
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
        let err = match publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults) {
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
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults)
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
        let out = publish_key_atomically(&key_path, pem.as_bytes(), &|| {}, faults)
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

        let kp = load_or_create_keypair(&key_config(&key_path))
            .expect("a crash-marked empty final must recover, not wedge the start");

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

        let err = match load_or_create_keypair_with(&key_path, &|| {}, PublishFaults::NONE, seam) {
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

        let err = match load_or_create_keypair_with(&key_path, &|| {}, PublishFaults::NONE, seam) {
            Err(e) => e,
            Ok(_) => panic!("a second crash state in the same start must error, not recover again"),
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

        let kp = load_or_create_keypair_with(&key_path, &before_link, faults, RecoverySeam::NONE)
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
