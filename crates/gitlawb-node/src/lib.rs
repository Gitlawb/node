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

fn load_or_create_keypair(config: &Config) -> Result<Keypair> {
    let key_path = config.resolved_key_path();

    // Load an already-provisioned key. On Unix, defensively tighten looser
    // permissions to 0600 (do NOT reject a loose key — that would break
    // existing deployments; just narrow them).
    fn load_existing(path: &std::path::Path) -> Result<Keypair> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.permissions().mode() & 0o777 != 0o600 {
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                }
            }
        }
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read key from {}", path.display()))?;
        let kp = Keypair::from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid PEM key: {e}"))?;
        info!(path = %path.display(), "loaded existing identity");
        Ok(kp)
    }

    // Load a key another concurrent start may still be writing. `create_new`
    // makes the inode appear before its PEM is flushed, so a race loser — or a
    // fast-path `exists()` that caught the winner mid-write — can momentarily
    // read an empty/partial file. Retry briefly until it parses rather than
    // crashing the boot. Bounded (~100ms); an already-provisioned key parses on
    // the first attempt with no sleep.
    fn load_racing(path: &std::path::Path) -> Result<Keypair> {
        let mut last_err = None;
        for _ in 0..50 {
            match load_existing(path) {
                Ok(kp) => return Ok(kp),
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("key at {} unreadable after create race", path.display())
        }))
    }

    // Fast path for the common already-provisioned case (still race-safe: a
    // concurrently-writing winner is handled by the retry inside `load_racing`).
    if key_path.exists() {
        return load_racing(&key_path);
    }

    let kp = Keypair::generate();
    let pem = kp
        .to_pem()
        .map_err(|e| anyhow::anyhow!("failed to serialize key: {e}"))?;

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Create atomically. `create_new` fails if the file already exists, which
    // closes the exists()->write TOCTOU: a lost race deterministically loads
    // the winner's key instead of overwriting it.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
        {
            Ok(mut f) => {
                // The file is 0600 from creation, so the PEM is never
                // world-readable, even momentarily.
                f.write_all(pem.as_bytes())
                    .with_context(|| format!("failed to write key to {}", key_path.display()))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A concurrent start won the race and wrote the identity; load
                // theirs rather than propagating the error or overwriting.
                return load_racing(&key_path);
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to create key at {}", key_path.display()));
            }
        }
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&key_path)
        {
            Ok(mut f) => {
                f.write_all(pem.as_bytes())
                    .with_context(|| format!("failed to write key to {}", key_path.display()))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return load_racing(&key_path);
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to create key at {}", key_path.display()));
            }
        }
    }

    info!(path = %key_path.display(), did = %kp.did(), "generated new node identity");
    Ok(kp)
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
    use super::{load_or_create_keypair, Config};
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt;

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
    // on a single identity: the `create_new` losers hit `AlreadyExists` and load
    // the winner's key rather than overwriting it. RED: revert the write to a
    // plain `fs::write` (no `create_new`) and each thread returns its own
    // freshly generated key, so the DIDs diverge.
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
}
