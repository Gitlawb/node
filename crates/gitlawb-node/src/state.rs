use gitlawb_core::did::Did;
use gitlawb_core::identity::Keypair;
use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::git::repo_store::RepoStore;
use crate::p2p::P2pHandle;
use crate::rate_limit::RateLimiter;

#[derive(Clone, Debug)]
pub struct RefUpdateBroadcast {
    pub repo: String,
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
    pub pusher_did: String,
    pub node_did: String,
    pub timestamp: String,
}

#[derive(Clone, Debug)]
pub struct TaskEventBroadcast {
    pub task_id: String,
    pub old_status: String,
    pub new_status: String,
    pub by_did: String,
    pub at: String,
}

/// Shared application state — cloned cheaply into every handler via Arc.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<Db>,
    pub node_did: Did,
    pub node_keypair: Arc<Keypair>,
    /// libp2p handle — None if p2p is disabled (p2p_port = 0)
    pub p2p: Option<Arc<P2pHandle>>,
    /// Shared HTTP client for outbound webhook deliveries
    pub http_client: Arc<reqwest::Client>,
    /// Broadcast channel for ref update events (GraphQL subscriptions)
    pub ref_update_tx: tokio::sync::broadcast::Sender<RefUpdateBroadcast>,
    /// Broadcast channel for task events (GraphQL subscriptions)
    pub task_event_tx: tokio::sync::broadcast::Sender<TaskEventBroadcast>,
    /// GraphQL schema (queries + mutations + subscriptions)
    pub graphql_schema: Arc<crate::graphql::GitlawbSchema>,
    /// Fly.io machine ID — used for fly-replay routing in multi-machine deployments
    pub machine_id: Option<String>,
    /// Centralized repo storage: local disk cache + optional Tigris backend
    pub repo_store: RepoStore,
    /// Per-DID rate limiter for creation endpoints (repos, issues, PRs)
    pub rate_limiter: RateLimiter,
    /// Per-client-IP rate limiter for git-receive-pack. Per-DID limits cannot
    /// brake a push flood from a DID farm (one throwaway DID per repo), so the
    /// push path throttles on the resolved client IP instead.
    pub push_rate_limiter: RateLimiter,
    /// Which forwarded header (if any) the edge is trusted to set, for
    /// resolving the push limiter's client-IP key. See `GITLAWB_TRUSTED_PROXY`.
    /// Node-wide; also keys the two peer-sync limiters below.
    pub push_limiter_trust: crate::rate_limit::TrustedProxy,
    /// Per-client-IP limiter for `POST /api/v1/sync/trigger` (tight). The route
    /// requires a signature, but a signature does not cap cost (a did:key farm
    /// self-registers), and its per-call cost is an O(peers) fan-out, so the IP
    /// brake is a separate, load-bearing half. Its own bucket so an unsigned
    /// `/sync/notify` flood cannot drain the signed trigger caller's quota.
    pub sync_trigger_rate_limiter: RateLimiter,
    /// Per-client-IP limiter for the peer-write routes (`/peers/announce`,
    /// `/sync/notify`) (generous). `/sync/notify` reaches the same `enqueue_sync`
    /// sink as trigger and accepts unsigned requests from known peers, so it is
    /// braked too; each peer's distinct IP gets its own bucket.
    pub peer_write_rate_limiter: RateLimiter,
    /// Process-wide graceful-shutdown signal. Sending `true` causes every
    /// task that holds a `watch::Receiver` to exit at its next await point.
    /// Used by:
    ///   * the SIGINT/SIGTERM handler in `main()`
    ///   * axum's `with_graceful_shutdown` to drain in-flight HTTP requests
    ///   * the libp2p swarm task
    ///   * the gossip, sync, operator heartbeat, and rate-limit cleanup loops
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl AppState {
    /// Subscribe to the shutdown signal. Returns a fresh receiver whose
    /// initial value matches the current state.
    pub fn subscribe_shutdown(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Trigger graceful shutdown. Idempotent — calling more than once
    /// has no effect. Returns `true` if this call was the one that
    /// flipped the signal.
    #[allow(dead_code)] // used by tests; main() drives the signal directly
    pub fn shutdown(&self) -> bool {
        self.shutdown_tx.send_if_modified(|v| {
            if *v {
                false
            } else {
                *v = true;
                true
            }
        })
    }

    /// `true` once shutdown has been signalled.
    #[allow(dead_code)] // used by tests and any future handler that wants to short-circuit
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_tx.borrow()
    }
}
