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
    /// Per-client-IP rate limiter for the same creation endpoints. The per-DID
    /// limiter above cannot brake a creation flood from a DID farm — one
    /// throwaway `did:key` per repo means each DID makes a single create call
    /// and never trips its own bucket. A valid iCaptcha proof does not cap this
    /// either: the enforced level draws only machine-solvable deterministic
    /// challenges (and the caller can pin the easy type), so a bot mints a fresh
    /// DID, solves a proof, and creates a repo unthrottled. Braking on the
    /// resolved client IP is what actually stops a single-source flood (same
    /// rationale as `push_rate_limiter`). Keyed by `push_limiter_trust`.
    pub create_ip_rate_limiter: RateLimiter,
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
    /// Bounds concurrent served git READ operations (upload-pack + both info/refs
    /// advertisements). A read handler acquires a permit before spawning git and
    /// holds it for the op; when none are free the request is shed with a 503.
    /// Writes draw from `git_write_semaphore` so a read flood cannot shed an
    /// authenticated push at admission (#174).
    pub git_read_semaphore: Arc<tokio::sync::Semaphore>,
    /// Bounds concurrent `git-receive-pack` (push) operations, a pool separate
    /// from `git_read_semaphore` so an anonymous READ flood can never shed an
    /// authenticated push (#174). Sized by `max_concurrent_git_pushes`. Drawn from
    /// by the `git-receive-pack` POST (owner-gated) ONLY. The anon-reachable
    /// receive-pack `info/refs` advertisement draws from the SEPARATE
    /// `git_push_advert_semaphore` below, never this pool, so a multi-source flood
    /// of push-handshake advertisements can never occupy a permit an authenticated
    /// POST needs at admission (#174).
    pub git_write_semaphore: Arc<tokio::sync::Semaphore>,
    /// Bounds concurrent anon-reachable `git-receive-pack` `info/refs`
    /// advertisements — a pool SEPARATE from `git_write_semaphore` so adverts (which
    /// hold a permit across `acquire_fresh` + `info/refs`) can never consume a slot
    /// the authenticated POST relies on. A per-source flood can at worst exhaust this
    /// advert pool (each source also capped by `git_push_advert_per_caller` and the
    /// per-IP push rate limiter), and the reserved POST pool is untouched (#174).
    pub git_push_advert_semaphore: Arc<tokio::sync::Semaphore>,
    /// Bounds concurrent post-receive git scans. Each successful push releases its
    /// handler write permit the moment receive-pack's git group is reaped, then runs
    /// up to four scans over the repo: the anonymous withheld walk
    /// (`replication_withheld_set`), the pin-candidate scan
    /// (`resolve_candidates_for_push`), the fail-closed full scan
    /// (`fail_closed_full_scan_objects`), and the DETACHED encrypt-then-pin walk
    /// (`withheld_blob_recipients_bounded`). Without a cap, N fast pushes spawn N
    /// concurrent full-history git walks past `max_concurrent_git_pushes` (which only
    /// bounds the in-handler receive-pack phase) — #174 P1-e closed the detached walk,
    /// F4 closed the other three. Each scan acquires ONE permit here per walk and
    /// DEFERS (blocks) when the pool is full rather than shedding — dropping the work
    /// would lose the recovery copy or silently under-pin the push. No-walk fast
    /// paths (not announceable, no path-scoped rule, deletion-only push) never touch
    /// the pool. A pool of its own, not `git_write_semaphore`: a long background
    /// walk must not hold a foreground write slot, and a handler already holding a
    /// write permit that needed a second would self-deadlock at pool size 1.
    pub git_encrypt_semaphore: Arc<tokio::sync::Semaphore>,
    /// Bounds the OUTSTANDING post-push encryption-task set by per-repo coalescing
    /// (#174 P2-2). `git_encrypt_semaphore` caps *active* walks; this caps how many
    /// detached tasks *spawn and park* on that semaphore's `acquire_owned().await`.
    /// Before spawning a per-push encryption task, the receive-pack handler consults
    /// this set: if the repo already has a task in flight it coalesces (skips the
    /// duplicate spawn) rather than parking a new unbounded waiter. Coalescing only
    /// delays a duplicate walk — it never drops the withheld-blob recovery copy, which
    /// `2a54c15` deliberately kept fail-closed (there is no reconciliation sweep to
    /// re-derive a dropped copy). See [`EncryptInflight`].
    pub encrypt_inflight: EncryptInflight,
    /// Per-caller concurrency sub-cap on the read pool: each caller (keyed on the
    /// resolved source IP, #174 U1) may hold at most `max_concurrent_reads_per_caller`
    /// in-flight read ops, so one caller cannot monopolize `git_read_semaphore`
    /// (#174). Applied by `git_upload_pack` and the upload-pack `info/refs`
    /// advertisement.
    pub git_read_per_caller: crate::rate_limit::PerCallerConcurrency,
    /// Per-source concurrency sub-cap on the anon-reachable receive-pack `info/refs`
    /// advertisement: each source IP may hold at most a small share of the write
    /// pool, so a multi-source flood of push-handshake advertisements cannot
    /// saturate `git_write_semaphore` and shed authenticated pushes (#174). Sized as
    /// a fraction of `max_concurrent_git_pushes`, so filling the write pool takes many
    /// distinct source IPs (each also braked by the per-IP push rate limiter).
    pub git_push_advert_per_caller: crate::rate_limit::PerCallerConcurrency,
    /// Per-source concurrency sub-cap on the authenticated `git-receive-pack` POST:
    /// each source IP may hold at most a small share of `git_write_semaphore`, so one
    /// host minting disposable `did:key` identities cannot open enough slow pushes to
    /// monopolize the write pool and 503 every other source's push (#174 P1-d). Keyed
    /// on the resolved source IP (never the DID — a DID farm defeats a DID key). Sized
    /// like `git_push_advert_per_caller`, a fraction of `max_concurrent_git_pushes`.
    pub git_write_per_caller: crate::rate_limit::PerCallerConcurrency,
    /// Bounds concurrent `GET /ipfs/{cid}` visibility-walk requests. The public
    /// `/ipfs/{cid}` route runs `allowed_blob_set_for_caller_bounded` in
    /// `spawn_blocking` (a full-history git walk) with NO served-git admission of its
    /// own; without this a permissionless caller fans out concurrent walks past every
    /// git pool, exhausting the blocking pool + PIDs (#174 P1-3). A request acquires a
    /// permit before the repo loop and holds it for the whole request (across every
    /// `spawn_blocking` walk), so the slot reflects real thread occupancy — a tokio
    /// walk-timeout cannot free it while the blocking work still runs. A pool of its
    /// own (`max_concurrent_ipfs_walks`), NOT a git pool: distinct cost center + public
    /// surface, so anonymous /ipfs traffic can never shed an authenticated git op.
    pub git_ipfs_walk_semaphore: Arc<tokio::sync::Semaphore>,
    /// Per-source concurrency sub-cap on the `/ipfs/{cid}` walk pool: each source
    /// (keyed on the resolved source IP, never the DID — `/ipfs` admits any `did:key`
    /// unthrottled, so a DID key would be free to mint around) may hold at most
    /// `ipfs_walk_per_source` in-flight walk slots, so one source cannot monopolize
    /// `git_ipfs_walk_semaphore` (#174 P1-3). A request with no resolvable key is
    /// bounded by the global pool only, never this sub-cap. The key map is bounded
    /// (`with_default_max_keys`, reject-before-insert) so a source-key farm cannot grow
    /// it (INV-15).
    pub git_ipfs_walk_per_caller: crate::rate_limit::PerCallerConcurrency,
    /// Per-client-IP rate limiter for `GET /ipfs/{cid}`. The route is publicly
    /// reachable and each request can drive a full-history git walk, so it carries a
    /// per-IP flood brake in addition to the concurrency cap above — a rate limit
    /// bounds request *rate*, the semaphore bounds concurrent slow holds (different
    /// axes). Keyed on the resolved client IP via `push_limiter_trust`. Layered on the
    /// `/ipfs` route via `rate_limit_by_ip`.
    pub ipfs_rate_limiter: RateLimiter,
    /// The `git` executable the served-git withheld-blob walk spawns. Production is
    /// `"git"` (resolved via PATH); injectable so a fake `git` can drive the walk's
    /// process-group teardown in handler tests without mutating the process-global
    /// PATH (#174).
    pub git_bin: String,
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

/// Bounds the OUTSTANDING post-push encryption-task set by per-repo coalescing
/// (#174 P2-2). Each successful path-scoped push `tokio::spawn`s a DETACHED task that
/// parks on `git_encrypt_semaphore.acquire_owned().await` (which DEFERS when the pool
/// is full rather than shedding — `2a54c15` kept it fail-closed so the withheld-blob
/// recovery copy is never dropped). The semaphore caps *active* walks, but nothing
/// capped how many detached tasks *spawn and park* on that await: N rapid pushes to a
/// repo spawn N parked tasks, each holding cloned object lists/rules/paths/keys — an
/// unbounded outstanding set.
///
/// This tracks the repo keys with an in-flight encryption task. Before spawning, the
/// handler calls [`try_begin`](Self::try_begin): if a task for the repo is already
/// in-flight it returns `None` and the handler SKIPS spawning a duplicate (coalesce —
/// the newer push's objects are covered by the pending/next walk over the same repo's
/// history). This bounds the outstanding set to <=1 pending task per repo WITHOUT
/// dropping work: coalescing only delays a duplicate walk, it never sheds the recovery
/// copy (there is no reconciliation sweep, so a *dropped* job would be lost forever).
///
/// The returned [`EncryptInflightGuard`] is moved into the detached task and removes
/// the repo key on drop — on normal completion, error, OR panic (Drop runs on unwind)
/// — so one crashed walk can never permanently lock a repo out of future recovery
/// copies.
#[derive(Clone, Default)]
pub struct EncryptInflight {
    // std::sync::Mutex: only ever held for O(1) HashSet insert/remove in a sync
    // context (right before `tokio::spawn`, and in the guard's Drop) — never across
    // an await, so a std Mutex is correct and cheaper than a tokio one.
    repos: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl EncryptInflight {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to begin an encryption task for `repo_id`. Returns `Some(guard)` if no task
    /// for the repo was in-flight (the caller should spawn), or `None` if one already
    /// is (the caller should COALESCE — skip spawning a duplicate). The guard releases
    /// the repo key on drop.
    pub fn try_begin(&self, repo_id: &str) -> Option<EncryptInflightGuard> {
        let mut set = self.repos.lock().expect("encrypt_inflight mutex poisoned");
        if set.insert(repo_id.to_string()) {
            Some(EncryptInflightGuard {
                repos: Arc::clone(&self.repos),
                repo_id: repo_id.to_string(),
            })
        } else {
            None
        }
    }

    /// Number of repos with an in-flight encryption task. Test/metrics observability;
    /// the bound under saturation is `len() <= number of distinct repos`, i.e. at most
    /// one task per repo.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.repos
            .lock()
            .expect("encrypt_inflight mutex poisoned")
            .len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// RAII guard removing a repo key from [`EncryptInflight`] when the detached
/// encryption task finishes (drop on completion, error, or panic-unwind). Move-only —
/// there is no reason to clone a guard, and cloning would double-remove.
pub struct EncryptInflightGuard {
    repos: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    repo_id: String,
}

impl Drop for EncryptInflightGuard {
    fn drop(&mut self) {
        // A poisoned lock (a prior panic while holding it) still lets us take the inner
        // set via into_inner-on-guard; but poisoning here is not expected because the
        // only critical sections are the O(1) ops above. Remove best-effort.
        if let Ok(mut set) = self.repos.lock() {
            set.remove(&self.repo_id);
        }
    }
}
