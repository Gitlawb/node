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
    /// Per-client-IP rate limiter for the `GET /ipfs/{cid}` full-history walk.
    /// The route is anonymous and a valid tree CID (exposed by the public pins
    /// index) makes each repeat request pay a fresh allowed-set walk (rev-list +
    /// ls-tree per commit), memoized only per request — unbounded amplification
    /// (INV-10). Braking the walk on the non-farmable source IP caps that cost
    /// without touching cheap non-walk fetches. Keyed by `push_limiter_trust`.
    pub ipfs_rate_limiter: RateLimiter,
    /// Per-request ceiling on full-history reachability walks the CID resolver
    /// may spawn (default `api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST`). A field,
    /// not a bare const, so tests can shrink it to exercise the cap cheaply;
    /// production keeps the const default.
    pub ipfs_max_history_walks: u32,
    /// Per-request ceiling on legacy (NULL-provenance) repo probes in the CID
    /// resolver's scan fallback (default `api::ipfs::MAX_LEGACY_PROBES_PER_REQUEST`).
    /// Bounds the anonymous `acquire` + `cat-file` fan-out across the node (#173,
    /// INV-10); a field for the same test-seam reason as `ipfs_max_history_walks`.
    pub ipfs_max_legacy_probes: u32,
    /// Hard ceiling on the byte size of an object `GET /ipfs/{cid}` will buffer and
    /// serve (default `api::ipfs::MAX_SERVED_OBJECT_BYTES`). The serve reads via a
    /// blocking `git cat-file` and buffers the whole object; without a bound a large
    /// public blob could exhaust memory or block a runtime worker (#173, F6, INV-10).
    /// A field for the same test-seam reason as the sibling caps.
    pub ipfs_max_served_object_bytes: u64,
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
    /// Bounds concurrent post-push encrypt-then-pin history walks. Each successful
    /// path-scoped push releases its handler write permit and then runs a DETACHED
    /// full-history walk (`withheld_blob_recipients_bounded`) to seal withheld blobs;
    /// without a cap, N fast pushes spawn N concurrent full-history git walks past
    /// `max_concurrent_git_pushes` (which only bounds the in-handler phase). The walk
    /// acquires a permit here and DEFERS (blocks) when the pool is full rather than
    /// shedding — the work is background and dropping it would lose the recovery copy
    /// (#174 P1-e). A pool of its own, not `git_write_semaphore`: a long background
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

    /// Sweep expired entries from every per-IP/DID rate limiter. Driven by the
    /// periodic cleanup task so a bounded limiter's key map sheds stale entries
    /// instead of sitting near its cap until an inline capacity sweep reclaims
    /// them. Every limiter on the state is swept here; adding a new limiter means
    /// adding it to this list.
    pub(crate) async fn sweep_rate_limiters(&self) {
        self.rate_limiter.cleanup().await;
        self.create_ip_rate_limiter.cleanup().await;
        self.push_rate_limiter.cleanup().await;
        self.ipfs_rate_limiter.cleanup().await;
        self.sync_trigger_rate_limiter.cleanup().await;
        self.peer_write_rate_limiter.cleanup().await;
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

    /// Legacy-probe budget wired from the `GITLAWB_IPFS_MAX_REPOS_WALKED` operator
    /// knob (R5, KTD5). The knob seeds `ipfs_max_legacy_probes` at construction so it
    /// controls the per-request legacy (NULL-provenance) probe fan-out it advertises.
    /// It deliberately does NOT feed `ipfs_max_history_walks`: that ceiling must stay
    /// at `MAX_HISTORY_WALKS_PER_REQUEST` (`MAX_PIN_SOURCES + 1`) or a provenanced
    /// request with a full source set is truncated into a false 503, and the knob's
    /// range starts at 1. The knob is `usize`, the field `u32`; the range cap
    /// (1_048_576) keeps the cast lossless.
    pub(crate) fn ipfs_legacy_probe_budget(config: &crate::config::Config) -> u32 {
        config.ipfs_max_repos_walked as u32
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
/// This tracks the repo keys with an in-flight encryption task, each carrying a
/// DIRTY flag. Before spawning, the handler calls [`try_begin`](Self::try_begin): if
/// a task for the repo is already in-flight it MARKS THE REPO DIRTY and returns `None`
/// so the handler SKIPS spawning a duplicate (coalesce). The in-flight task consults
/// the flag at its tail via [`requeue_or_release`](EncryptInflightGuard::requeue_or_release):
/// a set flag makes it run ONE MORE pass (re-reading repo state) before it exits, so a
/// push coalesced during the in-flight window is REQUEUED, never dropped. This bounds
/// the outstanding set to <=1 task per repo without losing work: there is no
/// reconciliation sweep, so a *dropped* job would be lost forever.
///
/// The returned [`EncryptInflightGuard`] is moved into the detached task. The normal
/// exit path is `requeue_or_release`, which removes the repo key ATOMICALLY with the
/// "clean" decision — no push can land in the gap between "checked clean" and "task
/// exits". `Drop` is a panic backstop only: if the task panics (or returns without
/// calling `requeue_or_release`) it still removes the key so a crashed walk can never
/// permanently lock a repo out of future recovery copies.
#[derive(Clone, Default)]
pub struct EncryptInflight {
    // std::sync::Mutex: only ever held for O(1) HashMap ops in a sync context (before
    // `tokio::spawn`, at the task tail, and in Drop) — never across an await, so a std
    // Mutex is correct and cheaper than a tokio one. The value is the DIRTY flag: a
    // coalesced push flips it true so the in-flight task requeues one more pass.
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, bool>>>,
}

impl EncryptInflight {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to begin an encryption task for `repo_id`. Returns `Some(guard)` if no task
    /// for the repo was in-flight (the caller should spawn). If one already is, MARKS
    /// the repo dirty and returns `None` (the caller COALESCES — skips the duplicate
    /// spawn; the in-flight task requeues one more pass to cover this push).
    pub fn try_begin(&self, repo_id: &str) -> Option<EncryptInflightGuard> {
        let mut map = self.repos.lock().expect("encrypt_inflight mutex poisoned");
        match map.get_mut(repo_id) {
            Some(dirty) => {
                *dirty = true;
                None
            }
            None => {
                map.insert(repo_id.to_string(), false);
                Some(EncryptInflightGuard {
                    repos: Arc::clone(&self.repos),
                    repo_id: repo_id.to_string(),
                    released: false,
                })
            }
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

    /// Test-only: read the dirty flag for `repo_id` (`None` if no task is in-flight).
    #[cfg(test)]
    pub fn dirty(&self, repo_id: &str) -> Option<bool> {
        self.repos
            .lock()
            .expect("encrypt_inflight mutex poisoned")
            .get(repo_id)
            .copied()
    }
}

/// RAII guard for one in-flight encryption task's repo key. The task drives it at its
/// tail with [`requeue_or_release`](Self::requeue_or_release); `Drop` is a panic
/// backstop. Move-only — cloning would double-release.
pub struct EncryptInflightGuard {
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, bool>>>,
    repo_id: String,
    released: bool,
}

impl EncryptInflightGuard {
    /// TASK-TAIL check-and-clear, atomic with the release decision. If a push
    /// coalesced since the last pass (dirty), clear the flag and return `true` (the
    /// task loops one more pass). Otherwise remove the key and return `false` (the task
    /// exits). Atomic under the mutex: a concurrent push either sets the flag BEFORE
    /// this reads it (-> requeue covers it) or arrives AFTER the key is removed (-> a
    /// fresh `try_begin` spawns a new task) — there is no window where the key is
    /// present-but-clean while the task exits.
    pub fn requeue_or_release(&mut self) -> bool {
        let mut map = self.repos.lock().expect("encrypt_inflight mutex poisoned");
        match map.get_mut(&self.repo_id) {
            Some(dirty) if *dirty => {
                *dirty = false;
                true
            }
            _ => {
                map.remove(&self.repo_id);
                self.released = true;
                false
            }
        }
    }
}

impl Drop for EncryptInflightGuard {
    fn drop(&mut self) {
        // Panic backstop ONLY. The normal exit is `requeue_or_release` (which removed
        // the key atomically and set `released`), so this does nothing then. If the
        // task panicked or returned without releasing, remove the key so one crashed
        // walk never permanently locks the repo out.
        //
        // Accepted residual: a panic with the dirty flag still set drops the requeued
        // work — Drop cannot loop — the same loss class as the on-panic behavior before
        // this change. No reconciliation sweep re-derives it.
        if self.released {
            return;
        }
        if let Ok(mut map) = self.repos.lock() {
            map.remove(&self.repo_id);
        }
    }
}
