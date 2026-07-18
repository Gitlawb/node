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
    /// duplicate spawn) rather than parking a new unbounded waiter, and its tip pairs
    /// are recorded for that task's drain loop (#174 F5). Coalescing only delays the
    /// coalesced push's walk — it never drops the withheld-blob recovery copy, which
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
/// handler calls [`try_begin`](Self::try_begin) with the push's (old, new) tip pairs:
/// if no task is in-flight the push is [`Admitted`](BeginOutcome::Admitted) and spawns
/// one; if a task IS in-flight the push [`Coalesces`](BeginOutcome::Coalesced) — no
/// duplicate spawn — and its tip pairs are merged into the in-flight key's pending
/// slot in the SAME critical section as the presence check. The in-flight task pins
/// only its own pre-spawn object-list snapshot, so the merge is what keeps coalescing
/// lossless (#174 F5): the task loop-drains the pending slot via
/// [`EncryptInflightGuard::finish_or_take_pending`] before releasing the key, so a
/// coalesced push's pins and recovery copies are delayed, never dropped (there is no
/// reconciliation sweep, so a *dropped* job would be lost forever). Check-then-record
/// as two lock acquisitions would race the task's final pending check — hence one
/// critical section for both.
///
/// The returned [`EncryptInflightGuard`] is moved into the detached task. On normal
/// exit the key is removed (and the guard disarmed) inside `finish_or_take_pending`'s
/// empty-pending critical section; the guard's Drop is the PANIC backstop (Drop runs
/// on unwind), so one crashed walk can never permanently lock a repo out of future
/// recovery copies.
#[derive(Clone, Default)]
pub struct EncryptInflight {
    // std::sync::Mutex: only ever held for O(1)-ish map ops (insert/remove/merge —
    // the merge is an O(pairs) Vec extend bounded by MAX_PENDING_TIP_PAIRS) in a
    // sync context, never across an await, so a std Mutex is correct and cheaper
    // than a tokio one. Key present == task in flight; the value is the work
    // recorded by pushes that coalesced against it.
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, PendingWork>>>,
}

/// Cap on the accumulated coalesced tip pairs per repo. Past it the pending slot
/// degrades to [`PendingWork::FullScan`], so a hostile pusher cannot grow the slot
/// without bound while a walk is in flight; the drain then costs one full-repo
/// enumeration instead (the same already-tested fallback the push path uses).
const MAX_PENDING_TIP_PAIRS: usize = 1024;

/// Work recorded by pushes that coalesced against an in-flight encryption task,
/// drained by that task one batch per loop iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingWork {
    /// The coalesced pushes' raw (old_sha, new_sha) ref-update pairs, zeros
    /// included — the drain strips the create/delete sentinels exactly like the
    /// handler tail does. An EMPTY vec is "nothing pending", never a work item.
    Tips(Vec<(String, String)>),
    /// The pair bound overflowed: drain with a FORCED full-repo scan. This must be
    /// signalled explicitly (the `force_full_scan` flag on
    /// `resolve_candidates_for_push`), never encoded as an empty tip list — empty
    /// tips resolve to an empty delta and would pin nothing (the F5 loss again).
    FullScan,
}

/// Outcome of [`EncryptInflight::try_begin`].
pub enum BeginOutcome {
    /// No task was in flight: the caller spawns one, moving the guard into it. The
    /// push's own tip pairs are NOT recorded — the caller's pre-spawn snapshot
    /// covers them; the pending slot starts empty.
    Admitted(EncryptInflightGuard),
    /// A task is in flight; this push's tip pairs were merged into its pending
    /// slot (same critical section as the presence check). The in-flight task's
    /// drain loop will process them.
    Coalesced,
}

/// Outcome of [`EncryptInflightGuard::finish_or_take_pending`].
pub enum FinishOutcome {
    /// Coalesced work was pending: it is handed back with the still-armed guard
    /// (the repo key is retained) and the task must run another drain iteration.
    Pending(EncryptInflightGuard, PendingWork),
    /// Nothing was pending: the repo key was removed AND the guard disarmed in one
    /// critical section, so dropping the returned guard is inert. The task exits.
    /// Remove-then-drop as two steps would double-remove: a successor task admitted
    /// between them would have ITS key deleted by the late Drop. The disarmed guard
    /// is handed back rather than dropped internally so that remove→drop window is
    /// real and the disarm is testable; production just lets it fall out of scope
    /// (hence the allow).
    Finished(#[allow(dead_code)] EncryptInflightGuard),
}

impl EncryptInflight {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin-or-coalesce an encryption task for `repo_id`, in one critical section.
    /// `tip_pairs` is this push's raw (old_sha, new_sha) ref-update list; it is
    /// merged into the pending slot only on the [`Coalesced`](BeginOutcome::Coalesced)
    /// arm (an admitted caller's own snapshot already covers its pairs).
    pub fn try_begin(&self, repo_id: &str, tip_pairs: Vec<(String, String)>) -> BeginOutcome {
        let mut map = self.repos.lock().expect("encrypt_inflight mutex poisoned");
        match map.entry(repo_id.to_string()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(PendingWork::Tips(Vec::new()));
                BeginOutcome::Admitted(EncryptInflightGuard {
                    repos: Arc::clone(&self.repos),
                    repo_id: repo_id.to_string(),
                    armed: true,
                })
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                merge_pending(slot.get_mut(), tip_pairs);
                BeginOutcome::Coalesced
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
}

/// Merge a coalesced push's tip pairs into a repo's pending slot. FullScan absorbs
/// everything; a Tips slot that would exceed [`MAX_PENDING_TIP_PAIRS`] degrades to
/// FullScan rather than growing without bound.
fn merge_pending(slot: &mut PendingWork, pairs: Vec<(String, String)>) {
    match slot {
        PendingWork::FullScan => {}
        PendingWork::Tips(acc) => {
            if acc.len().saturating_add(pairs.len()) > MAX_PENDING_TIP_PAIRS {
                *slot = PendingWork::FullScan;
            } else {
                acc.extend(pairs);
            }
        }
    }
}

/// Guard owned by the detached encryption task for its repo key. Move-only — there
/// is no reason to clone a guard, and cloning would double-remove. Normal exit goes
/// through [`finish_or_take_pending`](Self::finish_or_take_pending); Drop is the
/// panic-path backstop only.
pub struct EncryptInflightGuard {
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, PendingWork>>>,
    repo_id: String,
    /// True until the normal-exit path removes the key. A disarmed guard's Drop is
    /// a no-op: the key slot may already belong to a successor task admitted after
    /// our removal, and removing THAT key would break at-most-one-task-per-repo.
    armed: bool,
}

impl EncryptInflightGuard {
    /// The task's end-of-iteration step, one critical section: if coalesced work is
    /// pending, take it and hand the still-armed guard back (key retained — iterate);
    /// if nothing is pending, remove the key and disarm the guard (task exits; the
    /// returned guard's Drop is inert). The atomicity is load-bearing both ways: a
    /// push landing before this call is merged and therefore drained here; a push
    /// landing after it finds the key gone and is admitted as a fresh task. No
    /// interleaving can lose the work or admit two tasks for one repo.
    pub fn finish_or_take_pending(mut self) -> FinishOutcome {
        let mut map = self.repos.lock().expect("encrypt_inflight mutex poisoned");
        match map.get_mut(&self.repo_id) {
            Some(PendingWork::Tips(acc)) if acc.is_empty() => {
                map.remove(&self.repo_id);
                self.armed = false;
                drop(map);
                FinishOutcome::Finished(self)
            }
            Some(slot) => {
                let work = std::mem::replace(slot, PendingWork::Tips(Vec::new()));
                drop(map);
                FinishOutcome::Pending(self, work)
            }
            None => {
                // Unreachable while armed (only this method removes a live key),
                // but never panic in the release path: treat as finished.
                self.armed = false;
                drop(map);
                FinishOutcome::Finished(self)
            }
        }
    }
}

impl Drop for EncryptInflightGuard {
    fn drop(&mut self) {
        // Normal exit disarmed us inside finish_or_take_pending's critical section;
        // an armed drop means the task ended abnormally (panic-unwind, or a future
        // code path that returns without finishing). Release the key so the repo is
        // not permanently locked out, and log any pending work this loses — there
        // is no sweep, so it stays lost until a later push re-walks the repo.
        if !self.armed {
            return;
        }
        // A poisoned lock is not expected (the critical sections above are small
        // and panic-free); remove best-effort.
        if let Ok(mut map) = self.repos.lock() {
            match map.remove(&self.repo_id) {
                Some(PendingWork::Tips(acc)) if !acc.is_empty() => tracing::warn!(
                    repo = %self.repo_id,
                    lost_tip_pairs = acc.len(),
                    "encryption task ended abnormally with coalesced pushes pending; \
                     their pins/recovery copies are lost until a later push"
                ),
                Some(PendingWork::FullScan) => tracing::warn!(
                    repo = %self.repo_id,
                    "encryption task ended abnormally with a pending full-scan drain; \
                     it is lost until a later push"
                ),
                _ => {}
            }
        }
    }
}
