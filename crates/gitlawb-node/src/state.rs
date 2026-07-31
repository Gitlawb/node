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
    pub owner_did: String,
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
    /// Bounds concurrent post-push pin loops (`ipfs_pin` / `pinata` `pin_new_objects`)
    /// across all repos (#174 F6). `encrypt_inflight` caps the pin-task COUNT to one
    /// per repo, but each pin loop holds a full per-push object-id list while walking
    /// it, so N distinct repos could hold N such MB-scale lists at once. This caps how
    /// many run concurrently; a loop DEFERS (waits) when the pool is full, never drops.
    ///
    /// It does NOT bound the lists held by tasks PARKED on it. The local IPFS path
    /// materializes its list before acquiring, so a parked task still holds one, and the
    /// parked-task count is capped only per repo by `encrypt_inflight`. Cross-repo
    /// retained memory is therefore not bounded by this pool. The Pinata twin acquires
    /// before it derives and does not carry that residual.
    pub pin_semaphore: Arc<tokio::sync::Semaphore>,
    /// Bounds the outstanding post-push encryption-task set to at most one PER REPO by
    /// coalescing (#174 P2-2). This is NOT a global cap: N distinct repos still admit N
    /// tasks; the cross-repo residual (an authenticated actor pushing to many repos
    /// leaves many parked tasks) is throttled by auth plus the per-IP/per-DID rate
    /// limits. Its real cost, the MB-scale per-push object-id list each parked task
    /// holds, is NOT bounded by `pin_semaphore` either; see that field's doc above for
    /// why. Nothing currently bounds this memory across repos. `git_encrypt_semaphore` caps
    /// *active* walks; this caps duplicate SPAWNS per repo. Before spawning a per-push
    /// encryption task, the receive-pack handler consults this set: if the repo already
    /// has a task in flight it coalesces (skips the duplicate spawn) rather than parking
    /// a new waiter, and its tip pairs are recorded for that task's drain loop (#174 F5).
    /// Coalescing only delays the coalesced push's walk — it never drops the withheld-blob
    /// recovery copy, which `2a54c15` deliberately kept fail-closed (there is no
    /// reconciliation sweep to re-derive a dropped copy). See [`EncryptInflight`].
    pub encrypt_inflight: EncryptInflight,
    /// Per-repo in-process write serializer that SUPPLEMENTS the cluster-wide pg
    /// advisory lock on the receive-pack path (#174 U2/F3). On a client disconnect
    /// mid-`receive-pack`, `RepoWriteGuard::Drop` releases the pg advisory lock at the
    /// disconnect instant, but the disconnected push's git process GROUP is still
    /// being torn down by `KillGroupOnDrop`'s detached reaper (~4s TERM/grace/KILL/reap)
    /// over the shared LOCAL objects/ dir — so a second SAME-NODE push could acquire
    /// the repo and race the still-writing group into a torn snapshot. This lease is
    /// held by the write-path `AdmissionGuard`, which rides that reaper, so a second
    /// same-repo push blocks until the first group is reaped. It is per-NODE (the
    /// corruption is same-node: shared local objects/ + in-process reaper, and the
    /// disconnect path uploads nothing to Tigris), so it needs no cross-node counterpart
    /// and does NOT replace the pg lock (which stays the genuine cluster-wide serializer).
    /// See [`RepoWriteLeases`].
    pub repo_write_leases: RepoWriteLeases,
    /// Per-caller concurrency sub-cap on the read pool: each caller (keyed on the
    /// resolved source IP, #174 U1) may hold at most `max_concurrent_reads_per_caller`
    /// in-flight read ops, so one caller cannot monopolize `git_read_semaphore`
    /// (#174). Applied by `git_upload_pack` and the upload-pack `info/refs`
    /// advertisement.
    pub git_read_per_caller: crate::rate_limit::PerCallerConcurrency,
    /// Per-source concurrency sub-cap on the anon-reachable receive-pack `info/refs`
    /// advertisement: each source IP may hold at most a small share of the DEDICATED
    /// advert pool (`git_push_advert_semaphore`), so a multi-source flood of
    /// push-handshake advertisements cannot saturate that pool and shed other sources'
    /// advertisements (#174). An advert flood cannot reach `git_write_semaphore` at
    /// all, since the two pools are disjoint. Sized as a fraction of
    /// `max_concurrent_git_pushes` because the advert pool is created at the same size,
    /// so filling it takes many distinct source IPs (each also braked by the per-IP
    /// push rate limiter).
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

    /// The work currently queued against a repo's in-flight task, or `None` when
    /// no task holds the key. Test-only observability: it lets a test assert that
    /// a coalesced push's tip pairs were actually recorded, rather than that the
    /// outcome merely was `Coalesced`.
    #[cfg(test)]
    pub fn pending_for(&self, repo_id: &str) -> Option<PendingWork> {
        self.repos
            .lock()
            .expect("encrypt_inflight mutex poisoned")
            .get(repo_id)
            .cloned()
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

/// Per-repo in-process write-lease serializer (#174 U2/F3). Keyed by the repo's DB
/// id (1:1 with the pg advisory lock's owner/name key), each entry is a one-permit
/// semaphore: the receive-pack handler takes it BEFORE `acquire_write` (see the acquire
/// order note on [`acquire`](Self::acquire)) and a second same-repo push BLOCKS on it —
/// block-and-wait, NOT coalesce. It mirrors [`EncryptInflight`]'s keyed-map + guard +
/// Drop-frees-key STRUCTURE; the semantics differ (block-and-wait, so there is no
/// lossy-coalesce degradation to fall back on).
#[derive(Clone)]
pub struct RepoWriteLeases {
    // std::sync::Mutex: held only for O(1) map ops (get-or-create + refcount) in a sync
    // context, never across an await — the semaphore wait happens OUTSIDE this lock.
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, LeaseSlot>>>,
    /// Most handlers allowed to be PARKED on one repo's lease at once
    /// (`GITLAWB_REPO_LEASE_MAX_WAITERS`). Past it `acquire` sheds instead of queueing.
    max_waiters: usize,
}

/// The stable per-repo identity that [`RepoWriteLeases`] and [`EncryptInflight`]
/// key on (#174 U2).
///
/// NOT `record.id`. A repo deleted and recreated under the same owner/name gets a
/// new row id while the bare repo on disk is reused, so an id-keyed serializer
/// stops serializing across that rotation and lets two writers onto one
/// `objects/` directory. `RepoStore::local_path` and the pg advisory lock both
/// key on the sanitized owner slug plus repo name, and this reproduces exactly
/// that identity so the in-process serializers agree with them.
///
/// Three details are load-bearing:
///
/// - The sanitization is [`crate::git::store::repo_disk_path`]'s
///   (`replace([':', '/'], "_")`), NOT `db::normalize_owner_key`, which strips a
///   `did:key:` prefix instead and would map the same input to a different
///   string. The disk path is authoritative because the `objects/` directory is
///   the resource being serialized.
/// - The separator is `/`, which cannot occur in the owner slug by construction
///   (`replace([':', '/'], "_")` removes it) and mirrors the shape of the disk
///   path this key exists to reproduce. A plain join would collide (owner `a` +
///   name `bc` against owner `ab` + name `c`, both `abc`), letting one repo's
///   push park another's. It must stay PRINTABLE: this key is logged as the
///   `repo` field on the lease shed and steal-bound warnings below, and an unprintable
///   separator (a NUL, a unit separator) truncates at a NUL-hostile log sink and
///   renders two different repos' warnings identically.
/// - Callers pass `record.owner_did` / `record.name`, never the request's path
///   segments: `db::get_repo` normalizes DID aliases, so a caller could otherwise
///   mint two keys for one directory just by varying the DID spelling.
///
/// The sanitization is not injective (`did:web:example.com:alice` and
/// `did:web:example.com/alice` fold to one slug), which would be a cross-tenant
/// hazard for the coalescing map if it were reachable. It is not: `repos.disk_path`
/// is `NOT NULL UNIQUE` and holds exactly this derivation, so two rows that fold
/// to one key cannot coexist. Do not "fix" this by making the key injective —
/// that is precisely what would let two owners sharing one `objects/` directory
/// push concurrently.
pub fn repo_identity_key(owner_did: &str, repo_name: &str) -> String {
    let owner_slug = owner_did.replace([':', '/'], "_");
    format!("{owner_slug}/{repo_name}")
}

/// A per-repo lease entry: the one-permit semaphore, a refcount of the handlers
/// currently referencing it (holding or waiting), and a count of the ones actually
/// PARKED. While `refs > 0` every acquirer shares the SAME semaphore, so mutual exclusion
/// holds; the entry is removed only when `refs` hits 0 (no one references it), so a fresh
/// entry can never split serialization.
///
/// `waiters` and `refs` are deliberately different counts, and the shed cap is on
/// `waiters`. `refs` includes the HOLDER, and a holder whose Drop never runs (task abort,
/// runtime teardown without unwind, `mem::forget`: precisely the leak `steal_after` exists
/// to survive) keeps its ref forever. Capping `refs` would let that leaked ref
/// permanently occupy a slot and wedge the repo, reintroducing the permanent wedge the
/// steal backstop was written to prevent. A waiter, by contrast, always leaves: it either
/// gets the permit, steals at `steal_after`, is shed, or is cancelled, and every one of
/// those paths drops the RAII waiter guard.
struct LeaseSlot {
    sem: Arc<tokio::sync::Semaphore>,
    refs: usize,
    waiters: usize,
}

impl RepoWriteLeases {
    /// `max_waiters` is the per-repo live-waiter cap (see [`acquire`](Self::acquire)).
    pub fn new(max_waiters: usize) -> Self {
        Self {
            repos: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            max_waiters: max_waiters.max(1),
        }
    }

    /// Acquire the per-repo write lease, blocking until it is free (a second same-repo
    /// writer waits). `steal_after` bounds that wait: past it the acquirer STEALS
    /// (proceeds permit-less) rather than block forever. Returns `None` when this repo
    /// already has `max_waiters` handlers parked, so the caller sheds (503) instead of
    /// adding to an unbounded queue: `git_receive_pack` reaches here with the whole pack
    /// already buffered by axum, and the park runs to `steal_after` (1260s at defaults),
    /// so unbounded parking is unbounded buffered bytes. The cap is per repo and counts
    /// only live waiters, so shedding is confined to the contended repo; a push to any
    /// other repo, from any source, is unaffected.
    ///
    /// Why a bounded steal: block-and-wait has no degradation of its own (unlike the
    /// coalescing [`EncryptInflight`], whose lost key merely delays a best-effort copy),
    /// and unlike the pg advisory lock (60s stale reclaim) an in-process waiter has no
    /// reclaim — so a leaked/never-run Drop (runtime teardown without unwind, task abort,
    /// `mem::forget`) would otherwise wedge the repo permanently. A stealer takes NO
    /// permit and touches NO count, so a merely-slow holder that later drops can never
    /// leave the semaphore over-counted; the caller must therefore set `steal_after`
    /// safely ABOVE any legitimate hold (a full receive-pack under
    /// `git_service_timeout_secs` + the ~4s reaper cap + the Tigris upload).
    ///
    /// Acquire order (one consistent order everywhere, so no inversion self-hang): the
    /// lease is taken BEFORE the pg advisory lock (`acquire_write`) and released AFTER
    /// it. Nothing anywhere takes the pg lock before this lease, so the two serializers
    /// can never deadlock; taking the lease first also means a blocked second writer
    /// pins no pooled pg connection while it waits.
    pub async fn acquire(
        &self,
        repo_id: &str,
        steal_after: std::time::Duration,
    ) -> Option<RepoWriteLease> {
        // Take the entry refcount BEFORE the await, so the entry cannot be GC'd out from
        // under a waiter (a fresh entry for a new acquirer would split serialization).
        let sem = {
            let mut map = self.repos.lock().expect("repo_write_leases mutex poisoned");
            let slot = map.entry(repo_id.to_string()).or_insert_with(|| LeaseSlot {
                sem: Arc::new(tokio::sync::Semaphore::new(1)),
                refs: 0,
                waiters: 0,
            });
            slot.refs += 1;
            Arc::clone(&slot.sem)
        };
        // Cancellation-safe refcount: hold a reservation across the (cancellable) wait so
        // that if this acquire future is DROPPED mid-wait — a client disconnect while a
        // second same-repo push is blocked here — the reservation's Drop still decrements
        // the ref it just took, rather than stranding it (which would defeat the
        // Drop-frees-key GC). On success the reservation is `forget`-transferred into the
        // returned guard, which then owns the single decrement.
        let reservation = RefReservation {
            repos: Arc::clone(&self.repos),
            repo_id: repo_id.to_string(),
        };

        // Uncontended fast path: take the free permit without spending waiter budget, so
        // the cap bounds only handlers that actually park. `try_acquire_owned` on tokio's
        // semaphore does NOT barge a queued FIFO waiter (it fails while anyone is queued),
        // so the fast path is not a fairness hole; probed at 2000 rounds with a queued
        // waiter present, 0 barges.
        let permit = match Arc::clone(&sem).try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                // Contended: park, holding a waiter slot for exactly the cancellable wait.
                // Claimed in ONE critical section (check and increment together), so a
                // burst of concurrent acquirers cannot all read an under-cap count and
                // then all park. Past the cap, drop the reservation (freeing the ref, and
                // the entry with it if nobody else holds one) and shed.
                let waiter = match WaiterSlot::claim(&self.repos, repo_id, self.max_waiters) {
                    Some(w) => w,
                    None => {
                        tracing::warn!(
                            repo = %repo_id,
                            max_waiters = self.max_waiters,
                            "repo write-lease waiter cap reached; shedding this acquirer"
                        );
                        drop(reservation);
                        return None;
                    }
                };
                let parked =
                    tokio::time::timeout(steal_after, Arc::clone(&sem).acquire_owned()).await;
                // Released HERE, at the end of the wait, not at the end of the push: past
                // this point the handler is a holder, counted by `refs`, and a waiter slot
                // it kept would be budget no parked request could ever use.
                drop(waiter);
                match parked {
                    Ok(Ok(p)) => Some(p),
                    // The semaphore is never closed; treat the (unreachable) closed case
                    // as a steal so acquire always makes forward progress.
                    Ok(Err(_closed)) => None,
                    Err(_elapsed) => {
                        tracing::warn!(
                            repo = %repo_id,
                            steal_after_secs = steal_after.as_secs(),
                            "repo write-lease wait exceeded the steal bound; presuming a \
                             leaked lease and proceeding permit-less (in-process \
                             serializer reclaim)"
                        );
                        None
                    }
                }
            }
        };
        // Transfer the ref from the reservation to the guard: forget the reservation (so
        // it does NOT decrement) and let the guard own the single decrement on its Drop.
        std::mem::forget(reservation);
        Some(RepoWriteLease(Arc::new(LeaseGuardInner {
            repos: Arc::clone(&self.repos),
            repo_id: repo_id.to_string(),
            _permit: permit,
        })))
    }

    /// Number of repos with a live lease entry. Test/metrics observability.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.repos
            .lock()
            .expect("repo_write_leases mutex poisoned")
            .len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many handlers currently reference this repo's lease entry: the holder plus
    /// every waiter parked in [`acquire`](Self::acquire). The ref is taken SYNCHRONOUSLY,
    /// before the (cancellable) semaphore wait, so a waiter is visible here the moment it
    /// reaches the lease. Tests use it to observe "this push parked" as a state rather
    /// than inferring it from a deadline that never fired.
    #[cfg(test)]
    pub fn refs_for(&self, repo_id: &str) -> usize {
        self.repos
            .lock()
            .expect("repo_write_leases mutex poisoned")
            .get(repo_id)
            .map(|slot| slot.refs)
            .unwrap_or(0)
    }

    /// How many handlers are PARKED on this repo's lease right now (the count the shed
    /// cap is enforced against, holder excluded). Tests use it to observe "this push
    /// parked" and "the waiter slot was released" as state.
    #[cfg(test)]
    pub fn waiters_for(&self, repo_id: &str) -> usize {
        self.repos
            .lock()
            .expect("repo_write_leases mutex poisoned")
            .get(repo_id)
            .map(|slot| slot.waiters)
            .unwrap_or(0)
    }
}

/// Shared-ownership handle to a held repo write lease (#174 U2/F3). `Clone` hands a
/// second holder a handle to the SAME inner guard; the lease (permit + map refcount)
/// frees only when the LAST clone drops. The receive-pack handler makes two:
///   * clone (a) rides the write-path [`AdmissionGuard`] into `KillGroupOnDrop`'s
///     detached reaper, so on a client disconnect it drops only AFTER the git group is
///     reaped (this is the F3 fix — a lease tied to `RepoWriteGuard` would instead drop
///     at the disconnect instant, reopening the race);
///   * clone (b) is held by the handler across `guard.release()`, so on the clean path
///     it spans the success-only Tigris upload that runs inside `release`, AFTER
///     `receive_pack` has already dropped clone (a) inside `run_git_service`.
///
/// `Send + 'static` with NO pg connection (just an `Arc`), so it can ride the reaper.
#[derive(Clone)]
pub struct RepoWriteLease(#[allow(dead_code)] Arc<LeaseGuardInner>);

struct LeaseGuardInner {
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, LeaseSlot>>>,
    repo_id: String,
    // `None` only on the steal path (the bounded wait elapsed). Dropping `None` releases
    // no permit, so a stealer never corrupts the semaphore's permit count.
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Drop for LeaseGuardInner {
    fn drop(&mut self) {
        // Runs exactly ONCE per handler acquisition — when the last `RepoWriteLease`
        // clone drops (the Arc strong count hits 0) — so the refcount decrements once,
        // however many clones existed. `_permit` drops after this body, releasing the
        // semaphore permit so a waiting acquirer proceeds.
        release_lease_ref(&self.repos, &self.repo_id);
    }
}

/// Holds the entry refcount across the cancellable wait inside
/// [`RepoWriteLeases::acquire`]. If that acquire future is dropped mid-wait, this Drop
/// decrements the ref it took; on success `acquire` `forget`s it and hands the ref to
/// the returned [`LeaseGuardInner`], so the ref is decremented exactly once either way.
struct RefReservation {
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, LeaseSlot>>>,
    repo_id: String,
}

impl Drop for RefReservation {
    fn drop(&mut self) {
        release_lease_ref(&self.repos, &self.repo_id);
    }
}

/// Holds one LIVE-WAITER slot on a lease entry for exactly the duration of the
/// cancellable park inside [`RepoWriteLeases::acquire`]. Every way out of that park
/// (permit acquired, steal on timeout, shed, or the acquire future being dropped on a
/// client disconnect) drops this guard, so the count can only reflect handlers that are
/// parked right now. That is why the shed cap is on this count and not on `refs`.
struct WaiterSlot {
    repos: Arc<std::sync::Mutex<std::collections::HashMap<String, LeaseSlot>>>,
    repo_id: String,
}

impl WaiterSlot {
    /// Claim a waiter slot, or `None` when the repo already has `max_waiters` live
    /// waiters. The entry always exists here: the caller took its `refs` reference in an
    /// earlier critical section and still holds it. Check and increment share one
    /// critical section, so concurrent acquirers cannot overshoot the cap.
    fn claim(
        repos: &Arc<std::sync::Mutex<std::collections::HashMap<String, LeaseSlot>>>,
        repo_id: &str,
        max_waiters: usize,
    ) -> Option<Self> {
        if let Ok(mut map) = repos.lock() {
            if let Some(slot) = map.get_mut(repo_id) {
                if slot.waiters >= max_waiters {
                    return None;
                }
                slot.waiters += 1;
            }
        }
        Some(Self {
            repos: Arc::clone(repos),
            repo_id: repo_id.to_string(),
        })
    }
}

impl Drop for WaiterSlot {
    fn drop(&mut self) {
        if let Ok(mut map) = self.repos.lock() {
            if let Some(slot) = map.get_mut(&self.repo_id) {
                slot.waiters = slot.waiters.saturating_sub(1);
            }
        }
    }
}

/// Decrement a lease entry's refcount and remove it once no handler references it, so
/// the map cannot grow without bound (Drop-frees-key, like `EncryptInflight`). Safe
/// under block-and-wait: while `refs > 0` every acquirer shares the SAME semaphore, and
/// a fresh entry is created only after `refs` hits 0, when no one references the old one.
fn release_lease_ref(
    repos: &Arc<std::sync::Mutex<std::collections::HashMap<String, LeaseSlot>>>,
    repo_id: &str,
) {
    if let Ok(mut map) = repos.lock() {
        if let Some(slot) = map.get_mut(repo_id) {
            slot.refs = slot.refs.saturating_sub(1);
            if slot.refs == 0 {
                map.remove(repo_id);
            }
        }
    }
}

/// Admit a post-receive git scan to the shared `git_encrypt_semaphore` pool
/// (#174 F4): DEFER (await), never shed — a dropped scan would lose the push's
/// recovery copy or silently under-pin it. The returned permit must move into
/// the blocking closure so a started scan always completes holding it (a
/// disconnect cannot cancel `spawn_blocking` or leak the permit mid-walk).
/// Accepted residual, stated once for every caller: the park wait is queue-depth
/// multiplied — post-receive tails are no longer admission-bounded once the write
/// permit is released, so N landed pushes can queue N scans and the last waits N
/// scan-durations. A client-timeout disconnect no longer loses the work (#174 F2):
/// the whole post-receive replication tail runs in an independently owned task, so
/// dropping the request future cannot drop this parked scan — the park no longer
/// precedes any durable-record gate in a cancellable future.
pub async fn acquire_scan_permit(
    scan_sem: Arc<tokio::sync::Semaphore>,
    repo: &std::path::Path,
    stage: &'static str,
) -> tokio::sync::OwnedSemaphorePermit {
    let parked = std::time::Instant::now();
    let permit = scan_sem
        .acquire_owned()
        .await
        .expect("git_encrypt_semaphore is never closed");
    tracing::debug!(
        repo = %repo.display(),
        stage,
        queue_wait_ms = parked.elapsed().as_millis() as u64,
        "post-receive scan admitted to the scan pool"
    );
    permit
}

#[cfg(test)]
mod repo_identity_key_tests {
    use super::repo_identity_key;

    /// The key must reproduce `repo_disk_path`'s slug derivation exactly, because
    /// the whole point is to agree with the on-disk identity the store and the pg
    /// advisory lock already use.
    #[test]
    fn matches_repo_disk_paths_sanitization() {
        let owner = "did:key:z6Mkfoo";
        let name = "r";
        let expected_slug = owner.replace([':', '/'], "_");
        assert_eq!(
            repo_identity_key(owner, name),
            format!("{expected_slug}/{name}")
        );

        // The disk path for the same pair must carry the same slug component.
        let disk = crate::git::store::repo_disk_path(std::path::Path::new("/srv"), owner, name);
        assert!(
            disk.to_string_lossy().contains(&expected_slug),
            "the key's slug must be the one repo_disk_path puts on disk: {disk:?}"
        );
    }

    /// Stability across the rotation is the entire reason this key exists: the row
    /// id changes on delete+recreate, the identity does not.
    #[test]
    fn is_stable_across_a_row_id_rotation() {
        assert_eq!(
            repo_identity_key("did:key:z6Mkfoo", "r"),
            repo_identity_key("did:key:z6Mkfoo", "r"),
        );
    }

    /// The `/` separator is what stops one repo's push parking another's. These
    /// two pairs both concatenate to `abc`, so with a plain join they would
    /// produce a single key.
    #[test]
    fn separator_prevents_the_owner_name_boundary_collision() {
        assert_ne!(
            repo_identity_key("a", "bc"),
            repo_identity_key("ab", "c"),
            "owner/name boundary must not be ambiguous"
        );
    }

    /// The key is logged as the `repo` field on the lease waiter-cap shed and the
    /// steal-bound warning, so it must contain no control characters. A NUL (or a
    /// unit separator) truncates at a NUL-hostile log sink, which would render two
    /// different repos' shed warnings identically — an observability lie on
    /// exactly the messages an operator reads to find a contended repo.
    #[test]
    fn key_is_printable_so_the_lease_warnings_stay_readable() {
        let k = repo_identity_key("did:web:example.com:alice", "my-repo.git");
        assert!(
            !k.chars().any(|c| c.is_control()),
            "the identity key is logged; it must carry no control characters: {k:?}"
        );
        assert_eq!(k, "did_web_example.com_alice/my-repo.git");
    }

    /// Distinct repos and distinct owners never share a key.
    #[test]
    fn distinct_repos_and_owners_do_not_share_a_key() {
        assert_ne!(
            repo_identity_key("did:key:z6A", "r"),
            repo_identity_key("did:key:z6A", "s")
        );
        assert_ne!(
            repo_identity_key("did:key:z6A", "r"),
            repo_identity_key("did:key:z6B", "r")
        );
    }

    /// Documents the ONE collision the sanitization admits, and why it is safe
    /// rather than fixed: `repos.disk_path` is UNIQUE and holds this derivation,
    /// so two rows folding to one key cannot coexist. If this assertion ever
    /// flips to `assert_ne!`, the key became injective and two owners sharing one
    /// `objects/` directory could push concurrently — the defect U2 closes.
    #[test]
    fn folds_did_web_alias_spellings_together_which_the_unique_disk_path_makes_unreachable() {
        assert_eq!(
            repo_identity_key("did:web:example.com:alice", "r"),
            repo_identity_key("did:web:example.com/alice", "r"),
        );
    }
}

#[cfg(test)]
mod repo_write_lease_tests {
    use super::RepoWriteLeases;
    use std::time::Duration;

    /// #174 U2/F3 lease mechanics: block-and-wait serialization on the same repo,
    /// no serialization across distinct repos, Drop-frees-key GC, and the bounded-wait
    /// steal reclaim so a leaked (never-run Drop) holder cannot wedge the repo forever.
    #[tokio::test]
    async fn serializes_same_repo_frees_key_and_steals_on_leak() {
        let leases = RepoWriteLeases::new(8);
        let big = Duration::from_secs(3600);

        // Block-and-wait: a second same-repo acquire waits while the first is held.
        let a = leases.acquire("repo1", big).await.expect("uncontended");
        let blocked =
            tokio::time::timeout(Duration::from_millis(200), leases.acquire("repo1", big)).await;
        assert!(
            blocked.is_err(),
            "a second same-repo acquire must block while the first lease is held"
        );
        // ... and proceeds once the first frees.
        drop(a);
        let b = tokio::time::timeout(Duration::from_millis(500), leases.acquire("repo1", big))
            .await
            .expect("the second acquire must proceed once the first lease frees")
            .expect("under the waiter cap, so it must not shed");
        drop(b);

        // Drop-frees-key: with no holders the entry is removed (bounded map growth).
        assert!(
            leases.is_empty(),
            "the lease entry must be removed once no handler references it"
        );

        // Distinct repos never serialize against each other.
        let x = leases.acquire("repoX", big).await.expect("uncontended");
        let _y = tokio::time::timeout(Duration::from_millis(200), leases.acquire("repoY", big))
            .await
            .expect("distinct repos must not serialize")
            .expect("a distinct repo has its own waiter budget");
        drop(x);
        drop(_y);
    }

    /// Scenario 4: the steal backstop survives the waiter cap. A holder whose Drop never
    /// runs (task abort, runtime teardown, `mem::forget`) keeps its entry `refs` forever;
    /// the next acquirer must still proceed permit-less at `steal_after` and must not be
    /// shed on the way in. This is why the cap counts LIVE WAITERS and never `refs`:
    /// capping `refs` (which includes the holder) lets one leaked lease pin a slot
    /// permanently and wedge the repo, the exact permanent wedge the steal exists to
    /// prevent. `max_waiters` is 1 here, so a `refs`-based cap has no room at all.
    #[tokio::test]
    async fn steal_on_leaked_lease_still_works_under_the_waiter_cap() {
        let leases = RepoWriteLeases::new(1);
        let big = Duration::from_secs(3600);

        let leaked = leases.acquire("repoZ", big).await.expect("uncontended");
        std::mem::forget(leaked);
        assert_eq!(
            leases.refs_for("repoZ"),
            1,
            "the leaked holder keeps its entry reference forever (that is the leak)"
        );

        let stolen = tokio::time::timeout(
            Duration::from_secs(5),
            leases.acquire("repoZ", Duration::from_millis(150)),
        )
        .await
        .expect("a leaked lease must be reclaimed by the bounded-wait steal, not hang forever")
        .expect(
            "the waiter cap must not shed the stealer: it counts live waiters, and a leaked \
             HOLDER is not a waiter. Capping refs instead wedges the repo permanently",
        );
        assert_eq!(
            leases.waiters_for("repoZ"),
            0,
            "the stealer must return its waiter slot when its wait ends"
        );
        drop(stolen);
    }

    /// Scenario 5: a shed leaves no residue. Past the cap `acquire` returns `None`
    /// without keeping either count, so the entry still GCs once the real holder and the
    /// real waiter finish. A shed that stranded a ref would leak the map entry forever;
    /// one that stranded a waiter slot would shrink the repo's budget permanently.
    #[tokio::test]
    async fn shed_waiter_leaves_no_ref_or_waiter_residue() {
        let leases = RepoWriteLeases::new(1);
        let big = Duration::from_secs(3600);

        let holder = leases.acquire("repoS", big).await.expect("uncontended");
        let waiting = leases.clone();
        let parked = tokio::spawn(async move { waiting.acquire("repoS", big).await });
        assert!(
            wait_for(Duration::from_secs(5), || leases.waiters_for("repoS") == 1).await,
            "the second acquire must park and be counted as a live waiter"
        );

        // At the cap (1 live waiter): the next acquire sheds instead of queueing.
        let shed = tokio::time::timeout(Duration::from_secs(5), leases.acquire("repoS", big))
            .await
            .expect("a shed must return immediately, not park");
        assert!(
            shed.is_none(),
            "past max_waiters the acquire must shed (None), not join the queue"
        );
        assert_eq!(
            leases.refs_for("repoS"),
            2,
            "the shed must leave no refcount residue: only the holder and the real waiter"
        );
        assert_eq!(
            leases.waiters_for("repoS"),
            1,
            "the shed must leave no waiter-count residue: only the real waiter"
        );

        // The entry still GCs once the real handlers finish.
        drop(holder);
        let promoted = parked
            .await
            .expect("the parked acquire task must not panic")
            .expect("the parked acquire must be served once the holder frees");
        drop(promoted);
        assert!(
            wait_for(Duration::from_secs(5), || leases.is_empty()).await,
            "the lease entry must still GC after a shed (no stranded ref)"
        );
    }

    /// Cancellation safety: dropping an acquire future while it is BLOCKED waiting for
    /// the lease (a client disconnect on a second same-repo push) must not strand the
    /// entry refcount — after the holder frees and the waiter is cancelled, the key GCs.
    #[tokio::test]
    async fn cancelled_waiter_does_not_strand_the_refcount() {
        let leases = RepoWriteLeases::new(8);
        let big = Duration::from_secs(3600);

        let a = leases.acquire("repoC", big).await.expect("uncontended");
        // A waiter blocks, then is cancelled (its acquire future dropped) mid-wait.
        let cancelled =
            tokio::time::timeout(Duration::from_millis(150), leases.acquire("repoC", big)).await;
        assert!(
            cancelled.is_err(),
            "the waiter must be blocked, then cancelled"
        );

        // Release the holder. If the cancelled waiter had stranded its ref, the entry
        // would never GC; assert it does once the holder frees.
        drop(a);
        // Let any pending Drop bookkeeping settle.
        tokio::task::yield_now().await;
        assert!(
            leases.is_empty(),
            "a cancelled waiter must not strand the entry refcount (key must GC)"
        );
    }

    /// Scenario 6: a cancelled waiter returns its WAITER slot too, not just its ref. A
    /// client that disconnects while parked is the common case, so a slot stranded here
    /// would shrink the repo's waiter budget on every disconnect until the repo shed
    /// every push. Observed as state: the count drops back to 0, and a later acquire on
    /// the still-held lease parks rather than shedding, with the cap at 1.
    #[tokio::test]
    async fn cancelled_waiter_releases_its_waiter_slot() {
        let leases = RepoWriteLeases::new(1);
        let big = Duration::from_secs(3600);

        let holder = leases.acquire("repoX2", big).await.expect("uncontended");
        let cancelled =
            tokio::time::timeout(Duration::from_millis(200), leases.acquire("repoX2", big)).await;
        assert!(
            cancelled.is_err(),
            "the waiter must be parked, then cancelled mid-wait"
        );
        assert_eq!(
            leases.waiters_for("repoX2"),
            0,
            "a cancelled waiter must release its waiter slot"
        );

        // The freed budget is usable: the next acquire parks (times out) instead of
        // shedding (returning None immediately).
        let next =
            tokio::time::timeout(Duration::from_millis(300), leases.acquire("repoX2", big)).await;
        assert!(
            next.is_err(),
            "the next acquire must be able to park on the freed waiter slot; it was shed \
             instead, so the cancelled waiter's slot was stranded"
        );
        drop(holder);
    }

    /// Scenario 7: an uncontended acquire spends no waiter budget, and a promoted waiter
    /// hands its slot back at the END OF ITS WAIT rather than holding it for the whole
    /// push. With `max_waiters` at 1: the uncontended holder leaves the count at 0, the
    /// one waiter is counted while parked, and once that waiter is promoted to holder the
    /// count returns to 0 so the NEXT push can still park. Holding the slot for the push
    /// instead would let one waiter permanently occupy the only slot, shedding every
    /// same-repo push behind it.
    #[tokio::test]
    async fn uncontended_acquire_spends_no_waiter_budget() {
        let leases = RepoWriteLeases::new(1);
        let big = Duration::from_secs(3600);

        // Fast path: the lease is free, so this takes it without parking.
        let holder = leases.acquire("repoF", big).await.expect("uncontended");
        assert_eq!(
            leases.waiters_for("repoF"),
            0,
            "an uncontended acquire must take the free permit without spending waiter budget"
        );

        // One waiter parks behind it, spending the single slot.
        let waiting = leases.clone();
        let parked = tokio::spawn(async move { waiting.acquire("repoF", big).await });
        assert!(
            wait_for(Duration::from_secs(5), || leases.waiters_for("repoF") == 1).await,
            "the second acquire must park and be counted"
        );

        // Promote it: the slot must come back at the end of its WAIT.
        drop(holder);
        let promoted = parked
            .await
            .expect("the parked acquire task must not panic")
            .expect("the parked acquire must be served once the holder frees");
        assert!(
            wait_for(Duration::from_secs(5), || leases.waiters_for("repoF") == 0).await,
            "a promoted waiter must release its waiter slot when its wait ends, not when \
             its push finishes"
        );

        // ... so a third acquire can still park behind the new holder.
        let third =
            tokio::time::timeout(Duration::from_millis(300), leases.acquire("repoF", big)).await;
        assert!(
            third.is_err(),
            "the freed waiter slot must be usable: this acquire was shed instead of parking"
        );
        drop(promoted);
    }

    /// Poll `cond` until it holds, yielding so spawned tasks progress. Returns false if
    /// `cap` elapses first; callers assert on the state the loop settled into.
    async fn wait_for(cap: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + cap;
        loop {
            if cond() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
