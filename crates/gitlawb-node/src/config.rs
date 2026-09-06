use clap::Parser;
use std::path::PathBuf;

/// Upper bound on `git_service_timeout_secs`, `ipfs_request_budget_secs`, and
/// `ipfs_resolve_budget_secs`, in seconds (100 years).
///
/// Three consumers now, so a future tightening moves all of them. `ipfs_request_budget_secs`
/// and `ipfs_resolve_budget_secs` derive only the `Instant` addition in `get_by_cid`, not the
/// lease-steal multiply below, but they share this ceiling because the defect class and the
/// "set it very large to disable" contract are the same.
///
/// The knob is not just stored, it is arithmetic input: the write path derives the
/// per-repo lease steal bound from it (`* 2 + 60`), and #174 routed it into
/// `build_filtered_pack` and `blob_paths`, which each build a deadline as
/// `Instant::now() + Duration::from_secs(this)`. That addition panics on overflow in
/// RELEASE as well as debug, so an unbounded `u64` here turns an operator typo into a
/// serve-path crash rather than a very long timeout. Bounding at parse time keeps every
/// derived duration in range at once, instead of hardening each site as it is found.
///
/// The ceiling is representability, NOT a policy view of a sane timeout, and that
/// distinction is what sets the number. The help text has always told operators to set
/// this very large to disable the bound, so values like `999999999` (~31 years) are
/// working production "off" settings; a tighter, tidier cap would fail those nodes at
/// boot on upgrade over a value that was never the defect. 100 years clears every such
/// setting while staying a factor of about 5.85 under the ~584-year ceiling of a
/// `u64`-nanosecond `Instant`, which is the tightest representation on any platform we
/// build for. Every value that worked before still parses; only the ones that would have
/// panicked are rejected.
pub const GIT_SERVICE_TIMEOUT_SECS_MAX: u64 = 100 * 365 * 24 * 60 * 60;

#[derive(Parser, Debug, Clone)]
#[command(name = "gitlawb-node", about = "gitlawb node daemon", version)]
pub struct Config {
    /// Directory where bare git repositories are stored
    #[arg(long, env = "GITLAWB_REPOS_DIR", default_value = "./data/repos")]
    pub repos_dir: PathBuf,

    /// PostgreSQL connection URL (Supabase or any Postgres instance)
    #[arg(
        long,
        env = "DATABASE_URL",
        default_value = "postgresql://localhost/gitlawb"
    )]
    pub database_url: String,

    /// Host to bind to
    #[arg(long, env = "GITLAWB_HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to listen on
    #[arg(long, env = "GITLAWB_PORT", default_value_t = 7545)]
    pub port: u16,

    /// Path to the node's Ed25519 identity PEM key
    #[arg(long, env = "GITLAWB_KEY", default_value = "~/.gitlawb/identity.pem")]
    pub key_path: String,

    /// Reserved for private-read mode; per-repo read enforcement is not wired in alpha
    #[arg(long, env = "GITLAWB_PUBLIC_READ", default_value_t = true)]
    pub public_read: bool,

    /// Public URL of this node (for peer announcements)
    #[arg(long, env = "GITLAWB_PUBLIC_URL")]
    pub public_url: Option<String>,

    /// Comma-separated list of bootstrap peer URLs to announce to on startup
    #[arg(long, env = "GITLAWB_BOOTSTRAP_PEERS", value_delimiter = ',')]
    pub bootstrap_peers: Vec<String>,

    /// Require RFC 9421 signatures on peer announce/sync write routes.
    /// Keep false during rolling upgrades so existing live nodes can still gossip.
    #[arg(
        long,
        env = "GITLAWB_REQUIRE_SIGNED_PEER_WRITES",
        default_value_t = false
    )]
    pub require_signed_peer_writes: bool,

    /// Require the authenticated pusher to be the repo owner on `git-receive-pack`.
    /// Authentication (a valid did:key signature) is not authorization on its own:
    /// any party can mint a did:key and sign as it, so with this off every signed
    /// caller may push to every repository, private ones included. On by default.
    ///
    /// Turn it off only for a rolling upgrade whose pushers are not yet the repo
    /// owner. Both `GITLAWB_ENFORCE_OWNER_PUSH=false` and `--enforce-owner-push
    /// false` disable it, and the bare `--enforce-owner-push` form still means
    /// `true`.
    ///
    /// The value-taking action is what makes the CLI form parse at all: as a
    /// presence-only flag, `--enforce-owner-push false` is an "unexpected argument"
    /// error. The env form resolved correctly either way, so it is the CLI escape
    /// hatch this buys, not the environment one.
    #[arg(
        long,
        env = "GITLAWB_ENFORCE_OWNER_PUSH",
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_value_t = true,
        default_missing_value = "true"
    )]
    pub enforce_owner_push: bool,

    /// URL of local IPFS/Kubo node HTTP API (e.g. http://127.0.0.1:5001)
    #[arg(long, env = "GITLAWB_IPFS_API", default_value = "")]
    pub ipfs_api: String,

    /// Pinata JWT for IPFS warm storage. Leave empty to disable (default).
    #[arg(long, env = "GITLAWB_PINATA_JWT", default_value = "")]
    pub pinata_jwt: String,

    /// Pinata v3 upload URL
    #[arg(
        long,
        env = "GITLAWB_PINATA_UPLOAD_URL",
        default_value = "https://uploads.pinata.cloud/v3/files"
    )]
    pub pinata_upload_url: String,

    /// libp2p QUIC/UDP port (0 = disabled)
    #[arg(long, env = "GITLAWB_P2P_PORT", default_value_t = 7546)]
    pub p2p_port: u16,

    /// libp2p bootstrap multiaddrs (comma-separated)
    /// Example: /ip4/1.2.3.4/udp/7546/quic-v1/p2p/12D3KooW...
    #[arg(long, env = "GITLAWB_P2P_BOOTSTRAP", value_delimiter = ',')]
    pub p2p_bootstrap: Vec<String>,

    /// Automatically mirror repos from peers when ref-update events arrive via Gossipsub.
    #[arg(long, env = "GITLAWB_AUTO_SYNC", default_value_t = false)]
    pub auto_sync: bool,

    /// Irys URL for Arweave permanent anchoring.
    /// Leave empty to disable. Use https://devnet.irys.xyz for free devnet.
    #[arg(long, env = "GITLAWB_IRYS_URL", default_value = "")]
    pub irys_url: String,

    /// Base L2 DID registry contract address (0x...)
    #[arg(long, env = "GITLAWB_CONTRACT_DID_REGISTRY", default_value = "")]
    pub contract_did_registry: String,

    /// Base L2 name registry contract address (0x...)
    #[arg(long, env = "GITLAWB_CONTRACT_NAME_REGISTRY", default_value = "")]
    pub contract_name_registry: String,

    /// Base L2 RPC URL
    #[arg(
        long,
        env = "GITLAWB_CHAIN_RPC_URL",
        default_value = "https://sepolia.base.org"
    )]
    pub chain_rpc_url: String,

    /// Base L2 node staking contract address (GitlawbNodeStaking). When set
    /// along with `operator_private_key`, the node verifies its stake on
    /// startup and posts a heartbeat on a fixed cadence.
    #[arg(long, env = "GITLAWB_CONTRACT_NODE_STAKING", default_value = "")]
    pub contract_node_staking: String,

    /// Hex-encoded (0x-prefixed) private key for the operator wallet that
    /// posts heartbeats. Not required unless on-chain PoS is enabled.
    #[arg(long, env = "GITLAWB_OPERATOR_PRIVATE_KEY", default_value = "")]
    pub operator_private_key: String,

    /// If true, the node refuses to start when it is not registered on-chain
    /// or is currently inactive (missed heartbeats). Use once your network is
    /// live and every operator is expected to have stake.
    #[arg(long, env = "GITLAWB_OPERATOR_STRICT_MODE", default_value_t = false)]
    pub operator_strict_mode: bool,

    /// How often to post the operator heartbeat, in hours. Must be less than
    /// the contract's HEARTBEAT_WINDOW (24h) with headroom. Default: 20h.
    #[arg(long, env = "GITLAWB_HEARTBEAT_INTERVAL_HOURS", default_value_t = 20)]
    pub heartbeat_interval_hours: u64,

    /// Tigris (S3-compatible) bucket for repo storage.
    /// Leave empty to disable Tigris and use local-only storage.
    #[arg(long, env = "GITLAWB_TIGRIS_BUCKET", default_value = "")]
    pub tigris_bucket: String,

    /// Maximum pack body size for git-receive-pack and git-upload-pack, in bytes.
    /// Applies only to git smart-HTTP routes — all other API routes keep the 2 MB default.
    /// Default: 2 GB.  Set lower on resource-constrained nodes.
    #[arg(long, env = "GITLAWB_MAX_PACK_BYTES", default_value_t = 2_147_483_648)]
    pub max_pack_bytes: usize,

    /// Per-client-IP rate limit for `POST /api/v1/sync/trigger`, in requests per
    /// hour. `/sync/trigger` requires a signature and drives an O(peers) outbound
    /// fan-out per call, so it gets a tight bucket. `0` disables. Default: 60.
    #[arg(long, env = "GITLAWB_SYNC_TRIGGER_RATE_LIMIT", default_value_t = 60)]
    pub sync_trigger_rate_limit: usize,

    /// Per-client-IP rate limit for the peer-write routes (`/peers/announce`,
    /// `/sync/notify`), in requests per hour. These accept unsigned requests from
    /// known peers and run at higher frequency, so the bucket is generous. Keeping
    /// it separate from the trigger bucket stops an unsigned notify flood from
    /// draining the signed trigger caller's quota. `0` disables. Default: 600.
    #[arg(long, env = "GITLAWB_PEER_WRITE_RATE_LIMIT", default_value_t = 600)]
    pub peer_write_rate_limit: usize,

    /// Optional address to bind a Prometheus `/metrics` exposition endpoint on.
    /// Example: `127.0.0.1:9091`. Leave empty (default) to disable.
    /// Bind to localhost or a private interface — the metrics endpoint is
    /// unauthenticated.
    #[arg(long, env = "GITLAWB_METRICS_ADDR", default_value = "")]
    pub metrics_addr: String,

    /// Maximum time to wait for in-flight requests to drain on shutdown, in
    /// seconds. After this elapses, the server returns 503 to anything still
    /// in flight and exits. Default: 30s.
    #[arg(long, env = "GITLAWB_SHUTDOWN_GRACE_SECS", default_value_t = 30)]
    pub shutdown_grace_secs: u64,

    /// Maximum wall-clock time a single served git operation (upload-pack /
    /// receive-pack through `run_git_service`) may run before it is aborted and
    /// its process group torn down, in seconds. Bounds a git that neither
    /// finishes nor disconnects. Must be positive and at most
    /// [`GIT_SERVICE_TIMEOUT_SECS_MAX`] (100 years, the largest value every derived
    /// deadline can represent); setting it very large is still the way to disable the
    /// bound. Default: 600s (10 min), generous for large clones. Also bounds the ref
    /// advertisement
    /// (`info/refs`) and the withheld-blob pack build (`upload_pack_excluding`'s
    /// pack-objects stage), which now share the same timeout + process-group
    /// teardown (#174).
    #[arg(
        long,
        env = "GITLAWB_GIT_SERVICE_TIMEOUT_SECS",
        default_value_t = 600,
        value_parser = clap::value_parser!(u64).range(1..=GIT_SERVICE_TIMEOUT_SECS_MAX)
    )]
    pub git_service_timeout_secs: u64,

    /// Maximum wall-clock time the storage-acquisition phase of a served git
    /// operation may run before the request is shed with a 503, in seconds. This
    /// bounds `RepoStore::{acquire,acquire_fresh,acquire_write}` — the Tigris
    /// HEAD/GET on a read/advert acquire and the advisory-lock retry loop (incl. a
    /// per-iteration `pg_try_advisory_lock` that can block on a hung Postgres pool)
    /// on a write acquire. A concurrency permit is taken BEFORE this phase, and
    /// `git_service_timeout_secs` only starts once git spawns, so without this the
    /// acquire phase is unbounded: a stalled backend pins the permit and drains the
    /// pool until every later request 503s. On expiry the permit is released and a
    /// bounded 503 + Retry-After is returned (fail-closed). Kept separate from
    /// `git_service_timeout_secs` because acquisition and git execution are distinct
    /// cost centers — one shared budget would let a slow acquire starve git. Must be
    /// positive; set it very large to effectively disable the bound. Default: 30s.
    #[arg(
        long,
        env = "GITLAWB_GIT_ACQUIRE_TIMEOUT_SECS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub git_acquire_timeout_secs: u64,

    /// Maximum connections in the PostgreSQL pool. This is a cap, not a floor
    /// (connections open lazily). Size against the database server's
    /// max_connections, remembering admin tooling opens its own pool. Each
    /// concurrent write pins one pooled connection for its whole duration (the
    /// advisory lock in `repo_store::acquire_write` is connection-affine), so this
    /// must exceed `max_concurrent_git_pushes` by `DB_POOL_APP_HEADROOM` or slow
    /// pushes starve every other DB path — enforced by `Config::validate`.
    #[arg(
        long,
        env = "GITLAWB_DB_MAX_CONNECTIONS",
        default_value_t = 48,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub db_max_connections: u32,

    /// Maximum time a request waits for a pool connection before failing with
    /// 503, in seconds. Bounds queueing when the database is slow or down.
    #[arg(
        long,
        env = "GITLAWB_DB_ACQUIRE_TIMEOUT_SECS",
        default_value_t = 5,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub db_acquire_timeout_secs: u64,

    /// Upper bound on each startup connect-and-migrate attempt, in seconds.
    /// Migrations wait on a cross-instance advisory lock, so this must be
    /// generous enough for a peer instance to finish migrating; on expiry the
    /// attempt is retried (migrations are idempotent).
    #[arg(
        long,
        env = "GITLAWB_DB_CONNECT_TIMEOUT_SECS",
        default_value_t = 60,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub db_connect_timeout_secs: u64,

    /// First retry delay when the database is unavailable at startup, in
    /// seconds. Doubles each attempt up to --db-retry-max-secs.
    #[arg(
        long,
        env = "GITLAWB_DB_RETRY_INITIAL_SECS",
        default_value_t = 5,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub db_retry_initial_secs: u64,

    /// Ceiling on the startup retry delay, in seconds.
    #[arg(
        long,
        env = "GITLAWB_DB_RETRY_MAX_SECS",
        default_value_t = 60,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub db_retry_max_secs: u64,

    /// Maximum number of served git operations (upload-pack / receive-pack /
    /// info-refs) allowed to run concurrently. Beyond this the node sheds the
    /// request with a clean 503 + Retry-After instead of spawning another git
    /// subprocess and risking PID/thread exhaustion. Portable backstop: the
    /// compose `pids_limit` is not present on Fly, whose connection-concurrency
    /// cap is a different axis (500 connections each fan out to git +
    /// pack-objects + threads). Size below the process budget with headroom.
    ///
    /// This is the READ pool (`git_read_semaphore`): upload-pack and the UPLOAD-PACK
    /// `info/refs` advertisement only. The authenticated push POST draws from a
    /// separate write pool (`max_concurrent_git_pushes`) that anonymous reads can
    /// never reach, and each read caller is additionally bounded by
    /// `max_concurrent_reads_per_caller`, so an anonymous flood cannot shed the actual
    /// push nor monopolize reads (#174). The anon-reachable RECEIVE-PACK `info/refs`
    /// advertisement draws from its OWN dedicated pool (sized like the write pool but
    /// disjoint), so an advertisement flood can never occupy a permit the
    /// authenticated push POST needs at admission (#174).
    ///
    /// A permit is held for the whole op. Every git subprocess that STREAMS is
    /// duration-bounded and reaps its process group on disconnect: upload-pack,
    /// receive-pack, and both info/refs advertisements run under
    /// `git_service_timeout_secs` with `process_group(0)` teardown, and the
    /// withheld-blob (`upload_pack_excluding`) pack-objects stage plus the push-side
    /// candidate-discovery children (`rev-list` / `cat-file`) now run under the same
    /// bounded runner with process-group teardown, so a stuck git child no longer
    /// holds its slot indefinitely (#174 closed the duration/cancellation gaps this
    /// comment previously tracked).
    ///
    /// Default: 128. Must be between 1 and 1_048_576; the ceiling keeps the value
    /// well under tokio's `Semaphore` permit limit so an oversized value is a
    /// clean CLI error rather than a boot-time panic.
    #[arg(
        long,
        env = "GITLAWB_MAX_CONCURRENT_GIT_OPS",
        default_value_t = 128,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub max_concurrent_git_ops: usize,

    /// Maximum number of concurrent `git-receive-pack` (push) operations. The
    /// authenticated push POST draws from this dedicated pool, separate from
    /// `max_concurrent_git_ops` (reads), so a flood of anonymous reads cannot shed an
    /// authenticated push at admission (#174). The anon-reachable receive-pack
    /// `info/refs` advertisement runs in a SEPARATE pool of the same size (derived
    /// from this knob), disjoint from this one, so an advertisement flood cannot
    /// occupy a POST's slot either (#174). Beyond this a push sheds a clean 503 +
    /// Retry-After.
    ///
    /// Default: 32. Must be between 1 and 1_048_576 (the ceiling keeps the value
    /// under tokio's `Semaphore` permit limit so an oversized value is a clean CLI
    /// error rather than a boot-time panic).
    ///
    /// CONNECTION BUDGET. A push holds a Postgres connection from the node's separate
    /// advisory-lock pool for the whole receive-pack, and that pool is sized from this
    /// knob (this value + 8, clamped to 64 in `main.rs`). The node's total ceiling is
    /// therefore `db_max_connections` (default 48) + the lock pool (default 40), i.e.
    /// 88 by default, and at most `db_max_connections` + 64. Size BOTH against the
    /// database server's `max_connections`: `db_max_connections`' own doc predates the
    /// lock pool and no longer covers most of the node's connections. The +8 headroom
    /// is shared with the three non-push `acquire_write` callers (`api/issues.rs` x2,
    /// `api/pulls.rs`). Raising this knob past the clamp does NOT buy more lock-pool
    /// connections; pushes beyond it wait briefly and then shed a 503 + Retry-After.
    #[arg(
        long,
        env = "GITLAWB_MAX_CONCURRENT_GIT_PUSHES",
        default_value_t = 32,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub max_concurrent_git_pushes: usize,

    /// Maximum number of pushes that may be PARKED on one repo's in-process write lease
    /// at once. Same-repo pushes are serialized (block-and-wait), and a parked push has
    /// already had its entire pack buffered by axum, so an unbounded queue on a contended
    /// repo is unbounded buffered memory held for up to `git_service_timeout_secs * 2 +
    /// 60` (1260s at defaults). Past this cap the newest push sheds a clean 503 +
    /// Retry-After instead of joining the queue.
    ///
    /// The trade: raising it lets more same-repo pushes wait their turn (fewer 503s for a
    /// hot repo, more memory pinned by waiters); lowering it sheds sooner. Only pushes to
    /// the SAME repo count, and only ones parked right now, so the cap can never deny a
    /// push to a different repo. The holder is deliberately not counted: a holder whose
    /// cleanup never ran would otherwise pin a slot forever and wedge the repo, which is
    /// the failure the `steal_after` reclaim exists to survive.
    ///
    /// Default: 8, a quarter of the default `max_concurrent_git_pushes` (32). Raising the
    /// push pool does not raise this; set it explicitly. Must be between 1 and 1_048_576.
    #[arg(
        long,
        env = "GITLAWB_REPO_LEASE_MAX_WAITERS",
        default_value_t = 8,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub repo_lease_max_waiters: usize,

    /// Max concurrent post-push pin loops (`ipfs_pin` and `pinata`
    /// `pin_new_objects`) across all repos. `EncryptInflight` bounds the outstanding
    /// pin-task COUNT to one per repo, but each pin loop holds a full per-push
    /// object-id list (up to `git_max_pack_bytes` worth of OIDs) while it walks it,
    /// so N distinct repos could hold N such lists at once. This caps how many run
    /// concurrently (#174 F6). Beyond it a pin loop DEFERS (waits) and never drops,
    /// since a dropped pin would lose the object's replication copy.
    ///
    /// It does not cap the memory itself: the local IPFS path builds its list before
    /// taking a permit, so tasks parked on this pool still hold theirs, and how many
    /// park is capped only per repo. Lowering this knob bounds concurrent pinning, not
    /// how much an actor pushing to many repos can retain.
    ///
    /// Default: 8. Must be between 1 and 1_048_576.
    #[arg(
        long,
        env = "GITLAWB_MAX_CONCURRENT_PIN_TASKS",
        default_value_t = 8,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub max_concurrent_pin_tasks: usize,

    /// Maximum concurrent read operations (`upload-pack` and the upload-pack
    /// `info/refs` advertisement) a single caller may hold at once, so one caller
    /// cannot monopolize the `max_concurrent_git_ops` read pool (#174). Callers are
    /// keyed on the RESOLVED SOURCE IP, never the DID — a signature does not move a
    /// caller off this cap, so an authenticated client cannot mint DIDs to escape it.
    /// IMPORTANT: the source-IP key is only as granular as `GITLAWB_TRUSTED_PROXY`.
    /// Left unset (the default), a node behind an edge/NAT keys all callers on the
    /// edge IP, so this cap collapses to a single global cap rather than per-client.
    /// Set `GITLAWB_TRUSTED_PROXY` to key on the real client; a high-fanout caller (a
    /// CI fleet behind one NAT) then needs the operator to raise this. Over-cap for a
    /// caller sheds a clean 503 + Retry-After.
    ///
    /// Default: 16. Must be between 1 and 1_048_576.
    #[arg(
        long,
        env = "GITLAWB_MAX_CONCURRENT_READS_PER_CALLER",
        default_value_t = 16,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub max_concurrent_reads_per_caller: usize,

    /// Maximum number of concurrent `GET /ipfs/{cid}` requests that may run their
    /// visibility walk at once. The publicly-reachable `/ipfs/{cid}` route runs
    /// `allowed_blob_set_for_caller_bounded` in `spawn_blocking` — a full-history
    /// git walk (up to `git_service_timeout_secs`) — for each candidate repo. It
    /// draws from THIS pool, not any served-git pool: a distinct public cost center
    /// on a distinct surface, so sharing a git pool would let anonymous /ipfs
    /// traffic shed authenticated git ops (the auth-boundary trap). A permit is
    /// held for the whole request (across the repo loop) so it reflects real
    /// blocking-thread occupancy, not merely the tokio wait. Beyond this the request
    /// sheds a clean 503 + Retry-After. Must be between 1 and 1_048_576; the ceiling
    /// keeps the value under tokio's `Semaphore` permit limit so an oversized value
    /// is a clean CLI error rather than a boot-time panic. Default: 32.
    #[arg(
        long,
        env = "GITLAWB_MAX_CONCURRENT_IPFS_WALKS",
        default_value_t = 32,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub max_concurrent_ipfs_walks: usize,

    /// Maximum concurrent `/ipfs/{cid}` walk requests a single source may hold at
    /// once, so one source cannot monopolize `max_concurrent_ipfs_walks` (#174).
    /// Callers are keyed on the RESOLVED SOURCE IP (`client_key`/`GITLAWB_TRUSTED_PROXY`),
    /// never the DID — `/ipfs` accepts any `did:key` via `optional_signature` with no
    /// admission step, so keying on the DID would let one host mint disposable DIDs to
    /// multiply its budget. A request with no resolvable key (no trusted header, no
    /// peer) is bounded by the global pool only, never this sub-cap. Over-cap sheds a
    /// clean 503 + Retry-After. Must be between 1 and 1_048_576. Default: 4.
    #[arg(
        long,
        env = "GITLAWB_IPFS_WALK_PER_SOURCE",
        default_value_t = 4,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub ipfs_walk_per_source: usize,

    /// Per-request ceiling on the number of legacy (NULL-provenance) repos the
    /// `/ipfs/{cid}` resolver's scan fallback will PROBE (`acquire` + `git cat-file
    /// -t`) before giving up. The provenance path targets its recorded sources; the
    /// legacy scan, absent this bound, fans one anonymous request out to O(repos)
    /// subprocess spawns and cold-cache fetches for a CID enumerable from the public
    /// pins index. A truncated scan surfaces as a retryable 503, never a false 404.
    /// Wired into `AppState::ipfs_max_legacy_probes` at construction. This knob does
    /// not govern the history-walk ceiling; see `ipfs_max_repos_walked` for that.
    /// Must be between 1 and 1_048_576. Default: 256.
    #[arg(
        long,
        env = "GITLAWB_IPFS_MAX_LEGACY_PROBES",
        default_value_t = crate::api::ipfs::MAX_LEGACY_PROBES_PER_REQUEST as usize,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub ipfs_max_legacy_probes: usize,

    /// Per-request ceiling on how many repo ROWS the `/ipfs/{cid}` resolver's legacy
    /// scan may fetch from the database. The probe ceiling above only starts counting
    /// once a probe runs, and the two denial classes that dominate a hostile inventory
    /// (quarantine, and a root-scope visibility deny) return before a probe or a visit
    /// is spent, so without this an all-denying node paged its ENTIRE repo table for one
    /// anonymous request while holding a scarce walk permit.
    ///
    /// Reach bound: a holder buried past the ceiling is servable in
    /// `ceil(repos / ceiling) + 1` token-echoing retries. A truncated scan sheds a
    /// retryable 503 carrying a sealed continuation token; the caller echoes it as
    /// `?scan=` and the scan resumes where it stopped. No server-side scan state.
    ///
    /// Floor coupling: raising this knob raises every caller's per-window `/ipfs` work
    /// allowance whenever the route limit sits below the derived floor, because the
    /// floor must fit one full deep scan's page toll (see `AppState::ipfs_work_budget`).
    ///
    /// Tuning DOWN trade: token presence is a coarse inventory-size oracle. A ceiling
    /// truncation emits a token and a wrapped scan does not, so laddering to the
    /// `scan-wrapped` taint tells an anonymous caller the node's total repo count,
    /// private and quarantined included, to within one ceiling. Tolled and coarse at
    /// the 2048 default; it sharpens as the ceiling is lowered.
    ///
    /// Must be between 1 and 1_048_576. Default: 2048.
    #[arg(
        long,
        env = "GITLAWB_IPFS_MAX_LEGACY_SCAN_ROWS",
        default_value_t = crate::api::ipfs::MAX_LEGACY_SCAN_ROWS_PER_REQUEST,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub ipfs_max_legacy_scan_rows: usize,

    /// Upper bound on the number of EXPENSIVE visibility walks
    /// (`allowed_blob_set_for_caller_bounded`, a full-history git walk in a
    /// blocking thread) a single `/ipfs/{cid}` request may run. Only a blob in a
    /// path-scoped repo costs a walk, so the cap counts exactly those candidates
    /// — cheap probe-only visits are bounded by `ipfs_max_repo_visits` instead
    /// (counting them here would starve a plain public copy past the cap out of
    /// its 200). On exhaustion the walk-needing repo is skipped WITHOUT a verdict
    /// and the scan continues; if the request then finds the object nowhere it
    /// sheds a retryable 503 + Retry-After rather than misreport existing content
    /// absent with a 404. The handler still short-circuits the moment it serves.
    /// Must be between 1 and 1_048_576. Default: 64.
    ///
    /// The effective ceiling is the TIGHTER of this knob and the node's internal
    /// history-walk ceiling, `MAX_PIN_SOURCES + 1` = 17 (see
    /// `api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST` and the `min()` that combines the
    /// two in the resolver). Setting this above 17 changes nothing, because the
    /// internal ceiling already binds. Setting it below 17 does lower the cap: the
    /// constant side of the `min()` is what keeps a request from being truncated
    /// before its whole bounded provenance source set has been tried, so an operator
    /// who goes under it is choosing a tighter cap that can 503 a provenanced
    /// request, which is allowed.
    ///
    /// That combined cap is charged PER PHASE, not per request: the provenance phase and
    /// the legacy-scan fallback each get their own equal budget, so one request can run
    /// up to twice it in total (see `MAX_HISTORY_WALKS_PER_REQUEST`, which explains why
    /// the split is what keeps the fallback from inheriting a provenance phase's spent
    /// remainder).
    #[arg(
        long,
        env = "GITLAWB_IPFS_MAX_REPOS_WALKED",
        default_value_t = 64,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub ipfs_max_repos_walked: usize,

    /// Ceiling on the number of repos a single `/ipfs/{cid}` request may VISIT —
    /// pass the repo-level visibility gate into the acquire + `cat-file` probe.
    /// Each visit costs a `RepoStore::acquire` (on a Tigris cache miss that is a
    /// full repo-archive download from object storage, so the worst-case
    /// object-store fetch count for one request equals this ceiling) plus a git
    /// probe subprocess. On exhaustion the scan STOPS — unlike
    /// `ipfs_max_repos_walked`, which skips just the walk-needing repo, there is
    /// no cheaper way to keep scanning — and the request sheds a retryable 503 +
    /// Retry-After rather than a false 404. Must be between 1 and 1_048_576.
    /// Default: 1024.
    #[arg(
        long,
        env = "GITLAWB_IPFS_MAX_REPO_VISITS",
        default_value_t = 1024,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub ipfs_max_repo_visits: usize,

    /// Absolute wall-clock budget for one admitted `GET /ipfs/{cid}` request's
    /// acquire+walk lifetime, in seconds. `max_concurrent_ipfs_walks` bounds how
    /// MANY requests hold walk slots; this bounds how LONG one admitted request
    /// may keep its slot. Without it, each repo iteration draws a fresh
    /// `git_acquire_timeout_secs` and each expensive walk a fresh
    /// `git_service_timeout_secs`, so one request scanning many repos could hold
    /// a scarce walk slot for hours. Every stage (acquire, `cat-file` probe,
    /// visibility walk, content read) starts only while budget remains, and the
    /// acquire wait and walk deadline are clamped to `min(their own timeout,
    /// remaining budget)`; a stage is never started with zero remaining. On
    /// exhaustion the scan stops without a verdict and the request sheds a
    /// retryable 503 + Retry-After rather than a false 404. The clamps bound
    /// only the acquire and walk stages (overshoot there is the walk watchdog's
    /// SIGTERM grace + SIGKILL settle); the `object_type` /
    /// `read_object_content` probe subprocesses are budget-checked before they
    /// start AND each run under their own deadline (the lesser of
    /// `git_service_timeout_secs` and the remaining budget), reaped by
    /// process-group teardown, so a hung `cat-file` cannot hold the request's walk
    /// slot past it. Still unbounded: the probe's `object_store_readable` check is a
    /// synchronous filesystem sweep with nothing to reap, so a wedged filesystem can
    /// hold the slot past the deadline.
    /// Must be positive, and no larger than `GIT_SERVICE_TIMEOUT_SECS_MAX`. The ceiling is
    /// representability, NOT a policy view of a sane budget: `get_by_cid` derives the
    /// request deadline as `Instant::now() + Duration::from_secs(this)`, and that addition
    /// is an explicit overflow check rather than a debug-only one, so a value near the top
    /// of the `u64` range aborts every `/ipfs/{cid}` request in a release build instead of
    /// setting a very long budget. The ceiling sits well below where that starts, about a
    /// factor of 5.85 (see the constant's own note), so it is a conservative margin rather than the
    /// exact overflow point; rejecting at parse time keeps the unrepresentable values out
    /// of every reachable configuration. Setting it very large is still the way to
    /// effectively disable the budget, and the documented sentinels (`999999999`,
    /// `1000000000`) are well inside the range.
    /// Default: 600s (10 min), matching `git_service_timeout_secs` so a single full-length
    /// walk still fits.
    #[arg(
        long,
        env = "GITLAWB_IPFS_REQUEST_BUDGET_SECS",
        default_value_t = 600,
        value_parser = clap::value_parser!(u64).range(1..=GIT_SERVICE_TIMEOUT_SECS_MAX)
    )]
    pub ipfs_request_budget_secs: u64,

    /// Budget for the PRE-WALK CID resolve inside `get_by_cid`, in seconds: the
    /// `oids_for_cid` lookup that maps the requested CID to its git oid(s), which runs
    /// while the scarce walk admission (the global pool permit plus the per-source
    /// sub-permit) is already held.
    ///
    /// It exists because that one await decides whether the request does any admitted
    /// work at all. A syntactically valid CID with no `pinned_cids` row runs zero probes
    /// and zero walks, so under a stalled or saturated pool it would otherwise occupy a
    /// walk slot for the whole `ipfs_request_budget_secs` window (600s by default) while
    /// nothing is walking, and enough distinct source keys doing that reject every real
    /// `/ipfs` retrieval at admission. The other repair, resolving the CID before taking
    /// admission, was rejected: admission stays FIRST so an anonymous flood sheds before
    /// touching the database at all, and moving the read ahead of it would let arbitrarily
    /// many unadmitted permissionless callers stack concurrent DB queries.
    ///
    /// The effective deadline is the lesser of this and the remaining request budget, so a
    /// value larger than `ipfs_request_budget_secs` degrades to the request budget rather
    /// than extending it. Only the resolve is on this clock; every later stage stays on the
    /// full request budget, because from the second oid candidate on those run after real
    /// probe and walk work and a short deadline anchored at admission would shed a
    /// legitimately slow but progressing scan.
    ///
    /// Must be positive, and no larger than `GIT_SERVICE_TIMEOUT_SECS_MAX`, for the same
    /// representability reason as the request budget above: `get_by_cid` derives the
    /// resolve deadline as `Instant::now() + Duration::from_secs(this)`, and that addition
    /// panics on overflow in release builds too. Default: 10s.
    #[arg(
        long,
        env = "GITLAWB_IPFS_RESOLVE_BUDGET_SECS",
        default_value_t = 10,
        value_parser = clap::value_parser!(u64).range(1..=GIT_SERVICE_TIMEOUT_SECS_MAX)
    )]
    pub ipfs_resolve_budget_secs: u64,

    /// Per-client-IP rate limit for `GET /ipfs/{cid}`, in requests per hour. The
    /// route is publicly reachable (`optional_signature`) and each request can drive
    /// a full-history git walk, so it carries a per-IP flood brake in addition to the
    /// concurrency cap above (a rate limit bounds request *rate*, the semaphore
    /// bounds concurrent slow holds — different axes). Keyed on the resolved client
    /// IP via `GITLAWB_TRUSTED_PROXY`. `0` disables. Default: 600.
    ///
    /// This is the pure once-per-request ROUTE brake. The resolver's internal
    /// per-probe/per-walk WORK budget is a SEPARATE bucket whose capacity is DERIVED
    /// from this value (`AppState::ipfs_work_budget`), not a knob of its own; `0` here
    /// disables that derived bucket too.
    #[arg(long, env = "GITLAWB_IPFS_RATE_LIMIT", default_value_t = 600)]
    pub ipfs_rate_limit: usize,

    /// Rows the legacy provider-CID repair sweep reads per batch (U4, #173).
    ///
    /// The sweep walks every `pinned_cids` row on the node once, repairing rows that
    /// releases before this branch keyed on a PROVIDER CID (Kubo dag-pb / Pinata CIDv0)
    /// instead of the raw-content resolver key. This bounds one batch, so the sweep can
    /// never turn into a single unbounded table scan competing with request traffic.
    /// Conservative on purpose: paired with the inter-batch delay below the default is
    /// ~64 rows per minute, which finishes a large pin set in hours of idle background
    /// work rather than one expensive burst. Must be between 1 and 100_000.
    #[arg(
        long,
        env = "GITLAWB_PIN_REPAIR_SWEEP_BATCH",
        default_value_t = 64,
        value_parser = clap::builder::RangedU64ValueParser::<i64>::new().range(1..=100_000)
    )]
    pub pin_repair_sweep_batch: i64,

    /// Seconds the legacy provider-CID repair sweep sleeps between batches (U4, #173).
    ///
    /// Each batch costs an indexed range scan plus, for the legacy rows in it, a
    /// `git cat-file` per row. The delay is what keeps that off the DB's and the disk's
    /// critical path: the sweep is repairing rows that have been unresolvable since the
    /// upgrade, so finishing slowly is fine and finishing fast at the cost of live
    /// traffic is not. `0` disables the pause (test and one-off operational use only).
    /// Must be between 0 and 86_400.
    #[arg(
        long,
        env = "GITLAWB_PIN_REPAIR_SWEEP_DELAY_SECS",
        default_value_t = 60,
        value_parser = clap::builder::RangedU64ValueParser::<u64>::new().range(0..=86_400)
    )]
    pub pin_repair_sweep_delay_secs: u64,
}

impl Config {
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Resolve ~ in key_path
    pub fn resolved_key_path(&self) -> PathBuf {
        if self.key_path.starts_with("~/") {
            if let Some(home) = dirs_next::home_dir() {
                return home.join(&self.key_path[2..]);
            }
        }
        PathBuf::from(&self.key_path)
    }

    /// DB connections reserved for everything other than held write-locks: auth
    /// lookups, visibility-rule reads, the post-receive tail's own DB writes, and
    /// admin tooling. A write pins one pooled connection for its whole duration, so
    /// the pool must clear the concurrent-write cap by at least this margin.
    pub const DB_POOL_APP_HEADROOM: u32 = 8;

    /// Cross-field boot validation. Single-field ranges are enforced by clap; this
    /// catches combinations that ship a denial-of-service under otherwise-valid
    /// values. Call once at startup and fail fast on `Err`.
    pub fn validate(&self) -> Result<(), String> {
        // A write pins one pooled connection for its whole duration (the
        // connection-affine advisory lock in repo_store::acquire_write), and
        // concurrent writes are capped at max_concurrent_git_pushes. If the pool
        // does not exceed that cap by DB_POOL_APP_HEADROOM, a burst of slow pushes
        // drains every connection and every other DB path 503s. (#174 F1)
        let floor = (self.max_concurrent_git_pushes as u64) + (Self::DB_POOL_APP_HEADROOM as u64);
        if (self.db_max_connections as u64) < floor {
            return Err(format!(
                "GITLAWB_DB_MAX_CONNECTIONS ({}) must be at least max_concurrent_git_pushes ({}) \
                 + {} headroom = {}: each concurrent write pins one pooled connection for its whole \
                 duration, so a smaller pool lets a burst of slow pushes starve every other DB path.",
                self.db_max_connections,
                self.max_concurrent_git_pushes,
                Self::DB_POOL_APP_HEADROOM,
                floor
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_service_timeout_defaults_to_600_and_rejects_zero() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).git_service_timeout_secs,
            600
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--git-service-timeout-secs", "30"])
                .git_service_timeout_secs,
            30
        );
        // 0 is a footgun (immediate-504 on every request); clap must reject it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--git-service-timeout-secs", "0"]).is_err()
        );
    }

    /// #174 (RED-before/GREEN-after): the upper bound is what keeps every duration
    /// derived from this knob in range — the lease steal bound's `* 2 + 60` on the write
    /// path, and the `Instant::now() + Duration::from_secs(..)` deadlines in
    /// `build_filtered_pack` / `blob_paths` on the serve path, which panic on overflow in
    /// release builds too. Checked at parse time so no reachable configuration can carry a
    /// value those sites cannot represent.
    ///
    /// The pre-existing "set it very large to disable the bound" settings are asserted
    /// alongside the rejections on purpose. The bound exists to exclude unrepresentable
    /// values, not to impose a view of a reasonable timeout, so a node that has been
    /// running on ~31 years must not start failing at boot on upgrade.
    #[test]
    fn git_service_timeout_rejects_values_no_derived_duration_can_represent() {
        let parse = |secs: u64| {
            Config::try_parse_from([
                "gitlawb-node",
                "--git-service-timeout-secs",
                &secs.to_string(),
            ])
        };

        // Large "disable the bound" values that predate the ceiling still parse.
        for disable in [1_000_000_000, 999_999_999] {
            assert_eq!(
                parse(disable)
                    .unwrap_or_else(|e| panic!("{disable} was a working setting: {e}"))
                    .git_service_timeout_secs,
                disable
            );
        }

        // At the ceiling: accepted, and every derived duration still fits.
        let at_max =
            parse(GIT_SERVICE_TIMEOUT_SECS_MAX).expect("the documented maximum must parse");
        assert_eq!(
            at_max.git_service_timeout_secs,
            GIT_SERVICE_TIMEOUT_SECS_MAX
        );
        assert!(at_max
            .git_service_timeout_secs
            .checked_mul(2)
            .and_then(|v| v.checked_add(60))
            .is_some());
        assert!(std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(
                at_max.git_service_timeout_secs
            ))
            .is_some());

        // Past the ceiling, and the top of the u64 range clap used to accept — the value
        // that panics `Instant::now() + Duration::from_secs(..)` outright.
        for over in [GIT_SERVICE_TIMEOUT_SECS_MAX + 1, u64::MAX] {
            assert!(
                parse(over).is_err(),
                "{over} is past the representable ceiling and must be rejected at parse time"
            );
        }
        assert!(std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(u64::MAX))
            .is_none());
    }

    #[test]
    fn max_concurrent_pin_tasks_defaults_and_rejects_out_of_range() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).max_concurrent_pin_tasks,
            8
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-pin-tasks", "2"])
                .max_concurrent_pin_tasks,
            2
        );
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-pin-tasks", "0"]).is_err()
        );
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-pin-tasks", "1048577"])
                .is_err()
        );
    }

    #[test]
    fn max_concurrent_git_ops_defaults_and_rejects_out_of_range() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).max_concurrent_git_ops,
            128
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-git-ops", "8"])
                .max_concurrent_git_ops,
            8
        );
        // 0 permits would shed every served-git request with a 503; clap must reject it.
        assert!(Config::try_parse_from(["gitlawb-node", "--max-concurrent-git-ops", "0"]).is_err());
        // Above the ceiling would panic tokio's Semaphore::new at boot (permits >
        // usize::MAX >> 3); clap must reject it as a clean CLI error instead.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-git-ops", "1048577"])
                .is_err()
        );
        // The ceiling itself is accepted.
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-git-ops", "1048576"])
                .max_concurrent_git_ops,
            1_048_576
        );
    }

    #[test]
    fn max_concurrent_git_pushes_defaults_and_rejects_out_of_range() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).max_concurrent_git_pushes,
            32
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-git-pushes", "8"])
                .max_concurrent_git_pushes,
            8
        );
        // 0 permits would shed every push with a 503; clap must reject it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-git-pushes", "0"]).is_err()
        );
        // Above the ceiling would panic tokio's Semaphore::new at boot; clap rejects it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-git-pushes", "1048577"])
                .is_err()
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-git-pushes", "1048576"])
                .max_concurrent_git_pushes,
            1_048_576
        );
    }

    #[test]
    fn max_concurrent_ipfs_walks_defaults_and_rejects_out_of_range() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).max_concurrent_ipfs_walks,
            32
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-ipfs-walks", "4"])
                .max_concurrent_ipfs_walks,
            4
        );
        // 0 permits would shed every /ipfs walk with a 503; clap must reject it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-ipfs-walks", "0"]).is_err()
        );
        // Above the ceiling would panic tokio's Semaphore::new at boot; clap rejects it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-ipfs-walks", "1048577"])
                .is_err()
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-ipfs-walks", "1048576"])
                .max_concurrent_ipfs_walks,
            1_048_576
        );
    }

    /// U4 (#173): the repair sweep's bounds are conservative by default and a batch of
    /// 0 (a sweep that walks nothing and never terminates) is a CLI error, not a
    /// runtime hang. The delay does accept 0, for tests and one-off operational runs.
    #[test]
    fn pin_repair_sweep_knobs_default_conservatively() {
        let c = Config::parse_from(["gitlawb-node"]);
        assert_eq!(c.pin_repair_sweep_batch, 64);
        assert_eq!(c.pin_repair_sweep_delay_secs, 60);

        assert!(Config::try_parse_from(["gitlawb-node", "--pin-repair-sweep-batch", "0"]).is_err());
        assert!(
            Config::try_parse_from(["gitlawb-node", "--pin-repair-sweep-batch", "100001"]).is_err()
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--pin-repair-sweep-batch", "8"])
                .pin_repair_sweep_batch,
            8
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--pin-repair-sweep-delay-secs", "0"])
                .pin_repair_sweep_delay_secs,
            0
        );
        assert!(
            Config::try_parse_from(["gitlawb-node", "--pin-repair-sweep-delay-secs", "86401"])
                .is_err()
        );
    }

    #[test]
    fn ipfs_walk_per_source_defaults_and_rejects_out_of_range() {
        assert_eq!(Config::parse_from(["gitlawb-node"]).ipfs_walk_per_source, 4);
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--ipfs-walk-per-source", "2"])
                .ipfs_walk_per_source,
            2
        );
        // 0 would shed every /ipfs walk from a keyed source; clap must reject it.
        assert!(Config::try_parse_from(["gitlawb-node", "--ipfs-walk-per-source", "0"]).is_err());
        assert!(
            Config::try_parse_from(["gitlawb-node", "--ipfs-walk-per-source", "1048577"]).is_err()
        );
    }

    /// The legacy-probe budget and the expensive-walk cap are SEPARATE knobs with
    /// different defaults. They were one field until the probe budget and the walk cap
    /// were split apart, so assert both defaults here: a future collapse back into one
    /// field silently gives one of the two the other's default.
    #[test]
    fn ipfs_probe_and_walk_knobs_default_apart_and_reject_out_of_range() {
        let default = Config::parse_from(["gitlawb-node"]);
        assert_eq!(default.ipfs_max_legacy_probes, 256, "legacy-probe budget");
        assert_eq!(default.ipfs_max_repos_walked, 64, "expensive-walk cap");

        assert_eq!(
            Config::parse_from(["gitlawb-node", "--ipfs-max-legacy-probes", "8"])
                .ipfs_max_legacy_probes,
            8
        );
        // 0 would probe no repos (serve nothing); clap must reject it.
        assert!(Config::try_parse_from(["gitlawb-node", "--ipfs-max-legacy-probes", "0"]).is_err());
        assert!(
            Config::try_parse_from(["gitlawb-node", "--ipfs-max-legacy-probes", "1048577"])
                .is_err()
        );
        assert!(Config::try_parse_from(["gitlawb-node", "--ipfs-max-repos-walked", "0"]).is_err());
    }

    /// The `GITLAWB_IPFS_MAX_LEGACY_PROBES` knob must actually reach the legacy-probe
    /// budget it advertises: production seeds `ipfs_max_legacy_probes` from this helper,
    /// so the knob is a no-op unless the helper reflects it. RED while the helper returns
    /// the hardcoded `MAX_LEGACY_PROBES_PER_REQUEST` (256 regardless of the knob), GREEN
    /// once it reads the knob.
    #[test]
    fn ipfs_max_legacy_probes_wires_the_legacy_probe_budget() {
        use crate::state::AppState;
        // Knob set to 1 → a one-probe legacy budget.
        let one = Config::parse_from(["gitlawb-node", "--ipfs-max-legacy-probes", "1"]);
        assert_eq!(
            AppState::ipfs_legacy_probe_budget(&one),
            1,
            "the knob must control the legacy-probe budget, not be ignored"
        );
        // Unset knob preserves the shipped 256-probe behaviour.
        let default = Config::parse_from(["gitlawb-node"]);
        assert_eq!(
            AppState::ipfs_legacy_probe_budget(&default),
            256,
            "the default knob keeps the shipped 256-probe budget"
        );
        assert_eq!(
            AppState::ipfs_legacy_probe_budget(&default),
            crate::api::ipfs::MAX_LEGACY_PROBES_PER_REQUEST,
            "the default budget equals the constant it replaced"
        );
        // Ceiling guard: the knob never governs the history-walk ceiling, which must
        // stay at MAX_PIN_SOURCES + 1 or a provenanced full source set false-503s.
        assert!(
            crate::api::ipfs::MAX_HISTORY_WALKS_PER_REQUEST > crate::db::MAX_PIN_SOURCES as u32,
            "the history-walk ceiling is independent of the repos-walked knob"
        );
    }

    /// The `/ipfs` work-budget capacity is DERIVED from the route limit (R6, KTD6), with
    /// a hard floor of one complete COMBINED resolution per window: the provenance
    /// phase's walk term plus a full legacy search (the effective
    /// `ipfs_max_legacy_probes` plus the row ceiling's page toll). This guards the
    /// derived default so a single default-config deep search never self-throttles
    /// mid-scan and recreates the F6 admit-then-429 for a legitimate caller. A
    /// `RateLimiter` sized to the derived budget must admit the whole budget back to
    /// back.
    #[test]
    fn ipfs_work_budget_derives_from_route_limit_and_clears_the_probe_floor() {
        use crate::state::AppState;

        // Default config: derived work budget = max(route 600, probe budget 256) = 600,
        // comfortably above the 256-probe floor.
        let default = Config::parse_from(["gitlawb-node"]);
        let budget = AppState::ipfs_work_budget(&default);
        assert_eq!(budget, 600, "default derives max(route 600, probe 256)");
        assert!(
            budget >= AppState::ipfs_legacy_probe_budget(&default) as usize,
            "the work budget must clear one full legacy search per window"
        );

        // Tight route limit (1): the floor lifts the work budget to one complete
        // COMBINED resolution, the 256-probe budget PLUS the page toll a 2048-row
        // ceiling costs at 128 rows per page (16) PLUS the provenance phase's walk term
        // min(17, 64) = 17, so 289, NOT down to 1. The provenance walks come off the
        // same bucket before the fallback runs, so a floor without that term hands the
        // legacy search a bucket the provenance phase already spent from. This case
        // also carries the walk term's ABOVE-constant direction: the repos-walked knob
        // is at its default 64, so `MAX_HISTORY_WALKS_PER_REQUEST` (17) is what binds.
        let tight = Config::parse_from(["gitlawb-node", "--ipfs-rate-limit", "1"]);
        assert_eq!(
            AppState::ipfs_work_budget(&tight),
            289,
            "a tight route limit is floored at probes + pages + walks \
             (256 + 16 + min(17, 64) = 17), not clamped to 1"
        );

        // The walk term's BELOW-constant direction: a repos-walked knob under the
        // history-walk constant is what the resolver's own `walk_cap` min() selects, so
        // it is what the floor must carry too. 256 + 16 + min(17, 3) = 275.
        let narrow_walk = Config::parse_from([
            "gitlawb-node",
            "--ipfs-rate-limit",
            "1",
            "--ipfs-max-repos-walked",
            "3",
        ]);
        assert_eq!(
            AppState::ipfs_work_budget(&narrow_walk),
            275,
            "the walk term takes min(17, repos-walked 3) = 3, the resolver's own \
             walk_cap, so the floor is 256 + 16 + 3"
        );

        // Raised probe budget lifts the floor with it (the work budget tracks the
        // effective probe budget, not the constant). The walk cap here is a SECOND
        // below-constant proof at a different pair of values: min(17, 7) = 7, and the
        // probe knob is raised at the same time so a floor that folded the two terms
        // together (they were one field before the split) reads visibly wrong rather
        // than plausibly right.
        let raised = Config::parse_from([
            "gitlawb-node",
            "--ipfs-rate-limit",
            "10",
            "--ipfs-max-legacy-probes",
            "1000",
            "--ipfs-max-repos-walked",
            "7",
        ]);
        assert_eq!(
            AppState::ipfs_work_budget(&raised),
            1023,
            "the floor tracks the operator-raised legacy-probe budget (1000) plus the \
             default row ceiling's page toll (16) plus the walk term min(17, 7) = 7"
        );

        // The scan-rows knob is coupled to the floor too, and this EXECUTES the coupling
        // rather than describing it: every page the ceiling permits is charged to the
        // caller's work bucket, so a raised ceiling that did not lift the floor would
        // 429 an honest caller part-way down their own token ladder. 4096 rows at 128
        // rows per page is 32 pages, so the floor is 256 + 32 + the default walk term
        // of 17.
        let wide_scan = Config::parse_from([
            "gitlawb-node",
            "--ipfs-rate-limit",
            "10",
            "--ipfs-max-legacy-scan-rows",
            "4096",
        ]);
        assert_eq!(
            AppState::ipfs_work_budget(&wide_scan),
            305,
            "raising the row ceiling must raise the work floor by the pages it buys \
             (256 probes + 4096/128 = 32 pages + min(17, 64) = 17 walks), or a full \
             deep scan self-throttles"
        );

        // 0 route limit disables the derived bucket too (a 0-capacity limiter admits all).
        let disabled = Config::parse_from(["gitlawb-node", "--ipfs-rate-limit", "0"]);
        assert_eq!(
            AppState::ipfs_work_budget(&disabled),
            0,
            "route limit 0 disables the derived work bucket alongside the route brake"
        );

        // Behavioral floor: a limiter sized to the derived (tight-route) budget admits
        // a whole combined resolution's worth of charges back to back for one source,
        // then sheds the next.
        let budget = AppState::ipfs_work_budget(&tight);
        let limiter =
            crate::rate_limit::RateLimiter::new(budget, std::time::Duration::from_secs(3600));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for i in 0..budget {
                assert!(
                    limiter.check("1.2.3.4").await,
                    "charge {i} of one full combined resolution must be admitted (no mid-scan throttle)"
                );
            }
            assert!(
                !limiter.check("1.2.3.4").await,
                "the probe past the derived budget is shed"
            );
        });
    }

    #[test]
    fn ipfs_max_repos_walked_defaults_and_rejects_out_of_range() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).ipfs_max_repos_walked,
            64
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--ipfs-max-repos-walked", "8"])
                .ipfs_max_repos_walked,
            8
        );
        // 0 would walk no repos (serve nothing); clap must reject it.
        assert!(Config::try_parse_from(["gitlawb-node", "--ipfs-max-repos-walked", "0"]).is_err());
        assert!(
            Config::try_parse_from(["gitlawb-node", "--ipfs-max-repos-walked", "1048577"]).is_err()
        );
    }

    #[test]
    fn ipfs_max_repo_visits_defaults_and_rejects_out_of_range() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).ipfs_max_repo_visits,
            1024
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--ipfs-max-repo-visits", "8"])
                .ipfs_max_repo_visits,
            8
        );
        // 0 would visit no repos (serve nothing); clap must reject it.
        assert!(Config::try_parse_from(["gitlawb-node", "--ipfs-max-repo-visits", "0"]).is_err());
        assert!(
            Config::try_parse_from(["gitlawb-node", "--ipfs-max-repo-visits", "1048577"]).is_err()
        );
    }

    #[test]
    fn ipfs_request_budget_secs_defaults_to_600_and_rejects_zero() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).ipfs_request_budget_secs,
            600
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--ipfs-request-budget-secs", "30"])
                .ipfs_request_budget_secs,
            30
        );
        // 0 would expire every /ipfs request at its first stage (unconditional
        // 503); clap must reject it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--ipfs-request-budget-secs", "0"]).is_err()
        );
    }

    #[test]
    fn ipfs_resolve_budget_secs_defaults_to_10_and_rejects_zero() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).ipfs_resolve_budget_secs,
            10
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--ipfs-resolve-budget-secs", "3"])
                .ipfs_resolve_budget_secs,
            3
        );
        // 0 would shed every /ipfs request at the pre-walk resolve (unconditional
        // 503); clap must reject it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--ipfs-resolve-budget-secs", "0"]).is_err()
        );
        // The ceiling is shared with the request budget: at the max it parses and the
        // derived deadline is still representable, past it clap rejects.
        let at_max = Config::try_parse_from([
            "gitlawb-node",
            "--ipfs-resolve-budget-secs",
            &GIT_SERVICE_TIMEOUT_SECS_MAX.to_string(),
        ])
        .expect("the documented maximum must parse");
        assert_eq!(
            at_max.ipfs_resolve_budget_secs,
            GIT_SERVICE_TIMEOUT_SECS_MAX
        );
        assert!(std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(
                at_max.ipfs_resolve_budget_secs
            ))
            .is_some());
        for over in [GIT_SERVICE_TIMEOUT_SECS_MAX + 1, u64::MAX] {
            assert!(
                Config::try_parse_from([
                    "gitlawb-node",
                    "--ipfs-resolve-budget-secs",
                    &over.to_string(),
                ])
                .is_err(),
                "{over} is past the representable ceiling and must be rejected at parse time"
            );
        }
    }

    /// #174 (RED-before/GREEN-after): the upper bound is what keeps the deadline derived
    /// from this knob in range. `get_by_cid` builds the request budget as
    /// `Instant::now() + Duration::from_secs(this)` (api/ipfs.rs), and that addition is an
    /// explicit overflow check rather than a debug-only one, so an oversized value aborts
    /// every `/ipfs/{cid}` request in a release build instead of setting a very long budget.
    /// The route is anon-reachable, so the failure is operator-triggered but publicly felt.
    /// Checked at parse time so no reachable configuration can carry a value the deadline
    /// cannot represent.
    ///
    /// The large "disable the bound" settings are asserted alongside the rejections on
    /// purpose, the same way the `git_service_timeout_secs` sibling does it. The ceiling
    /// exists to exclude unrepresentable values, not to impose a view of a reasonable
    /// budget, so a node already running on such a value must not start failing at boot on
    /// upgrade. A test that only checked the boundary would pass with a far tighter cap.
    #[test]
    fn ipfs_request_budget_rejects_values_no_derived_duration_can_represent() {
        let parse = |secs: u64| {
            Config::try_parse_from([
                "gitlawb-node",
                "--ipfs-request-budget-secs",
                &secs.to_string(),
            ])
        };

        // Large "disable the bound" values that predate the ceiling still parse.
        for disable in [1_000_000_000, 999_999_999] {
            assert_eq!(
                parse(disable)
                    .unwrap_or_else(|e| panic!("{disable} was a working setting: {e}"))
                    .ipfs_request_budget_secs,
                disable
            );
        }

        // At the ceiling: accepted, and the derived deadline still fits. This knob feeds
        // only the `Instant` addition (no multiply derivation like the lease steal bound),
        // so there is no `checked_mul` clause to carry over from the sibling test.
        let at_max =
            parse(GIT_SERVICE_TIMEOUT_SECS_MAX).expect("the documented maximum must parse");
        assert_eq!(
            at_max.ipfs_request_budget_secs,
            GIT_SERVICE_TIMEOUT_SECS_MAX
        );
        assert!(std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(
                at_max.ipfs_request_budget_secs
            ))
            .is_some());

        // Past the ceiling, and the top of the u64 range clap used to accept. Only the
        // latter actually panics `Instant::now() + Duration::from_secs(..)`; the ceiling
        // sits well below that, which is the conservative margin the constant documents.
        for over in [GIT_SERVICE_TIMEOUT_SECS_MAX + 1, u64::MAX] {
            assert!(
                parse(over).is_err(),
                "{over} is past the representable ceiling and must be rejected at parse time"
            );
        }
        assert!(std::time::Instant::now()
            .checked_add(std::time::Duration::from_secs(u64::MAX))
            .is_none());
    }

    #[test]
    fn max_concurrent_reads_per_caller_defaults_and_rejects_out_of_range() {
        assert_eq!(
            Config::parse_from(["gitlawb-node"]).max_concurrent_reads_per_caller,
            16
        );
        assert_eq!(
            Config::parse_from(["gitlawb-node", "--max-concurrent-reads-per-caller", "4"])
                .max_concurrent_reads_per_caller,
            4
        );
        // 0 would shed every read from a keyed caller; clap must reject it.
        assert!(
            Config::try_parse_from(["gitlawb-node", "--max-concurrent-reads-per-caller", "0"])
                .is_err()
        );
        assert!(Config::try_parse_from([
            "gitlawb-node",
            "--max-concurrent-reads-per-caller",
            "1048577"
        ])
        .is_err());
        assert_eq!(
            Config::parse_from([
                "gitlawb-node",
                "--max-concurrent-reads-per-caller",
                "1048576"
            ])
            .max_concurrent_reads_per_caller,
            1_048_576
        );
    }

    /// #174 F1: a connection-affine write lock pins a pooled connection per
    /// concurrent write, so the pool must clear `max_concurrent_git_pushes` by
    /// `DB_POOL_APP_HEADROOM` or a push burst starves every other DB path.
    /// `validate()` must reject an under-sized pool at boot.
    #[test]
    fn db_pool_must_clear_the_git_push_cap() {
        // Shipped defaults validate (48 >= 32 + 8).
        Config::parse_from(["gitlawb-node"])
            .validate()
            .expect("default config must validate");

        // An under-sized pool relative to the push cap is rejected (20 < 32 + 8).
        let under = Config::parse_from([
            "gitlawb-node",
            "--db-max-connections",
            "20",
            "--max-concurrent-git-pushes",
            "32",
        ]);
        assert!(
            under.validate().is_err(),
            "db_max_connections 20 below max_concurrent_git_pushes 32 + headroom must be rejected"
        );

        // Exactly at the floor validates (40 == 32 + 8).
        let at_floor = Config::parse_from([
            "gitlawb-node",
            "--db-max-connections",
            "40",
            "--max-concurrent-git-pushes",
            "32",
        ]);
        assert!(
            at_floor.validate().is_ok(),
            "db_max_connections at the floor (pushes + headroom) must validate"
        );
    }

    /// The DECLARED default, read off the parser rather than out of a parse.
    ///
    /// `Config::parse_from` consults the process environment, so on a host that
    /// exports `GITLAWB_ENFORCE_OWNER_PUSH=false` a parse-based assertion says
    /// nothing about what this crate declares — it reports the operator's setting.
    /// Asserting the declaration is the env-independent form, and it is the one that
    /// actually fails if someone flips `default_value_t` back.
    #[test]
    fn enforce_owner_push_is_declared_true_independent_of_the_environment() {
        use clap::CommandFactory;
        let cmd = Config::command();
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_id() == "enforce_owner_push")
            .expect("the argument must exist");
        assert_eq!(
            arg.get_default_values(),
            ["true"],
            "owner-only push must be the declared default; a node started with no \
             configuration cannot accept a push from a self-minted key"
        );
    }

    /// The flip must not strand an operator mid-upgrade.
    ///
    /// Turning the gate on is a breaking change for any deployment whose pushers are
    /// not yet the repo owner, so the escape hatch has to keep working. As a
    /// presence-only flag `--enforce-owner-push false` is not "false", it is an
    /// "unexpected argument" error; the value-taking action is what makes that form
    /// parse.
    ///
    /// This pins the CLI form only. The environment form resolved to `false` under
    /// the presence-only declaration too, so it is not what this change fixed, and it
    /// is not exercised here because the process environment is global and these
    /// tests run in parallel.
    #[test]
    fn enforce_owner_push_stays_disableable_for_rolling_upgrades() {
        assert!(
            !Config::parse_from(["gitlawb-node", "--enforce-owner-push", "false"])
                .enforce_owner_push,
            "operators must still be able to opt out during a rolling upgrade"
        );
        assert!(
            Config::parse_from(["gitlawb-node", "--enforce-owner-push", "true"]).enforce_owner_push
        );
    }
}
