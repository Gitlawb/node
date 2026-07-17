use clap::Parser;
use std::path::PathBuf;

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
    /// any party can sign as their own DID. When true, pushes whose authenticated
    /// DID is not the repo owner are rejected. Keep false during rolling upgrades;
    /// flip it on once owners are ready for owner-only writes.
    #[arg(long, env = "GITLAWB_ENFORCE_OWNER_PUSH", default_value_t = false)]
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
    /// finishes nor disconnects. Must be positive; set it very large to
    /// effectively disable the bound. Default: 600s (10 min), generous for large
    /// clones. Also bounds the ref advertisement (`info/refs`) and the withheld-blob
    /// pack build (`upload_pack_excluding`'s pack-objects stage), which now share the
    /// same timeout + process-group teardown (#174).
    #[arg(
        long,
        env = "GITLAWB_GIT_SERVICE_TIMEOUT_SECS",
        default_value_t = 600,
        value_parser = clap::value_parser!(u64).range(1..)
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
    /// max_connections, remembering admin tooling opens its own pool.
    #[arg(
        long,
        env = "GITLAWB_DB_MAX_CONNECTIONS",
        default_value_t = 20,
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
    #[arg(
        long,
        env = "GITLAWB_MAX_CONCURRENT_GIT_PUSHES",
        default_value_t = 32,
        value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=1_048_576)
    )]
    pub max_concurrent_git_pushes: usize,

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
    /// retryable 503 + Retry-After rather than a false 404. Residual overshoot
    /// past the budget is bounded by the kill/reap slack of the one in-flight
    /// clamped stage (the walk watchdog's SIGTERM grace + SIGKILL settle) plus
    /// the `object_type` / `read_object_content` probe subprocesses, which are
    /// budget-checked before they start but carry no internal duration clamp.
    /// Must be positive. Default: 600s (10 min), matching
    /// `git_service_timeout_secs` so a single full-length walk still fits.
    #[arg(
        long,
        env = "GITLAWB_IPFS_REQUEST_BUDGET_SECS",
        default_value_t = 600,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub ipfs_request_budget_secs: u64,

    /// Per-client-IP rate limit for `GET /ipfs/{cid}`, in requests per hour. The
    /// route is publicly reachable (`optional_signature`) and each request can drive
    /// a full-history git walk, so it carries a per-IP flood brake in addition to the
    /// concurrency cap above (a rate limit bounds request *rate*, the semaphore
    /// bounds concurrent slow holds — different axes). Keyed on the resolved client
    /// IP via `GITLAWB_TRUSTED_PROXY`. `0` disables. Default: 600.
    #[arg(long, env = "GITLAWB_IPFS_RATE_LIMIT", default_value_t = 600)]
    pub ipfs_rate_limit: usize,
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
}
