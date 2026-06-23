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

    /// Tigris (S3-compatible) bucket for repo storage. Legacy alias for
    /// `s3_bucket` — still honoured so existing deployments keep working.
    /// Leave empty to disable Tigris and use local-only storage.
    #[arg(long, env = "GITLAWB_TIGRIS_BUCKET", default_value = "")]
    pub tigris_bucket: String,

    /// Object-storage backend: `s3` (any S3-compatible service), `fs` (local
    /// directory), or `ipfs` (Kubo MFS). Empty = auto-detect: `s3` when a bucket
    /// is set, else `fs` when a storage dir is set, else `ipfs` when an IPFS API
    /// is set, else local-only.
    #[arg(long, env = "GITLAWB_STORAGE_BACKEND", default_value = "")]
    pub storage_backend: String,

    /// Bucket for the `s3` backend (Tigris, R2, AWS S3, MinIO, B2). Falls back to
    /// `tigris_bucket` when empty.
    #[arg(long, env = "GITLAWB_S3_BUCKET", default_value = "")]
    pub s3_bucket: String,

    /// Endpoint URL override for the `s3` backend (e.g. R2/MinIO). On Tigris/Fly
    /// the endpoint is auto-provided via `AWS_ENDPOINT_URL_S3`, so leave empty.
    #[arg(long, env = "GITLAWB_S3_ENDPOINT", default_value = "")]
    pub s3_endpoint: String,

    /// Force path-style S3 addressing (required by MinIO and some S3-compatibles).
    #[arg(long, env = "GITLAWB_S3_FORCE_PATH_STYLE", default_value_t = false)]
    pub s3_force_path_style: bool,

    /// Directory for the `fs` (local filesystem) storage backend.
    #[arg(long, env = "GITLAWB_STORAGE_FS_DIR", default_value = "")]
    pub storage_fs_dir: String,

    /// Acknowledge a push to the client before the durable upload to object
    /// storage finishes (write-back). Lowers push latency, but opens a
    /// durability window: if the node stops between the ack and the upload, on
    /// restart a stale remote archive can overwrite the newer local copy. Off
    /// by default (strict upload-before-ack); opt in only where the latency win
    /// is worth that risk.
    #[arg(long, env = "GITLAWB_ASYNC_UPLOAD", default_value_t = false)]
    pub async_upload: bool,

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
    /// clones. Does not cover the ref advertisement (`info/refs`) or the
    /// withheld-blob fetch path (`upload_pack_excluding`, a blocking
    /// `spawn_blocking` a tokio timeout cannot cancel); both remain unbounded.
    #[arg(
        long,
        env = "GITLAWB_GIT_SERVICE_TIMEOUT_SECS",
        default_value_t = 600,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub git_service_timeout_secs: u64,

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
}
