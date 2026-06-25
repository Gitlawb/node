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
