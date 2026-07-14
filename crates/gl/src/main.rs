#![recursion_limit = "256"]

use anyhow::Result;
use clap::{Parser, Subcommand};

mod agent;
mod bounty;
mod cert;
mod changelog;
mod clone;
mod doctor;
mod http;
mod identity;
mod init;
mod ipfs_cmd;
mod issue;
mod mcp;
mod mirror;
mod name;
mod node;
mod node_stake;
mod peer;
mod pr;
mod profile;
mod protect;
mod quickstart;
mod register;
mod repo;
mod star;
mod status;
mod sync;
mod task;
mod ucan_cmd;
mod visibility;
mod webhook;
mod whoami;

#[derive(Parser)]
#[command(
    name = "gl",
    about = "gitlawb CLI — identity, repos, MCP server",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage your gitlawb identity (DID + keypair)
    Identity {
        #[command(subcommand)]
        cmd: identity::IdentityCmd,
    },

    /// Register this agent with a gitlawb node
    Register(register::RegisterArgs),

    /// Clone a gitlawb repo, handling private subtrees cleanly
    Clone(clone::CloneArgs),

    /// Manage repositories
    Repo(repo::RepoArgs),

    /// Manage issues (stored as git refs)
    Issue(issue::IssueArgs),

    /// Peer discovery — add and inspect known nodes
    Peer(peer::PeerArgs),

    /// Manage pull requests
    Pr(pr::PrArgs),

    /// Inspect signed ref-update certificates
    Cert(cert::CertArgs),

    /// IPFS pin management — list pinned CIDs and retrieve objects by CID
    Ipfs(ipfs_cmd::IpfsArgs),

    /// Node status and network info
    Node(node::NodeArgs),

    /// Manage webhooks for a repository
    Webhook(webhook::WebhookArgs),

    /// Mirror a public GitHub/GitLab/any-git repo into gitlawb
    Mirror(mirror::MirrorArgs),

    /// MCP server — expose gitlawb tools to LLM agents
    Mcp(mcp::McpArgs),

    /// Sync repos from peer nodes (HTTP fallback for p2p gossip)
    Sync(sync::SyncArgs),

    /// Manage agent task delegation
    Task(task::TaskArgs),

    /// Register and resolve names on Base L2
    Name(name::NameArgs),

    /// Check your gitlawb installation and connectivity
    Doctor(doctor::DoctorArgs),

    /// Zero-to-push in one command — init repo, identity, register, remote
    Init(init::InitArgs),

    /// Interactive setup wizard — identity, registration, first repo
    Quickstart(quickstart::QuickstartArgs),

    /// Star and unstar repositories
    Star(star::StarArgs),

    /// Snapshot of your current context: identity, node, repo, open work
    Status(status::StatusArgs),

    /// List and inspect registered agents on a node
    Agent(agent::AgentArgs),

    /// Manage your agent profile (name, bio, avatar, social links)
    Profile(profile::ProfileArgs),

    /// Manage branch protection rules
    Protect(protect::ProtectArgs),

    /// Manage path-scoped read visibility rules
    Visibility(visibility::VisibilityArgs),

    /// Show unified activity changelog for a repository
    Changelog(changelog::ChangelogArgs),

    /// Manage token-powered bounties on repositories
    Bounty(bounty::BountyArgs),

    /// Delegate, show, and verify UCAN capability tokens
    Ucan(ucan_cmd::UcanArgs),

    /// Print your current identity (DID) and optional node info
    Whoami(whoami::WhoamiArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("gl=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr) // keep stdout clean for MCP framing
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Identity { cmd } => identity::run(cmd).await,
        Commands::Register(args) => register::run(args).await,
        Commands::Clone(args) => clone::run(args).await,
        Commands::Repo(args) => repo::run(args).await,
        Commands::Issue(args) => issue::run(args).await,
        Commands::Pr(args) => pr::run(args).await,
        Commands::Peer(args) => peer::run(args).await,
        Commands::Cert(args) => cert::run(args).await,
        Commands::Ipfs(args) => ipfs_cmd::run(args).await,
        Commands::Node(args) => node::run(args).await,
        Commands::Webhook(args) => webhook::run(args).await,
        Commands::Mirror(args) => mirror::run(args).await,
        Commands::Mcp(args) => mcp::run(args).await,
        Commands::Sync(args) => sync::run(args).await,
        Commands::Task(args) => task::run(args).await,
        Commands::Name(args) => name::run(args).await,
        Commands::Doctor(args) => doctor::run(args).await,
        Commands::Init(args) => init::run(args).await,
        Commands::Quickstart(args) => quickstart::run(args).await,
        Commands::Star(args) => star::run(args).await,
        Commands::Status(args) => status::run(args).await,
        Commands::Agent(args) => agent::run(args).await,
        Commands::Profile(args) => profile::run(args).await,
        Commands::Protect(args) => protect::run(args).await,
        Commands::Visibility(args) => visibility::run(args).await,
        Commands::Changelog(args) => changelog::run(args).await,
        Commands::Bounty(args) => bounty::run(args).await,
        Commands::Ucan(args) => ucan_cmd::run(args).await,
        Commands::Whoami(args) => whoami::run(args).await,
    }
}
