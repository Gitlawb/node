//! `gl name` — register and resolve names on the Base L2 GitlawbNameRegistry.
//!
//! Commands:
//!   gl name register <name>      — claim name → your DID on Base L2
//!   gl name resolve <name>       — resolve name → (owner, DID)
//!   gl name lookup <did>         — reverse lookup DID → name
//!   gl name available <name>     — check if name is unclaimed
//!   gl name register-did         — anchor your DID in the DID registry
//!   gl name resolve-did <did>    — resolve DID from on-chain registry

use alloy::{
    network::EthereumWallet, primitives::Address, providers::ProviderBuilder,
    signers::local::PrivateKeySigner, sol,
};
use anyhow::{Context, Result};
use clap::Subcommand;
use std::path::PathBuf;

// ── Contract addresses (Base Sepolia testnet) ─────────────────────────────────

const DEFAULT_RPC_URL: &str = "https://sepolia.base.org";
const DEFAULT_NAME_REGISTRY: &str = "0x73094B9DAb2421878A20Abed1497001fbD51302c";
const DEFAULT_DID_REGISTRY: &str = "0x8046284116C5ac6724adbBf860feBeA85692d574";

// ── ABI definitions ───────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    interface GitlawbNameRegistry {
        function register(string name, string did) external;
        function update(string name, string newDid) external;
        function transfer(string name, address newOwner) external;
        function resolve(string name) external view returns (
            address owner,
            string did,
            uint256 registeredAt,
            uint256 updatedAt
        );
        function reverseLookup(string did) external view returns (string name);
        function isAvailable(string name) external view returns (bool);
    }

    #[sol(rpc)]
    interface GitlawbDIDRegistry {
        function register(string did, string document) external;
        function update(string did, string document) external;
        function resolve(string did) external view returns (address owner, string document);
        function isRegistered(string did) external view returns (bool);
    }
}

// ── CLI args ──────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct NameArgs {
    #[command(subcommand)]
    pub cmd: NameCmd,
}

#[derive(Subcommand)]
pub enum NameCmd {
    /// Register a name → your DID on Base L2
    Register {
        /// Name to register (lowercase a-z, 0-9, hyphens, 1-64 chars)
        name: String,
        /// Ethereum private key (hex, 0x-prefixed). Reads ETH_PRIVATE_KEY env var.
        #[arg(long, env = "ETH_PRIVATE_KEY")]
        private_key: String,
        /// RPC URL (default: Base Sepolia)
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        /// Name registry contract address
        #[arg(long, env = "GITLAWB_CONTRACT_NAME_REGISTRY", default_value = DEFAULT_NAME_REGISTRY)]
        contract: String,
        /// gitlawb identity directory (reads your DID)
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Resolve name → owner address + DID
    Resolve {
        name: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        #[arg(long, env = "GITLAWB_CONTRACT_NAME_REGISTRY", default_value = DEFAULT_NAME_REGISTRY)]
        contract: String,
    },

    /// Reverse lookup: DID → registered name
    Lookup {
        did: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        #[arg(long, env = "GITLAWB_CONTRACT_NAME_REGISTRY", default_value = DEFAULT_NAME_REGISTRY)]
        contract: String,
    },

    /// Check whether a name is available to register
    Available {
        name: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        #[arg(long, env = "GITLAWB_CONTRACT_NAME_REGISTRY", default_value = DEFAULT_NAME_REGISTRY)]
        contract: String,
    },

    /// Anchor your DID document in the on-chain DID registry
    RegisterDid {
        #[arg(long, env = "ETH_PRIVATE_KEY")]
        private_key: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        #[arg(long, env = "GITLAWB_CONTRACT_DID_REGISTRY", default_value = DEFAULT_DID_REGISTRY)]
        contract: String,
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Resolve a DID from the on-chain DID registry
    ResolveDid {
        did: String,
        #[arg(long, env = "GITLAWB_CHAIN_RPC_URL", default_value = DEFAULT_RPC_URL)]
        rpc_url: String,
        #[arg(long, env = "GITLAWB_CONTRACT_DID_REGISTRY", default_value = DEFAULT_DID_REGISTRY)]
        contract: String,
    },
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub async fn run(args: NameArgs) -> Result<()> {
    match args.cmd {
        NameCmd::Register {
            name,
            private_key,
            rpc_url,
            contract,
            dir,
        } => cmd_register(name, private_key, rpc_url, contract, dir).await,
        NameCmd::Resolve {
            name,
            rpc_url,
            contract,
        } => cmd_resolve(name, rpc_url, contract).await,
        NameCmd::Lookup {
            did,
            rpc_url,
            contract,
        } => cmd_lookup(did, rpc_url, contract).await,
        NameCmd::Available {
            name,
            rpc_url,
            contract,
        } => cmd_available(name, rpc_url, contract).await,
        NameCmd::RegisterDid {
            private_key,
            rpc_url,
            contract,
            dir,
        } => cmd_register_did(private_key, rpc_url, contract, dir).await,
        NameCmd::ResolveDid {
            did,
            rpc_url,
            contract,
        } => cmd_resolve_did(did, rpc_url, contract).await,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn identity_dir(dir: Option<PathBuf>) -> PathBuf {
    dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gitlawb")
    })
}

fn load_did(dir: Option<PathBuf>) -> Result<String> {
    let path = identity_dir(dir).join("identity.pem");
    let pem = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "No identity at {} — run `gl identity new` first",
            path.display()
        )
    })?;
    let keypair =
        gitlawb_core::identity::Keypair::from_pem(&pem).context("Failed to parse identity PEM")?;
    Ok(keypair.did().to_string())
}

fn load_did_and_document(dir: Option<PathBuf>) -> Result<(String, String)> {
    let path = identity_dir(dir).join("identity.pem");
    let pem = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "No identity at {} — run `gl identity new` first",
            path.display()
        )
    })?;
    let keypair =
        gitlawb_core::identity::Keypair::from_pem(&pem).context("Failed to parse identity PEM")?;
    let did = keypair.did();
    let vk = keypair.verifying_key();
    let doc = gitlawb_core::did::DidDocument::new(did.clone(), &vk);
    let doc_json = serde_json::to_string(&doc)?;
    Ok((did.to_string(), doc_json))
}

fn explorer_tx_url(rpc_url: &str, tx_hash: &str) -> String {
    if rpc_url.contains("sepolia") {
        format!("https://sepolia.basescan.org/tx/{tx_hash}")
    } else {
        format!("https://basescan.org/tx/{tx_hash}")
    }
}

fn build_write_provider(
    private_key: &str,
    rpc_url: &str,
) -> Result<impl alloy::providers::Provider + Clone> {
    let signer: PrivateKeySigner = private_key
        .trim()
        .parse()
        .context("Invalid Ethereum private key (expected 0x-prefixed hex)")?;
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse().context("Invalid RPC URL")?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
    Ok(provider)
}

fn build_read_provider(rpc_url: &str) -> Result<impl alloy::providers::Provider + Clone> {
    let url: reqwest::Url = rpc_url.parse().context("Invalid RPC URL")?;
    Ok(ProviderBuilder::new().connect_http(url))
}

// ── Commands ──────────────────────────────────────────────────────────────────

async fn cmd_register(
    name: String,
    private_key: String,
    rpc_url: String,
    contract: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let did = load_did(dir)?;

    println!("Registering name on Base L2...");
    println!("  Name:     {name}");
    println!("  DID:      {did}");
    println!("  Network:  {rpc_url}");
    println!("  Contract: {contract}");
    println!();

    let provider = build_write_provider(&private_key, &rpc_url)?;
    let addr: Address = contract.parse().context("Invalid contract address")?;
    let registry = GitlawbNameRegistry::new(addr, provider);

    let pending = registry
        .register(name.clone(), did.clone())
        .send()
        .await
        .context("Transaction failed — name may already be taken or invalid")?;

    let tx_hash = pending.tx_hash().to_string();
    println!("Transaction submitted: {tx_hash}");
    println!("Waiting for confirmation...");

    let receipt = pending
        .get_receipt()
        .await
        .context("Failed to get transaction receipt")?;

    if receipt.status() {
        println!();
        println!("✓ '{}' is yours on Base L2", name);
        println!("  DID:   {did}");
        println!("  Block: {}", receipt.block_number.unwrap_or_default());
        println!("  Tx:    {tx_hash}");
        println!("  View:  {}", explorer_tx_url(&rpc_url, &tx_hash));
    } else {
        anyhow::bail!("Transaction reverted — name may be taken or invalid");
    }

    Ok(())
}

async fn cmd_resolve(name: String, rpc_url: String, contract: String) -> Result<()> {
    let provider = build_read_provider(&rpc_url)?;
    let addr: Address = contract.parse().context("Invalid contract address")?;
    let registry = GitlawbNameRegistry::new(addr, provider);

    let result = registry
        .resolve(name.clone())
        .call()
        .await
        .context("eth_call failed")?;

    if result.owner == Address::ZERO {
        println!("Name '{}' is not registered.", name);
    } else {
        println!("Name:         {name}");
        println!("Owner:        {}", result.owner);
        println!("DID:          {}", result.did);
        println!("Registered:   {}", result.registeredAt);
        println!("Updated:      {}", result.updatedAt);
    }

    Ok(())
}

async fn cmd_lookup(did: String, rpc_url: String, contract: String) -> Result<()> {
    let provider = build_read_provider(&rpc_url)?;
    let addr: Address = contract.parse().context("Invalid contract address")?;
    let registry = GitlawbNameRegistry::new(addr, provider);

    let name = registry
        .reverseLookup(did.clone())
        .call()
        .await
        .context("eth_call failed")?;

    if name.is_empty() {
        println!("No name registered for DID: {did}");
    } else {
        println!("DID:  {did}");
        println!("Name: {name}");
    }

    Ok(())
}

async fn cmd_available(name: String, rpc_url: String, contract: String) -> Result<()> {
    let provider = build_read_provider(&rpc_url)?;
    let addr: Address = contract.parse().context("Invalid contract address")?;
    let registry = GitlawbNameRegistry::new(addr, provider);

    let available = registry
        .isAvailable(name.clone())
        .call()
        .await
        .context("eth_call failed")?;

    if available {
        println!("✓ '{}' is available", name);
    } else {
        println!("✗ '{}' is already taken", name);
    }

    Ok(())
}

async fn cmd_register_did(
    private_key: String,
    rpc_url: String,
    contract: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let (did, document) = load_did_and_document(dir)?;

    println!("Anchoring DID on Base L2...");
    println!("  DID:      {did}");
    println!("  Network:  {rpc_url}");
    println!("  Contract: {contract}");
    println!();

    let provider = build_write_provider(&private_key, &rpc_url)?;
    let addr: Address = contract.parse().context("Invalid contract address")?;
    let registry = GitlawbDIDRegistry::new(addr, provider);

    let pending = registry
        .register(did.clone(), document)
        .send()
        .await
        .context("Transaction failed — DID may already be registered")?;

    let tx_hash = pending.tx_hash().to_string();
    println!("Transaction submitted: {tx_hash}");
    println!("Waiting for confirmation...");

    let receipt = pending
        .get_receipt()
        .await
        .context("Failed to get transaction receipt")?;

    if receipt.status() {
        println!();
        println!("✓ DID anchored on Base L2");
        println!("  DID:   {did}");
        println!("  Block: {}", receipt.block_number.unwrap_or_default());
        println!("  Tx:    {tx_hash}");
        println!("  View:  {}", explorer_tx_url(&rpc_url, &tx_hash));
    } else {
        anyhow::bail!("Transaction reverted — DID may already be registered");
    }

    Ok(())
}

async fn cmd_resolve_did(did: String, rpc_url: String, contract: String) -> Result<()> {
    let provider = build_read_provider(&rpc_url)?;
    let addr: Address = contract.parse().context("Invalid contract address")?;
    let registry = GitlawbDIDRegistry::new(addr, provider);

    let result = registry
        .resolve(did.clone())
        .call()
        .await
        .context("eth_call failed")?;

    if result.owner == Address::ZERO {
        println!("DID '{}' is not registered on-chain.", did);
    } else {
        println!("DID:      {did}");
        println!("Owner:    {}", result.owner);
        println!("Document: {}", result.document);
    }

    Ok(())
}
