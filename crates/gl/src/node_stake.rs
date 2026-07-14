//! `gl node` staking subcommands — on-chain PoS operations for node operators.
//!
//! Commands:
//!   gl node register --stake 10000   — stake $GITLAWB and register this node
//!   gl node heartbeat                — manually post a heartbeat (usually automatic)
//!   gl node onchain-status           — view stake, rewards, active flag
//!   gl node claim                    — claim accumulated rewards
//!   gl node unstake-request          — start 7-day cooldown
//!   gl node unstake                  — complete unstake after cooldown

use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result};
use std::path::PathBuf;

// ── Defaults ────────────────────────────────────────────────────────────────

const DEFAULT_RPC_URL: &str = "https://sepolia.base.org";

// ── ABI ─────────────────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    interface GitlawbNodeStaking {
        function registerNode(bytes32 nodeDidHash, string httpUrl, uint256 stakeAmount) external;
        function heartbeat(bytes32 nodeDidHash) external;
        function requestUnstake(bytes32 nodeDidHash) external;
        function unstake(bytes32 nodeDidHash) external;
        function claimRewards(bytes32 nodeDidHash) external;
        function getNodeInfo(bytes32 nodeDidHash) external view returns (
            address operator,
            string httpUrl,
            uint256 stake,
            uint256 lastHeartbeat,
            uint256 registeredAt,
            bool active,
            bool currentlyActive,
            uint256 pendingRewards,
            uint256 unstakeRequestAt
        );
    }

    #[sol(rpc)]
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub async fn cmd_register(
    stake: u64,
    http_url: String,
    private_key: String,
    token: String,
    contract: String,
    rpc_url: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let did = load_did(dir)?;
    let did_hash = keccak256(did.as_bytes());
    let stake_wei = tokens_to_wei(stake);

    let token_addr: Address = token.parse().context("invalid token address")?;
    let contract_addr: Address = contract.parse().context("invalid contract address")?;

    println!("Registering gitlawb node on Base L2...");
    println!("  DID:      {did}");
    println!("  Stake:    {stake} $GITLAWB");
    println!("  HTTP URL: {http_url}");
    println!("  Network:  {rpc_url}");
    println!();

    let signer: PrivateKeySigner = private_key.trim().parse().context("invalid private key")?;
    let operator_addr = signer.address();
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse().context("invalid RPC URL")?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);

    let token_c = IERC20::new(token_addr, provider.clone());
    let staking = GitlawbNodeStaking::new(contract_addr, provider);

    // 1. Check balance
    let bal = token_c
        .balanceOf(operator_addr)
        .call()
        .await
        .context("balanceOf failed")?;
    if bal < stake_wei {
        anyhow::bail!(
            "insufficient $GITLAWB balance: have {}, need {}",
            wei_to_tokens(bal),
            stake
        );
    }

    // 2. Approve if needed
    let allowance = token_c
        .allowance(operator_addr, contract_addr)
        .call()
        .await
        .context("allowance failed")?;
    if allowance < stake_wei {
        println!("Approving {stake} $GITLAWB for staking contract...");
        let approve_tx = token_c
            .approve(contract_addr, stake_wei)
            .send()
            .await
            .context("approve failed")?;
        let approve_receipt = approve_tx
            .get_receipt()
            .await
            .context("approve receipt failed")?;
        println!(
            "  approved: {}",
            explorer_tx_url(&rpc_url, &format!("{:?}", approve_receipt.transaction_hash))
        );
    }

    // 3. Register
    println!("Registering node (staking {stake} $GITLAWB)...");
    let register_tx = staking
        .registerNode(did_hash, http_url, stake_wei)
        .send()
        .await
        .context("registerNode failed")?;
    let receipt = register_tx
        .get_receipt()
        .await
        .context("registerNode receipt failed")?;

    println!();
    println!("✓ Node registered");
    println!(
        "  Tx: {}",
        explorer_tx_url(&rpc_url, &format!("{:?}", receipt.transaction_hash))
    );
    println!("  Operator wallet: {operator_addr}");
    println!();
    println!("Next: set these env vars on the node:");
    println!("  export GITLAWB_CONTRACT_NODE_STAKING={contract}");
    println!("  export GITLAWB_OPERATOR_PRIVATE_KEY=<your-key>");
    println!("  export GITLAWB_CHAIN_RPC_URL={rpc_url}");

    Ok(())
}

pub async fn cmd_heartbeat(
    private_key: String,
    contract: String,
    rpc_url: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let did = load_did(dir)?;
    let did_hash = keccak256(did.as_bytes());
    let contract_addr: Address = contract.parse().context("invalid contract address")?;

    let signer: PrivateKeySigner = private_key.trim().parse().context("invalid private key")?;
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse().context("invalid RPC URL")?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
    let staking = GitlawbNodeStaking::new(contract_addr, provider);

    println!("Posting heartbeat for {did}...");
    let tx = staking
        .heartbeat(did_hash)
        .send()
        .await
        .context("heartbeat failed")?;
    let receipt = tx.get_receipt().await.context("heartbeat receipt failed")?;
    println!(
        "✓ heartbeat sent: {}",
        explorer_tx_url(&rpc_url, &format!("{:?}", receipt.transaction_hash))
    );
    Ok(())
}

pub async fn cmd_onchain_status(
    contract: String,
    rpc_url: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let did = load_did(dir)?;
    let did_hash = keccak256(did.as_bytes());
    let contract_addr: Address = contract.parse().context("invalid contract address")?;

    let url: reqwest::Url = rpc_url.parse().context("invalid RPC URL")?;
    let provider = ProviderBuilder::new().connect_http(url);
    let staking = GitlawbNodeStaking::new(contract_addr, provider);

    let info = staking
        .getNodeInfo(did_hash)
        .call()
        .await
        .context("getNodeInfo failed")?;

    println!("On-chain status for {did}");
    println!();
    if info.operator == Address::ZERO {
        println!("  Status: NOT REGISTERED");
        println!("  Run `gl node register --stake <amount>` to register.");
        return Ok(());
    }

    println!("  Operator wallet:  {}", info.operator);
    println!("  Staked:           {} $GITLAWB", wei_to_tokens(info.stake));
    println!("  HTTP URL:         {}", info.httpUrl);
    println!("  Last heartbeat:   {} (unix)", info.lastHeartbeat);
    println!("  Registered:       {} (unix)", info.registeredAt);
    println!("  Active flag:      {}", info.active);
    println!("  Currently active: {}", info.currentlyActive);
    println!(
        "  Pending rewards:  {} $GITLAWB",
        wei_to_tokens(info.pendingRewards)
    );
    if info.unstakeRequestAt > U256::ZERO {
        println!(
            "  Unstake pending:  yes (requested at unix {})",
            info.unstakeRequestAt
        );
    }

    Ok(())
}

pub async fn cmd_claim(
    private_key: String,
    contract: String,
    rpc_url: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let did = load_did(dir)?;
    let did_hash = keccak256(did.as_bytes());
    let contract_addr: Address = contract.parse().context("invalid contract address")?;

    let signer: PrivateKeySigner = private_key.trim().parse().context("invalid private key")?;
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse().context("invalid RPC URL")?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
    let staking = GitlawbNodeStaking::new(contract_addr, provider);

    println!("Claiming rewards for {did}...");
    let tx = staking
        .claimRewards(did_hash)
        .send()
        .await
        .context("claimRewards failed")?;
    let receipt = tx.get_receipt().await.context("claim receipt failed")?;
    println!(
        "✓ rewards claimed: {}",
        explorer_tx_url(&rpc_url, &format!("{:?}", receipt.transaction_hash))
    );
    Ok(())
}

pub async fn cmd_unstake_request(
    private_key: String,
    contract: String,
    rpc_url: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let did = load_did(dir)?;
    let did_hash = keccak256(did.as_bytes());
    let contract_addr: Address = contract.parse().context("invalid contract address")?;

    let signer: PrivateKeySigner = private_key.trim().parse().context("invalid private key")?;
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse().context("invalid RPC URL")?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
    let staking = GitlawbNodeStaking::new(contract_addr, provider);

    println!("Requesting unstake (starts 7-day cooldown)...");
    let tx = staking
        .requestUnstake(did_hash)
        .send()
        .await
        .context("requestUnstake failed")?;
    let receipt = tx
        .get_receipt()
        .await
        .context("requestUnstake receipt failed")?;
    println!(
        "✓ unstake requested: {}",
        explorer_tx_url(&rpc_url, &format!("{:?}", receipt.transaction_hash))
    );
    println!("  Run `gl node unstake` after 7 days to complete withdrawal.");
    Ok(())
}

pub async fn cmd_unstake(
    private_key: String,
    contract: String,
    rpc_url: String,
    dir: Option<PathBuf>,
) -> Result<()> {
    let did = load_did(dir)?;
    let did_hash = keccak256(did.as_bytes());
    let contract_addr: Address = contract.parse().context("invalid contract address")?;

    let signer: PrivateKeySigner = private_key.trim().parse().context("invalid private key")?;
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse().context("invalid RPC URL")?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
    let staking = GitlawbNodeStaking::new(contract_addr, provider);

    println!("Completing unstake...");
    let tx = staking
        .unstake(did_hash)
        .send()
        .await
        .context("unstake failed")?;
    let receipt = tx.get_receipt().await.context("unstake receipt failed")?;
    println!(
        "✓ unstaked: {}",
        explorer_tx_url(&rpc_url, &format!("{:?}", receipt.transaction_hash))
    );
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn load_did(dir: Option<PathBuf>) -> Result<String> {
    let base = dir.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gitlawb")
    });
    let path = base.join("identity.pem");
    let pem = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "No identity at {} — run `gl identity new` first",
            path.display()
        )
    })?;
    let kp =
        gitlawb_core::identity::Keypair::from_pem(&pem).context("failed to parse identity PEM")?;
    Ok(kp.did().to_string())
}

fn tokens_to_wei(tokens: u64) -> U256 {
    U256::from(tokens) * U256::from(10u64).pow(U256::from(18))
}

fn wei_to_tokens(wei: U256) -> String {
    let scale = U256::from(10u64).pow(U256::from(18));
    let whole = wei / scale;
    let frac = wei % scale;
    if frac.is_zero() {
        whole.to_string()
    } else {
        let two_dp = (frac * U256::from(100)) / scale;
        format!("{whole}.{two_dp:02}")
    }
}

fn explorer_tx_url(rpc_url: &str, tx_hash: &str) -> String {
    if rpc_url.contains("sepolia") {
        format!("https://sepolia.basescan.org/tx/{tx_hash}")
    } else {
        format!("https://basescan.org/tx/{tx_hash}")
    }
}

pub fn default_rpc_url() -> &'static str {
    DEFAULT_RPC_URL
}
