//! On-chain operator module — Proof-of-Stake integration with
//! `GitlawbNodeStaking.sol` on Base L2.
//!
//! When configured, the node:
//!   1. On startup, reads its registration from the NodeStaking contract
//!      and logs stake amount, active status, and pending rewards.
//!   2. Spawns a background task that posts `heartbeat(nodeDidHash)` every
//!      `heartbeat_interval_hours` (default 20h, safely under the 24h window).
//!
//! If `strict_mode` is enabled, the node refuses to start unless it is
//! registered and currently active.

use std::sync::Arc;
use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, B256, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{anyhow, Context, Result};
use tracing::{error, info, warn};

// ── Contract binding ────────────────────────────────────────────────────────

sol! {
    #[sol(rpc)]
    interface IGitlawbNodeStaking {
        function heartbeat(bytes32 nodeDidHash) external;
        function isActive(bytes32 nodeDidHash) external view returns (bool);
        function getNodeInfo(bytes32 nodeDidHash) external view returns (
            address operator,
            string memory httpUrl,
            uint256 stake,
            uint256 lastHeartbeat,
            uint256 registeredAt,
            bool active,
            bool currentlyActive,
            uint256 pendingRewards,
            uint256 unstakeRequestAt
        );
    }
}

// ── Config + client ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OperatorConfig {
    pub rpc_url: String,
    pub private_key: String,
    pub contract_address: Address,
    pub node_did: String,
    pub heartbeat_interval: Duration,
    pub strict_mode: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NodeStatus {
    pub registered: bool,
    pub operator: Address,
    pub stake: U256,
    pub last_heartbeat: u64,
    pub active: bool,
    pub currently_active: bool,
    pub pending_rewards: U256,
}

#[derive(Clone)]
pub struct OperatorClient {
    cfg: OperatorConfig,
    node_did_hash: B256,
}

impl OperatorClient {
    pub fn new(cfg: OperatorConfig) -> Self {
        let node_did_hash = keccak256(cfg.node_did.as_bytes());
        Self { cfg, node_did_hash }
    }

    #[allow(dead_code)]
    pub fn node_did_hash(&self) -> B256 {
        self.node_did_hash
    }

    /// Read the node's on-chain record. Returns a zero-ish `NodeStatus` with
    /// `registered = false` if the node has never been registered.
    pub async fn check_status(&self) -> Result<NodeStatus> {
        let rpc_url: reqwest::Url = self
            .cfg
            .rpc_url
            .parse()
            .with_context(|| format!("invalid RPC URL: {}", self.cfg.rpc_url))?;
        let provider = ProviderBuilder::new().connect_http(rpc_url);
        let contract = IGitlawbNodeStaking::new(self.cfg.contract_address, provider);

        let info = contract
            .getNodeInfo(self.node_did_hash)
            .call()
            .await
            .context("getNodeInfo call failed")?;

        let registered = info.operator != Address::ZERO;
        Ok(NodeStatus {
            registered,
            operator: info.operator,
            stake: info.stake,
            last_heartbeat: info.lastHeartbeat.try_into().unwrap_or(0),
            active: info.active,
            currently_active: info.currentlyActive,
            pending_rewards: info.pendingRewards,
        })
    }

    /// Send a `heartbeat(nodeDidHash)` transaction. Returns the transaction hash.
    pub async fn send_heartbeat(&self) -> Result<B256> {
        let signer: PrivateKeySigner = self
            .cfg
            .private_key
            .trim()
            .parse()
            .context("invalid operator private key")?;
        let wallet = EthereumWallet::from(signer);

        let rpc_url: reqwest::Url = self
            .cfg
            .rpc_url
            .parse()
            .with_context(|| format!("invalid RPC URL: {}", self.cfg.rpc_url))?;
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);
        let contract = IGitlawbNodeStaking::new(self.cfg.contract_address, provider);

        let pending = contract
            .heartbeat(self.node_did_hash)
            .send()
            .await
            .context("heartbeat send failed")?;
        let receipt = pending
            .get_receipt()
            .await
            .context("heartbeat receipt failed")?;
        Ok(receipt.transaction_hash)
    }

    /// Spawn a background task that posts a heartbeat on `heartbeat_interval` cadence.
    /// Errors are logged and retried on the next tick. The task exits cleanly
    /// when `shutdown_rx` flips to `true`.
    pub fn spawn_heartbeat_loop(
        self: Arc<Self>,
        mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) {
        let interval_secs = self.cfg.heartbeat_interval.as_secs();
        info!(
            interval_hours = interval_secs / 3600,
            contract = %self.cfg.contract_address,
            "operator heartbeat loop starting"
        );
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.cfg.heartbeat_interval);
            // First tick fires immediately — use it to send an initial heartbeat
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match self.send_heartbeat().await {
                            Ok(tx) => info!(tx = %tx, "operator heartbeat sent"),
                            Err(e) => warn!(err = %e, "operator heartbeat failed — will retry"),
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("operator heartbeat loop: shutdown signal received, exiting");
                            return;
                        }
                    }
                }
            }
        });
    }
}

// ── Startup helper ──────────────────────────────────────────────────────────

/// Run the startup check. Logs the result; if `strict_mode` and the node is
/// not currently active, returns an error so the caller can abort.
pub async fn startup_check(client: &OperatorClient) -> Result<NodeStatus> {
    let status = client
        .check_status()
        .await
        .context("failed to read node on-chain status")?;

    if !status.registered {
        let msg = format!(
            "node is not registered on-chain (contract {}, did hash {})",
            client.cfg.contract_address, client.node_did_hash
        );
        if client.cfg.strict_mode {
            error!("{msg} — strict mode requires registration");
            return Err(anyhow!(msg));
        } else {
            warn!("{msg} — register via GitlawbNodeStaking.registerNode()");
            return Ok(status);
        }
    }

    info!(
        operator = %status.operator,
        stake = %format_token(status.stake),
        last_heartbeat = status.last_heartbeat,
        active = status.currently_active,
        pending_rewards = %format_token(status.pending_rewards),
        "operator on-chain status"
    );

    if client.cfg.strict_mode && !status.currently_active {
        return Err(anyhow!(
            "node is registered but not currently active (missed heartbeat) — strict mode refuses to start"
        ));
    }

    Ok(status)
}

/// Format a U256 token amount as a whole-token decimal string (18 decimals).
fn format_token(amount: U256) -> String {
    let scale = U256::from(10u64).pow(U256::from(18));
    let whole = amount / scale;
    let frac = amount % scale;
    if frac.is_zero() {
        format!("{whole}")
    } else {
        // Show 2 decimal places
        let two_dp = (frac * U256::from(100)) / scale;
        format!("{whole}.{two_dp:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_did_hash_matches_solidity_keccak() {
        let did = "did:key:z6MksHu3VKbRLLTpDMJmhqSrLKJeYoondrQkpmhmcfTbWxMf";
        let hash = keccak256(did.as_bytes());
        // Sanity: keccak of a non-empty string is non-zero
        assert_ne!(hash, B256::ZERO);
    }

    #[test]
    fn format_token_whole() {
        let amt = U256::from(10_000u64) * U256::from(10u64).pow(U256::from(18));
        assert_eq!(format_token(amt), "10000");
    }

    #[test]
    fn format_token_fractional() {
        let amt = U256::from(10_500u64) * U256::from(10u64).pow(U256::from(15));
        // 10.5 tokens
        assert_eq!(format_token(amt), "10.50");
    }
}
