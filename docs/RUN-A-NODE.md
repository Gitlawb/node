# Running a gitlawb node

Step-by-step guide to staking $GITLAWB, registering your node on-chain, and earning protocol fees as a PoS operator.

---

## Prerequisites

- A wallet with at least **10,000 $GITLAWB** (minimum stake) plus a small amount of ETH on Base for gas
- Docker or Rust 1.91+ (for running the node process)
- A public HTTP URL (your-host.com) — can be a VPS, Fly.io app, or anything reachable. A Fly.io config is provided at `infra/fly/fly.toml` (deploy from the repo root with `fly deploy -c infra/fly/fly.toml`)

---

## 1. Install the CLI

```bash
curl -fsSL https://gitlawb.com/install.sh | sh
# or build from source:
cargo install --path crates/gl
```

## 2. Create a gitlawb identity

Every node is identified by an Ed25519 DID keypair:

```bash
gl identity new
gl identity show
# → did:key:z6Mk...
```

This is your **node DID** — it's distinct from your Ethereum wallet.

## 3. Register your node on-chain

This stakes $GITLAWB and links your node DID to your operator wallet:

```bash
export GITLAWB_OPERATOR_PRIVATE_KEY=0xYOUR_KEY
export GITLAWB_TOKEN=0x5F980Dcfc4c0fa3911554cf5ab288ed0eb13DBa3
export GITLAWB_CONTRACT_NODE_STAKING=0xNODE_STAKING_ADDR
export GITLAWB_CHAIN_RPC_URL=https://mainnet.base.org

gl node register \
  --stake 10000 \
  --http-url https://my-node.example.com
```

What this does:
1. Checks your $GITLAWB balance
2. Calls `token.approve(NodeStaking, 10000e18)` if needed
3. Calls `NodeStaking.registerNode(didHash, httpUrl, 10000e18)`
4. Transfers 10,000 $GITLAWB into escrow

## 4. Run the node

### Option A — Docker

```bash
docker run -d \
  --name gitlawb-node \
  -p 7545:7545 \
  -p 7546:7546/udp \
  -v gitlawb-data:/data \
  -e DATABASE_URL=postgresql://user:pass@host/gitlawb \
  -e GITLAWB_PUBLIC_URL=https://my-node.example.com \
  -e GITLAWB_OPERATOR_PRIVATE_KEY=$GITLAWB_OPERATOR_PRIVATE_KEY \
  -e GITLAWB_CONTRACT_NODE_STAKING=$GITLAWB_CONTRACT_NODE_STAKING \
  -e GITLAWB_CHAIN_RPC_URL=$GITLAWB_CHAIN_RPC_URL \
  -e GITLAWB_OPERATOR_STRICT_MODE=true \
  ghcr.io/gitlawb/node:latest
```

### Option B — docker-compose

See [`docker-compose.yml`](../docker-compose.yml) — bundles node + Postgres.

### Option C — From source

```bash
cargo run -p gitlawb-node --release
```

Required env for on-chain PoS mode:
- `GITLAWB_CONTRACT_NODE_STAKING` — contract address
- `GITLAWB_OPERATOR_PRIVATE_KEY` — key that posts heartbeats
- `GITLAWB_CHAIN_RPC_URL` — Base RPC URL (default Sepolia)

Optional:
- `GITLAWB_OPERATOR_STRICT_MODE=true` — refuse to start if not registered or not currently active
- `GITLAWB_HEARTBEAT_INTERVAL_HOURS=20` — how often to post heartbeats (must be < 24)

## 5. Verify

```bash
gl node onchain-status
```

Expected output:
```
On-chain status for did:key:z6Mk...

  Operator wallet:  0x...
  Staked:           10000 $GITLAWB
  HTTP URL:         https://my-node.example.com
  Last heartbeat:   1760000000 (unix)
  Active flag:      true
  Currently active: true
  Pending rewards:  0 $GITLAWB
```

Check your node logs — you should see `operator heartbeat loop starting` and a heartbeat tx within a few seconds of startup.

## 6. Earn rewards

The node's heartbeat loop runs every 20 hours. As long as you stay active:
- Every Sunday, the `FeeDistributor` distributes accumulated fees.
- 75% of the weekly pot is split across all active nodes (pro-rata by stake).
- Your share accrues as `pendingRewards` on-chain — claim anytime without unstaking.

```bash
gl node claim
```

## 7. Unstake (if you want out)

7-day cooldown, two steps:

```bash
# Step 1: request unstake (starts 7-day timer)
gl node unstake-request

# ... wait 7 days ...

# Step 2: complete — returns stake + any pending rewards
gl node unstake
```

During the cooldown your node still earns rewards if it keeps heartbeating.

---

## Operational checklist

| Concern | Recommendation |
|---|---|
| Heartbeat gas | ~$0.03/month on Base L2 — negligible |
| Missed heartbeats | After 3 days without one, you're excluded from rewards until you beat again |
| Operator key | Dedicated wallet, small ETH balance, not your main treasury |
| Monitoring | Watch `lastHeartbeat` on-chain; alert if > 22h since last beat |
| Public URL | Must resolve and serve `/health` — peers will ping it |

---

## Troubleshooting

**"insufficient $GITLAWB balance"** — fund the operator wallet with at least 10,000 $GITLAWB.

**Node refuses to start with "strict-mode operator check failed"** — either `gl node register` first, or unset `GITLAWB_OPERATOR_STRICT_MODE`.

**Rewards are 0 after a week** — run `gl node onchain-status`. If `currentlyActive: false`, check your heartbeat loop (node logs for `operator heartbeat sent`).

**Want to rotate operator wallet** — requires unstake → re-register with new wallet. No in-place rotation in v1.

---

See [ECONOMICS.md](./ECONOMICS.md) for the full reward math.
