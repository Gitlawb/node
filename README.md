# Gitlawb Node

**Decentralized git infrastructure for developers, AI agents, and app delivery.**

Gitlawb Node is the open-source node software behind the Gitlawb network. It lets anyone run a self-hosted node, publish repositories under a DID, sign writes with Ed25519 HTTP signatures, replicate git activity across peers, and move toward a resilient app-delivery network where code and build assets can be served closer to users.

Gitlawb is not trying to be only “another git host.” The long-term direction is:

```txt
Decentralized GitHub
+ signed agent-native workflows
+ resilient repo replication
+ CDN-style app/code delivery
```

The mission is simple: once code is pushed to the network, it should not disappear because one server went down.

---

## What is in this repository?

This is a Rust workspace with four crates:

| Crate | Purpose |
|---|---|
| `gitlawb-node` | The node daemon: Axum HTTP server, git smart-HTTP, Postgres metadata, libp2p gossip, optional S3/Tigris/IPFS/Arweave/Base PoS hooks. |
| `gl` | The Gitlawb CLI for identity, repos, issues, PRs, bounties, tasks, peers, node status, MCP, and setup flows. |
| `git-remote-gitlawb` | Git remote helper for `gitlawb://` URLs, so normal `git clone`, `git fetch`, and `git push` can talk to Gitlawb nodes. |
| `gitlawb-core` | Shared primitives: Ed25519 identities, `did:key`, CIDs, RFC 9421 HTTP signatures, certificates, and UCAN tokens. |

---

## Why Gitlawb Nodes?

Most git hosting today depends on a small number of centralized platforms. Gitlawb Nodes are designed for a different model:

- **Own your identity** — every user, agent, and node is an Ed25519 keypair represented as `did:key:z6Mk...`.
- **Signed writes by default** — write requests use RFC 9421 HTTP Signatures instead of passwords.
- **Git-native transport** — repositories are still real git repositories served over smart HTTP.
- **Agent-native workflows** — the `gl` CLI and MCP server expose repo, issue, task, PR, and UCAN flows to AI agents.
- **Peer-aware delivery** — nodes can announce, discover, gossip, and sync with each other.
- **App CDN direction** — the network can evolve from decentralized code storage into code + asset + app delivery.

---

## Current status

Gitlawb Node is live early infrastructure. It is useful today, but some security and reliability features are intentionally staged for compatibility with existing nodes.

Good today:

- Local or Docker node startup.
- Postgres-backed repo metadata.
- Bare git repository storage.
- Git smart-HTTP clone/fetch/push.
- RFC 9421-signed writes.
- DID identities.
- `gl` CLI workflows.
- libp2p peer discovery/gossip foundation.
- Optional Tigris/S3 storage.
- Optional IPFS/Pinata and Arweave/Irys hooks.
- Optional Base node-operator staking/heartbeat hooks.

Known limitations:

- Private repository read enforcement is not wired yet. Treat public nodes as public infrastructure unless you restrict access at your proxy/firewall.
- UCAN chain validation and revocation are not complete.
- Repository write authorization is not capability-complete yet; HTTP signatures prove identity, not full authorization policy.
- Peer writes are signed by upgraded nodes, but strict signed-peer enforcement is opt-in during rolling upgrades.
- GraphQL mutations need mutation-aware auth before becoming a public write surface.

See:

- [`SECURITY.md`](SECURITY.md)
- [`docs/OSS-READINESS-AUDIT.md`](docs/OSS-READINESS-AUDIT.md)
- [`docs/MAINTAINER-ROADMAP.md`](docs/MAINTAINER-ROADMAP.md)

---

## Quickstart: run a local node

The fastest path is Docker Compose. It starts a node and Postgres.

```bash
git clone https://github.com/Gitlawb/node.git
cd node
cp .env.example .env
docker compose up -d
```

Your local node will serve:

| Service | Default |
|---|---|
| HTTP API + git smart-HTTP | `http://localhost:7545` |
| libp2p QUIC/UDP | `7546` |
| Postgres | compose-managed |

Verify:

```bash
curl http://localhost:7545/health
curl http://localhost:7545/api/v1/stats
```

Expected health response:

```json
{ "status": "ok" }
```

Stop it:

```bash
docker compose down
```

---

## Install the CLI

```bash
# npm (macOS / Linux)
npm install -g @gitlawb/gl

# Homebrew (macOS / Linux)
brew install gitlawb/tap/gl

# curl (macOS / Linux)
curl -fsSL https://gitlawb.com/install.sh | sh

# PowerShell (Windows)
irm https://gitlawb.com/install.ps1 | iex
```

Or build from source:

```bash
cargo build --release -p gl -p git-remote-gitlawb -p gitlawb-node
```

Put these binaries on your `PATH`:

```txt
target/release/gl
target/release/git-remote-gitlawb
target/release/gitlawb-node
```

Check your setup:

```bash
gl doctor
```

---

## First repo flow

Create an identity:

```bash
gl identity new
gl identity show
```

Register against your local node:

```bash
gl register --node http://localhost:7545
```

Create a repo:

```bash
gl repo create my-repo --description "My first Gitlawb repo" --node http://localhost:7545
```

Use the git remote helper:

```bash
export GITLAWB_NODE=http://localhost:7545
git clone gitlawb://did:key:z6Mk.../my-repo
```

For public-network use, make sure `GITLAWB_NODE` points to the node you want. The helper defaults to localhost for local development.

### Full lifecycle against an iCaptcha-enforcing node

Public nodes (e.g. `node.gitlawb.com`) require two things on writes:

1. **RFC 9421 HTTP Signatures** — every write is signed by your identity key. `gl`
   and the `git-remote-gitlawb` helper do this automatically. An old/unsigned CLI
   fails with `401 not_an_agent`; `gl` will tell you to upgrade and register.
2. **An iCaptcha proof** on the spam-gated writes (**repo create, fork, register**).
   `gl` solves this for you: on the node's `403 icaptcha_proof_required` it reads the
   `x-icaptcha-url` / `x-icaptcha-level` hints, requests a challenge, solves it
   locally (arithmetic / algebra / sequence), and **retries the same signed request**
   with the `x-icaptcha-proof` header — no manual steps, no env vars.

```bash
gl identity new                                   # create did:key identity
gl register      --node https://node.gitlawb.com  # signed + auto-solves iCaptcha
gl repo create memlawb --node https://node.gitlawb.com   # signed + auto-solves iCaptcha
git push  origin2 main                            # origin2 = gitlawb://<your-did>/memlawb (signed)
git clone gitlawb://<your-did>/memlawb            # public read, no proof needed
gl doctor                                         # preflight: identity, node, version, iCaptcha
```

Notes:

- **`requesterId` is always your DID.** The proof's `sub` claim must equal the
  authenticated signer; `gl`/helper set this automatically and the node enforces
  `sub == authenticated DID` (so a proof minted for another identity is rejected).
- **Proofs are short-lived (~5 min TTL) and single-use.** If one expires between
  solving and use, the client transparently solves a fresh one and retries.
- **What needs what:** create / fork / register are signed **and** iCaptcha-gated;
  `git push` is **signed-only** (owner signature is the gate — no per-push challenge);
  reads (clone / fetch / `repo info`) need no proof. A non-existent repo returns a
  clear `404`, never a placeholder.
- **API-key iCaptcha deployments:** set `GITLAWB_ICAPTCHA_URL` to your iCaptcha
  origin and `GITLAWB_ICAPTCHA_API_KEY` to its key. The client only talks to an
  `https` origin whose host is allowlisted (that URL or the public default), and
  sends the bearer token **only** to your configured origin — never to a URL a
  node advertises — so a hostile node can't capture the key or redirect the solve.

---

## Architecture

```txt
┌──────────────────────────┐
│ gl CLI / git / AI agents │
└────────────┬─────────────┘
             │ signed HTTP writes / git smart-HTTP
             ↓
┌──────────────────────────┐
│ gitlawb-node             │
│ Axum API + git routes    │
└────────────┬─────────────┘
             │
    ┌────────┴────────┐
    ↓                 ↓
Postgres        Bare git repos
metadata        local disk / optional S3
    │                 │
    └────────┬────────┘
             ↓
       libp2p peers
  gossip + discovery + sync
             ↓
 optional IPFS / Arweave / Base PoS
```

### Core concepts

| Concept | Meaning |
|---|---|
| DID | A user, agent, or node identity derived from an Ed25519 public key. |
| HTTP Signature | RFC 9421 signature proving control of the DID key for write requests. |
| Ref certificate | Signed record of a ref update. Useful for audit and replication. |
| UCAN | Delegation token for future capability-based workflows. |
| Peer announce | Node-to-node HTTP announcement of DID + public URL. |
| Gossipsub | libp2p topic for ref-update events. |
| Smart HTTP | Standard git protocol over HTTP for clone/fetch/push. |

---

## API surface

The node exposes both git smart-HTTP routes and JSON APIs.

Common public read routes:

```txt
GET /health
GET /
GET /api/v1/stats
GET /api/v1/contracts
GET /api/v1/repos
GET /api/v1/repos/{owner}/{repo}
GET /api/v1/repos/{owner}/{repo}/tree
GET /api/v1/repos/{owner}/{repo}/blob/{path}
GET /api/v1/repos/{owner}/{repo}/issues
GET /api/v1/repos/{owner}/{repo}/pulls
GET /api/v1/peers
GET /{owner}/{repo}/info/refs
POST /{owner}/{repo}/git-upload-pack
```

Signed write routes include:

```txt
POST /api/v1/repos
POST /api/register
POST /api/v1/repos/{owner}/{repo}/fork
POST /api/v1/repos/{owner}/{repo}/issues
POST /api/v1/repos/{owner}/{repo}/pulls
POST /api/v1/repos/{owner}/{repo}/pulls/{number}/merge
POST /api/v1/repos/{owner}/{repo}/hooks
POST /api/v1/bounties/{id}/...
POST /{owner}/{repo}/git-receive-pack
```

These peer write routes support staged rollout:

```txt
POST /api/v1/peers/announce
POST /api/v1/sync/notify
```

When `GITLAWB_REQUIRE_SIGNED_PEER_WRITES=false`, unsigned legacy peers are accepted on those two routes, but signed requests are verified when signature headers are present. Once all live peers upgrade, operators can set:

```bash
GITLAWB_REQUIRE_SIGNED_PEER_WRITES=true
```

`POST /api/v1/sync/trigger` is not part of the staged rollout: it always requires a signature in both config modes and returns 401 without one, because each call drives an O(peers) outbound fan-out.

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full reference.

Minimum required for a persistent node:

```env
DATABASE_URL=postgresql://gitlawb:changeme@localhost:5432/gitlawb
```

Important node settings:

| Variable | Purpose |
|---|---|
| `GITLAWB_HOST` / `GITLAWB_PORT` | HTTP bind address and port. |
| `GITLAWB_REPOS_DIR` | Local bare repo storage directory. |
| `GITLAWB_PUBLIC_URL` | Public HTTP URL announced to peers. |
| `GITLAWB_P2P_PORT` | libp2p QUIC/UDP port. Use `0` to disable. |
| `GITLAWB_BOOTSTRAP_PEERS` | Comma-separated HTTP peer URLs. |
| `GITLAWB_P2P_BOOTSTRAP` | Comma-separated libp2p multiaddrs. |
| `GITLAWB_BOOTSTRAP_DISABLE_SEEDS` | Disable embedded seed peers for isolated dev/test networks. |
| `GITLAWB_REQUIRE_SIGNED_PEER_WRITES` | Require signed peer announce/sync writes. |
| `GITLAWB_AUTO_SYNC` | Enable automatic sync from known peers. |
| `GITLAWB_MAX_PACK_BYTES` | Max git pack body size for smart-HTTP routes. |
| `GITLAWB_GIT_SERVICE_TIMEOUT_SECS` | Max seconds a served git upload-pack, receive-pack, or `info/refs` advertisement may run before it is aborted (504). Default 600. Also bounds the withheld-blob classification walk (on both the upload-pack serve and receive-pack replication paths) and the push-side pin-candidate discovery (`rev-list` / `cat-file`), each reaped via process-group teardown at the deadline. |
| `GITLAWB_GIT_ACQUIRE_TIMEOUT_SECS` | Max seconds the storage-acquisition phase (Tigris HEAD/GET, push advisory-lock) of a served git op may run before the request is shed with a 503, separate from the git-run timeout. The concurrency permit is released on expiry so a stalled backend cannot pin the pool. Default 30. |
| `GITLAWB_MAX_CONCURRENT_IPFS_WALKS` | Max concurrent `GET /ipfs/{cid}` visibility walks across all callers (own pool, disjoint from the served-git pools); over-cap sheds 503. Default 32. |
| `GITLAWB_IPFS_WALK_PER_SOURCE` | Max concurrent `/ipfs` walks a single source IP may hold. Default 4. |
| `GITLAWB_IPFS_MAX_REPOS_WALKED` | Max repos walked per `/ipfs/{cid}` request, bounding one request's fan-out. Default 64. |
| `GITLAWB_IPFS_RATE_LIMIT` | Max `/ipfs/{cid}` requests per client IP per hour (route flood brake). 0 disables. Default 600. |
| `GITLAWB_TIGRIS_BUCKET` | Optional S3/Tigris shared repo storage bucket. |
| `GITLAWB_PINATA_JWT` | Optional Pinata/IPFS warm-storage pinning. |
| `GITLAWB_IRYS_URL` | Optional Irys/Arweave permanent anchoring. |

Production note: change the default Postgres password before exposing a node publicly.

---

## Optional node staking

Gitlawb Node includes optional Base L2 node-operator hooks. Operators can register a node DID, stake `$GITLAWB`, and post heartbeats.

PoS is disabled unless these are configured:

```env
GITLAWB_CONTRACT_NODE_STAKING=0x...
GITLAWB_OPERATOR_PRIVATE_KEY=0x...
GITLAWB_CHAIN_RPC_URL=https://mainnet.base.org
```

Recommended for operators:

```env
GITLAWB_OPERATOR_STRICT_MODE=true
GITLAWB_HEARTBEAT_INTERVAL_HOURS=20
```

Read:

- [`docs/RUN-A-NODE.md`](docs/RUN-A-NODE.md)
- [`docs/ECONOMICS.md`](docs/ECONOMICS.md)

Use a dedicated low-balance operator wallet. Do not use a treasury wallet as the heartbeat key.

---

## Building from source

Requires Rust 1.91+.

```bash
cargo build --release -p gitlawb-node -p gl -p git-remote-gitlawb
```

Run tests:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run the node from source:

```bash
DATABASE_URL=postgresql://gitlawb:changeme@localhost:5432/gitlawb \
  cargo run -p gitlawb-node --release
```

---

## macOS menu bar app

A native Swift/AppKit menu bar app is included for managing a local Docker Compose stack without living in the terminal.

Requirements:

- macOS 26+
- Xcode Command Line Tools
- Docker Desktop, OrbStack, or Colima

Build:

```bash
./scripts/build-macos-app.sh
```

Output:

```txt
dist/Gitlawb Node.app
dist/Gitlawb Node.dmg
```

Features:

- Start/stop local node stack.
- Status indicator.
- Settings GUI.
- Auto-start on login.
- Docker runtime detection.

Unsigned local build:

```bash
xattr -cr "dist/Gitlawb Node.app"
```

---

## Roadmap

The current maintainer focus is live-network stability first.

Short-term priorities:

1. Keep CI green: fmt, clippy, tests, release build.
2. Add Docker and installer smoke tests.
3. Improve operator docs and `gl doctor` checks.
4. Harden peer writes and publish the signed-peer rollout plan.
5. Implement repo write authorization: owner checks, protected branches, and UCAN capability checks.
6. Implement private-read enforcement or remove private repo affordances until it exists.
7. Add metrics for pushes, fetches, pack sizes, peer sync, failed auth, and webhooks.

Product direction:

1. Reliable repo replication.
2. Health-aware peer syncing.
3. CDN-style clone/fetch routing to healthy replicas.
4. App asset/build delivery from nodes.
5. Operator dashboard and desktop UX.

Read the maintainer roadmap:

```txt
docs/MAINTAINER-ROADMAP.md
```

---

## Contributing

Start here:

- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`docs/MAINTAINER-ROADMAP.md`](docs/MAINTAINER-ROADMAP.md)
- [`docs/OSS-READINESS-AUDIT.md`](docs/OSS-READINESS-AUDIT.md)
- [`SECURITY.md`](SECURITY.md)

Good first contribution areas:

- docs and install polish
- Docker smoke tests
- CLI error messages
- `gl doctor` checks
- operator dashboard UX
- test coverage for peer sync and signed writes

Security issues should follow [`SECURITY.md`](SECURITY.md).

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual licensed as above, without any additional terms or conditions.
