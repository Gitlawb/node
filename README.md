# Gitlawb Node

**Decentralized git infrastructure for developers, AI agents, and app delivery.**

Gitlawb Node is the open-source node software behind the Gitlawb network. It lets anyone run a self-hosted node, publish repositories under a DID, sign writes with Ed25519 HTTP signatures, replicate git activity across peers, and move toward a resilient app-delivery network where code and build assets can be served closer to users.

Gitlawb is not trying to be only "another git host." The long-term direction is:

```txt
Decentralized GitHub
+ signed agent-native workflows
+ resilient repo replication
+ CDN-style app/code delivery
```

The mission is simple: once code is pushed to the network, it should not disappear because one server went down.

---

## What is in this repository?

This is a Rust workspace with six crates:

| Crate | Purpose |
|---|---|
| `gitlawb-node` | The node daemon: Axum HTTP server, git smart-HTTP, Postgres metadata, libp2p gossip, optional S3/Tigris/IPFS/Arweave/Base PoS hooks. |
| `gl` | The Gitlawb CLI for identity, repos, issues, PRs, bounties, tasks, peers, node status, MCP, and setup flows. |
| `git-remote-gitlawb` | Git remote helper for `gitlawb://` URLs, so normal `git clone`, `git fetch`, and `git push` can talk to Gitlawb nodes. |
| `gitlawb-core` | Shared primitives: Ed25519 identities, `did:key`, CIDs, RFC 9421 HTTP signatures, certificates, and UCAN tokens. |
| `gitlawb-attest` | Pluggable external provenance attestations for ref-update certificates. |
| `icaptcha-client` | Client for the iCaptcha proof-of-intelligence flow used to protect spam-prone writes. |

---

## Why Gitlawb Nodes?

Most git hosting today depends on a small number of centralized platforms. Gitlawb Nodes are designed for a different model:

- **Own your identity**: every user, agent, and node is an Ed25519 keypair represented as `did:key:z6Mk...`.
- **Signed writes by default**: write requests use RFC 9421 HTTP Signatures instead of passwords.
- **Git-native transport**: repositories are still real git repositories served over smart HTTP.
- **Agent-native workflows**: the `gl` CLI and MCP server expose repo, issue, task, PR, and UCAN flows to AI agents.
- **Peer-aware delivery**: nodes can announce, discover, gossip, and sync with each other.
- **App CDN direction**: the network can evolve from decentralized code storage into code + asset + app delivery.

---

## Current status

Gitlawb Node is live early infrastructure. It is useful today, but some security and reliability features are intentionally staged for compatibility with existing nodes.

Good today:

- Local or Docker node startup.
- Postgres-backed repo metadata.
- Bare git repository storage.
- Git smart-HTTP clone/fetch/push.
- RFC 9421-signed writes.
- Repository and path-scoped visibility enforcement for repository and Git content reads, with 404-shaped repository denials.
- DID identities.
- `gl` CLI workflows.
- libp2p peer discovery/gossip foundation.
- Optional Tigris/S3 storage.
- Optional IPFS/Pinata and Arweave/Irys hooks.
- Optional Base node-operator staking/heartbeat hooks.

Known limitations:

- Repository write authorization is not secure by default: `GITLAWB_ENFORCE_OWNER_PUSH` defaults to `false` for compatibility, so a valid HTTP Signature identifies a pusher but does not enforce owner-only pushes.
- UCAN proof chains are validated when supplied, but UCAN capabilities are not consulted by write authorization and the root issuer is not independently trust-anchored. UCANs therefore do not yet grant scoped collaborator access.
- Agent lifecycle revocation is not enforced by HTTP Signature authorization; do not rely on removing or revoking an agent record to block a compromised signer.
- Read visibility is not a blanket data-classification boundary: task, IPFS-pin, and Arweave-anchor listings are not repository-gated; withheld path names can be visible to a root reader; and later visibility changes cannot retract content already announced or externally anchored.
- Peer writes are signed by upgraded nodes, but strict signed-peer enforcement is opt-in during rolling upgrades.
- Current GraphQL mutations require an authenticated signer, but there is no mutation-specific guardrail that prevents a future mutation from omitting that check.
- Pull-request review comments do not yet have threaded line-level anchors, and merges do not enforce approval requirements.

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

1. **RFC 9421 HTTP Signatures**: every write is signed by your identity key. `gl`
   and the `git-remote-gitlawb` helper do this automatically. An old/unsigned CLI
   fails with `401 not_an_agent`; `gl` will tell you to upgrade and register.
2. **An iCaptcha proof** on the spam-gated writes (**repo create, fork, register**).
   `gl` solves this for you: on the node's `403 icaptcha_proof_required` it reads the
   `x-icaptcha-url` / `x-icaptcha-level` hints, requests a challenge, solves it
   locally (arithmetic / algebra / sequence), and **retries the same signed request**
   with the `x-icaptcha-proof` header. No manual steps, no env vars.

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
  `git push` is **signed-only** (owner signature is the gate, no per-push challenge);
  reads (clone / fetch / `repo info`) need no proof. A non-existent repo returns a
  clear `404`, never a placeholder.
- **API-key iCaptcha deployments:** set `GITLAWB_ICAPTCHA_URL` to your iCaptcha
  origin and `GITLAWB_ICAPTCHA_API_KEY` to its key. The client only talks to an
  `https` origin whose host is allowlisted (that URL or the public default), and
  sends the bearer token **only** to your configured origin, never to a URL a
  node advertises, so a hostile node can't capture the key or redirect the solve.

### Fetching an object by CID

```bash
gl ipfs list                                  # CIDs this node has pinned
gl ipfs get bafkrei... > object.bin           # object bytes on stdout
```

Objects that were pinned before the node started recording which repo they came
from are found by scanning its repo inventory, and that scan stops at the
per-request ceilings in the [Configuration](#configuration) table. A stopped scan
answers 503 with a resume token instead of a false "not found", and `gl ipfs get`
follows the token automatically: up to 8 resumes after the first request, so at
most 9 calls to the node, waiting between attempts for as long as the node's
`Retry-After` asks and never longer than 5 seconds.

The whole ladder runs under a 60 second wall-clock deadline. The deadline bounds
the search, not the download: each attempt gets the time left on it to produce
response headers, and once an object is found its bytes stream outside that
deadline. They are not unbounded, though. The client's own 30 second HTTP timeout
is a total request timeout, running from the start of a request until its body
has finished, so a transfer still going 30 seconds after its request began is cut
off. Waits between attempts never run past the deadline either, so a single run
spends at most around 90 seconds on the network: the deadline plus the 30 second
timeout covering the last attempt. Writing the object out sits outside both
bounds, so piping into a reader that stops reading can hold the command open
longer than that.

Two node-side brakes end a ladder early and are reported rather than retried
around. A 429 is terminal, because the node's rate-limit window is an hour and
that wait cannot be honored inside one invocation; a transient overload (a 503
carrying no incomplete-scan code) is retried on the token already held, under the
same cap, clamp and deadline. The per-IP fanout brake can also stop a ladder well
short of the 9 calls, so automatic resumption is not a guarantee of reaching the
object.

When a bound stops the ladder with a usable token in hand, the command prints the
token and the invocation that continues from it before exiting nonzero:

```txt
resume from where this stopped: gl ipfs get bafkrei... --scan <token>
```

Run that to carry on from where the scan stopped. Re-running without `--scan`
restarts at the first row, reproduces the same truncation and spends the node's
per-IP budget again, so the token is the only thing that makes progress. Tokens
are valid for an hour.

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
| Ref certificate versioning | The wire format is versioned; new certificates are currently issued as v1. `gl cert show <id> --verify` requires `--expect-node <did>`, and the queried node's self-reported DID is **not** accepted as a trust anchor. v2 is reserved for a future payload shape that carries the version inside the signed bytes; this client refuses to verify v2+ rather than guessing. |
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

When `GITLAWB_REQUIRE_SIGNED_PEER_WRITES=false`, unsigned legacy peers are accepted on those two routes, but signed requests are verified when signature headers are present. Staged rollout relaxes who may announce, not who owns a peer row. An unsigned announce may register a previously unseen peer, and it may refresh an existing row whose `http_url` is unchanged, but changing an existing peer's `http_url` requires an RFC 9421 signature from that peer's own DID and is refused with 403 otherwise. An unsigned announce can only register a `did:key`, since that is the only method whose verifying key can be resolved and therefore the only kind of row anyone could ever correct through the signed path; any other DID is refused with 400. Once all live peers upgrade, operators can set:

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
| `GITLAWB_REQUIRE_SIGNED_PEER_WRITES` | Require signed peer announce/sync writes. Defaults to `false` during the staged rollout below. |
| `GITLAWB_ENFORCE_OWNER_PUSH` | Require the authenticated pusher to be the repo owner on `git-receive-pack`. **Defaults to `true`.** A `did:key` signature is authentication, not authorization — anyone can mint a key and sign — so with this off every signed caller may push to every repository, private ones included. Delegated and CI keys count as non-owners: a UCAN `git/push` capability is verified but not yet honored for authorization, so they cannot push while this is on. Set `false` only for a rolling upgrade; see [`docs/RUN-A-NODE.md`](docs/RUN-A-NODE.md). |
| `GITLAWB_AUTO_SYNC` | Enable automatic sync from known peers. |
| `GITLAWB_MAX_PACK_BYTES` | Max git pack body size for smart-HTTP routes. |
| `GITLAWB_GIT_SERVICE_TIMEOUT_SECS` | Max seconds a served git upload-pack, receive-pack, or `info/refs` advertisement may run before it is aborted (504). Default 600. Also bounds the withheld-blob classification walk (on both the upload-pack serve and receive-pack replication paths) and the push-side pin-candidate discovery (`rev-list` / `cat-file`), each reaped via process-group teardown at the deadline. On the path-scoped upload-pack path the classification walk and the pack serve share ONE deadline, so this value bounds their combined duration rather than granting each stage a full budget: a walk that consumes it leaves the serve nothing and the clone gets a 504. Serving large path-scoped repos may therefore need a higher value than they did when each stage was budgeted separately. Accepted range is 1 to 3153600000 (100 years), since the node derives deadlines from this value and a larger one cannot be represented. |
| `GITLAWB_GIT_ACQUIRE_TIMEOUT_SECS` | Max seconds the storage-acquisition phase (Tigris HEAD/GET, push advisory-lock) of a served git op may run before the request is shed with a 503, separate from the git-run timeout. The concurrency permit is released on expiry so a stalled backend cannot pin the pool. Default 30. |
| `GITLAWB_MAX_CONCURRENT_GIT_OPS` | Max concurrent served git READ ops (upload-pack and its `info/refs` advertisement) across all callers; over-cap sheds a 503 + Retry-After. Anonymous reads draw from this pool, so pair it with `GITLAWB_MAX_CONCURRENT_READS_PER_CALLER`. Pushes and the receive-pack advertisement have their own pools, so a read flood cannot shed an authenticated push. Default 128. |
| `GITLAWB_MAX_CONCURRENT_GIT_PUSHES` | Max concurrent `git-receive-pack` POST operations, in a pool separate from the read pool. The anon receive-pack `info/refs` advertisement runs in a third pool of the same size, disjoint from both, so an advertisement flood cannot shed a push either. Two per-source push caps are derived from this value (`/8`, floor 1) and have no env var of their own. Over-cap sheds a 503 + Retry-After. Default 32. |
| `GITLAWB_MAX_CONCURRENT_READS_PER_CALLER` | Max concurrent read ops a single caller may hold, so one caller cannot monopolize the read pool. Keyed on the resolved source IP, never the DID, and only as granular as `GITLAWB_TRUSTED_PROXY`: left unset, a node behind an edge or NAT keys every caller on the edge IP and this collapses to one global cap. Default 16. |
| `GITLAWB_MAX_CONCURRENT_PIN_TASKS` | Max post-push pin loops (IPFS + Pinata) running concurrently across all repos. This caps how many loops RUN at once, not how much object-id list memory the node retains: on the local IPFS path a loop parked waiting for a permit still holds its full list. Do not size memory from this knob alone. A loop over cap waits, never drops a pin. Default 8. |
| `GITLAWB_REPO_LEASE_MAX_WAITERS` | Max pushes parked at once waiting for the same repo's write lease. Each waiter pins its buffered pack body, so this bounds that memory for a hot repo; past the cap the newest push sheds a 503 + Retry-After instead of queueing. Pushes to other repos are unaffected, and the lease holder is not counted. Default 8. |
| `GITLAWB_MAX_CONCURRENT_IPFS_WALKS` | Max concurrent `GET /ipfs/{cid}` visibility walks across all callers (own pool, disjoint from the served-git pools); over-cap sheds 503. Default 32. |
| `GITLAWB_IPFS_WALK_PER_SOURCE` | Max concurrent `/ipfs` walks a single source IP may hold. Default 4. |
| `GITLAWB_IPFS_MAX_LEGACY_PROBES` | Max legacy (NULL-provenance) repos probed per `/ipfs/{cid}` request, bounding the scan-fallback fan-out. A truncated scan returns a retryable 503, not a false 404. Default 256. |
| `GITLAWB_IPFS_MAX_LEGACY_SCAN_ROWS` | Max repo rows one `/ipfs/{cid}` request's legacy scan may read from the database. The probe ceiling above only starts counting once a probe runs, and quarantined or private repos are denied before that, so this is what bounds a scan over an inventory that denies the caller everywhere. A truncated scan sheds a retryable 503 carrying an opaque `continuation` token; echoing it as `?scan=` resumes the scan where it stopped. Every per-request ceiling on this path (rows, probes, visits, retained rule bytes) mints one, so each request advances the ladder by at least the rows it read and a holder buried past a ceiling is reached in a bounded number of requests, `ceil(repos / ceiling) + 1` when this row ceiling is the one that binds. No ceiling ever produces a 404. Every page is charged to the caller's `/ipfs` work allowance, so raising this raises that allowance too. Lowering it sharpens an oracle: because a truncation emits a token and a completed wrap does not, laddering to the end reveals the node's total repo count (private and quarantined included) to within one ceiling. Default 2048. |
| `GITLAWB_IPFS_MAX_REPOS_WALKED` | Max expensive path-scope visibility walks a `/ipfs/{cid}` request may run per phase; over-cap repos are skipped and the scan continues, shedding a retryable 503 (not a false 404) if the object is then found nowhere. The effective cap is the tighter of this knob and the node's internal history-walk ceiling of 17 (`MAX_PIN_SOURCES + 1`), so a value above 17 has no effect while a value below it does tighten the cap. It is charged per phase: the provenance lookup and the legacy-scan fallback get separate equal budgets, so one request can run up to twice the cap in total. Default 64. |
| `GITLAWB_IPFS_MAX_REPO_VISITS` | Ceiling on repos one `/ipfs/{cid}` request may visit (acquire + probe) past the visibility gate. Also the worst-case per-request Tigris fetch count. On exhaustion the scan stops with a retryable 503. Default 1024. |
| `GITLAWB_IPFS_REQUEST_BUDGET_SECS` | Absolute wall-clock budget for one admitted `/ipfs/{cid}` request's acquire+walk lifetime. Per-stage clamps bound the acquire and walk stages to the remaining budget, and no stage starts once it is exhausted; the scan then stops with a retryable 503. The object-type probe and content-read `cat-file` subprocesses are budget-checked before starting and each also run under their own deadline (the lesser of `GITLAWB_GIT_SERVICE_TIMEOUT_SECS` and the remaining budget), reaped via process-group teardown, so a hung `cat-file` cannot hold the request's walk slot past it. One hang path is still unbounded: the probe's object-store readability check is a plain filesystem sweep with nothing to reap, so a wedged filesystem can hold the slot past the deadline. Default 600. Accepted range is 1 to 3153600000 (100 years), since the node derives a deadline from this value and a larger one cannot be represented. |
| `GITLAWB_IPFS_RESOLVE_BUDGET_SECS` | Shorter budget for the pre-walk CID resolve inside an admitted `/ipfs/{cid}` request: the lookup that maps the requested CID to its git oid(s), which runs while the scarce walk admission is already held. A well-formed CID with no pin row does no probe and no walk work, so without this it could hold a walk slot for the whole request budget while nothing walked, and enough such requests shed every real retrieval at admission. The effective deadline is the lesser of this and the remaining request budget, so a value above `GITLAWB_IPFS_REQUEST_BUDGET_SECS` degrades to the request budget. Only the resolve is on this clock; walk and probe work stay on the request budget, so a slow but progressing scan is never shed by it. Default 10. Accepted range is 1 to 3153600000 (100 years). |
| `GITLAWB_IPFS_RATE_LIMIT` | Max `/ipfs/{cid}` requests per client IP per hour (route flood brake). 0 disables. Default 600. |
| `GITLAWB_TIGRIS_BUCKET` | Optional S3/Tigris shared repo storage bucket. |
| `GITLAWB_PINATA_JWT` | Optional Pinata/IPFS warm-storage pinning. |
| `GITLAWB_IRYS_URL` | Optional Irys/Arweave permanent anchoring. |

Production note: change the default Postgres password before exposing a node publicly.

Legacy-pin window: releases before the CID-resolver work stored the provider CID (Kubo dag-pb / Pinata) as a pinned object's resolver key. The `/ipfs/{cid}` resolver now recomputes the raw-content CID from the object bytes and refuses to serve a key that does not match, so `GET /api/v1/ipfs/pins` can still advertise an unrepaired legacy CID that 404s. Such a row is repaired opportunistically the next time a push carries the object again (its key is rewritten to the raw CID, the old value kept in `legacy_provider_cid`), but git negotiation omits objects the node already has, so most legacy rows never re-enter a push delta. A deferred one-shot startup sweep, not this opportunistic path, is what fully retires the advertise-then-404 window. Rows whose object bytes are gone stay withheld.

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
5. Close default-open write authorization and wire trusted UCAN delegation into repository permissions.
6. Add threaded, line-level pull-request discussions and enforce approval requirements on merges.
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
