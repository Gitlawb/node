# gitlawb node

**Decentralized git for AI agents and developers.** Run your own node, host repos under your own DID, and connect to the gitlawb network.

This repository contains the open-source node software:

- `gitlawb-node` — Axum HTTP server, git smart-HTTP, libp2p gossip, optional S3-compatible storage
- `gl` — CLI for identity, repos, PRs, MCP server
- `git-remote-gitlawb` — `git remote helper` for `gitlawb://` URLs
- `gitlawb-core` — shared crypto primitives (DID, CID, HTTP signatures, UCAN)

---

## Quickstart

The fastest way to run a node is via Docker. You'll get a node + Postgres locally with one command.

```bash
git clone https://github.com/gitlawb/node.git
cd node
cp .env.example .env
docker compose up -d
```

Your node is now serving:

- HTTP + git smart-HTTP on `:7545`
- libp2p gossip on `:7546`

Verify:

```bash
curl http://localhost:7545/health
```

---

## How it works

- **Identity** — every actor (human or agent) is an Ed25519 keypair → `did:key:z6Mk...`. No accounts, no passwords.
- **Auth** — every write is signed via HTTP Signatures (RFC 9421).
- **Delegation** — UCAN capability tokens.
- **Storage** — local disk + optional S3-compatible bucket (Tigris, MinIO, AWS S3).
- **Networking** — libp2p Gossipsub for ref-update events, Kademlia DHT for node discovery.

The node is **stateless beyond Postgres + the repos directory.** You can scale horizontally by pointing multiple nodes at a shared S3 bucket and database.

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full reference.

The minimum required:

- `DATABASE_URL` — Postgres connection string

Everything else has sensible defaults. Optional features:

- `GITLAWB_TIGRIS_BUCKET` (+ AWS credentials) — S3-compatible shared storage
- `GITLAWB_PINATA_JWT` — IPFS warm-storage pinning
- `GITLAWB_IRYS_URL` — Arweave permanent anchoring
- `GITLAWB_BOOTSTRAP_PEERS` — comma-separated peer URLs to announce to on startup
- `GITLAWB_P2P_BOOTSTRAP` — comma-separated libp2p multiaddrs

### On-chain Proof-of-Stake (advanced, optional)

The node supports an optional on-chain PoS layer where operators register their DID, stake $GITLAWB on Base L2, and receive a share of protocol fees. Smart contracts are in a separate repository at [github.com/gitlawb/contracts](https://github.com/gitlawb/contracts).

PoS is **disabled by default** and currently paused pending external audit. To enable, set `GITLAWB_CONTRACT_NODE_STAKING` and `GITLAWB_OPERATOR_PRIVATE_KEY`. See [`docs/RUN-A-NODE.md`](docs/RUN-A-NODE.md) for details.

---

## Build from source

Requires Rust 1.85+ and a Postgres instance.

```bash
cargo build --release -p gitlawb-node -p gl -p git-remote-gitlawb
```

Binaries are placed in `target/release/`. The `gl` and `git-remote-gitlawb` binaries should be on your `$PATH` for client use.

---

## CLI usage

```bash
gl identity new
gl register --node http://localhost:7545
gl repo create my-repo --description "..."
git clone gitlawb://did:key:z6Mk.../my-repo
```

Full CLI reference: `gl --help`.

---

## Architecture

```
crates/
├── gitlawb-core/        crypto primitives (DID, CID, HTTP sigs, UCAN)
├── gitlawb-node/        node daemon (Axum + git smart-HTTP)
├── gl/                  CLI
└── git-remote-gitlawb/  git remote helper
```

---

## macOS Menu Bar App

A native Swift/AppKit menu bar app that manages the Docker Compose stack (node + Postgres) without touching the terminal.

**Requirements:** macOS 26+, Xcode Command Line Tools (`xcode-select --install`), and a Docker runtime (Docker Desktop, OrbStack, or Colima).

### Build

```bash
./scripts/build-macos-app.sh
```

The resulting `Gitlawb Node.app` and `.dmg` are placed in `dist/`.

To codesign for distribution:

```bash
./scripts/build-macos-app.sh --sign "Developer ID Application: ..."
```

### Features

- Start/Stop the node from the menu bar
- Status indicator (green = running, yellow = starting, red = stopped)
- Settings GUI (ports, Postgres password, operator config)
- Auto-start on login
- Detects Docker Desktop, OrbStack, and Colima automatically

### Running an unsigned build

If you built the app locally without a Developer ID, macOS Gatekeeper will block it. To allow it:

```bash
xattr -cr "dist/Gitlawb Node.app"
```

Then open the app normally. Alternatively, go to **System Settings → Privacy & Security** and click **Open Anyway** after the first blocked launch attempt.

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: see [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
