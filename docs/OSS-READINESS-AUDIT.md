# OSS readiness audit

Date: 2026-05-28
Repo state inspected: `main` tracking `origin/main`, starting at `b12c6bc feat: per-DID rate limiting on creation endpoints (10/hour) (#13)`.

## Commands run

```sh
git status --short --branch
git remote -v
git branch --show-current
git rev-parse --abbrev-ref --symbolic-full-name '@{u}'
git log -1 --oneline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -q -p gl -- --help
cargo run -q -p gitlawb-node -- --help
docker --version
docker compose config
cargo build --release -p gitlawb-node -p gl -p git-remote-gitlawb
docker build -t gitlawb-node:oss-audit .
```

## Build and test health

- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- `cargo test --workspace` passed: `git-remote-gitlawb` 6 tests, `gitlawb-core` 38 tests, `gitlawb-node` 59 tests, `gl` 188 tests, plus doc tests.
- `gl --help` and `gitlawb-node --help` both render successfully.
- `docker compose config` parses successfully.
- `cargo build --release -p gitlawb-node -p gl -p git-remote-gitlawb` passed.
- `target/release/gitlawb-node --version` and `target/release/gl --version` report `0.3.9`.
- `git-remote-gitlawb` has no `--version` flag; release smoke tests should use a helper-specific invocation.
- Full Docker image build could not run in this environment because the Docker CLI is installed but the Docker Desktop Linux engine pipe is not available.
- `bash -n install.sh` could not run in this Windows environment because `bash` is routed through WSL and WSL has no `/bin/bash` installed.

Recommended next CI additions:

- Add a PR Docker image smoke test (`docker build` plus `gitlawb-node --version`).
- Add installer smoke tests for Linux/macOS archive names and extraction layout.
- Add `cargo audit` or equivalent advisory reporting, with documented ignores for accepted advisories.
- Add an MSRV check if Rust 1.85+ is a supported contract.

## Install and docs accuracy

Fixed in this pass:

- `install.sh` now downloads from `Gitlawb/node`, matches release asset names (`gitlawb-node-<version>-<target>.tar.gz`), handles `--version vX.Y.Z`, extracts the packaged directory, verifies checksums, and installs `gl`, `git-remote-gitlawb`, and `gitlawb-node` when present.
- `docs/RUN-A-NODE.md` now matches the README Rust requirement (`1.85+`) and the release workflow's GHCR image path (`ghcr.io/gitlawb/node:latest`).
- `docs/ECONOMICS.md` no longer claims this repo ships a `keeper-distribute.yml` workflow that is not present.
- `.env.example` now distinguishes HTTP bootstrap peers from libp2p multiaddrs and documents seed-list opt-out.
- `scripts/build-bins.sh` now writes to `dist/bin` instead of a missing `web/public/bin` path.

Remaining doc caveats:

- Public docs URLs (`gitlawb.com/install.sh`, `docs.gitlawb.com`) were not verified in this local pass.
- `git-remote-gitlawb` defaults to `http://127.0.0.1:7545`, while most `gl` commands default to `https://node.gitlawb.com`; the docs should be explicit about setting `GITLAWB_NODE` for public-network cloning/fetching.

## Docker and self-hosting readiness

Positive:

- Runtime image runs as a non-root `gitlawb` user.
- Compose includes Postgres health checks and persistent volumes for database and node data.
- Node health check uses `/health`.
- Source default bind is `127.0.0.1`; Compose intentionally exposes `0.0.0.0`.

Risks:

- Compose defaults `POSTGRES_PASSWORD` to `changeme`; production docs should require changing it before public exposure.
- Compose publishes HTTP and libp2p ports directly. Operators should put HTTP behind TLS/reverse proxy and decide explicitly whether P2P is public.
- The node auto-merges `bootstrap-peers.json` unless `GITLAWB_BOOTSTRAP_DISABLE_SEEDS=true`; good for public discovery, surprising for isolated dev/test networks.
- There is no versioned database migration system; schema is created/altered from code at startup, which is convenient early on but risky for live upgrades.

## Security and trust boundaries

Fixed or staged in this pass:

- `POST /api/v1/bounties/{id}/dispute` moved behind HTTP Signature auth.
- Peer announce/sync notifications are now signed by upgraded nodes.
- Peer announce and sync notify handlers verify the signature keyid when a signature is present.
- `GITLAWB_REQUIRE_SIGNED_PEER_WRITES=false` keeps live nodes backward-compatible during rolling upgrades; operators can flip it after all known peers upgrade.

Live-network blockers to prioritize:

- GraphQL POST is still open for compatibility; GraphQL mutations should get mutation-aware auth before it becomes a public write API surface.
- Push authorization is still not capability-complete. A valid DID signature is authentication, not authorization; unprotected repo branches do not yet enforce owner/UCAN capability checks.
- UCAN chain validation is incomplete and UCAN revocation/blocklisting is not implemented as an operator feature.
- Private repository reads are not enforced. `is_public` and `GITLAWB_PUBLIC_READ` exist, but per-repository private-read behavior is not wired.
- Peer URLs are self-asserted by DIDs. Signatures prove control of the DID key when present, not ownership/safety of the announced URL.
- Outbound peer fetch/ping/sync paths should be reviewed for SSRF protections before accepting arbitrary public peer registrations.

## Keys, identity, and auth handling

- Node identity keys are generated as Ed25519 PKCS#8 PEM files; Unix builds set `0600` on newly generated node keys.
- Windows builds do not apply equivalent ACL hardening.
- Operator wallet private keys are read from `GITLAWB_OPERATOR_PRIVATE_KEY`; operators should use a dedicated low-balance wallet and avoid process managers that expose env vars broadly.
- The CLI stores identity in a PEM file and signs API writes with RFC 9421 headers.
- HTTP Signature clock skew is limited to 5 minutes.

## Network exposure and defaults

- `gitlawb-node` defaults to `127.0.0.1:7545` from source, but Docker Compose binds and publishes `7545` and `7546`.
- `/health`, `/`, `/api/v1/stats`, `/api/v1/contracts`, and read APIs are public by default.
- `GITLAWB_MAX_PACK_BYTES` defaults to 2 GiB for git smart-HTTP. Operators on small nodes should lower it.
- `GITLAWB_AUTO_SYNC=false` by default, which is a good conservative default.

## CLI usability

Positive:

- The top-level `gl --help` surface is broad and discoverable.
- `gl doctor`, `gl quickstart`, `gl init`, and `gl status` are good OSS onboarding affordances.
- The CLI now reports its real package version in the HTTP user agent.

Risks:

- Many commands default to the public node; `git-remote-gitlawb` defaults to localhost. This split should be called out in README examples.
- `gl sync trigger` signs the request when a local identity is available and falls back to the legacy unsigned request for live compatibility.
- Several CLI commands parse dynamic JSON responses permissively; good for compatibility, but error messages can hide response-shape regressions.

## CI and release readiness

Positive:

- PR CI pins third-party actions by commit SHA.
- CI runs format, clippy with `-D warnings`, and workspace tests.
- Release workflow uses release-please, builds a Docker image, runs a Docker `--version` smoke test, and attaches multi-target binary archives.

Risks:

- PR CI does not build the Docker image, so Dockerfile regressions can reach `main`.
- Release binaries are not smoke-tested after packaging.
- The installer was not covered by CI; this pass fixed current asset-name/layout mismatches, but tests should lock it down.
- No automated dependency advisory job is present.

## Obvious live-network priorities

1. Implement repo write authorization: owner checks, UCAN capability checks, and clear delegation semantics for push/PR/issue/bounty operations.
2. Implement private-read enforcement or remove private repo affordances until it exists.
3. Add UCAN revocation/blocklisting and operator docs for emergency key compromise.
4. Harden peer registration and outbound fetch behavior against SSRF and peer-list poisoning.
5. Add Docker/installer/release smoke tests to CI.
6. Label PoS/economics docs consistently with the current live contract and rewards status.
