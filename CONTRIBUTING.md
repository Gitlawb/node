# Contributing to gitlawb

Thanks for your interest in contributing. gitlawb is an open protocol — agents and humans welcome.

## Quick start for contributors

```sh
# Clone and build
git clone https://github.com/Gitlawb/node
cd node

# Build everything
cargo build

# Run the workspace test suite
cargo test --workspace

# Run a local node (requires a Postgres instance — see docker-compose.yml)
cargo run -p gitlawb-node

# Build the CLI
cargo run -p gl -- --help
```

The fastest dev loop is `docker compose up postgres -d` for the database, then `cargo run -p gitlawb-node` for the node.

## Repository layout

```
crates/
├── gitlawb-core/       crypto primitives (DID, CID, HTTP sigs, UCAN, ref certs)
├── gitlawb-node/       axum HTTP server, git smart HTTP, P2P, GraphQL
├── gl/                 CLI — identity, repos, MCP server, Base L2 names
└── git-remote-gitlawb/ git remote helper for gitlawb:// URLs
docs/                   Operator guides
scripts/                Build helpers
```

Smart contracts live in a separate repo: [github.com/Gitlawb/contracts](https://github.com/Gitlawb/contracts).

## Ways to contribute

- **Bug reports** — open an issue with steps to reproduce
- **Feature requests** — open an issue describing the use case
- **Code** — open a PR (see guidelines below)
- **Documentation** — fixes and improvements always welcome
- **Node operators** — run a node and join the network
- **Agent integrations** — build tools using `gl mcp serve`

## PR guidelines

1. **One thing per PR.** Small, focused PRs get reviewed faster.
2. **Tests.** New functionality should have tests. Run `cargo test --workspace` before opening a PR.
3. **No breaking changes without discussion.** Open an issue first for protocol-level changes.
4. **Conventional commits.** Use `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`. Releases are automated by [release-please](https://github.com/googleapis/release-please) — your commit prefixes drive the next version bump.
5. **Format and lint.** Run `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` before submitting. CI will reject anything that fails these.

## What gets merged, what gets closed

We welcome contributions from humans and agents alike. To keep review sustainable, PRs are
expected to clear a basic quality bar:

- **Link an issue.** Bug fixes and features should reference an issue (`Closes #123`). For
  protocol-level changes (identity, signatures, UCAN, ref certs, wire formats), open the
  issue *before* writing code.
- **One change per PR.** Unrelated churn slows review and gets sent back.
- **Tests and a green pipeline.** New behavior needs tests; `cargo fmt`, `cargo clippy`,
  and the full CI suite must pass.
- **A real description.** Say what changes and why. "Update code" is not a description.

A triage bot labels PRs that are missing these and leaves a short note. Nothing is closed
automatically while you're engaging. A flagged PR that goes 14 days with no linked issue or
description gets a stale warning, and is closed 7 days later if still untouched. Closed PRs can
be reopened at any time once updated.

## Development environment

**Requirements:**
- Rust stable (≥ 1.91) — install via [rustup](https://rustup.rs)
- PostgreSQL — required for the node. Use the bundled `docker-compose.yml` for local dev.
- Docker (optional, for full-stack local testing)

**Environment variables:**

```sh
cp .env.example .env
# edit .env
```

The minimum required variable is `DATABASE_URL`. Everything else has sensible defaults — see [`.env.example`](.env.example).

## Running tests

```sh
# All workspace tests
cargo test --workspace

# Specific crate
cargo test -p gitlawb-core
cargo test -p gitlawb-node
```

## Areas actively looking for help

- **TypeScript SDK** (`@gitlawb/sdk`) — client library for the HTTP API
- **Python SDK** (`gitlawb`) — for ML/agent pipeline integration
- **UCAN chain validation** — complete the auth middleware
- **Filecoin storage tier** — wire up cold storage deals
- **Documentation** — guides, tutorials, API examples
- **Node operators** — run a public node and report issues

## Code of conduct

Be constructive and respectful. This is a technical project — focus on ideas and code, not people.

## License

By contributing, you agree that your contributions will be dual licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE), at the user's option.
