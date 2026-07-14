# Maintainer roadmap

Gitlawb node is live software. People are already using the network, so maintainer work should optimize for uptime, compatibility, and predictable rollouts before feature velocity.

Mission: when code is pushed to a node, the node should not go down, and the network should be able to serve git content like a resilient delivery layer.

## Operating principles

- Protect live nodes first. Do not ship breaking protocol or API changes without a staged compatibility window.
- Prefer opt-in hardening flags before making behavior mandatory across the network.
- Make every public claim in docs match current behavior.
- Treat every node operator as a production user, even when the feature is early.
- Keep new contributor tasks small and testable.

## Now: stabilize the live network

Owner focus: maintainers.

- Keep CI green on `main`: format, clippy, workspace tests, release build.
- Add PR Docker smoke testing so quickstart regressions are caught before merge.
- Add installer smoke tests for release archive names and extraction layout.
- Publish a short operator notice for `GITLAWB_REQUIRE_SIGNED_PEER_WRITES`: leave it `false` until all known peers upgrade, then flip it.
- Add a live-node checklist: health endpoint, database backup, data volume backup, public URL, reverse proxy/TLS, peer reachability.
- Track known public nodes and their version so coordinated upgrades are possible.

## Next: stop avoidable downtime

Owner focus: node reliability.

- Add versioned database migrations instead of implicit startup schema changes.
- Add graceful shutdown and startup logging that clearly distinguishes database, repos, P2P, and operator-loop failures.
- Add bounded request/concurrency settings for git pack operations.
- Add operator docs for lowering `GITLAWB_MAX_PACK_BYTES` on small nodes.
- Add recovery docs for a broken repo cache, missing data volume, or failed Tigris/S3 sync.
- Add basic metrics for pushes, fetches, pack sizes, peer sync queue, failed auth, and webhook failures.

## Security hardening

Owner focus: protocol/auth.

- Implement repo write authorization: repo owner checks, protected branches, UCAN capability checks, and clear delegation semantics.
- Implement private-read enforcement or remove private-repo affordances until it exists.
- Add UCAN revocation or blocklisting, with an emergency compromised-key runbook.
- Add mutation-aware GraphQL auth before GraphQL becomes a public write API surface.
- Harden peer registration and outbound peer calls against SSRF and peer-list poisoning.
- After all live peers upgrade, enable signed peer writes by default.

## Product and CLI

Owner focus: developer experience.

- Make public-node vs localhost behavior explicit across `gl`, `git-remote-gitlawb`, README, and quickstart docs.
- Add `--version` support to `git-remote-gitlawb` so release smoke tests can validate it directly.
- Improve `gl doctor` for live operators: check Docker, Postgres, public URL, node health, p2p port, and binary versions.
- Add a compact `gl node doctor` command for self-hosted nodes.
- Make errors from JSON API responses more consistent and actionable.

## UI direction

Owner focus: desktop/operator UI.

- Start with an operator dashboard, not a broad GitHub clone UI.
- Show node status, version, DID, public URL, database status, repo count, peer count, recent pushes, sync queue, and storage mode.
- Include safe controls: start/stop local stack, copy config, open logs, run health checks.
- Avoid making PoS/operator wallet actions one-click until signing, key storage, and failure states are reviewed.

## Release rhythm

- Patch releases: bug fixes, docs corrections, backward-compatible hardening.
- Minor releases: new CLI/API features, opt-in hardening flags, new operator UI capabilities.
- Breaking protocol changes: require a migration note, rollout plan, and compatibility window.

## Suggested issue labels

- `live-network`
- `good-first-issue`
- `operator-experience`
- `security`
- `protocol`
- `ci-release`
- `docs`
- `ui`
