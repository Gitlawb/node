# Contributor guide for coding agents

This file carries the rules a patch author cannot recover from the code alone, for humans and coding agents alike. For build, test, and PR basics, read `CONTRIBUTING.md` first.

## Authorization invariants (the rules PRs most often break)

Every repo-scoped endpoint must bind the caller to an authorization decision before serving or mutating anything. The `known_ungated` allowlist in `authz_guard::every_repo_scoped_handler_is_gated` is empty on main: `list_webhooks`, `list_replicas`, and `list_protected_branches` are gated (`list_webhooks` with read-visibility then owner; the other two with `authorize_repo_read`). Do not re-open those surfaces as exceptions.

- Owner-only mutations (visibility, webhooks, protected branches, merges) are gated against the repo owner. Three gate forms are in use and all are recognized: webhooks and merges call `require_repo_owner` (`crates/gitlawb-node/src/api/mod.rs`), visibility uses its module-local `require_owner`, and protected branches compare inline with `did_matches`. Use the form the surrounding module already uses.
- Not every write is owner-only, and that is by design: `star_repo`/`unstar_repo` bind to the signer (they still require repo read access), `register_replica`/`unregister_replica` bind to the replica's own DID, the bounty actions (claim, submit, approve, cancel, dispute) have their own multi-party rules, and closing a PR or issue is owner-or-author. Do not add owner gates to these.
- Content-serving reads (blobs, trees, raw files) gate through `authorize_repo_read` with the specific path being served, so a withheld subtree is denied even on an otherwise-public repo; repo-level reads (listings) pass `"/"` by the helper's own contract. The source scans below cannot check this argument's value, so review will.
- A route that reaches repo data through a global id, with no repo in its path, or through an extractor shape the scans do not recognize still needs the same gate; the scans cannot see those.
- Read-surface denials must not reveal existence: a caller who may not read a repo (or a withheld subtree) gets the same 404 as a missing repo, never a 403. (Owner-gated mutations currently return 403 after the repo lookup; do not widen that shape to read paths.)
- Two tests in module `authz_guard` (`crates/gitlawb-node/src/api/mod.rs`) scan handler sources and fail on a repo-scoped handler without a recognized gate: `every_in_scope_mutation_has_its_gate` and `every_repo_scoped_handler_is_gated`. If they fail on your handler, add the gate. The second test's `known_ungated` allowlist is empty; never add an entry to it without an open issue and review.

## Adding or changing routes

- A new gated handler needs tests proving its route-specific gate fires: exercise an unauthorized authenticated caller and an anonymous caller where applicable, assert the exact denial status each way, and assert the body leaks nothing. The non-owner tests in `crates/gitlawb-node/src/test_support.rs` show the shape for owner-gated routes.
- A new mutation handler also gets a row in `every_in_scope_mutation_has_its_gate` naming its gate type; the per-handler row is the point of that test.
- A table-driven deny suite covering every deny-bearing route is in review (#194, #195). If it is present in your checkout, add a probe row there for any new deny-bearing route.

## Verifying signatures and certificates

- Derive the verifying key from something outside the artifact you are checking: the node's own DID, a pinned or configured value, a peers lookup. A key read from a field of the object being verified (`Did::from_str(&cert.node_did)`) only proves the artifact is self-consistent, and identities here are permissionless, so anyone can mint a keypair, name it in the artifact, self-sign, and be told it is valid. A mismatch against that anchor has to fail the result, not log a warning.
- A handler whose correct answer is "valid" needs a positive case driven by a trusted, independently anchored artifact, and a rejection case for a well-formed, fully populated forged artifact. Invalid-only suites miss an implementation that rejects everything; a forged artifact that still returns valid is the regression that matters.
- The fields a signature covers are a versioned format. Adding one invalidates every artifact already signed, so give the payload a version, keep a path that verifies the older form, and add a test that verifies an artifact signed before your change.

## Removing a serving path

When a fix removes a path that used to serve content, the same PR must add a test asserting the removed path now denies. The deletion is what turns that test green; without it the path can quietly come back.

## Database migrations

Schema changes are code-defined in `MIGRATIONS` (`crates/gitlawb-node/src/db/mod.rs`). Always append a new versioned entry; never edit an entry that has merged (operators deploy from main). Test runs build the schema from scratch, so editing an applied version stays green in CI while breaking every existing deployment.

## Client behavior (`gl`, `git-remote-gitlawb`)

When a node denies a request, surface the denial to the user. Never render a denial as an empty list or a silent success; that turns an authorization boundary into invisible data loss.

## Toolchain and CI reality

- MSRV is Rust 1.91 (`rust-version` in the workspace `Cargo.toml`). The MSRV CI job runs `cargo check --workspace --all-targets` on exactly 1.91, so check that an API you rely on is stable there; the full test suite runs on stable.
- The PR workflow runs these jobs on every PR: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (against Postgres), a release build, `cargo audit`, the MSRV check, and a Docker build. The `main` branch ruleset currently requires one approving review but does not require these checks to pass before merge; a failing job should block review approval in practice, but nothing enforces that mechanically today.
- Conventional commit titles (`feat:`, `fix:`, `docs:`, ...) are required by convention and drive releases, but no CI job checks them; a bad title fails review, not the pipeline.
