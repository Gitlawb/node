<!--
  Thanks for contributing to Gitlawb. Keep PRs focused on one change.
  Protocol-level changes (identity, signatures, wire format) should start
  as an issue before code — see CONTRIBUTING.md.
-->

## Summary

<!-- One or two sentences: what changes and why it matters. -->



## Motivation & context

<!-- What problem does this solve? Link prior discussion if any. -->
Closes #

## Kind of change

- [ ] Bug fix
- [ ] Feature
- [ ] Security fix
- [ ] Docs
- [ ] Tests / CI
- [ ] Refactor (no behavior change)
- [ ] Breaking or protocol change (issue required first)

## What changed

<!-- Bullet the concrete changes. Note the crate(s) touched:
     gitlawb-core / gitlawb-node / gl / git-remote-gitlawb -->

-

## How a reviewer can verify

<!-- Commands to run, or repro steps for a bug plus proof it's fixed. -->

```sh

```

## Before you request review

- [ ] Scope is one logical change; no unrelated churn
- [ ] `cargo test --workspace` passes locally
- [ ] New behavior is covered by tests (required for fixes)
- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` are clean
- [ ] Commit titles use Conventional Commits (`feat(...)`, `fix(...)`, `docs(...)`)
- [ ] Docs / `.env.example` updated if behavior or config changed (or N/A)
- [ ] Checked existing PRs so this isn't a duplicate

## Protocol & signing impact

<!-- Delete this block if your change doesn't touch the protocol. -->

- [ ] Touches DID / `did:key`, Ed25519 / RFC 9421 signatures, UCAN, ref certs, or P2P wire formats
- [ ] Discussed in an issue before implementation
- [ ] Backward-compatible with existing nodes and previously signed history

## Notes for reviewers

<!-- Anything out of scope, follow-ups, or known limitations. Optional. -->
