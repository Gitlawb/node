# Storage and pinning

How a gitlawb node's **optional post-push pinning tiers** work. This documents
the behavior implemented in `crates/gitlawb-node/src/ipfs_pin.rs` and
`crates/gitlawb-node/src/pinata.rs`; it does not change any behavior. Primary
git storage for clone/fetch lives in bare repos under `GITLAWB_REPOS_DIR`
(with optional `GITLAWB_TIGRIS_BUCKET` backing), covered in the README
Configuration table.

## Two-tier model

After a push lands, eligible new git objects can be pinned to up to two
independent sinks. Both are **opt-in and independent** — a node runs fine with
neither, either, or both configured.

Pinning does not run on every push. The post-push tail only reaches the pin
steps when the push passed publish-durability confirmation and the repository
replicates at root (`announce_at_root`): private repositories and other repos
that are not anonymously readable at the root skip both public pin paths, and
path-scoped rules exclude withheld objects. The warm path additionally requires
this push's own withheld walk to have succeeded. A separate best-effort path can
pin encrypted withheld blobs to Kubo for authorized readers; it is not a
two-tier backup and is outside this page's scope.

| Tier | Sink | Module | Enabled by | Purpose |
|------|------|--------|-----------|---------|
| Hot  | Local Kubo (IPFS) | `ipfs_pin.rs` | `GITLAWB_IPFS_API` set | Node-local availability; the node is an HTTP client of a co-located Kubo daemon |
| Warm | Pinata (IPFS) | `pinata.rs` | `GITLAWB_PINATA_JWT` set | Off-node durability + public IPFS gateway reachability |

If a sink's config value is empty, its **upload** step is a no-op — so leaving
`GITLAWB_PINATA_JWT` unset disables warm-tier *uploads*. The tail's cost is
conditional on the same admission gates above: only when the push was admitted
to replication does the warm worker still take a global pin permit and run the
full object-list re-derivation walk before the upload step returns empty,
because its gate is the announce/walk state, not the JWT. On a push that was
not admitted, no warm worker runs at all. Note the no-op applies to pinning
only, not reads: the hot-tier read path (`ipfs_pin::cat`) returns an error rather
than a no-op when `GITLAWB_IPFS_API` is unset, so a node that serves the
encrypted-blob read endpoint needs Kubo configured. An empty `GITLAWB_IPFS_API`
can still briefly touch the pin pool: the hot worker may take a permit when the
built object list is non-empty even though the upload call returns immediately.

## Configuration

| Env var | Default | Meaning |
|---------|---------|---------|
| `GITLAWB_IPFS_API` | `""` (disabled) | Base URL of the local Kubo HTTP API, e.g. `http://127.0.0.1:5001` |
| `GITLAWB_PINATA_JWT` | `""` (disabled) | Pinata bearer JWT enabling the warm tier |
| `GITLAWB_PINATA_UPLOAD_URL` | `https://uploads.pinata.cloud/v3/files` | Pinata v3 upload endpoint |
| `GITLAWB_MAX_CONCURRENT_PIN_TASKS` | `8` | Cap on concurrent post-push pin loops across all repos |

## How pinning runs

Pinning happens **after** a push is accepted, not on the push's critical path:

- The **hot** tier pins inline in the post-push encrypt/pin task.
- The **warm** (Pinata) tier runs in a spawned replication tail, so a slow or
  unreachable Pinata never blocks the pusher.

Both tiers share a single global **pin admission semaphore**
(`max_concurrent_pin_tasks`). One admitted push with both backends configured
can hold up to **two** loops on this pool at once, so the default of eight caps
loops, not pushes: roughly four concurrent all-dual-tier pushes fit before new
loops wait. The pool **defers rather than sheds**: when it is
saturated, a pin loop waits for a slot instead of dropping the pin. Each batch is
bounded by `PIN_BATCH_BUDGET` (120s) so the pin batch itself cannot hold a slot
indefinitely. The Pinata tail re-derives its object list only *after* acquiring a
slot, which bounds *its* outstanding memory to O(refs) rather than
O(pushes × objects) — but that bound is the warm tail's alone. A **hot-tier** pin
loop takes an owned object list materialized by its caller *before* it waits for
a slot, so every hot loop parked on a saturated pool is holding its full list:
the hot side of the parked-list memory is O(pushes × objects), capped per repo by
`EncryptInflight` but not across repos. Do not size a node's memory from the
semaphore knob (README says the same).
Note the budget covers the pin batch, not the preceding object-list re-derivation
walk: that walk holds the slot too, and bounds only each child git process
individually (no aggregate deadline).

De-duplication is per sink and best-effort, backed by the single `pinned_cids`
table: the hot tier skips an object when `has_ipfs_cid` reports true, which is
`local_ipfs_provenance = TRUE` — a row that records a real local Kubo CID — and
the warm tier on the nullable `pinata_cid` column, so later pushes normally skip
objects whose successful pin is already recorded for that sink. The isolation is
one-directional: a hot-only pin does not suppress the warm tier (`pinata_cid`
stays null), and a warm-tier pin does not suppress the hot tier either: a row
with only `pinata_cid` set has `local_ipfs_provenance = FALSE`, so an object
warm-pinned while `GITLAWB_IPFS_API` was unset can still enter the hot upload
path once Kubo is configured — provided a later push selects it (the hot walk
covers objects new to that push) or the enabled reconciliation sweep picks it
up among eligible public objects — subject to visibility checks, budgets, and
failure handling. The check-upload-record sequence is not atomic,
so concurrent post-push tasks for the same object, or a failure to record after a
successful upload, can still cause a repeat upload attempt.

## Durability notes

- With only the **hot** tier, availability depends on the node (and any IPFS
  peers that have fetched the CIDs). If the node is down and no peer holds the
  objects, they are unreachable until it returns.
- The **warm** tier adds off-node durability via Pinata's Filecoin-backed
  storage and makes objects reachable through the public IPFS gateway.
- Running **both** can give a node-local hot copy plus an off-node warm copy:
  each copy exists only when its own sink's pin succeeded, so a sink failure or
  a truncated batch can leave an object single-copied (the enabled
  reconciliation sweep can fill gaps for public objects later). An object
  warm-pinned before Kubo was configured can still enter the hot path when a
  later push or the sweep selects it (the dedup paragraph above).

> The two sinks are currently invoked as separate call paths. Unifying them
> behind a single pluggable backend interface (to add providers such as direct
> Filecoin deals or self-hosted clusters without touching push logic) is tracked
> separately.

## See also

- [RUN-A-NODE.md](RUN-A-NODE.md) — provisioning and running a node
- `crates/gitlawb-node/src/ipfs_pin.rs` — hot-tier implementation
- `crates/gitlawb-node/src/pinata.rs` — warm-tier implementation
