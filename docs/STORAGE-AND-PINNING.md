# Storage and pinning

How a gitlawb node stores git objects and keeps them available. This documents
the behavior implemented in `crates/gitlawb-node/src/ipfs_pin.rs` and
`crates/gitlawb-node/src/pinata.rs`; it does not change any behavior.

## Two-tier model

After a push lands, new git objects are pinned to up to two independent sinks.
Both are **opt-in and independent** — a node runs fine with neither, either, or
both configured.

| Tier | Sink | Module | Enabled by | Purpose |
|------|------|--------|-----------|---------|
| Hot  | Local Kubo (IPFS) | `ipfs_pin.rs` | `GITLAWB_IPFS_API` set | Node-local availability; the node is itself an IPFS peer |
| Warm | Pinata (Filecoin-backed) | `pinata.rs` | `GITLAWB_PINATA_JWT` set | Off-node durability + public IPFS gateway reachability |

If a sink's config value is empty, every call into that sink is a no-op — so
leaving `GITLAWB_PINATA_JWT` unset simply disables the warm tier.

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
(`max_concurrent_pin_tasks`). The pool **defers rather than sheds**: when it is
saturated, a pin loop waits for a slot instead of dropping the pin. Each batch is
bounded by `PIN_BATCH_BUDGET` (120s) so a single large or slow push cannot hold a
slot indefinitely. The Pinata tail re-derives its object list only *after*
acquiring a slot, which bounds outstanding memory to O(refs) rather than
O(pushes × objects).

De-duplication is per sink and best-effort: the `pinned_cids` and `pinata_cids`
tables record what each sink already holds, so later pushes normally skip objects
whose successful pin is already recorded. The check-upload-record sequence is not
atomic, so concurrent post-push tasks for the same object, or a failure to record
after a successful upload, can still cause a repeat upload attempt.

## Durability notes

- With only the **hot** tier, availability depends on the node (and any IPFS
  peers that have fetched the CIDs). If the node is down and no peer holds the
  objects, they are unreachable until it returns.
- The **warm** tier adds off-node durability via Pinata's Filecoin-backed
  storage and makes objects reachable through the public IPFS gateway.
- Running **both** gives a node-local hot copy plus an off-node warm copy.

> The two sinks are currently invoked as separate call paths. Unifying them
> behind a single pluggable backend interface (to add providers such as direct
> Filecoin deals or self-hosted clusters without touching push logic) is tracked
> separately.

## See also

- [RUN-A-NODE.md](RUN-A-NODE.md) — provisioning and running a node
- `crates/gitlawb-node/src/ipfs_pin.rs` — hot-tier implementation
- `crates/gitlawb-node/src/pinata.rs` — warm-tier implementation
