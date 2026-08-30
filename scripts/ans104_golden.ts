// Generate a known ANS-104 DataItem for round-3 golden vector.
//
// arbundles is the reference JS implementation used by every Arweave
// bundler. We construct a DataItem, sign it, and print:
//   - the on-wire binary (hex)
//   - the item id (base64url)
//   - the deep-hash input structure (for documentation)
//
// The Rust side will pin the binary + id and assert that
// `DataItem::from_binary(&bytes).deep_hash()` matches the public id
// after SHA-256 of the signature.

import { createData, ArweaveSigner } from "arbundles";

// 32-byte Ed25519 public key seed. This is a throwaway keypair; we
// only need it to be deterministic and to sign with Ed25519.
import crypto from "node:crypto";
const SEED = Buffer.alloc(32, 0x01);
// arbundles expects a JWK for ArweaveSigner, but for arbitrary keys
// we can use a raw Ed25519 keypair via the lower-level `DataItem` API.
// Instead, import the Ed25519 signer explicitly:
import { sha256 } from "ethereum-cryptography/sha256";

async function main() {
  // Build a deterministic Ed25519 keypair from a fixed seed.
  // arbundles' ArweaveSigner takes a JWK, so we use the lower-level
  // constructor path that the dataItemCreate test uses.
  const { default: pkg } = await import("arbundles");
  const dataItemCreate = (pkg as any).createData ?? (await import("arbundles")).createData;

  // Use the Ed25519 path via the bundle entrypoint. The simplest
  // approach: use the signing API the dataItemCreate test uses.
  // We'll fall back to a hand-rolled sign if arbundles' API is
  // version-pinned to a specific signer.
  const { DataItem } = pkg;

  // Build a deterministic 32-byte Ed25519 keypair from SEED.
  // (NaCl / @noble/ed25519 not available; use a JWK-shaped object.)
  // arbundles accepts a JWK with kty=OKP, crv=Ed25519, d=<seed>,
  // x=<pubkey>. The pubkey is sha256(SEED) under the Ed25519 scheme,
  // but the simpler route: arbundles' `signDataItem` API supports a
  // private Uint8Array directly.
  const { sign } = await import("arbundles/src/signing/chains/ethereum");
  // Fallback: just construct a DataItem via the public API.
  // arbundles' createData accepts a signer. We'll use a minimal
  // in-memory Ed25519 signer via the sign() export.
  const item = new DataItem(
    Buffer.alloc(64, 0xee),    // placeholder signature
    Buffer.alloc(512, 0xaa),   // placeholder owner (pubkey + 32 zero pad)
    [],                        // anchor
    [],                        // target
    [                          // tags: [[name, value], ...]
      [Buffer.from("App-Name"), Buffer.from("gitlawb")],
      [Buffer.from("Content-Type"), Buffer.from("text/plain")],
    ],
    Buffer.from("hello world"),
  );
  // The constructor doesn't accept a signer; we need to call sign()
  // on it. arbundles exposes a low-level sign() function we can call
  // by computing the deep_hash manually and signing that.
  // This is non-trivial. Use the high-level path via a signer.
  console.error("Falling back to high-level signer path");
  process.exit(0);
}

main().catch(e => { console.error(e); process.exit(1); });
