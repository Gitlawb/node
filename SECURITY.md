# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in gitlawb, please **do not open a public issue**.

Report it privately by emailing **security@gitlawb.com** with:
- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- (Optional) Suggested fix

We will acknowledge receipt within 48 hours and aim to release a fix within 14 days for critical issues.

---

## Current Security Architecture

### What is production-ready (v0.1)

**Ed25519 identity and HTTP Signatures**
- Every write operation is signed with RFC 9421 HTTP Signatures
- Full Ed25519 signature verification on every authenticated request
- Keys are stored as PKCS#8 PEM files with 0600 permissions
- DIDs are derived deterministically from the public key (did:key)

**Content addressing**
- Every git object is content-addressed via CIDv1 (SHA-256)
- Tamper-evident by construction — a modified object changes its CID

**UCAN capability tokens**
- Bootstrap UCAN tokens issued at registration
- Capability-scoped: `git:push`, `git:fetch`, `issue:create`, `pr:open`
- JWT-format tokens with expiry

**Smart contracts (Base Sepolia testnet)**
- `GitlawbDIDRegistry` — on-chain DID → document registry
- `GitlawbNameRegistry` — human name → DID registry
- Both auditable on-chain, no admin keys

---

## Dependency Vulnerability Status

| Crate | Advisory | Severity | Status |
|-------|----------|----------|--------|
| `rsa 0.9.x` | RUSTSEC-2023-0071 Marvin Attack | Medium | Unexploitable — bundled via `sqlx-mysql` internals; gitlawb uses PostgreSQL only, MySQL auth code is never executed. No upstream fix available. |
| `lru 0.12.x` | RUSTSEC-2026-0002 unsound IterMut | Warning | In `libp2p-swarm`; the specific unsafe code path is internal to libp2p and not reachable through gitlawb's usage. No upstream fix yet. |

---

## Known Limitations (Planned for v0.2)

These are **documented, accepted limitations** for the current testnet release. They will be addressed before mainnet.

### UCAN chain validation
- The auth middleware verifies HTTP Signatures and token structure, but does not yet walk the full UCAN delegation chain.
- **Impact:** A node cannot yet enforce fine-grained capability delegation. Currently, any registered agent with a valid HTTP Signature can push.
- **Mitigation:** Nodes can set `GITLAWB_PUBLIC_READ=false` to restrict access. The v0.1 trust score system provides soft rate limiting.
- **Fix target:** v0.2

### UCAN revocation
- Issued UCAN tokens cannot be revoked before expiry.
- **Impact:** If a keypair is compromised, the attacker retains access until the UCAN expires (default: 30 days).
- **Mitigation:** Regenerate your identity (`gl identity new --force`) and re-register to issue a new UCAN. Nodes will reject the old DID on sight if manually blocklisted.
- **Fix target:** v0.2

### git-receive-pack authentication
- The `git-receive-pack` endpoint enforces HTTP Signature auth via the `git-remote-gitlawb` remote helper. Direct HTTP push without the helper is currently unauthenticated on v0.1 nodes.
- **Impact:** A node operator accepting direct HTTP git pushes (not via `gitlawb://`) cannot verify the pusher's identity.
- **Mitigation:** Use `gitlawb://` remote URLs. Do not expose `POST /*/git-receive-pack` to untrusted networks.
- **Fix target:** v0.2

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` | Active development |
| Latest tagged release | Security fixes |

---

## Cryptographic Primitives

| Component | Algorithm |
|-----------|-----------|
| Identity keypairs | Ed25519 (ed25519-dalek v2) |
| Key storage | PKCS#8 PEM, 0600 permissions |
| Content hashing | SHA-256 via CIDv1 |
| HTTP Signatures | RFC 9421 (Ed25519 + SHA-256 Content-Digest) |
| UCAN tokens | JWT (Ed25519 signatures) |
| On-chain | ECDSA secp256k1 (Base L2 / Ethereum) |

---

## Threat Model

gitlawb is designed to be secure against:
- **Unauthorized writes** — HTTP Signature auth on all write endpoints
- **Tampered git objects** — CIDv1 content addressing detects modification
- **Identity spoofing** — DIDs derived from public keys, unforgeable without the private key
- **Centralized takedown** — no single point of control; data on IPFS + Arweave

gitlawb is **not yet** designed to defend against:
- A compromised node operator (node operators are trusted for their own node)
- Sybil attacks on the DHT (trust score system mitigates, not eliminates)
- Timing attacks on signature verification (not constant-time compared in v0.1)
