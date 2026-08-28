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

### Current live security controls

**Ed25519 identity and HTTP Signatures**
- Every write operation is signed with RFC 9421 HTTP Signatures
- Full Ed25519 signature verification on every authenticated request
- Keys are stored as PKCS#8 PEM files with 0600 permissions
- DIDs are derived deterministically from the public key (did:key)

**Content addressing**
- Every git object is content-addressed via CIDv1 (SHA-256)
- Tamper-evident by construction — a modified object changes its CID

**UCAN token validation**
- Bootstrap UCAN tokens are issued at registration.
- A supplied token's signature, audience, expiry, and proof-chain attenuation are validated.
- Tokens use a signed JSON wire format with expiry.
- Capability grants are not yet consulted by repository write authorization; see the limitations below.

**Smart contracts (Base Sepolia testnet)**
- `GitlawbDIDRegistry` — on-chain DID → document registry
- `GitlawbNameRegistry` — human name → DID registry
- Both auditable on-chain, no admin keys

---

## Dependency Vulnerability Status

| Area | Status |
|------|--------|
| Dependabot alerts | Current open Rust alerts were addressed by updating vulnerable dependencies, removing libp2p mDNS, and moving P2P transport from TCP/Yamux to QUIC/UDP. |

---

## Known Limitations

These are documented limitations of the current live release. They should be prioritized without breaking existing nodes during rolling upgrades.

### Repository write authorization defaults
- `git-receive-pack` verifies HTTP Signatures and, with the default configuration, also requires the pusher DID to be the repository owner: `GITLAWB_ENFORCE_OWNER_PUSH` defaults to `true`.
- **Impact:** With the default setting, a valid signature authenticates the pusher *and* the pusher must be the repository owner. Authentication is not authorization on its own — anyone can mint a `did:key` and sign — so owner enforcement is the only thing that prevents every signed caller from pushing to every repository, including private ones.
- **Mitigation:** `GITLAWB_ENFORCE_OWNER_PUSH=false` is the explicit rolling-upgrade compatibility override. Disable it only for the duration of an upgrade whose pushers are not yet the repo owner, then turn it back on. Delegated and CI keys count as non-owners: a UCAN `git/push` capability is verified but not yet honored for authorization, so they cannot push while this is on.

### UCAN delegation and revocation
- The middleware validates a supplied UCAN's complete proof chain, but a root token is accepted without an independently trusted issuer anchor. `Ucan::can` is not yet used by write handlers, so a UCAN does not grant scoped repository access.
- Agent lifecycle revocation is not checked by HTTP Signature authorization. Removing or revoking an agent record does not itself block a compromised DID from authenticating.
- **Impact:** Do not use UCANs for collaborator permissions or rely on agent-record revocation as a key-compromise response.
- **Mitigation:** Keep sensitive deployments behind operational network controls and enable owner-only push enforcement where it fits the deployment until trusted delegation and authorization-aware revocation are implemented.

### git-receive-pack authentication
- The `git-receive-pack` endpoint enforces HTTP Signature auth. Plain Git smart-HTTP clients do not generate those headers, so the `git-remote-gitlawb` helper is required for pushes.
- **Impact:** Direct HTTP pushes without RFC 9421 headers are rejected; users need `gitlawb://` remotes or equivalent signed clients.
- **Mitigation:** Use `gitlawb://` remote URLs and keep `git-remote-gitlawb` on the user's `PATH`.
- **Fix target:** v0.2

### Private repository reads
- Repository and path-scoped visibility checks are enforced for repository API and Git content reads. A denied whole-repository or root read returns the same 404 shape as a missing repository, so the denial does not reveal private-repository existence.
- Sparse-clone support exposes withheld path globs to callers who may read the repository root. Do not put sensitive information in withheld path names.
- `GET /api/v1/tasks`, `/api/v1/ipfs/pins`, and `/api/v1/arweave/anchors` are not repository-gated. Task records include a UCAN token; pin and anchor listings expose object and ref metadata.
- Changing a repository's visibility controls future serving, but cannot retract ref metadata or configured external pins and anchors already announced while the repository was public. Do not push secrets to an announceable repository.
- **Impact:** Visibility policies protect the repository and Git content routes they gate, not every metadata endpoint or previously published content.
- **Remaining boundary:** This read control does not address the independent write-authorization and UCAN-delegation limitations described above.

### Pull-request review enforcement
- Pull-request review comments are not yet threaded or line-anchored, and merges do not enforce required approvals.
- **Impact:** Teams must use their own review policy or external controls for merge approval requirements.

### GraphQL mutation coverage
- Existing GraphQL mutations require an authenticated signer, but a mutation-specific source-level guardrail has not yet been added for future mutations.
- **Impact:** A new mutation could accidentally omit its signer check without an explicit test fence.

### Peer route hardening rollout
- Peer announce and sync notification routes accept signed requests and verify DID matches when a signature is present.
- **Impact:** Unsigned peer writes are still accepted by default so existing live nodes can keep communicating during rolling upgrades.
- **Mitigation:** After all active peers run signed-node builds, operators can set `GITLAWB_REQUIRE_SIGNED_PEER_WRITES=true`.
- **Fix target:** staged rollout

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
| UCAN tokens | Signed JSON object (Ed25519 signature) |
| On-chain | ECDSA secp256k1 (Base L2 / Ethereum) |

---

## Threat Model

gitlawb is designed to be secure against:
- **Unauthenticated writes** — HTTP Signature auth on protected write endpoints; see Known Limitations for owner and capability authorization gaps
- **Tampered git objects** — CIDv1 content addressing detects modification
- **Identity spoofing** — DIDs derived from public keys, unforgeable without the private key
- **Centralized takedown** — no single point of control; data on IPFS + Arweave

gitlawb is **not yet** designed to defend against:
- A compromised node operator (node operators are trusted for their own node)
- Sybil attacks on the DHT (trust score system mitigates, not eliminates)
- Timing attacks on signature verification (not constant-time compared in v0.1)
