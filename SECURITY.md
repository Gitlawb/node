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
**UCAN capability tokens**
- Issued at registration as a signed JSON envelope `{ "payload": {...}, "s": "<base64url Ed25519 signature over the payload JSON>" }` — not a JWT (#224 review: the policy must describe the actual wire format)
- Capability-scoped: `git/push`, `git/fetch`, `issue/create`, `pr/open`
- Expiry enforced on every verification
- The auth middleware (`require_ucan_chain`) verifies the full delegation chain when the `X-Ucan` header is present: the UCAN issuer must match the HTTP Signature identity, the audience must be this node's DID, and every proof in the chain must be cryptographically sound with no capability escalation

**Authorization**
- Every repo-scoped read and mutation binds the caller to an authorization decision before serving or mutating anything
- Per-repository read enforcement is wired: `authorize_repo_read` denies with the same 404 a missing repo returns, and content endpoints pass the specific path so a withheld subtree is denied even on an otherwise-public repo
- Owner-only mutations (visibility, webhooks, protected branches, merges) are gated to the repo owner; star/unstar, replica registration, and bounty actions have their own intended gates

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
- `git-receive-pack` verifies HTTP Signatures, but `GITLAWB_ENFORCE_OWNER_PUSH` defaults to `false` for compatibility during rollout.
- **Impact:** With the default setting, a valid signature authenticates the pusher but does not require that DID to be the repository owner.
- **Mitigation:** Set `GITLAWB_ENFORCE_OWNER_PUSH=true` on nodes where owner-only pushes are required. Confirm that every legitimate pusher uses the owner DID before enabling it.
### UCAN chain validation is optional per request
- The middleware verifies the full UCAN delegation chain only when the client presents an `X-Ucan` header. Requests without the header pass through unchanged, so agents that predate UCAN delegation are not forced off.
- **Impact:** A client can still authenticate with a bare RFC 9421 HTTP Signature and skip delegation-chain enforcement entirely; capability delegation is enforced only for clients that opt into presenting a UCAN.
- **Mitigation:** Keep write endpoints signed, treat public nodes as public infrastructure, and treat trust scores as soft rate-limiting signals rather than authorization.
- **Fix target:** make UCAN presentation mandatory for pushes (planned together with owner-push enforcement).

### Owner-push enforcement defaults off
- `GITLAWB_ENFORCE_OWNER_PUSH` defaults to `false`: a valid did:key HTTP Signature is authentication, not authorization, so any registered agent can push to a repo until the operator enables owner-only writes.
- **Impact:** Anyone who can register an agent can push to any repo while the flag is off.
- **Mitigation:** Enable `GITLAWB_ENFORCE_OWNER_PUSH=true` in production; keep write endpoints signed in the meantime.

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
- Per-repository private-read enforcement IS wired: `authorize_repo_read` and per-path visibility rules deny non-readers with an opaque 404, on reads and writes alike.
- **Impact:** The remaining risk is operational, not structural: a public node should still not be handed secrets, because read access is granted by the repo owner's visibility rules and any node operator can see everything stored on their own node.
- **Mitigation:** Keep secrets on isolated nodes and restrict network access at the reverse proxy or firewall layer.

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
| UCAN tokens | Signed JSON envelope (Ed25519 over the payload JSON), not JWT |
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
