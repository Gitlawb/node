# Gitlawb Wire Protocol Specification (v1)

## 1. Identity & DIDs
- **Key Type:** Ed25519 (`ed25519`).
- **Supported Methods:** `did:key`, `did:web`, and `did:gitlawb`.
- **Resolution:** Deterministic public key extraction from multicodec prefixes for verification.

## 2. Authentication (RFC 9421)
- **HTTP Signatures:** Route requests require `Signature-Input` covering `@method`, `@path`, and `content-digest`.
- **Signer Identity:** `keyid` points to the actor DID; algorithm standard is `alg="ed25519"`.
- **Integrity:** `Content-Digest` SHA-256 header validation on mutating POST/PUT endpoints.

## 3. Proof of Intelligence (iCaptcha)
- **Gate:** Enforced via `403 icaptcha_proof_required` responses.
- **Headers:** Clients must present `x-icaptcha-url`, `x-icaptcha-level`, and a valid `x-icaptcha-proof`.

## 4. Ref-Update Certificate
- **Schema:** `gitlawb/ref-update/v1`.
- **Payload:** Canonical JSON bytes including target repository, commit OID, previous OID, and actor DID.
- **Validation:** Multi-signature threshold validation against configured branch protection rules.

## 5. Storage & Git Transport
- **Smart-HTTP:** Standard `/{owner}/{repo}/info/refs` and `git-upload-pack` endpoints.
- **Content Addressing:** Git SHA-256 mapped to IPFS CID chunks with IPNS-backed branch pointers.
