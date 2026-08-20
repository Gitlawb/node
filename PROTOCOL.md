# Gitlawb Wire Protocol Specification (v1)

## 1. Identity & DIDs
- **Key Types:** Ed25519 (`ed25519`).
- **Methods:** `did:key`, `did:web`, `did:gitlawb`.
- **Resolution:** Deterministic public key extraction from multicodec prefixes.

## 2. Authentication (RFC 9421)
- **HTTP Signatures:** Requires `Signature-Input` covering `@method`, `@path`, and `content-digest`.
- **Signer Identity:** `keyid` points to the actor DID; algorithm is `alg="ed25519"`.
- **Integrity:** SHA-256 `Content-Digest` verification on write endpoints.

## 3. Proof of Intelligence (iCaptcha)
- **Gate:** Enforced via `403 icaptcha_proof_required` responses.
- **Headers:** Clients must present `x-icaptcha-url`, `x-icaptcha-level`, and `x-icaptcha-proof`.

## 4. Ref-Update Certificate
- **Schema:** `gitlawb/ref-update/v1`.
- **Payload:** Canonical JSON bytes defining target repo, commit OID, previous OID, and actor DID.

## 5. Storage & Git Transport
- **Smart-HTTP:** Endpoints at `/{owner}/{repo}/info/refs` and `git-upload-pack`.
- **Content Addressing:** Git SHA-256 mapped to IPFS CID chunks with IPNS-backed branch pointers.
