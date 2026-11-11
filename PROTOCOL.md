# Gitlawb Wire Protocol Specification (v1, alpha)

This document describes the wire behavior a second implementation can interop
with **today**. Anything the node does not ship yet is explicitly marked
*planned*; nothing below is aspirational unless it says so.

## 1. Identity & DIDs

- **Key type:** Ed25519.
- **Method (alpha):** `did:key` only. Resolution is deterministic public-key
  extraction from the multicodec prefix (`z6Mk…`, multicodec `0xed01`).
- Signed requests presenting any other DID method are rejected; the node's
  auth layer answers with a hint that only `did:key` is supported in alpha.
- *Planned:* `did:web` and `did:gitlawb` resolution. Clients MUST NOT assume
  either is accepted anywhere yet.

## 2. Authentication (RFC 9421)

- **Transport:** signed requests are expected over TLS; the node does not
  terminate HTTP signatures over cleartext.
- **HTTP signatures:** `Signature-Input` covers `@method`, `@path`, and
  `content-digest`:
  `sig1=("@method" "@path" "content-digest");keyid="did:key:…";alg="ed25519";created=<unix>`
  All three components are mandatory: a `Signature-Input` missing one is
  rejected as `incomplete_signature`.
- **`@path` value:** the node binds `@path` to the path *and* query string of
  the request, not to the path-only value RFC 9421 defines for `@path`. A
  second implementation must sign `GET /r/info/refs?service=git-upload-pack`
  including the `?service=…` part.
- **Signer identity:** `keyid` is the actor DID (`did:key` only, see §1).
- **Integrity:** `Content-Digest` is SHA-256 over the request body and is
  verified when the header is present. Because `content-digest` is a covered
  component, every signed request signs a digest value: on a body-less
  request the signed value is the SHA-256 of the empty body, which the node
  also accepts when the header is absent entirely.

## 3. Proof of Intelligence (iCaptcha)

- **Mode:** controlled by `ICAPTCHA_MODE` = `off` | `shadow` | `enforce`,
  **default `off`**. A node with the gate off never demands proof.
- **Scope:** the gate applies to a small set of write endpoints (agent
  registration and repo create/fork), not to all writes.
- **Wire shape:** the client-supplied header is `x-icaptcha-proof` — that is
  the only iCaptcha header a node reads from a request. When proof is
  required and missing/invalid, the node answers
  `403 icaptcha_proof_required` and sets `x-icaptcha-url` and
  `x-icaptcha-level` **on the response** (also mirrored as JSON fields) so
  the client can go solve a challenge and retry.

## 4. Ref-Update Certificate

*Planned:* the `gitlawb/ref-update/v1` schema below is defined in code, but no
shipped endpoint serves or verifies these certificates today; nothing in
sections 2-3 produces one on the wire. It is documented here so a second
implementation shares the type vocabulary ahead of the wire surface.

The hash fields reserve 64 hex characters for the SHA-256 object format; the
repositories the node serves are sha1 with 40-hex OIDs (see §5), so the field
width is a forward reservation, not what a current push produces.

Two distinct certificate-shaped payloads exist; this section documents the
**core signing schema**, which is what `gitlawb/ref-update/v1` names:

- **Type string:** `gitlawb/ref-update/v1`.
- **Body (canonical JSON, the signed bytes):** `type`, `repo` (the
  repository DID), `ref_name`, `from` (previous hash, 64 hex chars,
  all-zeros for a new ref), `to` (target hash, 64 hex chars), `seq`
  (monotonically increasing, replay prevention), `timestamp` (RFC 3339),
  `nonce`.
- **Signatures:** a list of `{signer: did:key, sig: base64url-unpadded
  Ed25519}` entries appended outside the signed body; thresholds are counted
  over distinct signers that verify.

The node's REST API separately serves **push receipts** — a different,
node-issued JSON payload attesting that a push was processed. Receipts are
not `gitlawb/ref-update/v1` documents and are not interchangeable with them;
they are documented with the node's HTTP API, not here.

## 5. Storage & Git Transport

- **Object format:** bare repositories are created with
  `--object-format=sha1`; production OIDs are 40 hex chars. *Planned:*
  SHA-256 object format.
- **Smart-HTTP endpoints:**
  - `GET /{owner}/{repo}/info/refs?service=git-upload-pack` — fetch
    advertisement.
  - `GET /{owner}/{repo}/info/refs?service=git-receive-pack` — push
    advertisement.
    The `?service=` parameter is mandatory and takes exactly those two
    values; a missing parameter is a `400`, not an omitted-service default.
  - `POST /{owner}/{repo}/git-upload-pack` — clone/fetch. Request and
    response bodies are pkt-line framed; the result content type is
    `application/x-git-upload-pack-result`.
  - `POST /{owner}/{repo}/git-receive-pack` — push. **Authentication is
    mandatory**: an unsigned push is refused with `401`. Same pkt-line
    framing; the result content type is
    `application/x-git-receive-pack-result`.
    Signed requests on this path follow §2, including TLS transport.
- **Fetch vs push auth split:** fetch-side requests against a withheld or
  private repo answer `404` (existence is not confirmed to unauthorized
  callers), while the push path answers `401` for missing/invalid
  signatures. A second implementation must not treat the two symmetrically.
- **Content addressing:** the node records IPFS CID metadata per branch and
  serves it over REST (the repo `refs` endpoint maps branch heads to CIDs).
  *Planned:* IPNS-backed branch pointers; IPNS is not part of the shipped
  wire contract.
