//! Pluggable provenance attachments for gitlawb ref-update certs.
//!
//! A `gitlawb/ref-update/v1` cert proves who pushed and where a ref moved to.
//! It does not say how the commit was produced. This crate adds an optional
//! `attestations` field that lets any provenance system (SLSA, Sigstore,
//! in-toto, agent runtimes) attach a typed, signed blob bound to the cert by
//! its hash.
//!
//! The cert format stays additive. A cert with no attestations serializes the
//! same bytes it does today, and existing decoders (which do not set
//! `deny_unknown_fields`) silently drop the new `attestations` field rather
//! than reject the cert.
//!
//! ## Wire shape
//!
//! ```json
//! {
//!   "type": "gitlawb/ref-update/v1",
//!   // ...standard cert fields...,
//!   "signatures": [...],
//!   "attestations": [
//!     {
//!       "type": "covenant/exec/v1",
//!       "payload": { /* opaque, type-specific */ },
//!       "cert_hash": "<sha256 hex of JCS-encoded cert body>",
//!       "signer":    "did:key:z6Mk...",
//!       "sig":       "<base64url ed25519 over the signing input>"
//!     }
//!   ]
//! }
//! ```
//!
//! ## Canonical bytes
//!
//! Hashing and signing inputs use JCS (RFC 8785) so they reproduce across
//! implementations regardless of struct field order or JSON library.
//!
//! The cert hash is `SHA-256(JCS(cert_body_without_signatures_or_attestations))`,
//! expressed as lowercase hex on the wire. Uppercase is non-canonical and
//! rejected on verify so the JCS signing input is uniquely determined by the
//! cert bytes alone — there is no implicit normalization rule that
//! cross-language signers might miss.
//!
//! The attestation signing input is the byte string
//! `b"gitlawb-attest-sig/v1\n" || JCS({type, payload, cert_hash})`. The
//! domain tag is in the byte stream, not the canonical JSON, so an attestation
//! cannot be confused with a same-shape JCS document signed for a different
//! protocol that uses the same Ed25519 key.
//!
//! ## DID:key
//!
//! Signers are `did:key` DIDs over Ed25519, encoded with the multibase
//! base58btc (`z`) prefix per the W3C DID:key specification. Non-base58btc
//! encodings of the same public key are rejected on verify so allowlists,
//! deduplication, and signer-pinning policies that compare `signer` strings
//! stay consistent across peers.
//!
//! ## Verification
//!
//! [`Registry`] looks up a verifier by type discriminator. [`Policy`] decides
//! what to do when no verifier matches: `AcceptKnown` (default) lets unknown
//! types pass without trust; `RequireAll` enforces a per-repo allowlist while
//! still letting unrelated attached attestations through unverified (so a
//! third-party attachment cannot DoS the cert); `RejectUnknown` rejects
//! anything unregistered.
//!
//! ## Quick start
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use gitlawb_attest::{
//!     Attestation, AttestationPayload, AttestationVerifier, AttestedRefUpdateCert,
//!     Error, Policy, Registry, Result, CERT_TYPE,
//! };
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct ExecPayload { agent: String }
//! impl AttestationPayload for ExecPayload {
//!     fn payload_type() -> &'static str { "covenant/exec/v1" }
//! }
//!
//! struct ExecVerifier;
//! impl AttestationVerifier for ExecVerifier {
//!     fn type_(&self) -> &'static str { "covenant/exec/v1" }
//!     fn verify_payload(&self, payload: &serde_json::Value) -> Result<()> {
//!         payload.get("agent").and_then(|v| v.as_str())
//!             .ok_or_else(|| Error::Payload("missing agent".into()))?;
//!         Ok(())
//!     }
//! }
//!
//! # fn run() -> Result<()> {
//! let cert = serde_json::json!({
//!     "type": CERT_TYPE, "repo": "did:key:z6MkRepo",
//!     "ref_name": "refs/heads/main",
//!     "from": "0".repeat(64), "to": "a".repeat(64),
//!     "seq": 1, "timestamp": "2026-01-01T00:00:00Z", "nonce": "n1",
//!     "signatures": []
//! });
//! let mut env = AttestedRefUpdateCert::from_cert(&cert)?;
//!
//! let sk = SigningKey::from_bytes(&[7u8; 32]);
//! let payload = ExecPayload { agent: "did:key:z6MkAgent".into() };
//! let att = Attestation::sign(&sk, payload, env.cert_hash()?)?;
//! env.attach(att);
//!
//! let mut registry = Registry::new().with_policy(Policy::RejectUnknown);
//! registry.register(ExecVerifier);
//! let verified = env.verify_attestations(&registry)?;
//! assert_eq!(verified[0].type_, "covenant/exec/v1");
//! assert!(verified[0].fully_verified);
//! # Ok(()) }
//! # run().unwrap();
//! ```

pub mod attestation;
pub mod cert;
pub mod error;
pub mod verifier;

pub use attestation::{Attestation, AttestationPayload};
pub use cert::{cert_hash, AttestedRefUpdateCert, CERT_TYPE};
pub use error::{Error, Result};
pub use verifier::{AttestationVerifier, Policy, Registry, VerifiedAttestation};

/// Version string for the attestation envelope wire shape.
///
/// Bumped only when the binding rules — JCS input shape, domain-separation
/// tag, hash algorithm — change. Independent of [`CERT_TYPE`], which versions
/// the underlying ref-update cert.
pub const ATTEST_ENVELOPE_VERSION: &str = "v1";
