//! Canonical test vectors.
//!
//! Ed25519 signatures are deterministic (RFC 8032). JCS canonicalization is
//! deterministic (RFC 8785). SHA-256 is deterministic. Given fixed inputs the
//! cert hash, signature, signer DID, and full wire JSON are therefore exactly
//! reproducible across implementations. This file pins those values so a
//! port to Go, JS, Python, or any other language has a concrete oracle to
//! check against without reading Rust.
//!
//! If a vector changes, that is a wire-protocol break. The change is either
//! intentional (bump `ATTEST_ENVELOPE_VERSION` and document the migration) or
//! a regression that broke interoperability with every other implementation.

use ed25519_dalek::SigningKey;
use gitlawb_attest::{Attestation, AttestationPayload, AttestedRefUpdateCert, Registry, CERT_TYPE};
use serde::{Deserialize, Serialize};

/// Fixed seed for the attestation signer. Real signers use a CSPRNG; this is a
/// test-vector convention only.
const SIGNER_SEED: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

/// Fixed cert body for the vectors. Mirrors the field layout of a
/// `gitlawb-core::cert::RefUpdateBody` plus a `signatures` array. The
/// signatures array is deliberately non-empty to test that it is stripped
/// before hashing.
fn fixture_cert_body() -> serde_json::Value {
    serde_json::json!({
        "type": CERT_TYPE,
        "repo": "did:key:z6MkpYqTAt8jq3SExeUiVdyTrDdocy9j2NjGxFE6S6ZBh1Yt",
        "ref_name": "refs/heads/main",
        "from": "0000000000000000000000000000000000000000000000000000000000000000",
        "to": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "seq": 1,
        "timestamp": "2026-01-01T00:00:00Z",
        "nonce": "vector-nonce-1",
        "signatures": [
            {"signer": "did:key:z6MkpYqTAt8jq3SExeUiVdyTrDdocy9j2NjGxFE6S6ZBh1Yt", "sig": "ignored"}
        ]
    })
}

/// Fixed attestation payload. Shape mirrors what Covenant's runtime would
/// produce for a `covenant/exec/v1` attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ExecPayload {
    agent: String,
    capability: String,
    sandbox_digest: String,
}

impl AttestationPayload for ExecPayload {
    fn payload_type() -> &'static str {
        "covenant/exec/v1"
    }
}

fn fixture_payload() -> ExecPayload {
    ExecPayload {
        agent: "did:key:z6MkAgentTestVector".to_string(),
        capability: "code.write+sandbox.exec".to_string(),
        sandbox_digest: "sha256:c0ffee".to_string(),
    }
}

/// The expected lowercase-hex SHA-256 of `JCS(cert_body \ {signatures})`.
/// Any port that produces a different value is not JCS-canonicalizing the
/// same way (likely culprits: key ordering, integer or string escaping).
const EXPECTED_CERT_HASH_HEX: &str =
    "5898d7c7a7d32a5faaaf9a52bfc92e0eff98027554adeefba0c575816f43ce56";

/// The expected `did:key` of the signer derived from `SIGNER_SEED`. Any port
/// that produces a different value has a multibase or multicodec encoding bug.
const EXPECTED_SIGNER_DID: &str = "did:key:z6MkqkKY69DYo23W4YFDoCNgjr7cMvmJqHtJVoQkEzrbaopZ";

/// The expected base64url-no-pad Ed25519 signature over
/// `b"gitlawb-attest-sig/v1\n" || JCS({type, payload, cert_hash})`. Any port
/// that produces a different value is missing the domain tag, JCS-encoding
/// the input differently, or using a different Ed25519 implementation.
const EXPECTED_SIGNATURE_B64URL: &str =
    "4L3ONbhrksB9pn--u86lMeAdePSiZZplAsxuN2Cy6vgI30ndle7gDUVuoGRJr4Ylhz7ipQvUzXaDTvZGFLPXBQ";

#[test]
fn cert_hash_is_deterministic_from_jcs() {
    let env = AttestedRefUpdateCert::from_cert(&fixture_cert_body()).unwrap();
    let actual_hex = hex::encode(env.cert_hash().unwrap());
    assert_eq!(
        actual_hex, EXPECTED_CERT_HASH_HEX,
        "cert hash drifted — JCS encoding or hash algorithm changed",
    );
}

#[test]
fn signer_did_is_deterministic_from_seed() {
    let sk = SigningKey::from_bytes(&SIGNER_SEED);
    let env = AttestedRefUpdateCert::from_cert(&fixture_cert_body()).unwrap();
    let cert_hash = env.cert_hash().unwrap();
    let att = Attestation::sign(&sk, fixture_payload(), cert_hash).unwrap();
    assert_eq!(
        att.signer, EXPECTED_SIGNER_DID,
        "signer DID drifted — multibase or multicodec encoding changed",
    );
}

#[test]
fn attestation_signature_is_deterministic() {
    let sk = SigningKey::from_bytes(&SIGNER_SEED);
    let env = AttestedRefUpdateCert::from_cert(&fixture_cert_body()).unwrap();
    let cert_hash = env.cert_hash().unwrap();
    let att = Attestation::sign(&sk, fixture_payload(), cert_hash).unwrap();
    assert_eq!(
        att.sig, EXPECTED_SIGNATURE_B64URL,
        "signature drifted — domain tag, JCS shape, or Ed25519 implementation changed",
    );
}

#[test]
fn vector_attestation_verifies_through_the_public_api() {
    // Round-trip the entire pipeline using only the public API on the fixed
    // vectors. A non-Rust implementor should be able to:
    //   1. Compute cert_hash and check against EXPECTED_CERT_HASH_HEX.
    //   2. Derive signer DID and check against EXPECTED_SIGNER_DID.
    //   3. Sign a payload identical to fixture_payload() and check against
    //      EXPECTED_SIGNATURE_B64URL.
    //   4. Reconstruct the wire envelope and verify it round-trips.
    let sk = SigningKey::from_bytes(&SIGNER_SEED);
    let mut env = AttestedRefUpdateCert::from_cert(&fixture_cert_body()).unwrap();
    let cert_hash = env.cert_hash().unwrap();
    let att = Attestation::sign(&sk, fixture_payload(), cert_hash).unwrap();
    env.attach(att);

    let wire = serde_json::to_string(&env).unwrap();
    let back: AttestedRefUpdateCert = serde_json::from_str(&wire).unwrap();
    assert_eq!(back.attestations.len(), 1);
    assert_eq!(back.attestations[0].sig, EXPECTED_SIGNATURE_B64URL);

    let recovered = back.attestations[0]
        .verify_signature(back.cert_hash().unwrap())
        .unwrap();
    assert_eq!(recovered.to_bytes(), sk.verifying_key().to_bytes());

    // And through a registry, with the convenience method.
    let reg = Registry::new();
    let verified = back.verify_attestations(&reg).unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].cert_hash, EXPECTED_CERT_HASH_HEX);
    assert_eq!(verified[0].signer, EXPECTED_SIGNER_DID);
}
