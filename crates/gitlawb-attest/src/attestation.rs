//! One typed, signed, cert-bound provenance blob.
//!
//! Fields: `type` (discriminator), `payload` (opaque, type-specific JSON),
//! `cert_hash` (binds to one ref-update cert), `signer` (`did:key`), and
//! `sig` (base64url-no-pad ed25519).
//!
//! The signature covers the domain-separated input
//! `b"gitlawb-attest-sig/v1\n"` followed by JCS-encoded `{type, payload,
//! cert_hash}` per RFC 8785. The domain tag is in the byte stream rather
//! than the canonical JSON so the wire shape stays additive: an `Attestation`
//! deserialized today and one constructed by a future `v2` signer differ only
//! by which tag the verifier prepends.
//!
//! Type discriminators are slash-separated namespace + version strings
//! (`covenant/exec/v1`, `slsa/v1.0`, `sigstore/dsse/v1`); verifiers register
//! by exact match.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{Error, Result};

/// Domain-separation tag prepended to the JCS signing input. Bumped to
/// `v2` if the signing-input shape changes.
const SIGNING_DOMAIN: &[u8] = b"gitlawb-attest-sig/v1\n";

/// Multicodec varint prefix for Ed25519 public keys (0xed 0x01).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// A signed provenance blob attached to a ref-update cert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    /// Type discriminator, e.g. `covenant/exec/v1`.
    #[serde(rename = "type")]
    pub type_: String,

    /// Type-specific payload. The verifier reparses into its concrete shape.
    pub payload: serde_json::Value,

    /// Lowercase SHA-256 hex of the cert body. Binds this attestation to one
    /// cert. The lowercase form is canonical because the JCS signing input
    /// includes this field verbatim — accepting mixed case on the wire would
    /// require both signer and verifier to normalize before computing the
    /// JCS bytes, an easy spec rule to miss across language ports.
    pub cert_hash: String,

    /// `did:key` of the signer; the verifying key is recoverable from it.
    pub signer: String,

    /// base64url-no-pad ed25519 signature over the JCS signing input.
    pub sig: String,
}

/// Type-specific payload. Implement on a struct that is `Serialize +
/// DeserializeOwned` to participate.
pub trait AttestationPayload: Serialize + DeserializeOwned + Send + Sync {
    /// The discriminator string written on the wire.
    fn payload_type() -> &'static str;
}

#[derive(Serialize)]
struct SigningInput<'a> {
    #[serde(rename = "type")]
    type_: &'a str,
    payload: &'a serde_json::Value,
    cert_hash: &'a str,
}

impl Attestation {
    /// Sign a fresh attestation. `cert_hash_bytes` comes from
    /// [`crate::cert::cert_hash`].
    pub fn sign<P: AttestationPayload>(
        signing_key: &SigningKey,
        payload: P,
        cert_hash_bytes: [u8; 32],
    ) -> Result<Self> {
        let type_ = P::payload_type().to_string();
        validate_type(&type_)?;
        let payload_value = serde_json::to_value(payload)?;
        let cert_hash_hex = hex::encode(cert_hash_bytes);

        let bytes = canonical_signing_bytes(&type_, &payload_value, &cert_hash_hex)?;
        let sig: Signature = signing_key.sign(&bytes);

        Ok(Self {
            type_,
            payload: payload_value,
            cert_hash: cert_hash_hex,
            signer: did_key_from_verifying_key(&signing_key.verifying_key()),
            sig: B64U.encode(sig.to_bytes()),
        })
    }

    /// Verify the signature and check that `cert_hash` matches
    /// `expected_cert_hash`. Returns the recovered verifying key so the caller
    /// can check it against an allowlist.
    pub fn verify_signature(&self, expected_cert_hash: [u8; 32]) -> Result<VerifyingKey> {
        let expected_hex = hex::encode(expected_cert_hash);
        if self.cert_hash != expected_hex {
            return Err(Error::CertHashMismatch);
        }

        validate_type(&self.type_)?;
        let bytes = canonical_signing_bytes(&self.type_, &self.payload, &self.cert_hash)?;

        let vk = verifying_key_from_did_key(&self.signer)?;
        self.verify_sig_with_key(&vk, &bytes)?;

        Ok(vk)
    }

    /// The signature check itself, against a key the caller supplies.
    ///
    /// Split out so the STRICTNESS of the check stays provable on its own.
    /// `verifying_key_from_did_key` now refuses a small-order key, so a weak
    /// signer can no longer reach this line through `verify_signature`. Without
    /// this seam there would be nothing left that fails when `verify_strict` is
    /// downgraded to the non-strict `verify`, and that regression would land
    /// silently. Check order in `verify_signature` is unchanged.
    fn verify_sig_with_key(&self, vk: &VerifyingKey, bytes: &[u8]) -> Result<()> {
        let sig_bytes: [u8; 64] = B64U
            .decode(&self.sig)
            .map_err(|e| Error::Signature(format!("base64url: {e}")))?
            .try_into()
            .map_err(|_| Error::Signature("signature must be 64 bytes".to_string()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(bytes, &sig)
            .map_err(|e| Error::Signature(format!("ed25519: {e}")))?;

        Ok(())
    }

    /// Reparse `payload` as `P`. Errors if the type discriminator does not
    /// match `P::payload_type()`.
    pub fn payload_as<P: AttestationPayload>(&self) -> Result<P> {
        if self.type_ != P::payload_type() {
            return Err(Error::Type(format!(
                "expected '{}', got '{}'",
                P::payload_type(),
                self.type_
            )));
        }
        Ok(P::deserialize(&self.payload)?)
    }
}

/// Discriminator grammar: nonempty, ASCII-graphic only, slash-separated
/// segments of `[a-zA-Z0-9._+-]`, no empty segment, capped at 128 bytes.
/// Matches `covenant/exec/v1`, `slsa/v1.0`, `sigstore/dsse/v1`.
fn validate_type(t: &str) -> Result<()> {
    if t.is_empty() {
        return Err(Error::Type("empty discriminator".to_string()));
    }
    if t.len() > 128 {
        return Err(Error::Type(format!(
            "discriminator longer than 128 bytes ({})",
            t.len()
        )));
    }
    if !t.is_ascii() {
        return Err(Error::Type(format!("discriminator must be ASCII: '{t}'")));
    }
    for segment in t.split('/') {
        if segment.is_empty() {
            return Err(Error::Type(format!(
                "discriminator has an empty segment: '{t}'"
            )));
        }
        for c in segment.chars() {
            if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '+' || c == '-') {
                return Err(Error::Type(format!(
                    "discriminator segment '{segment}' has disallowed character '{c}'"
                )));
            }
        }
    }
    Ok(())
}

fn canonical_signing_bytes(
    type_: &str,
    payload: &serde_json::Value,
    cert_hash_hex: &str,
) -> Result<Vec<u8>> {
    let input = SigningInput {
        type_,
        payload,
        cert_hash: cert_hash_hex,
    };
    let jcs = serde_jcs::to_vec(&input).map_err(|e| Error::Jcs(e.to_string()))?;
    let mut out = Vec::with_capacity(SIGNING_DOMAIN.len() + jcs.len());
    out.extend_from_slice(SIGNING_DOMAIN);
    out.extend_from_slice(&jcs);
    Ok(out)
}

fn did_key_from_verifying_key(key: &VerifyingKey) -> String {
    let mut buf = Vec::with_capacity(ED25519_MULTICODEC.len() + 32);
    buf.extend_from_slice(&ED25519_MULTICODEC);
    buf.extend_from_slice(&key.to_bytes());
    let encoded = multibase::encode(multibase::Base::Base58Btc, &buf);
    format!("did:key:{encoded}")
}

/// The DID:key spec mandates base58btc (multibase `z`-prefix). Other multibase
/// encodings of the same key bytes are rejected so allowlists, dedup, and
/// signer-pinning policies that compare `signer` strings remain consistent
/// across peers.
fn verifying_key_from_did_key(did: &str) -> Result<VerifyingKey> {
    let method_id = did
        .strip_prefix("did:key:")
        .ok_or_else(|| Error::Did(format!("not a did:key: {did}")))?;
    if !method_id.starts_with('z') {
        return Err(Error::Did(format!(
            "did:key must use base58btc (z-prefix): {did}"
        )));
    }
    // Refuse an oversized id before decoding. base58 decoding is quadratic in
    // its input and `signer` comes off an attacker-supplied attestation, so a
    // short request could otherwise buy a large decode. An ed25519 did:key
    // method-id is a fixed 48 characters, so this bound is slack rather than a
    // behavior change, and it only helps ahead of the decode. Mirrors the same
    // cap in gitlawb-core's Did::to_verifying_key, which this crate cannot call
    // (gitlawb-core is a dev-dependency here).
    const MAX_METHOD_ID_LEN: usize = 64;
    if method_id.len() > MAX_METHOD_ID_LEN {
        return Err(Error::Did(
            "did:key method-specific id too long".to_string(),
        ));
    }
    let (base, bytes) =
        multibase::decode(method_id).map_err(|e| Error::Did(format!("multibase: {e}")))?;
    if base != multibase::Base::Base58Btc {
        return Err(Error::Did(format!(
            "did:key must use base58btc (z-prefix): {did}"
        )));
    }
    if bytes.len() != ED25519_MULTICODEC.len() + 32
        || bytes[..ED25519_MULTICODEC.len()] != ED25519_MULTICODEC
    {
        return Err(Error::Did("not an ed25519 did:key".to_string()));
    }
    let key_bytes: [u8; 32] = bytes[ED25519_MULTICODEC.len()..]
        .try_into()
        .expect("length checked above");
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::Did(format!("invalid ed25519 key: {e}")))?;

    // `from_bytes` only decompresses, so it accepts a small-order point. This
    // crate parses did:key itself rather than going through gitlawb-core's
    // `Did`, and it cannot go through it (gitlawb-core is a dev-dependency
    // here), so the rejection is mirrored rather than inherited. Signature
    // verification is already strict, so this is defense in depth against a
    // future consumer of this parser that does not verify strictly.
    if key.is_weak() {
        return Err(Error::Did("small-order ed25519 key".to_string()));
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};

    fn fresh() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct DummyPayload {
        agent: String,
        commit: String,
    }

    impl AttestationPayload for DummyPayload {
        fn payload_type() -> &'static str {
            "test/dummy/v1"
        }
    }

    fn sample_cert_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = i as u8;
        }
        h
    }

    fn dummy_attestation(sk: &SigningKey, cert_hash: [u8; 32]) -> Attestation {
        Attestation::sign(
            sk,
            DummyPayload {
                agent: "a".to_string(),
                commit: "b".to_string(),
            },
            cert_hash,
        )
        .unwrap()
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let sk = fresh();
        let cert_hash = sample_cert_hash();
        let payload = DummyPayload {
            agent: "did:key:z6MkTest".to_string(),
            commit: "deadbeef".to_string(),
        };
        let att = Attestation::sign(&sk, payload.clone(), cert_hash).unwrap();
        let vk = att.verify_signature(cert_hash).unwrap();
        assert_eq!(vk.to_bytes(), sk.verifying_key().to_bytes());
        assert_eq!(att.payload_as::<DummyPayload>().unwrap(), payload);
    }

    #[test]
    fn cross_cert_replay_fails() {
        let sk = fresh();
        let cert_a = sample_cert_hash();
        let mut cert_b = sample_cert_hash();
        cert_b[0] ^= 0xff;
        let att = dummy_attestation(&sk, cert_a);
        let err = att.verify_signature(cert_b).unwrap_err();
        assert!(matches!(err, Error::CertHashMismatch));
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let sk = fresh();
        let cert_hash = sample_cert_hash();
        let mut att = dummy_attestation(&sk, cert_hash);
        att.payload = serde_json::json!({ "agent": "evil", "commit": "b" });
        let err = att.verify_signature(cert_hash).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    #[test]
    fn payload_as_wrong_type_errors() {
        let sk = fresh();
        let att = dummy_attestation(&sk, sample_cert_hash());

        #[derive(Debug, Serialize, Deserialize)]
        struct Wrong {
            #[allow(dead_code)]
            x: String,
        }
        impl AttestationPayload for Wrong {
            fn payload_type() -> &'static str {
                "test/other/v1"
            }
        }
        let err = att.payload_as::<Wrong>().unwrap_err();
        assert!(matches!(err, Error::Type(_)));
    }

    #[test]
    fn json_roundtrip_preserves_signature() {
        let sk = fresh();
        let cert_hash = sample_cert_hash();
        let att = dummy_attestation(&sk, cert_hash);
        let json = serde_json::to_string(&att).unwrap();
        let back: Attestation = serde_json::from_str(&json).unwrap();
        back.verify_signature(cert_hash).unwrap();
    }

    /// Wire shape is part of the public protocol — pin field names so an
    /// accidental rename surfaces as a test failure, not silent interop drift.
    #[test]
    fn wire_shape_pins_field_names() {
        let sk = fresh();
        let att = dummy_attestation(&sk, sample_cert_hash());
        let v: serde_json::Value = serde_json::to_value(&att).unwrap();
        let obj = v.as_object().expect("attestation must serialize as object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        let expected: std::collections::BTreeSet<&str> =
            ["type", "payload", "cert_hash", "signer", "sig"]
                .into_iter()
                .collect();
        assert_eq!(keys, expected);
        assert!(obj["type"].is_string());
        assert!(obj["cert_hash"].is_string());
        assert!(obj["signer"].is_string());
        assert!(obj["sig"].is_string());
    }

    /// The spec mandates lowercase hex on the wire. An uppercase cert_hash
    /// is rejected as `CertHashMismatch` so a non-canonical signer can't
    /// produce attestations that verify against some peers but not others.
    #[test]
    fn uppercase_cert_hash_is_rejected_as_non_canonical() {
        let sk = fresh();
        let cert_hash = sample_cert_hash();
        let mut att = dummy_attestation(&sk, cert_hash);
        att.cert_hash = att.cert_hash.to_uppercase();
        let err = att.verify_signature(cert_hash).unwrap_err();
        assert!(matches!(err, Error::CertHashMismatch));
    }

    #[test]
    fn empty_type_rejected_at_signing() {
        #[derive(Serialize, Deserialize)]
        struct Empty {}
        impl AttestationPayload for Empty {
            fn payload_type() -> &'static str {
                ""
            }
        }
        let sk = fresh();
        let err = Attestation::sign(&sk, Empty {}, sample_cert_hash()).unwrap_err();
        assert!(matches!(err, Error::Type(_)));
    }

    #[test]
    fn validate_type_grammar() {
        validate_type("covenant/exec/v1").unwrap();
        validate_type("slsa/v1.0").unwrap();
        validate_type("sigstore/dsse/v1").unwrap();
        validate_type("a").unwrap();
        validate_type("a.b-c_d+e/x").unwrap();

        for bad in [
            "",
            " ",
            "covenant/exec/v1 ",
            "covenant//v1",
            "/covenant/v1",
            "covenant/v1/",
            "covenant\x00exec/v1",
            "covenant/exec\nv1",
            "сovenant/exec/v1",
            "covenant/ex ec/v1",
            "covenant/exec/v1#frag",
        ] {
            let err = validate_type(bad).unwrap_err();
            assert!(matches!(err, Error::Type(_)), "must reject '{bad}'");
        }

        let too_long = "a/".repeat(70);
        let err = validate_type(&too_long).unwrap_err();
        assert!(matches!(err, Error::Type(_)));
    }

    #[test]
    fn did_key_must_be_base58btc() {
        // Sign with a real key, then re-encode the public-key bytes in a
        // different multibase. Verification must reject.
        let sk = fresh();
        let mut att = dummy_attestation(&sk, sample_cert_hash());
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        buf.extend_from_slice(&sk.verifying_key().to_bytes());
        for base in [
            multibase::Base::Base64Url,
            multibase::Base::Base32Lower,
            multibase::Base::Base16Lower,
        ] {
            att.signer = format!("did:key:{}", multibase::encode(base, &buf));
            let err = att.verify_signature(sample_cert_hash()).unwrap_err();
            assert!(matches!(err, Error::Did(_)), "must reject base {base:?}");
        }
    }

    #[test]
    fn verify_rejects_did_without_did_key_prefix() {
        let sk = fresh();
        let mut att = dummy_attestation(&sk, sample_cert_hash());
        att.signer = "ed25519:abc".to_string();
        let err = att.verify_signature(sample_cert_hash()).unwrap_err();
        assert!(matches!(err, Error::Did(_)));
    }

    #[test]
    fn verify_rejects_did_with_wrong_multicodec() {
        let sk = fresh();
        let mut att = dummy_attestation(&sk, sample_cert_hash());
        // 0x12 0x00 = sha2-256 multicodec — wrong for an ed25519 public key.
        let mut buf = vec![0x12, 0x00];
        buf.extend_from_slice(&sk.verifying_key().to_bytes());
        att.signer = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &buf)
        );
        let err = att.verify_signature(sample_cert_hash()).unwrap_err();
        assert!(matches!(err, Error::Did(_)));
    }

    #[test]
    fn verify_rejects_did_with_wrong_key_length() {
        let sk = fresh();
        let mut att = dummy_attestation(&sk, sample_cert_hash());
        let mut buf = Vec::with_capacity(33);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        // 31 bytes instead of 32.
        buf.extend_from_slice(&sk.verifying_key().to_bytes()[..31]);
        att.signer = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &buf)
        );
        let err = att.verify_signature(sample_cert_hash()).unwrap_err();
        assert!(matches!(err, Error::Did(_)));
    }

    #[test]
    fn verify_rejects_bad_signature_base64() {
        let sk = fresh();
        let mut att = dummy_attestation(&sk, sample_cert_hash());
        att.sig = "!!not-base64!!".to_string();
        let err = att.verify_signature(sample_cert_hash()).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    #[test]
    fn verify_rejects_signature_wrong_length() {
        let sk = fresh();
        let mut att = dummy_attestation(&sk, sample_cert_hash());
        att.sig = B64U.encode([0u8; 32]); // valid base64, wrong size.
        let err = att.verify_signature(sample_cert_hash()).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    /// A payload that happens to contain a `cert_hash` field of its own does
    /// not interfere with the outer binding: the attestation envelope's
    /// `cert_hash` is the only field consulted by `verify_signature`, and the
    /// payload is treated as opaque JSON throughout. A reviewer worried about
    /// shadowing or smuggling can verify this directly.
    #[test]
    fn payload_cert_hash_field_does_not_shadow_outer_binding() {
        #[derive(Serialize, Deserialize)]
        struct Sneaky {
            cert_hash: String,
            x: String,
        }
        impl AttestationPayload for Sneaky {
            fn payload_type() -> &'static str {
                "test/sneaky/v1"
            }
        }

        let sk = fresh();
        let outer_hash = sample_cert_hash();
        let att = Attestation::sign(
            &sk,
            Sneaky {
                cert_hash: "forged-by-the-attacker".to_string(),
                x: "y".to_string(),
            },
            outer_hash,
        )
        .unwrap();

        // Envelope's cert_hash is the outer (real) hash, lowercase hex.
        assert_eq!(att.cert_hash, hex::encode(outer_hash));
        // Payload retains its own field — opaque to the protocol.
        assert_eq!(
            att.payload.get("cert_hash").and_then(|v| v.as_str()),
            Some("forged-by-the-attacker"),
        );
        // Verification binds to the outer envelope's cert_hash.
        att.verify_signature(outer_hash).unwrap();
        // And rejects when the outer cert hash differs.
        let mut wrong = outer_hash;
        wrong[0] ^= 0xff;
        let err = att.verify_signature(wrong).unwrap_err();
        assert!(matches!(err, Error::CertHashMismatch));
    }

    /// A different protocol that also signs `{type, payload, cert_hash}` with
    /// the same key would still fail attestation verification because the
    /// signing input carries a domain tag the other protocol does not include.
    #[test]
    fn cross_protocol_replay_is_rejected_by_domain_separation() {
        let sk = fresh();
        let cert_hash = sample_cert_hash();
        let att = dummy_attestation(&sk, cert_hash);

        // Sign the same JCS bytes WITHOUT the domain tag and graft the
        // signature back onto the attestation.
        let cert_hash_hex = hex::encode(cert_hash);
        let bare = serde_jcs::to_vec(&SigningInput {
            type_: &att.type_,
            payload: &att.payload,
            cert_hash: &cert_hash_hex,
        })
        .unwrap();
        let other_sig: Signature = sk.sign(&bare);
        let mut tampered = att.clone();
        tampered.sig = B64U.encode(other_sig.to_bytes());

        let err = tampered.verify_signature(cert_hash).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    /// Regression guard for strict verification: a signature forged under a
    /// weak (small-order) public key satisfies the verification equation
    /// but must be rejected. The identity point is such a key: with R the
    /// identity and S = 0, [S]B - [k]A is the identity for any message.
    /// gitlawb-attest parses did:key itself and never routes through
    /// gitlawb-core's `Did`, which it cannot: gitlawb-core is a dev-dependency
    /// here. So the choke-point rejection has to be mirrored in this parser or
    /// this crate keeps handing out keys the rest of the system rejects.
    #[test]
    fn verifying_key_from_did_key_rejects_a_small_order_key() {
        let mut weak = [0u8; 32];
        weak[0] = 1; // compressed identity point
        let mut buf = Vec::with_capacity(ED25519_MULTICODEC.len() + 32);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        buf.extend_from_slice(&weak);
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &buf)
        );

        let err =
            verifying_key_from_did_key(&did).expect_err("a small-order did:key must not resolve");
        match err {
            Error::Did(msg) => assert!(
                msg.contains("small-order"),
                "rejection must name the small-order key, got: {msg}"
            ),
            other => panic!("expected Error::Did, got {other:?}"),
        }
    }

    /// base58 decoding is quadratic in its input and `signer` is attacker
    /// controlled, so an oversized method-id must be refused BEFORE the decode
    /// or a hostile attestation buys a large decode for a short request. The
    /// assertion is on the length error specifically: a multibase error here
    /// would mean the cap ran too late to matter.
    #[test]
    fn verifying_key_from_did_key_refuses_an_oversized_method_id_before_decoding() {
        let oversized = format!("did:key:z{}", "1".repeat(65_536));
        let err = verifying_key_from_did_key(&oversized)
            .expect_err("an oversized method-id must be refused");
        match err {
            Error::Did(msg) => assert!(
                msg.contains("too long"),
                "must fail on the length cap, not after decoding: {msg}"
            ),
            other => panic!("expected Error::Did, got {other:?}"),
        }
    }

    /// Strictness regression guard. The parser now refuses a small-order key,
    /// so `verify_signature` can no longer carry a weak signer down to the
    /// signature check; this drives that check directly to prove it is still
    /// STRICT. Downgrading `verify_strict` to `verify` makes this go red,
    /// which nothing else in the suite would catch.
    #[test]
    fn verify_sig_with_key_is_strict_about_a_weak_key() {
        let mut weak_key_bytes = [0u8; 32];
        weak_key_bytes[0] = 1; // compressed identity point
        let weak_vk = VerifyingKey::from_bytes(&weak_key_bytes).unwrap();
        assert!(weak_vk.is_weak());

        let cert_hash = sample_cert_hash();
        let mut att = dummy_attestation(&SigningKey::generate(&mut OsRng), cert_hash);
        // R = identity, S = 0: satisfies the non-strict verification equation
        // for any message under a small-order key.
        let mut forged = [0u8; 64];
        forged[0] = 1;
        att.sig = B64U.encode(forged);

        let bytes = canonical_signing_bytes(&att.type_, &att.payload, &att.cert_hash).expect("jcs");
        let err = att
            .verify_sig_with_key(&weak_vk, &bytes)
            .expect_err("strict verification must reject a small-order key");
        assert!(
            matches!(err, Error::Signature(_)),
            "expected a signature error, got {err:?}"
        );
    }

    /// Accept control for the seam: a genuine signature still verifies through
    /// the same helper, so the guard above is not simply rejecting everything.
    #[test]
    fn verify_sig_with_key_accepts_a_genuine_signature() {
        let cert_hash = sample_cert_hash();
        let sk = SigningKey::generate(&mut OsRng);
        let att = dummy_attestation(&sk, cert_hash);
        let bytes = canonical_signing_bytes(&att.type_, &att.payload, &att.cert_hash).expect("jcs");
        att.verify_sig_with_key(&sk.verifying_key(), &bytes)
            .expect("a real signature must verify");
    }

    /// Control for the guard above: a real did:key must still resolve.
    #[test]
    fn verifying_key_from_did_key_still_accepts_a_real_key() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let vk = sk.verifying_key();
        let mut buf = Vec::with_capacity(ED25519_MULTICODEC.len() + 32);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        buf.extend_from_slice(&vk.to_bytes());
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &buf)
        );

        let got = verifying_key_from_did_key(&did).expect("a real did:key must resolve");
        assert_eq!(got.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn verify_rejects_weak_key_signature() {
        let mut weak_key_bytes = [0u8; 32];
        weak_key_bytes[0] = 1; // compressed identity point (y = 1, x = 0)
        let weak_vk = VerifyingKey::from_bytes(&weak_key_bytes).unwrap();
        assert!(weak_vk.is_weak(), "identity point must be a weak key");

        let cert_hash = sample_cert_hash();
        let mut forged = [0u8; 64];
        forged[0] = 1; // R = identity point, S = 0
        let forged_sig = B64U.encode(forged);

        // Build an attestation with the weak key as signer and the forged
        // signature. Rejection now happens at DID RESOLUTION rather than at
        // verify time: `verifying_key_from_did_key` refuses a small-order key
        // before `verify_strict` is reached, so the observed error is
        // `Error::Did`, not `Error::Signature`. `verify_strict` remains the
        // second layer for malleability cases that do not involve a weak
        // public key (a small-order R under an honest key), which this fixture
        // cannot construct and therefore no longer covers.
        let mut att = dummy_attestation(&SigningKey::generate(&mut OsRng), cert_hash);
        let mut buf = Vec::with_capacity(ED25519_MULTICODEC.len() + 32);
        buf.extend_from_slice(&ED25519_MULTICODEC);
        buf.extend_from_slice(&weak_key_bytes);
        att.signer = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &buf)
        );
        att.sig = forged_sig;

        let err = att.verify_signature(cert_hash).unwrap_err();
        match err {
            Error::Did(msg) => assert!(
                msg.contains("small-order"),
                "weak signer must be refused as a small-order key, got: {msg}"
            ),
            other => panic!("expected Error::Did for a small-order signer, got {other:?}"),
        }
    }
}
