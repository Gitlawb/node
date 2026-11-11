//! Envelope around a `gitlawb/ref-update/v1` cert plus optional attestations,
//! and the cert-hash helper attestations bind to.
//!
//! An empty envelope serializes to the same bytes as the underlying bare cert.
//! `cert_hash` strips `signatures` and `attestations`, JCS-encodes the rest,
//! and SHA-256s; the result is what every attestation binds to.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attestation::Attestation;
use crate::error::{Error, Result};
use crate::verifier::{Registry, VerifiedAttestation};

/// The discriminator the wrapped cert must carry. Matches the constant of the
/// same name in `gitlawb-core::cert`.
pub const CERT_TYPE: &str = "gitlawb/ref-update/v1";

/// A ref-update cert with optional attestations.
///
/// The cert is flattened into the top-level JSON, so an empty envelope
/// produces the same bytes as a bare cert and existing decoders ignore the
/// extra `attestations` field. The cert is held as `serde_json::Value` so
/// this crate has no runtime dependency on `gitlawb-core::cert::RefUpdateCert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedRefUpdateCert {
    /// The cert body and signatures, flattened to the top level.
    #[serde(flatten)]
    pub cert: serde_json::Value,

    /// Attached attestations. Empty when absent on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<Attestation>,
}

impl AttestedRefUpdateCert {
    /// Wrap a cert. No attestations are attached yet.
    ///
    /// The serialized cert must be a JSON object whose `type` field equals
    /// [`CERT_TYPE`] and which does **not** already carry an `attestations`
    /// field. The second rule catches two cases that would otherwise leave
    /// the envelope in an inconsistent in-memory state:
    ///
    /// - Double-wrap: `from_cert(&previously_wrapped_envelope)` would put the
    ///   inner attestations on `self.cert` and leave `self.attestations` empty.
    /// - Pre-attested cert from a peer: a malformed or malicious cert with an
    ///   attached `attestations` field would survive `cert_hash` (which strips
    ///   the field) but bypass the wrapper's append-and-verify path entirely.
    ///
    /// Both are rejected with [`Error::Payload`]. To re-wrap, deserialize the
    /// envelope as `AttestedRefUpdateCert` directly.
    pub fn from_cert<T: Serialize>(cert: &T) -> Result<Self> {
        let value = serde_json::to_value(cert)?;
        let obj = value
            .as_object()
            .ok_or_else(|| Error::Payload("cert must serialize as a JSON object".to_string()))?;
        match obj.get("type").and_then(|v| v.as_str()) {
            Some(t) if t == CERT_TYPE => {}
            Some(other) => {
                return Err(Error::Payload(format!(
                    "cert type must be '{CERT_TYPE}', got '{other}'"
                )));
            }
            None => {
                return Err(Error::Payload(format!(
                    "cert missing 'type' field (expected '{CERT_TYPE}')"
                )));
            }
        }
        if obj.contains_key("attestations") {
            return Err(Error::Payload(
                "cert already carries an 'attestations' field; deserialize as \
                 AttestedRefUpdateCert directly instead of re-wrapping"
                    .to_string(),
            ));
        }
        Ok(Self {
            cert: value,
            attestations: Vec::new(),
        })
    }

    /// The 32-byte cert hash every attached attestation must bind to.
    pub fn cert_hash(&self) -> Result<[u8; 32]> {
        cert_hash(&self.cert)
    }

    /// Append an already-signed attestation.
    pub fn attach(&mut self, attestation: Attestation) {
        self.attestations.push(attestation);
    }

    /// Verify every attached attestation against this envelope's cert hash,
    /// applying the registry's policy. Equivalent to
    /// `registry.verify_all(&self.attestations, self.cert_hash()?)` but
    /// reads as one operation at call sites.
    pub fn verify_attestations(&self, registry: &Registry) -> Result<Vec<VerifiedAttestation>> {
        registry.verify_all(&self.attestations, self.cert_hash()?)
    }
}

/// SHA-256 of the cert body. The body must be a JSON object; `signatures` and
/// `attestations` are stripped before JCS encoding (RFC 8785), so the hash is
/// reproducible across languages and JSON libraries and is stable across
/// countersignatures.
pub fn cert_hash(cert: &serde_json::Value) -> Result<[u8; 32]> {
    let mut body = cert.clone();
    let obj = body
        .as_object_mut()
        .ok_or_else(|| Error::Payload("cert body must be a JSON object".to_string()))?;
    obj.remove("signatures");
    obj.remove("attestations");
    let bytes = serde_jcs::to_vec(&body).map_err(|e| Error::Jcs(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bare_cert() -> serde_json::Value {
        json!({
            "type": CERT_TYPE,
            "repo": "did:key:z6MkRepo",
            "ref_name": "refs/heads/main",
            "from": "0".repeat(64),
            "to": "a".repeat(64),
            "seq": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "nonce": "n1",
            "signatures": [{"signer": "did:key:z6MkRepo", "sig": "abc"}]
        })
    }

    #[test]
    fn empty_envelope_serializes_as_bare_cert() {
        let bare = bare_cert();
        let env = AttestedRefUpdateCert::from_cert(&bare).unwrap();
        let env_json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();

        let bare_keys: std::collections::BTreeSet<&String> =
            bare.as_object().unwrap().keys().collect();
        let env_keys: std::collections::BTreeSet<&String> =
            env_json.as_object().unwrap().keys().collect();
        assert_eq!(bare_keys, env_keys);
    }

    #[test]
    fn bare_cert_parses_as_envelope_with_no_attestations() {
        let bare = bare_cert();
        let env: AttestedRefUpdateCert = serde_json::from_value(bare.clone()).unwrap();
        assert!(env.attestations.is_empty());
        assert_eq!(env.cert, bare);
    }

    #[test]
    fn cert_hash_is_stable_across_countersignatures() {
        let base_body = json!({
            "type": CERT_TYPE,
            "repo": "did:key:z6MkRepo",
            "ref_name": "refs/heads/main",
            "from": "0".repeat(64),
            "to": "a".repeat(64),
            "seq": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "nonce": "n1"
        });

        let mut one_sig = base_body.clone();
        one_sig["signatures"] = json!([{"signer": "x", "sig": "y"}]);

        let mut two_sigs = base_body.clone();
        two_sigs["signatures"] = json!([
            {"signer": "x", "sig": "y"},
            {"signer": "a", "sig": "b"}
        ]);

        assert_eq!(cert_hash(&one_sig).unwrap(), cert_hash(&two_sigs).unwrap());
    }

    #[test]
    fn cert_hash_changes_when_body_changes() {
        let body_a = json!({
            "type": CERT_TYPE,
            "repo": "did:key:z6MkRepo",
            "ref_name": "refs/heads/main",
            "from": "0".repeat(64),
            "to": "a".repeat(64),
            "seq": 1,
            "timestamp": "2026-01-01T00:00:00Z",
            "nonce": "n1",
            "signatures": []
        });
        let mut body_b = body_a.clone();
        body_b["to"] = json!("b".repeat(64));

        assert_ne!(cert_hash(&body_a).unwrap(), cert_hash(&body_b).unwrap());
    }

    #[test]
    fn cert_hash_rejects_non_object_root() {
        let err = cert_hash(&json!(null)).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
        let err = cert_hash(&json!([1, 2, 3])).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
        let err = cert_hash(&json!("scalar")).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }

    #[test]
    fn from_cert_rejects_wrong_type() {
        let wrong = json!({"type": "gitlawb/ref-update/v0", "repo": "did:key:z"});
        let err = AttestedRefUpdateCert::from_cert(&wrong).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }

    #[test]
    fn from_cert_rejects_missing_type() {
        let no_type = json!({"repo": "did:key:z"});
        let err = AttestedRefUpdateCert::from_cert(&no_type).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }

    #[test]
    fn from_cert_rejects_non_object() {
        let arr = json!([1, 2, 3]);
        let err = AttestedRefUpdateCert::from_cert(&arr).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }

    #[test]
    fn mutating_env_cert_changes_the_hash() {
        let mut env = AttestedRefUpdateCert::from_cert(&bare_cert()).unwrap();
        let hash_before = env.cert_hash().unwrap();
        env.cert.as_object_mut().unwrap().insert(
            "nonce".to_string(),
            serde_json::Value::String("mutated".to_string()),
        );
        let hash_after = env.cert_hash().unwrap();
        assert_ne!(hash_before, hash_after);
    }

    /// A cert that already carries an `attestations` field is rejected
    /// regardless of the field's contents. Catches double-wrap (where the
    /// inner attestations would otherwise be smuggled into `self.cert`) and
    /// peer-supplied "pre-attested" certs that would bypass the wrapper.
    #[test]
    fn from_cert_rejects_preexisting_attestations_field() {
        let mut sneaky = bare_cert();
        sneaky["attestations"] = json!([{"smuggled": true}]);
        let err = AttestedRefUpdateCert::from_cert(&sneaky).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));

        // Empty array still rejected — the field's mere presence is the signal.
        let mut empty = bare_cert();
        empty["attestations"] = json!([]);
        let err = AttestedRefUpdateCert::from_cert(&empty).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }

    /// `from_cert` on an already-wrapped envelope is the same case as
    /// `from_cert` on a cert with a pre-existing `attestations` field: serde
    /// flattens the envelope back into a JSON object that carries the field.
    #[test]
    fn from_cert_rejects_a_previously_wrapped_envelope() {
        let mut env = AttestedRefUpdateCert::from_cert(&bare_cert()).unwrap();
        // Inject an attestation-shaped value so the wire round-trip would
        // actually re-emit the field.
        env.cert
            .as_object_mut()
            .unwrap()
            .insert("attestations".to_string(), json!([]));
        let err = AttestedRefUpdateCert::from_cert(&env).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }

    /// `attestations: null` is explicitly not the same as missing. The
    /// `#[serde(default)]` attribute only fills in when the key is absent —
    /// a present-but-null wire field is rejected, which surfaces malformed
    /// payloads early instead of silently treating them as empty.
    #[test]
    fn attestations_null_on_wire_is_rejected() {
        let mut with_null = bare_cert();
        with_null["attestations"] = serde_json::Value::Null;
        let err = serde_json::from_value::<AttestedRefUpdateCert>(with_null).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("expected a sequence") || msg.contains("invalid type"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn attestations_string_on_wire_is_rejected() {
        let mut with_str = bare_cert();
        with_str["attestations"] = serde_json::Value::String("oops".to_string());
        let err = serde_json::from_value::<AttestedRefUpdateCert>(with_str).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("expected a sequence") || msg.contains("invalid type"));
    }

    /// `attach` does not deduplicate. Duplicate attestations are a verifier-
    /// policy concern (e.g., "at most one SLSA provenance"), not a wrapper
    /// concern. Pinning the behavior so a future deduplication change is an
    /// intentional break.
    #[test]
    fn attach_does_not_deduplicate() {
        let mut env = AttestedRefUpdateCert::from_cert(&bare_cert()).unwrap();
        let att = Attestation {
            type_: "demo/v1".to_string(),
            payload: serde_json::json!({}),
            cert_hash: "deadbeef".to_string(),
            signer: "did:key:z6MkDup".to_string(),
            sig: "AAAA".to_string(),
        };
        env.attach(att.clone());
        env.attach(att);
        assert_eq!(env.attestations.len(), 2);
    }
}
