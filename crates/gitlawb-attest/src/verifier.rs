//! Verifier trait, registry, and policy.
//!
//! A [`Registry`] maps a type discriminator to a verifier. [`Policy`] decides
//! what happens for types nothing is registered for: accept without trust,
//! reject, or require an allowlist.
//!
//! Under [`Policy::RequireAll`] the registry never short-circuits on unknown
//! types — any attestation can be attached by any third party, so blocking
//! the cert because an attacker added an unrelated `attacker/spam/v1` would
//! be a denial-of-service vector. Unknown types are silently treated as
//! `fully_verified = false`; the allowlist is enforced only by the
//! presence-and-verified check on `required_types` after the batch runs.

use std::collections::HashMap;

use crate::attestation::Attestation;
use crate::error::{Error, Result};

/// Verifier for one attestation type. Implementors declare the discriminator
/// they handle and validate the payload's shape. The signature and cert-hash
/// binding are checked by [`Registry::verify`] before `verify_payload` runs.
pub trait AttestationVerifier: Send + Sync {
    /// The discriminator this verifier handles. Must be a `'static` literal
    /// so the registry can key on it without copying.
    fn type_(&self) -> &'static str;

    /// Validate payload structure. Signature is already verified.
    fn verify_payload(&self, payload: &serde_json::Value) -> Result<()>;
}

/// What to do for attestation types with no registered verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// Unknown types pass but are flagged `fully_verified = false`. Default.
    #[default]
    AcceptKnown,

    /// Every entry in `required_types` must be present and fully verified.
    /// Unknown types beyond the required set are still accepted unverified,
    /// so a malicious extra attestation cannot DoS the cert.
    RequireAll,

    /// Reject every attestation whose type is not registered.
    RejectUnknown,
}

/// Result of verifying one attestation.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    /// Type discriminator.
    pub type_: String,
    /// Signer's `did:key`.
    pub signer: String,
    /// Lowercase SHA-256 hex of the cert body the attestation bound to.
    pub cert_hash: String,
    /// `true` when a verifier ran a payload check and accepted it. `false`
    /// when the policy let an unknown type through without one.
    pub fully_verified: bool,
}

/// Verifiers keyed by type discriminator.
#[derive(Default)]
pub struct Registry {
    by_type: HashMap<&'static str, Box<dyn AttestationVerifier>>,
    policy: Policy,
    required_types: Vec<String>,
}

impl Registry {
    /// Empty registry with the default policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a verifier by value. Returns the prior verifier for the same
    /// type, if any, so callers can detect double-registration.
    pub fn register<V: AttestationVerifier + 'static>(
        &mut self,
        verifier: V,
    ) -> Option<Box<dyn AttestationVerifier>> {
        self.register_boxed(Box::new(verifier))
    }

    /// Like [`Self::register`] but takes an already-boxed trait object — useful
    /// when verifiers are constructed dynamically.
    pub fn register_boxed(
        &mut self,
        verifier: Box<dyn AttestationVerifier>,
    ) -> Option<Box<dyn AttestationVerifier>> {
        let key = verifier.type_();
        self.by_type.insert(key, verifier)
    }

    /// Switch policy.
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Type discriminators that must be present and verified under
    /// `Policy::RequireAll`. Ignored under other policies.
    pub fn require_types<I, S>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_types = types.into_iter().map(Into::into).collect();
        self
    }

    /// Active policy.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Verify signature, cert-hash binding, and (if a verifier is registered)
    /// payload structure. Under `RequireAll` this is lenient on unknown types
    /// — see the module docstring.
    pub fn verify(
        &self,
        attestation: &Attestation,
        expected_cert_hash: [u8; 32],
    ) -> Result<VerifiedAttestation> {
        attestation.verify_signature(expected_cert_hash)?;

        let fully = match self.by_type.get(attestation.type_.as_str()) {
            Some(v) => {
                v.verify_payload(&attestation.payload)?;
                true
            }
            None => match self.policy {
                Policy::AcceptKnown | Policy::RequireAll => false,
                Policy::RejectUnknown => {
                    return Err(Error::UnknownType(attestation.type_.clone()));
                }
            },
        };

        Ok(VerifiedAttestation {
            type_: attestation.type_.clone(),
            signer: attestation.signer.clone(),
            cert_hash: attestation.cert_hash.clone(),
            fully_verified: fully,
        })
    }

    /// Verify a batch, then enforce `RequireAll`.
    pub fn verify_all(
        &self,
        attestations: &[Attestation],
        expected_cert_hash: [u8; 32],
    ) -> Result<Vec<VerifiedAttestation>> {
        let mut verified = Vec::with_capacity(attestations.len());
        for a in attestations {
            verified.push(self.verify(a, expected_cert_hash)?);
        }
        if self.policy == Policy::RequireAll {
            for required in &self.required_types {
                let present = verified
                    .iter()
                    .any(|v| &v.type_ == required && v.fully_verified);
                if !present {
                    return Err(Error::RequiredMissing(required.clone()));
                }
            }
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Attestation, AttestationPayload};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde::{Deserialize, Serialize};

    fn fresh() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[derive(Serialize, Deserialize)]
    struct Demo {
        a: String,
    }
    impl AttestationPayload for Demo {
        fn payload_type() -> &'static str {
            "demo/v1"
        }
    }

    struct DemoVerifier;
    impl AttestationVerifier for DemoVerifier {
        fn type_(&self) -> &'static str {
            "demo/v1"
        }
        fn verify_payload(&self, payload: &serde_json::Value) -> Result<()> {
            payload
                .get("a")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|_| ())
                .ok_or_else(|| Error::Payload("missing or empty 'a'".to_string()))
        }
    }

    /// A second verifier that has the same discriminator as `DemoVerifier` —
    /// used to test last-wins on `register`.
    struct DemoVerifierAlt;
    impl AttestationVerifier for DemoVerifierAlt {
        fn type_(&self) -> &'static str {
            "demo/v1"
        }
        fn verify_payload(&self, _payload: &serde_json::Value) -> Result<()> {
            Err(Error::Payload("alt always rejects".to_string()))
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Other {
        x: u32,
    }
    impl AttestationPayload for Other {
        fn payload_type() -> &'static str {
            "other/v1"
        }
    }

    fn sample_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        h
    }

    fn signed_demo(sk: &SigningKey, cert_hash: [u8; 32], a: &str) -> Attestation {
        Attestation::sign(sk, Demo { a: a.to_string() }, cert_hash).unwrap()
    }

    fn signed_other(sk: &SigningKey, cert_hash: [u8; 32], x: u32) -> Attestation {
        Attestation::sign(sk, Other { x }, cert_hash).unwrap()
    }

    #[test]
    fn registry_accepts_registered_type() {
        let sk = fresh();
        let cert_hash = sample_hash();
        let mut reg = Registry::new();
        reg.register(DemoVerifier);
        let att = signed_demo(&sk, cert_hash, "ok");
        let v = reg.verify(&att, cert_hash).unwrap();
        assert!(v.fully_verified);
        assert_eq!(v.type_, "demo/v1");
        assert_eq!(v.cert_hash, hex::encode(cert_hash));
    }

    #[test]
    fn accept_known_lets_unknown_pass_unverified() {
        let sk = fresh();
        let cert_hash = sample_hash();
        let reg = Registry::new().with_policy(Policy::AcceptKnown);
        let att = signed_demo(&sk, cert_hash, "ok");
        let v = reg.verify(&att, cert_hash).unwrap();
        assert!(!v.fully_verified);
    }

    #[test]
    fn reject_unknown_blocks_unregistered_types() {
        let sk = fresh();
        let cert_hash = sample_hash();
        let reg = Registry::new().with_policy(Policy::RejectUnknown);
        let att = signed_demo(&sk, cert_hash, "ok");
        let err = reg.verify(&att, cert_hash).unwrap_err();
        assert!(matches!(err, Error::UnknownType(_)));
    }

    #[test]
    fn require_all_enforces_presence() {
        let sk = fresh();
        let cert_hash = sample_hash();
        let mut reg = Registry::new()
            .with_policy(Policy::RequireAll)
            .require_types(["demo/v1"]);
        reg.register(DemoVerifier);

        let err = reg.verify_all(&[], cert_hash).unwrap_err();
        assert!(matches!(err, Error::RequiredMissing(t) if t == "demo/v1"));

        let att = signed_demo(&sk, cert_hash, "ok");
        let v = reg.verify_all(&[att], cert_hash).unwrap();
        assert_eq!(v.len(), 1);
    }

    /// Even when a junk attestation of an unrelated type is attached first, a
    /// `RequireAll` registry must still accept the cert as long as the
    /// required type is present and fully verified — the attacker shouldn't
    /// be able to DoS the cert by attaching `attacker/spam/v1` before
    /// `covenant/exec/v1`.
    #[test]
    fn require_all_is_lenient_on_unknown_types_in_the_batch() {
        let sk = fresh();
        let cert_hash = sample_hash();
        let mut reg = Registry::new()
            .with_policy(Policy::RequireAll)
            .require_types(["demo/v1"]);
        reg.register(DemoVerifier);

        let spam = signed_other(&sk, cert_hash, 7);
        let real = signed_demo(&sk, cert_hash, "ok");
        let verified = reg.verify_all(&[spam, real], cert_hash).unwrap();
        assert_eq!(verified.len(), 2);
        assert!(verified
            .iter()
            .any(|v| v.type_ == "demo/v1" && v.fully_verified));
        assert!(verified
            .iter()
            .any(|v| v.type_ == "other/v1" && !v.fully_verified));
    }

    /// A required type that is present but unverified (no verifier registered
    /// even though the type appears in `required_types`) must fail
    /// `verify_all` with `RequiredMissing`. Catches a misconfiguration where
    /// the operator listed a type but forgot to register a verifier.
    #[test]
    fn require_all_rejects_present_but_unverified_required_type() {
        let sk = fresh();
        let cert_hash = sample_hash();
        let reg = Registry::new()
            .with_policy(Policy::RequireAll)
            .require_types(["demo/v1"]); // type listed, but no verifier registered.

        let att = signed_demo(&sk, cert_hash, "ok");
        let err = reg.verify_all(&[att], cert_hash).unwrap_err();
        assert!(matches!(err, Error::RequiredMissing(t) if t == "demo/v1"));
    }

    #[test]
    fn payload_check_failure_rejects() {
        let sk = fresh();
        let cert_hash = sample_hash();
        let mut reg = Registry::new();
        reg.register(DemoVerifier);
        // Sign an empty `a` so the signature verifies but the payload check fails.
        let att = Attestation::sign(&sk, Demo { a: String::new() }, cert_hash).unwrap();
        let err = reg.verify(&att, cert_hash).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }

    /// `RequireAll` with an empty allowlist degenerates to "no required types
    /// to check" — the loop over `required_types` is a no-op, so an empty
    /// batch verifies successfully. Pinned so operators relying on the empty
    /// allowlist as a default-permissive RequireAll see consistent behavior.
    #[test]
    fn require_all_with_empty_allowlist_and_empty_batch_succeeds() {
        let reg = Registry::new().with_policy(Policy::RequireAll);
        let verified = reg.verify_all(&[], sample_hash()).unwrap();
        assert!(verified.is_empty());
    }

    #[test]
    fn register_returns_the_prior_verifier_on_double_register() {
        let mut reg = Registry::new();
        assert!(reg.register(DemoVerifier).is_none());
        let prior = reg.register(DemoVerifierAlt);
        let prior = prior.expect("second register must return the previous verifier");
        assert_eq!(prior.type_(), "demo/v1");

        // Last-wins semantics confirmed by behavior.
        let sk = fresh();
        let cert_hash = sample_hash();
        let att = signed_demo(&sk, cert_hash, "ok");
        let err = reg.verify(&att, cert_hash).unwrap_err();
        assert!(matches!(err, Error::Payload(_)));
    }
}
