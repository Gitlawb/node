//! End-to-end integration with `gitlawb-core`.
//!
//! Proves the attest envelope composes with the real `RefUpdateCert` from
//! `gitlawb-core`: a cert built and signed through the core API wraps cleanly,
//! survives signing and verifying an attestation, and round-trips back to a
//! `RefUpdateCert` that core still verifies. None of this is exercised by the
//! unit tests in `cert.rs`, which use hand-written JSON literals to keep the
//! crate's runtime deps minimal.

use ed25519_dalek::SigningKey;
use gitlawb_attest::{
    Attestation, AttestationPayload, AttestationVerifier, AttestedRefUpdateCert, Error, Policy,
    Registry, Result as AttestResult,
};
use gitlawb_core::cert::RefUpdateCert;
use gitlawb_core::identity::Keypair;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

fn zero_hash() -> String {
    "0".repeat(64)
}

fn commit_hash(c: char) -> String {
    c.to_string().repeat(64)
}

fn fresh_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct CovenantExecPayload {
    agent: String,
    capability: String,
    sandbox_digest: String,
}

impl AttestationPayload for CovenantExecPayload {
    fn payload_type() -> &'static str {
        "covenant/exec/v1"
    }
}

struct CovenantExecVerifier;

impl AttestationVerifier for CovenantExecVerifier {
    fn type_(&self) -> &'static str {
        "covenant/exec/v1"
    }

    fn verify_payload(&self, payload: &serde_json::Value) -> AttestResult<()> {
        for field in ["agent", "capability", "sandbox_digest"] {
            payload
                .get(field)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::Payload(format!("missing or empty '{field}'")))?;
        }
        Ok(())
    }
}

#[test]
fn wraps_real_cert_signs_and_verifies_attestation_then_unwraps_cleanly() {
    // 1. Build a real cert through gitlawb-core. The pusher is the repo owner
    //    in this minimal setup; the cert is single-signature.
    let pusher = Keypair::generate();
    let repo_did = pusher.did();
    let cert = RefUpdateCert::new(
        repo_did,
        "refs/heads/main".to_string(),
        zero_hash(),
        commit_hash('a'),
        1,
        &pusher,
    )
    .unwrap();
    cert.validate_structure().unwrap();
    let valid_signers = cert.verify_all().unwrap();
    assert_eq!(valid_signers.len(), 1);

    // 2. Wrap. With no attestations attached the envelope is byte-identical to
    //    the underlying cert — that's the additive-on-the-wire promise.
    let cert_json = serde_json::to_value(&cert).unwrap();
    let mut env = AttestedRefUpdateCert::from_cert(&cert).unwrap();
    assert_eq!(
        serde_json::to_value(&env).unwrap(),
        cert_json,
        "empty envelope must serialize as the bare cert"
    );

    // 3. A separate party (here, an agent runtime) attests to how the commit
    //    was produced. The attestation signer is intentionally not the cert
    //    pusher: trust in the attestation is evaluated independently of trust
    //    in the push.
    let agent_signer = fresh_signing_key();
    let payload = CovenantExecPayload {
        agent: "did:key:z6MkAgent".to_string(),
        capability: "code.write+sandbox.exec".to_string(),
        sandbox_digest: "sha256:c0ffee".to_string(),
    };
    let cert_hash = env.cert_hash().unwrap();
    let attestation = Attestation::sign(&agent_signer, payload.clone(), cert_hash).unwrap();
    env.attach(attestation);

    // 4. Verify through a registry that knows `covenant/exec/v1`. Strict
    //    policy so an unknown discriminator would have been rejected.
    let mut registry = Registry::new().with_policy(Policy::RejectUnknown);
    registry.register(CovenantExecVerifier);
    let verified = registry
        .verify_all(&env.attestations, env.cert_hash().unwrap())
        .unwrap();
    assert_eq!(verified.len(), 1);
    assert!(verified[0].fully_verified);
    assert_eq!(verified[0].type_, "covenant/exec/v1");
    assert_eq!(verified[0].cert_hash, hex::encode(cert_hash));

    // 5. Round-trip through JSON and back. The wrapped cert with one
    //    attestation must parse back into the same envelope, and stripping
    //    the attestations must yield a `RefUpdateCert` core still verifies.
    let on_wire = serde_json::to_string(&env).unwrap();
    let back: AttestedRefUpdateCert = serde_json::from_str(&on_wire).unwrap();
    assert_eq!(back.attestations.len(), 1);
    assert_eq!(
        back.attestations[0]
            .payload_as::<CovenantExecPayload>()
            .unwrap(),
        payload
    );

    let mut unwrapped = back.cert.clone();
    if let Some(obj) = unwrapped.as_object_mut() {
        obj.remove("attestations");
    }
    let unwrapped_cert: RefUpdateCert = serde_json::from_value(unwrapped).unwrap();
    let revalidated = unwrapped_cert.verify_all().unwrap();
    assert_eq!(revalidated, valid_signers);
}

#[test]
fn cert_hash_is_stable_when_a_maintainer_countersigns() {
    // The cert hash strips `signatures` before hashing, so countersignatures
    // added after an attestation is signed must not invalidate the
    // attestation's binding.
    let pusher = Keypair::generate();
    let maintainer = Keypair::generate();
    let mut cert = RefUpdateCert::new(
        pusher.did(),
        "refs/heads/main".to_string(),
        zero_hash(),
        commit_hash('b'),
        7,
        &pusher,
    )
    .unwrap();

    let env_before = AttestedRefUpdateCert::from_cert(&cert).unwrap();
    let hash_before = env_before.cert_hash().unwrap();

    cert.countersign(&maintainer).unwrap();
    let env_after = AttestedRefUpdateCert::from_cert(&cert).unwrap();
    let hash_after = env_after.cert_hash().unwrap();

    assert_eq!(
        hash_before, hash_after,
        "cert hash must be stable across countersignatures"
    );

    // An attestation signed against the pre-countersign hash still verifies
    // against the post-countersign cert.
    let agent = fresh_signing_key();
    let payload = CovenantExecPayload {
        agent: "did:key:z6MkAgent2".to_string(),
        capability: "code.write".to_string(),
        sandbox_digest: "sha256:deadbeef".to_string(),
    };
    let attestation = Attestation::sign(&agent, payload, hash_before).unwrap();
    attestation.verify_signature(hash_after).unwrap();
}

#[test]
fn cross_cert_replay_is_rejected_against_a_real_cert() {
    // Negative case: an attestation signed for one cert must not verify on a
    // different cert built through the core API.
    let pusher = Keypair::generate();
    let cert_a = RefUpdateCert::new(
        pusher.did(),
        "refs/heads/main".to_string(),
        zero_hash(),
        commit_hash('a'),
        1,
        &pusher,
    )
    .unwrap();
    let cert_b = RefUpdateCert::new(
        pusher.did(),
        "refs/heads/main".to_string(),
        commit_hash('a'),
        commit_hash('b'),
        2,
        &pusher,
    )
    .unwrap();

    let env_a = AttestedRefUpdateCert::from_cert(&cert_a).unwrap();
    let env_b = AttestedRefUpdateCert::from_cert(&cert_b).unwrap();
    let hash_a = env_a.cert_hash().unwrap();
    let hash_b = env_b.cert_hash().unwrap();
    assert_ne!(hash_a, hash_b);

    let agent = fresh_signing_key();
    let payload = CovenantExecPayload {
        agent: "did:key:z6MkAgent3".to_string(),
        capability: "code.write".to_string(),
        sandbox_digest: "sha256:cafe".to_string(),
    };
    let attestation = Attestation::sign(&agent, payload, hash_a).unwrap();
    let err = attestation.verify_signature(hash_b).unwrap_err();
    assert!(matches!(err, Error::CertHashMismatch));
}

/// A cert deserialized from JSON and a cert built through the core API must
/// hash identically. JCS canonicalization is what makes the additive-on-wire
/// promise hold across the serialize/deserialize boundary — without it, the
/// hash would depend on which side built the `serde_json::Value`.
#[test]
fn cert_hash_is_identical_across_the_deserialize_boundary() {
    let pusher = Keypair::generate();
    let cert = RefUpdateCert::new(
        pusher.did(),
        "refs/heads/main".to_string(),
        zero_hash(),
        commit_hash('c'),
        9,
        &pusher,
    )
    .unwrap();

    let direct_hash = AttestedRefUpdateCert::from_cert(&cert)
        .unwrap()
        .cert_hash()
        .unwrap();

    let wire = serde_json::to_string(&cert).unwrap();
    let parsed_value: serde_json::Value = serde_json::from_str(&wire).unwrap();
    let parsed_env: AttestedRefUpdateCert = serde_json::from_value(parsed_value).unwrap();
    let parsed_hash = parsed_env.cert_hash().unwrap();

    assert_eq!(direct_hash, parsed_hash);
}
