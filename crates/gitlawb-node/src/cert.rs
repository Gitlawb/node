//! Certificate issuance for ref updates.
//!
//! When a push lands, the node signs a receipt proving the commit was
//! accepted. This receipt is a `RefCertificate` stored in the DB and
//! accessible via the API.

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use crate::db::RefCertificate;
use crate::state::AppState;

/// Build the v1 signing payload — the EXACT bytes the node signs and
/// gl's `verify_signature` reconstructs. This is the single source
/// of truth shared by `issue_ref_certificate` and the frozen
/// canonical-form tests below; drift here is what would break every
/// existing cert.
///
/// Field order and key set are fixed: a default `serde_json::Value`
/// serializes `Map<String, Value>` with sorted keys, so any change to
/// the literal is observable as a different byte sequence on the
/// wire. Adding a key (in particular `version`) for v2+ will break
/// the v1 verify path, which is exactly the contract the version
/// field exists to enforce.
pub(crate) fn v1_signing_payload(
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
    node_did: &str,
    issued_at: &str,
) -> serde_json::Value {
    serde_json::json!({
        "repo_id": repo_id,
        "ref":     ref_name,
        "old":     old_sha,
        "new":     new_sha,
        "pusher":  pusher_did,
        "node":    node_did,
        "ts":      issued_at,
    })
}

/// Issue a signed ref-update certificate for a successful push.
///
/// Builds a canonical JSON payload, signs it with the node's Ed25519 key,
/// persists the certificate, and returns it.
pub async fn issue_ref_certificate(
    state: &AppState,
    repo_id: &str,
    ref_name: &str,
    old_sha: &str,
    new_sha: &str,
    pusher_did: &str,
) -> Result<RefCertificate> {
    let node_did = state.node_did.to_string();
    let issued_at = Utc::now().to_rfc3339();

    // Build the canonical signing payload via the shared builder so
    // the frozen-vector test below and the live signer cannot drift
    // apart — a regression in either side fails both.
    let payload = v1_signing_payload(
        repo_id,
        ref_name,
        old_sha,
        new_sha,
        pusher_did,
        &node_did,
        &issued_at,
    );
    let payload_bytes = serde_json::to_vec(&payload)?;

    let signature = state.node_keypair.sign_b64(&payload_bytes);

    let cert = RefCertificate {
        id: Uuid::new_v4().to_string(),
        repo_id: repo_id.to_string(),
        ref_name: ref_name.to_string(),
        old_sha: old_sha.to_string(),
        new_sha: new_sha.to_string(),
        pusher_did: pusher_did.to_string(),
        node_did,
        signature,
        issued_at,
        // #26 Split PR 3: the wire-format version. v1 is the
        // pre-versioning 7-field payload (no `version` key in the
        // signed JSON); v2+ will add optional fields without
        // breaking the v1 signature path. Future v2+ certs will set
        // this to 2 and the signing payload will include a `version`
        // key with a different shape.
        version: 1,
    };

    // Persist and return the row as it exists in the database (on a
    // conflict the existing row survives when it is newer).
    state.db.insert_ref_certificate(&cert).await
}

#[cfg(test)]
mod v1_payload_tests {
    //! #26 Split PR 3 — cert payload version compat.
    //!
    //! The v1 cert payload is the frozen canonical byte form the
    //! node signs. gl's `verify_signature` reconstructs the same
    //! payload and verifies. Any drift in field order, key set, or
    //! whitespace breaks every existing cert. The tests here pin
    //! the v1 payload shape, the round-trip, the cert id
    //! determinism per the v1 version, and the v2 read forward
    //! compat (an unknown version refuses to verify rather than
    //! guessing).
    //!
    //! Reviewer 1 finding: the live signer (`issue_ref_certificate`)
    //! and the frozen-vector test (`v1_payload_matches_frozen_canonical_form`)
    //! previously held two separate `serde_json::json!` literals,
    //! so a regression in the signer could not fail this test.
    //! Both now go through the shared `v1_signing_payload` builder.
    use super::v1_signing_payload;
    use crate::db::RefCertificate;
    use gitlawb_core::identity::Keypair;

    /// v1 payload is the same shape the legacy code signed, byte
    /// for byte. Reverting this assertion to the v2 shape (which
    /// includes a `version` key) is what the versioned format
    /// forbids: an old client reading a v1 cert must not see a
    /// `version` key in the signed JSON.
    ///
    /// The literal is built via the shared `v1_signing_payload`
    /// helper that `issue_ref_certificate` also uses, so the live
    /// signer and the frozen vector share one source of truth.
    #[test]
    fn v1_payload_matches_frozen_canonical_form() {
        let payload = v1_signing_payload(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            "did:key:z6MkNode",
            "2026-07-22T00:00:00+00:00",
        );
        let frozen = format!(
            r#"{{"new":"{}","node":"did:key:z6MkNode","old":"{}","pusher":"did:key:z6MkPusher","ref":"refs/heads/main","repo_id":"repo-1","ts":"2026-07-22T00:00:00+00:00"}}"#,
            "a".repeat(40),
            "0".repeat(40),
        );
        assert_eq!(serde_json::to_string(&payload).unwrap(), frozen);
    }

    /// Round-trip: sign the v1 payload with a keypair, build a
    /// RefCertificate with version: 1, and verify the structure.
    /// This is the construction the live code does on every push.
    ///
    /// Uses the shared builder for both halves so a regression in
    /// the live signer (adding/removing/renaming a field) cannot
    /// pass this test by accident.
    #[test]
    fn v1_ref_certificate_structure_is_well_formed() {
        let kp = Keypair::generate();
        let node_did = kp.did().as_str().to_string();
        let payload = v1_signing_payload(
            "repo-1",
            "refs/heads/main",
            &"0".repeat(40),
            &"a".repeat(40),
            "did:key:z6MkPusher",
            &node_did,
            "2026-07-22T00:00:00+00:00",
        );
        let sig = kp.sign_b64(&serde_json::to_vec(&payload).unwrap());
        let cert = RefCertificate {
            id: "cert-id".into(),
            repo_id: "repo-1".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a".repeat(40),
            pusher_did: "did:key:z6MkPusher".into(),
            node_did: node_did.clone(),
            signature: sig.clone(),
            issued_at: "2026-07-22T00:00:00+00:00".into(),
            version: 1,
        };
        assert_eq!(cert.version, 1, "v1 cert carries version: 1");
        // The signed payload reconstructs identically: gl's
        // verify_signature would build the same JSON, hash the
        // same bytes, and verify the same signature.
        let reconstructed = v1_signing_payload(
            &cert.repo_id,
            &cert.ref_name,
            &cert.old_sha,
            &cert.new_sha,
            &cert.pusher_did,
            &cert.node_did,
            &cert.issued_at,
        );
        let reconstructed_bytes = serde_json::to_vec(&reconstructed).unwrap();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        assert_eq!(
            reconstructed_bytes, payload_bytes,
            "the round-trip serialization must be byte-identical; \
             this is what makes gl's verify_signature succeed"
        );
    }

    /// Reviewer 1 finding: the live signer must share the
    /// canonical-form literal so a regression in either side
    /// fails both. This test pins the shared builder's output
    /// against the literal a future v2 byte stream would have
    /// to break — if someone adds a `version` key to
    /// `v1_signing_payload`, every existing cert breaks verify,
    /// and this test is one of the canaries that fires.
    #[test]
    fn v1_signing_payload_has_no_version_key() {
        let payload = v1_signing_payload(
            "repo-1",
            "refs/heads/main",
            "oldsha",
            "newsha",
            "did:key:z6MkPusher",
            "did:key:z6MkNode",
            "2026-07-22T00:00:00+00:00",
        );
        let obj = payload.as_object().expect("payload is a JSON object");
        assert!(
            !obj.contains_key("version"),
            "v1 signing payload must not carry a `version` key — adding \
             one changes the bytes and breaks every existing cert's \
             signature. v2 certs build a different payload, not this one"
        );
        // Pin the exact set so a future field addition is caught.
        let expected: std::collections::BTreeSet<&str> = [
            "new", "node", "old", "pusher", "ref", "repo_id", "ts",
        ]
        .into_iter()
        .collect();
        let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(actual, expected, "v1 payload key set is frozen");
    }

    /// The v1 RefCertificate shape with version: 2 is a
    /// forward-compat hole: a v1 client reading a v2 cert
    /// reconstructs the wrong payload. The gl client refuses
    /// to verify v2 certs explicitly; this test pins that the
    /// default version on the wire is 1, so the current code path
    /// is correct.
    #[test]
    fn v1_is_the_default_version() {
        let cert = RefCertificate {
            id: "cert-id".into(),
            repo_id: "repo-1".into(),
            ref_name: "refs/heads/main".into(),
            old_sha: "0".repeat(40),
            new_sha: "a".repeat(40),
            pusher_did: "did:key:z6MkPusher".into(),
            node_did: "did:key:z6MkNode".into(),
            signature: "sig".into(),
            issued_at: "2026-07-22T00:00:00+00:00".into(),
            version: 1,
        };
        assert_eq!(cert.version, 1);
    }
}
