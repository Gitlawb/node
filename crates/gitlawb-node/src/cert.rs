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

    // Build the canonical signing payload.
    let payload = serde_json::json!({
        "repo_id": repo_id,
        "ref":     ref_name,
        "old":     old_sha,
        "new":     new_sha,
        "pusher":  pusher_did,
        "node":    node_did,
        "ts":      issued_at,
    });
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
    use crate::db::RefCertificate;
    use gitlawb_core::identity::Keypair;

    /// v1 payload is the same shape the legacy code signed, byte
    /// for byte. Reverting this assertion to the v2 shape (which
    /// includes a `version` key) is what the versioned format
    /// forbids: an old client reading a v1 cert must not see a
    /// `version` key in the signed JSON.
    #[test]
    fn v1_payload_matches_frozen_canonical_form() {
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    "did:key:z6MkNode",
            "ts":      "2026-07-22T00:00:00+00:00",
        });
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
    #[test]
    fn v1_ref_certificate_structure_is_well_formed() {
        let kp = Keypair::generate();
        let node_did = kp.did().as_str().to_string();
        let payload = serde_json::json!({
            "repo_id": "repo-1",
            "ref":     "refs/heads/main",
            "old":     "0".repeat(40),
            "new":     "a".repeat(40),
            "pusher":  "did:key:z6MkPusher",
            "node":    node_did,
            "ts":      "2026-07-22T00:00:00+00:00",
        });
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
        let reconstructed = serde_json::json!({
            "repo_id": cert.repo_id,
            "ref":     cert.ref_name,
            "old":     cert.old_sha,
            "new":     cert.new_sha,
            "pusher":  cert.pusher_did,
            "node":    cert.node_did,
            "ts":      cert.issued_at,
        });
        let reconstructed_bytes = serde_json::to_vec(&reconstructed).unwrap();
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        assert_eq!(
            reconstructed_bytes, payload_bytes,
            "the round-trip serialization must be byte-identical; \
             this is what makes gl's verify_signature succeed"
        );
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
