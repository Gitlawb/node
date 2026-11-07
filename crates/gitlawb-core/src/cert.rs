//! Ref-update certificates — the consensus mechanism for decentralized branch state.
//!
//! A certificate authorizes a change to a git ref (branch/tag). It must be
//! signed by the pusher and optionally countersigned by a threshold of maintainers.
//!
//! The schema is frozen at v1. All fields are mandatory for forward compatibility.
//! Nodes that receive a certificate with an unknown version MUST reject it.
//!
//! ## Replay
//!
//! A certificate proves *who* asserted a ref update and *what* they asserted.
//! It does not prove the assertion is fresh. [`RefUpdateBody::seq`] and
//! [`RefUpdateBody::nonce`] are inside the signed bytes (see
//! [`RefUpdateBody::to_signing_bytes`]), so a verifier can trust the values,
//! but deciding whether a nonce is being reused or a `seq` is going backwards
//! needs state.
//!
//! This crate is deliberately stateless — it is embedded in both nodes and
//! clients — so replay is **not** enforced here and cannot be. Ownership of
//! the check sits with the verifier that accepts and persists certificates,
//! which must:
//!
//! - reject a `nonce` it has already accepted for the same `(repo, ref_name)`;
//! - reject a `seq` that does not advance past the last accepted `seq` for
//!   that `(repo, ref_name)`.
//!
//! Until such a verifier exists, replay of ref-update certificates is not
//! enforced anywhere in this workspace. This contract exists so the first one
//! inherits the requirement instead of re-deriving it.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::did::Did;
use crate::identity::{verify, Keypair};
use crate::{Error, Result};

/// The certificate type discriminant. Always `"gitlawb/ref-update/v1"`.
pub const CERT_TYPE: &str = "gitlawb/ref-update/v1";

/// A signature on a ref-update certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSignature {
    pub signer: Did,
    /// base64url-encoded Ed25519 signature over the certificate body JSON.
    pub sig: String,
}

/// The body of a ref-update certificate (what gets signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefUpdateBody {
    /// Always `"gitlawb/ref-update/v1"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The repository DID.
    pub repo: Did,
    /// The git ref being updated (e.g. `"refs/heads/main"`).
    pub ref_name: String,
    /// The previous commit hash (SHA-256 hex). Use all-zeros for new refs.
    pub from: String,
    /// The new commit hash (SHA-256 hex).
    pub to: String,
    /// Monotonically increasing sequence number, scoped to `(repo, ref_name)`.
    ///
    /// Signed, but not enforced by this crate: core holds no state. The
    /// verifier that persists certificates must reject a `seq` that does not
    /// advance for the same repo and ref. See the module docs on replay.
    pub seq: u64,
    /// RFC 3339 timestamp of this update.
    pub timestamp: DateTime<Utc>,
    /// Random nonce, unique per certificate.
    ///
    /// Signed, but not enforced by this crate: core holds no state. The
    /// verifier that persists certificates must reject a nonce it has already
    /// accepted for the same repo and ref. See the module docs on replay.
    pub nonce: String,
}

impl RefUpdateBody {
    /// Serialize to canonical JSON bytes for signing.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// A complete ref-update certificate with at least one signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefUpdateCert {
    #[serde(flatten)]
    pub body: RefUpdateBody,
    pub signatures: Vec<CertSignature>,
}

impl RefUpdateCert {
    /// Create a new certificate and sign it with the given keypair.
    pub fn new(
        repo: Did,
        ref_name: String,
        from: String,
        to: String,
        seq: u64,
        keypair: &Keypair,
    ) -> Result<Self> {
        let body = RefUpdateBody {
            type_: CERT_TYPE.to_string(),
            repo,
            ref_name,
            from,
            to,
            seq,
            timestamp: Utc::now(),
            nonce: Uuid::new_v4().to_string(),
        };

        let signing_bytes = body.to_signing_bytes()?;
        let sig = keypair.sign_b64(&signing_bytes);

        Ok(Self {
            body,
            signatures: vec![CertSignature {
                signer: keypair.did(),
                sig,
            }],
        })
    }

    /// Add a countersignature from a maintainer keypair.
    pub fn countersign(&mut self, keypair: &Keypair) -> Result<()> {
        let signing_bytes = self.body.to_signing_bytes()?;
        let sig = keypair.sign_b64(&signing_bytes);
        self.signatures.push(CertSignature {
            signer: keypair.did(),
            sig,
        });
        Ok(())
    }

    /// Verify all signatures on this certificate.
    ///
    /// Returns the list of DIDs whose signatures are valid.
    pub fn verify_all(&self) -> Result<Vec<Did>> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let signing_bytes = self.body.to_signing_bytes()?;
        let mut valid = Vec::new();

        for cert_sig in &self.signatures {
            // Resolve the verifying key from the DID
            let vk = cert_sig.signer.to_verifying_key()?;

            let sig_bytes_vec = URL_SAFE_NO_PAD
                .decode(&cert_sig.sig)
                .map_err(|e| Error::RefCert(format!("invalid base64 sig: {e}")))?;

            let sig_bytes: [u8; 64] = sig_bytes_vec
                .try_into()
                .map_err(|_| Error::RefCert("signature must be 64 bytes".to_string()))?;

            verify(&vk, &signing_bytes, &sig_bytes)?;
            valid.push(cert_sig.signer.clone());
        }

        Ok(valid)
    }

    /// Check if this certificate satisfies a threshold of valid signatures
    /// from the provided set of authorized maintainer DIDs.
    ///
    /// Counts distinct signer DIDs, not signature entries: a repeated
    /// signature from the same maintainer counts once.
    ///
    /// `threshold` must be at least 1. Zero is rejected instead of being
    /// treated as "no signatures required": a caller that derives the
    /// threshold from configuration and gets 0 would otherwise accept any
    /// certificate, whether its signatures verify or not.
    pub fn satisfies_threshold(&self, maintainers: &[Did], threshold: usize) -> Result<bool> {
        if threshold == 0 {
            return Err(Error::RefCert("threshold must be at least 1".to_string()));
        }

        let valid = self.verify_all()?;
        let distinct_signers: HashSet<&Did> =
            valid.iter().filter(|d| maintainers.contains(d)).collect();
        Ok(distinct_signers.len() >= threshold)
    }

    /// Validate the certificate structure (not signatures).
    pub fn validate_structure(&self) -> Result<()> {
        if self.body.type_ != CERT_TYPE {
            return Err(Error::RefCert(format!(
                "unknown cert type: {}",
                self.body.type_
            )));
        }
        if self.body.from.len() != 64 || !self.body.from.chars().all(|c| c.is_ascii_hexdigit()) {
            // Allow all-zeros for new refs
            if self.body.from != "0".repeat(64) {
                return Err(Error::RefCert("invalid 'from' hash".to_string()));
            }
        }
        if self.body.to.len() != 64 || !self.body.to.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::RefCert("invalid 'to' hash".to_string()));
        }
        if self.signatures.is_empty() {
            return Err(Error::RefCert("certificate has no signatures".to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    fn dummy_hash(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn create_and_verify() {
        let kp = Keypair::generate();
        let repo_did = kp.did();
        let cert = RefUpdateCert::new(
            repo_did,
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();

        cert.validate_structure().unwrap();
        let valid = cert.verify_all().unwrap();
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0], kp.did());
    }

    #[test]
    fn countersign() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let repo_did = kp1.did();

        let mut cert = RefUpdateCert::new(
            repo_did,
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp1,
        )
        .unwrap();

        cert.countersign(&kp2).unwrap();
        let valid = cert.verify_all().unwrap();
        assert_eq!(valid.len(), 2);
    }

    #[test]
    fn threshold_check() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let repo_did = kp1.did();

        let mut cert = RefUpdateCert::new(
            repo_did.clone(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp1,
        )
        .unwrap();
        cert.countersign(&kp2).unwrap();

        let maintainers = vec![kp1.did(), kp2.did()];
        assert!(cert.satisfies_threshold(&maintainers, 2).unwrap());
        assert!(cert.satisfies_threshold(&maintainers, 1).unwrap());
    }

    #[test]
    fn serializes_to_json() {
        let kp = Keypair::generate();
        let cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('b'),
            42,
            &kp,
        )
        .unwrap();

        let json = serde_json::to_string_pretty(&cert).unwrap();
        assert!(json.contains("gitlawb/ref-update/v1"));
        assert!(json.contains("refs/heads/main"));

        // Round-trip
        let _: RefUpdateCert = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn validate_structure_rejects_wrong_cert_type() {
        let kp = Keypair::generate();
        let mut cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();
        cert.body.type_ = "gitlawb/ref-update/v0".to_string();
        assert!(cert.validate_structure().is_err());
    }

    #[test]
    fn validate_structure_rejects_invalid_to_hash() {
        let kp = Keypair::generate();
        let mut cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();
        cert.body.to = "not-a-valid-sha256".to_string();
        assert!(cert.validate_structure().is_err());
    }

    #[test]
    fn validate_structure_rejects_empty_signatures() {
        let kp = Keypair::generate();
        let mut cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();
        cert.signatures.clear();
        assert!(cert.validate_structure().is_err());
    }

    #[test]
    fn tampered_signature_fails_verify_all() {
        let kp = Keypair::generate();
        let kp2 = Keypair::generate();
        let mut cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();
        // Replace kp's signature with a signature from kp2 over different bytes.
        // The signer DID still points to kp, so verification must fail.
        cert.signatures[0].sig = kp2.sign_b64(b"unrelated bytes");
        assert!(cert.verify_all().is_err());
    }

    #[test]
    fn threshold_not_met_when_signer_outside_maintainer_list() {
        let kp_pusher = Keypair::generate();
        let kp_maintainer = Keypair::generate();

        let cert = RefUpdateCert::new(
            kp_pusher.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp_pusher,
        )
        .unwrap();

        let maintainers = vec![kp_maintainer.did()];
        assert!(!cert.satisfies_threshold(&maintainers, 1).unwrap());
    }

    #[test]
    fn satisfies_threshold_rejects_duplicated_signature() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let kp3 = Keypair::generate();
        let repo_did = kp1.did();

        let mut cert = RefUpdateCert::new(
            repo_did,
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp1,
        )
        .unwrap();
        // Copy-paste the only real signature onto the certificate a second
        // time. Same signer, same valid signature, still one real signer.
        let dup = cert.signatures[0].clone();
        cert.signatures.push(dup);

        let maintainers = vec![kp1.did(), kp2.did(), kp3.did()];
        // Two signature entries but a single distinct signer must not
        // satisfy a 2-of-3 threshold.
        assert!(!cert.satisfies_threshold(&maintainers, 2).unwrap());
    }

    #[test]
    fn threshold_zero_is_rejected() {
        let kp = Keypair::generate();
        let cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();

        // Zero must never read as "no signatures required", even with an empty
        // maintainer set.
        let err = cert.satisfies_threshold(&[], 0).unwrap_err();
        assert!(
            err.to_string().contains("threshold must be at least 1"),
            "zero must be refused as an invalid threshold"
        );
    }

    /// The threshold is checked before any signature work, so a zero is
    /// reported as a threshold error even when the certificate's signatures
    /// are also invalid. Otherwise a broken certificate would let a caller
    /// mistake the failure for a legitimate verification result.
    #[test]
    fn threshold_zero_is_rejected_before_signature_verification() {
        let kp = Keypair::generate();
        let other = Keypair::generate();
        let mut cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();
        cert.signatures[0].sig = other.sign_b64(b"unrelated bytes");

        let err = cert.satisfies_threshold(&[kp.did()], 0).unwrap_err();
        assert!(
            err.to_string().contains("threshold must be at least 1"),
            "the invalid threshold must win over the invalid signature"
        );
    }

    /// `seq` and `nonce` are the verifier's replay inputs, so they have to be
    /// inside the signed body; tapping either one must invalidate the
    /// certificate rather than leave it verifying with different values.
    #[test]
    fn replay_fields_are_covered_by_the_signature() {
        let kp = Keypair::generate();
        let cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            7,
            &kp,
        )
        .unwrap();
        cert.verify_all().expect("baseline must verify");

        let mut bumped = cert.clone();
        bumped.body.seq = 8;
        assert!(
            matches!(bumped.verify_all(), Err(Error::SignatureInvalid)),
            "changing seq must invalidate the signature"
        );

        let mut renamed = cert.clone();
        renamed.body.nonce = "different-nonce".to_string();
        assert!(
            matches!(renamed.verify_all(), Err(Error::SignatureInvalid)),
            "changing nonce must invalidate the signature"
        );
    }

    /// A signature minted by a real key must not verify when the signer is
    /// spelled in another multibase alphabet. Otherwise the same identity
    /// would satisfy a maintainer allowlist under several DID strings.
    ///
    /// Base64url is deliberate: its 47-character method-id fits under the
    /// pre-existing length bound, so this test reaches the canonical-prefix
    /// rule and fails on the pre-fix code instead of being refused for length.
    #[test]
    fn verify_all_rejects_a_non_canonical_did_spelling() {
        let kp = Keypair::generate();
        let mut cert = RefUpdateCert::new(
            kp.did(),
            "refs/heads/main".to_string(),
            dummy_hash('0'),
            dummy_hash('a'),
            1,
            &kp,
        )
        .unwrap();

        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&kp.verifying_key().to_bytes());
        cert.signatures[0].signer = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base64Url, &prefixed)
        )
        .parse()
        .expect("method is still `key`");

        let err = cert
            .verify_all()
            .expect_err("a non-canonical did:key spelling must not resolve");
        assert!(
            err.to_string().contains("base58btc"),
            "rejection must come from the canonical-prefix rule, not the length guard"
        );
        assert!(
            !matches!(
                cert.satisfies_threshold(&[cert.signatures[0].signer.clone()], 1),
                Ok(true)
            ),
            "the alternate spelling must not satisfy a threshold"
        );

        // The canonical spelling of the same key is unaffected.
        cert.signatures[0].signer = kp.did();
        assert!(cert.satisfies_threshold(&[kp.did()], 1).unwrap());
    }
}
