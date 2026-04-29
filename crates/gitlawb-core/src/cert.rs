//! Ref-update certificates — the consensus mechanism for decentralized branch state.
//!
//! A certificate authorizes a change to a git ref (branch/tag). It must be
//! signed by the pusher and optionally countersigned by a threshold of maintainers.
//!
//! The schema is frozen at v1. All fields are mandatory for forward compatibility.
//! Nodes that receive a certificate with an unknown version MUST reject it.

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
    /// Monotonically increasing sequence number. Prevents replay.
    pub seq: u64,
    /// RFC 3339 timestamp of this update.
    pub timestamp: DateTime<Utc>,
    /// Random nonce for deduplication.
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
    pub fn satisfies_threshold(&self, maintainers: &[Did], threshold: usize) -> Result<bool> {
        let valid = self.verify_all()?;
        let count = valid.iter().filter(|d| maintainers.contains(d)).count();
        Ok(count >= threshold)
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
}
