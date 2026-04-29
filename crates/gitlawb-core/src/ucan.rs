//! UCAN (User Controlled Authorization Networks) — capability token types.
//!
//! UCANs let a DID delegate specific capabilities to another DID,
//! with optional expiry and revocation. gitlawb uses UCANs for:
//!   - Delegating push access to a branch to a CI agent
//!   - Granting a reviewer the ability to approve PRs
//!   - Bootstrap tokens issued at registration
//!
//! This module provides the data types and serialization.
//! Cryptographic verification is handled by `identity::verify`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};
use crate::did::Did;
use crate::identity::Keypair;

/// A UCAN capability: what resource the token grants access to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// The resource URI. e.g. `"gitlawb://repos/gitlawb/gitlawb"`
    pub with: String,
    /// The action. e.g. `"git/push"`, `"pr/open"`, `"issue/create"`, `"network/join"`
    pub can: String,
    /// Optional constraints on the capability.
    #[serde(rename = "nb", skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
}

impl Capability {
    pub fn new(with: impl Into<String>, can: impl Into<String>) -> Self {
        Self { with: with.into(), can: can.into(), constraints: None }
    }

    pub fn with_constraints(mut self, constraints: serde_json::Value) -> Self {
        self.constraints = Some(constraints);
        self
    }
}

/// Well-known gitlawb capability strings.
pub mod caps {
    pub const GIT_PUSH: &str = "git/push";
    pub const GIT_FETCH: &str = "git/fetch";
    pub const PR_OPEN: &str = "pr/open";
    pub const PR_MERGE: &str = "pr/merge";
    pub const PR_REVIEW: &str = "pr/review";
    pub const ISSUE_CREATE: &str = "issue/create";
    pub const ISSUE_CLOSE: &str = "issue/close";
    pub const NETWORK_JOIN: &str = "network/join";
    pub const AGENT_DEPLOY: &str = "agent/deploy";
    pub const REPO_ADMIN: &str = "repo/admin";
}

/// The UCAN payload (what gets signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcanPayload {
    /// UCAN version. Always "1.0.0".
    pub ucan: String,
    /// Issuer DID — who is granting this capability.
    pub iss: Did,
    /// Audience DID — who receives this capability.
    pub aud: Did,
    /// The capabilities being granted.
    pub att: Vec<Capability>,
    /// Expiry as Unix timestamp (seconds). None = no expiry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Not-before as Unix timestamp. None = valid immediately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Proof chain — UCANs that authorize the issuer to delegate.
    /// Empty for root capabilities (self-issued by a repo owner).
    #[serde(default)]
    pub prf: Vec<String>,
}

/// A signed UCAN token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ucan {
    pub payload: UcanPayload,
    /// base64url-encoded Ed25519 signature over the payload JSON.
    pub s: String,
}

impl Ucan {
    /// Issue a new UCAN token.
    pub fn issue(
        issuer: &Keypair,
        audience: Did,
        capabilities: Vec<Capability>,
        exp: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        let payload = UcanPayload {
            ucan: "1.0.0".to_string(),
            iss: issuer.did(),
            aud: audience,
            att: capabilities,
            exp: exp.map(|e| e.timestamp()),
            nbf: None,
            prf: vec![],
        };

        let signing_bytes = serde_json::to_vec(&payload)?;
        let sig = issuer.sign_b64(&signing_bytes);

        Ok(Self { payload, s: sig })
    }

    /// Issue a bootstrap UCAN — grants `network/join` on the alpha network.
    pub fn bootstrap(issuer: &Keypair, audience: Did) -> Result<Self> {
        let exp = chrono::Utc::now() + chrono::Duration::days(30);
        Self::issue(
            issuer,
            audience,
            vec![Capability::new("gitlawb://alpha", caps::NETWORK_JOIN)],
            Some(exp),
        )
    }

    /// Check if this UCAN has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.payload.exp {
            Utc::now().timestamp() > exp
        } else {
            false
        }
    }

    /// Verify the signature on this UCAN.
    pub fn verify_signature(&self) -> Result<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use crate::identity::verify;

        let vk = self.payload.iss.to_verifying_key()?;
        let signing_bytes = serde_json::to_vec(&self.payload)?;

        let sig_bytes_vec = URL_SAFE_NO_PAD.decode(&self.s)
            .map_err(|e| Error::Ucan(format!("invalid base64 signature: {e}")))?;

        let sig_bytes: [u8; 64] = sig_bytes_vec.try_into()
            .map_err(|_| Error::Ucan("signature must be 64 bytes".to_string()))?;

        verify(&vk, &signing_bytes, &sig_bytes)
            .map_err(|_| Error::Ucan("signature verification failed".to_string()))
    }

    /// Check if this UCAN grants a specific capability on a resource.
    pub fn can(&self, resource: &str, action: &str) -> bool {
        self.payload.att.iter().any(|cap| {
            cap.with == resource && cap.can == action
        })
    }

    /// Encode to a compact JSON string (the wire format).
    pub fn encode(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Decode from a JSON string.
    pub fn decode(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::Ucan(e.to_string()))
    }

    /// Issue a UCAN with proof chain — delegates from a parent UCAN.
    ///
    /// The issuer must be the audience of the parent UCAN (the entity
    /// that received the capability). The parent's encoded token is
    /// included in the `prf` field.
    pub fn delegate(
        issuer: &Keypair,
        audience: Did,
        capabilities: Vec<Capability>,
        exp: Option<DateTime<Utc>>,
        proof: &Ucan,
    ) -> Result<Self> {
        let proof_token = proof.encode()?;
        let payload = UcanPayload {
            ucan: "1.0.0".to_string(),
            iss: issuer.did(),
            aud: audience,
            att: capabilities,
            exp: exp.map(|e| e.timestamp()),
            nbf: None,
            prf: vec![proof_token],
        };

        let signing_bytes = serde_json::to_vec(&payload)?;
        let sig = issuer.sign_b64(&signing_bytes);

        Ok(Self { payload, s: sig })
    }

    /// Verify the full proof chain of this UCAN.
    ///
    /// For each proof in the `prf` field:
    /// 1. Decode and verify its signature
    /// 2. Ensure the proof's audience matches this UCAN's issuer
    ///    (the entity that received the capability must be the one delegating)
    /// 3. Check the proof is not expired
    /// 4. Recursively verify the proof's own chain
    ///
    /// A UCAN with no proofs (root capability) passes trivially.
    pub fn verify_chain(&self) -> Result<()> {
        // First verify our own signature
        self.verify_signature()?;

        if self.is_expired() {
            return Err(Error::Ucan("token is expired".to_string()));
        }

        for proof_token in &self.payload.prf {
            let proof = Self::decode(proof_token)
                .map_err(|e| Error::Ucan(format!("failed to decode proof: {e}")))?;

            // The proof's audience must be this UCAN's issuer
            if proof.payload.aud != self.payload.iss {
                return Err(Error::Ucan(format!(
                    "proof chain broken: proof audience {} does not match issuer {}",
                    proof.payload.aud, self.payload.iss
                )));
            }

            // Verify the proof's signature and chain recursively
            proof.verify_chain()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    #[test]
    fn issue_and_verify() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();

        let ucan = Ucan::issue(
            &issuer,
            audience.clone(),
            vec![Capability::new("gitlawb://repos/test/repo", caps::GIT_PUSH)],
            None,
        ).unwrap();

        ucan.verify_signature().unwrap();
        assert!(!ucan.is_expired());
        assert_eq!(ucan.payload.iss, issuer.did());
        assert_eq!(ucan.payload.aud, audience);
        assert!(ucan.can("gitlawb://repos/test/repo", caps::GIT_PUSH));
        assert!(!ucan.can("gitlawb://repos/test/repo", caps::PR_MERGE));
    }

    #[test]
    fn bootstrap_ucan() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let ucan = Ucan::bootstrap(&issuer, audience).unwrap();
        ucan.verify_signature().unwrap();
        assert!(ucan.can("gitlawb://alpha", caps::NETWORK_JOIN));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let ucan = Ucan::bootstrap(&issuer, audience).unwrap();
        let encoded = ucan.encode().unwrap();
        let decoded = Ucan::decode(&encoded).unwrap();
        assert_eq!(ucan.payload.iss, decoded.payload.iss);
        assert_eq!(ucan.payload.aud, decoded.payload.aud);
        decoded.verify_signature().unwrap();
    }

    #[test]
    fn capability_with_constraints() {
        use serde_json::json;
        let cap = Capability::new("gitlawb://repos/org/repo", caps::GIT_PUSH)
            .with_constraints(json!({ "branch": "refs/heads/ci/*" }));

        let json = serde_json::to_string(&cap).unwrap();
        assert!(json.contains("ci/*"));
    }

    #[test]
    fn verify_chain_root_ucan() {
        let issuer = Keypair::generate();
        let audience = Keypair::generate().did();
        let ucan = Ucan::issue(
            &issuer, audience,
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
        ).unwrap();
        // Root UCAN (no proofs) should verify fine
        ucan.verify_chain().unwrap();
    }

    #[test]
    fn verify_chain_valid_delegation() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();

        // Alice grants Bob push access
        let root = Ucan::issue(
            &alice, bob.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
        ).unwrap();

        // Bob delegates to Charlie (with proof from Alice)
        let delegated = Ucan::delegate(
            &bob, charlie.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
            &root,
        ).unwrap();

        // Chain should verify: Charlie's token → Bob's proof → Alice signed it
        delegated.verify_chain().unwrap();
        assert_eq!(delegated.payload.prf.len(), 1);
    }

    #[test]
    fn verify_chain_broken_audience_issuer() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();
        let eve = Keypair::generate();

        // Alice grants Bob access
        let root = Ucan::issue(
            &alice, bob.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
        ).unwrap();

        // Eve (NOT Bob) tries to delegate using Alice's proof
        let bad = Ucan::delegate(
            &eve, charlie.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
            &root,
        ).unwrap();

        // Should fail: proof audience (Bob) != UCAN issuer (Eve)
        let err = bad.verify_chain().unwrap_err();
        assert!(err.to_string().contains("proof chain broken"));
    }

    #[test]
    fn verify_chain_expired_proof() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();

        // Alice grants Bob access with expiry in the past
        let exp = chrono::Utc::now() - chrono::Duration::hours(1);
        let root = Ucan::issue(
            &alice, bob.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            Some(exp),
        ).unwrap();

        let delegated = Ucan::delegate(
            &bob, charlie.did(),
            vec![Capability::new("gitlawb://repos/test", caps::GIT_PUSH)],
            None,
            &root,
        ).unwrap();

        // Should fail: the proof is expired
        let err = delegated.verify_chain().unwrap_err();
        assert!(err.to_string().contains("expired"));
    }
}
