//! Decentralized Identifier (DID) types for the gitlawb network.
//!
//! Supported methods:
//!   - `did:key`      — ephemeral, derived directly from an Ed25519 public key
//!   - `did:web`      — anchored to a domain
//!   - `did:gitlawb`  — native, anchored to the libp2p DHT
//!
//! The canonical DID for a gitlawb actor is `did:key` during bootstrap
//! and migrates to `did:gitlawb` once DHT anchoring is live.

use ed25519_dalek::VerifyingKey;
use multibase::Base;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// Multicodec prefix for Ed25519 public keys.
/// Value: 0xed01 encoded as a varint.
const ED25519_MULTICODEC: &[u8] = &[0xed, 0x01];

/// A Decentralized Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Construct a `did:key` from an Ed25519 verifying key.
    ///
    /// Encoding: multibase(base58btc, multicodec(ed25519-pub) || pubkey_bytes)
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let key_bytes = key.to_bytes();
        let mut prefixed = Vec::with_capacity(ED25519_MULTICODEC.len() + key_bytes.len());
        prefixed.extend_from_slice(ED25519_MULTICODEC);
        prefixed.extend_from_slice(&key_bytes);

        let encoded = multibase::encode(Base::Base58Btc, &prefixed);
        Self(format!("did:key:{encoded}"))
    }

    /// Construct a `did:web` DID from a domain.
    pub fn web(domain: &str) -> Self {
        Self(format!("did:web:{domain}"))
    }

    /// Construct a `did:gitlawb` DID from a DHT key (base58btc-encoded).
    pub fn gitlawb(key: &str) -> Self {
        Self(format!("did:gitlawb:{key}"))
    }

    /// Return the DID method (`key`, `web`, `gitlawb`).
    pub fn method(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("")
    }

    /// Return the method-specific identifier portion.
    pub fn method_id(&self) -> &str {
        self.0.splitn(3, ':').nth(2).unwrap_or("")
    }

    /// Return true if this is a `did:key`.
    pub fn is_did_key(&self) -> bool {
        self.method() == "key"
    }

    /// Return true if this is a `did:gitlawb`.
    pub fn is_did_gitlawb(&self) -> bool {
        self.method() == "gitlawb"
    }

    /// Resolve the Ed25519 verifying key from a `did:key`.
    ///
    /// Returns `Err` if the DID is not a `did:key` or the key bytes are invalid.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey> {
        if !self.is_did_key() {
            return Err(Error::InvalidDid(format!(
                "expected did:key, got did:{}",
                self.method()
            )));
        }

        let (_, bytes) =
            multibase::decode(self.method_id()).map_err(|e| Error::InvalidDid(e.to_string()))?;

        if !bytes.starts_with(ED25519_MULTICODEC) {
            return Err(Error::InvalidDid(
                "not an ed25519 multicodec key".to_string(),
            ));
        }

        let key_bytes: [u8; 32] = bytes[ED25519_MULTICODEC.len()..]
            .try_into()
            .map_err(|_| Error::InvalidDid("ed25519 key must be 32 bytes".to_string()))?;

        VerifyingKey::from_bytes(&key_bytes).map_err(|e| Error::InvalidDid(e.to_string()))
    }

    /// Return the full DID string as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that this DID is well-formed.
    pub fn validate(&self) -> Result<()> {
        match self.method() {
            "key" | "web" | "gitlawb" => Ok(()),
            other => Err(Error::InvalidDid(format!(
                "unsupported DID method: {other}"
            ))),
        }
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if !s.starts_with("did:") {
            return Err(Error::InvalidDid(format!(
                "'{s}' does not start with 'did:'"
            )));
        }
        let did = Self(s.to_string());
        did.validate()?;
        Ok(did)
    }
}

impl From<Did> for String {
    fn from(did: Did) -> String {
        did.0
    }
}

/// A DID Document for a gitlawb actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: Did,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service: Vec<ServiceEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<DidMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: Did,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidMetadata {
    #[serde(rename = "type")]
    pub actor_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl DidDocument {
    pub fn new(did: Did, verifying_key: &VerifyingKey) -> Self {
        let key_bytes = verifying_key.to_bytes();
        let mut prefixed = Vec::with_capacity(ED25519_MULTICODEC.len() + key_bytes.len());
        prefixed.extend_from_slice(ED25519_MULTICODEC);
        prefixed.extend_from_slice(&key_bytes);
        let public_key_multibase = multibase::encode(Base::Base58Btc, &prefixed);

        Self {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: did.clone(),
            verification_method: vec![VerificationMethod {
                id: format!("{}#signing-key", did),
                type_: "Ed25519VerificationKey2020".to_string(),
                controller: did,
                public_key_multibase,
            }],
            service: vec![],
            metadata: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    #[test]
    fn did_key_round_trip() {
        let kp = Keypair::generate();
        let vk = kp.verifying_key();
        let did = Did::from_verifying_key(&vk);

        assert!(did.is_did_key());
        assert!(did.to_string().starts_with("did:key:z6Mk"));

        let recovered = did.to_verifying_key().unwrap();
        assert_eq!(vk.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn did_parse_roundtrip() {
        let kp = Keypair::generate();
        let did = kp.did();
        let s = did.to_string();
        let parsed: Did = s.parse().unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn did_methods() {
        let web = Did::web("agents.example.com");
        assert_eq!(web.method(), "web");

        let gl = Did::gitlawb("z6MkSomeKey");
        assert_eq!(gl.method(), "gitlawb");
    }

    #[test]
    fn did_document_serializes() {
        let kp = Keypair::generate();
        let did = kp.did();
        let vk = kp.verifying_key();
        let doc = DidDocument::new(did, &vk);
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("Ed25519VerificationKey2020"));
    }

    #[test]
    fn to_verifying_key_fails_for_did_web() {
        let web = Did::web("example.com");
        let result = web.to_verifying_key();
        assert!(
            result.is_err(),
            "did:web cannot resolve to a verifying key locally"
        );
    }

    #[test]
    fn to_verifying_key_fails_for_did_gitlawb() {
        let gl = Did::gitlawb("z6MkSomeKey");
        let result = gl.to_verifying_key();
        assert!(
            result.is_err(),
            "did:gitlawb cannot resolve to a verifying key locally"
        );
    }

    #[test]
    fn from_str_rejects_missing_did_prefix() {
        let result = "key:z6MkABCD".parse::<Did>();
        assert!(result.is_err());
    }

    #[test]
    fn from_str_rejects_unsupported_method() {
        let result = "did:ethr:0x1234abcd".parse::<Did>();
        assert!(result.is_err());
    }

    #[test]
    fn validate_accepts_all_supported_methods() {
        Did::web("example.com").validate().unwrap();
        Did::gitlawb("z6MkSomeKey").validate().unwrap();
        Keypair::generate().did().validate().unwrap();
    }

    #[test]
    fn is_did_key_and_is_did_gitlawb_predicates() {
        let key_did = Keypair::generate().did();
        assert!(key_did.is_did_key());
        assert!(!key_did.is_did_gitlawb());

        let gl = Did::gitlawb("z6MkSomeKey");
        assert!(!gl.is_did_key());
        assert!(gl.is_did_gitlawb());
    }

    #[test]
    fn method_id_extraction() {
        assert_eq!(Did::web("example.com").method_id(), "example.com");
        assert_eq!(Did::gitlawb("z6MkSomeKey").method_id(), "z6MkSomeKey");
    }
}
