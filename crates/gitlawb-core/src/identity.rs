//! Keypair generation, storage, and signing.
//!
//! A gitlawb identity is an Ed25519 keypair. The public key encodes into a
//! `did:key` DID. The private key is stored as PKCS#8 PEM on disk.

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result};
use crate::did::Did;

/// An Ed25519 keypair that is the root identity for a gitlawb actor.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load a keypair from raw 32-byte seed bytes (zeroized after use).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(seed);
        Ok(Self { signing_key })
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The `did:key` DID derived from this keypair's public key.
    pub fn did(&self) -> Did {
        Did::from_verifying_key(&self.verifying_key())
    }

    /// Sign arbitrary bytes. Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Sign and return base64url-encoded signature string.
    pub fn sign_b64(&self, msg: &[u8]) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let sig = self.sign(msg);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    /// Export the signing key as raw 32-byte seed (wrapped in Zeroizing).
    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Export to PEM-encoded PKCS#8 private key string.
    pub fn to_pem(&self) -> Result<Zeroizing<String>> {
        use pkcs8::EncodePrivateKey;
        self.signing_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| Zeroizing::new(pem.to_string()))
            .map_err(|e| Error::Key(e.to_string()))
    }

    /// Load from PEM-encoded PKCS#8 private key string.
    pub fn from_pem(pem: &str) -> Result<Self> {
        use pkcs8::DecodePrivateKey;
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self { signing_key })
    }
}

/// Verify an Ed25519 signature.
pub fn verify(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<()> {
    use ed25519_dalek::Verifier;
    let sig = Signature::from_bytes(sig_bytes);
    verifying_key
        .verify(msg, &sig)
        .map_err(|_| Error::SignatureInvalid)
}

/// A signed payload: the data plus the DID of the signer and the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub payload: T,
    pub signer: Did,
    #[serde(with = "sig_b64")]
    pub signature: [u8; 64],
}

impl<T: Serialize> Signed<T> {
    pub fn new(payload: T, keypair: &Keypair) -> Result<Self> {
        let bytes = serde_json::to_vec(&payload)?;
        let sig = keypair.sign(&bytes);
        Ok(Self {
            payload,
            signer: keypair.did(),
            signature: sig.to_bytes(),
        })
    }
}

impl<T: Serialize> Signed<T> {
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let bytes = serde_json::to_vec(&self.payload)?;
        verify(verifying_key, &bytes, &self.signature)
    }
}

mod sig_b64 {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserializer, Serializer, Deserialize};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD.decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_pem() {
        let kp = Keypair::generate();
        let pem = kp.to_pem().unwrap();
        let kp2 = Keypair::from_pem(&pem).unwrap();
        assert_eq!(kp.verifying_key(), kp2.verifying_key());
    }

    #[test]
    fn sign_and_verify() {
        let kp = Keypair::generate();
        let msg = b"gitlawb test message";
        let sig = kp.sign(msg);
        let sig_bytes = sig.to_bytes();
        verify(&kp.verifying_key(), msg, &sig_bytes).unwrap();
    }

    #[test]
    fn did_from_keypair() {
        let kp = Keypair::generate();
        let did = kp.did();
        assert!(did.to_string().starts_with("did:key:z6Mk"));
    }
}
