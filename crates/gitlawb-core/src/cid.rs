//! Content Identifier (CID) computation for gitlawb.
//!
//! Git SHA-256 object hashes map **deterministically** to IPFS CIDs:
//!
//!   CID = CIDv1(codec=raw, mh=multihash(sha2-256, git_object_bytes))
//!
//! This means any git client using `--object-format=sha256` can verify
//! objects fetched from IPFS without modification. The CID is derived
//! from the raw git object bytes, not the SHA-256 hash string.

use cid::CidGeneric;
use multihash_codetable::{Code, MultihashDigest};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::fmt;

use crate::{Error, Result};

/// IPFS multicodec for raw binary data.
const RAW: u64 = 0x55;

/// A CIDv1 identifier for a git object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cid(String);

impl Cid {
    /// Compute a CID from raw git object bytes.
    ///
    /// This is the canonical mapping: git objects pushed to IPFS always
    /// produce this CID, so the content is self-verifying.
    pub fn from_git_object_bytes(bytes: &[u8]) -> Self {
        let mh = Code::Sha2_256.digest(bytes);
        // CIDv1 with raw codec
        let c = CidGeneric::<64>::new_v1(RAW, mh);
        Self(c.to_string())
    }

    /// Compute a CID from an existing SHA-256 hex hash (e.g. from `git rev-parse`).
    ///
    /// NOTE: This requires the original object bytes to recompute the multihash
    /// correctly. If you only have the hex hash and not the bytes, use
    /// `from_sha256_hex_trusted` — but note that is not self-verifying.
    pub fn from_sha256_bytes(sha256_bytes: &[u8; 32]) -> Self {
        // Construct multihash from raw bytes (0x12 = sha2-256, 0x20 = 32 bytes length)
        let mut mh_bytes = vec![0x12u8, 0x20];
        mh_bytes.extend_from_slice(sha256_bytes);
        let mh = multihash::Multihash::<64>::from_bytes(&mh_bytes)
            .expect("valid multihash construction from sha256 bytes");
        let c = CidGeneric::<64>::new_v1(RAW, mh);
        Self(c.to_string())
    }

    /// Parse a CID from a string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        s.parse::<CidGeneric<64>>()
            .map(|_| Self(s.to_string()))
            .map_err(|e| Error::InvalidCid(e.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Compute a SHA-256 hash of arbitrary bytes and return as hex string.
/// Used for git object hashing (git uses SHA-256 in --object-format=sha256 mode).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Compute a SHA-256 hash and return as raw bytes.
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Parse a 64-character hex SHA-256 string into raw bytes.
pub fn sha256_hex_to_bytes(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::InvalidCid(format!("invalid hex: {e}")))?;
    bytes.try_into()
        .map_err(|_| Error::InvalidCid("sha256 hash must be 32 bytes (64 hex chars)".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_is_deterministic() {
        let data = b"hello gitlawb";
        let c1 = Cid::from_git_object_bytes(data);
        let c2 = Cid::from_git_object_bytes(data);
        assert_eq!(c1, c2);
    }

    #[test]
    fn cid_starts_with_b() {
        // CIDv1 base32 strings start with 'b'
        let data = b"blob 13\0hello gitlawb";
        let c = Cid::from_git_object_bytes(data);
        assert!(c.to_string().starts_with('b'), "CIDv1 should be base32 (starts with 'b')");
    }

    #[test]
    fn sha256_hex_len() {
        let h = sha256_hex(b"test");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn sha256_round_trip() {
        let data = b"git object content";
        let hex = sha256_hex(data);
        let bytes = sha256_hex_to_bytes(&hex).unwrap();
        assert_eq!(sha256_bytes(data), bytes);
    }
}
