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
use sha2::{Digest, Sha256};
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

/// True when `s` parses as a CIDv1 with the raw codec — the exact shape
/// [`Cid::from_git_object_bytes`] produces and the `/ipfs` resolver looks up.
/// A legacy provider CID (Kubo dag-pb, Pinata CIDv0) parses to a different
/// version or codec and returns `false`, marking it an opportunistic-repair
/// candidate. Decidable from the string alone (no object bytes), so the pin path
/// can gate the byte-read/recompute cost on it and leave non-legacy rows at the
/// existing DB-only skip cost. An unparseable string is non-canonical (`false`).
pub fn is_raw_cidv1(s: &str) -> bool {
    s.parse::<CidGeneric<64>>()
        .map(|c| c.version() == cid::Version::V1 && c.codec() == RAW)
        .unwrap_or(false)
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
    let bytes = hex::decode(hex_str).map_err(|e| Error::InvalidCid(format!("invalid hex: {e}")))?;
    bytes
        .try_into()
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
        assert!(
            c.to_string().starts_with('b'),
            "CIDv1 should be base32 (starts with 'b')"
        );
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

    #[test]
    fn from_sha256_bytes_matches_object_bytes() {
        // from_sha256_bytes must produce the same CID as from_git_object_bytes
        // when given the SHA-256 of those bytes — the two construction paths
        // must be equivalent for self-verifying content addressing to hold.
        let data = b"blob 5\0hello";
        let cid_from_object = Cid::from_git_object_bytes(data);
        let hash = sha256_bytes(data);
        let cid_from_hash = Cid::from_sha256_bytes(&hash);
        assert_eq!(cid_from_object, cid_from_hash);
    }

    #[test]
    fn from_str_parses_valid_cid() {
        let data = b"tree content for test";
        let cid = Cid::from_git_object_bytes(data);
        let parsed = Cid::from_str(cid.as_str()).unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn from_str_rejects_invalid_string() {
        let result = Cid::from_str("not-a-valid-cid");
        assert!(result.is_err());
    }

    #[test]
    fn different_data_produces_different_cids() {
        let c1 = Cid::from_git_object_bytes(b"blob 5\0hello");
        let c2 = Cid::from_git_object_bytes(b"blob 5\0world");
        assert_ne!(c1, c2);
    }

    #[test]
    fn sha256_hex_to_bytes_rejects_non_hex() {
        let non_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(non_hex.len(), 64);
        let result = sha256_hex_to_bytes(non_hex);
        assert!(result.is_err());
    }

    #[test]
    fn sha256_hex_to_bytes_rejects_wrong_length() {
        let result = sha256_hex_to_bytes("deadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn is_raw_cidv1_classifies_codec_from_string() {
        // The canonical resolver key: CIDv1 + raw codec → not a repair candidate.
        let raw = Cid::from_git_object_bytes(b"blob 5\0hello");
        assert!(
            is_raw_cidv1(raw.as_str()),
            "from_git_object_bytes output is CIDv1/raw"
        );

        // A CIDv0 (Pinata dag-pb legacy shape) → repair candidate.
        assert!(
            !is_raw_cidv1("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"),
            "a CIDv0 dag-pb value is a legacy-repair candidate"
        );

        // A CIDv1 with the dag-pb codec (the Kubo above-block-size root) over the
        // same multihash → still a repair candidate (codec, not just version).
        let parsed = raw.as_str().parse::<CidGeneric<64>>().unwrap();
        const DAG_PB: u64 = 0x70;
        let dagpb = CidGeneric::<64>::new_v1(DAG_PB, *parsed.hash()).to_string();
        assert!(
            !is_raw_cidv1(&dagpb),
            "a CIDv1 dag-pb value is a legacy-repair candidate"
        );

        // Garbage is non-canonical.
        assert!(
            !is_raw_cidv1("not-a-cid"),
            "an unparseable string is non-canonical"
        );
    }

    #[test]
    fn sha256_hex_of_empty_input_is_well_known() {
        // SHA-256("") is a fixed constant; verifies the hasher is wired correctly.
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
