//! #26 Split PR 2 — ANS-104 data item (de)serialization and signature verification.
//!
//! ANS-104 is the Arweave / Bundler data item format. The wire shape is a
//! JSON object with base64url-encoded fields; the deep-hash is the
//! canonical signing input. A signed data item is what an Arweave
//! gateway serves from `GET /<tx_id>`: parsing the response, verifying
//! the Ed25519 signature against the persisted `node_did`, and only
//! then trusting the embedded cert is what
//! `verify_anchor` in `arweave.rs` does.
//!
//! This module owns:
//!   - `DataItem`: the in-memory struct, parsed from the wire shape.
//!   - `data_item_data(item)`: serialize the data payload to bytes (the
//!     JSON body the node anchored).
//!   - `serialize_signing_payload(item)`: the bytes the signature is
//!     over (the deep-hash, per the spec).
//!   - `verify_data_item(item, expected_owner)`: parse the
//!     base64url-encoded owner, check the Ed25519 signature against
//!     `expected_owner`'s public key.
//!
//! The deep-hash follows the spec at
//! <https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md>:
//!
//!   deep_hash(tags) =
//!     sha256(
//!       sha256("list") +
//!       sha256(
//!         sha256("map") +
//!         len(tags).to_be_bytes::<8>() +
//!         concat(sha256(name), sha256(value) for tag in tags)
//!       )
//!     )
//!
//!   deep_hash_item(signature_type, owner, target, anchor, data, deep_hash(tags)) =
//!     sha256(
//!       sha256("dataitem") +
//!       sha256(signature_type.to_string()) +
//!       sha256(owner) +
//!       sha256(target) +
//!       sha256(anchor) +
//!       deep_hash(tags) +
//!       sha256(data)
//!     )
//!
//! The signature is over the 32-byte deep-hash output. Ed25519 only
//! (signature_type = 1).

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The signature type byte for Ed25519. ANS-104 defines several
/// signature algorithms; the node only ever emits or verifies Ed25519.
pub const SIGNATURE_TYPE_ED25519: u8 = 1;

/// The on-wire shape of an ANS-104 data item. Every byte payload is
/// base64url-encoded WITHOUT padding; every text field is UTF-8.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataItem {
    /// Ed25519 signature over `serialize_signing_payload(self)`. base64url.
    pub signature: String,
    /// 32-byte Ed25519 public key, followed by 32 zero bytes, base64url-encoded.
    /// (The 32-byte padding is the ANS-104 convention; only the first
    /// 32 bytes are the public key.)
    pub owner: String,
    /// Optional target address. Empty for gitlawb anchors.
    pub target: String,
    /// Optional anchor string. Empty for gitlawb anchors.
    pub anchor: String,
    /// Free-form tags, name and value each base64url-encoded.
    pub tags: Vec<DataItemTag>,
    /// The data payload, base64url-encoded.
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataItemTag {
    pub name: String,
    pub value: String,
}

impl DataItem {
    /// Construct a new unsigned data item with the given payload bytes
    /// and tags. The caller is responsible for calling `sign` with a
    /// keypair before sending the item to the bundler.
    ///
    /// `tags` is the raw `(name, value)` form, NOT base64url-encoded.
    /// The constructor handles the base64url encoding.
    #[allow(dead_code)] // production caller is the bundler upload, the next slice
    pub fn new_unsigned(
        owner_pubkey: &[u8; PUBLIC_KEY_LENGTH],
        target: &str,
        anchor: &str,
        tags: Vec<(&[u8], &[u8])>,
        data: Vec<u8>,
    ) -> Self {
        // ANS-104 owner field: 32-byte pubkey || 32-byte zero pad, base64url.
        let mut owner_bytes = [0u8; 64];
        owner_bytes[..PUBLIC_KEY_LENGTH].copy_from_slice(owner_pubkey);
        let owner = URL_SAFE_NO_PAD.encode(owner_bytes);

        let data_b64 = URL_SAFE_NO_PAD.encode(&data);
        let tags = tags
            .into_iter()
            .map(|(name, value)| DataItemTag {
                name: URL_SAFE_NO_PAD.encode(name),
                value: URL_SAFE_NO_PAD.encode(value),
            })
            .collect();

        DataItem {
            signature: String::new(),
            owner,
            target: target.to_string(),
            anchor: anchor.to_string(),
            tags,
            data: data_b64,
        }
    }

    /// Decode the data payload to raw bytes.
    pub fn data_bytes(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .with_context(|| "decoding ANS-104 data payload from base64url")
    }

    /// Decode the 32-byte Ed25519 public key from the owner field.
    /// The owner field carries 32 pubkey bytes + 32 zero bytes; the
    /// zero pad is silently ignored here. The returned bytes are the
    /// raw 32-byte public key, suitable for `VerifyingKey::from_bytes`.
    pub fn owner_pubkey(&self) -> Result<[u8; PUBLIC_KEY_LENGTH]> {
        let owner_bytes = URL_SAFE_NO_PAD
            .decode(self.owner.as_bytes())
            .with_context(|| "decoding ANS-104 owner from base64url")?;
        if owner_bytes.len() < PUBLIC_KEY_LENGTH {
            bail!(
                "ANS-104 owner is {} bytes, expected at least {}",
                owner_bytes.len(),
                PUBLIC_KEY_LENGTH
            );
        }
        let mut pubkey = [0u8; PUBLIC_KEY_LENGTH];
        pubkey.copy_from_slice(&owner_bytes[..PUBLIC_KEY_LENGTH]);
        Ok(pubkey)
    }

    /// Return the deep-hash of the data item with the signature field
    /// cleared. This is the bytes the signature is computed over.
    ///
    /// ANS-104's deep-hash is non-trivial: it mixes a tag list
    /// (itself hashed) into the data item hash. Implementing it
    /// directly is the only correct way; a hand-rolled sha256 of the
    /// JSON body would produce a hash that no Arweave gateway would
    /// recognize.
    pub fn deep_hash(&self) -> Result<[u8; 32]> {
        // The signature is part of the wire shape but NOT part of the
        // signing input. The spec says: sign over the deep-hash of
        // (signature_type, owner, target, anchor, data, deep_hash(tags))
        // — without including the signature itself.
        let owner_bytes = URL_SAFE_NO_PAD
            .decode(self.owner.as_bytes())
            .with_context(|| "decoding owner for deep-hash")?;
        let target_bytes = self.target.as_bytes();
        let anchor_bytes = self.anchor.as_bytes();
        let data_bytes = URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .with_context(|| "decoding data for deep-hash")?;

        // Decode the tag names and values to raw bytes.
        let mut raw_tags: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(self.tags.len());
        for t in &self.tags {
            let name = URL_SAFE_NO_PAD
                .decode(t.name.as_bytes())
                .with_context(|| "decoding tag name for deep-hash")?;
            let value = URL_SAFE_NO_PAD
                .decode(t.value.as_bytes())
                .with_context(|| "decoding tag value for deep-hash")?;
            raw_tags.push((name, value));
        }

        let tags_hash = deep_hash_tags(&raw_tags);
        let sig_type_str = SIGNATURE_TYPE_ED25519.to_string();

        let mut hasher = Sha256::new();
        hasher.update(sha256(b"dataitem"));
        hasher.update(sha256(sig_type_str.as_bytes()));
        hasher.update(sha256(&owner_bytes));
        hasher.update(sha256(target_bytes));
        hasher.update(sha256(anchor_bytes));
        hasher.update(tags_hash);
        hasher.update(sha256(&data_bytes));
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Ok(out)
    }
}

/// Compute `deep_hash(tags)` per the ANS-104 spec.
fn deep_hash_tags(tags: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sha256(b"list"));

    let mut inner = Sha256::new();
    inner.update(sha256(b"map"));
    inner.update((tags.len() as u64).to_be_bytes());
    for (name, value) in tags {
        inner.update(sha256(name));
        inner.update(sha256(value));
    }
    hasher.update(inner.finalize());

    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// sha256 wrapper that returns the 32-byte digest as a `Vec<u8>` for
/// `update`-chaining convenience.
fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Sign an unsigned data item with the given Ed25519 keypair. Sets
/// `signature` to the base64url-encoded Ed25519 signature over the
/// deep-hash. Does NOT mutate the rest of the item.
#[allow(dead_code)] // production caller is the bundler upload, the next slice
pub fn sign_data_item(
    item: &mut DataItem,
    keypair: &gitlawb_core::identity::Keypair,
) -> Result<()> {
    let hash = item.deep_hash()?;
    let sig = keypair.sign(&hash);
    item.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(())
}

/// Verify a parsed data item against an expected Ed25519 public key.
///
/// Returns `Ok(())` if the signature is valid for the deep-hash, and
/// `Err` otherwise. The error chain names the specific failure mode
/// (bad base64, wrong key, malformed signature) so a probe of the
/// verification endpoint can surface a useful reason to the caller.
pub fn verify_data_item(item: &DataItem, expected_pubkey: &[u8; PUBLIC_KEY_LENGTH]) -> Result<()> {
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(item.signature.as_bytes())
        .with_context(|| "decoding ANS-104 signature from base64url")?;
    if sig_bytes.len() != 64 {
        bail!(
            "ANS-104 signature is {} bytes, expected 64",
            sig_bytes.len()
        );
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let owner_pk = item.owner_pubkey()?;
    if &owner_pk != expected_pubkey {
        bail!(
            "ANS-104 owner does not match expected public key: \
             owner={}, expected={}",
            hex::encode(owner_pk),
            hex::encode(expected_pubkey)
        );
    }

    let vk = VerifyingKey::from_bytes(&owner_pk)
        .with_context(|| "decoding owner public key as Ed25519 verifying key")?;

    let hash = item.deep_hash()?;
    vk.verify(&hash, &sig)
        .map_err(|e| anyhow!("ANS-104 signature failed Ed25519 verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitlawb_core::identity::Keypair;

    fn sample_tags() -> Vec<(&'static [u8], &'static [u8])> {
        vec![
            (b"App-Name", b"gitlawb"),
            (b"Schema", b"gitlawb/ref-update/v1"),
        ]
    }

    /// Signing then verifying round-trips for a fresh keypair.
    #[test]
    fn sign_then_verify_round_trips() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let tags = sample_tags();
        let data = br#"{"repo":"alice/r","ref":"refs/heads/main"}"#;
        let mut item = DataItem::new_unsigned(&pk, "", "", tags, data.to_vec());
        sign_data_item(&mut item, &kp).unwrap();

        // Owner pubkey in the item matches the keypair.
        let owner_pk = item.owner_pubkey().unwrap();
        assert_eq!(owner_pk, pk);

        // Verify succeeds.
        verify_data_item(&item, &pk).expect("round-trip verify");
    }

    /// A flipped signature byte fails the verify.
    #[test]
    fn flipped_signature_byte_fails_verify() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut item = DataItem::new_unsigned(&pk, "", "", sample_tags(), b"{}".to_vec());
        sign_data_item(&mut item, &kp).unwrap();
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(item.signature.as_bytes()).unwrap();
        sig_bytes[0] ^= 0x01;
        item.signature = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let err = verify_data_item(&item, &pk).unwrap_err();
        assert!(
            err.to_string().contains("signature failed Ed25519 verify"),
            "expected Ed25519 failure, got: {err}"
        );
    }

    /// A different public key (a non-matching `expected_pubkey`)
    /// fails the verify, even if the item's own owner matches.
    #[test]
    fn wrong_expected_pubkey_fails_verify() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let pk1 = kp1.verifying_key().to_bytes();
        let pk2 = kp2.verifying_key().to_bytes();
        let mut item = DataItem::new_unsigned(&pk1, "", "", sample_tags(), b"{}".to_vec());
        sign_data_item(&mut item, &kp1).unwrap();
        let err = verify_data_item(&item, &pk2).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match expected public key"),
            "expected owner mismatch, got: {err}"
        );
    }

    /// The data item's deep-hash differs for items with different
    /// data payloads. A data mutation after signing breaks verify.
    #[test]
    fn mutated_data_fails_verify() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut item = DataItem::new_unsigned(&pk, "", "", sample_tags(), b"a".to_vec());
        sign_data_item(&mut item, &kp).unwrap();
        // Mutate the data after signing.
        item.data = URL_SAFE_NO_PAD.encode(b"b");
        let err = verify_data_item(&item, &pk).unwrap_err();
        assert!(err.to_string().contains("signature failed Ed25519 verify"));
    }

    /// A wire-shape round-trip: build, JSON-serialize, JSON-parse,
    /// verify. This is the path the verify_anchor endpoint takes when
    /// the gateway responds.
    #[test]
    fn wire_shape_round_trip() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut item = DataItem::new_unsigned(&pk, "", "", sample_tags(), b"{}".to_vec());
        sign_data_item(&mut item, &kp).unwrap();
        let json = serde_json::to_string(&item).unwrap();
        let parsed: DataItem = serde_json::from_str(&json).unwrap();
        verify_data_item(&parsed, &pk).expect("wire round-trip verify");
    }

    /// The deep-hash is stable: two items with the same payload, tags,
    /// owner, target, and anchor produce the same hash. This is what
    /// makes signature verification deterministic.
    #[test]
    fn deep_hash_is_stable() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut a = DataItem::new_unsigned(&pk, "", "", sample_tags(), b"hello".to_vec());
        let mut b = DataItem::new_unsigned(&pk, "", "", sample_tags(), b"hello".to_vec());
        sign_data_item(&mut a, &kp).unwrap();
        sign_data_item(&mut b, &kp).unwrap();
        assert_eq!(a.deep_hash().unwrap(), b.deep_hash().unwrap());
    }

    /// The empty-tags deep-hash is well-defined and distinct from a
    /// one-tag item. A regression here means the tag-list hash is
    /// skipping the empty-list case.
    #[test]
    fn deep_hash_empty_tags_is_distinct_from_one_tag() {
        let pk = [0u8; 32];
        let empty = DataItem::new_unsigned(&pk, "", "", vec![], b"x".to_vec());
        let one = DataItem::new_unsigned(&pk, "", "", vec![(b"A", b"B")], b"x".to_vec());
        assert_ne!(empty.deep_hash().unwrap(), one.deep_hash().unwrap());
    }
}
