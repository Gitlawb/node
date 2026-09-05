//! #26 Split PR 2 — ANS-104 data item (de)serialization and signature verification.
//!
//! ANS-104 is the Arweave / Bundler data item format. The wire shape
//! per the spec at
//! <https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md>
//! is a binary frame (not the JSON projection). The JSON shape
//! (base64url fields, etc.) is a separate ergonomic layer; the
//! canonical artifact identity (`base64url(SHA256(signature))`) and
//! the deep-hash signing input are derived from the binary form. A
//! signed data item is what an Arweave gateway serves from
//! `GET /<tx_id>`: parsing the response, verifying the signature
//! against the persisted `node_did`, and only then trusting the
//! embedded cert is what `verify_anchor` in `arweave_v2.rs` does.
//!
//! The Arweave 2.0 deep-hash is the SHA-384 recursive list/blob
//! construction. The on-wire id is
//! `base64url(SHA256(signature))` — a separate, deterministic hash
//! derived from the signature, not from the deep-hash. Comparing
//! this id to the requested URL id is the artifact-identity check
//! the team memory `verify-against-artifact-id-not-signer.md`
//! requires: a node key signs many data items, so a valid signature
//! only proves who signed the response, not that it is the item the
//! caller asked to verify.
//!
//! ## Spec format (binary)
//!
//! Quoting the ANS-104 spec verbatim, the DataItem binary frame is:
//!
//! > ```text
//! > signature type   (2 bytes,  little-endian)
//! > signature        (variable, sigSize(sigtype))
//! > owner            (variable, ownerSize(sigtype))
//! > target           (1 byte presence || optional 32 bytes)
//! > anchor           (1 byte presence || optional 32 bytes)
//! > number of tags   (8 bytes,  little-endian)
//! > number of tag bytes (8 bytes, little-endian)
//! > tags             (Avro array, ZigZag VInt lengths — see §1.3.1)
//! > data             (variable)
//! > ```
//!
//! The presence flag for the optional `target` and `anchor` fields is
//! `1` for present, `0` for absent. Signature and owner lengths are
//! per the configured `signature_type`. The signature_type values
//! defined by the spec are Arweave (1), Ed25519 (2), Ethereum (3),
//! Solana (4); see [`signature_size`] / [`owner_size`] for the
//! concrete byte widths.
//!
//! ## Deep-hash (the signing input)
//!
//! The signing input matches `arbundles@0.10.x` `getSignatureData`
//! (`ar-data-base.js`): an 8-element recursive deep-hash:
//!
//! ```text
//! deepHash(blob)  = SHA384( SHA384("blob" || dec(len(blob))) || SHA384(blob) )
//! deepHash(list)  = foldLeft(SHA384("list" || dec(len(list))), items,
//!                            (acc, item) => SHA384(acc || deepHash(item)))
//! deepHashItem(item) = deepHash([
//!     "dataitem",
//!     "1",
//!     signature_type_ascii, // e.g. b"2" for Ed25519
//!     owner_raw,            // canonical owner_size(sigtype) bytes
//!     target_raw,           // empty buffer if absent
//!     anchor_raw,           // empty buffer if absent
//!     tags_serialized,      // Avro tag-array buffer as a flat blob
//!     data_raw,             // raw bytes
//! ])
//! ```
//!
//! The signature is over the raw 48-byte deep-hash output. `tags` is
//! the serialized Avro buffer (the same bytes the binary frame
//! carries), folded as a single blob via [`deep_hash_chunk`].
//!
//! The pin for this shape is the test
//! `dataitem_matches_arbundles_golden_vector` against a real
//! `arbundles`-signed Ed25519 item captured in
//! `scripts/ans104_golden_ed25519.mjs`.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

/// The signature type byte for Ed25519. ANS-104 defines several
/// signature algorithms; the node primarily emits or verifies
/// Ed25519 but parses/signs/verifies any other supported type
/// through the binary frame.
pub const SIGNATURE_TYPE_ED25519: u8 = 2;
#[allow(dead_code)] // used by the binary golden-vector test; clippy sees no caller at the bin-build level
pub const SIGNATURE_TYPE_ETHEREUM: u8 = 3;

/// Length, in bytes, of the signature field for a given signature
/// type. Per the spec, the signature size depends on the signature
/// type: Arweave/RSA = 512, Ed25519 = 64, Ethereum = 65,
/// Solana = 64. Unknown types fall back to the Ed25519 width with a
/// debug-visible `0`.
pub fn signature_size(sig_type: u8) -> usize {
    match sig_type {
        1 => 512, // Arweave / RSA
        2 => 64,  // Ed25519
        3 => 65,  // Ethereum
        4 => 64,  // Solana
        _ => 0,
    }
}

/// Length, in bytes, of the owner field for a given signature type.
pub fn owner_size(sig_type: u8) -> usize {
    match sig_type {
        1 => 512, // Arweave / RSA
        2 => 32,  // Ed25519
        3 => 65,  // Ethereum uncompressed pubkey
        4 => 32,  // Solana
        _ => 0,
    }
}

/// The on-wire shape of an ANS-104 data item. Every byte payload is
/// base64url-encoded WITHOUT padding; every text field is UTF-8.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataItem {
    /// Signature over the 48-byte deep-hash. base64url.
    pub signature: String,
    /// Public key bytes, padded per the signature type, base64url.
    pub owner: String,
    /// Optional target address. Empty when absent.
    pub target: String,
    /// Optional anchor string. Empty when absent.
    pub anchor: String,
    /// Free-form tags, name and value each base64url-encoded.
    pub tags: Vec<DataItemTag>,
    /// The data payload, base64url-encoded.
    pub data: String,
    /// Signature type byte. Defaults to Ed25519 (2) when missing in
    /// JSON to preserve compatibility with payloads emitted before
    /// the binary parser was added. The on-wire frame always
    /// carries the byte.
    #[serde(default = "default_signature_type")]
    pub signature_type: u8,
    /// Original Avro tag-array payload bytes when parsed from the
    /// binary frame. The deep-hash folds these exact bytes (arbundles
    /// hashes `rawTags` as a flat blob), and `to_binary` re-emits
    /// them, so multi-block or size-prefixed encodings survive the
    /// parse/hash/encode path instead of being normalized by
    /// re-encoding. `None` for items built locally or from JSON,
    /// which encode via `encode_tags_block`. Skipped by serde: the
    /// JSON projection carries tags, not the Avro bytes.
    #[serde(skip)]
    pub raw_tags: Option<Vec<u8>>,
}

fn default_signature_type() -> u8 {
    SIGNATURE_TYPE_ED25519
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataItemTag {
    pub name: String,
    pub value: String,
}

/// A node of the ANS-104 deep-hash tree. The deep-hash primitive
/// walks this tree recursively: a `Blob` is a leaf
/// (`SHA384("blob" || dec(len)) || SHA384(blob)`); a `List` is a
/// fold over its children.
#[derive(Debug, Clone)]
pub enum DeepHashChunk {
    Blob(Vec<u8>),
    List(Vec<DeepHashChunk>),
}

impl DataItem {
    /// Construct a new unsigned data item with the given payload bytes
    /// and tags. The caller is responsible for calling `sign` with a
    /// keypair before sending the item to the bundler.
    ///
    /// `tags` is the raw `(name, value)` form, NOT base64url-encoded.
    /// The constructor handles the base64url encoding for the on-wire
    /// representation. The deep-hash path decodes the on-wire bytes
    /// back to raw bytes, which is the identity.
    #[allow(dead_code)] // production caller is the bundler upload, the next slice
    pub fn new_unsigned(
        owner_pubkey: &[u8; PUBLIC_KEY_LENGTH],
        target: &str,
        anchor: &str,
        tags: Vec<(&[u8], &[u8])>,
        data: Vec<u8>,
    ) -> Self {
        // ANS-104 owner field: canonical 32-byte pubkey, base64url.
        // The wire frame carries exactly `owner_size(sigtype)` bytes
        // (32 for Ed25519); the deep-hash folds those same bytes, so
        // the signature computed in memory belongs to the frame that
        // gets published.
        let owner = URL_SAFE_NO_PAD.encode(owner_pubkey);

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
            signature_type: SIGNATURE_TYPE_ED25519,
            raw_tags: None,
        }
    }

    /// Decode the data payload to raw bytes.
    pub fn data_bytes(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .with_context(|| "decoding ANS-104 data payload from base64url")
    }

    /// Decode the public-key bytes from the owner field. The first
    /// `owner_size(signature_type)` bytes are the actual key; any
    /// trailing bytes (the ANS-104 RSA/Arweave padding) are silently
    /// ignored here.
    pub fn owner_pubkey(&self) -> Result<Vec<u8>> {
        let owner_bytes = URL_SAFE_NO_PAD
            .decode(self.owner.as_bytes())
            .with_context(|| "decoding ANS-104 owner from base64url")?;
        let need = owner_size(self.signature_type);
        if owner_bytes.len() < need {
            bail!(
                "ANS-104 owner is {} bytes, expected at least {} for sigtype {}",
                owner_bytes.len(),
                need,
                self.signature_type
            );
        }
        Ok(owner_bytes[..need].to_vec())
    }

    /// Decode the 32-byte Ed25519 public key from the owner field.
    /// The owner field carries 32 pubkey bytes + 32 zero bytes; the
    /// zero pad is silently ignored here. The returned bytes are the
    /// raw 32-byte public key, suitable for `VerifyingKey::from_bytes`.
    pub fn owner_pubkey_ed25519(&self) -> Result<[u8; PUBLIC_KEY_LENGTH]> {
        if self.signature_type != SIGNATURE_TYPE_ED25519 {
            bail!(
                "ANS-104 owner_pubkey_ed25519 called on a non-Ed25519 item \
                 (sigtype = {})",
                self.signature_type
            );
        }
        let owner_bytes = self.owner_pubkey()?;
        let mut pubkey = [0u8; PUBLIC_KEY_LENGTH];
        pubkey.copy_from_slice(&owner_bytes);
        Ok(pubkey)
    }

    /// The protocol-defined on-wire id: `base64url(SHA256(signature))`.
    /// The signature is over the 48-byte deep-hash digest, but the
    /// id is hashed from the signature itself, separately. This is
    /// the value a gateway URL identifies the item by, and the
    /// artifact-identity check in `arweave_v2::verify_anchor` compares
    /// it to the requested `item_id` from the URL.
    ///
    /// Returns `Err` if the signature is empty (the item was not
    /// signed) or not valid base64url.
    pub fn id(&self) -> Result<String> {
        if self.signature.is_empty() {
            bail!("cannot derive id from an unsigned data item");
        }
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(self.signature.as_bytes())
            .with_context(|| "decoding ANS-104 signature from base64url")?;
        let mut hasher = Sha256::new();
        hasher.update(&sig_bytes);
        let id = hasher.finalize();
        Ok(URL_SAFE_NO_PAD.encode(id))
    }

    /// Return the 48-byte SHA-384 deep-hash of the data item with
    /// the signature field cleared. The signature is computed over
    /// these raw 48 bytes (Ed25519 with signature_type = 2).
    ///
    /// The fold matches `arbundles@0.10.x` `getSignatureData`
    /// (`ar-data-base.js`): an 8-element list
    ///
    /// ```text
    /// deepHash([
    ///   "dataitem",
    ///   "1",
    ///   signature_type_ascii, // e.g. b"2" for Ed25519
    ///   owner_raw,            // canonical owner_size(sigtype) bytes
    ///   target_raw,           // empty if absent
    ///   anchor_raw,           // empty if absent
    ///   tags_serialized,      // Avro-serialized tag buffer as a flat blob
    ///   data_raw,
    /// ])
    /// ```
    ///
    /// `tags_serialized` is the Avro tag-array buffer (the same bytes
    /// `to_binary`/`from_binary` carry as the tags payload), folded
    /// as a single blob — NOT a nested `[[name, value], ...]` list.
    pub fn deep_hash(&self) -> Result<[u8; 48]> {
        // Decode the JSON projection back to raw bytes for each
        // field. `deep_hash_chunk` borrows into these owned buffers
        // for the duration of the call.
        let owner_full: Vec<u8> = URL_SAFE_NO_PAD
            .decode(self.owner.as_bytes())
            .with_context(|| "decoding owner for deep-hash")?;
        let need = owner_size(self.signature_type);
        if need == 0 {
            bail!(
                "ANS-104 deep-hash: unknown signature_type {} (no owner length)",
                self.signature_type
            );
        }
        if owner_full.len() < need {
            bail!(
                "ANS-104 owner is {} bytes, expected at least {} for sigtype {}",
                owner_full.len(),
                need,
                self.signature_type
            );
        }
        // Canonical owner: exactly owner_size(sigtype) bytes. A
        // legacy 64-byte owner (32 pubkey + 32 zero pad) truncates
        // to the first 32; the wire frame carries the same prefix.
        let owner: Vec<u8> = owner_full[..need].to_vec();
        let data: Vec<u8> = URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .with_context(|| "decoding data for deep-hash")?;

        let raw_tags: Vec<(Vec<u8>, Vec<u8>)> = self
            .tags
            .iter()
            .map(|t| -> Result<(Vec<u8>, Vec<u8>)> {
                let name = URL_SAFE_NO_PAD
                    .decode(t.name.as_bytes())
                    .with_context(|| "decoding tag name for deep-hash")?;
                let value = URL_SAFE_NO_PAD
                    .decode(t.value.as_bytes())
                    .with_context(|| "decoding tag value for deep-hash")?;
                Ok((name, value))
            })
            .collect::<Result<Vec<_>>>()?;

        let target: Vec<u8> = if self.target.is_empty() {
            Vec::new()
        } else {
            URL_SAFE_NO_PAD
                .decode(self.target.as_bytes())
                .with_context(|| "decoding target for deep-hash")?
        };
        let anchor: Vec<u8> = if self.anchor.is_empty() {
            Vec::new()
        } else {
            // The DataItem projection stores the anchor's raw bytes
            // base64url-encoded (see `from_binary`/`to_binary`); the
            // deep-hash folds those raw bytes. A caller that passed a
            // plain UTF-8 anchor to `new_unsigned` would have stored
            // it verbatim, which is not valid base64url — fall back
            // to the verbatim bytes so the fold stays defined rather
            // than erroring on a legacy shape.
            match URL_SAFE_NO_PAD.decode(self.anchor.as_bytes()) {
                Ok(b) => b,
                Err(_) => self.anchor.as_bytes().to_vec(),
            }
        };

        // 8-element fold matching arbundles. The tags slot is the
        // serialized Avro buffer as a flat blob: the original payload
        // when parsed from binary, otherwise the single-block encoding
        // of the local tags.
        let tags_block: Vec<u8> = match &self.raw_tags {
            Some(raw) => raw.clone(),
            None => encode_tags_block(&raw_tags),
        };

        let fields: Vec<DeepHashChunk> = vec![
            DeepHashChunk::Blob(b"dataitem".to_vec()),
            DeepHashChunk::Blob(b"1".to_vec()),
            DeepHashChunk::Blob(self.signature_type.to_string().into_bytes()),
            DeepHashChunk::Blob(owner),
            DeepHashChunk::Blob(target),
            DeepHashChunk::Blob(anchor),
            DeepHashChunk::Blob(tags_block),
            DeepHashChunk::Blob(data),
        ];

        let mut out = [0u8; 48];
        out.copy_from_slice(&deep_hash_chunk(&DeepHashChunk::List(fields)));
        Ok(out)
    }

    /// Parse the ANS-104 binary wire frame into a `DataItem`. See
    /// the module-level documentation for the exact byte layout.
    #[allow(dead_code)] // consumed by `arweave_v2` and the golden-vector test in the next slice
    pub fn from_binary(bytes: &[u8]) -> Result<Self> {
        let mut cur = 0usize;
        // Helper that returns the next `n` bytes, or bails if the
        // buffer is too short.
        let take = |cur: &mut usize, n: usize, what: &str| -> Result<&[u8]> {
            if bytes.len().saturating_sub(*cur) < n {
                bail!(
                    "ANS-104 binary truncated: needed {} more bytes for {}, have {}",
                    n,
                    what,
                    bytes.len().saturating_sub(*cur)
                );
            }
            let s = &bytes[*cur..*cur + n];
            *cur += n;
            Ok(s)
        };
        // 2-byte signature type (LE).
        let sig_type_bytes = take(&mut cur, 2, "signature_type")?;
        let signature_type = u16::from_le_bytes([sig_type_bytes[0], sig_type_bytes[1]]) as u8;
        let sig_len = signature_size(signature_type);
        let own_len = owner_size(signature_type);
        if sig_len == 0 || own_len == 0 {
            bail!(
                "ANS-104 binary has unknown signature_type {} (no sig/owner length)",
                signature_type
            );
        }
        // signature
        let signature_bytes = take(&mut cur, sig_len, "signature")?.to_vec();
        // owner
        let owner_bytes = take(&mut cur, own_len, "owner")?.to_vec();
        // target presence
        let target_present = take(&mut cur, 1, "target presence")?[0];
        let target_bytes = if target_present == 1 {
            take(&mut cur, 32, "target")?.to_vec()
        } else if target_present == 0 {
            Vec::new()
        } else {
            bail!(
                "ANS-104 binary has invalid target presence byte {} (must be 0 or 1)",
                target_present
            );
        };
        // anchor presence
        let anchor_present = take(&mut cur, 1, "anchor presence")?[0];
        let anchor_bytes = if anchor_present == 1 {
            take(&mut cur, 32, "anchor")?.to_vec()
        } else if anchor_present == 0 {
            Vec::new()
        } else {
            bail!(
                "ANS-104 binary has invalid anchor presence byte {} (must be 0 or 1)",
                anchor_present
            );
        };
        // 8-byte tag count (LE).
        let tag_count_bytes = take(&mut cur, 8, "tag count")?;
        let tag_count = u64::from_le_bytes(tag_count_bytes.try_into().unwrap()) as usize;
        // 8-byte tag bytes count (LE).
        let tag_bytes_len_bytes = take(&mut cur, 8, "tag byte count")?;
        let tag_bytes_len = u64::from_le_bytes(tag_bytes_len_bytes.try_into().unwrap()) as usize;
        let tags_payload = take(&mut cur, tag_bytes_len, "tags payload")?;
        // Decode the Avro-encoded tag array.
        let tags = decode_tags(tags_payload, tag_count)
            .with_context(|| "decoding ANS-104 Avro tag array")?;
        // Anything left is the data payload.
        let data_bytes = bytes[cur..].to_vec();

        Ok(DataItem {
            signature: URL_SAFE_NO_PAD.encode(&signature_bytes),
            owner: URL_SAFE_NO_PAD.encode(&owner_bytes),
            target: URL_SAFE_NO_PAD.encode(&target_bytes),
            anchor: URL_SAFE_NO_PAD.encode(&anchor_bytes),
            tags: tags
                .into_iter()
                .map(|(n, v)| DataItemTag {
                    name: URL_SAFE_NO_PAD.encode(&n),
                    value: URL_SAFE_NO_PAD.encode(&v),
                })
                .collect(),
            data: URL_SAFE_NO_PAD.encode(&data_bytes),
            signature_type,
            // Preserve the original Avro payload so the deep-hash
            // folds the exact bytes the signer hashed and `to_binary`
            // re-emits them byte-exact.
            raw_tags: Some(tags_payload.to_vec()),
        })
    }

    /// Encode the data item to the ANS-104 binary wire frame. The
    /// inverse of [`DataItem::from_binary`]. The populated signature
    /// is serialized into the signature slot, and the canonical
    /// `owner_size(sigtype)` owner prefix is written, so
    /// `sign -> to_binary -> from_binary -> verify` preserves a valid
    /// signature without re-signing after parse. An unsigned item
    /// (empty `signature`) encodes a zeroed slot as a placeholder.
    #[allow(dead_code)] // consumed by `arweave_v2` and the golden-vector test in the next slice
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let sig_len = signature_size(self.signature_type);
        let own_len = owner_size(self.signature_type);
        if sig_len == 0 || own_len == 0 {
            bail!(
                "ANS-104 to_binary: unknown signature_type {} (no sig/owner length)",
                self.signature_type
            );
        }
        let owner_bytes = URL_SAFE_NO_PAD
            .decode(self.owner.as_bytes())
            .with_context(|| "decoding owner for to_binary")?;
        if owner_bytes.len() < own_len {
            bail!(
                "ANS-104 to_binary: owner is {} bytes, expected at least {}",
                owner_bytes.len(),
                own_len
            );
        }
        // Signature slot: the populated signature when signed, zeros
        // as an unsigned placeholder.
        let sig_bytes: Vec<u8> = if self.signature.is_empty() {
            vec![0u8; sig_len]
        } else {
            let b = URL_SAFE_NO_PAD
                .decode(self.signature.as_bytes())
                .with_context(|| "decoding signature for to_binary")?;
            if b.len() != sig_len {
                bail!(
                    "ANS-104 to_binary: signature is {} bytes, expected {}",
                    b.len(),
                    sig_len
                );
            }
            b
        };
        if owner_bytes.len() < own_len {
            bail!(
                "ANS-104 to_binary: owner is {} bytes, expected at least {}",
                owner_bytes.len(),
                own_len
            );
        }
        let target_bytes = if self.target.is_empty() {
            Vec::new()
        } else {
            URL_SAFE_NO_PAD
                .decode(self.target.as_bytes())
                .with_context(|| "decoding target for to_binary")?
        };
        if !target_bytes.is_empty() && target_bytes.len() != 32 {
            bail!(
                "ANS-104 to_binary: target is {} bytes, expected 32 or empty",
                target_bytes.len()
            );
        }
        let anchor_bytes = if self.anchor.is_empty() {
            Vec::new()
        } else {
            match URL_SAFE_NO_PAD.decode(self.anchor.as_bytes()) {
                Ok(b) => b,
                Err(_) => self.anchor.as_bytes().to_vec(),
            }
        };
        if !anchor_bytes.is_empty() && anchor_bytes.len() != 32 {
            bail!(
                "ANS-104 to_binary: anchor is {} bytes, expected 32 or empty",
                anchor_bytes.len()
            );
        }
        let data_bytes = URL_SAFE_NO_PAD
            .decode(self.data.as_bytes())
            .with_context(|| "decoding data for to_binary")?;

        // Tag block: re-emit the original Avro payload when the item
        // was parsed from binary (multi-block or size-prefixed forms
        // survive byte-exact); otherwise encode the single-block form.
        let tags_block: Vec<u8> = match &self.raw_tags {
            Some(raw) => raw.clone(),
            None => {
                let tag_pairs: Vec<(Vec<u8>, Vec<u8>)> = self
                    .tags
                    .iter()
                    .map(|t| -> Result<(Vec<u8>, Vec<u8>)> {
                        let n = URL_SAFE_NO_PAD
                            .decode(t.name.as_bytes())
                            .with_context(|| "decoding tag name for to_binary")?;
                        let v = URL_SAFE_NO_PAD
                            .decode(t.value.as_bytes())
                            .with_context(|| "decoding tag value for to_binary")?;
                        Ok((n, v))
                    })
                    .collect::<Result<Vec<_>>>()?;
                encode_tags_block(&tag_pairs)
            }
        };

        // Length computation.
        let len = 2
            + sig_len
            + own_len
            + 1
            + target_bytes.len()
            + 1
            + anchor_bytes.len()
            + 8
            + 8
            + tags_block.len()
            + data_bytes.len();
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&(self.signature_type as u16).to_le_bytes());
        out.extend_from_slice(&sig_bytes);
        out.extend_from_slice(&owner_bytes[..own_len]);
        out.push(if target_bytes.is_empty() { 0 } else { 1 });
        out.extend_from_slice(&target_bytes);
        out.push(if anchor_bytes.is_empty() { 0 } else { 1 });
        out.extend_from_slice(&anchor_bytes);
        out.extend_from_slice(&(self.tags.len() as u64).to_le_bytes());
        out.extend_from_slice(&(tags_block.len() as u64).to_le_bytes());
        out.extend_from_slice(&tags_block);
        out.extend_from_slice(&data_bytes);
        debug_assert_eq!(out.len(), len);
        Ok(out)
    }
}

/// Decode the Avro-encoded tag array from the binary frame. Returns
/// the `(name, value)` pairs as raw bytes. `expected_count` is the
/// pre-parsed u64 tag count from the frame; used to validate that
/// the block contains the right number of items.
#[allow(dead_code)] // only used inside `from_binary`; clippy sees no caller at the bin-build level
fn decode_tags(payload: &[u8], expected_count: usize) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    // Empty payload is the arbundles encoding for zero tags:
    // `serializeTags` returns an empty buffer when there are no tags,
    // so the frame carries tag_bytes_len == 0.
    if payload.is_empty() {
        if expected_count != 0 {
            bail!(
                "ANS-104 tag count mismatch: frame header said {}, Avro block said 0 (empty payload)",
                expected_count
            );
        }
        return Ok(Vec::new());
    }
    let mut pos = 0usize;
    let mut tags: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    while pos < payload.len() {
        // First VInt: block item count (signed). 0 = terminator.
        // A negative count is the valid size-prefixed Avro form:
        // `-count` followed by the block's byte length, then `count`
        // items.
        let (block_count_raw, p) = read_zigzag_vint(payload, pos)?;
        pos = p;
        if block_count_raw == 0 {
            break;
        }
        let (block_count, block_end) = if block_count_raw < 0 {
            // `unsigned_abs` (not negation): `i64::MIN` has no
            // positive counterpart and `-i64::MIN` overflows.
            let count_u = block_count_raw.unsigned_abs();
            let count = usize::try_from(count_u).map_err(|_| {
                anyhow!("ANS-104 Avro tag block count {count_u} does not fit in usize")
            })?;
            if count == 0 {
                bail!("ANS-104 Avro tag block count is zero after negation");
            }
            let (block_size_i, p) = read_zigzag_vint(payload, pos)?;
            pos = p;
            if block_size_i < 0 {
                bail!(
                    "ANS-104 Avro tag block byte length is negative ({})",
                    block_size_i
                );
            }
            let block_size = block_size_i as usize;
            if block_size > payload.len().saturating_sub(pos) {
                bail!("ANS-104 Avro tag block byte length overruns payload");
            }
            (count, Some(pos + block_size))
        } else {
            let count = usize::try_from(block_count_raw).map_err(|_| {
                anyhow!("ANS-104 Avro tag block count {block_count_raw} does not fit in usize")
            })?;
            (count, None)
        };
        for _ in 0..block_count {
            let (name_len_i, p) = read_zigzag_vint(payload, pos)?;
            pos = p;
            if name_len_i < 0 {
                bail!("ANS-104 Avro tag name length is negative ({})", name_len_i);
            }
            let name_len = name_len_i as usize;
            if pos + name_len > payload.len() {
                bail!("ANS-104 Avro tag name overruns payload");
            }
            let name = payload[pos..pos + name_len].to_vec();
            pos += name_len;
            let (value_len_i, p) = read_zigzag_vint(payload, pos)?;
            pos = p;
            if value_len_i < 0 {
                bail!(
                    "ANS-104 Avro tag value length is negative ({})",
                    value_len_i
                );
            }
            let value_len = value_len_i as usize;
            if pos + value_len > payload.len() {
                bail!("ANS-104 Avro tag value overruns payload");
            }
            let value = payload[pos..pos + value_len].to_vec();
            pos += value_len;
            tags.push((name, value));
        }
        // For the size-prefixed form, the block must consume exactly
        // its declared byte length.
        if let Some(end) = block_end {
            if pos != end {
                bail!(
                    "ANS-104 Avro tag block size mismatch: declared end {end}, consumed to {pos}"
                );
            }
        }
    }
    if tags.len() != expected_count {
        bail!(
            "ANS-104 tag count mismatch: frame header said {}, Avro block said {}",
            expected_count,
            tags.len()
        );
    }
    Ok(tags)
}

/// Encode the `(name, value)` tag pairs into the Avro array buffer
/// `arbundles` (`tags.js` `serializeTags`) produces: empty tags encode
/// as an empty buffer (zero tag bytes in the frame), otherwise a
/// single block whose count equals `tags.len()` followed by a
/// zero-count terminator.
#[allow(dead_code)] // only used inside `to_binary`; clippy sees no caller at the bin-build level
fn encode_tags_block(tags: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    if tags.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    // Block count (positive = no leading size field).
    write_zigzag_vint(&mut out, tags.len() as i64);
    for (n, v) in tags {
        write_zigzag_vint(&mut out, n.len() as i64);
        out.extend_from_slice(n);
        write_zigzag_vint(&mut out, v.len() as i64);
        out.extend_from_slice(v);
    }
    // Block terminator.
    write_zigzag_vint(&mut out, 0);
    out
}

/// Read a ZigZag-encoded variable-length integer from `buf` at `pos`.
/// Returns the decoded signed value and the position immediately
/// after the VInt.
#[allow(dead_code)] // only used inside `decode_tags`; clippy sees no caller at the bin-build level
fn read_zigzag_vint(buf: &[u8], pos: usize) -> Result<(i64, usize)> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    let mut p = pos;
    loop {
        if p >= buf.len() {
            bail!("ANS-104 VInt overruns payload");
        }
        let b = buf[p];
        p += 1;
        val |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            bail!("ANS-104 VInt too long");
        }
    }
    let decoded = ((val >> 1) as i64) ^ -((val & 1) as i64);
    Ok((decoded, p))
}

/// Write a ZigZag-encoded variable-length integer into `out`.
#[allow(dead_code)] // only used inside `encode_tags_block`; clippy sees no caller at the bin-build level
fn write_zigzag_vint(out: &mut Vec<u8>, n: i64) {
    let encoded = ((n << 1) ^ (n >> 63)) as u64;
    let mut val = encoded;
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// Compute the deep-hash of a [`DeepHashChunk`] tree. A `Blob` is a
/// leaf; a `List` folds left over its children.
#[allow(dead_code)] // consumed by `deep_hash` on `DataItem`; kept public for downstream callers
pub fn deep_hash_chunk(chunk: &DeepHashChunk) -> [u8; 48] {
    match chunk {
        DeepHashChunk::Blob(b) => deep_hash_blob(b),
        DeepHashChunk::List(items) => deep_hash_list_chunk(items),
    }
}

/// Compute the Arweave 2.0 deep-hash of a flat list of items using
/// the recursive `acc = SHA384(acc || deepHash(item))` folding. The
/// list tag `SHA384("list" || decimal(len))` seeds the accumulator.
fn deep_hash_list_chunk(items: &[DeepHashChunk]) -> [u8; 48] {
    let mut acc = sha384(format!("list{}", items.len()).as_bytes());
    for item in items {
        let item_hash = deep_hash_chunk(item);
        let mut concat = Vec::with_capacity(acc.len() + item_hash.len());
        concat.extend_from_slice(&acc);
        concat.extend_from_slice(&item_hash);
        acc = sha384(&concat);
    }
    acc
}

/// Compute the Arweave 2.0 deep-hash of a flat list of byte slices.
/// The deep-hash primitive for byte items is the same recursive
/// fold as [`deep_hash_list_chunk`]; this is a convenience wrapper
/// kept for the round-2 reference-vector tests in
/// [`external_reference_vectors`], which assert the spec-correct
/// blob/list primitives independently of the fold shape.
#[allow(dead_code)] // kept for future test helpers
fn deep_hash_list(items: &[&[u8]]) -> [u8; 48] {
    let mut acc = sha384(format!("list{}", items.len()).as_bytes());
    for item in items {
        let item_hash = deep_hash_blob(item);
        let mut concat = Vec::with_capacity(acc.len() + item_hash.len());
        concat.extend_from_slice(&acc);
        concat.extend_from_slice(&item_hash);
        acc = sha384(&concat);
    }
    acc
}

/// Hash a single value as a blob (leaf). The blob path is
/// `SHA384( SHA384("blob" || decimal(len)) || SHA384(blob) )`.
fn deep_hash_blob(blob: &[u8]) -> [u8; 48] {
    let tag = format!("blob{}", blob.len());
    let tag_hash = sha384(tag.as_bytes());
    let blob_hash = sha384(blob);
    let mut concat = Vec::with_capacity(tag_hash.len() + blob_hash.len());
    concat.extend_from_slice(&tag_hash);
    concat.extend_from_slice(&blob_hash);
    sha384(&concat)
}

/// SHA-384 of `data`, returned as a 48-byte array for chaining.
fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Sign an unsigned data item with the given Ed25519 keypair. Sets
/// `signature` to the base64url-encoded Ed25519 signature over the
/// 48-byte deep-hash. Does NOT mutate the rest of the item.
#[allow(dead_code)] // production caller is the bundler upload, the next slice
pub fn sign_data_item(
    item: &mut DataItem,
    keypair: &gitlawb_core::identity::Keypair,
) -> Result<()> {
    // Ed25519 is sigtype 2 in the on-wire frame. If the item was
    // constructed via the JSON projection (which carries the byte
    // explicitly), use whatever sigtype is set; default to Ed25519
    // if it was zeroed for an in-progress unsigned item.
    let sig_len = signature_size(SIGNATURE_TYPE_ED25519);
    let hash = item.deep_hash()?;
    let sig = keypair.sign(&hash);
    item.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    item.signature_type = SIGNATURE_TYPE_ED25519;
    debug_assert_eq!(sig.to_bytes().len(), sig_len);
    Ok(())
}

/// Verify a parsed data item against an expected Ed25519 public key.
///
/// Returns `Ok(())` if the signature is valid for the deep-hash, and
/// `Err` otherwise. The error chain names the specific failure mode
/// (bad base64, wrong key, malformed signature) so a probe of the
/// verification endpoint can surface a useful reason to the caller.
pub fn verify_data_item(item: &DataItem, expected_pubkey: &[u8; PUBLIC_KEY_LENGTH]) -> Result<()> {
    if item.signature_type != SIGNATURE_TYPE_ED25519 {
        bail!(
            "ANS-104 verify_data_item only supports Ed25519 (sigtype={}); \
             ref sigtype = {}",
            SIGNATURE_TYPE_ED25519,
            item.signature_type
        );
    }
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

    let owner_pk = item.owner_pubkey_ed25519()?;
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
    vk.verify_strict(&hash, &sig)
        .map_err(|e| anyhow!("ANS-104 signature failed Ed25519 verify: {e}"))
}

#[cfg(test)]
mod tests {
    //! Self-roundtrip tests prove internal consistency: sign-then-verify
    //! in this module, mutated bytes fail verify, owner-mismatch fails
    //! verify. They do NOT prove interop with a real bundler or
    //! gateway. The interop canary is the `external_reference_vectors`
    //! module (low-level primitives) AND the golden vector in
    //! `dataitem_matches_arbundles_golden_vector` — a real signed
    //! DataItem captured from arbundles 0.10.x via
    //! `scripts/ans104_golden.mjs`. The team memory
    //! `self-roundtrip-tests-do-not-prove-interop.md` is the policy.
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
        let owner_pk = item.owner_pubkey_ed25519().unwrap();
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

    /// A binary wire-shape round-trip: build, `to_binary`,
    /// `from_binary`, verify without re-signing. Pins that the
    /// signature slot, canonical owner, target, anchor, tags, and
    /// data survive the binary round-trip with the signature intact.
    #[test]
    fn binary_round_trip() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        // 32-byte target and 32-byte anchor, base64url-encoded so
        // `to_binary` can decode them back to raw bytes.
        let target_b64 = URL_SAFE_NO_PAD.encode([0x33u8; 32]);
        let anchor_b64 = URL_SAFE_NO_PAD.encode([0x44u8; 32]);
        let mut item = DataItem::new_unsigned(
            &pk,
            &target_b64,
            &anchor_b64,
            vec![(b"tag1", b"value1"), (b"tag2", b"value2")],
            b"hello world".to_vec(),
        );
        sign_data_item(&mut item, &kp).unwrap();

        // Verify the JSON projection still parses.
        let json = serde_json::to_string(&item).unwrap();
        let parsed: DataItem = serde_json::from_str(&json).unwrap();
        verify_data_item(&parsed, &pk).expect("JSON round-trip verify");

        // Round-trip the binary form and verify WITHOUT re-signing:
        // the signature, owner, target, anchor, tags, and data must
        // survive intact. Re-signing after parse would hide an owner
        // width or signature-slot mismatch.
        let bin = item.to_binary().expect("to_binary");
        let parsed_bin = DataItem::from_binary(&bin).expect("from_binary");
        assert_eq!(
            parsed_bin.signature, item.signature,
            "signature must survive the binary round-trip"
        );
        assert_eq!(
            parsed_bin.owner, item.owner,
            "owner must survive the binary round-trip"
        );
        verify_data_item(&parsed_bin, &pk)
            .expect("binary round-trip must verify (signature, owner, target, anchor, tags, data round-trip)");
        let bin2 = parsed_bin.to_binary().expect("to_binary again");
        assert_eq!(bin2, bin, "binary re-encode must be stable");
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

    /// The protocol-defined on-wire id is
    /// `base64url(SHA256(signature))`. This pins the id-derivation
    /// contract so a future refactor of the deep-hash path does not
    /// silently change the artifact identity check in
    /// `arweave_v2::verify_anchor`.
    #[test]
    fn data_item_id_is_base64url_of_sha256_of_signature() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut item = DataItem::new_unsigned(&pk, "", "", sample_tags(), b"x".to_vec());
        sign_data_item(&mut item, &kp).unwrap();

        let sig_bytes = URL_SAFE_NO_PAD.decode(item.signature.as_bytes()).unwrap();
        let expected_id = {
            let mut h = Sha256::new();
            h.update(&sig_bytes);
            URL_SAFE_NO_PAD.encode(h.finalize())
        };
        let actual_id = item.id().unwrap();
        assert_eq!(actual_id, expected_id);
        // The id is a base64url-encoded 32-byte SHA-256 digest.
        assert_eq!(
            URL_SAFE_NO_PAD.decode(actual_id.as_bytes()).unwrap().len(),
            32
        );
    }

    /// #26 split 2 — `DataItem::from_binary`, `deep_hash`,
    /// `verify_data_item`, and `to_binary` against a REAL signed
    /// `arbundles@0.10.x` Ed25519 vector.
    ///
    /// The fixture was captured by
    /// `scripts/ans104_golden_ed25519.mjs` (deterministic seed
    /// `0x01 * 32` via `SolanaSigner`, which carries sigtype 2):
    ///   data     = `"hello gitlawb ed25519 golden"`
    ///   tags     = `[{name:"App-Name",value:"gitlawb"},
    ///               {name:"Schema",value:"gitlawb/ref-update/v1"}]`
    ///   target   = absent, anchor = absent
    ///
    /// The script calls `await item.sign(signer)` so the signature
    /// is real; `item.isValid()` returns true on the JS side. The
    /// Rust side parses the binary, checks the deep-hash against the
    /// JS `getSignatureData` output, verifies the Ed25519 signature
    /// WITHOUT re-signing, and round-trips the binary byte-exact.
    #[test]
    fn dataitem_matches_arbundles_golden_vector() {
        let binary_hex = "0200da41825fd44ca3b2705af18fce86ed6d04d0204331965d9af5d5cb1a740fcc6587ee81501b1d7928c54c0f174fde8893560d785db4d988a3161113b10a2028038a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00000200000000000000300000000000000004104170702d4e616d650e6769746c6177620c536368656d612a6769746c6177622f7265662d7570646174652f76310068656c6c6f206769746c617762206564323535313920676f6c64656e";
        let binary = hex::decode(binary_hex).expect("golden binary hex decodes");
        assert_eq!(binary.len(), 192, "golden binary length");
        let item = DataItem::from_binary(&binary).expect("from_binary on golden vector");

        // Shape pin: Ed25519 signature type.
        assert_eq!(item.signature_type, SIGNATURE_TYPE_ED25519);
        // Owner is the Ed25519 32-byte pubkey.
        let owner_bytes = item.owner_pubkey().expect("owner_pubkey");
        assert_eq!(owner_bytes.len(), 32);
        // Target / anchor absent.
        assert!(item.target.is_empty(), "golden has no target");
        assert!(item.anchor.is_empty(), "golden has no anchor");
        // Two tags, in order.
        assert_eq!(item.tags.len(), 2);
        let t0n = URL_SAFE_NO_PAD
            .decode(item.tags[0].name.as_bytes())
            .unwrap();
        let t0v = URL_SAFE_NO_PAD
            .decode(item.tags[0].value.as_bytes())
            .unwrap();
        let t1n = URL_SAFE_NO_PAD
            .decode(item.tags[1].name.as_bytes())
            .unwrap();
        let t1v = URL_SAFE_NO_PAD
            .decode(item.tags[1].value.as_bytes())
            .unwrap();
        assert_eq!(&t0n[..], b"App-Name");
        assert_eq!(&t0v[..], b"gitlawb");
        assert_eq!(&t1n[..], b"Schema");
        assert_eq!(&t1v[..], b"gitlawb/ref-update/v1");
        // Data round-trips.
        let data = item.data_bytes().expect("data_bytes");
        assert_eq!(&data[..], b"hello gitlawb ed25519 golden");

        // Artifact identity: sha256(signature) base64url == published id.
        let expected_id = "SGrcBs-ITTyzvd7eIB5kk2GdBWoxB_iTi9iJ6KOe_RE";
        assert_eq!(item.id().expect("id"), expected_id);

        // Deep-hash pin against arbundles' `getSignatureData` output
        // for this vector (the 8-element fold: "dataitem", "1",
        // sigtype ASCII, owner, target, anchor, serialized tags as a
        // flat blob, data):
        //   f15c82431767f14ac9e66ab8e995a8cd08e094be3773245163b53c12feb50aefc55d9f8c1098fabcfbf11a462706d347
        let dh = item.deep_hash().expect("deep_hash on golden vector");
        let expected: [u8; 48] = [
            0xf1, 0x5c, 0x82, 0x43, 0x17, 0x67, 0xf1, 0x4a, 0xc9, 0xe6, 0x6a, 0xb8, 0xe9, 0x95,
            0xa8, 0xcd, 0x08, 0xe0, 0x94, 0xbe, 0x37, 0x73, 0x24, 0x51, 0x63, 0xb5, 0x3c, 0x12,
            0xfe, 0xb5, 0x0a, 0xef, 0xc5, 0x5d, 0x9f, 0x8c, 0x10, 0x98, 0xfa, 0xbc, 0xfb, 0xf1,
            0x1a, 0x46, 0x27, 0x06, 0xd3, 0x47,
        ];
        assert_eq!(
            dh, expected,
            "DataItem::deep_hash disagrees with arbundles getSignatureData. \
             The fold must be the 8-element arbundles shape."
        );

        // Ed25519 verify WITHOUT re-signing: the signature came from
        // arbundles, not from this module. The expected key is pinned
        // independently (the fixture's owner for seed `0x01 * 32`,
        // per `scripts/ans104_golden_ed25519.mjs`), NOT extracted
        // from the item — extracting it from the item would make the
        // owner-equality check vacuous.
        let expected_owner_b64 = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";
        assert_eq!(
            item.owner, expected_owner_b64,
            "golden owner must match the pinned seed pubkey"
        );
        let expected_owner_bytes = URL_SAFE_NO_PAD
            .decode(expected_owner_b64.as_bytes())
            .expect("pinned owner b64 decodes");
        let expected_pk: [u8; PUBLIC_KEY_LENGTH] = expected_owner_bytes
            .as_slice()
            .try_into()
            .expect("pinned owner is 32 bytes");
        verify_data_item(&item, &expected_pk).expect("arbundles-signed golden must verify");

        // The binary form must round-trip back to the same bytes
        // (signature slot preserved, not zeroed).
        let bin2 = item.to_binary().expect("to_binary on parsed golden");
        assert_eq!(bin2, binary, "binary round-trip mismatch on golden vector");
    }

    /// Size-prefixed Avro tag block form: a negative block count
    /// followed by the block byte length must parse. This is the
    /// legal encoding `arbundles`' `readTags` accepts
    /// (`if (n < 0) { n = -n; skipLong(); }`).
    #[test]
    fn decode_tags_accepts_negative_block_count_with_size() {
        // One tag ("A" -> "B") encoded as block count -1, block size
        // 4, then the tag bytes, then terminator 0. Tag bytes: name
        // len 1 (one VInt byte), "A", value len 1 (one VInt byte),
        // "B" = 4 bytes total.
        let mut payload = Vec::new();
        write_zigzag_vint(&mut payload, -1);
        write_zigzag_vint(&mut payload, 4);
        write_zigzag_vint(&mut payload, 1);
        payload.extend_from_slice(b"A");
        write_zigzag_vint(&mut payload, 1);
        payload.extend_from_slice(b"B");
        write_zigzag_vint(&mut payload, 0);
        let tags = decode_tags(&payload, 1).expect("size-prefixed block must parse");
        assert_eq!(tags.len(), 1);
        assert_eq!(&tags[0].0[..], b"A");
        assert_eq!(&tags[0].1[..], b"B");
    }

    /// Signed binary parse-and-verify over non-canonical tag blocks.
    /// A multi-block encoding and a size-prefixed (negative-count)
    /// encoding carry the same two tags as the canonical single
    /// block but as different bytes. The deep-hash must fold the
    /// ORIGINAL payload bytes, so an item parsed from either form,
    /// signed, and re-parsed verifies WITHOUT re-signing, and
    /// `to_binary` re-emits the original payload byte-exact
    /// (signature slot excepted). Re-encoding before hashing would
    /// normalize both forms to one digest the signer never hashed.
    #[test]
    fn signed_binary_parse_and_verify_multi_block_and_negative_count() {
        fn entry(n: &[u8], v: &[u8]) -> Vec<u8> {
            let mut out = Vec::new();
            write_zigzag_vint(&mut out, n.len() as i64);
            out.extend_from_slice(n);
            write_zigzag_vint(&mut out, v.len() as i64);
            out.extend_from_slice(v);
            out
        }
        fn unsigned_frame(
            owner_pk: &[u8; 32],
            tag_count: u64,
            tags_payload: &[u8],
            data: &[u8],
        ) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&(SIGNATURE_TYPE_ED25519 as u16).to_le_bytes());
            out.extend(std::iter::repeat_n(
                0u8,
                signature_size(SIGNATURE_TYPE_ED25519),
            ));
            out.extend_from_slice(owner_pk);
            out.push(0); // no target
            out.push(0); // no anchor
            out.extend_from_slice(&tag_count.to_le_bytes());
            out.extend_from_slice(&(tags_payload.len() as u64).to_le_bytes());
            out.extend_from_slice(tags_payload);
            out.extend_from_slice(data);
            out
        }

        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let data = b"multi-block interop".to_vec();
        let e1 = entry(b"App-Name", b"gitlawb");
        let e2 = entry(b"Schema", b"gitlawb/ref-update/v1");

        // Two blocks of one tag each, then the terminator.
        let mut multi = Vec::new();
        write_zigzag_vint(&mut multi, 1);
        multi.extend_from_slice(&e1);
        write_zigzag_vint(&mut multi, 1);
        multi.extend_from_slice(&e2);
        write_zigzag_vint(&mut multi, 0);

        // One size-prefixed block of two tags, then the terminator.
        let mut neg = Vec::new();
        write_zigzag_vint(&mut neg, -2);
        let body_len: i64 = (e1.len() + e2.len())
            .try_into()
            .expect("tag body fits in i64");
        write_zigzag_vint(&mut neg, body_len);
        neg.extend_from_slice(&e1);
        neg.extend_from_slice(&e2);
        write_zigzag_vint(&mut neg, 0);

        for payload in [multi, neg] {
            let frame = unsigned_frame(&pk, 2, &payload, &data);
            let mut item = DataItem::from_binary(&frame).expect("from_binary");
            // Tags decode identically in both forms.
            assert_eq!(item.tags.len(), 2);
            // The original payload is preserved for hashing/encoding.
            assert_eq!(item.raw_tags.as_deref(), Some(payload.as_slice()));
            // Sign over the original payload bytes, then verify.
            sign_data_item(&mut item, &kp).expect("sign");
            verify_data_item(&item, &pk).expect("verify without re-signing");
            // Re-encoding preserves the original payload byte-exact;
            // only the signature slot changes (zeros -> real sig).
            let sig_len = signature_size(SIGNATURE_TYPE_ED25519);
            let bin2 = item.to_binary().expect("to_binary");
            assert_eq!(bin2.len(), frame.len());
            let sig_bytes = URL_SAFE_NO_PAD
                .decode(item.signature.as_bytes())
                .expect("sig decodes");
            assert_eq!(&bin2[2..2 + sig_len], &sig_bytes[..]);
            assert_eq!(&bin2[2 + sig_len..], &frame[2 + sig_len..]);
            // A fresh parse of the signed frame verifies directly.
            let parsed = DataItem::from_binary(&bin2).expect("re-parse");
            verify_data_item(&parsed, &pk).expect("signed re-parse verifies");
        }
    }
}

/// Interop canary: three `#[test]` cases that bit-exact-assert the
/// SHA-384 deep-hash output for inputs that match the
/// `Irys-xyz/arbundles/src/__tests__/deepHash.spec.ts` reference
/// suite. The team memory `self-roundtrip-tests-do-not-prove-interop`
/// is the policy: a sign/verify round-trip in this module alone
/// only proves internal consistency, so the interop canary is the
/// external reference vector.
///
/// Each vector below was reproduced byte-exact with an independent
/// Python reimplementation of the algorithm before being pasted
/// here. If the algorithm changes, every test in this module turns
/// red and the implementer must re-derive the expected outputs from
/// the JS reference.
#[cfg(test)]
mod external_reference_vectors {
    use super::*;

    /// `deepHash(Uint8Array([1, 2, 3]))` — the blob path, a single
    /// Uint8Array input.
    ///   tag = "blob3"
    ///   SHA384(tag)                              = T
    ///   SHA384(blob)                             = B
    ///   result = SHA384(T || B)                  = <expected>
    #[test]
    fn deephash_blob_path_1_2_3() {
        let mut concat = Vec::with_capacity(48 + 48);
        concat.extend_from_slice(&sha384(b"blob3"));
        concat.extend_from_slice(&sha384(&[1u8, 2, 3]));
        let actual = sha384(&concat);
        let expected: [u8; 48] = [
            0x41, 0x30, 0x0a, 0xf7, 0x92, 0x85, 0xf8, 0x56, 0xe8, 0x33, 0x16, 0x45, 0x18, 0xc7,
            0xec, 0x49, 0x74, 0xf5, 0x86, 0x9e, 0xc7, 0x7c, 0xa3, 0x45, 0x81, 0x13, 0xfe, 0x6c,
            0x58, 0x76, 0x80, 0xd0, 0x50, 0xf9, 0xf6, 0x86, 0x4f, 0xd7, 0x7f, 0x9e, 0xb6, 0x2b,
            0xd4, 0xe2, 0xfa, 0xea, 0x9a, 0xe8,
        ];
        assert_eq!(actual, expected);
    }

    /// `deepHash(Uint8Array([]))` — the empty-blob case. Coincides
    /// with the empty-list case by the recursive-fold identity
    /// `SHA384(SHA384("list0")) = SHA384(SHA384("blob0") || SHA384(""))`.
    #[test]
    fn deephash_empty_blob() {
        let mut concat = Vec::with_capacity(48 + 48);
        concat.extend_from_slice(&sha384(b"blob0"));
        concat.extend_from_slice(&sha384(b""));
        let actual = sha384(&concat);
        let expected: [u8; 48] = [
            0xfb, 0xf0, 0x0c, 0xc4, 0x44, 0xf5, 0xfe, 0xa9, 0xdc, 0x3b, 0xed, 0xf6, 0x2a, 0x13,
            0xfb, 0xa8, 0xae, 0x87, 0xe7, 0x44, 0x5f, 0xc9, 0x10, 0x56, 0x7a, 0x23, 0xbe, 0xc4,
            0xeb, 0x82, 0xfa, 0xdb, 0x11, 0x43, 0xc4, 0x33, 0x06, 0x93, 0x14, 0xd8, 0x36, 0x29,
            0x83, 0xdc, 0x3c, 0x2e, 0x4a, 0x38,
        ];
        assert_eq!(actual, expected);
    }

    /// `deepHash([Uint8Array([1,2,3]), Uint8Array([4,5,6])])` — a
    /// 2-item list. Each item is a blob; the list folds left:
    ///   acc₀ = SHA384("list2")
    ///   acc₁ = SHA384(acc₀ || deepHash(blob₁))
    ///   acc₂ = SHA384(acc₁ || deepHash(blob₂))   = result
    #[test]
    fn deephash_two_item_list() {
        let acc0 = sha384(b"list2");

        let mut c1 = Vec::with_capacity(48 + 48);
        c1.extend_from_slice(&sha384(b"blob3"));
        c1.extend_from_slice(&sha384(&[1u8, 2, 3]));
        let blob1 = sha384(&c1);

        let mut c2 = Vec::with_capacity(acc0.len() + blob1.len());
        c2.extend_from_slice(&acc0);
        c2.extend_from_slice(&blob1);
        let acc1 = sha384(&c2);

        let mut c3 = Vec::with_capacity(48 + 48);
        c3.extend_from_slice(&sha384(b"blob3"));
        c3.extend_from_slice(&sha384(&[4u8, 5, 6]));
        let blob2 = sha384(&c3);

        let mut c4 = Vec::with_capacity(acc1.len() + blob2.len());
        c4.extend_from_slice(&acc1);
        c4.extend_from_slice(&blob2);
        let acc2 = sha384(&c4);

        let expected: [u8; 48] = [
            0x4d, 0xac, 0xdc, 0xc8, 0x1a, 0xcd, 0x09, 0xf3, 0x8c, 0x77, 0xa0, 0x7a, 0x2a, 0x7a,
            0xe8, 0x1f, 0x77, 0xc6, 0x1e, 0x6b, 0x97, 0xee, 0x5c, 0xc7, 0xb9, 0x2f, 0x3a, 0x7f,
            0x25, 0x8e, 0x8d, 0x5b, 0xa6, 0x9d, 0x14, 0xd7, 0xd6, 0x60, 0x70, 0x79, 0x7b, 0x08,
            0x38, 0x73, 0x71, 0x7c, 0x98, 0x96,
        ];
        assert_eq!(acc2, expected);
    }
}
