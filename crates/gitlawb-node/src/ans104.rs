//! ANS-104 signed data items for Arweave bundler uploads.
//!
//! Bundlers (Irys, Turbo, ...) accept a raw **Arweave data item** on their
//! upload endpoint and verify the embedded Ed25519 signature before accepting
//! the upload, so the item provably originates from this node's keypair. The
//! signature authenticates the item's authorship — it is NOT payment. The
//! bundler charges each upload against a funded account and rejects items whose
//! account is unfunded. The node therefore carries a funded account and payment
//! token in its config (`GITLAWB_BUNDLER_ACCOUNT`, `GITLAWB_BUNDLER_TOKEN`) and
//! sends them on every upload as the Irys `x-irys-paid-by` header to
//! `/tx/{token}`; `Config::validate()` refuses to start with a bundler URL but
//! no funded account.
//!
//! Binary layout (per the ANS-104 spec, ed25519 = signature type 2):
//!
//! ```text
//!  0   2   signature type (u16 LE) = 2
//!  2   66  signature (64 bytes)
//!  66  98  owner public key (32 bytes)
//!  98      target presence byte (0 = absent)
//!  99      anchor presence byte (0 = absent)
//!  100 108 number of tags (u64 LE)
//!  108 116 number of tag bytes (u64 LE)
//!  116 ... serialized tags (Avro-style, see `serialize_tags`)
//!  ...     data (runs to end of buffer)
//! ```
//!
//! The signature covers `deepHash(["dataitem", "1", type, owner, target,
//! anchor, tags, data])` using the bundler deepHash (recursive length-tagged
//! SHA-384, identical to the published `arbundles` package), so a bundler,
//! gateway, or the node itself can re-derive it from the item's own fields and
//! verify against the owner. The `tags` element is the FLAT serialized tag
//! stream (`item.rawTags` in `arbundles`' `getSignatureData`) — NOT a nested
//! list. The nested `[[name, value], ...]` form is what Arweave layer-one
//! transactions use; data items deep-hash the serialized tag blob. Zero tags is
//! an empty blob.

use anyhow::Result;
#[cfg(test)]
use anyhow::{anyhow, bail};
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha384};

/// SignatureConfig value for Ed25519 data items (ANS-104).
pub const SIGNATURE_TYPE_ED25519: u16 = 2;
const SIGNATURE_LEN: usize = 64;
const OWNER_LEN: usize = 32;

/// Parsed contents of a verified data item. Verification is exercised by the
/// enforcement tests (see `verify_data_item`), which is gated on `cfg(test)`.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub struct DataItem {
    pub signature: [u8; 64],
    pub owner: [u8; 32],
    pub tags: Vec<(String, String)>,
    pub data: Vec<u8>,
}

/// Build and sign an ANS-104 data item carrying `data` plus the given tags.
///
/// The tags are embedded *inside* the item (where the bundler verifies them
/// against the signature); nothing is passed out-of-band.
pub fn build_signed_data_item(
    keypair: &gitlawb_core::identity::Keypair,
    tags: &[(&str, &str)],
    data: &[u8],
) -> Result<Vec<u8>> {
    let owner = keypair.verifying_key().to_bytes();
    let serialized_tags = serialize_tags(tags)?;

    let mut item = Vec::with_capacity(
        2 + SIGNATURE_LEN + OWNER_LEN + 2 + 16 + serialized_tags.len() + data.len(),
    );
    item.extend_from_slice(&SIGNATURE_TYPE_ED25519.to_le_bytes()); // 0..2
    item.extend_from_slice(&[0u8; SIGNATURE_LEN]); // 2..66, filled below
    item.extend_from_slice(&owner); // 66..98
    item.push(0u8); // target presence: absent
    item.push(0u8); // anchor presence: absent
    item.extend_from_slice(&(tags.len() as u64).to_le_bytes()); // 100..108
    item.extend_from_slice(&(serialized_tags.len() as u64).to_le_bytes()); // 108..116
    item.extend_from_slice(&serialized_tags);
    item.extend_from_slice(data);

    let signature_data = deep_hash(&[
        b"dataitem",
        b"1",
        SIGNATURE_TYPE_ED25519.to_string().as_bytes(),
        &owner,
        &[],
        &[],
        &serialized_tags,
        data,
    ]);
    let signature = keypair.sign(&signature_data).to_bytes();
    item[2..2 + SIGNATURE_LEN].copy_from_slice(&signature);
    Ok(item)
}

/// The ANS-104 data-item id: `base64url(sha256(signature))` where signature
/// is bytes 2..66 (the 64-byte Ed25519 signature) of the serialized item.
/// This is the id the bundler returns for a data item and the id gateways
/// resolve `{gateway}/{id}` under, so it is a stable, content-derived remote
/// identity: the durable job persists it BEFORE the upload request is sent,
/// and a recovery probes that id to decide whether a crashed upload actually
/// landed before ever issuing a second paid request (#224 review).
///
/// Note: this differs from hashing the complete serialized item — the id is
/// derived solely from the signature bytes, per the ANS-104 specification.
pub fn data_item_id(item: &[u8]) -> String {
    if item.len() < 2 + SIGNATURE_LEN {
        // Invalid item: return an impossible ID so callers fail safe
        return base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(b"invalid data item"));
    }
    let signature_region = &item[2..2 + SIGNATURE_LEN];
    let digest = Sha256::digest(signature_region);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Parse a data item and verify its Ed25519 signature against `verifying_key`
/// over the deepHash of its own fields. Returns the parsed item (tags + data)
/// on success. This is exactly what a bundler/gateway does on receipt, so a
/// test can use it to enforce the signed-upload contract.
#[cfg(test)]
pub fn verify_data_item(
    verifying_key: &ed25519_dalek::VerifyingKey,
    item: &[u8],
) -> Result<DataItem> {
    if item.len() < 2 + SIGNATURE_LEN + OWNER_LEN + 2 + 16 {
        bail!("data item too short");
    }
    let signature_type = u16::from_le_bytes(item[0..2].try_into()?);
    if signature_type != SIGNATURE_TYPE_ED25519 {
        bail!("unsupported signature type {signature_type}");
    }
    let signature: [u8; SIGNATURE_LEN] = item[2..2 + SIGNATURE_LEN].try_into()?;
    let owner: [u8; OWNER_LEN] =
        item[2 + SIGNATURE_LEN..2 + SIGNATURE_LEN + OWNER_LEN].try_into()?;

    let mut p = 2 + SIGNATURE_LEN + OWNER_LEN;
    let target_present = item[p];
    p += 1;
    let raw_target: &[u8] = match target_present {
        0 => &[],
        1 => {
            let end = p + OWNER_LEN;
            if end > item.len() {
                bail!("data item truncated in target");
            }
            let t = &item[p..end];
            p = end;
            t
        }
        other => bail!("invalid target presence byte {other}"),
    };
    let anchor_present = item[p];
    p += 1;
    let raw_anchor: &[u8] = match anchor_present {
        0 => &[],
        1 => {
            let end = p + OWNER_LEN;
            if end > item.len() {
                bail!("data item truncated in anchor");
            }
            let a = &item[p..end];
            p = end;
            a
        }
        other => bail!("invalid anchor presence byte {other}"),
    };

    let num_tags = u64::from_le_bytes(item[p..p + 8].try_into()?);
    p += 8;
    let num_tag_bytes = u64::from_le_bytes(item[p..p + 8].try_into()?);
    p += 8;
    let tags_end = p
        .checked_add(num_tag_bytes as usize)
        .ok_or_else(|| anyhow!("tag byte count overflow"))?;
    if tags_end > item.len() {
        bail!("data item truncated in tags");
    }
    let raw_tags = &item[p..tags_end];
    let raw_data = &item[tags_end..];

    let tags = deserialize_tags(raw_tags)?;
    if tags.len() != num_tags as usize {
        bail!(
            "tag count {} disagrees with serialized length {}",
            tags.len(),
            num_tags
        );
    }

    let signature_data = deep_hash(&[
        b"dataitem",
        b"1",
        signature_type.to_string().as_bytes(),
        &owner,
        raw_target,
        raw_anchor,
        raw_tags,
        raw_data,
    ]);
    let sig = ed25519_dalek::Signature::from_bytes(&signature);
    verifying_key
        .verify_strict(&signature_data, &sig)
        .map_err(|e| anyhow!("data item signature verification failed: {e}"))?;

    Ok(DataItem {
        signature,
        owner,
        tags,
        data: raw_data.to_vec(),
    })
}

/// The bundler's `deepHash` over the data item's signature fields,
/// byte-for-byte identical to the published `arbundles` `deepHash` for the
/// all-blob preimage a data item uses: seeded by SHA-384("list<N>") over the
/// element count, then each element chained as SHA-384(acc || blob-chunk)
/// where a blob-chunk is SHA-384(SHA-384("blob<len>") || SHA-384(data)). The
/// bundler also recurses for nested list elements, but a data item's signature
/// fields are all blobs (tags included — see the module docs), so no nesting
/// is needed here.
pub fn deep_hash(elems: &[&[u8]]) -> [u8; 48] {
    let mut acc = sha384(format!("list{}", elems.len()).as_bytes());
    for elem in elems {
        let chunk = deep_hash_blob(elem);
        let mut pair = [0u8; 96];
        pair[..48].copy_from_slice(&acc);
        pair[48..].copy_from_slice(&chunk);
        acc = sha384(&pair);
    }
    acc
}

fn deep_hash_blob(data: &[u8]) -> [u8; 48] {
    let mut tagged = [0u8; 96];
    tagged[..48].copy_from_slice(&sha384(format!("blob{}", data.len()).as_bytes()));
    tagged[48..].copy_from_slice(&sha384(data));
    sha384(&tagged)
}

fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().into()
}

/// Avro-style tag encoding matching the published `arbundles` `serializeTags`.
/// The serialized stream is the `tags` preimage element (`item.rawTags`), so a
/// bundler recomputes the signature from the exact bytes the item carries.
///
/// For `n > 0` tags: zigzag-varint(n), then for each tag the zigzag-varint
/// length + UTF-8 bytes of name and value, then a terminating zigzag-varint(0).
/// Zero tags serializes to an empty buffer.
fn serialize_tags(tags: &[(&str, &str)]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if tags.is_empty() {
        return Ok(out);
    }
    write_long(&mut out, tags.len() as i64)?;
    for (name, value) in tags {
        write_string(&mut out, name)?;
        write_string(&mut out, value)?;
    }
    write_long(&mut out, 0)?;
    Ok(out)
}

#[cfg(test)]
fn deserialize_tags(buf: &[u8]) -> Result<Vec<(String, String)>> {
    let mut pos = 0usize;
    let mut tags = Vec::new();
    loop {
        let n = read_long(buf, &mut pos)?;
        if n == 0 {
            break;
        }
        let mut count = n;
        if n < 0 {
            // Negative array length: block count + a block byte-size to skip.
            count = -n;
            let _block_size = read_long(buf, &mut pos)?;
        }
        for _ in 0..count {
            let name = read_string(buf, &mut pos)?;
            let value = read_string(buf, &mut pos)?;
            tags.push((name, value));
        }
    }
    Ok(tags)
}

fn write_string(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    write_long(out, bytes.len() as i64)?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
fn read_string(buf: &[u8], pos: &mut usize) -> Result<String> {
    let len = read_long(buf, pos)?;
    if len < 0 {
        bail!("negative string length");
    }
    let len = len as usize;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow!("string length overflow"))?;
    if end > buf.len() {
        bail!("tag stream truncated in string");
    }
    let s = std::str::from_utf8(&buf[*pos..end])?.to_string();
    *pos = end;
    Ok(s)
}

/// Zigzag + base-128 varint (Avro `writeLong`).
fn write_long(out: &mut Vec<u8>, n: i64) -> Result<()> {
    let mut m = ((n as u64) << 1) ^ ((n >> 63) as u64);
    loop {
        let mut byte = (m & 0x7f) as u8;
        m >>= 7;
        if m != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if m == 0 {
            break;
        }
    }
    Ok(())
}

/// Zigzag + base-128 varint (Avro `readLong`).
#[cfg(test)]
fn read_long(buf: &[u8], pos: &mut usize) -> Result<i64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *pos >= buf.len() {
            bail!("tag stream truncated in varint");
        }
        let byte = buf[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("tag stream varint overlong");
        }
    }
    Ok(((value >> 1) as i64) ^ -((value & 1) as i64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitlawb_core::identity::Keypair;

    /// Independent reference vector, generated with the published `arbundles`
    /// package's `deepHash` (not the code under test) over the ANS-104 spec
    /// preimage. Pins the deepHash wire format — decimal-ASCII length tags,
    /// recursive list handling, chained SHA-384 — so an accidental divergence
    /// in the length-tagging (e.g. reintroducing the old pairwise chaining) or
    /// in the tags element turns this test red and every previously-signed
    /// anchor would no longer verify.
    #[test]
    fn deep_hash_matches_independent_reference_vector() {
        let owner = [0x41u8; 32];
        // Elements: "dataitem", "1", "2", owner, target, anchor, tags, data.
        // 0 tags -> tags element is an EMPTY BLOB (deepHash([]) = SHA384("list0")
        // would be a different value): data items hash the flat serialized tag
        // stream, and an empty tag stream is zero bytes.
        let hash = deep_hash(&[b"dataitem", b"1", b"2", &owner, &[], &[], &[], b"hi"]);
        let expected = "98a0a3b931f9c5cc370e822ca06b6e9635f690f81979b70b6dfe92d0af3f601169b0d8dc72d518241e3caba7f9daad1d";
        assert_eq!(hex::encode(hash), expected);
    }

    /// Full-serialization interoperability fixture produced by the published
    /// `arbundles` package: `createData` + `sign` (its own `getSignatureData`
    /// deepHash over the flat `item.rawTags`, plus its Ed25519 signer) with
    /// NONEMPTY tags. Proves the flat-tags preimage and the binary layout
    /// interop with the real bundler toolchain — a round trip through this
    /// module alone is not enough, and the node's own signer must produce
    /// items a bundler (and this verifier) accepts.
    #[test]
    fn verify_data_item_matches_independent_interop_fixture() {
        let owner_hex = "d520b4cc5001a7ce12d1aaad57d6fd8e4b1c7b9926f699e6f778fb69f7e6f98b";
        let item_hex = "0200611e031059cf0395a990a1cd59e7c73f877cd36a065795630f9d1858a111d34e9db705dd01b6e2dbf0f5bbe9d6f8d5111d420512f60b80b7dfa7448a83c22e0bd520b4cc5001a7ce12d1aaad57d6fd8e4b1c7b9926f699e6f778fb69f7e6f98b00000300000000000000420000000000000006104170702d4e616d650e6769746c617762085265706f18616c6963652f6d797265706f0c536368656d612a6769746c6177622f7265662d7570646174652f7631007b22736368656d61223a226769746c6177622f7265662d7570646174652f7631222c227265706f223a22616c6963652f6d797265706f227d";
        let owner: [u8; 32] = hex::decode(owner_hex).unwrap().try_into().unwrap();
        let item = hex::decode(item_hex).unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&owner).unwrap();

        let parsed = verify_data_item(&key, &item).unwrap();
        assert_eq!(
            parsed.tags,
            vec![
                ("App-Name".to_string(), "gitlawb".to_string()),
                ("Repo".to_string(), "alice/myrepo".to_string()),
                ("Schema".to_string(), "gitlawb/ref-update/v1".to_string()),
            ]
        );
        assert_eq!(
            parsed.data,
            br#"{"schema":"gitlawb/ref-update/v1","repo":"alice/myrepo"}"#
        );
        assert_eq!(parsed.owner, owner);
    }

    #[test]
    fn serialize_tags_matches_reference_layout() {
        assert!(serialize_tags(&[]).unwrap().is_empty());
        // 1 tag: zigzag(1)=0x02, then name/value as varint-len + utf8,
        // then terminating 0x00.
        let one = serialize_tags(&[("App-Name", "gitlawb")]).unwrap();
        assert_eq!(
            one,
            [
                0x02, // zigzag(1) = array count 1
                0x10, // zigzag(8) = "App-Name".len()
                b'A', b'p', b'p', b'-', b'N', b'a', b'm', b'e',
                0x0e, // zigzag(7) = "gitlawb".len()
                b'g', b'i', b't', b'l', b'a', b'w', b'b', 0x00, // end of array
            ]
        );
    }

    #[test]
    fn build_then_verify_round_trip() {
        let kp = Keypair::generate();
        let data = br#"{"schema":"gitlawb/ref-update/v1","repo":"alice/myrepo"}"#;
        let item = build_signed_data_item(
            &kp,
            &[("App-Name", "gitlawb"), ("Repo", "alice/myrepo")],
            data,
        )
        .unwrap();

        // Layout sanity: sig type first, owner at its fixed offset.
        assert_eq!(&item[0..2], &[0x02, 0x00]);
        assert_eq!(
            &item[2 + SIGNATURE_LEN..2 + SIGNATURE_LEN + OWNER_LEN],
            &kp.verifying_key().to_bytes()
        );

        let parsed = verify_data_item(&kp.verifying_key(), &item).unwrap();
        assert_eq!(
            parsed.tags,
            vec![
                ("App-Name".to_string(), "gitlawb".to_string()),
                ("Repo".to_string(), "alice/myrepo".to_string()),
            ]
        );
        assert_eq!(parsed.data, data);
        assert_eq!(parsed.owner, kp.verifying_key().to_bytes());
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let kp = Keypair::generate();
        let item = build_signed_data_item(&kp, &[("App-Name", "gitlawb")], b"payload").unwrap();
        let mut forged = item.clone();
        forged[3] ^= 0x01;
        assert!(verify_data_item(&kp.verifying_key(), &forged).is_err());
    }

    #[test]
    fn verify_rejects_item_signed_by_other_key() {
        let node = Keypair::generate();
        let attacker = Keypair::generate();
        let item =
            build_signed_data_item(&attacker, &[("App-Name", "gitlawb")], b"payload").unwrap();
        assert!(
            verify_data_item(&node.verifying_key(), &item).is_err(),
            "item signed by a different key must not verify against the node key"
        );
    }

    #[test]
    fn verify_rejects_altered_data_or_tags() {
        let kp = Keypair::generate();
        let item = build_signed_data_item(&kp, &[("Repo", "alice/real")], b"original").unwrap();
        let mut tampered_data = item.clone();
        let n = tampered_data.len();
        tampered_data[n - 1] ^= 0x01;
        assert!(verify_data_item(&kp.verifying_key(), &tampered_data).is_err());
        // Tag value flipped inside the item.
        let mut tampered_tag = item;
        tampered_tag[120] = b'x';
        assert!(verify_data_item(&kp.verifying_key(), &tampered_tag).is_err());
    }

    #[test]
    fn verify_rejects_truncated_and_garbage_items() {
        let kp = Keypair::generate();
        let item = build_signed_data_item(&kp, &[("App-Name", "gitlawb")], b"payload").unwrap();
        assert!(verify_data_item(&kp.verifying_key(), &item[..item.len() - 1]).is_err());
        assert!(verify_data_item(&kp.verifying_key(), b"not a data item").is_err());
    }
}
