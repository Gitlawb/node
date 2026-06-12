//! Encrypt-then-pin for withheld blobs (Option B1). Each withheld blob is sealed
//! to its recipient DIDs and the envelope pinned to IPFS, recorded in
//! `encrypted_blobs`. Best-effort per blob: a failure is logged and skipped,
//! never pinned in plaintext.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::str::FromStr;

use ed25519_dalek::VerifyingKey;
use gitlawb_core::did::Did;
use gitlawb_core::encrypt::seal_blob;

use crate::db::Db;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Opaque, node-keyed fingerprint of a blob's recipient set. Stored in place of
/// the cleartext DID list so a DB compromise cannot reveal the reader set; used
/// only to detect a recipient-set change so an unchanged blob is not re-sealed.
/// Order-insensitive (the input `BTreeSet` is already sorted).
pub fn recipients_tag(node_seed: &[u8; 32], dids: &BTreeSet<String>) -> String {
    let mut mac = HmacSha256::new_from_slice(node_seed).expect("HMAC accepts any key length");
    mac.update(b"gitlawb/recipients-tag/v1");
    for did in dids {
        mac.update(b"\n");
        mac.update(did.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

/// Resolve a DID string to its Ed25519 verifying key, or None if it carries no
/// inline key (e.g. did:web / did:gitlawb).
fn did_to_key(did: &str) -> Option<VerifyingKey> {
    Did::from_str(did).ok()?.to_verifying_key().ok()
}

/// Encrypt and pin every withheld blob. `recipients` maps blob oid -> DID set;
/// `node_seed` keys the opaque recipients tag. Returns `(oid, cid)` for each blob
/// actually sealed and recorded this call (the per-push delta), used by Option B3
/// to anchor a manifest. Recipient identities are never stored or returned.
pub async fn encrypt_and_pin(
    ipfs_api: &str,
    repo_path: &Path,
    db: &Db,
    repo_id: &str,
    node_seed: &[u8; 32],
    recipients: &HashMap<String, BTreeSet<String>>,
) -> Vec<(String, String)> {
    let mut sealed = Vec::new();
    for (oid, dids) in recipients {
        // Skip only if an existing envelope already covers exactly these
        // recipients. If the recipient set changed (e.g. a reader was added to
        // the rule), re-seal so the new reader can recover the blob. Reader
        // removal is not retroactive: the old envelope is already public. The
        // comparison is on the opaque node-keyed tag, never the DID list.
        let tag = recipients_tag(node_seed, dids);
        if let Ok(Some(stored_tag)) = db.encrypted_blob_recipients_tag(repo_id, oid).await {
            if stored_tag == tag {
                continue;
            }
        }
        let keys: Vec<VerifyingKey> = dids.iter().filter_map(|d| did_to_key(d)).collect();
        if keys.is_empty() {
            tracing::warn!(oid = %oid, "no resolvable recipient keys; skipping encrypted pin");
            continue;
        }
        let data = match crate::git::store::read_object(repo_path, oid) {
            Ok(Some((_t, bytes))) => bytes,
            _ => continue,
        };
        let envelope = match seal_blob(&data, &keys) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(oid = %oid, err = %e, "seal_blob failed; skipping");
                continue;
            }
        };
        let cid = match crate::ipfs_pin::pin_git_object(ipfs_api, oid, &envelope).await {
            Ok(c) if !c.is_empty() => c,
            _ => continue,
        };
        if let Err(e) = db.record_encrypted_blob(repo_id, oid, &cid, &tag).await {
            tracing::warn!(oid = %oid, err = %e, "record_encrypted_blob failed");
            continue;
        }
        sealed.push((oid.clone(), cid.clone()));
    }
    sealed
}

#[cfg(test)]
mod tests {
    use super::recipients_tag;
    use std::collections::BTreeSet;

    fn set(dids: &[&str]) -> BTreeSet<String> {
        dids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tag_is_order_insensitive() {
        let seed = [7u8; 32];
        let a = recipients_tag(&seed, &set(&["did:key:zA", "did:key:zB"]));
        let b = recipients_tag(&seed, &set(&["did:key:zB", "did:key:zA"]));
        assert_eq!(a, b);
    }

    #[test]
    fn tag_differs_for_different_sets() {
        let seed = [7u8; 32];
        let a = recipients_tag(&seed, &set(&["did:key:zA"]));
        let b = recipients_tag(&seed, &set(&["did:key:zA", "did:key:zB"]));
        assert_ne!(a, b);
    }

    #[test]
    fn tag_is_keyed_by_node_seed() {
        let dids = set(&["did:key:zA", "did:key:zB"]);
        let a = recipients_tag(&[1u8; 32], &dids);
        let b = recipients_tag(&[2u8; 32], &dids);
        assert_ne!(
            a, b,
            "tag must depend on the node seed, not be a plain hash"
        );
    }
}
