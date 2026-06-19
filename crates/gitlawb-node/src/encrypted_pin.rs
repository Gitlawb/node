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

/// Resolve every recipient DID to its verifying key. Returns `None` if *any* DID
/// fails to resolve locally (e.g. a did:web / did:gitlawb reader).
///
/// Fail closed rather than sealing to the resolvable subset: a partial seal would
/// silently exclude an authorized reader, and because `recipients_tag` is computed
/// over the full DID set the blob would never be re-sealed once that DID later
/// resolves — locking the reader out permanently.
fn resolve_recipient_keys(dids: &BTreeSet<String>) -> Option<Vec<VerifyingKey>> {
    dids.iter().map(|d| did_to_key(d)).collect()
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
        match db.encrypted_blob_recipients_tag(repo_id, oid).await {
            Ok(Some(stored_tag)) if stored_tag == tag => continue,
            Ok(_) => {}
            Err(e) => {
                // A DB read failure is not a cache miss: re-sealing here would do
                // an avoidable IPFS write during a partial outage. Skip and retry
                // on the next push.
                tracing::warn!(oid = %oid, err = %e, "recipients_tag lookup failed; skipping reseal");
                continue;
            }
        }
        let keys = match resolve_recipient_keys(dids) {
            Some(keys) if !keys.is_empty() => keys,
            Some(_) => {
                tracing::warn!(oid = %oid, "empty recipient set; skipping encrypted pin");
                continue;
            }
            None => {
                // At least one recipient DID is unresolvable; sealing now would
                // exclude it permanently. Skip and retry on the next push.
                tracing::warn!(oid = %oid, "unresolvable recipient DID; skipping encrypted pin rather than sealing to a partial set");
                continue;
            }
        };
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
    use super::{recipients_tag, resolve_recipient_keys};
    use gitlawb_core::did::Did;
    use gitlawb_core::identity::Keypair;
    use std::collections::BTreeSet;

    fn set(dids: &[&str]) -> BTreeSet<String> {
        dids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn resolve_returns_all_keys_when_every_did_resolves() {
        let a = Keypair::generate().did().to_string();
        let b = Keypair::generate().did().to_string();
        let keys = resolve_recipient_keys(&set(&[&a, &b]));
        assert_eq!(keys.map(|k| k.len()), Some(2));
    }

    #[test]
    fn resolve_returns_none_when_any_did_is_unresolvable() {
        let a = Keypair::generate().did().to_string();
        let web = Did::web("example.com").to_string();
        assert!(
            resolve_recipient_keys(&set(&[&a, &web])).is_none(),
            "an unresolvable did:web recipient must abort sealing, not seal to a partial set"
        );
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
