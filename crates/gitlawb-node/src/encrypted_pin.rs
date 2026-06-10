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

/// Resolve a DID string to its Ed25519 verifying key, or None if it carries no
/// inline key (e.g. did:web / did:gitlawb).
fn did_to_key(did: &str) -> Option<VerifyingKey> {
    Did::from_str(did).ok()?.to_verifying_key().ok()
}

/// Encrypt and pin every withheld blob. `recipients` maps blob oid -> DID set.
pub async fn encrypt_and_pin(
    ipfs_api: &str,
    repo_path: &Path,
    db: &Db,
    repo_id: &str,
    recipients: &HashMap<String, BTreeSet<String>>,
) {
    for (oid, dids) in recipients {
        if db.has_encrypted_blob(repo_id, oid).await.unwrap_or(false) {
            continue;
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
        let dids_vec: Vec<String> = dids.iter().cloned().collect();
        if let Err(e) = db.record_encrypted_blob(repo_id, oid, &cid, &dids_vec).await {
            tracing::warn!(oid = %oid, err = %e, "record_encrypted_blob failed");
        }
    }
}
