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

/// Resolve every recipient DID to its verifying key, all-or-nothing.
///
/// Returns `Ok(keys)` only when every DID resolves. If any DID fails, returns
/// `Err(unresolved)` listing the unresolvable DID strings so the caller can fail
/// closed rather than seal to a partial recipient set (#47): sealing to a subset
/// while recording the full set as covered permanently locks out the dropped
/// readers. Resolution is local-only, so `did:web`/`did:gitlawb` recipients (and
/// any malformed `did:key`) land in the unresolved set until off-`did:key`
/// resolution exists.
fn resolve_all_recipients(dids: &BTreeSet<String>) -> Result<Vec<VerifyingKey>, Vec<String>> {
    let mut keys = Vec::with_capacity(dids.len());
    let mut unresolved = Vec::new();
    for did in dids {
        match did_to_key(did) {
            Some(k) => keys.push(k),
            None => unresolved.push(did.clone()),
        }
    }
    if unresolved.is_empty() {
        Ok(keys)
    } else {
        Err(unresolved)
    }
}

/// What to do with a single withheld blob, decided without any DB or IO so the
/// fail-closed invariant (#47) is unit-testable in isolation.
#[derive(Debug)]
enum SealPlan {
    /// An existing envelope already covers exactly this recipient set; nothing to do.
    SkipUnchanged,
    /// The stored tag matches, but the stored reader set contains a DID that
    /// must not resolve (e.g. a small-order did:key sealed before the choke
    /// point landed). The old envelope is already public and cannot be
    /// withdrawn, but it must be surfaced for operator action rather than
    /// silently skipped as unchanged.
    SkipUnresolvableStored(Vec<String>),
    /// No recipient DID resolved to a key, so there is nothing to seal to.
    SkipNoRecipients,
    /// At least one recipient DID is unresolvable. Fail closed: never seal to a
    /// partial set. Carries the unresolvable DIDs for logging.
    SkipUnresolvable(Vec<String>),
    /// Seal to `keys` and record coverage under `tag`.
    Seal {
        keys: Vec<VerifyingKey>,
        tag: String,
    },
}

/// Decide what to do with one blob given its desired recipient set and the tag
/// already stored for it (if any). Pure: no DB, no IO.
///
/// This is the #47 fail-closed gate in isolation: it returns `Seal` only when
/// EVERY recipient DID resolves, so no caller can seal to a partial set. A
/// changed recipient set (different tag) re-seals so a newly added reader can
/// recover the blob; reader removal is not retroactive (the old envelope is
/// already public). The comparison is on the opaque node-keyed tag, never the
/// DID list.
///
/// A matching stored tag is normally a skip, but the set is still resolved
/// before skipping: a reader that used to resolve and now must not (a
/// small-order did:key sealed before the choke point landed) is surfaced as
/// [`SealPlan::SkipUnresolvableStored`] instead of being silently treated as
/// unchanged. The old envelope is already public and cannot be withdrawn, but
/// the operator must be able to see that a persisted envelope was sealed to a
/// weak recipient.
fn plan_seal(node_seed: &[u8; 32], dids: &BTreeSet<String>, stored_tag: Option<&str>) -> SealPlan {
    let tag = recipients_tag(node_seed, dids);
    if stored_tag == Some(tag.as_str()) {
        // The stored envelope already covers exactly this set, so there is
        // nothing to re-seal. Resolve anyway so a now-unresolvable reader in an
        // unchanged set is surfaced rather than hidden by the tag match.
        match resolve_all_recipients(dids) {
            Ok(_) => SealPlan::SkipUnchanged,
            Err(unresolved) => SealPlan::SkipUnresolvableStored(unresolved),
        }
    } else {
        match resolve_all_recipients(dids) {
            Ok(keys) if keys.is_empty() => SealPlan::SkipNoRecipients,
            Ok(keys) => SealPlan::Seal { keys, tag },
            Err(unresolved) => SealPlan::SkipUnresolvable(unresolved),
        }
    }
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
    let mut skipped_unresolvable = 0usize;
    for (oid, dids) in recipients {
        // A DB read failure is not a cache miss: re-sealing here would do an
        // avoidable IPFS write during a partial outage. Skip and retry next push.
        let stored_tag = match db.encrypted_blob_recipients_tag(repo_id, oid).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(oid = %oid, err = %e, "recipients_tag lookup failed; skipping reseal");
                continue;
            }
        };
        // Fail closed: plan_seal returns Seal only when every recipient DID
        // resolves, so we never seal to a partial set and record the full set as
        // covered (which would permanently lock out the dropped readers, #47).
        let (keys, tag) = match plan_seal(node_seed, dids, stored_tag.as_deref()) {
            SealPlan::SkipUnchanged => continue,
            SealPlan::SkipUnresolvableStored(unresolved) => {
                // A stored envelope already covers this exact reader set, and
                // the set now contains a DID that must not resolve (a
                // small-order did:key sealed before the choke point landed).
                // The old envelope is already public and cannot be withdrawn
                // or re-sealed; surface it so the operator can act.
                let sample: Vec<&String> = unresolved.iter().take(3).collect();
                tracing::warn!(
                    oid = %oid,
                    unresolved_count = unresolved.len(),
                    unresolved_sample = ?sample,
                    "stored envelope was sealed to a recipient that must not resolve; operator action may be required"
                );
                continue;
            }
            SealPlan::SkipNoRecipients => {
                tracing::warn!(oid = %oid, "no resolvable recipient keys; skipping encrypted pin");
                continue;
            }
            SealPlan::SkipUnresolvable(unresolved) => {
                skipped_unresolvable += 1;
                // DIDs are user-controlled (rule reader_dids); log a bounded
                // sample, not an unbounded dump. Wording stays neutral about the
                // cause: a malformed did:key is not DHT-pending and never will
                // resolve, unlike a did:gitlawb awaiting anchoring.
                let sample: Vec<&String> = unresolved.iter().take(3).collect();
                tracing::warn!(
                    oid = %oid,
                    unresolved_count = unresolved.len(),
                    unresolved_sample = ?sample,
                    "unresolvable recipient DID(s); skipping encrypted pin to avoid sealing to a partial set"
                );
                continue;
            }
            SealPlan::Seal { keys, tag } => (keys, tag),
        };
        let data = match crate::git::store::read_object(repo_path, oid) {
            Ok(Some((_t, bytes))) => bytes,
            Ok(None) => {
                tracing::warn!(oid = %oid, "git object not found; skipping encrypted pin");
                continue;
            }
            Err(e) => {
                tracing::warn!(oid = %oid, err = %e, "read_object failed; skipping encrypted pin");
                continue;
            }
        };
        let envelope = match seal_blob(&data, &keys) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(oid = %oid, err = %e, "seal_blob failed; skipping");
                continue;
            }
        };
        let cid = match crate::ipfs_pin::pin_git_object(ipfs_api, oid, &envelope, None).await {
            Ok(c) if !c.is_empty() => c,
            Ok(_) => {
                tracing::warn!(oid = %oid, "pin_git_object returned no cid; skipping");
                continue;
            }
            Err(e) => {
                tracing::warn!(oid = %oid, err = %e, "pin_git_object failed; skipping");
                continue;
            }
        };
        if let Err(e) = db.record_encrypted_blob(repo_id, oid, &cid, &tag).await {
            tracing::warn!(oid = %oid, err = %e, "record_encrypted_blob failed");
            continue;
        }
        sealed.push((oid.clone(), cid.clone()));
    }
    // One aggregate signal so a coverage collapse is a single greppable line, not
    // a per-oid scrape. In a fully-migrated did:gitlawb org every blob skips and
    // recovery coverage silently drops to zero; this is the operator's cue that
    // the gap is the deliberate fail-closed posture, not a malfunction.
    if skipped_unresolvable > 0 {
        tracing::warn!(
            sealed = sealed.len(),
            skipped = skipped_unresolvable,
            "encrypted-pin coverage reduced: blobs skipped for unresolvable recipients"
        );
    }
    sealed
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// A did:key encoding a small-order point. Well-formed, indistinguishable
    /// from a real one by eye, and refused at resolution since the choke-point
    /// guard landed.
    fn weak_did_key() -> String {
        let mut weak = [0u8; 32];
        weak[0] = 1; // compressed identity point
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&weak).expect("decompresses");
        Did::from_verifying_key(&vk).to_string()
    }

    /// The #47 fail-closed arm already refuses to seal to a partial recipient
    /// set. Because a small-order did:key no longer RESOLVES, it lands in the
    /// unresolved set and that existing arm catches it: nothing is sealed, and
    /// no new code path was added to make that happen.
    #[test]
    fn weak_recipient_falls_into_the_existing_fail_closed_arm() {
        let weak = weak_did_key();
        let mut dids = BTreeSet::new();
        dids.insert(did_key(9));
        dids.insert(weak.clone());

        match plan_seal(&[0u8; 32], &dids, None) {
            SealPlan::SkipUnresolvable(unresolved) => assert!(
                unresolved.contains(&weak),
                "the weak DID must be named in the unresolved set, got {unresolved:?}"
            ),
            other => panic!("expected SkipUnresolvable, got {other:?}"),
        }
    }

    /// Must-not-over-reject control: an all-legitimate recipient set still seals.
    #[test]
    fn legitimate_recipient_set_still_seals() {
        let mut dids = BTreeSet::new();
        dids.insert(did_key(9));
        dids.insert(did_key(11));

        match plan_seal(&[0u8; 32], &dids, None) {
            SealPlan::Seal { keys, .. } => assert_eq!(keys.len(), 2, "both recipients resolve"),
            other => panic!("expected Seal, got {other:?}"),
        }
    }

    fn did_key(seed: u8) -> String {
        let vk = SigningKey::from_bytes(&[seed; 32]).verifying_key();
        Did::from_verifying_key(&vk).to_string()
    }

    // Accepts both `&[String]` (resolve tests, built from `did_key`) and
    // `&[&str]` (tag tests, built from literals).
    fn set<S: AsRef<str>>(dids: &[S]) -> BTreeSet<String> {
        dids.iter().map(|s| s.as_ref().to_string()).collect()
    }

    #[test]
    fn all_did_key_recipients_resolve() {
        let dids = set(&[did_key(1), did_key(2)]);
        let keys = resolve_all_recipients(&dids).expect("all did:key resolve");
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn mixed_set_with_did_gitlawb_fails_closed() {
        // Core #47 regression: a resolvable subset must never yield a sealable
        // key set. Two did:key plus one did:gitlawb -> Err naming only the
        // unresolvable DID.
        let gitlawb = Did::gitlawb("zSomeDhtKey").to_string();
        let dids = set(&[did_key(1), did_key(2), gitlawb.clone()]);
        let unresolved = resolve_all_recipients(&dids).expect_err("must fail closed");
        assert_eq!(unresolved, vec![gitlawb]);
    }

    #[test]
    fn did_web_recipient_fails_closed() {
        let web = Did::web("example.com").to_string();
        let dids = set(&[did_key(1), web.clone()]);
        let unresolved = resolve_all_recipients(&dids).expect_err("did:web cannot resolve locally");
        assert_eq!(unresolved, vec![web]);
    }

    #[test]
    fn malformed_did_key_fails_closed() {
        // The third state: not a method-resolution gap but a permanently broken
        // did:key (invalid multibase). Must also fail closed.
        let broken = "did:key:z!!!invalid".to_string();
        let dids = set(&[did_key(1), broken.clone()]);
        let unresolved = resolve_all_recipients(&dids).expect_err("malformed did:key fails");
        assert_eq!(unresolved, vec![broken]);
    }

    #[test]
    fn empty_set_resolves_to_empty_keys() {
        let dids = BTreeSet::new();
        let keys = resolve_all_recipients(&dids).expect("empty set is not an error");
        assert!(keys.is_empty());
    }

    #[test]
    fn single_unresolvable_did_returns_that_did() {
        let gitlawb = Did::gitlawb("zOnlyOne").to_string();
        let dids: BTreeSet<String> = [gitlawb.clone()].into_iter().collect();
        let unresolved = resolve_all_recipients(&dids).expect_err("must fail closed");
        assert_eq!(unresolved, vec![gitlawb]);
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

    // plan_seal is the seal/skip decision `encrypt_and_pin` acts on. Testing it
    // directly pins the #47 fail-closed invariant at the function that owns it,
    // which a unit test of `resolve_all_recipients` alone cannot do (it can't
    // catch the caller falling through to a partial seal).
    const SEED: [u8; 32] = [9u8; 32];

    #[test]
    fn plan_seal_seals_when_all_recipients_resolve() {
        let dids = set(&[did_key(1), did_key(2)]);
        match plan_seal(&SEED, &dids, None) {
            SealPlan::Seal { keys, tag } => {
                assert_eq!(keys.len(), 2, "must seal to the full recipient set");
                assert_eq!(
                    tag,
                    recipients_tag(&SEED, &dids),
                    "records the full-set tag"
                );
            }
            other => panic!("expected Seal, got {other:?}"),
        }
    }

    #[test]
    fn plan_seal_fails_closed_on_any_unresolvable_recipient() {
        // The #47 invariant at the decision boundary: one unresolvable DID among
        // resolvable ones must NOT yield a Seal (which would seal a partial set).
        let gitlawb = Did::gitlawb("zPending").to_string();
        let dids = set(&[did_key(1), did_key(2), gitlawb.clone()]);
        match plan_seal(&SEED, &dids, None) {
            SealPlan::SkipUnresolvable(unresolved) => assert_eq!(unresolved, vec![gitlawb]),
            other => panic!("must fail closed, never seal a partial set; got {other:?}"),
        }
    }

    #[test]
    fn plan_seal_skips_empty_recipient_set() {
        let dids = BTreeSet::new();
        assert!(matches!(
            plan_seal(&SEED, &dids, None),
            SealPlan::SkipNoRecipients
        ));
    }

    #[test]
    fn plan_seal_skips_when_tag_unchanged() {
        let dids = set(&[did_key(1)]);
        let stored = recipients_tag(&SEED, &dids);
        assert!(matches!(
            plan_seal(&SEED, &dids, Some(&stored)),
            SealPlan::SkipUnchanged
        ));
    }

    /// P1 remediation (review): an unchanged reader set is normally a skip, but
    /// the skip must not hide a recipient that now fails to resolve. A blob
    /// sealed to a small-order did:key before the choke-point guard landed keeps
    /// its old CID and stays decryptable-without-a-private-key unless the
    /// matching-tag path surfaces it. This pins that the stored-tag match still
    /// resolves the set instead of short-circuiting.
    #[test]
    fn plan_seal_surfaces_unresolvable_recipient_in_unchanged_reader_set() {
        let weak = weak_did_key();
        let mut dids = BTreeSet::new();
        dids.insert(did_key(9));
        dids.insert(weak.clone());
        let stored = recipients_tag(&SEED, &dids);

        match plan_seal(&SEED, &dids, Some(&stored)) {
            SealPlan::SkipUnresolvableStored(unresolved) => assert!(
                unresolved.contains(&weak),
                "the weak DID must be named in the unresolved set, got {unresolved:?}"
            ),
            other => panic!("expected SkipUnresolvableStored, got {other:?}"),
        }
    }

    /// Degenerate control: an empty set with a matching stored tag stays a
    /// silent skip. The state is unreachable in practice (a seal is never
    /// recorded for an empty reader set), so this pins only that the
    /// resolve-on-match path must not turn it into a re-seal or a warning.
    #[test]
    fn plan_seal_unchanged_empty_set_still_skips() {
        let empty = BTreeSet::new();
        let empty_tag = recipients_tag(&SEED, &empty);
        assert!(matches!(
            plan_seal(&SEED, &empty, Some(&empty_tag)),
            SealPlan::SkipUnchanged
        ));
    }

    #[test]
    fn plan_seal_reseals_when_recipient_set_changed() {
        // A stored tag for a DIFFERENT set is a miss: a newly added reader must
        // trigger a re-seal, not be skipped as unchanged.
        let dids = set(&[did_key(1), did_key(2)]);
        let stale = recipients_tag(&SEED, &set(&[did_key(1)]));
        match plan_seal(&SEED, &dids, Some(&stale)) {
            SealPlan::Seal { keys, .. } => assert_eq!(keys.len(), 2),
            other => panic!("changed recipient set must re-seal; got {other:?}"),
        }
    }
}
