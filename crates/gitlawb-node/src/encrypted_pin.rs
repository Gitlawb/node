//! Encrypt-then-pin for withheld blobs (Option B1). Each withheld blob is sealed
//! to its recipient DIDs and the envelope pinned to IPFS, recorded in
//! `encrypted_blobs`. Best-effort per blob: a failure is logged and skipped,
//! never pinned in plaintext.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

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
fn plan_seal(node_seed: &[u8; 32], dids: &BTreeSet<String>, stored_tag: Option<&str>) -> SealPlan {
    let tag = recipients_tag(node_seed, dids);
    if stored_tag == Some(tag.as_str()) {
        return SealPlan::SkipUnchanged;
    }
    match resolve_all_recipients(dids) {
        Ok(keys) if keys.is_empty() => SealPlan::SkipNoRecipients,
        Ok(keys) => SealPlan::Seal { keys, tag },
        Err(unresolved) => SealPlan::SkipUnresolvable(unresolved),
    }
}

/// Encrypt and pin every withheld blob. `recipients` maps blob oid -> DID set;
/// `node_seed` keys the opaque recipients tag. Returns `(oid, cid)` for each blob
/// actually sealed and recorded this call (the per-push delta), used by Option B3
/// to anchor a manifest. Recipient identities are never stored or returned.
///
/// Nine args (the fence joins the seal's eight) but grouping them would churn
/// both callers and the race/hung-git tests for no behavioral gain.
#[allow(clippy::too_many_arguments)]
pub async fn encrypt_and_pin(
    ipfs_api: &str,
    repo_path: &Path,
    db: &Db,
    repo_id: &str,
    node_seed: &[u8; 32],
    git_bin: &str,
    batch_budget: Duration,
    recipients: &HashMap<String, BTreeSet<String>>,
    fence: Option<&crate::ipfs_pin::PolicyFence>,
) -> Vec<(String, String)> {
    let mut sealed = Vec::new();
    let mut skipped_unresolvable = 0usize;
    // One shared read deadline for the whole batch, like `pin_new_objects`: a
    // hung git child is watchdog-reaped at this bound, so the outer
    // `PIN_PHASE_DEADLINE` timeout cannot be held open by a blocking read
    // (R1-P2). Each read runs under `spawn_blocking` — it is synchronous child
    // spawn + pipe drain + watchdog join.
    let read_deadline = std::time::Instant::now() + batch_budget;
    let total = recipients.len();
    for (attempted, (oid, dids)) in recipients.iter().enumerate() {
        // Batch budget gate (R2-P3), mirroring the public pin loops: an object
        // is never started with a remainder too small to cover a bounded read's
        // teardown. This is consistency (the seal is bounded by the outer
        // `PIN_PHASE_DEADLINE` either way), but it keeps the three loops from
        // drifting apart in how they report a truncated batch.
        if crate::ipfs_pin::batch_budget_gate(
            "encrypted-seal",
            read_deadline,
            sealed.len(),
            total - attempted,
        )
        .is_none()
        {
            break;
        }
        // Policy fence (R1-P1): the recipients snapshot was derived before the
        // long withheld-blob walk; if a visibility rule moved while that walk
        // ran (a reader added or removed), stop sealing instead of pinning to a
        // stale recipient set. Checked FIRST so a changed policy costs nothing.
        if let Some(f) = fence {
            if !f.is_current().await {
                tracing::warn!(
                    repo = %f.repo_id(),
                    oid = %oid,
                    "visibility policy changed after the recipients snapshot; stopping the seal loop"
                );
                break;
            }
        }
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
        let data = match read_object_bounded_spawn_blocking(git_bin, repo_path, oid, read_deadline)
            .await
        {
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
        // Dispatch fence (R1-P1): re-read the policy epoch immediately before
        // the irreversible HTTP POST. The iteration-top check catches a narrow
        // that landed before work began; THIS check catches a narrow that landed
        // during the tag lookup, recipient resolution, git read, or seal — all
        // of which can take seconds. Without this, a reader removed during
        // preparation can still receive a newly published envelope.
        if let Some(f) = fence {
            if !f.is_current().await {
                tracing::warn!(
                    repo = %f.repo_id(),
                    oid = %oid,
                    "visibility policy changed during encrypted seal preparation; aborting upload"
                );
                break;
            }
        }
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

/// Bounded, reaped git object read for the seal loop, run off the async thread:
/// `read_object_bounded` is synchronous child spawn + pipe drain + watchdog
/// join, so blocking the runtime task on it would let a hung git hold a worker
/// thread (R1-P2). The `deadline` is the batch's shared read deadline; a child
/// still alive at it is SIGTERM/SIGKILL group-reaped by the watchdog.
async fn read_object_bounded_spawn_blocking(
    git_bin: &str,
    repo_path: &Path,
    sha256_hex: &str,
    deadline: std::time::Instant,
) -> anyhow::Result<Option<(String, Vec<u8>)>> {
    let git_bin = git_bin.to_string();
    let repo_path = repo_path.to_path_buf();
    let sha256_hex = sha256_hex.to_string();
    tokio::task::spawn_blocking(move || {
        crate::git::store::read_object_bounded(&git_bin, &repo_path, &sha256_hex, deadline)
            .map_err(anyhow::Error::from)
    })
    .await
    .map_err(|e| anyhow::anyhow!("read_object spawn_blocking join failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::time::Duration;

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

    /// A reader removed mid-seal must stop the seal loop (R1-P1 "race test for
    /// reader removal"): `encrypt_and_pin` re-checks the policy fence before
    /// each blob, so a `remove_visibility_rule` landing while the first seal is
    /// in flight aborts before a later blob is pinned to a stale recipient set.
    #[sqlx::test]
    async fn encrypt_and_pin_stops_sealing_when_reader_removed_mid_batch(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("seal-race.git");

        // Three loose blobs, each withheld (path-scoped deny exists so the sweep
        // would have derived recipients for them).
        let oids: Vec<String> = {
            crate::git::store::init_bare(&repo_path).expect("init bare repo");
            (0..3)
                .map(|i| {
                    let mut cmd = std::process::Command::new("git");
                    cmd.args(["hash-object", "-w", "--stdin"])
                        .current_dir(&repo_path)
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped());
                    let mut child = cmd.spawn().expect("spawn git hash-object");
                    {
                        use std::io::Write;
                        child
                            .stdin
                            .as_mut()
                            .expect("stdin")
                            .write_all(format!("secret blob {i}\n").as_bytes())
                            .expect("write stdin");
                    }
                    let out = child.wait_with_output().expect("hash-object output");
                    assert!(out.status.success());
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                })
                .collect()
        };

        // A real repos row so the fence has an epoch and a reader can be removed.
        let now = chrono::Utc::now();
        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&crate::db::RepoRecord {
            id: repo_id.clone(),
            name: "seal-race-repo".into(),
            owner_did: "did:key:zSealRaceOwner".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: repo_path.display().to_string(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .expect("create repo");
        // A rule whose removal is the "reader removed" mutation: one reader per
        // blob, all under the same path glob.
        let reader = did_key(1);
        db.set_visibility_rule(
            &repo_id,
            "**/secret/*",
            crate::db::VisibilityMode::B,
            std::slice::from_ref(&reader),
            "did:key:zSealRaceOwner",
        )
        .await
        .expect("set rule");

        // IPFS endpoint that delays the FIRST add 2s so the removal lands while
        // that seal is in flight, then answers immediately.
        let endpoint = delaying_cid_endpoint(vec![Duration::from_secs(2)]).await;

        let recipients: HashMap<String, BTreeSet<String>> = oids
            .iter()
            .cloned()
            .map(|oid| {
                let mut s = BTreeSet::new();
                s.insert(reader.clone());
                (oid, s)
            })
            .collect();

        let fence = crate::ipfs_pin::PolicyFence::capture(&db, &repo_id)
            .await
            .expect("fence captures");

        let sealed = tokio::time::timeout(Duration::from_secs(30), async {
            let seal_db = db.clone();
            let seal_repo = repo_path.clone();
            let seal_endpoint = endpoint.clone();
            let seal_repo_id = repo_id.clone();
            let handle = tokio::spawn(async move {
                encrypt_and_pin(
                    &seal_endpoint,
                    &seal_repo,
                    &seal_db,
                    &seal_repo_id,
                    &SEED,
                    "git",
                    Duration::from_secs(60),
                    &recipients,
                    Some(&fence),
                )
                .await
            });
            // Let the first add start (endpoint sleeps 2s), then remove the
            // reader so the fence is stale before the loop checks again.
            tokio::time::sleep(Duration::from_millis(300)).await;
            db.remove_visibility_rule(&repo_id, "**/secret/*")
                .await
                .expect("remove rule");
            handle.await.expect("seal task")
        })
        .await
        .expect("wedge guard: the fence abort must not take 30s");

        assert!(
            sealed.len() < oids.len(),
            "a reader removal landing mid-batch must abort before every blob is sealed: {}",
            sealed.len()
        );
        assert!(
            !sealed.is_empty(),
            "at least the blob already in flight before the removal completes"
        );
    }

    /// A hung git must not hold the seal loop past its read budget (R1-P2): the
    /// git read runs under `spawn_blocking` against `read_object_bounded`, so
    /// the watchdog reaps a wedged child at the batch deadline and the loop
    /// keeps its shape instead of blocking a runtime worker indefinitely.
    #[cfg(unix)]
    #[sqlx::test]
    async fn encrypt_and_pin_returns_by_budget_with_a_hung_git(pool: sqlx::PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("seal-hung.git");
        let oids: Vec<String> = {
            crate::git::store::init_bare(&repo_path).expect("init bare repo");
            (0..2)
                .map(|i| {
                    let mut cmd = std::process::Command::new("git");
                    cmd.args(["hash-object", "-w", "--stdin"])
                        .current_dir(&repo_path)
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped());
                    let mut child = cmd.spawn().expect("spawn git hash-object");
                    {
                        use std::io::Write;
                        child
                            .stdin
                            .as_mut()
                            .expect("stdin")
                            .write_all(format!("secret blob {i}\n").as_bytes())
                            .expect("write stdin");
                    }
                    let out = child.wait_with_output().expect("hash-object output");
                    assert!(out.status.success());
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                })
                .collect()
        };

        // A git that wedges forever, ignoring SIGTERM, so only the watchdog's
        // SIGKILL can reap it.
        let fake = tmp.path().join("hanging-git");
        std::fs::write(&fake, "#!/bin/sh\ntrap '' TERM\necho $$ > pid\nsleep 30\n").unwrap();
        let mut perm = std::fs::metadata(&fake).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&fake, perm).unwrap();

        let now = chrono::Utc::now();
        let repo_id = uuid::Uuid::new_v4().to_string();
        db.create_repo(&crate::db::RepoRecord {
            id: repo_id.clone(),
            name: "seal-hung-repo".into(),
            owner_did: "did:key:zSealHungOwner".into(),
            description: None,
            is_public: true,
            default_branch: "main".into(),
            created_at: now,
            updated_at: now,
            disk_path: repo_path.display().to_string(),
            forked_from: None,
            machine_id: None,
        })
        .await
        .expect("create repo");
        db.set_visibility_rule(
            &repo_id,
            "**/secret/*",
            crate::db::VisibilityMode::B,
            &[did_key(1)],
            "did:key:zSealHungOwner",
        )
        .await
        .expect("set rule");

        let recipients: HashMap<String, BTreeSet<String>> = oids
            .iter()
            .cloned()
            .map(|oid| {
                let mut s = BTreeSet::new();
                s.insert(did_key(1));
                (oid, s)
            })
            .collect();

        // Unreachable endpoint: even if a read somehow succeeded, the pin would
        // fail; the read itself is the thing under test.
        let started = std::time::Instant::now();
        let sealed = tokio::time::timeout(
            Duration::from_secs(60),
            encrypt_and_pin(
                "http://127.0.0.1:9",
                &repo_path,
                &db,
                &repo_id,
                &SEED,
                fake.to_str().unwrap(),
                Duration::from_secs(2),
                &recipients,
                None,
            ),
        )
        .await
        .expect("a hung git must not hold the seal past the outer wedge guard");

        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(10),
            "a hung git must be watchdog-reaped inside the read budget, not block the loop for ~10s+ (took {elapsed:?})"
        );
        assert!(
            sealed.is_empty(),
            "with a hung git no blob can be read, so nothing may be reported sealed"
        );
    }

    /// Local TCP endpoint that answers `{ "Hash": "QmMock" }` after an optional
    /// per-request delay, so a seal can be made to straddle a policy mutation.
    async fn delaying_cid_endpoint(delays: Vec<Duration>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut seen = 0usize;
            while let Ok((mut sock, _)) = listener.accept().await {
                let delay = *delays
                    .get(seen)
                    .or_else(|| delays.last())
                    .unwrap_or(&Duration::ZERO);
                seen += 1;
                tokio::spawn(async move {
                    let mut acc = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        acc.extend_from_slice(&buf[..n]);
                        if let Some(hdr_end) =
                            acc.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
                        {
                            let headers = String::from_utf8_lossy(&acc[..hdr_end]).to_lowercase();
                            let len: usize = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse().ok())
                                .unwrap_or(0);
                            if acc.len() >= hdr_end + len {
                                break;
                            }
                        }
                    }
                    tokio::time::sleep(delay).await;
                    let body = br#"{"Hash":"QmSealRaceMockCid"}"#;
                    let _ = sock
                        .write_all(
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                                .as_bytes(),
                        )
                        .await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.flush().await;
                });
            }
        });
        endpoint
    }
}
