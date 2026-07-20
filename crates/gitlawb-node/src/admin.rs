//! Admin subcommands invoked out-of-band, not part of the running node.
//!
//! `purge-spam` produces a reviewable dry-run list of empty spam-burst repos and,
//! only behind an explicit `--execute` flag, deletes them one at a time. The
//! selection logic is the load-bearing security part: a repo qualifies ONLY if it
//! is owned by the named burst DID AND is verified empty (zero git refs) PER REPO,
//! and a hard exclusion gate (evaluated BEFORE the empty check) keeps
//! content-bearing and intern/mirror-bot DIDs out no matter what.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::db::{Db, RepoRecord};
use crate::git::store;

/// The did:key of the spam burst this tool targets. The purge is scoped to
/// exactly this owner; an empty repo owned by anyone else is never a candidate.
pub const SPAM_BURST_TARGET_DID: &str = "did:key:z6Mkopj6mhcMayipekXbTRFMZPM6Bsgy4FQZuN9fannXSLTC";

/// DIDs that must never be touched, even when they own an empty repo whose
/// signature otherwise matches the burst. The gate is evaluated BEFORE the empty
/// check so it wins unconditionally:
///   - `z6Mkk4L…` is a content-bearing live user.
///   - `z6MkqRz…` is the intern / mirror-bot DID.
pub const EXCLUDED_DIDS: &[&str] = &[
    "did:key:z6Mkk4LDvfA8VQmdehbJDvxp133sdtXUhR2UkUnMPguX7gnP",
    "did:key:z6MkqRzACJ5iCDdkiymAPK3gq18z2iecZHeAuUyW6JnwRfoM",
];

/// Outcome tally of a `run_purge_spam` execute pass. Returned so the DB-delete
/// count is never conflated with full success: `disk_failed` records repos whose
/// row was deleted but whose on-disk dir could not be removed (or escaped the
/// repos_dir containment check), so an operator sees the DB/disk drift instead of
/// a clean "N deleted" summary.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PurgeSummary {
    /// Repo rows actually deleted from the DB.
    pub deleted: u64,
    /// Candidates skipped because they were no longer empty (pre-filter or the
    /// authoritative recheck under the lock).
    pub skipped_not_empty: usize,
    /// Candidates skipped because a live writer held the per-repo lock.
    pub skipped_locked: usize,
    /// Candidates skipped because the object store could not be consulted for the
    /// authoritative emptiness recheck (fail-closed: never delete on a store
    /// error rather than risk deleting a repo with live remote refs).
    pub skipped_store_error: usize,
    /// Rows deleted whose on-disk dir removal FAILED (or was refused by the
    /// containment guard) — DB/disk drift the operator must reconcile.
    pub disk_failed: usize,
    /// Rows+dirs deleted whose object-store archive removal FAILED — the archive
    /// survives and could be re-downloaded into a later same-owner/name repo, so
    /// this is tracked separately and never folded into a clean success.
    pub archive_failed: usize,
    /// Candidates with no local copy, admitted only because an object store is
    /// configured (emptiness decided under the lock at execute time). Reported so
    /// the dry-run can surface them distinctly from locally-verified candidates.
    pub remote_unverified: usize,
}

/// A repo selected for purge, with the evidence that qualified it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub owner_did: String,
    pub name: String,
    /// Number of git refs found on disk. 0 for a locally-verified empty candidate;
    /// also 0 for a remote-unverified one whose emptiness is decided under the lock.
    pub ref_count: usize,
    /// True when the repo has no local copy and was admitted only because an object
    /// store is configured. Its emptiness has NOT been verified — the execute path
    /// must refresh from the archive and recheck UNDER the per-repo lock before any
    /// delete; the dry-run lists it distinctly and never touches it.
    pub remote_unverified: bool,
}

/// Whether a DID is on the hard exclusion list. Compared under did:key
/// normalization (the same convention the repos table and every ownership check
/// use), so an excluded identity stored in either `did:key:z6…` or bare `z6…`
/// form is protected regardless of the form the exclusion constant is written in.
fn is_excluded(owner_did: &str) -> bool {
    let owner_key = crate::db::normalize_owner_key(owner_did);
    EXCLUDED_DIDS
        .iter()
        .any(|d| crate::db::normalize_owner_key(d) == owner_key)
}

/// Pure candidate selector — the security core, isolated from disk and DB so the
/// exclusion + empty logic is directly testable.
///
/// `repos` is the raw row set to consider (the caller supplies the target DID's
/// rows). `local_refs_of` returns `Some(n)` when a local bare repo exists (n
/// refs) and `None` when there is no local copy; the CLI wires the real on-disk
/// source, tests inject precomputed states. `store_configured` gates whether a
/// missing-local repo may be admitted.
///
/// A repo qualifies ONLY if, PER REPO:
///   1. its owner is NOT on the exclusion list (gate evaluated FIRST), AND
///   2. its owner is exactly the target burst DID, AND
///   3. EITHER it is locally verified empty (`Some(0)`), OR it has no local copy
///      (`None`) AND an object store is configured — in which case it is admitted
///      as remote-unverified and its emptiness is decided under the lock later.
///
/// The exclusion gate is checked before everything so an empty repo owned by an
/// excluded DID is dropped regardless of its ref signature. A missing-local repo
/// with no object store fails closed (skipped).
pub fn select_spam_candidates<F>(
    repos: &[RepoRecord],
    target_did: &str,
    store_configured: bool,
    mut local_refs_of: F,
) -> Vec<Candidate>
where
    F: FnMut(&RepoRecord) -> Option<usize>,
{
    let mut out = Vec::new();
    for repo in repos {
        // Hard exclusion gate FIRST — wins over the empty signature.
        if is_excluded(&repo.owner_did) {
            continue;
        }
        // Scope to the named burst only, under did:key normalization so a burst
        // row stored in either did:key or bare form is matched consistently.
        if crate::db::normalize_owner_key(&repo.owner_did)
            != crate::db::normalize_owner_key(target_did)
        {
            continue;
        }
        // `local_refs_of` is `Some(n)` when a local bare repo exists and `None`
        // when it does not. A local empty repo (Some(0)) is a verified candidate;
        // a local non-empty repo is skipped; a missing local copy is a candidate
        // ONLY when an object store is configured (its emptiness is then decided
        // authoritatively under the lock after refresh), else it fails closed.
        let remote_unverified = match local_refs_of(repo) {
            Some(0) => false,
            Some(_) => continue,
            None => {
                if store_configured {
                    true
                } else {
                    continue;
                }
            }
        };
        out.push(Candidate {
            id: repo.id.clone(),
            owner_did: repo.owner_did.clone(),
            name: repo.name.clone(),
            ref_count: 0,
            remote_unverified,
        });
    }
    out
}

/// Count the git refs of a repo on disk. Zero refs means the repo is empty.
///
/// Resolves the repo's bare path from `repos_dir` + owner/name (the same layout
/// `git::store::repo_disk_path` writes) and shells to `git for-each-ref` via
/// `store::list_refs`. A repo whose on-disk path is missing or unreadable is
/// treated as having an unknown, non-empty ref count so it is NOT selected — the
/// tool fails closed and never deletes on a read error.
///
/// Critically, a `0` count must come from THIS exact bare repo and never from
/// git's upward repository discovery. `git for-each-ref` runs with the repo path
/// as its cwd and no explicit `--git-dir`, so if the path exists but is not
/// itself a git dir, git walks parent directories for a `.git` — and `repos_dir`
/// may live inside the operator's own git checkout. That would read a DIFFERENT
/// repo's refs (possibly `0`) and delete a real repo. We defend by requiring the
/// bare-repo markers (`HEAD` file + `objects/` dir) before trusting any count;
/// anything else fails closed (treated non-empty, skipped).
/// Local ref state for selection: `Some(n)` when a local bare repo exists (n
/// refs), `None` ONLY when the path is verifiably absent (a `NotFound` from
/// `symlink_metadata`). `None` is what lets selection distinguish a truly
/// missing-local repo (a remote-unverified candidate when a store is configured)
/// from a one-ref repo — both of which `ref_count_on_disk` collapses to a
/// non-zero count. Everything else fails closed to `Some(1)` so it is skipped and
/// never admitted as remote-unverified: an unsafe name, an unreadable/unstat-able
/// path, a dangling symlink, or an existing directory that is not a bare git repo
/// (returning `None` for the latter would promote it, and the remote_unverified
/// refresh's `remove_dir_all` would overwrite that non-repository directory).
fn local_refs_on_disk(repos_dir: &Path, owner_did: &str, name: &str) -> Option<usize> {
    // Fail closed on an unsafe repo name BEFORE building any on-disk path (a
    // peer-mirror row can carry a `../` name). Report it as non-empty so it is
    // never a candidate — never as missing (which could admit it remote-unverified).
    if let Err(e) = crate::git::repo_store::validate_repo_name(name) {
        warn!(name = %name, err = %e,
            "purge-spam: unsafe repo name — treating as non-empty (skipped)");
        return Some(1);
    }
    let path = store::repo_disk_path(repos_dir, owner_did, name);
    // Only a VERIFIED NotFound (the path truly does not exist) may return None,
    // which promotes the repo to remote_unverified — and that refresh path does a
    // remove_dir_all on the target. Use `symlink_metadata` (not `metadata`) so a
    // dangling symlink counts as PRESENT, not NotFound. Any existing path, or any
    // stat error other than NotFound, fails closed to Some(1) so the refresh never
    // overwrites a non-repository directory sitting at the target.
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(path = %path.display(), err = %e,
                "purge-spam: could not stat path — treating as non-empty (skipped)");
            return Some(1);
        }
        Ok(_) => {}
    }
    if !path.join("HEAD").is_file() || !path.join("objects").is_dir() {
        // The path exists but is not a bare repo — fail closed as present so it is
        // never promoted to remote_unverified and overwritten by a refresh.
        warn!(path = %path.display(),
            "purge-spam: path exists but is not a bare git repo — treating as non-empty (skipped)");
        return Some(1);
    }
    match store::list_refs(&path) {
        Ok(refs) => Some(refs.len()),
        Err(e) => {
            warn!(path = %path.display(), err = %e,
                "purge-spam: could not read refs — treating as non-empty (skipped)");
            Some(1)
        }
    }
}

/// Ref count keyed on owner+name (returns 1 for a missing/unsafe/unreadable
/// repo — fail closed), used by the execute path to re-verify emptiness right
/// before deleting (using only a [`Candidate`]) and, after `refresh_from_archive`
/// downloads a remote-unverified candidate, to decide its emptiness under the lock.
fn ref_count_on_disk(repos_dir: &Path, owner_did: &str, name: &str) -> usize {
    // Fail closed on an unsafe repo name BEFORE building any on-disk path. A
    // peer-mirror row (which skips API name validation) can carry a `../` name;
    // `repo_disk_path` would join it verbatim and resolve OUTSIDE `repos_dir`,
    // pointing this "empty" check — and later the delete — at an unrelated repo.
    // Reject it here so such a row is never a candidate (treated non-empty).
    if let Err(e) = crate::git::repo_store::validate_repo_name(name) {
        warn!(name = %name, err = %e,
            "purge-spam: unsafe repo name — treating as non-empty (skipped)");
        return 1;
    }
    let path = store::repo_disk_path(repos_dir, owner_did, name);
    if !path.join("HEAD").is_file() || !path.join("objects").is_dir() {
        // Not a bare git repo at the exact expected path. Do NOT trust a ref
        // count that git discovery could have read from a parent repository.
        warn!(path = %path.display(),
            "purge-spam: path is not a bare git repo — treating as non-empty (skipped)");
        return 1;
    }
    match store::list_refs(&path) {
        Ok(refs) => refs.len(),
        Err(e) => {
            // Fail closed: an unreadable repo is not provably empty, so keep it
            // out of the candidate set (report it as one ref so it's excluded).
            warn!(path = %path.display(), err = %e,
                "purge-spam: could not read refs — treating as non-empty (skipped)");
            1
        }
    }
}

/// Whether `path` resolves canonically inside `root`. Both are canonicalized so
/// symlinks and `..` segments are fully resolved before the containment test; a
/// path that does not exist (or a root that cannot be canonicalized) fails closed
/// to `false`. Used as the last gate before a destructive `remove_dir_all`.
fn path_within(path: &Path, root: &Path) -> bool {
    match (std::fs::canonicalize(path), std::fs::canonicalize(root)) {
        (Ok(p), Ok(r)) => p.starts_with(&r),
        _ => false,
    }
}

/// Split selected candidates into (delete, skip) by a fresh emptiness re-check,
/// so a repo that gained a ref between selection and deletion (a TOCTOU push)
/// is never deleted. Pure over the `recheck` closure so the skip branch is
/// directly testable; the CLI wires the real on-disk re-check.
fn partition_for_delete<F>(
    candidates: &[Candidate],
    mut recheck: F,
) -> (Vec<&Candidate>, Vec<&Candidate>)
where
    F: FnMut(&Candidate) -> usize,
{
    let mut to_delete = Vec::new();
    let mut to_skip = Vec::new();
    for c in candidates {
        if recheck(c) == 0 {
            to_delete.push(c);
        } else {
            to_skip.push(c);
        }
    }
    (to_delete, to_skip)
}

/// Run the `purge-spam` admin subcommand.
///
/// Enumerates the target burst DID's repos, verifies each is empty on disk,
/// applies the exclusion gate, prints one dry-run row per candidate with owner +
/// ref-count evidence, and — only when `execute` is true — deletes the DB row of
/// each candidate one at a time. Dry-run (the default) deletes nothing.
pub async fn run_purge_spam(
    db: &Db,
    repo_store: &crate::git::repo_store::RepoStore,
    repos_dir: &Path,
    execute: bool,
) -> Result<PurgeSummary> {
    let repos_dir: PathBuf = repos_dir.to_path_buf();
    let rows = db
        .list_repos_by_owner_did(SPAM_BURST_TARGET_DID)
        .await
        .context("listing repos for the spam-burst target DID")?;

    // A repo with no local copy is admitted as a remote-unverified candidate
    // only when an object store is configured — its emptiness is then decided
    // under the lock after refresh_from_archive. Without a store, missing-local
    // fails closed (skipped), preserving the wrong-machine safety rule.
    let store_configured = repo_store.has_object_store();
    let candidates =
        select_spam_candidates(&rows, SPAM_BURST_TARGET_DID, store_configured, |repo| {
            local_refs_on_disk(&repos_dir, &repo.owner_did, &repo.name)
        });
    let remote_unverified_count = candidates.iter().filter(|c| c.remote_unverified).count();

    info!(
        target = SPAM_BURST_TARGET_DID,
        scanned = rows.len(),
        candidates = candidates.len(),
        execute,
        "purge-spam: candidate selection complete"
    );

    if candidates.is_empty() {
        println!("purge-spam: no empty spam-burst repos found for {SPAM_BURST_TARGET_DID}");
        return Ok(PurgeSummary::default());
    }

    println!(
        "purge-spam: {} candidate(s) for {} ({} mode)",
        candidates.len(),
        SPAM_BURST_TARGET_DID,
        if execute { "EXECUTE" } else { "dry-run" }
    );
    for c in &candidates {
        let marker = if c.remote_unverified {
            " [remote-only, emptiness verified under lock at execute]"
        } else {
            ""
        };
        println!(
            "  {} owner={} name={} refs={}{marker}",
            c.id, c.owner_did, c.name, c.ref_count
        );
    }

    if !execute {
        println!(
            "purge-spam: dry-run — nothing deleted ({remote_unverified_count} remote-only, verified under lock only on --execute). Re-run with --execute to delete the {} candidate(s).",
            candidates.len()
        );
        return Ok(PurgeSummary {
            remote_unverified: remote_unverified_count,
            ..PurgeSummary::default()
        });
    }

    // Re-verify emptiness immediately before deleting: a push may have landed
    // between selection and now (TOCTOU). A remote-unverified candidate has no
    // local copy yet, so `ref_count_on_disk` would report it non-empty and drop
    // it here — pass it straight through instead; the authoritative emptiness
    // check for it happens under the lock in the execute loop after refresh.
    let (to_delete, to_skip) = partition_for_delete(&candidates, |c| {
        if c.remote_unverified {
            0
        } else {
            ref_count_on_disk(&repos_dir, &c.owner_did, &c.name)
        }
    });
    for c in &to_skip {
        warn!(repo = %c.id, "purge-spam: repo no longer empty at delete time — skipped (TOCTOU)");
    }

    // Execute: delete per-repo, never a single blanket "delete all of owner X".
    // A per-repo failure warns and continues rather than aborting the batch.
    let mut summary = PurgeSummary {
        remote_unverified: remote_unverified_count,
        skipped_not_empty: to_skip.len(),
        ..PurgeSummary::default()
    };
    for c in &to_delete {
        // Hold the per-repo advisory lock across the FINAL emptiness recheck and
        // the delete, so a concurrent receive-pack cannot land a ref in the window
        // between recheck and delete (M4). A repo currently locked by a live writer
        // is skipped, never force-deleted out from under the push.
        let guard = match repo_store.try_lock_repo(&c.owner_did, &c.name).await {
            Ok(Some(g)) => g,
            Ok(None) => {
                warn!(repo = %c.id, "purge-spam: repo is locked by a live writer — skipped");
                summary.skipped_locked += 1;
                continue;
            }
            Err(e) => {
                warn!(repo = %c.id, err = %e, "purge-spam: could not acquire repo lock — skipped");
                summary.skipped_locked += 1;
                continue;
            }
        };
        // Refresh the local copy from the authoritative object store (if any)
        // before the recheck: on a Tigris deployment the admin node's local disk
        // can be stale, so an emptiness check against local alone could delete a
        // repo that has live remote refs. Fail closed on any store error — never
        // delete on an unverified view.
        if let Err(e) = repo_store.refresh_from_archive(&c.owner_did, &c.name).await {
            warn!(repo = %c.id, err = %e,
                "purge-spam: could not consult the object store — skipped (fail-closed)");
            summary.skipped_store_error += 1;
            guard.release().await;
            continue;
        }
        // Authoritative recheck UNDER the lock: a ref that landed before we locked
        // (or that the object-store refresh surfaced) makes the repo non-empty, so
        // it must not be deleted.
        if ref_count_on_disk(&repos_dir, &c.owner_did, &c.name) != 0 {
            warn!(repo = %c.id, "purge-spam: repo no longer empty under lock — skipped (TOCTOU)");
            summary.skipped_not_empty += 1;
            guard.release().await;
            continue;
        }
        match db.delete_repo_by_id(&c.id).await {
            Ok(0) => {
                warn!(repo = %c.id, "purge-spam: repo row already gone — nothing to delete");
            }
            Ok(n) => {
                summary.deleted += n;
                // Remove the now-orphaned on-disk bare repo (empty, so cheap) so
                // the DB row and disk stay consistent. Belt-and-suspenders: assert
                // the resolved path is canonically INSIDE repos_dir before any
                // remove_dir_all, so a symlinked slug dir or any residual traversal
                // can never delete outside the repo root (the name is already
                // validated at selection; this guards the destructive op itself).
                // A disk-removal failure is counted separately, NOT folded into the
                // deleted total, so the summary never reports a clean success while
                // an on-disk dir survives (DB/disk drift the operator must fix).
                let path = store::repo_disk_path(&repos_dir, &c.owner_did, &c.name);
                if !path_within(&path, &repos_dir) {
                    warn!(repo = %c.id, path = %path.display(),
                        "purge-spam: on-disk path escapes repos_dir — refusing to remove");
                    summary.disk_failed += 1;
                } else if let Err(e) = std::fs::remove_dir_all(&path) {
                    warn!(repo = %c.id, path = %path.display(), err = %e,
                        "purge-spam: deleted DB row but could not remove on-disk repo dir");
                    summary.disk_failed += 1;
                } else {
                    info!(repo = %c.id, rows = n, "purge-spam: deleted repo row + on-disk dir");
                }
                // Delete the object-store archive too (a no-op when no store is
                // configured), else it survives and can be downloaded into a
                // later repo created with the same owner/name. Counted separately
                // so a surviving archive never reads as a clean success.
                if let Err(e) = repo_store.delete_archive(&c.owner_did, &c.name).await {
                    warn!(repo = %c.id, err = %e,
                        "purge-spam: deleted row + dir but could not delete the object-store archive");
                    summary.archive_failed += 1;
                }
            }
            Err(e) => {
                warn!(repo = %c.id, err = %e, "purge-spam: failed to delete repo row — continuing");
            }
        }
        guard.release().await;
    }
    println!(
        "purge-spam: deleted {} repo row(s); skipped {} (no longer empty), {} (locked by a live writer), {} (object store unreachable); {} on-disk removal(s) failed, {} archive removal(s) failed.",
        summary.deleted,
        summary.skipped_not_empty,
        summary.skipped_locked,
        summary.skipped_store_error,
        summary.disk_failed,
        summary.archive_failed
    );
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    const TARGET: &str = SPAM_BURST_TARGET_DID;
    const EXCLUDED_CONTENT: &str = EXCLUDED_DIDS[0]; // z6Mkk4L… content-bearing live user
    const EXCLUDED_INTERN: &str = EXCLUDED_DIDS[1]; // z6MkqRz… intern/mirror-bot
    const UNRELATED: &str = "did:key:z6MkUnrelatedStrangerDidThatIsNotTheBurst";

    fn repo(id: &str, owner: &str, name: &str) -> RepoRecord {
        RepoRecord {
            id: id.to_string(),
            name: name.to_string(),
            owner_did: owner.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: format!("/srv/{id}.git"),
            forked_from: None,
            machine_id: None,
        }
    }

    /// Ref counts keyed by repo id; anything absent defaults to 0 (empty).
    fn refs_by_id<'a>(map: &'a [(&'a str, usize)]) -> impl Fn(&RepoRecord) -> Option<usize> + 'a {
        // A local bare repo exists for every test row (Some), with `n` refs.
        move |r: &RepoRecord| {
            Some(
                map.iter()
                    .find(|(id, _)| *id == r.id)
                    .map(|(_, n)| *n)
                    .unwrap_or(0),
            )
        }
    }

    // Test 1: an empty repo owned by the target DID is a candidate.
    #[test]
    fn empty_target_repo_is_a_candidate() {
        let repos = vec![repo("t-empty", TARGET, "spam1")];
        let got = select_spam_candidates(&repos, TARGET, false, refs_by_id(&[]));
        assert_eq!(got.len(), 1, "empty target repo must be selected");
        assert_eq!(got[0].id, "t-empty");
        assert_eq!(got[0].owner_did, TARGET);
        assert_eq!(
            got[0].ref_count, 0,
            "candidate must carry ref-count evidence"
        );
    }

    // Test 2: a target-owned repo WITH refs is absent (per-repo empty check, not
    // per-DID).
    #[test]
    fn target_repo_with_refs_is_absent() {
        let repos = vec![
            repo("t-empty", TARGET, "spam1"),
            repo("t-nonempty", TARGET, "real"),
        ];
        let got = select_spam_candidates(&repos, TARGET, false, refs_by_id(&[("t-nonempty", 3)]));
        let ids: Vec<&str> = got.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"t-empty"), "empty target repo still selected");
        assert!(
            !ids.contains(&"t-nonempty"),
            "a target repo WITH refs must NOT be selected (per-repo, not per-DID)"
        );
    }

    // Test 3 (MUST ASSERT): an EMPTY repo owned by the excluded content DID is
    // absent — the exclusion gate wins over the empty signature.
    //
    // Driven with the excluded DID passed AS the target so the exclusion gate is
    // the ONLY barrier: with the gate removed this repo would match owner==target
    // and be selected, so the test goes RED. This is what makes the gate
    // load-bearing rather than shadowed by the target-scope check.
    #[test]
    fn empty_excluded_content_repo_is_absent() {
        let repos = vec![repo("x-content", EXCLUDED_CONTENT, "anything")];
        let got = select_spam_candidates(&repos, EXCLUDED_CONTENT, false, refs_by_id(&[]));
        assert!(
            got.is_empty(),
            "an empty repo owned by the excluded content DID must be excluded even \
             if that DID were the target, got {got:?}"
        );
        // And of course it is also absent when the real burst DID is the target.
        let got = select_spam_candidates(&repos, TARGET, false, refs_by_id(&[]));
        assert!(got.is_empty());
    }

    // Test 4 (MUST ASSERT): an EMPTY repo owned by the intern DID is absent.
    // Same construction as test 3: the intern DID is passed as the target so the
    // exclusion gate is the sole reason it is dropped (RED without the gate).
    #[test]
    fn empty_intern_repo_is_absent() {
        let repos = vec![repo("x-intern", EXCLUDED_INTERN, "mirror")];
        let got = select_spam_candidates(&repos, EXCLUDED_INTERN, false, refs_by_id(&[]));
        assert!(
            got.is_empty(),
            "an empty repo owned by the intern/mirror-bot DID must be excluded even \
             if that DID were the target, got {got:?}"
        );
        let got = select_spam_candidates(&repos, TARGET, false, refs_by_id(&[]));
        assert!(got.is_empty());
    }

    // Test 5: an empty repo owned by an unrelated DID is absent — the tool targets
    // the named burst only.
    #[test]
    fn empty_unrelated_repo_is_absent() {
        let repos = vec![repo("u-empty", UNRELATED, "whatever")];
        let got = select_spam_candidates(&repos, TARGET, false, refs_by_id(&[]));
        assert!(
            got.is_empty(),
            "an empty repo owned by a non-target DID must not be selected, got {got:?}"
        );
    }

    // The full matrix in one selector pass: only the empty target repo survives.
    #[test]
    fn full_matrix_selects_only_empty_target() {
        let repos = vec![
            repo("t-empty", TARGET, "spam1"),         // selected
            repo("t-nonempty", TARGET, "real"),       // has refs → out
            repo("x-content", EXCLUDED_CONTENT, "a"), // excluded, empty → out
            repo("x-intern", EXCLUDED_INTERN, "b"),   // excluded, empty → out
            repo("u-empty", UNRELATED, "c"),          // wrong owner → out
        ];
        let got = select_spam_candidates(&repos, TARGET, false, refs_by_id(&[("t-nonempty", 2)]));
        assert_eq!(
            got.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["t-empty"],
            "only the empty target repo may survive the full matrix"
        );
    }

    // An excluded DID that is empty is still out even when that excluded DID is
    // itself the target — pins that the exclusion gate runs BEFORE the owner/empty
    // checks and is the sole barrier here (RED without the gate).
    #[test]
    fn exclusion_gate_precedes_empty_check() {
        let repos = vec![repo("collision", EXCLUDED_CONTENT, "spam1")];
        let got = select_spam_candidates(&repos, EXCLUDED_CONTENT, false, refs_by_id(&[]));
        assert!(got.is_empty(), "exclusion must win even on an empty repo");
    }

    // TOCTOU: a candidate that gained a ref between selection and the pre-delete
    // re-check must be skipped, not deleted; the rest of the batch still deletes.
    #[test]
    fn partition_for_delete_skips_repos_no_longer_empty() {
        let cand = |id: &str| Candidate {
            id: id.into(),
            owner_did: "o".into(),
            name: id.into(),
            ref_count: 0,
            remote_unverified: false,
        };
        let cands = vec![cand("still-empty"), cand("now-nonempty")];
        // Re-check reports the second repo as no longer empty.
        let (to_delete, to_skip) =
            partition_for_delete(&cands, |c| usize::from(c.id == "now-nonempty"));
        assert_eq!(
            to_delete.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["still-empty"]
        );
        assert_eq!(
            to_skip.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["now-nonempty"]
        );
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::db::{Db, RepoRecord};
    use chrono::Utc;
    use sqlx::PgPool;

    async fn db(pool: &PgPool) -> Db {
        let db = Db::for_testing(pool.clone());
        db.run_migrations().await.unwrap();
        db
    }

    /// Lock-only RepoStore over a test pool + repos_dir (no Tigris), for the purge
    /// callers that now take the advisory lock (M4).
    fn test_store(repos_dir: &Path, pool: &PgPool) -> crate::git::repo_store::RepoStore {
        crate::git::repo_store::RepoStore::for_testing(repos_dir.to_path_buf(), pool.clone())
    }

    /// A Postgres pool of a fixed size with a short acquire timeout and no ambient
    /// reaping, so a purge exercised at GITLAWB_DB_MAX_CONNECTIONS=1 fails fast
    /// (rather than stalling the whole test) if the single connection is pinned.
    /// min/idle/lifetime pinned so a held connection is never reclaimed
    /// mid-assertion.
    async fn sized_no_reap_pool(
        connect_opts: &sqlx::postgres::PgConnectOptions,
        max_connections: u32,
    ) -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .min_connections(0)
            .idle_timeout(None)
            .max_lifetime(None)
            .test_before_acquire(false)
            .connect_with(connect_opts.clone())
            .await
            .unwrap()
    }

    fn rec(id: &str, owner: &str, name: &str) -> RepoRecord {
        RepoRecord {
            id: id.to_string(),
            name: name.to_string(),
            owner_did: owner.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disk_path: format!("/srv/{id}.git"),
            forked_from: None,
            machine_id: None,
        }
    }

    async fn count_rows(db: &Db) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM repos")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    // Test 6: a dry-run over the full matrix deletes nothing. The empty check is
    // driven off a repos_dir with NO repos on disk, so every row reads as empty
    // (list_refs on a missing repo returns Err → treated as non-empty and skipped),
    // which is fine here: the assertion is that dry-run mutates no rows regardless.
    #[sqlx::test]
    async fn dry_run_deletes_nothing(pool: PgPool) {
        let db = db(&pool).await;
        for r in [
            rec("t-empty", SPAM_BURST_TARGET_DID, "spam1"),
            rec("t-nonempty", SPAM_BURST_TARGET_DID, "real"),
            rec("x-content", EXCLUDED_DIDS[0], "a"),
            rec("x-intern", EXCLUDED_DIDS[1], "b"),
            rec("u-empty", "did:key:z6MkUnrelated", "c"),
        ] {
            db.create_repo(&r).await.unwrap();
        }
        let before = count_rows(&db).await;
        assert_eq!(before, 5);

        // Materialize a REAL empty bare repo for the empty target so it is a genuine
        // purge candidate. Without an on-disk candidate, run_purge_spam hits the
        // no-candidate early return and the `if !execute { return }` guard is never
        // exercised with candidates present — the L10 gap this test now closes.
        let tmp = tempfile::TempDir::new().unwrap();
        let target_dir = store::repo_disk_path(tmp.path(), SPAM_BURST_TARGET_DID, "spam1");
        store::init_bare(&target_dir).unwrap();
        assert_eq!(
            store::list_refs(&target_dir).unwrap().len(),
            0,
            "precondition: the candidate is a real empty bare repo"
        );

        let store = test_store(tmp.path(), &pool);
        let summary = run_purge_spam(&db, &store, tmp.path(), false)
            .await
            .unwrap();

        // A candidate existed, but dry-run deletes nothing — DB row and on-disk dir
        // both survive. RED if the `if !execute` guard is removed.
        assert_eq!(summary.deleted, 0, "dry-run must delete no rows");
        let after = count_rows(&db).await;
        assert_eq!(after, before, "dry-run must not delete any repo rows");
        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "the candidate row must survive a dry-run"
        );
        assert!(
            target_dir.exists(),
            "dry-run must not remove the on-disk repo dir"
        );
    }

    // The DB accessor lists exactly the target DID's rows (exact owner match), and
    // delete_repo_by_id removes exactly one row, so the execute path deletes per
    // repo. This exercises the DB wiring end-to-end with a real empty repo on disk.
    #[sqlx::test]
    async fn execute_deletes_only_the_empty_target_repo_on_disk(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();

        // One empty target repo (real bare repo, zero refs) and one target repo
        // with a ref, plus an excluded-owner empty repo.
        let empty = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        let nonempty = rec("t-refs", SPAM_BURST_TARGET_DID, "real");
        let excluded = rec("x-content", EXCLUDED_DIDS[0], "keep");
        for r in [&empty, &nonempty, &excluded] {
            db.create_repo(r).await.unwrap();
        }

        // Materialize the two target repos on disk.
        let empty_path = store::repo_disk_path(tmp.path(), &empty.owner_did, &empty.name);
        store::init_bare(&empty_path).unwrap();
        let refs_path = store::repo_disk_path(tmp.path(), &nonempty.owner_did, &nonempty.name);
        store::init_bare(&refs_path).unwrap();
        // Give the non-empty repo an actual ref.
        seed_one_ref(&refs_path);

        // Sanity: our on-disk ref reader sees the expected counts.
        assert_eq!(store::list_refs(&empty_path).unwrap().len(), 0);
        assert!(!store::list_refs(&refs_path).unwrap().is_empty());

        let repo_store = test_store(tmp.path(), &pool);
        run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        // Only the empty target repo row is gone.
        assert!(db
            .get_repo(SPAM_BURST_TARGET_DID, "spam1")
            .await
            .unwrap()
            .is_none());
        assert!(db
            .get_repo(SPAM_BURST_TARGET_DID, "real")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .get_repo(EXCLUDED_DIDS[0], "keep")
            .await
            .unwrap()
            .is_some());
    }

    // Execute removes the on-disk bare repo dir too, so the DB row and disk stay
    // consistent (no orphaned empty git dir left behind).
    #[sqlx::test]
    async fn execute_removes_the_on_disk_repo_dir(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let empty = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&empty).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &empty.owner_did, &empty.name);
        store::init_bare(&path).unwrap();
        assert!(path.exists(), "precondition: on-disk repo exists");

        let repo_store = test_store(tmp.path(), &pool);
        run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_none(),
            "DB row deleted"
        );
        assert!(!path.exists(), "on-disk bare repo dir must be removed too");
    }

    // U3 (R3/KTD3): a purge at GITLAWB_DB_MAX_CONNECTIONS=1 (app pool size 1) must
    // still delete. U2 split the pools: the advisory-lock guard pins a connection
    // from the dedicated lock_pool while delete_repo_by_id runs on the app pool, so
    // the single app connection is free for the delete's begin() even while the guard
    // holds the repo lock. Load-bearing for the admin wiring: if the purge store were
    // (mis)wired to share ONE pool for the guard and the delete, the held guard
    // connection would leave begin() nothing to acquire, delete would time out
    // (PoolTimedOut), and the row would survive — deleted stays 0. The split store
    // built here is what keeps the purge correct at one connection.
    #[sqlx::test]
    async fn purge_at_one_app_connection_deletes_with_split_pools(
        _pool_opts: sqlx::postgres::PgPoolOptions,
        connect_opts: sqlx::postgres::PgConnectOptions,
    ) {
        // Migrate + seed on a normal multi-connection pool: migrate() pins one
        // connection for its advisory lock while running migration queries on
        // others, so it cannot run on a size-1 pool.
        let setup_db = Db::for_testing(sized_no_reap_pool(&connect_opts, 5).await);
        setup_db.run_migrations().await.unwrap();
        let empty = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        setup_db.create_repo(&empty).await.unwrap();

        let tmp = tempfile::TempDir::new().unwrap();
        let path = store::repo_disk_path(tmp.path(), &empty.owner_did, &empty.name);
        store::init_bare(&path).unwrap();
        assert_eq!(
            store::list_refs(&path).unwrap().len(),
            0,
            "precondition: the candidate is a real empty bare repo"
        );

        // The purge runs at ONE app connection (finding E's MAX_CONNECTIONS=1) with a
        // SEPARATE lock pool. Split store: the guard draws from lock_pool, the delete
        // runs on the app pool via `db` — the production wiring from main.rs's
        // purge-spam path.
        let app_pool = sized_no_reap_pool(&connect_opts, 1).await;
        let lock_pool = sized_no_reap_pool(&connect_opts, 1).await;
        let db = Db::for_testing(app_pool);
        let store =
            crate::git::repo_store::RepoStore::new(tmp.path().to_path_buf(), None, lock_pool);
        let summary = run_purge_spam(&db, &store, tmp.path(), true).await.unwrap();

        assert_eq!(
            summary.deleted, 1,
            "a split-pool purge at one app connection must delete the candidate row"
        );
        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_none(),
            "the target row must be gone after a size-1 purge"
        );
    }

    // U4 (M4): a repo whose per-repo advisory lock is held by a live writer must be
    // SKIPPED by purge, not deleted out from under the push. Holds the lock via the
    // same RepoStore (a separate pooled connection), runs execute, and asserts the
    // row + on-disk dir survive; once the writer releases, purge deletes it.
    #[sqlx::test]
    async fn locked_repo_is_skipped_not_deleted(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let empty = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&empty).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &empty.owner_did, &empty.name);
        store::init_bare(&path).unwrap();

        let repo_store = test_store(tmp.path(), &pool);
        // A live writer holds the per-repo advisory lock.
        let held = repo_store
            .try_lock_repo(&empty.owner_did, &empty.name)
            .await
            .unwrap()
            .expect("lock should be free initially");

        run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        // Locked → skipped: both the row and the on-disk dir survive.
        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "a repo locked by a live writer must NOT be deleted"
        );
        assert!(path.exists(), "on-disk dir must survive while locked");

        // Once the writer releases, the empty repo is deleted (the lock was the
        // only thing protecting it — baseline both ways).
        held.release().await;
        run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();
        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_none(),
            "once unlocked, the empty repo is deleted"
        );
    }

    // U5 (M6): a repo whose DB row is deleted but whose on-disk removal FAILS must
    // be counted in `disk_failed`, never folded into a clean "deleted" success —
    // else the summary reports success while the on-disk dir survives (DB/disk
    // drift). Forces the failure by making the parent (slug) dir read-only.
    #[sqlx::test]
    async fn disk_removal_failure_is_counted_not_reported_as_success(pool: PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let empty = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&empty).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &empty.owner_did, &empty.name);
        store::init_bare(&path).unwrap();

        // Read-only parent (slug) dir: remove_dir_all cannot unlink the repo dir.
        let slug_dir = path.parent().unwrap().to_path_buf();
        let orig = std::fs::metadata(&slug_dir).unwrap().permissions();
        std::fs::set_permissions(&slug_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let repo_store = test_store(tmp.path(), &pool);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        // Restore perms so TempDir cleanup works regardless of assertion outcome.
        std::fs::set_permissions(&slug_dir, orig).unwrap();

        assert_eq!(summary.deleted, 1, "the DB row was deleted");
        assert_eq!(
            summary.disk_failed, 1,
            "a failed on-disk removal must be counted, not reported as clean success"
        );
        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_none(),
            "DB row is gone (delete succeeded)"
        );
        assert!(
            path.exists(),
            "on-disk dir survived the failed removal (drift)"
        );
    }

    // U1 (M3): a burst-owned row whose NAME traverses out of repos_dir must never
    // cause a delete OUTSIDE repos_dir. Adversarial must-not: a real empty bare repo
    // planted as a "victim" beside repos_dir is reachable from repos_dir/<slug>/ via
    // a `../../victim` name; because the traversed path IS a real bare repo, the
    // marker check passes and the candidate is selected — then remove_dir_all would
    // delete the victim. The name validator must reject it so the victim survives.
    #[sqlx::test]
    async fn traversal_name_cannot_delete_a_repo_outside_repos_dir(pool: PgPool) {
        let db = db(&pool).await;
        let root = tempfile::TempDir::new().unwrap();
        let repos_dir = root.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        // The burst DID's own slug dir must exist for the OS to resolve the `..`
        // segments (a burst that owns any normal repo already has this dir).
        let slug = SPAM_BURST_TARGET_DID.replace([':', '/'], "_");
        std::fs::create_dir_all(repos_dir.join(&slug)).unwrap();

        // Victim: a real empty bare repo OUTSIDE repos_dir (sibling under root).
        let victim = root.path().join("victim.git");
        store::init_bare(&victim).unwrap();
        assert!(victim.join("HEAD").is_file(), "victim precondition");

        // Sanity: the evil name resolves from repos_dir/<slug>/ onto the victim.
        let evil = rec("evil", SPAM_BURST_TARGET_DID, "../../victim");
        let traversed = store::repo_disk_path(&repos_dir, &evil.owner_did, &evil.name);
        assert_eq!(
            std::fs::canonicalize(&traversed).unwrap(),
            std::fs::canonicalize(&victim).unwrap(),
            "test setup: the evil name must resolve onto the victim"
        );

        db.create_repo(&evil).await.unwrap();
        let repo_store = test_store(&repos_dir, &pool);
        run_purge_spam(&db, &repo_store, &repos_dir, true)
            .await
            .unwrap();

        assert!(
            victim.join("HEAD").is_file(),
            "a repo OUTSIDE repos_dir must never be deleted via a traversal name"
        );
    }

    // The DB query normalizes did:key form (OWNER_KEY_CASE_SQL), so a burst repo
    // stored in SHORT (bare) form is still found when querying by the full-form
    // target DID — the SQL side of the normalization fix.
    #[sqlx::test]
    async fn list_repos_by_owner_did_matches_short_form(pool: PgPool) {
        let db = db(&pool).await;
        let short = crate::db::normalize_owner_key(SPAM_BURST_TARGET_DID);
        assert_ne!(short, SPAM_BURST_TARGET_DID, "fixture must be short form");
        let repo = rec("short-owned", short, "spam");
        db.create_repo(&repo).await.unwrap();

        let rows = db
            .list_repos_by_owner_did(SPAM_BURST_TARGET_DID)
            .await
            .unwrap();
        assert!(
            rows.iter().any(|r| r.id == "short-owned"),
            "a short-form burst row must be found when querying by the full-form target"
        );
    }

    /// Create a single commit + ref in a bare repo via a throwaway worktree, so the
    /// repo reads as non-empty (≥1 ref).
    fn seed_one_ref(bare: &Path) {
        use std::process::Command;
        let wt = bare.join("_seed");
        let run = |args: &[&str], dir: &Path| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(dir)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?} failed");
        };
        run(
            &["worktree", "add", "--orphan", "-b", "main", "_seed"],
            bare,
        );
        std::fs::write(wt.join("f.txt"), b"x").unwrap();
        run(&["config", "user.email", "t@t"], &wt);
        run(&["config", "user.name", "t"], &wt);
        run(&["add", "."], &wt);
        run(&["commit", "-qm", "seed"], &wt);
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force", "_seed"])
            .current_dir(bare)
            .status();
    }

    /// A `0` ref count must come only from a real bare repo at the exact path,
    /// never from git discovery walking up to a parent `.git`. Load-bearing: the
    /// tempdir root is itself a git repo (zero refs), so a naive `for-each-ref`
    /// run from a child non-git dir would discover it and report 0 — the delete-a-
    /// real-repo fail-open. The marker check must make that path fail closed.
    #[test]
    fn nongit_path_fails_closed_even_under_a_git_ancestor() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Make the tempdir root a git repo with zero refs (the discovery trap).
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(tmp.path())
            .status()
            .unwrap();

        let repo = rec("t-x", SPAM_BURST_TARGET_DID, "spam1");
        let path = store::repo_disk_path(tmp.path(), &repo.owner_did, &repo.name);

        // (a0) A genuinely MISSING path is a verified NotFound — the only case that
        // returns None (eligible for a remote-unverified archive refresh).
        assert!(!path.exists());
        assert_eq!(
            local_refs_on_disk(tmp.path(), &repo.owner_did, &repo.name),
            None,
            "a verifiably-absent path must return None (eligible for archive refresh)"
        );

        // (a) Path exists as a plain (non-git) directory under the git ancestor.
        // Without the marker guard, git discovery would read the ancestor's 0 refs
        // and this repo would be deleted. It must fail CLOSED to Some(1) — NOT
        // None: returning None would promote it to remote_unverified, and the
        // refresh's remove_dir_all would overwrite this existing directory. And it
        // must never run list_refs to read the ancestor's 0.
        std::fs::create_dir_all(&path).unwrap();
        assert_eq!(
            local_refs_on_disk(tmp.path(), &repo.owner_did, &repo.name),
            Some(1),
            "an existing non-git dir must fail closed to Some(1), never None (which would overwrite it)"
        );
        assert_eq!(
            ref_count_on_disk(tmp.path(), &repo.owner_did, &repo.name),
            1,
            "the under-lock recheck must also fail closed on a non-git dir"
        );

        // (b) A real empty bare repo at the same path reads Some(0) — a candidate.
        std::fs::remove_dir_all(&path).unwrap();
        store::init_bare(&path).unwrap();
        assert_eq!(
            local_refs_on_disk(tmp.path(), &repo.owner_did, &repo.name),
            Some(0)
        );
    }

    /// The belt-and-suspenders containment gate (`path_within`) must reject a path
    /// that resolves outside repos_dir even when the *name* itself is innocuous —
    /// e.g. the owner slug dir is a symlink pointing elsewhere. Layer 1 (name
    /// validation) can't see this; only the canonical-containment check catches it.
    #[test]
    fn path_within_rejects_symlink_escape() {
        let root = tempfile::TempDir::new().unwrap();
        let repos_dir = root.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        // A real dir outside repos_dir, and a symlink INTO repos_dir that targets it.
        let outside = root.path().join("outside.git");
        std::fs::create_dir_all(&outside).unwrap();
        let link = repos_dir.join("evil.git");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        // The name is innocuous, but the path resolves outside repos_dir.
        assert!(
            !path_within(&link, &repos_dir),
            "a symlink escaping repos_dir must fail the containment gate"
        );
        // A genuine path inside repos_dir passes.
        let inside = repos_dir.join("real.git");
        std::fs::create_dir_all(&inside).unwrap();
        assert!(
            path_within(&inside, &repos_dir),
            "an in-root path must pass"
        );
    }

    /// The exclusion gate and the target scope must never overlap: if the burst
    /// target were ever set to an excluded DID, the gate would fail to protect it.
    #[test]
    fn target_did_is_never_excluded() {
        assert!(
            !EXCLUDED_DIDS.contains(&SPAM_BURST_TARGET_DID),
            "the purge target must never be an excluded (protected) DID"
        );
    }

    /// Exclusion is normalization-consistent: an excluded identity stored in the
    /// bare short form (as mirror upserts write it) is still excluded, even though
    /// the exclusion constants are full did:key form — and an empty repo it owns
    /// is never selected.
    #[test]
    fn short_form_excluded_did_is_still_protected() {
        let short = crate::db::normalize_owner_key(EXCLUDED_DIDS[1]); // bare z6MkqRz…
        assert_ne!(
            short, EXCLUDED_DIDS[1],
            "fixture must actually be short form"
        );
        assert!(
            is_excluded(short),
            "short-form of an excluded DID must be excluded"
        );

        // An empty repo owned by the short-form excluded DID is spared even though
        // its ref signature (0) otherwise matches the burst.
        let empty_excluded_short = rec("x-short", short, "spam");
        let cands = select_spam_candidates(
            &[empty_excluded_short],
            SPAM_BURST_TARGET_DID,
            false,
            |_| Some(0),
        );
        assert!(
            cands.is_empty(),
            "an empty repo owned by a short-form excluded DID must never be a candidate"
        );
    }

    // ── Tigris-authoritative purge (P1b) ───────────────────────────────────

    /// In-test object store. `download` materializes a bare repo with (or
    /// without) a ref so the purge tool's authoritative recheck can be driven
    /// without a live bucket; error flags exercise the fail-closed and
    /// archive-delete-failure paths.
    struct FakeStore {
        has_archive: bool,
        archive_has_refs: bool,
        fail_recheck: bool,
        fail_delete: bool,
        deleted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl crate::git::tigris::ObjectStore for FakeStore {
        async fn exists(&self, _owner: &str, _repo: &str) -> Result<bool> {
            if self.fail_recheck {
                anyhow::bail!("fake object store unreachable");
            }
            Ok(self.has_archive)
        }
        async fn upload(&self, _owner: &str, _repo: &str, _path: &Path) -> Result<()> {
            Ok(())
        }
        async fn download(&self, _owner: &str, _repo: &str, local_path: &Path) -> Result<()> {
            if self.fail_recheck {
                anyhow::bail!("fake object store unreachable");
            }
            // Materialize the authoritative archive on local disk so
            // ref_count_on_disk reflects remote state.
            let _ = std::fs::remove_dir_all(local_path);
            store::init_bare(local_path).unwrap();
            if self.archive_has_refs {
                seed_one_ref(local_path);
            }
            Ok(())
        }
        async fn delete(&self, _owner: &str, _repo: &str) -> Result<()> {
            self.deleted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if self.fail_delete {
                anyhow::bail!("fake object store delete failed");
            }
            Ok(())
        }
    }

    fn store_backed(
        repos_dir: &Path,
        pool: &PgPool,
        fake: FakeStore,
    ) -> crate::git::repo_store::RepoStore {
        crate::git::repo_store::RepoStore::new(
            repos_dir.to_path_buf(),
            Some(std::sync::Arc::new(fake)),
            pool.clone(),
        )
    }

    fn fake(
        has_archive: bool,
        archive_has_refs: bool,
        fail_recheck: bool,
        fail_delete: bool,
    ) -> (FakeStore, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let deleted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            FakeStore {
                has_archive,
                archive_has_refs,
                fail_recheck,
                fail_delete,
                deleted: deleted.clone(),
            },
            deleted,
        )
    }

    // A locally-empty repo whose authoritative archive HAS refs (pushed via
    // another machine) must NOT be purged on the stale-local view. Load-bearing:
    // RED on the Tigris-blind purge (deletes it), GREEN once the recheck
    // consults the object store.
    #[sqlx::test]
    async fn purge_skips_repo_with_remote_refs_when_local_empty(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-remote", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        store::init_bare(&path).unwrap();
        assert_eq!(
            store::list_refs(&path).unwrap().len(),
            0,
            "local starts empty"
        );

        let (f, _deleted) = fake(true, true, false, false);
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "a repo with live remote refs must not be purged on a stale-local view"
        );
        assert_eq!(summary.deleted, 0);
        assert_eq!(summary.skipped_not_empty, 1);
    }

    // A genuinely-empty repo (empty archive) is deleted AND its archive removed,
    // else the archive can be re-downloaded into a later same-name repo.
    // Load-bearing: RED on the Tigris-blind purge (archive survives), GREEN once
    // the delete wires the archive removal.
    #[sqlx::test]
    async fn purge_deletes_archive_on_successful_delete(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        store::init_bare(&path).unwrap();

        let (f, deleted) = fake(true, false, false, false);
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_none(),
            "a genuinely-empty repo is deleted"
        );
        assert!(
            deleted.load(std::sync::atomic::Ordering::SeqCst),
            "the object-store archive must be deleted on a successful purge"
        );
        assert_eq!(summary.deleted, 1);
        assert_eq!(summary.archive_failed, 0);
    }

    // An unreachable object store during the recheck must fail closed (skip),
    // never delete on an unverified view. Load-bearing: RED on the Tigris-blind
    // purge (deletes), GREEN once the recheck consults (and fails closed on) the
    // store.
    #[sqlx::test]
    async fn purge_fails_closed_when_store_unreachable(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        store::init_bare(&path).unwrap();

        let (f, _deleted) = fake(true, false, true, false);
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "must not delete when the object store is unreachable (fail-closed)"
        );
        assert_eq!(summary.deleted, 0);
        assert_eq!(summary.skipped_store_error, 1);
    }

    // An archive-delete failure after the row+dir are removed is counted
    // separately, never folded into a clean success.
    #[sqlx::test]
    async fn purge_archive_delete_failure_counted_separately(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        store::init_bare(&path).unwrap();

        let (f, deleted) = fake(true, false, false, true);
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_none(),
            "the row+dir are still deleted"
        );
        assert!(deleted.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(summary.deleted, 1);
        assert_eq!(
            summary.archive_failed, 1,
            "a surviving archive must be counted, not reported as clean success"
        );
    }

    // AE3/R4: a repo that exists ONLY as an object-store archive (no local copy)
    // with an EMPTY archive is reached, refreshed under the lock, and deleted
    // (row + dir + archive). Pre-U4 a missing-local row was never a candidate
    // (treated non-empty, skipped) -> RED; admitting it remote-unverified -> GREEN.
    #[sqlx::test]
    async fn purge_deletes_remote_only_empty_archive(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-remote-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        // NO local repo — it exists only as an archive.
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        assert!(!path.exists(), "no local copy — remote-only");

        let (f, deleted) = fake(true, false, false, false); // archive exists, empty
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_none(),
            "a remote-only empty archive must be reached and deleted"
        );
        assert!(
            deleted.load(std::sync::atomic::Ordering::SeqCst),
            "the archive must be deleted too"
        );
        assert_eq!(summary.deleted, 1);
        assert_eq!(
            summary.remote_unverified, 1,
            "the candidate was admitted as remote-unverified"
        );
    }

    // AE4/R4: a remote-only archive that turns out to HAVE refs is refreshed under
    // the lock and then skipped — never deleted on the missing-local view.
    #[sqlx::test]
    async fn purge_skips_remote_only_archive_with_refs(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-remote-refs", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        assert!(!path.exists());

        let (f, _deleted) = fake(true, true, false, false); // archive exists, HAS refs
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "a remote-only archive with refs must be refreshed and skipped, not deleted"
        );
        assert_eq!(summary.deleted, 0);
        assert_eq!(summary.skipped_not_empty, 1);
    }

    // U7/R7: an existing NON-repository directory (holding operator data) sits at
    // the exact target path. It is not a bare git repo, so it must fail CLOSED —
    // never be admitted remote-unverified, because that promotion drives
    // refresh_from_archive, whose remove_dir_all + extract would OVERWRITE the
    // directory. Load-bearing: on base, local_refs_on_disk returns None for a
    // non-bare path, the candidate is promoted, refresh wipes the dir and the row
    // is deleted (RED). After the fix, Some(1) keeps it out entirely (GREEN).
    #[sqlx::test]
    async fn purge_does_not_overwrite_non_repo_dir_at_target(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-nonrepo", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();

        // A plain directory with a file — deliberately NOT a bare git repo.
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        std::fs::create_dir_all(&path).unwrap();
        let sentinel = path.join("keep.txt");
        std::fs::write(&sentinel, b"operator data").unwrap();

        let (f, deleted) = fake(true, false, false, false); // archive exists, empty
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            sentinel.exists(),
            "an existing non-repo dir must not be overwritten by the purge refresh"
        );
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"operator data",
            "the non-repo dir's contents must be intact"
        );
        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "a repo whose disk path is a non-bare dir must not be purged"
        );
        assert_eq!(summary.deleted, 0);
        assert_eq!(
            summary.remote_unverified, 0,
            "a non-bare existing dir must never be admitted remote-unverified"
        );
        assert!(
            !deleted.load(std::sync::atomic::Ordering::SeqCst),
            "the archive must not be deleted"
        );
    }

    // AE5/R5: no local copy AND no archive — the candidate is admitted (a store is
    // configured) but the under-lock recheck finds nothing and fails closed.
    #[sqlx::test]
    async fn purge_skips_remote_unverified_with_no_archive(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-missing-both", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();

        let (f, _deleted) = fake(false, false, false, false); // NO archive
        let repo_store = store_backed(tmp.path(), &pool, f);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "missing local AND no archive must fail closed (not deleted)"
        );
        assert_eq!(summary.deleted, 0);
        assert_eq!(
            summary.skipped_not_empty, 1,
            "skipped by the authoritative under-lock recheck"
        );
    }

    // R5: with NO object store, a repo with no local copy is not even a candidate
    // (the missing-local admission is gated on a configured store).
    #[sqlx::test]
    async fn purge_storeless_missing_local_is_not_a_candidate(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-nolocal", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        // Storeless RepoStore, no local repo on disk.
        let repo_store = test_store(tmp.path(), &pool);
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(
            db.get_repo(SPAM_BURST_TARGET_DID, "spam1")
                .await
                .unwrap()
                .is_some(),
            "storeless + missing-local must fail closed — never a candidate"
        );
        assert_eq!(summary.deleted, 0);
        assert_eq!(summary.remote_unverified, 0);
    }

    // R7: with no object store configured (single-machine), an empty repo is
    // deleted exactly as before and nothing touches an archive.
    #[sqlx::test]
    async fn purge_tigris_disabled_deletes_empty_unchanged(pool: PgPool) {
        let db = db(&pool).await;
        let tmp = tempfile::TempDir::new().unwrap();
        let target = rec("t-empty", SPAM_BURST_TARGET_DID, "spam1");
        db.create_repo(&target).await.unwrap();
        let path = store::repo_disk_path(tmp.path(), &target.owner_did, &target.name);
        store::init_bare(&path).unwrap();

        let repo_store = test_store(tmp.path(), &pool); // Tigris = None
        let summary = run_purge_spam(&db, &repo_store, tmp.path(), true)
            .await
            .unwrap();

        assert!(db
            .get_repo(SPAM_BURST_TARGET_DID, "spam1")
            .await
            .unwrap()
            .is_none());
        assert_eq!(summary.deleted, 1);
        assert_eq!(summary.skipped_store_error, 0);
        assert_eq!(summary.archive_failed, 0);
    }
}
