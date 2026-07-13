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

/// A repo selected for purge, with the evidence that qualified it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub owner_did: String,
    pub name: String,
    /// Number of git refs found on disk. Always 0 for a selected candidate — kept
    /// as explicit evidence in the dry-run output rather than an implicit "empty".
    pub ref_count: usize,
}

/// Whether a DID is on the hard exclusion list.
fn is_excluded(owner_did: &str) -> bool {
    EXCLUDED_DIDS.contains(&owner_did)
}

/// Pure candidate selector — the security core, isolated from disk and DB so the
/// exclusion + empty logic is directly testable.
///
/// `repos` is the raw row set to consider (the caller supplies the target DID's
/// rows). `ref_count_of` returns the number of git refs for a given repo; the CLI
/// wires the real on-disk ref source, tests inject precomputed counts.
///
/// A repo qualifies ONLY if, PER REPO:
///   1. its owner is NOT on the exclusion list (gate evaluated FIRST), AND
///   2. its owner is exactly the target burst DID, AND
///   3. it is verified empty — `ref_count_of` returns 0.
///
/// The exclusion gate is checked before the empty check so that an empty repo
/// owned by an excluded DID is dropped regardless of its ref signature.
pub fn select_spam_candidates<F>(
    repos: &[RepoRecord],
    target_did: &str,
    mut ref_count_of: F,
) -> Vec<Candidate>
where
    F: FnMut(&RepoRecord) -> usize,
{
    let mut out = Vec::new();
    for repo in repos {
        // Hard exclusion gate FIRST — wins over the empty signature.
        if is_excluded(&repo.owner_did) {
            continue;
        }
        // Scope to the named burst only.
        if repo.owner_did != target_did {
            continue;
        }
        // Per-repo empty check.
        let ref_count = ref_count_of(repo);
        if ref_count != 0 {
            continue;
        }
        out.push(Candidate {
            id: repo.id.clone(),
            owner_did: repo.owner_did.clone(),
            name: repo.name.clone(),
            ref_count,
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
fn on_disk_ref_count(repos_dir: &Path, repo: &RepoRecord) -> usize {
    let path = store::repo_disk_path(repos_dir, &repo.owner_did, &repo.name);
    match store::list_refs(&path) {
        Ok(refs) => refs.len(),
        Err(e) => {
            // Fail closed: an unreadable repo is not provably empty, so keep it
            // out of the candidate set (report it as one ref so it's excluded).
            warn!(repo = %repo.id, path = %path.display(), err = %e,
                "purge-spam: could not read refs — treating as non-empty (skipped)");
            1
        }
    }
}

/// Run the `purge-spam` admin subcommand.
///
/// Enumerates the target burst DID's repos, verifies each is empty on disk,
/// applies the exclusion gate, prints one dry-run row per candidate with owner +
/// ref-count evidence, and — only when `execute` is true — deletes the DB row of
/// each candidate one at a time. Dry-run (the default) deletes nothing.
pub async fn run_purge_spam(db: &Db, repos_dir: &Path, execute: bool) -> Result<()> {
    let repos_dir: PathBuf = repos_dir.to_path_buf();
    let rows = db
        .list_repos_by_owner_did(SPAM_BURST_TARGET_DID)
        .await
        .context("listing repos for the spam-burst target DID")?;

    let candidates = select_spam_candidates(&rows, SPAM_BURST_TARGET_DID, |repo| {
        on_disk_ref_count(&repos_dir, repo)
    });

    info!(
        target = SPAM_BURST_TARGET_DID,
        scanned = rows.len(),
        candidates = candidates.len(),
        execute,
        "purge-spam: candidate selection complete"
    );

    if candidates.is_empty() {
        println!("purge-spam: no empty spam-burst repos found for {SPAM_BURST_TARGET_DID}");
        return Ok(());
    }

    println!(
        "purge-spam: {} candidate(s) for {} ({} mode)",
        candidates.len(),
        SPAM_BURST_TARGET_DID,
        if execute { "EXECUTE" } else { "dry-run" }
    );
    for c in &candidates {
        println!(
            "  {} owner={} name={} refs={}",
            c.id, c.owner_did, c.name, c.ref_count
        );
    }

    if !execute {
        println!(
            "purge-spam: dry-run — nothing deleted. Re-run with --execute to delete the {} candidate(s).",
            candidates.len()
        );
        return Ok(());
    }

    // Execute: delete per-repo, never a single blanket "delete all of owner X".
    let mut deleted = 0u64;
    for c in &candidates {
        match db.delete_repo_by_id(&c.id).await {
            Ok(n) => {
                deleted += n;
                info!(repo = %c.id, rows = n, "purge-spam: deleted repo row");
            }
            Err(e) => {
                warn!(repo = %c.id, err = %e, "purge-spam: failed to delete repo row");
            }
        }
    }
    println!("purge-spam: deleted {deleted} repo row(s).");
    Ok(())
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
    fn refs_by_id<'a>(map: &'a [(&'a str, usize)]) -> impl Fn(&RepoRecord) -> usize + 'a {
        move |r: &RepoRecord| {
            map.iter()
                .find(|(id, _)| *id == r.id)
                .map(|(_, n)| *n)
                .unwrap_or(0)
        }
    }

    // Test 1: an empty repo owned by the target DID is a candidate.
    #[test]
    fn empty_target_repo_is_a_candidate() {
        let repos = vec![repo("t-empty", TARGET, "spam1")];
        let got = select_spam_candidates(&repos, TARGET, refs_by_id(&[]));
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
        let got = select_spam_candidates(&repos, TARGET, refs_by_id(&[("t-nonempty", 3)]));
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
        let got = select_spam_candidates(&repos, EXCLUDED_CONTENT, refs_by_id(&[]));
        assert!(
            got.is_empty(),
            "an empty repo owned by the excluded content DID must be excluded even \
             if that DID were the target, got {got:?}"
        );
        // And of course it is also absent when the real burst DID is the target.
        let got = select_spam_candidates(&repos, TARGET, refs_by_id(&[]));
        assert!(got.is_empty());
    }

    // Test 4 (MUST ASSERT): an EMPTY repo owned by the intern DID is absent.
    // Same construction as test 3: the intern DID is passed as the target so the
    // exclusion gate is the sole reason it is dropped (RED without the gate).
    #[test]
    fn empty_intern_repo_is_absent() {
        let repos = vec![repo("x-intern", EXCLUDED_INTERN, "mirror")];
        let got = select_spam_candidates(&repos, EXCLUDED_INTERN, refs_by_id(&[]));
        assert!(
            got.is_empty(),
            "an empty repo owned by the intern/mirror-bot DID must be excluded even \
             if that DID were the target, got {got:?}"
        );
        let got = select_spam_candidates(&repos, TARGET, refs_by_id(&[]));
        assert!(got.is_empty());
    }

    // Test 5: an empty repo owned by an unrelated DID is absent — the tool targets
    // the named burst only.
    #[test]
    fn empty_unrelated_repo_is_absent() {
        let repos = vec![repo("u-empty", UNRELATED, "whatever")];
        let got = select_spam_candidates(&repos, TARGET, refs_by_id(&[]));
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
        let got = select_spam_candidates(&repos, TARGET, refs_by_id(&[("t-nonempty", 2)]));
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
        let got = select_spam_candidates(&repos, EXCLUDED_CONTENT, refs_by_id(&[]));
        assert!(got.is_empty(), "exclusion must win even on an empty repo");
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::db::{Db, RepoRecord};
    use chrono::Utc;
    use sqlx::PgPool;

    async fn db(pool: PgPool) -> Db {
        let db = Db::for_testing(pool);
        db.run_migrations().await.unwrap();
        db
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
        let db = db(pool).await;
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

        // Empty repos dir: no repo exists on disk, so nothing is provably empty.
        let tmp = tempfile::TempDir::new().unwrap();
        run_purge_spam(&db, tmp.path(), false).await.unwrap();

        let after = count_rows(&db).await;
        assert_eq!(after, before, "dry-run must not delete any repo rows");
    }

    // The DB accessor lists exactly the target DID's rows (exact owner match), and
    // delete_repo_by_id removes exactly one row, so the execute path deletes per
    // repo. This exercises the DB wiring end-to-end with a real empty repo on disk.
    #[sqlx::test]
    async fn execute_deletes_only_the_empty_target_repo_on_disk(pool: PgPool) {
        let db = db(pool).await;
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

        run_purge_spam(&db, tmp.path(), true).await.unwrap();

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
}
