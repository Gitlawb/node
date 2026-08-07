use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

#[cfg(unix)]
#[allow(clippy::single_component_path_imports)]
use libc;

use crate::config::Config;
use crate::db::Db;

/// How often to run a sweep pass.
const SWEEP_INTERVAL_SECS: u64 = 3600;

/// Maximum repos to process per pass — prevents the sweep from becoming
/// the O(repos) amplification the admission-control work exists to prevent.
const REPOS_PER_PASS: usize = 100;

/// Maximum objects to pin per backend per repo in a single pass — prevents one
/// large repo from monopolizing the blocking pool or the hourly budget. Applied
/// after filtering out already-pinned objects so the cap reflects actual work.
const MAX_OBJECTS_PER_REPO: usize = 50_000;

/// Per-repo deadline for the blocking git scan (list_all_objects + visibility
/// filter).  A pathological repo that stalls past this is skipped for the pass.
const REPO_SCAN_DEADLINE: Duration = Duration::from_secs(300);

/// Per-repo deadline for the pinning phase (IPFS + Pinata uploads).  An
/// unavailable backend that stalls per-object must not hold the sweep for
/// the entire backlog; this bounds the total wall time per repo per pass.
const PIN_PHASE_DEADLINE: Duration = Duration::from_secs(300);

/// Grace period between the SIGTERM sweep of a stalled repo's git subprocesses
/// and the SIGKILL escalation.  `git` normally exits promptly on TERM; only a
/// wedged process should survive this long.
const KILL_GRACE_SECS: u64 = 10;

/// node_state key under which the sweep's keyset cursor is persisted across
/// restarts (R2-P1).
const CURSOR_KEY: &str = "reconciliation_sweep_cursor";

/// Whether the sweep should spawn given the current configuration.
/// Extracted for testing — test both directions independently.
fn should_spawn(config: &Config) -> bool {
    if !config.reconciliation_sweep {
        return false;
    }
    !config.ipfs_api.is_empty() || !config.pinata_jwt.is_empty()
}

/// Spawn the periodic reconciliation sweep background task.
/// No-op when neither IPFS nor Pinata is configured, or when
/// `reconciliation_sweep` is disabled. Returns `true` when the worker was
/// actually spawned so the caller can gate its own "worker started" logging.
pub fn spawn(
    db: Arc<Db>,
    config: Arc<Config>,
    http_client: Arc<reqwest::Client>,
    node_keypair: Arc<gitlawb_core::identity::Keypair>,
    node_did: gitlawb_core::did::Did,
    mut shutdown_rx: watch::Receiver<bool>,
) -> bool {
    if !should_spawn(&config) {
        tracing::info!(
            "reconciliation sweep: disabled or neither IPFS nor Pinata configured, skipping spawn"
        );
        return false;
    }

    tokio::spawn(async move {
        let node_seed = *node_keypair.to_seed();
        // Resume from the persisted cursor (R2-P1): a node restart must not
        // re-walk every repo, and the cursor is only ever advanced after a
        // batch completes, so an interrupted pass resumes where it stopped.
        let mut cursor: Option<String> = match db.get_node_state(CURSOR_KEY).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(err = %e, "failed to load reconciliation sweep cursor from node_state; starting from scratch");
                None
            }
        };

        loop {
            let start = std::time::Instant::now();
            match run_pass(
                &db,
                &config,
                &http_client,
                &node_seed,
                &node_did,
                &mut cursor,
                &mut shutdown_rx,
            )
            .await
            {
                Ok((count, gaps, filled)) => {
                    tracing::info!(
                        repos = count,
                        gaps_found = gaps,
                        gaps_filled = filled,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "reconciliation sweep pass complete"
                    );
                }
                Err(e) => {
                    tracing::warn!(err = %e, "reconciliation sweep pass failed");
                }
            }

            if *shutdown_rx.borrow() {
                tracing::info!("reconciliation sweep: shutdown signal received, exiting");
                return;
            }

            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(SWEEP_INTERVAL_SECS)) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("reconciliation sweep: shutdown signal received, exiting");
                        return;
                    }
                }
            }
        }
    });

    true
}

/// Re-derive the *allowed* public-object set from fresh rules and intersect it
/// with the scanned object list. Returns `None` when the re-derivation failed
/// (caller skips the repo). This is the path-scoped-visibility re-filter that
/// runs against rules re-fetched after the git scan, so a narrowing made
/// mid-scan is honored before anything is pinned.
///
/// The two `spawn_blocking` stages (full scan, re-filter) share the deadline so
/// the total blocking time per repo stays bounded.
async fn refilter_public_objects(
    ctx: &Arc<crate::git::ScanContext>,
    disk: &std::path::Path,
    rules: &[crate::db::VisibilityRule],
    is_public: bool,
    owner_did: &str,
    object_list: Vec<String>,
) -> Option<Vec<String>> {
    let ctx_clone = ctx.clone();
    let disk_clone = disk.to_path_buf();
    let rules_clone = rules.to_vec();
    let owner_clone = owner_did.to_string();

    match tokio::time::timeout(
        REPO_SCAN_DEADLINE,
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
            let _guard = crate::git::set_scan_context(ctx_clone.clone());
            let allowed = crate::git::visibility_pack::replicable_blob_set(
                &disk_clone,
                &rules_clone,
                is_public,
                &owner_clone,
            )?;
            if ctx_clone.canceled.load(Ordering::SeqCst) {
                return Err(anyhow::anyhow!("scan canceled after replicable_blob_set"));
            }
            let all_blobs = crate::git::push_delta::all_blob_oids(&disk_clone)?;
            Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
                object_list,
                &allowed,
                &all_blobs,
            ))
        }),
    )
    .await
    {
        Ok(Ok(Ok(list))) => Some(list),
        Ok(Ok(Err(e))) => {
            tracing::warn!(err = %e, "visibility re-derivation failed");
            None
        }
        Ok(Err(e)) => {
            tracing::warn!(err = %e, "visibility re-derivation task panicked");
            None
        }
        Err(_) => {
            escalate_kill(ctx, "visibility re-derivation deadline exceeded");
            None
        }
    }
}
/// Re-check quarantine AND root visibility immediately before an irreversible
/// public pin (R1-P1). Returns the fresh repo row plus fresh rules, or `None`
/// when the pin must be skipped. DB failures are treated as skip (never pin on
/// a stale allow), so one repo's failure does not abort the pass.
async fn recheck_public_pin(
    db: &Db,
    repo_id: &str,
    repo_slug: &str,
) -> Option<(crate::db::RepoRecord, Vec<crate::db::VisibilityRule>)> {
    match db.is_repo_quarantined(repo_id).await {
        Ok(true) => {
            tracing::warn!(repo = %repo_slug, "repo quarantined, skipping pin");
            return None;
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(repo = %repo_slug, err = %e, "quarantine recheck failed, skipping pin");
            return None;
        }
    }
    let rules = match db.list_visibility_rules(repo_id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(repo = %repo_slug, err = %e, "visibility rules re-fetch failed, skipping pin");
            return None;
        }
    };
    let fresh = match db.get_repo_by_id(repo_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::warn!(repo = %repo_slug, "repo disappeared from DB, skipping pin");
            return None;
        }
        Err(e) => {
            tracing::warn!(repo = %repo_slug, err = %e, "repo re-fetch failed, skipping pin");
            return None;
        }
    };
    if !crate::visibility::listable_at_root(&rules, fresh.is_public, &fresh.owner_did, None) {
        tracing::warn!(repo = %repo_slug, "visibility narrowed, skipping pin");
        return None;
    }
    Some((fresh, rules))
}

/// SIGTERM every registered git process group; after `KILL_GRACE_SECS` re-scan
/// the registry and SIGKILL anything still alive. The escalation task is
/// fire-and-forget: a git process that ignores TERM must not be left running.
fn escalate_kill(ctx: &Arc<crate::git::ScanContext>, reason: &str) {
    tracing::warn!(reason, "killing active git subprocesses");
    #[cfg(unix)]
    {
        let pgids: Vec<i32> = ctx
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect();
        for &pgid in &pgids {
            unsafe {
                let _ = libc::kill(-pgid, libc::SIGTERM);
            }
        }
    }

    let ctx = ctx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(KILL_GRACE_SECS)).await;
        #[cfg(unix)]
        {
            let pgids: Vec<i32> = ctx
                .registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .copied()
                .collect();
            for &pgid in &pgids {
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
        }
    });
}

/// Compute the deterministic missing set: `all` minus `done`, sorted so two
/// passes over the same data yield the same pin order. Not capped here — the
/// caller applies the cap and logs a truncation warning.
fn missing_oids(all: &[String], done: &[String]) -> Vec<String> {
    let done_set: HashSet<&str> = done.iter().map(|s| s.as_str()).collect();
    let mut missing: Vec<String> = all
        .iter()
        .filter(|s| !done_set.contains(s.as_str()))
        .cloned()
        .collect();
    missing.sort();
    missing
}

/// Cap a missing set, logging once when it was truncated.
fn cap_missing(v: Vec<String>, repo_slug: &str, backend: &str) -> Vec<String> {
    if v.len() > MAX_OBJECTS_PER_REPO {
        tracing::warn!(
            repo = %repo_slug,
            backend,
            cap = MAX_OBJECTS_PER_REPO,
            "per-repo missing cap reached, truncating"
        );
        let mut v = v;
        v.truncate(MAX_OBJECTS_PER_REPO);
        v
    } else {
        v
    }
}

/// Run one sweep pass. Returns `(repos_scanned, gaps_found, gaps_filled)`.
///
/// `repos_scanned` counts every repo actually visited this pass (mirror rows
/// and hard skips excluded, and the loop stops counting the moment a shutdown
/// signal breaks the batch), so the returned value never overreports work that
/// a mid-pass shutdown prevented (R1-P3).
async fn run_pass(
    db: &Db,
    config: &Config,
    http_client: &reqwest::Client,
    node_seed: &[u8; 32],
    node_did: &gitlawb_core::did::Did,
    cursor: &mut Option<String>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<(usize, usize, usize)> {
    // Keyset pagination over repos ordered by immutable id so the cursor is
    // robust against insertions, deletions, or updated_at shifts.  The LIMIT
    // is pushed into the SQL query so the hourly pass does not allocate,
    // transfer, or deduplicate every repo on every sweep.
    let batch = db
        .list_all_repos_deduped_stable(cursor.as_deref(), REPOS_PER_PASS as i64)
        .await?;

    if batch.is_empty() {
        // Covered everything: clear the persisted cursor so the next pass
        // starts a fresh cycle instead of wedging on a stale key.
        *cursor = None;
        db.set_node_state(CURSOR_KEY, None).await?;
        return Ok((0, 0, 0));
    }

    // Advance the in-memory cursor now so the next page in this run continues
    // after this batch; the PERSISTED cursor is only moved once the batch fully
    // completes below, so an interrupted batch is re-walked on restart.
    let batch_last = batch.last().unwrap().id.clone();
    *cursor = Some(batch_last.clone());

    let mut total_gaps_found = 0usize;
    let mut total_gaps_filled = 0usize;
    let mut repos_scanned = 0usize;
    let mut batch_completed = true;

    for repo in &batch {
        if *shutdown_rx.borrow() {
            tracing::info!("reconciliation sweep: shutdown signal received mid-pass, exiting");
            batch_completed = false;
            break;
        }

        let repo_slug = format!(
            "{}/{}",
            crate::db::normalize_owner_key(&repo.owner_did),
            repo.name
        );

        // Mirror rows carry a slash-form id written only by upsert_mirror_repo;
        // they hardcode is_public = true and replicate no visibility rules, so a
        // sweep over one would irreversibly publish content that the canonical
        // gate never admitted (R2-P1). Skip them — the canonical row (if any)
        // is swept under its own id.
        if repo.id.contains('/') {
            tracing::debug!(repo = %repo_slug, "mirror row (no canonical repo), skipping sweep");
            continue;
        }

        let disk = PathBuf::from(&repo.disk_path);
        if !disk.exists() {
            tracing::warn!(repo = %repo_slug, "disk path missing, skipping");
            continue;
        }

        // Counted only once the repo has a real chance of work: mirror rows and
        // missing-disk rows are hard skips and never count as scanned (R1-P3).
        repos_scanned += 1;

        // Cheap quarantine pre-check BEFORE the expensive git scan (R1-P3):
        // a repo quarantined since admission should not burn a full scan just
        // to be told to skip.
        match db.is_repo_quarantined(&repo.id).await {
            Ok(true) => {
                tracing::warn!(repo = %repo_slug, "repo quarantined, skipping");
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "quarantine check failed, skipping");
                continue;
            }
        }

        let rules = match db.list_visibility_rules(&repo.id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "visibility rules fetch failed, skipping");
                continue;
            }
        };

        if !crate::visibility::listable_at_root(&rules, repo.is_public, &repo.owner_did, None) {
            continue;
        }

        // ── Full git scan (bounded) ─────────────────────────────────────
        let ctx = crate::git::ScanContext::new();
        let ctx_clone = ctx.clone();
        let disk_clone = disk.clone();
        let owner_clone = repo.owner_did.clone();
        let rules_clone = rules.clone();
        let is_public = repo.is_public;

        let object_list = tokio::time::timeout(
            REPO_SCAN_DEADLINE,
            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
                let _guard = crate::git::set_scan_context(ctx_clone.clone());
                let all_objs = crate::git::push_delta::list_all_objects(&disk_clone)?;
                if ctx_clone.canceled.load(Ordering::SeqCst) {
                    return Err(anyhow::anyhow!("scan canceled after list_all_objects"));
                }
                let allowed = crate::git::visibility_pack::replicable_blob_set(
                    &disk_clone,
                    &rules_clone,
                    is_public,
                    &owner_clone,
                )?;
                if ctx_clone.canceled.load(Ordering::SeqCst) {
                    return Err(anyhow::anyhow!("scan canceled after replicable_blob_set"));
                }
                let all_blobs = crate::git::push_delta::all_blob_oids(&disk_clone)?;
                Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
                    all_objs, &allowed, &all_blobs,
                ))
            }),
        )
        .await;

        let object_list: Vec<String> = match object_list {
            Ok(Ok(Ok(list))) => list,
            Ok(Ok(Err(e))) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan failed, skipping");
                continue;
            }
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan task panicked, skipping");
                continue;
            }
            Err(_) => {
                escalate_kill(&ctx, "full-scan deadline exceeded");
                tracing::warn!(repo = %repo_slug, "full-scan deadline exceeded, killed active git subprocesses, skipping");
                continue;
            }
        };

        if object_list.is_empty() {
            continue;
        }

        // ── Phase 1: Public-object pinning (IPFS + Pinata) ────────────────
        // Re-check quarantine AND visibility right now (fresh rules + repo row),
        // then re-derive the allowed set from those fresh rules so a path-scoped
        // narrowing made mid-scan is honored before anything is pinned.
        let (fresh_repo, fresh_rules) = match recheck_public_pin(db, &repo.id, &repo_slug).await {
            Some(v) => v,
            None => continue,
        };

        // Visibility may have narrowed mid-scan with a path-scoped deny.
        // Recompute the allowed set from fresh rules and intersect it with the
        // existing object_list.
        let refiltered = refilter_public_objects(
            &ctx,
            &disk,
            &fresh_rules,
            fresh_repo.is_public,
            &fresh_repo.owner_did,
            object_list,
        )
        .await;
        let Some(object_list) = refiltered else {
            tracing::warn!(repo = %repo_slug, "fresh-visibility re-filter failed, skipping");
            continue;
        };
        if object_list.is_empty() {
            continue;
        }

        let ipfs_enabled = !config.ipfs_api.is_empty();
        let pinata_enabled = !config.pinata_jwt.is_empty();

        // IPFS-missing set.  A filter DB error skips only the IPFS gap-fill and
        // lets the Pinata path still run (R1-P3), instead of dropping the repo.
        let ipfs_missing: Vec<String> = if ipfs_enabled {
            match db.filter_ipfs_pinned_oids(&object_list).await {
                Ok(already) => {
                    cap_missing(missing_oids(&object_list, &already), &repo_slug, "IPFS")
                }
                Err(e) => {
                    tracing::warn!(repo = %repo_slug, err = %e, "filter_ipfs_pinned_oids failed, IPFS gap-fill skipped this pass");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let pinata_missing: Vec<String> = if pinata_enabled {
            match db.filter_pinata_pinned_oids(&object_list).await {
                Ok(already) => {
                    cap_missing(missing_oids(&object_list, &already), &repo_slug, "Pinata")
                }
                Err(e) => {
                    tracing::warn!(repo = %repo_slug, err = %e, "filter_pinata_pinned_oids failed, Pinata gap-fill skipped this pass");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        // Count UNIQUE missing objects across both backends (R1-P3): an object
        // absent from both must not be counted twice.
        let mut gap_union: HashSet<&str> = HashSet::new();
        gap_union.extend(ipfs_missing.iter().map(|s| s.as_str()));
        gap_union.extend(pinata_missing.iter().map(|s| s.as_str()));
        let repo_gaps = gap_union.len();
        if repo_gaps > 0 {
            total_gaps_found += repo_gaps;
            crate::metrics::record_reconciliation_gaps_found(repo_gaps as u64);
        }

        // Re-validate quarantine + visibility IMMEDIATELY before each backend
        // pin (R1-P1): for content-addressed public pins a stale allow is
        // effectively irreversible, and the pin itself takes time.
        let pinned_ipfs: Vec<(String, String)> = if ipfs_enabled && !ipfs_missing.is_empty() {
            if recheck_public_pin(db, &repo.id, &repo_slug).await.is_none() {
                Vec::new()
            } else {
                match tokio::time::timeout(
                    PIN_PHASE_DEADLINE,
                    crate::ipfs_pin::pin_new_objects(&config.ipfs_api, &disk, ipfs_missing, db),
                )
                .await
                {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::warn!(repo = %repo_slug, "IPFS pin phase timed out after {:?}", PIN_PHASE_DEADLINE);
                        Vec::new()
                    }
                }
            }
        } else {
            Vec::new()
        };

        let pinned_pinata: Vec<(String, String)> = if pinata_enabled && !pinata_missing.is_empty() {
            if recheck_public_pin(db, &repo.id, &repo_slug).await.is_none() {
                Vec::new()
            } else {
                match tokio::time::timeout(
                    PIN_PHASE_DEADLINE,
                    crate::pinata::pin_new_objects(
                        http_client,
                        &config.pinata_upload_url,
                        &config.pinata_jwt,
                        &disk,
                        pinata_missing,
                        db,
                    ),
                )
                .await
                {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::warn!(repo = %repo_slug, "Pinata pin phase timed out after {:?}", PIN_PHASE_DEADLINE);
                        Vec::new()
                    }
                }
            }
        } else {
            Vec::new()
        };

        // `pin_new_objects` returns only objects whose DB record was written
        // (R1-P3), so a backend that uploaded bytes but failed to persist is
        // not counted as "filled".
        let repo_filled = pinned_ipfs.len() + pinned_pinata.len();
        if repo_filled > 0 {
            total_gaps_filled += repo_filled;
            crate::metrics::record_reconciliation_gaps_filled(repo_filled as u64);

            tracing::info!(
                repo = %repo_slug,
                ipfs = pinned_ipfs.len(),
                pinata = pinned_pinata.len(),
                total = repo_filled,
                "reconciliation sweep filled public-object gaps"
            );
        }

        // ── Phase 2: Encrypted recovery-copy resealing (withheld blobs) ──

        // Recheck quarantine AND root visibility before encrypted pinning, using
        // FRESH repo identity (R1-P2): the batch snapshot may predate a narrow.
        let (fresh_repo2, fresh_rules2) = match recheck_public_pin(db, &repo.id, &repo_slug).await {
            Some(v) => v,
            None => continue,
        };

        let has_path_scoped = crate::git::visibility_pack::has_path_scoped_rule(&fresh_rules2);
        if has_path_scoped && ipfs_enabled {
            let ctx2 = crate::git::ScanContext::new();
            let ctx2_clone = ctx2.clone();
            let p = disk.clone();
            let owner = fresh_repo2.owner_did.clone();
            let r = fresh_rules2.clone();
            let is_public_2 = fresh_repo2.is_public;
            let recipients = tokio::time::timeout(
                REPO_SCAN_DEADLINE,
                tokio::task::spawn_blocking(move || {
                    let _guard = crate::git::set_scan_context(ctx2_clone);
                    crate::git::visibility_pack::withheld_blob_recipients(
                        &p,
                        &r,
                        is_public_2,
                        &owner,
                    )
                }),
            )
            .await;

            let rec = match recipients {
                Ok(Ok(Ok(rec))) => rec,
                Ok(Ok(Err(e))) => {
                    tracing::warn!(
                        repo = %repo_slug, err = %e,
                        "withheld_blob_recipients failed, skipping encrypted pin"
                    );
                    continue;
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        repo = %repo_slug, err = %e,
                        "withheld_blob_recipients task panicked, skipping encrypted pin"
                    );
                    continue;
                }
                Err(_) => {
                    escalate_kill(&ctx2, "encrypted recovery deadline exceeded");
                    tracing::warn!(
                        repo = %repo_slug,
                        "encrypted recovery deadline exceeded, killed active git subprocesses, skipping"
                    );
                    continue;
                }
            };

            if !rec.is_empty() {
                // Bound the seal+pin work (R1-P2): an unavailable backend must
                // not hold the sweep past the pin-phase budget.
                let sealed = tokio::time::timeout(
                    PIN_PHASE_DEADLINE,
                    crate::encrypted_pin::encrypt_and_pin(
                        &config.ipfs_api,
                        &disk,
                        db,
                        &repo.id,
                        node_seed,
                        &rec,
                    ),
                )
                .await;

                let sealed: Vec<(String, String)> = match sealed {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::warn!(
                            repo = %repo_slug,
                            "encrypted pin phase timed out after {:?}",
                            PIN_PHASE_DEADLINE
                        );
                        Vec::new()
                    }
                };

                // Anchor only when something was newly sealed this pass.
                // This avoids unbounded Irys writes on a timer — repos
                // with no withheld changes do not re-anchor the manifest.
                if !sealed.is_empty() && !config.irys_url.is_empty() {
                    let owner_short = crate::db::normalize_owner_key(&repo.owner_did);
                    let slug = format!("{}/{}", owner_short, repo.name);
                    let ts = chrono::Utc::now().to_rfc3339();
                    let node_did_str = node_did.to_string();

                    let manifest = crate::arweave::EncryptedManifest {
                        repo: &slug,
                        owner_did: &repo.owner_did,
                        node_did: &node_did_str,
                        timestamp: &ts,
                        blobs: &sealed,
                    };
                    if let Err(e) = crate::arweave::anchor_encrypted_manifest(
                        http_client,
                        &config.irys_url,
                        &manifest,
                    )
                    .await
                    {
                        tracing::warn!(
                            repo = %slug,
                            err = %e,
                            "encrypted manifest anchor failed (will retry next pass)"
                        );
                    }
                }
            }
        }
    }

    // Persist the cursor only when the WHOLE batch completed. If shutdown
    // interrupted us, leave the persisted cursor at the previous batch's end so
    // the next run re-walks the unprocessed tail (R2-P1, R1-P3).
    if batch_completed {
        if let Err(e) = db.set_node_state(CURSOR_KEY, Some(&batch_last)).await {
            tracing::warn!(err = %e, "failed to persist reconciliation sweep cursor");
        }
    }

    Ok((repos_scanned, total_gaps_found, total_gaps_filled))
}

#[cfg(test)]
mod tests {
    use tokio::sync::watch;

    /// Build a minimal Config with both IPFS and Pinata fields empty so the
    /// spawn() gate fires and the function returns without touching the DB.
    fn empty_pin_config() -> std::sync::Arc<crate::config::Config> {
        // Config derives clap::Parser; supply only argv[0] (the program name)
        // so all fields get their defaults (ipfs_api = "", pinata_jwt = "").
        let cfg = <crate::config::Config as clap::Parser>::parse_from(["gitlawb-node-test"]);
        std::sync::Arc::new(cfg)
    }

    /// Build a config with IPFS API set so the gate fires the other way.
    fn ipfs_config() -> std::sync::Arc<crate::config::Config> {
        let cfg = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            "http://127.0.0.1:5001",
        ]);
        std::sync::Arc::new(cfg)
    }

    #[test]
    fn should_spawn_false_when_both_empty() {
        let cfg = empty_pin_config();
        assert!(!super::should_spawn(&cfg));
    }

    #[test]
    fn should_spawn_true_when_ipfs_set() {
        let cfg = ipfs_config();
        assert!(super::should_spawn(&cfg));
    }

    #[test]
    fn should_spawn_true_when_pinata_set() {
        let cfg = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--pinata-jwt",
            "test-jwt",
        ]);
        assert!(super::should_spawn(&cfg));
    }

    #[test]
    fn should_spawn_false_when_sweep_disabled() {
        let cfg = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            "http://127.0.0.1:5001",
            "--reconciliation-sweep",
            "false",
        ]);
        assert!(!super::should_spawn(&cfg));
    }

    /// spawn() must return `false` (and not spawn a task, touch the DB, or
    /// panic) when neither IPFS nor Pinata is configured. This proves the gate
    /// branch at the top of spawn() is actually reachable and observable.
    #[tokio::test]
    async fn test_spawn_gate_skips_when_no_pin_backends_configured() {
        let config = empty_pin_config();
        assert!(config.ipfs_api.is_empty(), "ipfs_api should be empty");
        assert!(config.pinata_jwt.is_empty(), "pinata_jwt should be empty");

        // Use a dummy Db built from a disconnected pool; spawn() must not
        // reach any code that would touch it.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgresql://localhost/gitlawb_test_nonexistent")
            .unwrap();
        let db = std::sync::Arc::new(crate::db::Db::for_testing(pool));
        let http = std::sync::Arc::new(reqwest::Client::new());
        let kp = std::sync::Arc::new(gitlawb_core::identity::Keypair::generate());
        let node_did = kp.did();
        let (_tx, rx) = watch::channel(false);

        // spawn() should return false synchronously (no tokio::spawn) and never
        // await the DB.  The test completes without timeout == gate is live.
        assert!(
            !super::spawn(db, config, http, kp, node_did, rx),
            "gated spawn must report it did not start a worker"
        );
    }

    /// spawn() returns true and starts a worker when a backend is configured;
    /// the caller uses that to gate its own "worker started" logging.
    #[tokio::test]
    async fn test_spawn_returns_true_when_ipfs_configured() {
        let config = ipfs_config();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgresql://localhost/gitlawb_test_nonexistent")
            .unwrap();
        let db = std::sync::Arc::new(crate::db::Db::for_testing(pool));
        let http = std::sync::Arc::new(reqwest::Client::new());
        let kp = std::sync::Arc::new(gitlawb_core::identity::Keypair::generate());
        let node_did = kp.did();
        let (_tx, rx) = watch::channel(false);

        assert!(
            super::spawn(db, config, http, kp, node_did, rx),
            "configured spawn must report it started a worker"
        );
    }

    /// The missing set must be deterministic, which is what makes the sweep's
    /// per-repo pin order reproducible across passes. The cap is applied by
    /// `cap_missing` at the call site, so `missing_oids` stays uncapped.
    #[test]
    fn missing_oids_is_deterministic() {
        let all = vec![
            "c".to_string(),
            "a".to_string(),
            "b".to_string(),
            "d".to_string(),
        ];
        let done = vec!["b".to_string()];

        let first = super::missing_oids(&all, &done);
        let second = super::missing_oids(&all, &done);
        assert_eq!(first, second, "missing set must be deterministic");
        assert_eq!(
            first,
            vec!["a".to_string(), "c".to_string(), "d".to_string()]
        );
    }

    /// Constant smoke-check kept as a compile-time tripwire.
    #[test]
    fn sweep_interval_constant_is_nonzero() {
        assert_ne!(super::SWEEP_INTERVAL_SECS, 0);
    }

    // ── run_pass integration tests ────────────────────────────────────────

    /// Minimal git repo builder (mirrors push_delta's test helper).
    struct Repo {
        _td: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    impl Repo {
        fn new() -> Self {
            let td = tempfile::TempDir::new().unwrap();
            let path = td.path().to_path_buf();
            let r = Repo { _td: td, path };
            r.git(&["init", "-q", "-b", "main"]);
            r.git(&["config", "user.email", "t@t"]);
            r.git(&["config", "user.name", "t"]);
            r
        }

        fn git(&self, args: &[&str]) -> String {
            let out = std::process::Command::new("git")
                .args(args)
                .current_dir(&self.path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        fn commit_file(&self, name: &str, body: &str) -> String {
            std::fs::write(self.path.join(name), body).unwrap();
            self.git(&["add", name]);
            self.git(&["commit", "-qm", &format!("add {name}")]);
            self.git(&["rev-parse", "HEAD"])
        }
    }

    fn seed_repo(owner: &str, name: &str, disk_path: &str) -> crate::db::RepoRecord {
        let now = chrono::Utc::now();
        crate::db::RepoRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            owner_did: owner.to_string(),
            description: None,
            is_public: true,
            default_branch: "main".to_string(),
            created_at: now,
            updated_at: now,
            disk_path: disk_path.to_string(),
            forked_from: None,
            machine_id: None,
        }
    }

    /// The sweep must repair an IPFS durability gap end to end: a public repo
    /// whose objects were never pinned gets every reachable blob pinned and
    /// recorded (R2-P2 "test the behavior the PR exists to change").
    #[sqlx::test]
    async fn sweep_fills_ipfs_gap_and_persists_cursor(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("a.txt", "public blob\n");

        let rec = seed_repo(
            "did:key:zSweepOwner",
            "sweep-repo",
            &repo_on_disk.path.display().to_string(),
        );
        db.create_repo(&rec).await.unwrap();

        // Mock IPFS: every /api/v0/add returns a fixed CID. mockito's unified
        // matcher compares the full "path?query" target, so the query string
        // pin_git_object appends must be part of the mock path.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("POST", "/api/v0/add?cid-version=1&raw-leaves=true&pin=true")
            .expect_at_least(1)
            .with_status(200)
            .with_body(r#"{"Hash":"QmSweepMockCid"}"#)
            .create_async()
            .await;

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            &server.url(),
        ]);

        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(scanned, 1, "one repo scanned");
        assert!(gaps >= 1, "at least one missing blob found");
        assert_eq!(
            filled, gaps,
            "every found gap is filled in a clean mock-backed run"
        );
        _m.assert_async().await;

        // The recorded pin makes the blob "already done" on the next pass.
        let blob = repo_on_disk.git(&["rev-parse", "HEAD:a.txt"]);
        assert!(
            db.has_ipfs_cid(&blob).await.unwrap(),
            "pinned CID must be recorded and classified as IPFS-pinned"
        );

        // Cursor persisted in node_state so a restart resumes, not re-walks.
        let persisted = db
            .get_node_state(super::CURSOR_KEY)
            .await
            .unwrap()
            .expect("cursor must be persisted after a completed batch");
        assert_eq!(persisted, rec.id, "cursor equals the last batch repo id");

        // Second pass: no gaps remain.
        let (_, gaps2, filled2) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();
        assert_eq!(gaps2, 0, "second pass finds no remaining gaps");
        assert_eq!(filled2, 0);
    }

    /// Mirror rows (slash-form id, hardcoded is_public=true, no replicated
    /// visibility rules) must be skipped entirely: sweeping one would
    /// irreversibly publish content the canonical gate never admitted (R2-P1).
    #[sqlx::test]
    async fn sweep_skips_mirror_rows(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let repo_on_disk = Repo::new();
        repo_on_disk.commit_file("secret.txt", "must not be published\n");

        // A mirror row pointing at a real, public-on-disk repo.
        db.upsert_mirror_repo(
            "zMirrorOwner",
            "mirror-repo",
            &repo_on_disk.path.display().to_string(),
            None,
            false,
        )
        .await
        .unwrap();

        let config = <crate::config::Config as clap::Parser>::parse_from([
            "gitlawb-node-test",
            "--ipfs-api",
            "http://127.0.0.1:1", // unreachable; must never be hit
        ]);
        let kp = gitlawb_core::identity::Keypair::generate();
        let node_did = kp.did();
        let node_seed = *kp.to_seed();
        let http = reqwest::Client::new();
        let (_tx, mut rx) = watch::channel(false);
        let mut cursor = None;

        let (scanned, gaps, filled) = super::run_pass(
            &db,
            &config,
            &http,
            &node_seed,
            &node_did,
            &mut cursor,
            &mut rx,
        )
        .await
        .unwrap();

        assert_eq!(scanned, 0, "mirror row is not scanned");
        assert_eq!(gaps, 0, "mirror row produces no gaps");
        assert_eq!(filled, 0, "mirror row is never pinned");

        // Nothing was recorded for the mirror's content.
        assert!(
            db.list_pinned_cids().await.unwrap().is_empty(),
            "no pinned_cids rows may exist after a mirror-only pass"
        );
    }
}
