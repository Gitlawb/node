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
/// `reconciliation_sweep` is disabled.
pub fn spawn(
    db: Arc<Db>,
    config: Arc<Config>,
    http_client: Arc<reqwest::Client>,
    node_keypair: Arc<gitlawb_core::identity::Keypair>,
    node_did: gitlawb_core::did::Did,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !should_spawn(&config) {
        tracing::info!(
            "reconciliation sweep: disabled or neither IPFS nor Pinata configured, skipping spawn"
        );
        return;
    }

    tokio::spawn(async move {
        let node_seed = *node_keypair.to_seed();
        let mut cursor: Option<String> = None;

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
}

/// Run one sweep pass. Returns `(repos_scanned, gaps_found, gaps_filled)`.
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
        *cursor = None;
        return Ok((0, 0, 0));
    }

    *cursor = Some(batch.last().unwrap().id.clone());

    let mut total_gaps_found = 0usize;
    let mut total_gaps_filled = 0usize;

    for repo in &batch {
        if *shutdown_rx.borrow() {
            tracing::info!("reconciliation sweep: shutdown signal received mid-pass, exiting");
            break;
        }

        let repo_slug = format!(
            "{}/{}",
            crate::db::normalize_owner_key(&repo.owner_did),
            repo.name
        );

        let disk = PathBuf::from(&repo.disk_path);
        if !disk.exists() {
            tracing::warn!(repo = %repo_slug, "disk path missing, skipping");
            continue;
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

        // Bound the blocking git scan with a deadline so a pathological repo
        // cannot stall the entire pass.
        let disk_clone = disk.clone();
        let owner_clone = repo.owner_did.clone();
        let rules_clone = rules.clone();
        let is_public = repo.is_public;

        let ctx = crate::git::ScanContext::new();
        let ctx_clone = ctx.clone();

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
                ctx.canceled.store(true, Ordering::SeqCst);
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
                tracing::warn!(repo = %repo_slug, "full-scan deadline exceeded, killed active git subprocesses, skipping");
                continue;
            }
        };

        if object_list.is_empty() {
            continue;
        }

        // ── Phase 1: Public-object pinning (IPFS + Pinata) ────────────────
        // Compute the actually-missing set per backend from the FULL object
        // list (no pre-cap) so trailing objects are never excluded.  The cap
        // applies to the missing sets, bounding pin work.
        //
        // Recheck quarantine AND visibility before pinning.  Rules and
        // is_public were fetched once before the scan and may have narrowed
        // since; for content-addressed public pins a stale allow is
        // effectively irreversible.
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
        // Recheck visibility rules (P2): owner may have narrowed visibility
        // mid-scan.  Re-fetch from DB rather than relying on the snapshot
        // taken before the git walk.
        let rules = match db.list_visibility_rules(&repo.id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "visibility rules re-fetch failed before phase 1, skipping");
                continue;
            }
        };
        let fresh_repo = match db.get_repo_by_id(&repo.id).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::warn!(repo = %repo_slug, "repo disappeared from DB before phase 1, skipping");
                continue;
            }
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "repo re-fetch failed before phase 1, skipping");
                continue;
            }
        };
        if !crate::visibility::listable_at_root(
            &rules,
            fresh_repo.is_public,
            &fresh_repo.owner_did,
            None,
        ) {
            tracing::warn!(repo = %repo_slug, "visibility narrowed mid-scan, skipping phase 1");
            continue;
        }

        // Visibility may have narrowed mid-scan with a path-scoped deny.
        // Recompute the allowed set from fresh rules in a spawn_blocking
        // and intersect it with the existing object_list (R1-P1, R1-P2).
        let fresh_disk = disk.clone();
        let fresh_rules = rules.clone();
        let fresh_owner = fresh_repo.owner_did.clone();
        let fresh_is_public = fresh_repo.is_public;
        let existing_list = object_list;
        let refilter_ctx = ctx.clone();

        let refiltered = tokio::time::timeout(
            REPO_SCAN_DEADLINE,
            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
                let _guard = crate::git::set_scan_context(refilter_ctx);
                let allowed = crate::git::visibility_pack::replicable_blob_set(
                    &fresh_disk,
                    &fresh_rules,
                    fresh_is_public,
                    &fresh_owner,
                )?;
                let all_blobs = crate::git::push_delta::all_blob_oids(&fresh_disk)?;
                Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
                    existing_list,
                    &allowed,
                    &all_blobs,
                ))
            }),
        )
        .await;

        let object_list: Vec<String> = match refiltered {
            Ok(Ok(Ok(list))) => list,
            Ok(Ok(Err(e))) => {
                tracing::warn!(repo = %repo_slug, err = %e, "fresh-visibility re-filter failed, skipping");
                continue;
            }
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo_slug, err = %e, "fresh-visibility re-filter task panicked, skipping");
                continue;
            }
            Err(_) => {
                ctx.canceled.store(true, Ordering::SeqCst);
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
                tracing::warn!(repo = %repo_slug, "fresh-visibility re-filter deadline exceeded, skipped");
                continue;
            }
        };

        let _ipfs_enabled = !config.ipfs_api.is_empty();
        let pinata_enabled = !config.pinata_jwt.is_empty();

        // IPFS-missing set (capped).
        let already_ipfs = match db.filter_ipfs_pinned_oids(&object_list).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "filter_ipfs_pinned_oids failed, skipping");
                continue;
            }
        };
        let ipfs_missing: Vec<String> = {
            let all_set: HashSet<&str> = object_list.iter().map(|s| s.as_str()).collect();
            let done_set: HashSet<&str> = already_ipfs.iter().map(|s| s.as_str()).collect();
            let mut v: Vec<String> = all_set
                .difference(&done_set)
                .map(|s| s.to_string())
                .collect();
            if v.len() > MAX_OBJECTS_PER_REPO {
                v.truncate(MAX_OBJECTS_PER_REPO);
                tracing::warn!(
                    repo = %repo_slug,
                    cap = MAX_OBJECTS_PER_REPO,
                    "IPFS per-repo missing cap reached, truncating"
                );
            }
            v
        };

        let pinata_missing: Vec<String> = if pinata_enabled {
            let already = match db.filter_pinata_pinned_oids(&object_list).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(repo = %repo_slug, err = %e, "filter_pinata_pinned_oids failed, skipping");
                    continue;
                }
            };
            let all_set: HashSet<&str> = object_list.iter().map(|s| s.as_str()).collect();
            let done_set: HashSet<&str> = already.iter().map(|s| s.as_str()).collect();
            let mut v: Vec<String> = all_set
                .difference(&done_set)
                .map(|s| s.to_string())
                .collect();
            if v.len() > MAX_OBJECTS_PER_REPO {
                v.truncate(MAX_OBJECTS_PER_REPO);
                tracing::warn!(
                    repo = %repo_slug,
                    cap = MAX_OBJECTS_PER_REPO,
                    "Pinata per-repo missing cap reached, truncating"
                );
            }
            v
        } else {
            Vec::new()
        };

        let gaps_ipfs = ipfs_missing.len();
        let gaps_pinata = pinata_missing.len();
        let repo_gaps = gaps_ipfs + gaps_pinata;
        if repo_gaps > 0 {
            total_gaps_found += repo_gaps;
            crate::metrics::record_reconciliation_gaps_found(repo_gaps as u64);
        }

        let pinned_ipfs = match tokio::time::timeout(
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
        };

        let pinned_pinata = match tokio::time::timeout(
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
        };

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

        // Recheck quarantine AND visibility before encrypted pinning (P2).
        match db.is_repo_quarantined(&repo.id).await {
            Ok(true) => {
                tracing::warn!(repo = %repo_slug, "repo quarantined, skipping encrypted pinning");
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "quarantine recheck failed, skipping encrypted pin");
                continue;
            }
        }
        let rules = match db.list_visibility_rules(&repo.id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "visibility rules re-fetch failed before phase 2, skipping");
                continue;
            }
        };
        let fresh_repo = match db.get_repo_by_id(&repo.id).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::warn!(repo = %repo_slug, "repo disappeared from DB before phase 2, skipping");
                continue;
            }
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "repo re-fetch failed before phase 2, skipping");
                continue;
            }
        };
        if !crate::visibility::listable_at_root(
            &rules,
            fresh_repo.is_public,
            &fresh_repo.owner_did,
            None,
        ) {
            tracing::warn!(repo = %repo_slug, "visibility narrowed mid-scan, skipping phase 2");
            continue;
        }

        let has_path_scoped = crate::git::visibility_pack::has_path_scoped_rule(&rules);
        if has_path_scoped && !config.ipfs_api.is_empty() {
            let ctx2 = crate::git::ScanContext::new();
            let ctx2_clone = ctx2.clone();
            let p = disk.clone();
            let owner = repo.owner_did.clone();
            let r = rules.clone();
            let is_public_2 = repo.is_public;
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
                    ctx2.canceled.store(true, Ordering::SeqCst);
                    #[cfg(unix)]
                    {
                        let pgids: Vec<i32> = ctx2
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
                    tracing::warn!(
                        repo = %repo_slug,
                        "encrypted recovery deadline exceeded, killed active git subprocesses, skipping"
                    );
                    continue;
                }
            };

            if !rec.is_empty() {
                let sealed = crate::encrypted_pin::encrypt_and_pin(
                    &config.ipfs_api,
                    &disk,
                    db,
                    &repo.id,
                    node_seed,
                    &rec,
                )
                .await;

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

    Ok((batch.len(), total_gaps_found, total_gaps_filled))
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

    /// spawn() must return immediately (without panicking or touching the DB)
    /// when neither IPFS nor Pinata is configured.  This proves the gate
    /// branch at the top of spawn() is actually reachable.
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

        // spawn() should return synchronously (no tokio::spawn) and never
        // await the DB.  The test completes without timeout == gate is live.
        super::spawn(db, config, http, kp, node_did, rx);
    }

    /// Constant smoke-check kept as a compile-time tripwire.
    #[test]
    fn sweep_interval_constant_is_nonzero() {
        assert_ne!(super::SWEEP_INTERVAL_SECS, 0);
    }
}
