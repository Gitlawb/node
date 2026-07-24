use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

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

/// Spawn the periodic reconciliation sweep background task.
pub fn spawn(
    db: Arc<Db>,
    config: Arc<Config>,
    http_client: Arc<reqwest::Client>,
    node_keypair: Arc<gitlawb_core::identity::Keypair>,
    node_did: gitlawb_core::did::Did,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let node_seed = *node_keypair.to_seed();
        let mut cursor = 0usize;

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

            // Check shutdown before sleeping.
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
    cursor: &mut usize,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> anyhow::Result<(usize, usize, usize)> {
    let all = db.list_all_repos_deduped().await?;

    if all.is_empty() {
        *cursor = 0;
        return Ok((0, 0, 0));
    }

    // Clamp the cursor so a shrinking eligible set never panics.
    let start = (*cursor).min(all.len());
    let end = (start + REPOS_PER_PASS).min(all.len());
    let batch = &all[start..end];
    *cursor = if end >= all.len() { 0 } else { end };

    let mut total_gaps_found = 0usize;
    let mut total_gaps_filled = 0usize;

    for repo in batch {
        // Cooperative shutdown: exit between repos if signal received.
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

        let disk_clone = disk.clone();
        let owner_clone = repo.owner_did.clone();
        let rules_clone = rules.clone();
        let is_public = repo.is_public;
        let object_list = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
            let all_objs = crate::git::push_delta::list_all_objects(&disk_clone)?;
            let allowed = crate::git::visibility_pack::replicable_blob_set(
                &disk_clone,
                &rules_clone,
                is_public,
                &owner_clone,
            )?;
            let all_blobs = crate::git::push_delta::all_blob_oids(&disk_clone)?;
            Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
                all_objs, &allowed, &all_blobs,
            ))
        })
        .await;

        let object_list = match object_list {
            Ok(Ok(list)) => list,
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan failed, skipping");
                continue;
            }
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan task panicked, skipping");
                continue;
            }
        };

        if object_list.is_empty() {
            continue;
        }

        // Pre-cap the object list before batch-filtering to keep queries bounded.
        let candidates: Vec<String> = if object_list.len() > MAX_OBJECTS_PER_REPO {
            tracing::warn!(
                repo = %repo_slug,
                cap = MAX_OBJECTS_PER_REPO,
                total = object_list.len(),
                "reconciliation per-repo candidate list truncated to cap"
            );
            object_list.into_iter().take(MAX_OBJECTS_PER_REPO).collect()
        } else {
            object_list
        };

        // ── Phase 1: Public-object pinning (IPFS + Pinata) ────────────────
        // Each backend independently tracks its own completion state, so we
        // compute the actually-missing set per backend and cap independently.

        // Recheck quarantine before attempting any external pinning.
        match db.is_repo_quarantined(&repo.id).await {
            Ok(true) => {
                tracing::warn!(repo = %repo_slug, "repo quarantined, skipping public-object pinning");
                // Phase 2 (encrypted) is also skipped — a quarantined repo's
                // withheld blobs should not be published either.
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "quarantine check failed, skipping");
                continue;
            }
        }

        // Compute IPFS-missing set, capped per-repo.
        let already_ipfs = db.filter_ipfs_pinned_oids(&candidates).await?;
        let ipfs_missing_set: HashSet<&str> = candidates
            .iter()
            .map(|s| s.as_str())
            .collect::<HashSet<_>>()
            .difference(&already_ipfs.iter().map(|s| s.as_str()).collect())
            .copied()
            .collect();
        let mut ipfs_candidates: Vec<String> =
            ipfs_missing_set.into_iter().map(String::from).collect();
        if ipfs_candidates.len() > MAX_OBJECTS_PER_REPO {
            ipfs_candidates.truncate(MAX_OBJECTS_PER_REPO);
            tracing::warn!(
                repo = %repo_slug,
                cap = MAX_OBJECTS_PER_REPO,
                "IPFS per-repo missing cap reached, truncating"
            );
        }

        // Compute Pinata-missing set, capped per-repo.
        let already_pinata = db.filter_pinata_pinned_oids(&candidates).await?;
        let pinata_missing_set: HashSet<&str> = candidates
            .iter()
            .map(|s| s.as_str())
            .collect::<HashSet<_>>()
            .difference(&already_pinata.iter().map(|s| s.as_str()).collect())
            .copied()
            .collect();
        let mut pinata_candidates: Vec<String> =
            pinata_missing_set.into_iter().map(String::from).collect();
        if pinata_candidates.len() > MAX_OBJECTS_PER_REPO {
            pinata_candidates.truncate(MAX_OBJECTS_PER_REPO);
            tracing::warn!(
                repo = %repo_slug,
                cap = MAX_OBJECTS_PER_REPO,
                "Pinata per-repo missing cap reached, truncating"
            );
        }

        let pinned_ipfs =
            crate::ipfs_pin::pin_new_objects(&config.ipfs_api, &disk, ipfs_candidates, db).await;

        let pinned_pinata = crate::pinata::pin_new_objects(
            http_client,
            &config.pinata_upload_url,
            &config.pinata_jwt,
            &disk,
            pinata_candidates,
            db,
        )
        .await;

        let repo_filled = pinned_ipfs.len() + pinned_pinata.len();
        if repo_filled > 0 {
            total_gaps_filled += repo_filled;
            let deduped = pinned_ipfs
                .iter()
                .chain(&pinned_pinata)
                .collect::<HashSet<_>>()
                .len();
            total_gaps_found += deduped;
            crate::metrics::record_reconciliation_gaps_found(deduped as u64);
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
        // Only relevant when path-scoped visibility rules exist — without them
        // no blobs are withheld and withheld_blob_recipients returns empty.

        // Recheck quarantine before encrypted pinning.
        let quarantined = match db.is_repo_quarantined(&repo.id).await {
            Ok(q) => q,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "quarantine recheck failed, skipping encrypted pin");
                continue;
            }
        };
        if quarantined {
            tracing::warn!(repo = %repo_slug, "repo quarantined, skipping encrypted pinning");
            continue;
        }

        let has_path_scoped = crate::git::visibility_pack::has_path_scoped_rule(&rules);
        if has_path_scoped && !config.ipfs_api.is_empty() {
            let p = disk.clone();
            let owner = repo.owner_did.clone();
            let r = rules.clone();
            let is_public_2 = repo.is_public;
            let recipients = tokio::task::spawn_blocking(move || {
                crate::git::visibility_pack::withheld_blob_recipients(&p, &r, is_public_2, &owner)
            })
            .await;

            match recipients {
                Ok(Ok(rec)) if !rec.is_empty() => {
                    let sealed = crate::encrypted_pin::encrypt_and_pin(
                        &config.ipfs_api,
                        &disk,
                        db,
                        &repo.id,
                        node_seed,
                        &rec,
                    )
                    .await;

                    // Anchor ALL existing encrypted blobs for this repo, not
                    // just the ones encrypted this pass.  This ensures that if
                    // a prior manifest anchor failed the retry will include
                    // previously-encrypted blobs too.
                    let all_existing = db.list_all_encrypted_blobs(&repo.id).await?;
                    if !all_existing.is_empty() && !config.irys_url.is_empty() {
                        let owner_short = crate::db::normalize_owner_key(&repo.owner_did);
                        let slug = format!("{}/{}", owner_short, repo.name);
                        let ts = chrono::Utc::now().to_rfc3339();
                        let node_did_str = node_did.to_string();

                        // Merge existing blobs with freshly-sealed ones,
                        // preferring later entries (newly-sealed) on conflict.
                        let mut blob_map: HashMap<String, String> = HashMap::new();
                        for (oid, cid) in &all_existing {
                            blob_map.insert(oid.clone(), cid.clone());
                        }
                        for (oid, cid) in &sealed {
                            blob_map.insert(oid.clone(), cid.clone());
                        }
                        let merged: Vec<(String, String)> = blob_map.into_iter().collect();

                        let manifest = crate::arweave::EncryptedManifest {
                            repo: &slug,
                            owner_did: &repo.owner_did,
                            node_did: &node_did_str,
                            timestamp: &ts,
                            blobs: &merged,
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
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::warn!(
                        repo = %repo_slug,
                        err = %e,
                        "withheld_blob_recipients failed, skipping encrypted pin"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        repo = %repo_slug,
                        err = %e,
                        "withheld_blob_recipients task panicked, skipping encrypted pin"
                    );
                }
            }
        }
    }

    Ok((batch.len(), total_gaps_found, total_gaps_filled))
}
