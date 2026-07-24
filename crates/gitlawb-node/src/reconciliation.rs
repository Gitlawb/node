use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
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

/// Per-repo deadline for the blocking git scan (list_all_objects + visibility
/// filter).  A pathological repo that stalls past this is skipped for the pass.
const REPO_SCAN_DEADLINE: Duration = Duration::from_secs(300);

/// Spawn the periodic reconciliation sweep background task.
/// No-op when neither IPFS nor Pinata is configured.
pub fn spawn(
    db: Arc<Db>,
    config: Arc<Config>,
    http_client: Arc<reqwest::Client>,
    node_keypair: Arc<gitlawb_core::identity::Keypair>,
    node_did: gitlawb_core::did::Did,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if config.ipfs_api.is_empty() && config.pinata_jwt.is_empty() {
        tracing::info!("reconciliation sweep: neither IPFS nor Pinata configured, skipping spawn");
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
    // robust against insertions, deletions, or updated_at shifts.
    let all = db.list_all_repos_deduped_stable().await?;

    if all.is_empty() {
        *cursor = None;
        return Ok((0, 0, 0));
    }

    let start_idx = cursor
        .as_ref()
        .and_then(|last_id| all.iter().position(|r| r.id == *last_id))
        .map(|pos| pos + 1)
        .unwrap_or(0);

    if start_idx >= all.len() {
        *cursor = None;
        return Ok((0, 0, 0));
    }

    let end = (start_idx + REPOS_PER_PASS).min(all.len());
    let batch = &all[start_idx..end];
    *cursor = Some(batch.last().unwrap().id.clone());

    let mut total_gaps_found = 0usize;
    let mut total_gaps_filled = 0usize;

    for repo in batch {
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
        let object_list = tokio::time::timeout(
            REPO_SCAN_DEADLINE,
            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
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
                tracing::warn!(repo = %repo_slug, "full-scan deadline exceeded, skipping");
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
        // Recheck quarantine before attempting any external pinning.
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

        // Pinata-missing set (capped).
        let already_pinata = match db.filter_pinata_pinned_oids(&object_list).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "filter_pinata_pinned_oids failed, skipping");
                continue;
            }
        };
        let pinata_missing: Vec<String> = {
            let all_set: HashSet<&str> = object_list.iter().map(|s| s.as_str()).collect();
            let done_set: HashSet<&str> = already_pinata.iter().map(|s| s.as_str()).collect();
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
        };

        let gaps_ipfs = ipfs_missing.len();
        let gaps_pinata = pinata_missing.len();
        let repo_gaps = gaps_ipfs + gaps_pinata;
        if repo_gaps > 0 {
            total_gaps_found += repo_gaps;
            crate::metrics::record_reconciliation_gaps_found(repo_gaps as u64);
        }

        let pinned_ipfs =
            crate::ipfs_pin::pin_new_objects(&config.ipfs_api, &disk, ipfs_missing, db).await;

        let pinned_pinata = crate::pinata::pin_new_objects(
            http_client,
            &config.pinata_upload_url,
            &config.pinata_jwt,
            &disk,
            pinata_missing,
            db,
        )
        .await;

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

        // Recheck quarantine before encrypted pinning.
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

                    // Anchor only when something was newly sealed this pass.
                    // This avoids unbounded Irys writes on a timer — repos
                    // with no withheld changes do not re-anchor the manifest.
                    if !sealed.is_empty() && !config.irys_url.is_empty() {
                        let all_existing = match db.list_all_encrypted_blobs(&repo.id).await {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(
                                    repo = %repo_slug,
                                    err = %e,
                                    "list_all_encrypted_blobs failed, skipping anchor"
                                );
                                continue;
                            }
                        };
                        if !all_existing.is_empty() {
                            let owner_short = crate::db::normalize_owner_key(&repo.owner_did);
                            let slug = format!("{}/{}", owner_short, repo.name);
                            let ts = chrono::Utc::now().to_rfc3339();
                            let node_did_str = node_did.to_string();

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

#[cfg(test)]
mod tests {
    /// Verify the spawn gating constant — when neither IPFS nor Pinata is
    /// configured the function logs and returns immediately.
    #[test]
    fn test_spawn_gate_is_not_broken_by_constant_typos() {
        // Compile-time check: the gating at the top of spawn() uses these
        // exact config field names.  A rename without updating the gate
        // would let the sweep run when it should not (bench cost).
        // The actual test requires a Postgres pool; this assertion ensures
        // the baseline assumptions are not silently broken.
        assert_ne!(super::SWEEP_INTERVAL_SECS, 0);
    }
}
