//! Multi-node repo sync worker.
//!
//! When `GITLAWB_AUTO_SYNC=true`, this background task polls the `sync_queue`
//! table and mirrors repos from peer nodes after receiving Gossipsub ref-update
//! events. Each sync item represents one ref update that arrived from a peer.
//!
//! For each pending item:
//!   1. Look up the origin node's HTTP URL from the peer table.
//!   2. If the repo doesn't exist locally → `git clone --mirror`.
//!   3. If it exists → `git fetch --prune` from the origin.
//!   4. Mark done or failed.

use std::path::Path;
use std::sync::Arc;

use tracing::{info, warn};

use crate::config::Config;
use crate::db::Db;

/// Start the background sync worker. Returns immediately; the worker runs
/// as a detached tokio task.
pub fn start(db: Arc<Db>, config: Arc<Config>) {
    tokio::spawn(async move {
        run(db, config).await;
    });
}

async fn run(db: Arc<Db>, config: Arc<Config>) {
    let machine_id = std::env::var("FLY_MACHINE_ID").ok();
    info!("sync worker started (auto_sync=true)");
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        interval.tick().await;
        process_batch(&db, &config, machine_id.as_deref()).await;
    }
}

async fn process_batch(db: &Db, config: &Config, machine_id: Option<&str>) {
    let items = match db.dequeue_pending_syncs(10).await {
        Ok(v) => v,
        Err(e) => {
            warn!(err = %e, "sync_queue fetch failed");
            return;
        }
    };

    for item in items {
        // Resolve origin node HTTP URL from peer table
        let peers = match db.list_peers().await {
            Ok(p) => p,
            Err(e) => {
                warn!(err = %e, "failed to list peers for sync");
                let _ = db.mark_sync_failed(&item.id).await;
                continue;
            }
        };

        let origin_url = match peers.iter().find(|p| p.did == item.node_did) {
            Some(p) => p.http_url.trim_end_matches('/').to_string(),
            None => {
                warn!(node_did = %item.node_did, repo = %item.repo, "no peer URL found for sync origin — skipping");
                let _ = db.mark_sync_failed(&item.id).await;
                continue;
            }
        };

        // Derive local disk path matching repo_disk_path convention:
        // {repos_dir}/{owner_slug}/{name}.git
        // item.repo is "{short_owner}/{name}" — split on first '/'
        let (owner_short, repo_name) = match item.repo.split_once('/') {
            Some(pair) => pair,
            None => {
                warn!(repo = %item.repo, "sync item repo has no '/' separator — skipping");
                let _ = db.mark_sync_failed(&item.id).await;
                continue;
            }
        };
        let local_path = config
            .repos_dir
            .join(owner_short)
            .join(format!("{repo_name}.git"));

        // Remote URL matches gitlawb-node git smart HTTP route: /{owner}/{repo}
        // (no .git suffix — the server routes don't include it)
        let remote_url = format!("{}/{}", origin_url, item.repo);

        let result = if local_path.exists() {
            fetch_repo(&local_path, &remote_url).await
        } else {
            clone_repo(&remote_url, &local_path).await
        };

        match result {
            Ok(()) => {
                info!(repo = %item.repo, origin = %origin_url, "synced repo from peer");
                // Register in DB so git smart HTTP can serve the mirrored repo
                let _ = db
                    .upsert_mirror_repo(
                        owner_short,
                        repo_name,
                        local_path.to_str().unwrap_or(""),
                        machine_id,
                    )
                    .await;
                let _ = db.mark_sync_done(&item.id).await;
            }
            Err(e) => {
                warn!(repo = %item.repo, origin = %origin_url, err = %e, "repo sync failed");
                let _ = db.mark_sync_failed(&item.id).await;
            }
        }
    }
}

/// Mirror-clone a repo from a remote URL into a local bare repo.
async fn clone_repo(remote_url: &str, local_path: &Path) -> anyhow::Result<()> {
    let out = tokio::process::Command::new("git")
        .args([
            "clone",
            "--mirror",
            remote_url,
            local_path.to_str().unwrap_or("."),
        ])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("git clone failed to spawn: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("git clone --mirror failed: {stderr}"));
    }
    Ok(())
}

/// Fetch all refs from the remote into an existing mirror repo.
async fn fetch_repo(local_path: &Path, remote_url: &str) -> anyhow::Result<()> {
    let out = tokio::process::Command::new("git")
        .args([
            "-C",
            local_path.to_str().unwrap_or("."),
            "fetch",
            "--prune",
            remote_url,
            "+refs/*:refs/*",
        ])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("git fetch failed to spawn: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("git fetch failed: {stderr}"));
    }
    Ok(())
}
