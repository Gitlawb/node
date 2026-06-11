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
//!   5. On success, register ourselves as a replica with the origin node so
//!      its `replica_count` reflects reality (best-effort, idempotent).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use gitlawb_core::identity::Keypair;
use tracing::{info, warn};

use crate::config::Config;
use crate::db::Db;

/// How to mirror a repo, decided from the origin's `withheld-paths` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MirrorMode {
    /// No withheld content: a normal full mirror.
    Plain,
    /// Withheld content present: a promisor mirror that tolerates the blobs the
    /// origin omits for an anonymous caller.
    Promisor,
}

/// Decide the mirror mode from the origin's `withheld-paths` response.
///
/// `Some(non-empty)` → the repo has a private subtree → `Promisor`.
/// `Some(empty)`     → fully public → `Plain`.
/// `None`            → the lookup 404'd or failed. Attempt a `Plain` mirror; a
///                     mode-A repo also 404s the git read endpoint, so the clone
///                     fails and nothing is mirrored (fail-closed at the git
///                     layer), while a public repo on a peer that predates the
///                     `withheld-paths` route still gets mirrored.
fn classify_mirror(withheld: Option<Vec<String>>) -> MirrorMode {
    match withheld {
        Some(globs) if !globs.is_empty() => MirrorMode::Promisor,
        _ => MirrorMode::Plain,
    }
}

/// One encrypted blob as advertised by an origin's `encrypted-blobs/replicate`
/// endpoint (Option B2). Ciphertext metadata only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
struct ReplicaBlob {
    oid: String,
    cid: String,
    #[serde(default)]
    recipients: Vec<String>,
}

/// The shape of the `encrypted-blobs/replicate` JSON response.
#[derive(Debug, serde::Deserialize)]
struct ReplicateResponse {
    #[serde(default)]
    blobs: Vec<ReplicaBlob>,
}

/// Decide which of the origin's encrypted blobs this mirror must (re)replicate.
///
/// `have` maps each already-stored blob's oid to its stored recipient DIDs. A
/// remote blob is returned when the mirror has no row for that oid, or when the
/// stored recipient set differs from the remote one (the origin re-sealed after a
/// reader-set change; same semantics as B1). Recipient order is ignored.
fn blobs_needing_replication(
    remote: &[ReplicaBlob],
    have: &HashMap<String, Vec<String>>,
) -> Vec<ReplicaBlob> {
    remote
        .iter()
        .filter(|b| match have.get(&b.oid) {
            None => true,
            Some(stored) => !same_recipients(stored, &b.recipients),
        })
        .cloned()
        .collect()
}

/// Order-insensitive equality of two recipient DID lists.
fn same_recipients(a: &[String], b: &[String]) -> bool {
    let mut a: Vec<&String> = a.iter().collect();
    let mut b: Vec<&String> = b.iter().collect();
    a.sort();
    b.sort();
    a == b
}

/// Start the background sync worker. Returns immediately; the worker runs
/// as a detached tokio task that exits cleanly when `shutdown_rx` flips
/// to `true`.
pub fn start(
    db: Arc<Db>,
    config: Arc<Config>,
    keypair: Arc<Keypair>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        run(db, config, keypair, &mut shutdown_rx).await;
    });
}

async fn run(
    db: Arc<Db>,
    config: Arc<Config>,
    keypair: Arc<Keypair>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    let machine_id = std::env::var("FLY_MACHINE_ID").ok();
    // Bound each peer HTTP call (withheld-paths lookup + replica registration)
    // so a stalled peer cannot hang the worker.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    info!("sync worker started (auto_sync=true)");
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                process_batch(&db, &config, &keypair, machine_id.as_deref(), &client).await;
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("sync worker: shutdown signal received, exiting");
                    return;
                }
            }
        }
    }
}

async fn process_batch(
    db: &Db,
    config: &Config,
    keypair: &Keypair,
    machine_id: Option<&str>,
    client: &reqwest::Client,
) {
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

        let withheld = fetch_withheld(client, &origin_url, owner_short, repo_name).await;
        let mode = classify_mirror(withheld);

        let result = if local_path.exists() {
            fetch_repo(&local_path, &remote_url, mode).await
        } else {
            clone_repo(&remote_url, &local_path, mode).await
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
                // Option B2: carry the encrypted withheld-blob envelopes too, so an
                // authorized reader can recover private content from this mirror if
                // the origin dies. `item.repo` is the slug "{owner_short}/{name}",
                // which is the id upsert_mirror_repo wrote (the local repo_id).
                replicate_encrypted_blobs(
                    client,
                    &origin_url,
                    owner_short,
                    repo_name,
                    db,
                    &item.repo,
                    &config.ipfs_api,
                )
                .await;
                let _ = db.mark_sync_done(&item.id).await;
                crate::metrics::record_sync_processed("done");

                // Tell the origin we now host a replica so its replica_count
                // reflects reality. Best-effort: idempotent on the origin and
                // never fails the sync.
                register_replica_with_origin(
                    client,
                    keypair,
                    config.public_url.as_deref(),
                    &origin_url,
                    owner_short,
                    repo_name,
                )
                .await;
            }
            Err(e) => {
                warn!(repo = %item.repo, origin = %origin_url, err = %e, "repo sync failed");
                let _ = db.mark_sync_failed(&item.id).await;
                crate::metrics::record_sync_processed("failed");
            }
        }
    }
}

/// Query the origin's anonymous `withheld-paths` endpoint. Returns the withheld
/// glob list on a 2xx, or `None` on any non-success / network / parse error
/// (treated as "unknown" by `classify_mirror`).
async fn fetch_withheld(
    client: &reqwest::Client,
    origin_url: &str,
    owner: &str,
    repo: &str,
) -> Option<Vec<String>> {
    let url = format!("{origin_url}/api/v1/repos/{owner}/{repo}/withheld-paths");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let globs = body
        .get("withheld")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    Some(globs)
}

/// Signed request path for replica registration on the origin node.
fn replica_registration_path(owner: &str, repo: &str) -> String {
    format!("/api/v1/repos/{owner}/{repo}/replicas")
}

/// Best-effort `PUT /api/v1/repos/{owner}/{repo}/replicas` against the origin
/// node after a successful mirror, signed with our node keypair. The origin
/// records (our DID, our public URL) and exposes it via its public replica
/// list. PUT is idempotent there (201 on first registration, 200 after), so
/// re-registering on every successful sync is safe and self-healing.
///
/// Skipped when we have no public URL to advertise. Failures are logged and
/// never affect the sync result. Reuses the worker's shared `client` (30s
/// timeout) with a tighter per-request timeout.
async fn register_replica_with_origin(
    client: &reqwest::Client,
    keypair: &Keypair,
    public_url: Option<&str>,
    origin_url: &str,
    owner: &str,
    repo: &str,
) {
    let self_url = match public_url {
        Some(u) if !u.is_empty() => u,
        _ => return,
    };

    let path = replica_registration_path(owner, repo);
    let body = serde_json::json!({ "url": self_url });
    let body_bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(e) => {
            warn!(owner, repo, err = %e, "failed to serialize replica registration");
            return;
        }
    };

    let signed = gitlawb_core::http_sig::sign_request(keypair, "PUT", &path, &body_bytes);
    match client
        .put(format!("{origin_url}{path}"))
        .header("Content-Type", "application/json")
        .header("Content-Digest", signed.content_digest)
        .header("Signature-Input", signed.signature_input)
        .header("Signature", signed.signature)
        .body(body_bytes)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            info!(owner, repo, origin = %origin_url, "registered as replica with origin");
        }
        Ok(r) => {
            warn!(owner, repo, origin = %origin_url, status = %r.status(), "replica registration rejected by origin");
        }
        Err(e) => {
            warn!(owner, repo, origin = %origin_url, err = %e, "replica registration request failed");
        }
    }
}

/// Replicate the origin's encrypted withheld blobs onto this mirror (Option B2).
///
/// After the git objects are mirrored, fetch the origin's replication listing,
/// then for each blob the mirror does not already hold (or whose recipients
/// changed) pull the ciphertext envelope over IPFS, pin it locally, and record
/// the `encrypted_blobs` row keyed by this mirror's local `repo_id`.
///
/// Best-effort and idempotent: any per-blob failure is logged and skipped, to be
/// retried on the next sync. Confidentiality is never at risk; the mirror only
/// ever handles ciphertext and never decrypts. Cleanly a no-op when IPFS is
/// unconfigured, the origin reports no encrypted blobs, or the replicate endpoint
/// is absent (older peer) or unreachable.
async fn replicate_encrypted_blobs(
    client: &reqwest::Client,
    origin_url: &str,
    owner: &str,
    repo: &str,
    db: &Db,
    repo_id: &str,
    ipfs_api: &str,
) {
    if ipfs_api.is_empty() {
        return;
    }

    let url = format!("{origin_url}/api/v1/repos/{owner}/{repo}/encrypted-blobs/replicate");
    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return,
    };
    let parsed: ReplicateResponse = match resp.json().await {
        Ok(p) => p,
        Err(e) => {
            warn!(repo = %repo, err = %e, "failed to parse encrypted-blobs/replicate response");
            return;
        }
    };
    if parsed.blobs.is_empty() {
        return;
    }

    let have: HashMap<String, Vec<String>> = match db.list_all_encrypted_blobs(repo_id).await {
        Ok(rows) => rows
            .into_iter()
            .map(|(oid, _cid, recipients)| (oid, recipients))
            .collect(),
        Err(e) => {
            warn!(repo = %repo, err = %e, "failed to list local encrypted blobs for replication");
            return;
        }
    };

    for blob in blobs_needing_replication(&parsed.blobs, &have) {
        let envelope = match crate::ipfs_pin::cat(ipfs_api, &blob.cid).await {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(oid = %blob.oid, cid = %blob.cid, err = %e, "failed to fetch encrypted envelope over IPFS; will retry next sync");
                continue;
            }
        };
        match crate::ipfs_pin::pin_git_object(ipfs_api, &blob.oid, &envelope).await {
            Ok(cid) if !cid.is_empty() => {
                if cid != blob.cid {
                    warn!(oid = %blob.oid, expected = %blob.cid, got = %cid, "replicated envelope CID mismatch; skipping record");
                    continue;
                }
                if let Err(e) = db
                    .record_encrypted_blob(repo_id, &blob.oid, &cid, &blob.recipients)
                    .await
                {
                    warn!(oid = %blob.oid, err = %e, "failed to record replicated encrypted blob");
                }
            }
            _ => {
                warn!(oid = %blob.oid, "failed to pin replicated encrypted envelope; will retry next sync");
            }
        }
    }
}

/// Run a git subprocess, returning an error with stderr on non-zero exit.
async fn git_run(args: &[&str]) -> anyhow::Result<()> {
    let out = tokio::process::Command::new("git")
        .args(args)
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("git failed to spawn: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("git {args:?} failed: {stderr}"));
    }
    Ok(())
}

/// Run a git subprocess, ignoring a non-zero exit. Used for idempotent
/// `config --unset`, which exits non-zero when the key is already absent.
async fn git_run_lenient(args: &[&str]) {
    let _ = tokio::process::Command::new("git")
        .args(args)
        .output()
        .await;
}

/// Read a single git config value; `None` if unset or on error.
async fn git_config_get(repo: &str, key: &str) -> Option<String> {
    let out = tokio::process::Command::new("git")
        .args(["-C", repo, "config", "--get", key])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// Mirror-clone a repo from a remote URL into a local bare repo.
/// `Promisor` mode adds `--filter=blob:limit=10g`, which marks the repo a git
/// promisor (so a pack with origin-omitted withheld blobs is accepted) while
/// the huge size limit means every blob the origin *does* send is kept.
async fn clone_repo(remote_url: &str, local_path: &Path, mode: MirrorMode) -> anyhow::Result<()> {
    let local_str = local_path.to_str().unwrap_or(".");
    let mut args = vec!["clone", "--mirror"];
    if mode == MirrorMode::Promisor {
        args.push("--filter=blob:limit=10g");
    }
    args.push(remote_url);
    args.push(local_str);

    let out = tokio::process::Command::new("git")
        .args(&args)
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("git clone failed to spawn: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow::anyhow!("git clone --mirror failed: {stderr}"));
    }
    Ok(())
}

/// Fetch all refs from the remote into an existing mirror repo. Refreshes the
/// stored `origin` URL (the peer's URL may have changed) and fetches via the
/// `origin` remote so any stored promisor settings are honored.
///
/// `Promisor` applies the promisor config first (covers a repo that became
/// mode-B after a plain initial mirror). `Plain` on a mirror that was previously
/// a promisor (the repo went private -> public) clears the partial-clone config
/// and `--refetch`es, so the once-withheld, now-public blobs are backfilled
/// rather than left permanently missing.
async fn fetch_repo(local_path: &Path, remote_url: &str, mode: MirrorMode) -> anyhow::Result<()> {
    let local_str = local_path.to_str().unwrap_or(".");

    git_run(&["-C", local_str, "remote", "set-url", "origin", remote_url]).await?;

    match mode {
        MirrorMode::Promisor => {
            git_run(&["-C", local_str, "config", "remote.origin.promisor", "true"]).await?;
            git_run(&[
                "-C",
                local_str,
                "config",
                "remote.origin.partialclonefilter",
                "blob:limit=10g",
            ])
            .await?;
            git_run(&["-C", local_str, "fetch", "--prune", "origin"]).await
        }
        MirrorMode::Plain => {
            let was_promisor = git_config_get(local_str, "remote.origin.promisor")
                .await
                .as_deref()
                == Some("true");
            if was_promisor {
                git_run_lenient(&[
                    "-C",
                    local_str,
                    "config",
                    "--unset",
                    "remote.origin.promisor",
                ])
                .await;
                git_run_lenient(&[
                    "-C",
                    local_str,
                    "config",
                    "--unset",
                    "remote.origin.partialclonefilter",
                ])
                .await;
                git_run(&["-C", local_str, "fetch", "--refetch", "--prune", "origin"]).await
            } else {
                git_run(&["-C", local_str, "fetch", "--prune", "origin"]).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn classify_promisor_when_withheld_nonempty() {
        let mode = classify_mirror(Some(vec!["/secret/**".to_string()]));
        assert!(matches!(mode, MirrorMode::Promisor));
    }

    #[test]
    fn classify_plain_when_withheld_empty() {
        let mode = classify_mirror(Some(vec![]));
        assert!(matches!(mode, MirrorMode::Plain));
    }

    #[test]
    fn classify_plain_when_lookup_failed() {
        // None == 404 / network error / parse failure: attempt a plain mirror
        // and let the git read endpoint fail-close a mode-A repo.
        let mode = classify_mirror(None);
        assert!(matches!(mode, MirrorMode::Plain));
    }

    fn rb(oid: &str, cid: &str, recipients: &[&str]) -> ReplicaBlob {
        ReplicaBlob {
            oid: oid.to_string(),
            cid: cid.to_string(),
            recipients: recipients.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn replicate_stores_new_blob() {
        let remote = vec![rb("oid1", "cidA", &["did:key:zA"])];
        let have = HashMap::new();
        assert_eq!(blobs_needing_replication(&remote, &have), remote);
    }

    #[test]
    fn replicate_skips_already_present_same_recipients() {
        let remote = vec![rb("oid1", "cidA", &["did:key:zA", "did:key:zB"])];
        let mut have = HashMap::new();
        // stored in a different order: must still count as present
        have.insert(
            "oid1".to_string(),
            vec!["did:key:zB".to_string(), "did:key:zA".to_string()],
        );
        assert!(blobs_needing_replication(&remote, &have).is_empty());
    }

    #[test]
    fn replicate_restores_on_recipient_change() {
        let remote = vec![rb("oid1", "cidB", &["did:key:zA", "did:key:zC"])];
        let mut have = HashMap::new();
        have.insert("oid1".to_string(), vec!["did:key:zA".to_string()]);
        assert_eq!(blobs_needing_replication(&remote, &have), remote);
    }

    #[test]
    fn replicate_empty_remote_is_noop() {
        assert!(blobs_needing_replication(&[], &HashMap::new()).is_empty());
    }

    #[test]
    fn replicate_response_parses() {
        let json = r#"{"blobs":[{"oid":"o1","cid":"c1","recipients":["did:key:zA"]}]}"#;
        let parsed: ReplicateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.blobs.len(), 1);
        assert_eq!(parsed.blobs[0].oid, "o1");
        assert_eq!(parsed.blobs[0].recipients, vec!["did:key:zA".to_string()]);
    }

    #[test]
    fn replicate_response_empty_blobs_parses() {
        let parsed: ReplicateResponse = serde_json::from_str(r#"{"blobs":[]}"#).unwrap();
        assert!(parsed.blobs.is_empty());
    }

    fn g(args: &[&str], dir: &Path) {
        assert!(Command::new("git")
            .args(args)
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
    }

    /// Build a bare remote containing `files`, committed on one branch.
    /// Returns (tempdir, file:// url). file:// makes git honor --filter.
    fn bare_remote(files: &[(&str, &[u8])]) -> (TempDir, String) {
        let td = TempDir::new().unwrap();
        let origin = td.path().join("origin");
        let bare = td.path().join("bare.git");
        for (path, contents) in files {
            let full = origin.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, contents).unwrap();
        }
        g(&["init", "-q"], &origin);
        g(&["config", "user.email", "t@t"], &origin);
        g(&["config", "user.name", "t"], &origin);
        g(&["add", "."], &origin);
        g(&["commit", "-qm", "init"], &origin);
        g(
            &[
                "clone",
                "-q",
                "--bare",
                origin.to_str().unwrap(),
                bare.to_str().unwrap(),
            ],
            td.path(),
        );
        let url = format!("file://{}", bare.display());
        (td, url)
    }

    fn git_config(repo: &Path, key: &str) -> String {
        let out = Command::new("git")
            .args(["-C", repo.to_str().unwrap(), "config", "--get", key])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn object_count(repo: &Path) -> usize {
        let out = Command::new("git")
            .args([
                "-C",
                repo.to_str().unwrap(),
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
    }

    #[tokio::test]
    async fn promisor_clone_marks_promisor_and_keeps_objects() {
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n"), ("secret/b.txt", b"SECRET\n")]);
        let dest = td.path().join("mirror.git");
        clone_repo(&url, &dest, MirrorMode::Promisor).await.unwrap();

        assert_eq!(git_config(&dest, "remote.origin.promisor"), "true");
        assert_eq!(git_config(&dest, "remote.origin.mirror"), "true");
        // No withholding on a plain bare origin, so every object is present:
        // 1 commit + 1 root tree + 2 subtrees + 2 blobs = 6.
        assert_eq!(object_count(&dest), 6);
    }

    #[tokio::test]
    async fn plain_clone_is_not_promisor() {
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n")]);
        let dest = td.path().join("mirror.git");
        clone_repo(&url, &dest, MirrorMode::Plain).await.unwrap();

        assert_eq!(git_config(&dest, "remote.origin.promisor"), "");
        assert_eq!(git_config(&dest, "remote.origin.mirror"), "true");
    }

    #[tokio::test]
    async fn promisor_fetch_updates_existing_mirror() {
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n")]);
        let dest = td.path().join("mirror.git");
        clone_repo(&url, &dest, MirrorMode::Promisor).await.unwrap();
        let before = object_count(&dest);

        // Add a second commit to the origin working tree and push to the bare
        // (the working repo has no named remote, so push via the file:// URL).
        let origin = td.path().join("origin");
        std::fs::write(origin.join("public/c.txt"), b"more\n").unwrap();
        g(&["add", "."], &origin);
        g(&["commit", "-qm", "second"], &origin);
        g(&["push", "-q", &url, "HEAD"], &origin);

        fetch_repo(&dest, &url, MirrorMode::Promisor).await.unwrap();

        assert_eq!(git_config(&dest, "remote.origin.promisor"), "true");
        assert!(object_count(&dest) > before, "fetch pulled the new commit");
    }

    #[tokio::test]
    async fn plain_fetch_clears_promisor_config_on_transition() {
        // Repo started mode-B (promisor mirror), then went fully public, so the
        // next sync classifies Plain. fetch_repo must drop the partial-clone
        // config and refetch instead of leaving the mirror a promisor forever.
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n")]);
        let dest = td.path().join("mirror.git");
        clone_repo(&url, &dest, MirrorMode::Promisor).await.unwrap();
        assert_eq!(git_config(&dest, "remote.origin.promisor"), "true");

        fetch_repo(&dest, &url, MirrorMode::Plain).await.unwrap();

        assert_eq!(git_config(&dest, "remote.origin.promisor"), "");
        assert_eq!(git_config(&dest, "remote.origin.partialclonefilter"), "");
    }

    #[test]
    fn registration_path_matches_replicas_route() {
        // Must stay in sync with the route in api/mod.rs:
        // PUT /api/v1/repos/:owner/:repo/replicas
        assert_eq!(
            replica_registration_path("z6MkOwner", "my-repo"),
            "/api/v1/repos/z6MkOwner/my-repo/replicas"
        );
    }

    #[tokio::test]
    async fn registration_skipped_without_public_url() {
        // No public URL to advertise → must return without sending anything.
        // An unroutable origin URL would otherwise surface as a warn + delay.
        let client = reqwest::Client::new();
        let keypair = Keypair::generate();
        register_replica_with_origin(
            &client,
            &keypair,
            None,
            "http://127.0.0.1:1", // would fail instantly if contacted
            "owner",
            "repo",
        )
        .await;
        register_replica_with_origin(&client, &keypair, Some(""), "http://127.0.0.1:1", "o", "r")
            .await;
    }
}
