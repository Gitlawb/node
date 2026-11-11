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
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use gitlawb_core::identity::Keypair;
use tracing::{error, info, warn};

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

/// The on-disk promisor state of an existing mirror, read from
/// `remote.origin.promisor`. Three-valued so a git error is not mistaken for a
/// definitive "not a promisor": `git config --get` collapses "key absent" and
/// "git failed" into the same non-zero exit otherwise, and treating an errored
/// probe as `NotPromisor` would let a transient failure downgrade a still-withheld
/// mirror (issue #48).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromisorProbe {
    /// `remote.origin.promisor` is `"true"`.
    Promisor,
    /// The key is absent (git exit 1) or set to a non-`true` value.
    NotPromisor,
    /// The probe itself failed (git spawn error or other non-zero exit).
    Unknown,
}

/// Decide the mirror mode from the origin's `withheld-paths` response plus, when
/// the response is unknown, the existing mirror's on-disk promisor state.
///
/// `Some(non-empty)` → the repo has a private subtree → `Promisor`.
/// `Some(empty)`     → fully public → `Plain`.
/// `None`            → the lookup 404'd or failed; the answer is *unknown*, which
///                     is not the same as "public". For a fresh clone this stays
///                     `Plain` (a mode-A repo also 404s the git read endpoint, so
///                     the clone fails and nothing is mirrored — fail-closed at the
///                     git layer — while a public repo on a peer that predates the
///                     `withheld-paths` route still gets mirrored). For an existing
///                     mirror it *biases toward preserving* the promisor state: a
///                     genuine public transition returns `Some(empty)`, so on
///                     `None` we cannot distinguish "still withheld, unreachable"
///                     from "newly public, unreachable" and prefer the recoverable
///                     choice over destroying the partial-clone config. An
///                     indeterminate probe (`Unknown`) preserves for the same
///                     reason (defense-in-depth, #48).
fn resolve_mirror_mode(
    withheld: Option<Vec<String>>,
    exists: bool,
    promisor: PromisorProbe,
) -> MirrorMode {
    match withheld {
        Some(globs) if !globs.is_empty() => MirrorMode::Promisor,
        Some(_) => MirrorMode::Plain,
        None if exists && promisor != PromisorProbe::NotPromisor => MirrorMode::Promisor,
        None => MirrorMode::Plain,
    }
}

/// One encrypted blob as advertised by an origin's `encrypted-blobs/replicate`
/// endpoint (Option B2). Ciphertext metadata only; recipient identities are
/// withheld from peers, so a re-seal is detected by the CID changing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
struct ReplicaBlob {
    oid: String,
    cid: String,
}

/// The shape of the `encrypted-blobs/replicate` JSON response.
#[derive(Debug, serde::Deserialize)]
struct ReplicateResponse {
    #[serde(default)]
    blobs: Vec<ReplicaBlob>,
}

/// Decide which of the origin's encrypted blobs this mirror must (re)replicate.
///
/// `have` maps each already-stored blob's oid to the CID the mirror pinned. A
/// remote blob is returned when the mirror has no row for that oid, or when the
/// stored CID differs from the advertised one. A re-seal regenerates the
/// envelope (new content key, nonce, and per-recipient wraps), so the CID
/// changes while the OID stays stable; comparing CIDs detects a re-seal without
/// the mirror ever holding recipient identities.
fn blobs_needing_replication(
    remote: &[ReplicaBlob],
    have: &HashMap<String, String>,
) -> Vec<ReplicaBlob> {
    remote
        .iter()
        .filter(|b| match have.get(&b.oid) {
            None => true,
            Some(stored_cid) => stored_cid != &b.cid,
        })
        .cloned()
        .collect()
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
    // No redirects: peer URLs are attacker-influenceable, so a 3xx to a
    // loopback/private address must not be followed (SSRF guard, matching the
    // shared http_client and announce-time validation).
    // Panic rather than fall back to reqwest::Client::new(): the default
    // builder follows redirects, which would silently reintroduce the SSRF
    // vector Policy::none() is here to close.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build no-redirect sync HTTP client");
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

/// Find the origin node's base HTTP URL for a sync item, trimming any trailing
/// slash so callers can append `/{path}` cleanly. Returns `None` when no peer
/// row matches the item's origin DID. Kept pure (no DB) so the per-batch peer
/// resolution can be unit-tested without a database.
fn resolve_origin_url(peers: &[crate::db::PeerRecord], node_did: &str) -> Option<String> {
    peers
        .iter()
        .find(|p| p.did == node_did)
        .map(|p| p.http_url.trim_end_matches('/').to_string())
}

/// Convert a sender-supplied RFC-3339 ref-update timestamp into an observable
/// lag. Missing, malformed, and future timestamps are deliberately ignored:
/// older peers and clock-skewed peers must not create fabricated observations.
fn sync_lag_from_origin_timestamp(
    origin_timestamp: Option<&str>,
    visible_at: DateTime<Utc>,
) -> Option<Duration> {
    let origin = DateTime::parse_from_rfc3339(origin_timestamp?).ok()?;
    visible_at
        .signed_duration_since(origin.with_timezone(&Utc))
        .to_std()
        .ok()
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

    // Nothing queued — the common case on the 30s idle poll. Bail before the
    // peer lookup so an empty batch costs zero extra DB round-trips.
    if items.is_empty() {
        return;
    }

    // Resolve the peer table once per batch — every item only needs a lookup.
    let peers = match db.list_peers().await {
        Ok(p) => p,
        Err(e) => {
            warn!(err = %e, "failed to list peers for sync");
            for item in &items {
                let _ = db.mark_sync_failed(&item.id).await;
            }
            return;
        }
    };

    for item in items {
        let origin_url = match resolve_origin_url(&peers, &item.node_did) {
            Some(url) => url,
            None => {
                warn!(node_did = %item.node_did, repo = %item.repo, "no peer URL found for sync origin — skipping");
                let _ = db.mark_sync_failed(&item.id).await;
                continue;
            }
        };

        // Validate the slug before deriving any path from it. The row may have
        // been queued before this check existed, or by the gossip/trigger
        // writers, so the worker does not trust it (issue #272). This has to run
        // ahead of the repos_dir join: PathBuf::join does not normalize, and an
        // absolute second component discards the root entirely, which put a
        // mirror outside repos_dir.
        let (owner_short, repo_name) = match crate::git::repo_store::validate_repo_slug(&item.repo)
        {
            Ok(pair) => pair,
            Err(e) => {
                warn!(id = %item.id, repo = %item.repo, err = %e, "sync item has an invalid repo slug, skipping");
                let _ = db.mark_sync_failed(&item.id).await;
                crate::metrics::record_sync_processed("rejected");
                continue;
            }
        };
        // Local disk path matching the repo_disk_path convention:
        // {repos_dir}/{owner_slug}/{name}.git
        let local_path = config
            .repos_dir
            .join(owner_short)
            .join(format!("{repo_name}.git"));

        // Third layer, after the slug's character rules and the component walk:
        // prove the resolved mirror path really sits inside repos_dir. Only this
        // sees a symlink standing between the root and the target, at either the
        // owner directory or the mirror itself (#272). The owner directory is
        // created first so the clone branch has a parent to canonicalize, and
        // the check then covers clone and fetch alike.
        let owner_dir = config.repos_dir.join(owner_short);
        if let Err(e) = std::fs::create_dir_all(&owner_dir) {
            // Split by whether retrying could ever change the answer. A
            // read-only or briefly unmounted repos_dir is transient, so the row
            // stays pending and is retried. A path that is simply not creatable
            // is not going to become creatable on the next poll, so leaving it
            // pending would retry it forever for nothing. `dequeue_pending_syncs`
            // stamps what it hands out, so such a row rotates rather than pins
            // the batch, but a row that can never succeed still should not sit
            // in the queue consuming a slot every rotation.
            //
            // AlreadyExists is in this set because create_dir_all only reports
            // it when something that is not a directory occupies the path — a
            // regular file, a dangling symlink, a link loop. The concurrent
            // mkdir race that looks like a false positive resolves to Ok
            // instead, since the implementation falls back to is_dir() on
            // EEXIST and a racing mkdir leaves a directory there. Clearing it
            // takes an operator (or, for a dangling link, its target appearing),
            // never a retry. This is also what the pre-#272 code did: the same
            // state failed the clone and hit the terminal Err arm below.
            let permanent = matches!(
                e.kind(),
                std::io::ErrorKind::AlreadyExists
                    | std::io::ErrorKind::InvalidFilename
                    | std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::NotADirectory
            );
            error!(
                id = %item.id, repo = %item.repo, path = %owner_dir.display(), err = %e,
                permanent, "cannot create the owner directory for a mirror"
            );
            if permanent {
                let _ = db.mark_sync_failed(&item.id).await;
                crate::metrics::record_sync_processed("rejected");
            } else {
                crate::metrics::record_sync_processed("deferred");
            }
            continue;
        }
        match crate::git::repo_store::path_within_root(&local_path, &config.repos_dir) {
            crate::git::repo_store::Containment::Contained => {}
            crate::git::repo_store::Containment::Outside => {
                warn!(
                    id = %item.id, repo = %item.repo, path = %local_path.display(),
                    "mirror path resolves outside repos_dir, skipping"
                );
                let _ = db.mark_sync_failed(&item.id).await;
                crate::metrics::record_sync_processed("rejected");
                continue;
            }
            crate::git::repo_store::Containment::IoError(e) => {
                // Pending, so it is retried when the condition clears. This is
                // the deferral the error-kind split above cannot reach: an
                // owner directory that exists but denies traversal lets
                // create_dir_all succeed and fails here instead, and it is
                // per-repo rather than a whole-repos_dir outage.
                //
                // No stamping is needed at this branch. `dequeue_pending_syncs`
                // stamps every row it hands out, so this row already sorts to
                // the back and cannot hold the batch against healthy repos.
                // There is still deliberately no attempt cap: bounding retries
                // needs an attempts column, which is its own change. The metric
                // is what makes a queue stalled on an operator condition
                // distinguishable from an idle one.
                error!(
                    id = %item.id, repo = %item.repo, path = %local_path.display(), err = %e,
                    "cannot resolve the mirror path against repos_dir; leaving the sync row pending"
                );
                crate::metrics::record_sync_processed("deferred");
                continue;
            }
        }

        // Remote URL matches gitlawb-node git smart HTTP route: /{owner}/{repo}
        // (no .git suffix — the server routes don't include it)
        let remote_url = format!("{}/{}", origin_url, item.repo);

        let withheld = fetch_withheld(client, &origin_url, owner_short, repo_name).await;
        let exists = local_path.exists();
        let lookup_unknown = withheld.is_none();
        // Only probe the on-disk promisor state when the lookup is unknown and the
        // repo already exists — the sole case where it changes the resolved mode.
        let promisor = if lookup_unknown && exists {
            let local_str = local_path.to_str().unwrap_or(".");
            existing_promisor_state(local_str).await
        } else {
            PromisorProbe::NotPromisor
        };
        let mode = resolve_mirror_mode(withheld, exists, promisor);
        // Surface the case where an unknown withheld-paths lookup kept (or, on an
        // indeterminate probe, defensively applied) promisor mode instead of
        // downgrading to a full clone. Derived from the resolved mode so it cannot
        // drift from resolve_mirror_mode's preserve branch.
        if lookup_unknown && mode == MirrorMode::Promisor {
            warn!(
                repo = %item.repo,
                origin = %origin_url,
                "withheld-paths lookup unavailable; using promisor mirror mode to avoid an unsafe full-clone downgrade"
            );
        }

        let result = if exists {
            fetch_repo(&local_path, &remote_url, mode).await
        } else {
            clone_repo(&remote_url, &local_path, mode).await
        };

        match result {
            Ok(()) => {
                info!(repo = %item.repo, origin = %origin_url, "synced repo from peer");
                // iCaptcha propagation gate: on a first-time mirror, re-verify the
                // proof the repo was created with (fetched from the origin) before
                // admitting it. A node that enforces iCaptcha quarantines a mirror
                // it cannot validate — kept on disk but hidden from serve/clone and
                // listings until an operator releases it. Re-syncs of an already
                // admitted repo keep their prior decision (upsert preserves it).
                //
                // "First-time" is keyed on DB-row absence, NOT on-disk presence: a
                // prior attempt could have cloned to disk but crashed before the
                // upsert, leaving no DB row. Disk-keying would skip admission on the
                // retry and admit it unquarantined. On a DB lookup error, default to
                // running the gate (fail toward quarantine, never silently admit).
                let is_new_in_db = db
                    .get_repo(owner_short, repo_name)
                    .await
                    .map(|r| r.is_none())
                    .unwrap_or(true);
                let quarantined = if is_new_in_db {
                    let proof =
                        fetch_icaptcha_proof(client, &origin_url, owner_short, repo_name).await;
                    match crate::icaptcha::admit_mirror(db, proof.as_deref(), owner_short).await {
                        crate::icaptcha::MirrorAdmission::Admit => false,
                        crate::icaptcha::MirrorAdmission::Quarantine(reason) => {
                            warn!(
                                repo = %item.repo, origin = %origin_url, reason,
                                "quarantining mirrored repo: failed iCaptcha propagation gate"
                            );
                            true
                        }
                    }
                } else {
                    false
                };
                // Register in DB so git smart HTTP can serve the mirrored repo
                let mirror_visible = db
                    .upsert_mirror_repo(
                        owner_short,
                        repo_name,
                        local_path.to_str().unwrap_or(""),
                        machine_id,
                        quarantined,
                    )
                    .await
                    .is_ok();
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
                let marked_done = db.mark_sync_done(&item.id).await;
                crate::metrics::record_sync_processed("done");
                if mirror_visible && marked_done.is_ok() {
                    if let Some(lag) =
                        sync_lag_from_origin_timestamp(item.origin_timestamp.as_deref(), Utc::now())
                    {
                        crate::metrics::observe_sync_lag(lag);
                    }
                }

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
                // Prune vs terminal classification lives in
                // `handle_sync_item_error` (defer = stays pending for the
                // next tick; anything else = failed).
                handle_sync_item_error(db, &item, &origin_url, e).await;
            }
        }
    }
}

/// Query the origin's anonymous `withheld-paths` endpoint. Returns the withheld
/// glob list on a 2xx, or `None` on any non-success / network / parse error
/// (treated as "unknown" by `resolve_mirror_mode`).
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

/// Fetch the iCaptcha proof token the origin recorded for this repo, used by the
/// mirror-admission gate. Returns `None` on any non-success / network / parse
/// error, or when the origin has no proof for the repo (treated as "no proof" by
/// `icaptcha::admit_mirror`, which quarantines in enforce mode).
async fn fetch_icaptcha_proof(
    client: &reqwest::Client,
    origin_url: &str,
    owner: &str,
    repo: &str,
) -> Option<String> {
    let url = format!("{origin_url}/api/v1/repos/{owner}/{repo}/icaptcha-proof");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("proof")?.as_str().map(str::to_string)
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
/// then for each blob the mirror does not already hold (or whose CID changed,
/// i.e. the origin re-sealed) pull the ciphertext envelope over IPFS, pin it
/// locally, and record the `encrypted_blobs` row keyed by this mirror's local
/// `repo_id`. The mirror stores no recipient identities.
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
        // A peer that predates the replicate route answers 404: expected and
        // quiet. Anything else is the route existing and refusing or failing,
        // which should be observable rather than read as route-absent.
        Ok(r) if r.status().as_u16() == 404 => return,
        Ok(r) => {
            tracing::warn!(repo = %repo, status = %r.status(), "encrypted-blobs replicate refused; skipping");
            return;
        }
        Err(e) => {
            tracing::warn!(repo = %repo, error = %e, "encrypted-blobs replicate request failed; skipping");
            return;
        }
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

    let have: HashMap<String, String> = match db.list_all_encrypted_blobs(repo_id).await {
        Ok(rows) => rows.into_iter().collect(),
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
        match crate::ipfs_pin::pin_git_object(ipfs_api, &blob.oid, &envelope, None).await {
            Ok(cid) if !cid.is_empty() => {
                if cid != blob.cid {
                    warn!(oid = %blob.oid, expected = %blob.cid, got = %cid, "replicated envelope CID mismatch; skipping record");
                    continue;
                }
                if let Err(e) = db.record_encrypted_blob(repo_id, &blob.oid, &cid, "").await {
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

/// Probe an existing mirror's `remote.origin.promisor` config as a three-valued
/// state. Unlike [`git_config_get`], this distinguishes a definitively-absent key
/// from a probe failure so a transient git error cannot be read as "not a
/// promisor" and trigger a downgrade (issue #48).
///
/// `git config --get` exits 0 when the key is set, 1 when it is absent (or the
/// directory is not a git repo) — both definitive `NotPromisor` — and other
/// non-zero codes (e.g. 128 for a bad path or unreadable config) on error. A spawn
/// failure or any non-{0,1} exit is `Unknown`.
async fn existing_promisor_state(repo: &str) -> PromisorProbe {
    let out = match tokio::process::Command::new("git")
        .args(["-C", repo, "config", "--get", "remote.origin.promisor"])
        .output()
        .await
    {
        Ok(out) => out,
        Err(_) => return PromisorProbe::Unknown,
    };
    match out.status.code() {
        Some(0) => {
            let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if value == "true" {
                PromisorProbe::Promisor
            } else {
                PromisorProbe::NotPromisor
            }
        }
        Some(1) => PromisorProbe::NotPromisor,
        _ => PromisorProbe::Unknown,
    }
}

/// Byte-prefix check for the two node-managed blob namespaces exempt from
/// the fail-closed commit walk (`visibility_pack.rs`): request markers
/// (`refs/gitlawb/requests/`) and issue records (`refs/gitlawb/issues/`).
/// Bytewise so non-UTF-8 refnames (which git accepts) are classified, not
/// lossy-decoded into a false exempt match. Extracted so the predicate is
/// unit-testable; [`prune_non_exempt_gitlawb_refs`] enforces it on import.
fn gitlawb_ref_is_exempt(raw_refname: &[u8]) -> bool {
    raw_refname.starts_with(b"refs/gitlawb/requests/")
        || raw_refname.starts_with(b"refs/gitlawb/issues/")
}

/// Parse one `git show-ref` output line into its refname bytes: `<hex-sha>`
/// (40-hex SHA-1 or 64-hex SHA-256, which a sha256 mirror inherits from its
/// origin), one space, then the refname. Empty lines (trailing newline) yield
/// `Ok(None)`; anything else-shaped is an anomaly the caller fails on rather
/// than skips — silently passing an unclassifiable line could leave an evil
/// ref imported. Extracted so malformed input is unit-testable without git.
fn show_ref_refname(line: &[u8]) -> anyhow::Result<Option<&[u8]>> {
    if line.is_empty() {
        return Ok(None);
    }
    let Some(sp) = line.iter().position(|b| *b == b' ') else {
        return Err(anyhow::anyhow!("git show-ref emitted an unparsable line"));
    };
    let (sha, raw) = (&line[..sp], &line[sp + 1..]);
    let sha_ok = (sha.len() == 40 || sha.len() == 64) && sha.iter().all(|b| b.is_ascii_hexdigit());
    if !sha_ok || raw.is_empty() {
        return Err(anyhow::anyhow!("git show-ref emitted an unparsable line"));
    }
    Ok(Some(raw))
}

/// Delete imported `refs/gitlawb/*` refs outside the two exempt subtrees.
///
/// Mirrors import whatever the origin advertises (`+refs/*:refs/*`), and
/// `transfer.hideRefs` is a serve-side knob: a repo's own `git fetch` never
/// consults local hideRefs, and origins hide only `requests/` anyway. So a
/// planted `refs/gitlawb/<other>` blob ref — creatable on any pre-gate node —
/// lands on every mirror and then trips `assert_all_refs_are_commits` closed,
/// wedging serving on each one. Prune at import instead: after clone/fetch,
/// list `refs/gitlawb` and delete every ref outside the exempt subtrees
/// (negative refspecs cannot re-include them, so post-import deletion is the
/// mechanism that works).
///
/// Callers map a transient prune error to [`PruneFailed`] so the batch
/// defers the row (stays `pending`, retried next tick) instead of failing
/// it: a failed row would leave a possibly-wedged mirror unretried until
/// the next peer announcement. Deterministic refusals (identity mismatch,
/// malformed enumeration) map to [`PruneInvalid`], which fails terminally
/// since no retry can clear them.
///
/// Enumeration is `git show-ref` (no pattern), parsed as raw bytes: refnames
/// cannot contain newlines, so one line per ref is lossless even for
/// non-UTF-8 names, which a lossy decode would miss. The `<sha> SP <refname>`
/// structure (not `for-each-ref --format=%(refname)`, which carries no object
/// id) is what lets the parser width-check 40-hex SHA-1 vs 64-hex SHA-256
/// and reject anything else-shaped instead of skipping it.
///
/// Fail-closed throughout: the exit code is classified (only `1` with empty
/// output means "no refs"; anything else non-zero, e.g. 128 on a missing
/// repo, is fatal, since a silent skip would leave an imported evil ref in
/// place while the sync reports success), and any line that is not
/// `<hex-sha> SP <refname>` — 40-hex SHA-1 or 64-hex SHA-256, which a sha256
/// mirror inherits from its origin — fails the sync rather than being
/// skipped into an unpruned wedge.
/// Bounded git spawn for the prune below: `kill_on_drop` plus a hard timeout
/// so a wedged child cannot stall a mirror import or sweep forever. The
/// refname delete runs on exact bytes, so args arrive as `OsStr`, not `str`.
/// Non-PruneInvalid failures (including a timeout) wrap as PruneFailed and
/// defer for retry, matching the transient classification below.
async fn prune_git(
    local_path: &Path,
    args: &[&std::ffi::OsStr],
    label: &str,
) -> anyhow::Result<std::process::Output> {
    let fut = async {
        // allow-unbounded-git: bounded by the tokio::time::timeout wrapping
        // this future below, plus kill_on_drop.
        let mut cmd = tokio::process::Command::new("git");
        cmd.kill_on_drop(true);
        cmd.arg("-C").arg(local_path).args(args);
        cmd.output().await
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), fut)
        .await
        .map_err(|_| anyhow::anyhow!("{label} timed out"))?
        .map_err(|e| anyhow::anyhow!("{label} failed to spawn: {e}"))
}

async fn prune_non_exempt_gitlawb_refs(local_path: &Path) -> anyhow::Result<()> {
    let local_str = local_path.to_str().unwrap_or(".");
    // Prove the path is itself a repo before trusting the enumeration:
    // `git -C` walks up to the nearest ancestor repo, so inside a non-repo
    // child (a partially-created mirror) `show-ref` would exit 0 with the
    // ANCESTOR's refs and `update-ref -d` would then run against that repo.
    // Require `rev-parse --absolute-git-dir` to resolve to the path itself
    // (mirrors are bare repos, where the git dir IS the path).
    let git_dir_out = prune_git(
        local_path,
        &[
            std::ffi::OsStr::new("rev-parse"),
            std::ffi::OsStr::new("--absolute-git-dir"),
        ],
        "git rev-parse",
    )
    .await?;
    if !git_dir_out.status.success() {
        let stderr = String::from_utf8_lossy(&git_dir_out.stderr);
        return Err(anyhow::anyhow!(PruneInvalid(format!(
            "mirror path is not a git repo (rev-parse failed): {stderr}"
        ))));
    }
    let actual_dir = PathBuf::from(
        String::from_utf8_lossy(&git_dir_out.stdout)
            .trim()
            .to_string(),
    );
    let canonical_path = local_path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!(PruneInvalid(format!("mirror path does not resolve: {e}"))))?;
    let canonical_git_dir = actual_dir
        .canonicalize()
        .map_err(|e| anyhow::anyhow!(PruneInvalid(format!("git dir does not resolve: {e}"))))?;
    if canonical_git_dir != canonical_path {
        return Err(anyhow::anyhow!(PruneInvalid(format!(
            "mirror path {local_str} is not itself a repo (git dir resolves elsewhere); refusing to enumerate"
        ))));
    }
    let out = prune_git(
        local_path,
        &[std::ffi::OsStr::new("show-ref")],
        "git show-ref",
    )
    .await?;
    // Classify on the exit code (the `existing_promisor_state` precedent):
    // 0 parses, 1 with empty output is an empty repo, anything else is a
    // fatal enumeration failure that must not read as "nothing to prune".
    match out.status.code() {
        Some(0) => {}
        Some(1) if out.stdout.is_empty() => return Ok(()),
        _ => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow::anyhow!(
                "git show-ref failed with code {:?}: {stderr}",
                out.status.code()
            ));
        }
    }
    for line in out.stdout.split(|b| *b == b'\n') {
        // Malformed lines are deterministic (same git, same output every
        // tick): fail terminally via PruneInvalid, not transiently.
        let Some(raw) =
            show_ref_refname(line).map_err(|e| anyhow::anyhow!(PruneInvalid(e.to_string())))?
        else {
            continue;
        };
        if !(raw == b"refs/gitlawb" || raw.starts_with(b"refs/gitlawb/"))
            || gitlawb_ref_is_exempt(raw)
        {
            continue;
        }
        // Delete by exact bytes (not the lossy display string below): a
        // non-UTF-8 refname would otherwise survive the prune.
        let refname_os = os_from_raw_refname(raw);
        let shown = refname_os.to_string_lossy().into_owned();
        let delete = prune_git(
            local_path,
            &[
                std::ffi::OsStr::new("update-ref"),
                std::ffi::OsStr::new("-d"),
                refname_os.as_os_str(),
                std::ffi::OsStr::new("--no-deref"),
            ],
            "git update-ref -d",
        )
        .await?;
        if !delete.status.success() {
            let stderr = String::from_utf8_lossy(&delete.stderr);
            return Err(anyhow::anyhow!(
                "git update-ref -d {shown} failed (mirror still carries a non-exempt refs/gitlawb ref): {stderr}"
            ));
        }
        tracing::info!(
            gitlawb_ref = %shown,
            "mirror: pruned non-exempt refs/gitlawb ref on import"
        );
    }
    Ok(())
}

/// Lossless bytes → OsString for `update-ref -d`: non-UTF-8 refnames must be
/// deleted by exact bytes. Unix is the serving platform; elsewhere fall back
/// to a lossy decode (best effort where exact bytes are unrepresentable).
#[cfg(unix)]
fn os_from_raw_refname(raw: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(raw.to_vec())
}

#[cfg(not(unix))]
fn os_from_raw_refname(raw: &[u8]) -> std::ffi::OsString {
    String::from_utf8_lossy(raw).into_owned().into()
}

/// Marker for mirror-prune failures: the clone/fetch succeeded, so the
/// mirror is on disk, but a non-exempt `refs/gitlawb/*` ref may still be
/// imported. Local-git conditions are transient (a retry can succeed), while
/// `mark_sync_failed` is terminal until the next peer announcement — and a
/// failed row would leave a possibly-wedged mirror unretried in the
/// meantime. The batch error arm downcasts to this and defers the row
/// (stays `pending`, retried on the next 30s tick, where fetch+prune are
/// idempotent) instead of failing it.
#[derive(Debug)]
struct PruneFailed(String);

impl std::fmt::Display for PruneFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mirror prune failed: {}", self.0)
    }
}

impl std::error::Error for PruneFailed {}

/// Marker for deterministic mirror-prune refusals: the identity check (path
/// is not itself a repo) and malformed `show-ref` output cannot clear on
/// retry — re-running fetch+prune every tick would spin forever on a
/// permanently bad path. Unlike [`PruneFailed`], these fail the row
/// terminally so the condition surfaces instead of looping silently.
#[derive(Debug)]
struct PruneInvalid(String);

/// Preserve a deterministic prune refusal through the clone/fetch call
/// sites: `prune_non_exempt_gitlawb_refs` already returns `PruneInvalid`
/// for identity mismatches and malformed enumeration, and re-wrapping
/// every error as `PruneFailed` would stringify that type away before
/// `handle_sync_item_error` downcasts it — leaving a permanently invalid
/// mirror deferred (fetch+prune every tick) instead of failed. Transient
/// failures keep the `PruneFailed` deferral.
fn wrap_prune_error(e: anyhow::Error) -> anyhow::Error {
    match e.downcast::<PruneInvalid>() {
        Ok(invalid) => anyhow::Error::new(invalid),
        Err(other) => anyhow::anyhow!(PruneFailed(other.to_string())),
    }
}

impl std::fmt::Display for PruneInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mirror prune refused: {}", self.0)
    }
}

impl std::error::Error for PruneInvalid {}

/// Classify a mirror sync failure for one queue row. Transient prune
/// failures ([`PruneFailed`]) defer: the mirror is on disk but may still
/// carry a non-exempt refs/gitlawb ref, a transient local-git condition a
/// retry can clear — failing the row would leave it unretried until the
/// next peer announcement, wedging serving in the meantime. Deterministic
/// refusals ([`PruneInvalid`]) and everything else fail the row terminally:
/// retrying a permanently bad path every tick would spin forever instead of
/// surfacing. Extracted so the deferral (not just the prune itself) is
/// unit-testable.
async fn handle_sync_item_error(
    db: &Db,
    item: &crate::db::SyncQueueItem,
    origin_url: &str,
    err: anyhow::Error,
) {
    if err.downcast_ref::<PruneFailed>().is_some() {
        warn!(repo = %item.repo, origin = %origin_url, err = %err, "mirror prune failed; leaving sync row pending for retry");
        crate::metrics::record_sync_processed("deferred");
        return;
    }
    warn!(repo = %item.repo, origin = %origin_url, err = %err, "repo sync failed");
    let _ = db.mark_sync_failed(&item.id).await;
    crate::metrics::record_sync_processed("failed");
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
    args.push("--");
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
    // A fresh mirror imports everything the origin advertises, including any
    // planted non-exempt `refs/gitlawb/*` ref; prune before serving from it.
    // Prune outcome flows through `wrap_prune_error`: transient failures
    // defer (stays pending), deterministic refusals fail terminally.
    prune_non_exempt_gitlawb_refs(local_path)
        .await
        .map_err(wrap_prune_error)?;
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

    git_run(&[
        "-C", local_str, "remote", "set-url", "origin", "--", remote_url,
    ])
    .await?;

    // The fetch imports whatever the origin advertises via the stored
    // `+refs/*:refs/*` refspec; prune non-exempt `refs/gitlawb/*` refs after
    // every fetch so one planted origin ref cannot wedge serving on the
    // mirror (see `prune_non_exempt_gitlawb_refs`).
    let fetch_result = match mode {
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
    };
    fetch_result?;
    // Prune after every fetch (see above); outcome flows through
    // `wrap_prune_error` like the clone path.
    prune_non_exempt_gitlawb_refs(local_path)
        .await
        .map_err(wrap_prune_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;
    use std::process::Command;
    use tempfile::TempDir;

    #[test]
    fn resolve_promisor_when_withheld_nonempty() {
        let mode = resolve_mirror_mode(
            Some(vec!["/secret/**".to_string()]),
            true,
            PromisorProbe::NotPromisor,
        );
        assert!(matches!(mode, MirrorMode::Promisor));
    }

    #[test]
    fn resolve_plain_when_withheld_empty() {
        // A genuine public transition returns Some(empty) and still downgrades,
        // regardless of whether the mirror exists or was a promisor.
        for exists in [true, false] {
            for probe in [
                PromisorProbe::Promisor,
                PromisorProbe::NotPromisor,
                PromisorProbe::Unknown,
            ] {
                let mode = resolve_mirror_mode(Some(vec![]), exists, probe);
                assert!(matches!(mode, MirrorMode::Plain));
            }
        }
    }

    #[test]
    fn resolve_preserves_promisor_on_unknown_lookup_for_existing_mirror() {
        // Regression for #48: a transient withheld-paths outage (None) must NOT
        // downgrade a still-withheld promisor mirror to a full clone.
        let mode = resolve_mirror_mode(None, true, PromisorProbe::Promisor);
        assert!(matches!(mode, MirrorMode::Promisor));
    }

    #[test]
    fn resolve_preserves_promisor_on_indeterminate_probe() {
        // Defense-in-depth (#48): if the config probe itself fails (Unknown) in the
        // same cycle as a withheld-paths outage, bias toward preserving rather than
        // firing the destructive downgrade.
        let mode = resolve_mirror_mode(None, true, PromisorProbe::Unknown);
        assert!(matches!(mode, MirrorMode::Promisor));
    }

    #[test]
    fn resolve_plain_when_unknown_lookup_for_non_promisor_mirror() {
        // An existing non-promisor mirror is unaffected by the preserve branch.
        let mode = resolve_mirror_mode(None, true, PromisorProbe::NotPromisor);
        assert!(matches!(mode, MirrorMode::Plain));
    }

    #[test]
    fn resolve_plain_when_unknown_lookup_for_fresh_clone() {
        // No local mirror yet: None stays Plain (fail-closed at the git layer).
        for probe in [
            PromisorProbe::Promisor,
            PromisorProbe::NotPromisor,
            PromisorProbe::Unknown,
        ] {
            let mode = resolve_mirror_mode(None, false, probe);
            assert!(matches!(mode, MirrorMode::Plain));
        }
    }

    fn rb(oid: &str, cid: &str) -> ReplicaBlob {
        ReplicaBlob {
            oid: oid.to_string(),
            cid: cid.to_string(),
        }
    }

    #[test]
    fn replicate_stores_new_blob() {
        let remote = vec![rb("oid1", "cidA")];
        let have = HashMap::new();
        assert_eq!(blobs_needing_replication(&remote, &have), remote);
    }

    #[test]
    fn replicate_skips_already_present_same_cid() {
        let remote = vec![rb("oid1", "cidA")];
        let mut have = HashMap::new();
        have.insert("oid1".to_string(), "cidA".to_string());
        assert!(blobs_needing_replication(&remote, &have).is_empty());
    }

    #[test]
    fn replicate_restores_on_cid_change() {
        // The origin re-sealed: same oid, new envelope, new cid.
        let remote = vec![rb("oid1", "cidB")];
        let mut have = HashMap::new();
        have.insert("oid1".to_string(), "cidA".to_string());
        assert_eq!(blobs_needing_replication(&remote, &have), remote);
    }

    #[test]
    fn replicate_empty_remote_is_noop() {
        assert!(blobs_needing_replication(&[], &HashMap::new()).is_empty());
    }

    #[test]
    fn replicate_response_parses() {
        // An older origin may still send a recipients field; it must be ignored.
        let json = r#"{"blobs":[{"oid":"o1","cid":"c1","recipients":["did:key:zA"]}]}"#;
        let parsed: ReplicateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.blobs.len(), 1);
        assert_eq!(parsed.blobs[0].oid, "o1");
        assert_eq!(parsed.blobs[0].cid, "c1");
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
    async fn probe_reports_promisor_for_promisor_mirror() {
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n")]);
        let dest = td.path().join("mirror.git");
        clone_repo(&url, &dest, MirrorMode::Promisor).await.unwrap();

        let probe = existing_promisor_state(dest.to_str().unwrap()).await;
        assert_eq!(probe, PromisorProbe::Promisor);
    }

    #[tokio::test]
    async fn probe_reports_not_promisor_when_key_absent() {
        // A plain mirror never sets remote.origin.promisor, so `git config --get`
        // exits 1 (key absent) — the probe must read that as NotPromisor, never
        // Unknown (which would wrongly preserve and upgrade a plain mirror).
        let (td, url) = bare_remote(&[("public/a.txt", b"pub\n")]);
        let dest = td.path().join("mirror.git");
        clone_repo(&url, &dest, MirrorMode::Plain).await.unwrap();

        let probe = existing_promisor_state(dest.to_str().unwrap()).await;
        assert_eq!(probe, PromisorProbe::NotPromisor);
    }

    /// #374: `clone_repo` interpolates the peer's origin URL into a `git
    /// clone --mirror` argument list. Without a `--` delimiter git parses a
    /// remote beginning with `-` as an option instead of a repository.
    ///
    /// The delimiter is what forces the same string to be a repository, and
    /// git says so in its own words: it reports the whole argument as a
    /// repository it cannot find. Undelimited, git consumes it as an option
    /// and fails against the *destination* instead (`fatal: repository '<dest>' does not exist`),
    /// never naming the injected string — which is why this assertion is RED
    /// before the fix and GREEN after.
    ///
    /// The payload is deliberately free of `:` and spaces: a colon would make
    /// git read the argument as an ssh-style `host:path` URL and report a
    /// hostname rather than a repository, which is a different code path.
    #[tokio::test]
    async fn clone_never_parses_a_remote_as_a_git_option() {
        let td = TempDir::new().unwrap();
        let dest = td.path().join("mirror.git");
        let injected = "--upload-pack=false";

        let err = clone_repo(injected, &dest, MirrorMode::Plain)
            .await
            .expect_err("a remote that is not a repository must fail the clone")
            .to_string();

        assert!(
            err.contains(injected),
            "git must report the argument as a repository, not consume it as an option: {err}"
        );
    }

    /// #374: `fetch_repo` interpolates the peer's origin URL into
    /// `git remote set-url`, a second argv construction with the same contract as
    /// the clone. It needs its own proof: the clone test cannot reach this path.
    ///
    /// The assertion is on stored state rather than on the error string, and that
    /// is deliberate. `git_run` formats its failure as `git {args:?} failed:
    /// {stderr}`, so the injected value is in the message via the debug-printed
    /// argv whether or not the delimiter is present — asserting on containment
    /// would pass with `--` deleted. Delimited, `set-url` succeeds and stores the
    /// value verbatim; undelimited, git exits 129 with `unknown option` and leaves
    /// the previous URL in place, so this goes red without the fix.
    ///
    /// The fetch that follows the rewrite fails, because the stored URL is not a
    /// repository. That is expected and ignored: the property under test is what
    /// `set-url` wrote, not whether the subsequent fetch could succeed.
    #[tokio::test]
    async fn fetch_never_parses_a_remote_as_a_git_option() {
        let td = TempDir::new().unwrap();
        let local = td.path().join("mirror.git");
        let local_str = local.to_str().unwrap();
        let placeholder = "http://example.invalid/x.git";

        assert!(Command::new("git")
            .args(["init", "-q", "--bare", local_str])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["-C", local_str, "remote", "add", "origin", placeholder])
            .status()
            .unwrap()
            .success());

        let injected = "--upload-pack=false";
        let _ = fetch_repo(&local, injected, MirrorMode::Plain).await;

        assert_eq!(
            git_config_get(local_str, "remote.origin.url")
                .await
                .as_deref(),
            Some(injected),
            "set-url must store an option-shaped remote verbatim, not reject it as an option"
        );
    }

    #[tokio::test]
    async fn probe_reports_unknown_on_git_error() {
        // A path git cannot resolve as a repo at all (exit 128) is an indeterminate
        // probe, not a definitive "not a promisor" — it must map to Unknown so the
        // caller preserves rather than downgrades (#48 defense-in-depth).
        let probe = existing_promisor_state("/nonexistent/gitlawb-probe-xyz").await;
        assert_eq!(probe, PromisorProbe::Unknown);
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

    fn peer(did: &str, http_url: &str) -> crate::db::PeerRecord {
        crate::db::PeerRecord {
            did: did.to_string(),
            http_url: http_url.to_string(),
            last_seen: None,
            last_ping_ok: false,
            announced_at: String::new(),
        }
    }

    #[test]
    fn resolve_origin_url_matches_and_trims_trailing_slash() {
        let peers = vec![
            peer("did:key:a", "https://a.example/"),
            peer("did:key:b", "https://b.example"),
        ];
        // Trailing slash is trimmed so callers can append `/{path}` cleanly.
        assert_eq!(
            resolve_origin_url(&peers, "did:key:a").as_deref(),
            Some("https://a.example")
        );
        // Already-trimmed URLs pass through unchanged.
        assert_eq!(
            resolve_origin_url(&peers, "did:key:b").as_deref(),
            Some("https://b.example")
        );
    }

    #[test]
    fn resolve_origin_url_returns_none_for_unknown_did() {
        let peers = vec![peer("did:key:a", "https://a.example")];
        assert_eq!(resolve_origin_url(&peers, "did:key:unknown"), None);
    }

    #[test]
    fn resolve_origin_url_returns_none_for_empty_peer_list() {
        assert_eq!(resolve_origin_url(&[], "did:key:a"), None);
    }

    // ── worker-side slug validation (issue #272) ─────────────────────────────

    /// Build a rooted remote: one bare repo per entry in `rels`, each at
    /// `root/{rel}`, and return the `file://` URL of `root` itself.
    ///
    /// `process_batch` composes the remote as `{peer_url}/{item.repo}`, so a
    /// peer URL has to be a root under which the slug resolves to the bare
    /// repo. `bare_remote` above returns a URL pointing straight at `bare.git`
    /// and cannot serve as a peer URL as is.
    ///
    /// `root` sits two directories deep inside the tempdir so that a `rel`
    /// carrying `..` (a hostile slug composed onto the root) still resolves
    /// inside the tempdir instead of somewhere in the real filesystem.
    fn rooted_remote(rels: &[&str]) -> (TempDir, String) {
        let td = TempDir::new().unwrap();
        let origin = td.path().join("origin");
        std::fs::create_dir_all(&origin).unwrap();
        std::fs::write(origin.join("a.txt"), b"hi\n").unwrap();
        g(&["init", "-q"], &origin);
        g(&["config", "user.email", "t@t"], &origin);
        g(&["config", "user.name", "t"], &origin);
        g(&["add", "."], &origin);
        g(&["commit", "-qm", "init"], &origin);

        let root = td.path().join("r1").join("r2").join("root");
        std::fs::create_dir_all(&root).unwrap();
        for rel in rels {
            let bare = root.join(rel);
            std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
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
        }
        let url = format!("file://{}", root.display());
        (td, url)
    }

    /// Insert a peer row directly.
    ///
    /// `Db::upsert_peer` runs the URL through `crate::api::peers::is_public_http_url`
    /// and bails on anything that is not public http/https, which rules out both
    /// `file://` and `http://127.0.0.1:PORT`. A worker test needs a locally
    /// reachable origin, so the row goes in with the same column list
    /// `upsert_peer` uses. Do not "fix" this back to the helper.
    async fn seed_local_peer(pool: &PgPool, did: &str, http_url: &str) {
        sqlx::query(
            "INSERT INTO peers (did, http_url, last_seen, last_ping_ok, announced_at)
             VALUES ($1, $2, $3, FALSE, $3)",
        )
        .bind(did)
        .bind(http_url)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(pool)
        .await
        .unwrap();
    }

    async fn sync_status(pool: &PgPool, repo: &str) -> String {
        let row: (String,) = sqlx::query_as("SELECT status FROM sync_queue WHERE repo = $1")
            .bind(repo)
            .fetch_one(pool)
            .await
            .unwrap();
        row.0
    }

    async fn enqueue(db: &Db, repo: &str, did: &str) {
        db.enqueue_sync(repo, did, "refs/heads/main", &"0".repeat(40), None, None)
            .await
            .unwrap();
    }

    #[test]
    fn sync_lag_uses_origin_timestamp_only_when_it_is_in_the_past() {
        let visible_at = chrono::DateTime::parse_from_rfc3339("2026-08-16T00:00:12Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(
            sync_lag_from_origin_timestamp(Some("2026-08-16T00:00:00Z"), visible_at),
            Some(Duration::from_secs(12))
        );
        assert_eq!(sync_lag_from_origin_timestamp(None, visible_at), None);
        assert_eq!(
            sync_lag_from_origin_timestamp(Some("not-a-timestamp"), visible_at),
            None
        );
        assert_eq!(
            sync_lag_from_origin_timestamp(Some("2026-08-16T00:00:13Z"), visible_at),
            None
        );
    }

    fn dir_entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Every `*.git` directory anywhere under `dir`.
    ///
    /// The property the escape tests actually protect is "no mirror was
    /// planted", not "the tree is untouched". `process_batch` creates the owner
    /// directory before it can canonicalize a parent for the containment check,
    /// so an empty `repos_dir/<owner>` is expected debris on a rejected row and
    /// asserting on it measures that side effect instead of the escape.
    fn mirrors_under(dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(next) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&next) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "git") {
                    found.push(path.to_string_lossy().into_owned());
                } else if path.is_dir() && !path.is_symlink() {
                    stack.push(path);
                }
            }
        }
        found.sort();
        found
    }

    /// Run one `process_batch` against `repos_dir`, cloning the test config and
    /// overriding only the repo root.
    async fn run_batch(state: &crate::state::AppState, repos_dir: &Path) {
        let mut cfg = (*state.config).clone();
        cfg.repos_dir = repos_dir.to_path_buf();
        process_batch(
            &state.db,
            &cfg,
            &Keypair::generate(),
            None,
            &reqwest::Client::new(),
        )
        .await;
    }

    /// Use a rooted path without a Windows drive prefix in the remote fixture.
    /// The destination still resolves on the temp directory's current drive,
    /// while the remote's relative path contains no illegal colon component.
    fn absolute_slug_path(path: &Path) -> String {
        assert!(path.is_absolute());
        path.components()
            .filter(|part| !matches!(part, std::path::Component::Prefix(_)))
            .collect::<std::path::PathBuf>()
            .to_string_lossy()
            .replace('\\', "/")
    }

    #[sqlx::test]
    async fn process_batch_rejects_slug_escaping_repos_dir(pool: PgPool) {
        // The verified escape from #272: `PathBuf::join` discards everything
        // accumulated before an absolute component, so `repos_dir/a` joined with
        // `/…/nest/escape.git` resolves to `/…/nest/escape.git`, outside the root.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        // `nest` does not exist yet, so both it and the mirror inside it are
        // proof the write left repos_dir. git clone removes the destination it
        // fails on but leaves the parent it created, so assert on both.
        let outside = TempDir::new().unwrap();
        let escape_dir = outside.path().join("nest");
        let escape_path = absolute_slug_path(&escape_dir);
        let slug = format!("a/{escape_path}/escape");
        let escape_target = escape_dir.join("escape.git");

        // Serve the composed URL for real, so a run without the guard genuinely
        // clones outside the root rather than merely failing at git.
        let rel = format!("a{escape_path}/escape");
        let (_remote, peer_url) = rooted_remote(&[&rel]);

        let did = "did:key:z6MkAttacker";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, &slug, did).await;

        run_batch(&state, &repos_dir).await;

        assert!(
            !escape_target.exists(),
            "mirror written outside repos_dir at {}",
            escape_target.display()
        );
        assert!(
            !escape_dir.exists(),
            "parent directory created outside repos_dir at {}",
            escape_dir.display()
        );
        assert_eq!(sync_status(&pool, &slug).await, "failed");
        // What this test measures, verified by mutation rather than assumed: the
        // slug rule and the containment check are each independently sufficient
        // for this input, so removing either one alone leaves it green, and it
        // goes red only when both are gone (observed: "mirror written outside
        // repos_dir"). It is the end-to-end property, not a probe for one layer.
        // Each layer has its own witness elsewhere: `./hello` in
        // process_batch_rejects_malformed_slugs isolates the slug rule (it
        // resolves back inside repos_dir, so containment approves it), and the
        // two symlink tests isolate containment (no character rule can see a
        // symlink). Assert on mirrors rather than on an empty repos_dir, because
        // the owner directory is created before containment has a parent to
        // canonicalize, so its presence is expected debris on a rejected row and
        // asserting on it would make this flip on a side effect instead.
        assert!(
            mirrors_under(&repos_dir).is_empty(),
            "no mirror may be planted inside repos_dir"
        );
    }

    #[sqlx::test]
    async fn process_batch_rejects_malformed_slugs(pool: PgPool) {
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        // Every slug's composed remote URL is served as a real bare repo, so a
        // run without the guard actually writes the mirror instead of dying at
        // git. `demo` has no separator and is caught by the pre-existing arm.
        let slugs = ["../hello", "./hello", "../../etc/evil", "a/../../x", "demo"];
        let (_remote, peer_url) = rooted_remote(&slugs);

        let did = "did:key:z6MkAttacker";
        seed_local_peer(&pool, did, &peer_url).await;
        for slug in slugs {
            enqueue(&state.db, slug, did).await;
        }

        run_batch(&state, &repos_dir).await;

        for slug in slugs {
            assert_eq!(sync_status(&pool, slug).await, "failed", "slug {slug}");
        }
        // `./hello` lands inside repos_dir; the other three land beside it.
        assert!(
            dir_entries(&repos_dir).is_empty(),
            "repos_dir must stay empty"
        );
        assert_eq!(dir_entries(home.path()), vec!["repos".to_string()]);
    }

    #[sqlx::test]
    async fn process_batch_still_fails_row_without_a_peer(pool: PgPool) {
        // The pre-existing no-peer arm still fires first. Without a peer row a
        // slug test would be green before the guard exists and prove nothing.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        enqueue(&state.db, "z6Mkfoo/hello", "did:key:z6MkNoPeer").await;

        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "failed");
        assert!(dir_entries(&repos_dir).is_empty());
    }

    #[sqlx::test]
    async fn process_batch_mirrors_a_valid_slug(pool: PgPool) {
        // Must-not-break, and the control that keeps the rejection tests above
        // from passing vacuously: this harness can mirror successfully.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;

        let mirror = repos_dir.join("z6Mkfoo").join("hello.git");
        assert!(mirror.is_dir(), "mirror missing at {}", mirror.display());
        assert!(object_count(&mirror) > 0, "mirror has no objects");
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");

        let disk: (String,) = sqlx::query_as("SELECT disk_path FROM repos WHERE id = $1")
            .bind("z6Mkfoo/hello")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(disk.0, mirror.to_str().unwrap());
    }

    // ── canonical containment before the git call (issue #272) ───────────────

    /// Every ref in `repo`, as one string, for a before/after comparison.
    #[cfg(unix)]
    fn refs_of(repo: &Path) -> String {
        let out = Command::new("git")
            .args(["-C", repo.to_str().unwrap(), "for-each-ref"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    async fn requeue(pool: &PgPool, repo: &str) {
        sqlx::query("UPDATE sync_queue SET status = 'pending' WHERE repo = $1")
            .bind(repo)
            .execute(pool)
            .await
            .unwrap();
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn process_batch_rejects_a_symlinked_owner_directory(pool: PgPool) {
        // The slug is textually valid, so U1's character rules pass it. The
        // escape is on disk: repos_dir/z6Mkfoo is a symlink out of the root, so
        // the clone would land outside repos_dir. Only canonical containment
        // sees this.
        use std::os::unix::fs::symlink;
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let outside = TempDir::new().unwrap();
        let target = outside.path().join("owner");
        std::fs::create_dir_all(&target).unwrap();
        symlink(&target, repos_dir.join("z6Mkfoo")).unwrap();

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkAttacker";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;

        assert!(
            dir_entries(&target).is_empty(),
            "wrote through the owner symlink into {}",
            target.display()
        );
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "failed");
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn process_batch_rejects_a_symlinked_mirror_path(pool: PgPool) {
        // The leaf case a parent-only canonicalize misses: the owner directory
        // is real and canonicalizes clean, but the mirror itself is a symlink to
        // a bare repo outside repos_dir. `local_path.exists()` follows the link,
        // so the fetch branch would run `git -C <link>` and overwrite the linked
        // repo's refs under the mirror refspec.
        use std::os::unix::fs::symlink;
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        let owner_dir = repos_dir.join("z6Mkfoo");
        std::fs::create_dir_all(&owner_dir).unwrap();

        // The victim is a mirror clone, which is what this node's own mirrors
        // are: `remote.origin.fetch = +refs/*:refs/*`, so a fetch through the
        // link force-overwrites every ref. Its content differs from the peer's
        // repo, so the overwrite is visible.
        let (outside_td, outside_url) = bare_remote(&[("outside.txt", b"outside\n")]);
        let outside_bare = outside_td.path().join("victim.git");
        g(
            &[
                "clone",
                "-q",
                "--mirror",
                &outside_url,
                outside_bare.to_str().unwrap(),
            ],
            outside_td.path(),
        );
        let refs_before = refs_of(&outside_bare);
        assert!(
            !refs_before.is_empty(),
            "outside repo has no refs to protect"
        );
        symlink(&outside_bare, owner_dir.join("hello.git")).unwrap();

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkAttacker";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;

        // The ref is the property under protection, so assert it before status.
        assert_eq!(
            refs_of(&outside_bare),
            refs_before,
            "refs of the linked-to repo outside repos_dir were rewritten"
        );
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "failed");
    }

    #[sqlx::test]
    async fn process_batch_clones_when_the_owner_directory_is_missing(pool: PgPool) {
        // Must-not-break, first clone: the mirror path does not exist yet, which
        // is the case a candidate-only canonicalize would reject outright. That
        // rejection is total loss of mirroring, so it gets its own test.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        assert!(
            !repos_dir.join("z6Mkfoo").exists(),
            "owner dir must be absent"
        );

        run_batch(&state, &repos_dir).await;

        let mirror = repos_dir.join("z6Mkfoo").join("hello.git");
        assert!(mirror.is_dir(), "mirror missing at {}", mirror.display());
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");
    }

    #[sqlx::test]
    async fn process_batch_fetches_into_an_existing_mirror(pool: PgPool) {
        // Must-not-break, fetch: the second sync of the same repo takes the
        // exists() branch and must still pull new objects through it.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let (remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;
        let mirror = repos_dir.join("z6Mkfoo").join("hello.git");
        assert!(mirror.is_dir(), "first sync did not clone");
        let before = object_count(&mirror);

        // Add a commit to the peer's bare repo so the fetch has work to do.
        let origin = remote.path().join("origin");
        let bare = remote
            .path()
            .join("r1")
            .join("r2")
            .join("root")
            .join("z6Mkfoo")
            .join("hello");
        std::fs::write(origin.join("b.txt"), b"second\n").unwrap();
        g(&["add", "."], &origin);
        g(&["commit", "-qm", "second"], &origin);
        g(&["push", "-q", bare.to_str().unwrap(), "HEAD"], &origin);

        requeue(&pool, "z6Mkfoo/hello").await;
        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");
        assert!(
            object_count(&mirror) > before,
            "fetch pulled nothing into the existing mirror"
        );
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn process_batch_leaves_the_row_pending_when_the_mirror_cannot_be_inspected(
        pool: PgPool,
    ) {
        // An I/O failure is transient, not hostile. `dequeue_pending_syncs`
        // selects only pending rows, so marking failed here would permanently
        // retire a legitimate repo over one EACCES.
        use std::os::unix::fs::PermissionsExt;
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        let owner_dir = repos_dir.join("z6Mkfoo");
        std::fs::create_dir_all(&owner_dir).unwrap();
        std::fs::set_permissions(&owner_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Probe by trying to CREATE inside the unreadable directory. Probing with
        // symlink_metadata on a child that was never created returns Err for
        // every user (ENOENT unprivileged, ENOENT as root), so that branch could
        // never fire and the guard it looks like was not there at all.
        if std::fs::create_dir(owner_dir.join("probe")).is_ok() {
            std::fs::set_permissions(&owner_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            panic!(
                "this test needs a user the mode bits actually restrict; it is the only \
                 coverage for leaving the row pending on an I/O error, and passing it as \
                 root would prove nothing. Run the suite unprivileged."
            );
        }

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "pending");

        // The condition clears and the very same row syncs on the next pass.
        std::fs::set_permissions(&owner_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");
        assert!(owner_dir.join("hello.git").is_dir());
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn process_batch_leaves_the_row_pending_when_the_owner_dir_cannot_be_created(
        pool: PgPool,
    ) {
        // Same reasoning for the create_dir_all at the call site: a read-only
        // repos_dir is an operator condition, not a hostile slug.
        use std::os::unix::fs::PermissionsExt;
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        std::fs::set_permissions(&repos_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::create_dir(repos_dir.join("probe")).is_ok() {
            std::fs::set_permissions(&repos_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::remove_dir(repos_dir.join("probe")).unwrap();
            // Fail rather than return: cargo swallows stderr for a passing test,
            // so an early return here would report "ok" on a root runner while
            // exercising nothing, and the pending-vs-failed contract would ship
            // unverified from that point on.
            panic!(
                "this test needs a user the mode bits actually restrict; \
                 run the suite unprivileged."
            );
        }

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "pending");

        std::fs::set_permissions(&repos_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");
        assert!(repos_dir.join("z6Mkfoo").join("hello.git").is_dir());
    }

    #[sqlx::test]
    async fn process_batch_terminally_fails_when_a_file_occupies_the_owner_path(pool: PgPool) {
        // A plain file at `repos_dir/<owner>` makes `create_dir_all` fail with
        // `AlreadyExists`, and retrying cannot change that. Before this was
        // classified permanent the row stayed pending and, because
        // `dequeue_pending_syncs` is oldest-first over a fixed batch, ten such
        // rows held the whole window and starved every healthy repo behind them.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let owner_path = repos_dir.join("z6Mkfoo");
        std::fs::write(&owner_path, b"not a directory\n").unwrap();

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "failed");
        // Terminal, not merely skipped: the row leaves the pending set, so it
        // can never come back as a poison item.
        assert!(state.db.dequeue_pending_syncs(10).await.unwrap().is_empty());
        run_batch(&state, &repos_dir).await;
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "failed");

        // The occupied path is left exactly as it was, and no mirror landed.
        assert_eq!(
            std::fs::read(&owner_path).unwrap(),
            b"not a directory\n".to_vec()
        );
        assert!(mirrors_under(home.path()).is_empty());
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn process_batch_terminally_fails_when_a_dangling_symlink_occupies_the_owner_path(
        pool: PgPool,
    ) {
        // Same `AlreadyExists` classification through a different filesystem
        // state: `mkdir` returns EEXIST and `is_dir()` is false because the
        // link resolves to nothing.
        use std::os::unix::fs::symlink;
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let owner_path = repos_dir.join("z6Mkfoo");
        symlink(home.path().join("no-such-target"), &owner_path).unwrap();

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "z6Mkfoo/hello", did).await;

        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "failed");
        assert!(state.db.dequeue_pending_syncs(10).await.unwrap().is_empty());
        run_batch(&state, &repos_dir).await;
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "failed");

        // The link is untouched and its target was never created on our behalf.
        assert!(owner_path.is_symlink());
        assert!(!home.path().join("no-such-target").exists());
        assert!(mirrors_under(home.path()).is_empty());
    }

    /// Enqueue a row and pin its `enqueued_at`, so batch ordering in the
    /// starvation tests is fixed rather than dependent on how fast the loop
    /// runs. Two rows enqueued in the same microsecond would otherwise order
    /// arbitrarily.
    #[cfg(unix)]
    async fn enqueue_at(db: &Db, pool: &PgPool, repo: &str, did: &str, enqueued_at: &str) {
        enqueue(db, repo, did).await;
        sqlx::query("UPDATE sync_queue SET enqueued_at = $1 WHERE repo = $2")
            .bind(enqueued_at)
            .bind(repo)
            .execute(pool)
            .await
            .unwrap();
    }

    /// An owner directory that exists but denies traversal. `create_dir_all`
    /// returns Ok (mkdir gets EEXIST and `is_dir()` succeeds, since that stat
    /// only needs +x on repos_dir), so this defers at `path_within_root`
    /// instead — the stall path that survives the AlreadyExists
    /// classification, which is what keeps the starvation tests load-bearing.
    #[cfg(unix)]
    fn make_stuck_owner(repos_dir: &Path, owner: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = repos_dir.join(owner);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::create_dir(dir.join("probe")).is_ok() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            // Fail rather than return: cargo swallows stderr for a passing
            // test, so an early return would report "ok" on a root runner while
            // exercising nothing, and the head-of-line contract would ship
            // unverified from that point on.
            panic!(
                "this test needs a user the mode bits actually restrict; it is the only \
                 coverage for a stuck batch yielding to a healthy row, and passing it as \
                 root would prove nothing. Run the suite unprivileged."
            );
        }
        dir
    }

    #[cfg(unix)]
    fn unstick(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn a_full_batch_of_stuck_rows_does_not_starve_a_healthy_one(pool: PgPool) {
        // Ten rows that defer forever, exactly filling the batch, with one
        // healthy row queued behind them. Ordering by enqueued_at alone means
        // the stuck ten are permanently the oldest and the healthy row is never
        // dequeued at all, on any number of polls.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let stuck = make_stuck_owner(&repos_dir, "z6Mkstuck");

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        for i in 0..10 {
            enqueue_at(
                &state.db,
                &pool,
                &format!("z6Mkstuck/r{i}"),
                did,
                &format!("2026-07-29T00:00:{i:02}Z"),
            )
            .await;
        }
        enqueue_at(
            &state.db,
            &pool,
            "z6Mkfoo/hello",
            did,
            "2026-07-29T00:01:00Z",
        )
        .await;

        run_batch(&state, &repos_dir).await;
        // Pin the premise before the yield: the stuck rows must actually fill
        // the first batch. Without this the test would still pass if the batch
        // size ever grew past the stuck set, having quietly stopped exercising
        // head-of-line yield at all.
        assert_eq!(
            sync_status(&pool, "z6Mkfoo/hello").await,
            "pending",
            "the first poll must be consumed by the stuck rows"
        );
        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");
        assert!(repos_dir.join("z6Mkfoo").join("hello.git").is_dir());
        // The stuck rows yielded their slot; they did not get retired for it.
        assert_eq!(sync_status(&pool, "z6Mkstuck/r0").await, "pending");

        unstick(&stuck);
    }

    #[cfg(unix)]
    #[sqlx::test]
    async fn a_stuck_set_larger_than_the_batch_still_yields(pool: PgPool) {
        // 25 stuck rows against a batch size of 10. The healthy row lands
        // within ceil(26/10) = 3 polls, which is the bound the PR claims;
        // the batch-sized case above is the easiest one and would pass under a
        // fix that only rotated a single full window.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();
        let stuck = make_stuck_owner(&repos_dir, "z6Mkstuck");

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        seed_local_peer(&pool, did, &peer_url).await;
        for i in 0..25 {
            enqueue_at(
                &state.db,
                &pool,
                &format!("z6Mkstuck/r{i}"),
                did,
                &format!("2026-07-29T00:00:{i:02}Z"),
            )
            .await;
        }
        enqueue_at(
            &state.db,
            &pool,
            "z6Mkfoo/hello",
            did,
            "2026-07-29T00:01:00Z",
        )
        .await;

        // Two polls cannot reach it: 25 stuck rows are ahead of it and the
        // batch is 10. Asserting that keeps the ceil(N/10) claim honest rather
        // than just asserting it eventually lands.
        run_batch(&state, &repos_dir).await;
        run_batch(&state, &repos_dir).await;
        assert_eq!(
            sync_status(&pool, "z6Mkfoo/hello").await,
            "pending",
            "25 stuck rows must still be ahead of it after two polls"
        );
        run_batch(&state, &repos_dir).await;

        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");
        // Rotated, not retired: yielding the slot must not settle the row.
        assert_eq!(sync_status(&pool, "z6Mkstuck/r0").await, "pending");
        assert_eq!(sync_status(&pool, "z6Mkstuck/r24").await, "pending");

        unstick(&stuck);
    }

    #[sqlx::test]
    async fn process_batch_does_not_repick_a_failed_row(pool: PgPool) {
        // `mark_sync_failed` is terminal: `dequeue_pending_syncs` selects only
        // pending rows, so a rejected slug never becomes a poison item.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let (_remote, peer_url) = rooted_remote(&["../hello"]);
        let did = "did:key:z6MkAttacker";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, "../hello", did).await;

        run_batch(&state, &repos_dir).await;
        assert_eq!(sync_status(&pool, "../hello").await, "failed");
        assert!(state.db.dequeue_pending_syncs(10).await.unwrap().is_empty());

        run_batch(&state, &repos_dir).await;
        assert_eq!(sync_status(&pool, "../hello").await, "failed");
        assert_eq!(dir_entries(home.path()), vec!["repos".to_string()]);
    }

    // ── committed attack probes from the #272 investigation ──────────────────

    #[sqlx::test]
    async fn queued_escape_slug_cannot_plant_a_mirror_outside_repos_dir(pool: PgPool) {
        // The worker half of #272, committed in its attack form. The row goes
        // into sync_queue directly rather than through notify, because that is
        // the case the boundary check cannot cover: rows queued before the fix
        // existed, plus the gossip and trigger writers, which also enqueue a
        // peer-controlled slug. `a/<abs>/gitlawb-probe` used to reach
        // PathBuf::join, whose absolute second component discards repos_dir and
        // puts the mirror at /<abs>/gitlawb-probe.git.
        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let outside = TempDir::new().unwrap();
        let escape_dir = outside.path().join("nest");
        let escape_path = absolute_slug_path(&escape_dir);
        let slug = format!("a/{escape_path}/gitlawb-probe");
        let escape_target = escape_dir.join("gitlawb-probe.git");

        // Two things this fixture must get right or the test is green for the
        // wrong reason. The peer row is mandatory: process_batch resolves the
        // origin URL before it looks at the slug, so an unseeded row dies at the
        // no-peer arm and would pass with the worker guard reverted. And the
        // composed remote {peer_url}/{slug} is served as a real bare repo, so a
        // run without the guard genuinely clones outside the root instead of
        // just failing at git. Db::upsert_peer cannot seed this row: it gates on
        // is_public_http_url, which rejects file://.
        let rel = format!("a{escape_path}/gitlawb-probe");
        let (_remote, peer_url) = rooted_remote(&[&rel]);
        let did = "did:key:z6MkAttacker";
        seed_local_peer(&pool, did, &peer_url).await;
        enqueue(&state.db, &slug, did).await;

        run_batch(&state, &repos_dir).await;

        assert!(
            !escape_target.exists(),
            "mirror written outside repos_dir at {}",
            escape_target.display()
        );
        // git clone removes the destination when the clone fails but leaves the
        // parent it created, so the .git path alone can pass vacuously.
        assert!(
            !escape_dir.exists(),
            "parent directory created outside repos_dir at {}",
            escape_dir.display()
        );
        // Mirrors, not entries: the owner directory is created before the
        // containment check has a parent to canonicalize, so it is expected
        // debris on a rejected row. Asserting repos_dir is empty would make this
        // flip on that side effect rather than on an escape.
        //
        // Like its sibling above, this is the end-to-end property. The slug rule
        // and containment are each sufficient here, so it goes red only when
        // both are removed; that was observed, with the mirror written outside
        // repos_dir. Per-layer isolation lives in the `./hello` case and the two
        // symlink tests.
        assert!(
            mirrors_under(&repos_dir).is_empty(),
            "no mirror may be planted inside repos_dir"
        );
        assert_eq!(sync_status(&pool, &slug).await, "failed");
    }

    #[sqlx::test]
    async fn notify_to_mirror_still_works_end_to_end_for_a_valid_slug(pool: PgPool) {
        // Positive control for the two #272 attack tests: the same unsigned
        // notify route an attacker reaches still carries a well-formed slug all
        // the way to a mirror on disk. Without it, both attack tests could be
        // green because the chain is broken rather than because the guards hold.
        use tower::ServiceExt as _;

        let state = crate::test_support::test_state(pool.clone()).await;
        let home = TempDir::new().unwrap();
        let repos_dir = home.path().join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let (_remote, peer_url) = rooted_remote(&["z6Mkfoo/hello"]);
        let did = "did:key:z6MkOrigin";
        // Direct insert for the same reason as above: upsert_peer rejects file://.
        seed_local_peer(&pool, did, &peer_url).await;

        let body = serde_json::json!({
            "repo": "z6Mkfoo/hello",
            "ref_name": "refs/heads/main",
            "new_sha": "0".repeat(40),
            "node_did": did,
        })
        .to_string();
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/v1/sync/notify")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "198.51.100.50:5000"
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        ));
        let resp = crate::server::build_router(state.clone())
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        run_batch(&state, &repos_dir).await;

        let mirror = repos_dir.join("z6Mkfoo").join("hello.git");
        assert!(mirror.is_dir(), "mirror missing at {}", mirror.display());
        assert!(object_count(&mirror) > 0, "mirror has no objects");
        assert_eq!(sync_status(&pool, "z6Mkfoo/hello").await, "done");
    }

    /// The import-exemption predicate is bytewise over both node-managed
    /// namespaces and nothing else. Non-UTF-8 bytes never match (git accepts
    /// them, so a lossy decode could false-exempt). Narrowing either prefix
    /// turns these red.
    #[test]
    fn gitlawb_import_exemption_covers_both_namespaces_by_bytes() {
        for exempt in [
            &b"refs/gitlawb/requests/550e8400-e29b-41d4-a716-446655440000"[..],
            &b"refs/gitlawb/issues/abc123"[..],
        ] {
            assert!(
                gitlawb_ref_is_exempt(exempt),
                "import must keep {}",
                String::from_utf8_lossy(exempt)
            );
        }
        for pruned in [
            &b"refs/gitlawb/evil"[..],
            &b"refs/gitlawb"[..],
            &b"refs/gitlawbfoo"[..],
            &b"refs/heads/main"[..],
            &b""[..],
            // Raw 0xFF byte: never an exempt prefix, always pruned.
            &b"refs/gitlawb/\xffvil"[..],
        ] {
            assert!(
                !gitlawb_ref_is_exempt(pruned),
                "import must prune {}",
                String::from_utf8_lossy(pruned)
            );
        }
    }

    /// End-to-end prune on a scratch bare repo: a planted non-exempt
    /// `refs/gitlawb/*` blob ref is deleted, exempt `requests/`/`issues/`
    /// blob refs and content refs survive. Removing the prune call from
    /// `clone_repo`/`fetch_repo` leaves the evil ref in place, which is what
    /// wedges serving on mirrors — this test plants exactly that state and
    /// proves the prune removes it.
    #[test]
    fn prune_removes_non_exempt_gitlawb_refs_and_keeps_exempt() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        rt.block_on(async {
            let td = TempDir::new().unwrap();
            let work = td.path().join("work");
            let bare = td.path().join("m.git");
            std::fs::create_dir_all(&work).unwrap();
            // A real commit for the content branch (branch refs must point
            // at commits; the evil/exempt refs below point at blobs).
            std::fs::write(work.join("f.txt"), b"x\n").unwrap();
            let run_work = |args: &[&str]| {
                assert!(
                    Command::new("git")
                        .args(args)
                        .current_dir(&work)
                        .status()
                        .unwrap()
                        .success(),
                    "git {args:?} failed"
                );
            };
            run_work(&["init", "-q"]);
            run_work(&["config", "user.email", "t@t"]);
            run_work(&["config", "user.name", "t"]);
            run_work(&["add", "f.txt"]);
            run_work(&["commit", "-qm", "init"]);
            assert!(
                Command::new("git")
                    .args([
                        "clone",
                        "-q",
                        "--bare",
                        work.to_str().unwrap(),
                        bare.to_str().unwrap()
                    ])
                    .current_dir(td.path())
                    .status()
                    .unwrap()
                    .success(),
                "git clone --bare failed"
            );
            let run = |args: &[&str]| {
                assert!(
                    Command::new("git")
                        .args(args)
                        .current_dir(&bare)
                        .status()
                        .unwrap()
                        .success(),
                    "git {args:?} failed"
                );
            };
            let run_out = |args: &[&str]| {
                let out = Command::new("git")
                    .args(args)
                    .current_dir(&bare)
                    .output()
                    .unwrap();
                assert!(out.status.success(), "git {args:?} failed");
                out.stdout
            };
            run(&["init", "-q", "--bare", "."]);
            std::fs::write(bare.join("blob-body"), b"marker\n").unwrap();
            let blob = String::from_utf8_lossy(&run_out(&["hash-object", "-w", "blob-body"]))
                .trim()
                .to_string();
            // The clone carries the content branch; plant the evil ref and
            // both exempt refs (all blob-pointing, like node metadata).
            run(&["update-ref", "refs/gitlawb/evil", &blob]);
            run(&["update-ref", "refs/gitlawb/requests/r1", &blob]);
            run(&["update-ref", "refs/gitlawb/issues/i1", &blob]);

            prune_non_exempt_gitlawb_refs(&bare)
                .await
                .expect("prune succeeds");

            let raw_refs = run_out(&["for-each-ref", "--format=%(refname)"]);
            let refs = String::from_utf8_lossy(&raw_refs);
            let set: std::collections::HashSet<&str> = refs
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            assert!(
                !set.contains("refs/gitlawb/evil"),
                "non-exempt blob ref must be pruned, still present: {set:?}"
            );
            for keep in ["refs/gitlawb/requests/r1", "refs/gitlawb/issues/i1"] {
                assert!(set.contains(keep), "{keep} must survive the prune: {set:?}");
            }
            assert!(
                set.iter().any(|r| r.starts_with("refs/heads/")),
                "content branch ref must survive the prune: {set:?}"
            );
        });
    }

    /// `show-ref` line parser: 40-hex SHA-1 and 64-hex SHA-256 lines yield
    /// the refname, empty lines yield None, and anything else-shaped errors
    /// (the caller fails the sync rather than skipping into an unpruned
    /// wedge). Reverting to a 40-only width check turns the sha256 case red.
    #[test]
    fn show_ref_line_parser_accepts_both_hash_widths_and_rejects_junk() {
        // 40-hex SHA-1 line.
        let sha1_line = format!("{} refs/gitlawb/evil", "a".repeat(40));
        assert_eq!(
            show_ref_refname(sha1_line.as_bytes()).unwrap(),
            Some(b"refs/gitlawb/evil".as_slice())
        );
        // 64-hex SHA-256 line (a sha256 mirror inherits the width).
        let sha256_line = format!("{} refs/gitlawb/evil", "b".repeat(64));
        assert_eq!(
            show_ref_refname(sha256_line.as_bytes()).unwrap(),
            Some(b"refs/gitlawb/evil".as_slice())
        );
        // Non-UTF-8 refname passes through as exact bytes.
        let mut raw = vec![b'c'; 40];
        raw.extend_from_slice(b" refs/gitlawb/\xffvil");
        assert_eq!(
            show_ref_refname(&raw).unwrap(),
            Some(b"refs/gitlawb/\xffvil".as_slice())
        );
        // Trailing newline residue.
        assert_eq!(show_ref_refname(b"").unwrap(), None);
        // No space, short sha, non-hex sha, empty refname: all errors.
        let bads: Vec<Vec<u8>> = vec![
            b"nospaceshere".to_vec(),
            format!("{}refs/x", "a".repeat(40)).into_bytes(),
            [b'z'; 40]
                .iter()
                .chain(b" refs/x".iter())
                .copied()
                .collect(),
            format!("{} ", "a".repeat(40)).into_bytes(),
            format!("{} refs/x", "a".repeat(41)).into_bytes(),
        ];
        for bad in &bads {
            assert!(
                show_ref_refname(bad).is_err(),
                "malformed show-ref line must error, not skip"
            );
        }
    }

    /// Pruning a path that is not a repo errors. Two shapes: a missing path
    /// fails `rev-parse` outright (exit 128), while a plain subdirectory of
    /// a repo would otherwise enumerate the ancestor's refs — covered by the
    /// identity test below. Either way the prune refuses instead of pruning
    /// the wrong repo or silently skipping an evil ref.
    #[test]
    fn prune_on_non_repo_path_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        rt.block_on(async {
            let err =
                prune_non_exempt_gitlawb_refs(Path::new("/tmp/gitlawb-definitely-not-a-repo-xyz"))
                    .await
                    .expect_err("non-repo path must fail the prune, not skip it");
            assert!(
                err.to_string().contains("not a git repo")
                    || err.to_string().contains("does not resolve"),
                "unexpected error shape: {err:#}"
            );
        });
    }

    /// Identity check: pruning a plain subdirectory of a repo refuses instead
    /// of enumerating the ancestor. `git -C` on the child exits 0 from
    /// `show-ref` with the ANCESTOR's refs, so without the
    /// `rev-parse --absolute-git-dir` identity check the delete loop would
    /// enumerate and delete the wrong repository's refs. Deleting the check
    /// makes the prune succeed and removes the ancestor's evil ref — both
    /// assertions go red.
    #[test]
    fn prune_on_non_repo_child_of_repo_refuses_and_touches_nothing() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        rt.block_on(async {
            let td = TempDir::new().unwrap();
            let ancestor = td.path().join("ancestor.git");
            std::fs::create_dir_all(&ancestor).unwrap();
            let run_ancestor = |args: &[&str]| {
                assert!(
                    Command::new("git")
                        .args(args)
                        .current_dir(&ancestor)
                        .status()
                        .unwrap()
                        .success(),
                    "git {args:?} failed"
                );
            };
            run_ancestor(&["init", "-q", "--bare", "."]);
            // Blob target for the planted ref (mirrors the node-metadata shape).
            std::fs::write(ancestor.join("blob-body"), b"marker\n").unwrap();
            let out = Command::new("git")
                .args(["hash-object", "-w", "blob-body"])
                .current_dir(&ancestor)
                .output()
                .unwrap();
            assert!(out.status.success(), "git hash-object failed");
            let blob = String::from_utf8_lossy(&out.stdout).trim().to_string();
            run_ancestor(&["update-ref", "refs/gitlawb/evil", &blob]);

            // A plain child directory: not itself a repo.
            let child = ancestor.join("not-a-repo");
            std::fs::create_dir_all(&child).unwrap();

            let err = prune_non_exempt_gitlawb_refs(&child)
                .await
                .expect_err("pruning a non-repo child must refuse, not enumerate the ancestor");
            assert!(
                err.to_string().contains("not itself a repo"),
                "refusal must name the identity mismatch, got: {err:#}"
            );

            // The ancestor's evil ref is untouched.
            let refs_out = Command::new("git")
                .args(["for-each-ref", "--format=%(refname)"])
                .current_dir(&ancestor)
                .output()
                .unwrap();
            let refs = String::from_utf8_lossy(&refs_out.stdout);
            assert!(
                refs.lines().any(|l| l.trim() == "refs/gitlawb/evil"),
                "ancestor evil ref must survive the refused prune"
            );
        });
    }

    /// sha256 mirror: a 64-hex `show-ref` line parses and the planted ref is
    /// pruned. A 40-only parser skips every line and leaves the evil ref.
    #[test]
    fn prune_parses_sha256_show_ref_and_prunes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        rt.block_on(async {
            let td = TempDir::new().unwrap();
            let bare = td.path().join("m256.git");
            std::fs::create_dir_all(&bare).unwrap();
            let run = |args: &[&str]| {
                assert!(
                    Command::new("git")
                        .args(args)
                        .current_dir(&bare)
                        .status()
                        .unwrap()
                        .success(),
                    "git {args:?} failed"
                );
            };
            let run_out = |args: &[&str]| {
                let out = Command::new("git")
                    .args(args)
                    .current_dir(&bare)
                    .output()
                    .unwrap();
                assert!(out.status.success(), "git {args:?} failed");
                out.stdout
            };
            run(&["init", "-q", "--bare", "--object-format=sha256", "."]);
            std::fs::write(bare.join("blob-body"), b"marker\n").unwrap();
            let blob = String::from_utf8_lossy(&run_out(&["hash-object", "-w", "blob-body"]))
                .trim()
                .to_string();
            assert_eq!(
                blob.len(),
                64,
                "sanity: sha256 repo must mint 64-hex objects"
            );
            run(&["update-ref", "refs/gitlawb/evil", &blob]);
            run(&["update-ref", "refs/gitlawb/issues/i1", &blob]);

            prune_non_exempt_gitlawb_refs(&bare)
                .await
                .expect("prune succeeds on a sha256 repo");

            let raw_refs = run_out(&["for-each-ref", "--format=%(refname)"]);
            let refs = String::from_utf8_lossy(&raw_refs);
            let set: std::collections::HashSet<&str> = refs
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            assert!(
                !set.contains("refs/gitlawb/evil"),
                "evil ref must be pruned from sha256 mirror: {set:?}"
            );
            assert!(
                set.contains("refs/gitlawb/issues/i1"),
                "exempt ref must survive: {set:?}"
            );
        });
    }

    /// Prune failures defer the queue row (stays `pending` for the next
    /// tick); deterministic prune refusals and any other sync error fail it
    /// terminally. Deleting the `downcast_ref::<PruneFailed>` arm restores
    /// terminal failure and turns the first assertion red.
    /// Prune failures defer the queue row (stays `pending` for the next
    /// tick); deterministic prune refusals and any other sync error fail it
    /// terminally. Deleting the `downcast_ref::<PruneFailed>` arm restores
    /// terminal failure and turns the first assertion red.
    ///
    /// The wrapper below is what the clone/fetch call sites run through:
    /// a `PruneInvalid` from the helper must still downcast as
    /// `PruneInvalid` afterwards (not stringified into `PruneFailed`),
    /// and anything else must arrive as `PruneFailed`.
    #[test]
    fn wrap_prune_error_preserves_deterministic_type() {
        let invalid = wrap_prune_error(anyhow::anyhow!(PruneInvalid("x".to_string())));
        assert!(
            invalid.downcast_ref::<PruneInvalid>().is_some(),
            "deterministic refusal must survive the call-site wrap"
        );
        assert!(
            invalid.downcast_ref::<PruneFailed>().is_none(),
            "deterministic refusal must not also read as transient"
        );
        let transient = wrap_prune_error(anyhow::anyhow!("boom"));
        assert!(
            transient.downcast_ref::<PruneFailed>().is_some(),
            "generic failure must arrive as transient"
        );
        assert!(
            transient.downcast_ref::<PruneInvalid>().is_none(),
            "generic failure must not read as deterministic"
        );
    }

    #[sqlx::test]
    async fn prune_failure_defers_row_other_failures_fail_it(pool: PgPool) {
        let state = crate::test_support::test_state(pool).await;
        let item = |id: &str| crate::db::SyncQueueItem {
            id: id.to_string(),
            repo: "z6Mkfoo/hello".to_string(),
            node_did: "did:key:z6MkOrigin".to_string(),
            ref_name: "refs/heads/main".to_string(),
            new_sha: "0".repeat(40),
            cid: None,
            status: "pending".to_string(),
            enqueued_at: chrono::Utc::now().to_rfc3339(),
        };
        async fn status_of(pool: &sqlx::PgPool, id: &str) -> String {
            let row: (String,) = sqlx::query_as("SELECT status FROM sync_queue WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .unwrap();
            row.0
        }
        // Seed three pending rows directly (enqueue_sync mints random ids).
        for id in ["sync-prune-defer", "sync-prune-invalid", "sync-other-fail"] {
            sqlx::query(
                "INSERT INTO sync_queue (id, repo, node_did, ref_name, new_sha, cid, status, enqueued_at)
                 VALUES ($1, $2, $3, $4, $5, NULL, 'pending', $6)",
            )
            .bind(id)
            .bind("z6Mkfoo/hello")
            .bind("did:key:z6MkOrigin")
            .bind("refs/heads/main")
            .bind("0".repeat(40))
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(state.db.pool())
            .await
            .unwrap();
        }

        handle_sync_item_error(
            &state.db,
            &item("sync-prune-defer"),
            "http://origin.example",
            anyhow::anyhow!(PruneFailed("boom".to_string())),
        )
        .await;
        assert_eq!(
            status_of(state.db.pool(), "sync-prune-defer").await,
            "pending",
            "prune failure must leave the row pending for retry"
        );

        handle_sync_item_error(
            &state.db,
            &item("sync-other-fail"),
            "http://origin.example",
            anyhow::anyhow!("boom"),
        )
        .await;
        assert_eq!(
            status_of(state.db.pool(), "sync-other-fail").await,
            "failed",
            "non-prune failure must fail the row"
        );

        // Deterministic refusal: no retry can clear it, so it fails
        // terminally instead of spinning every tick forever.
        handle_sync_item_error(
            &state.db,
            &item("sync-prune-invalid"),
            "http://origin.example",
            anyhow::anyhow!(PruneInvalid("not itself a repo".to_string())),
        )
        .await;
        assert_eq!(
            status_of(state.db.pool(), "sync-prune-invalid").await,
            "failed",
            "deterministic prune refusal must fail the row, not defer forever"
        );
    }
}
