//! IPFS pinning integration for gitlawb-node.
//!
//! After a git push lands, each new git object is pinned to a local Kubo node
//! via its HTTP API (`/api/v0/add`). Objects already recorded in the
//! `pinned_cids` DB table are skipped to avoid duplicate work.
//!
//! If `ipfs_api` is empty the functions are no-ops, so the node works fine
//! without a local IPFS daemon.

use anyhow::Result;
use gitlawb_core::cid::Cid;
use std::time::Duration;

/// Attempts (including the first) for a transient DB-record retry.
const PIN_RECORD_ATTEMPTS: u32 = 3;
/// Backoff between DB-record retry attempts.
const PIN_RECORD_BACKOFF: Duration = Duration::from_millis(50);

/// Run an idempotent DB-record operation with a bounded retry so a sub-second
/// transient error does not silently leave the pin-source set permanently
/// incomplete. The resolver treats a nonempty below-cap source set as complete,
/// so a dropped `record_pin_source`/`record_pinned_cid` makes `GET /ipfs/{cid}`
/// 404 a valid public copy. Every wrapped insert is idempotent (`ON CONFLICT DO
/// NOTHING` / provenance-preserving upsert), so re-running is safe. On exhausted
/// attempts the last error is returned and the caller keeps its warn — behavior
/// degrades to the pre-retry state, not worse. Process death mid-retry or a DB
/// outage outlasting the backoff horizon leaves the same residual hole (no
/// persisted marker to reconcile from at startup), retired only by a future
/// reconciliation sweep. Runs inside the already-detached post-push task, so the
/// backoff adds no push latency.
async fn retry_db_record<F, Fut>(mut op: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt >= PIN_RECORD_ATTEMPTS {
                    return Err(e);
                }
                tokio::time::sleep(PIN_RECORD_BACKOFF).await;
                attempt += 1;
            }
        }
    }
}

/// Pin a single git object to the local IPFS/Kubo node.
///
/// - `ipfs_api`: base URL of the Kubo HTTP API, e.g. `http://127.0.0.1:5001`.
///   If empty the function returns `Ok("")` immediately.
/// - `sha256_hex`: the git SHA-256 hex object ID (used only for logging).
/// - `data`: raw git object content bytes (same bytes used for CID computation).
///
/// Returns the CID string on success, or `""` when IPFS is not configured.
pub async fn pin_git_object(ipfs_api: &str, sha256_hex: &str, data: &[u8]) -> Result<String> {
    if ipfs_api.is_empty() {
        return Ok(String::new());
    }

    // Compute the expected CIDv1 from the content bytes
    let expected_cid = Cid::from_git_object_bytes(data).to_string();

    let url = format!(
        "{}/api/v0/add?cid-version=1&raw-leaves=true&pin=true",
        ipfs_api.trim_end_matches('/')
    );

    // Build multipart form with the object data
    let part = reqwest::multipart::Part::bytes(data.to_vec())
        .file_name("object")
        .mime_str("application/octet-stream")?;
    let form = reqwest::multipart::Form::new().part("file", part);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .multipart(form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("IPFS add request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "IPFS /api/v0/add returned {status}: {body}"
        ));
    }

    // Kubo returns newline-delimited JSON; we only care about the last object
    // (there's typically just one for a single-file add).
    let body = resp.text().await?;
    let cid = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            v["Hash"].as_str().map(|s| s.to_string())
        })
        .next_back()
        .unwrap_or(expected_cid.clone());

    tracing::debug!(sha256 = %sha256_hex, %cid, "pinned git object to IPFS");
    Ok(cid)
}

/// Fetch raw bytes for a CID from the local Kubo node (`/api/v0/cat`).
pub async fn cat(ipfs_api: &str, cid: &str) -> Result<Vec<u8>> {
    if ipfs_api.is_empty() {
        return Err(anyhow::anyhow!("IPFS not configured"));
    }
    let url = format!("{}/api/v0/cat?arg={}", ipfs_api.trim_end_matches('/'), cid);
    let resp = reqwest::Client::new().post(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("ipfs cat {cid}: {}", resp.status()));
    }
    Ok(resp.bytes().await?.to_vec())
}

/// Pin any of the given candidate git objects that are not yet recorded in
/// `pinned_cids`.
///
/// `object_list` is the already-withheld-filtered OID set to pin: the caller
/// applies `visibility_pack::replicable_objects` on the delta path or the
/// `..._fail_closed` filter on the full-scan path before calling, so this
/// function never sees a withheld blob. `repo_path` is still needed to read each
/// object's bytes. The twin in `pinata.rs` mirrors this shape — change both in
/// lockstep. `repo_id` records the pin's provenance so `GET /ipfs/{cid}` resolves
/// straight to this repo instead of scanning every repo (#173).
///
/// Returns a list of `(sha256_hex, cid)` pairs for objects pinned this call.
pub async fn pin_new_objects(
    ipfs_api: &str,
    repo_path: &std::path::Path,
    object_list: Vec<String>,
    db: &crate::db::Db,
    repo_id: &str,
) -> Vec<(String, String)> {
    if ipfs_api.is_empty() {
        return vec![];
    }

    let mut pinned = Vec::new();

    for sha in object_list {
        // Skip if already pinned — but first backfill provenance if the existing
        // pin has none. A legacy pin (recorded before repo_id existed, #173, jatmn)
        // is skipped here before record_pinned_cid ever runs, so its NULL provenance
        // would never resolve to one repo and known CIDs keep hitting the scan. The
        // backfill only sets repo_id (AND repo_id IS NULL guard preserves
        // first-pinner-owns) and never re-pins the bytes — the object is already on IPFS.
        match db.is_pinned(&sha).await {
            Ok(true) => {
                match db.provenance_for_oid(&sha).await {
                    Ok(None) => {
                        if let Err(e) = db.backfill_pin_provenance(&sha, repo_id).await {
                            tracing::warn!(sha = %sha, err = %e, "failed to backfill pin provenance");
                        }
                    }
                    Ok(Some(_)) => {}
                    Err(e) => {
                        tracing::warn!(sha = %sha, err = %e, "DB error reading pin provenance");
                    }
                }
                // F1 (#173 round 8): record this repo as an ADDITIONAL source for the
                // already-pinned object. This is the load-bearing skip-branch insert —
                // a later repo pushing a shared object hits this path (already pinned),
                // and without it `GET /ipfs/{cid}` only ever knows the first pinner, so a
                // shared object first pinned from a private/quarantined repo 404s even
                // when this repo would serve it. Bounded per object (MAX_PIN_SOURCES).
                if let Err(e) = retry_db_record(|| db.record_pin_source(&sha, repo_id)).await {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                }
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "DB error checking pinned status");
                continue;
            }
        }

        // Read raw object content
        let data = match crate::git::store::read_object(repo_path, &sha) {
            Ok(Some((_obj_type, bytes))) => bytes,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "failed to read git object for pinning");
                continue;
            }
        };

        // Pin to IPFS
        match pin_git_object(ipfs_api, &sha, &data).await {
            Ok(cid) if !cid.is_empty() => {
                // The resolver key (`pinned_cids.cid`) must be the locally-computed
                // raw-content CID, never the provider Hash: Kubo returns a dag-pb/UnixFS
                // root for objects above its block size, which does not hash the raw
                // content, so `GET /ipfs/{provider_cid}` would resolve then fail the F2
                // integrity check (list-then-404). The serve path reads bytes from git and
                // verifies them against the requested CID, so the raw CID is the correct
                // key. Mirrors the pinata twin, which already records the raw CID.
                let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(&data).to_string();
                if let Err(e) =
                    retry_db_record(|| db.record_pinned_cid(&sha, &raw_cid, Some(repo_id))).await
                {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pinned CID in DB");
                }
                // F1 (#173 round 8): also record the first pinner in pin_repo_sources so
                // every source (first and subsequent) is tried uniformly by the resolver.
                if let Err(e) = retry_db_record(|| db.record_pin_source(&sha, repo_id)).await {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                }
                // Return the provider Hash (not the resolver key), mirroring the pinata
                // twin's contract: the DB `cid` is the raw resolver key (recorded above),
                // the returned value is the provider CID. Here the return is consumed only
                // for logging, but keeping the twins structurally identical avoids drift.
                pinned.push((sha, cid));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "failed to pin git object to IPFS");
            }
        }
    }

    pinned
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // The retry helper is the load-bearing unit: it converts a sub-second
    // transient DB error at the three warn-only record sites into a landed row,
    // instead of a permanently incomplete pin-source set. These drive the helper
    // directly against a controlled closure (the record sites take a concrete
    // `&Db` over a `PgPool`, so a failing-first wrapper cannot slot in without
    // changing signatures — see U6 seam note).

    #[tokio::test]
    async fn retry_lands_after_transient_failures() {
        let calls = Cell::new(0u32);
        let result = retry_db_record(|| {
            let n = calls.get() + 1;
            calls.set(n);
            async move {
                if n < PIN_RECORD_ATTEMPTS {
                    Err(anyhow::anyhow!("transient failure on attempt {n}"))
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "retry lands the row after transient failures"
        );
        assert_eq!(
            calls.get(),
            PIN_RECORD_ATTEMPTS,
            "op is retried until it succeeds"
        );
    }

    #[tokio::test]
    async fn retry_returns_last_err_after_exhaustion() {
        let calls = Cell::new(0u32);
        let result = retry_db_record(|| {
            let n = calls.get() + 1;
            calls.set(n);
            async move { Err::<(), _>(anyhow::anyhow!("attempt {n} failed")) }
        })
        .await;

        let err = result.expect_err("all attempts fail so the last error surfaces");
        assert_eq!(
            calls.get(),
            PIN_RECORD_ATTEMPTS,
            "attempts are bounded to the cap"
        );
        assert_eq!(
            err.to_string(),
            "attempt 3 failed",
            "the LAST error is returned, not the first"
        );
    }

    // Happy path against a real DB: a single-attempt success lands the row, and a
    // redundant call is idempotent (`ON CONFLICT DO NOTHING`), so the source set
    // holds exactly one row.
    #[sqlx::test]
    async fn retry_records_pin_source_once(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.unwrap();

        let sha = "a".repeat(64);
        let repo_id = "repo-retry-1";

        retry_db_record(|| db.record_pin_source(&sha, repo_id))
            .await
            .expect("happy-path record succeeds in one attempt");
        retry_db_record(|| db.record_pin_source(&sha, repo_id))
            .await
            .expect("a redundant record is idempotent");

        let sources = db.pin_sources_for_oid(&sha).await.unwrap();
        assert_eq!(
            sources,
            vec![repo_id.to_string()],
            "exactly one source row lands under ON CONFLICT DO NOTHING"
        );
    }
}
