//! Pinata IPFS pinning integration for Filecoin-backed warm storage.
//!
//! After git objects land on the node, this module uploads them to Pinata
//! so they are pinned off-node and available via the public IPFS gateway.
//!
//! Set `GITLAWB_PINATA_JWT` to enable. Leave empty and every call is a
//! no-op, so nodes without Pinata backing work fine.

use anyhow::Result;
use std::time::{Duration, Instant};

/// Pin a single git object's raw bytes on Pinata (v3 API).
///
/// - `client`:     shared reqwest client
/// - `upload_url`: Pinata v3 upload URL (configured via `GITLAWB_PINATA_UPLOAD_URL`)
/// - `jwt`:        Pinata bearer JWT; returns `Ok("")` immediately if empty
/// - `sha`:        git object hash hex (used as the pin name)
/// - `data`:       raw git object bytes
///
/// Returns the IPFS CID assigned by Pinata on success.
pub async fn pin_object(
    client: &reqwest::Client,
    upload_url: &str,
    jwt: &str,
    sha: &str,
    data: &[u8],
) -> Result<String> {
    if jwt.is_empty() {
        return Ok(String::new());
    }

    let filename = format!("git-{}.bin", &sha[..sha.len().min(8)]);
    let part = reqwest::multipart::Part::bytes(data.to_vec())
        .file_name(filename)
        .mime_str("application/octet-stream")?;
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("network", "public")
        .text("name", format!("git-{sha}"));

    let resp = client
        .post(upload_url)
        .bearer_auth(jwt)
        .multipart(form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Pinata request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!("Pinata returned {status}: {body}"));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse Pinata response: {e}"))?;

    // v3 response: {"data": {"cid": "...", "name": "...", ...}}
    let cid = json["data"]["cid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no 'data.cid' in Pinata response: {json}"))?
        .to_string();

    tracing::debug!(sha = %sha, %cid, "pinned git object to Pinata");
    Ok(cid)
}

/// Pin any of the given candidate git objects that haven't yet been sent to
/// Pinata.
///
/// `object_list` is the already-withheld-filtered OID set to pin: the caller
/// applies `visibility_pack::replicable_objects` on the delta path or the
/// `..._fail_closed` filter on the full-scan path before calling. `repo_path` is
/// still needed to read each object's bytes, and `git_bin` names the binary those
/// reads run: the production caller passes the literal `"git"`, and a test passes a
/// fake so the loop's own bound can be driven with a git that never answers.
/// `git_timeout` is the per-object read bound, the same value and the same role it has
/// in the twin: it bounds both the pin read and the skip branch's opportunistic repair.
/// Objects already recorded with a `pinata_cid` are skipped, and `repo_id` records the
/// pin's provenance (#173). Returns `(sha_hex, provider_cid)` pairs for each newly
/// pinned object: the provider CID is the Pinata gateway CID (used for branch->CID
/// recording and ref-update gossip), NOT the raw resolver-key CID stored in
/// `pinned_cids.cid`.
///
/// # What `batch_budget` does and does not bound
///
/// The loop runs under a `pin_semaphore` permit and that pool defers rather than
/// sheds, so the hold has to be bounded by something other than the pusher's object
/// count. Two things here are:
///
/// - this loop's own wall-clock: the deadline is taken once at loop start and
///   checked at the top of every iteration, so no object's work begins with less
///   than the read floor left. It is a gate, not a hard ceiling, since a started
///   iteration still runs to completion;
/// - the git read: `store::read_object_bounded` runs under `spawn_blocking` against the
///   earlier of the ABSOLUTE batch deadline (not the loop-top remainder, which the
///   `has_pinata_cid` round-trip sitting between the two would push past it) and this
///   object's own `git_timeout`, with SIGTERM-then-SIGKILL process-group teardown, so a
///   hung `git cat-file` costs this batch one `git_timeout` plus one watchdog teardown
///   instead of holding the permit for the child's whole lifetime and blocking a runtime
///   worker while it does.
///
/// So the LOOP's hold is bounded by roughly `batch_budget`, plus one watchdog
/// teardown and one upload (the shared client's whole-request timeout bounds the
/// upload; `pin_object` takes no per-request override). The PERMIT's hold is NOT
/// bounded by any of this: `api::repos` acquires the permit and then re-derives the
/// object list with `pinata_object_list_for_refs` BEFORE this function is entered,
/// and that walk carries no aggregate deadline. The DB round-trips
/// (`has_pinata_cid`, `record_pinata_cid`) are untimed inside the budgeted region
/// too.
///
/// The twin in `ipfs_pin.rs` is at parity with this loop on everything that bounds or
/// repairs an object: the shared budget gate, the read bounded by the earlier of the
/// batch deadline and `git_timeout`, and the skip branch's opportunistic legacy
/// provider-CID repair. Change them in lockstep: the skip-if-pinned check, the
/// provenance and source recording, the fault arms, and the budget handling.
///
/// The RETURNED PAIRS are the one deliberate divergence, and it is not drift. This side
/// pushes a pin whose DB record exhausted its retries, because this return is a real
/// input: `api::repos` builds the sha-to-cid `cid_map` from it, which drives
/// `upsert_branch_cid` and the p2p `publish_ref_update` gossip CID. The twin's return is
/// log-only, so it omits a record-failed pin rather than logging a pin the resolver
/// cannot serve. Moving this side to match would need that consumer moved first.
// Ten arguments, over clippy's threshold: the three the budget and the git seam add
// (`git_bin`, `git_timeout`, `batch_budget`) plus #173's `repo_id` are what put the read
// under test injection and under a deadline, and grouping them into a struct would only
// move the same values behind a name the twin in `ipfs_pin.rs` does not use. Same allow
// as the sibling call sites in `api::repos`.
#[allow(clippy::too_many_arguments)]
pub async fn pin_new_objects(
    client: &reqwest::Client,
    upload_url: &str,
    jwt: &str,
    repo_path: &std::path::Path,
    git_bin: &str,
    git_timeout: Duration,
    object_list: Vec<String>,
    db: &crate::db::Db,
    repo_id: &str,
    batch_budget: Duration,
) -> Vec<(String, String)> {
    if jwt.is_empty() {
        return vec![];
    }

    let deadline = Instant::now() + batch_budget;
    let total = object_list.len();
    let mut pinned = Vec::new();

    for (attempted, sha) in object_list.into_iter().enumerate() {
        // Top of the iteration, before any of this object's work: an object is never
        // started with a remainder too small to cover a bounded read's teardown. The
        // gate is shared with the IPFS loop so the two cannot drift apart in how they
        // report a truncated batch. Consumed as a guard only: the read below runs against
        // the absolute batch deadline, and `pin_object` takes no per-request override, so
        // the remainder has no other consumer here.
        if crate::ipfs_pin::batch_budget_gate("Pinata", deadline, pinned.len(), total - attempted)
            .is_none()
        {
            break;
        }

        match db.has_pinata_cid(&sha).await {
            Ok(true) => {
                // Backfill NULL first-pinner provenance from a known source, in lockstep
                // with the ipfs_pin skip branch: a pinata-only node otherwise leaves
                // pre-provenance rows' `pinned_cids.repo_id` NULL forever (grok P2-D). The
                // resolver still finds the object via the pin_repo_sources union below, so
                // this is a consistency backfill, not a correctness fix.
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
                // F1 (#173 round 8): record this repo as an additional source for the
                // already-pinned object (mirrors the ipfs_pin skip-branch insert) so the
                // resolver can serve a shared object from any pin-path source. U3 (#173):
                // retried through the SHARED helper (this was a bare call, so a single
                // transient error dropped the source outright) and, on exhaustion, marked
                // durably so the resolver keeps the bounded scan fallback for the object.
                if let Err(e) =
                    crate::ipfs_pin::retry_db_record(|| db.record_pin_source(&sha, repo_id)).await
                {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                    if let Err(e) = db.mark_pin_sources_incomplete(&sha).await {
                        tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                    }
                }
                // R8 (#173 round 10), in lockstep with the ipfs_pin skip branch:
                // opportunistically repair a legacy provider-CID row (Kubo dag-pb /
                // Pinata) to the raw-content resolver key on this re-push. Cost-gated on
                // the stored key's codec, so a non-legacy row reads no bytes. Warn-only:
                // a failure leaves the row as-is for a later re-push or the deferred
                // one-shot sweep.
                // Clamped to the batch deadline, in lockstep with the ipfs_pin twin: this
                // runs with the pin permit held, so an unclamped `git_timeout` would let
                // one wedged read hold a global pin slot for 600s against a 120s budget.
                if let Err(e) = crate::ipfs_pin::repair_legacy_provider_cid(
                    repo_path,
                    git_bin,
                    std::cmp::min(deadline, std::time::Instant::now() + git_timeout),
                    &sha,
                    db,
                )
                .await
                {
                    tracing::warn!(sha = %sha, err = %e, "failed to repair legacy provider CID");
                }
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "DB error checking pinata_cid");
                continue;
            }
        }

        // Read raw object content, bounded and reaped, under `spawn_blocking`: this is
        // synchronous blocking work (child spawn, pipe drain, watchdog join), so calling
        // it from the runtime task would block a worker thread for its whole duration.
        // Placement mirrors the `/ipfs` serve path and the IPFS pin loop.
        //
        // The read runs against the ABSOLUTE batch deadline, not against the remainder
        // measured at the top of the iteration: the `has_pinata_cid` round-trip above sits
        // between the two, so `Instant::now() + budget_left` would land past `deadline` by
        // however long the DB took, and under a saturated pool that is the dominant term.
        // A slow DB check must not push the read's own bound out.
        //
        // Bounded by the EARLIER of the batch deadline (#174) and this object's own
        // `git_timeout` (#173), the same pair the ipfs_pin twin uses. Both bounds are
        // load-bearing and neither implies the other: the batch deadline alone would let
        // ONE wedged `cat-file` hold the pin permit for the whole budget, while
        // `git_timeout` alone would let a batch of merely-slow reads run past the budget.
        // As on the twin, at SHIPPED DEFAULTS the batch deadline is the arm that binds
        // (600s git timeout against a 120s budget); the `git_timeout` arm is for an
        // operator who tightens that knob below the remaining budget.
        let read_deadline = std::cmp::min(deadline, std::time::Instant::now() + git_timeout);
        let read_path = repo_path.to_path_buf();
        let read_sha = sha.clone();
        let read_git = git_bin.to_string();
        let read = tokio::task::spawn_blocking(move || {
            crate::git::store::read_object_bounded(&read_git, &read_path, &read_sha, read_deadline)
        })
        .await;
        let data = match read {
            Ok(Ok(Some((_kind, bytes)))) => bytes,
            // A verified absence, and the only outcome that is not a fault.
            Ok(Ok(None)) => continue,
            // A Transient fault does NOT by itself mean the store is gone. It also covers
            // a spawn or watchdog-timeout failure of the reaped child, an unaffordable
            // confirming re-probe, and, because readability is judged FOR one oid, a
            // single unreadable `objects/<xx>` fan-out, which is 1/256 of the store. So
            // re-check store-wide before deciding what the fault costs.
            Ok(Err(e @ crate::git::store::ProbeError::Transient(_))) => {
                if !crate::git::store::object_store_readable_store_wide(repo_path) {
                    // Genuinely store-wide: every remaining object fails identically, and
                    // continuing would spawn one doomed bounded child per object and spend
                    // the batch budget reaping them.
                    tracing::warn!(
                        sha = %sha,
                        err = %e,
                        unattempted = total - attempted,
                        "object store unreadable while pinning to Pinata; stopping the batch"
                    );
                    break;
                }
                // The store still reads store-wide, so the fault is object-scoped or
                // transient to this read. Breaking would forfeit a healthy store's
                // remaining objects permanently: the documented recovery re-derives the
                // same list and breaks at the same index.
                tracing::warn!(
                    sha = %sha,
                    err = %e,
                    "transient fault reading git object for Pinata; the object store is \
                     still readable store-wide, so this costs only this object"
                );
                continue;
            }
            // The store is readable and git still failed: a corrupt object, or a
            // repo-wide fault git reports immediately. Either way it is per-object work
            // that stays inside the budget, and breaking would forfeit a healthy store's
            // remaining objects over one bad one, permanently (a later full-scan push
            // re-offers the same object and breaks in the same place).
            Ok(Err(e)) => {
                tracing::warn!(sha = %sha, err = %e, "failed to read git object for Pinata");
                continue;
            }
            // A panic in the read closure leaves no evidence that the failure is
            // object-scoped, so fail toward the conservative arm.
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "bounded git read task failed; stopping the batch");
                break;
            }
        };

        match pin_object(client, upload_url, jwt, &sha, &data).await {
            Ok(cid) if !cid.is_empty() => {
                // The resolver key (`pinned_cids.cid`) must be the locally-computed
                // raw-content CID, never the provider CID: Pinata wraps the bytes in
                // dag-pb/UnixFS, so its returned CID does not hash the raw content and
                // must not become an alias `/ipfs/{cid}` serves raw git bytes for (#173).
                let raw_cid = gitlawb_core::cid::Cid::from_git_object_bytes(&data).to_string();
                // U3 (#173): both records go through the shared retry helper, at parity
                // with the ipfs_pin twin. These were bare calls, so one transient DB error
                // permanently dropped a pin source.
                if let Err(e) = crate::ipfs_pin::retry_db_record(|| {
                    db.record_pinata_cid(&sha, &raw_cid, &cid, Some(repo_id))
                })
                .await
                {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pinata_cid in DB");
                }
                // F1 (#173 round 8): also record the first pinner in pin_repo_sources.
                // U3: an exhausted retry marks the set incomplete so the resolver keeps
                // the scan fallback rather than 404ing a copy it could serve.
                if let Err(e) =
                    crate::ipfs_pin::retry_db_record(|| db.record_pin_source(&sha, repo_id)).await
                {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pin source");
                    if let Err(e) = db.mark_pin_sources_incomplete(&sha).await {
                        tracing::warn!(sha = %sha, err = %e, "failed to mark pin sources incomplete");
                    }
                }
                pinned.push((sha, cid));
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "Pinata pin failed — continuing");
            }
        }
    }

    pinned
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `n` loose blobs into a fresh bare repo and return their oids. The read
    /// path shells to `git cat-file`, so the objects must genuinely exist on disk: a
    /// fabricated oid would `continue` past the upload and the loop scenarios below
    /// would prove nothing. Copied from `ipfs_pin.rs`'s test mod rather than shared,
    /// since test mods are private.
    fn seed_loose_blobs(repo_path: &std::path::Path, n: usize) -> Vec<String> {
        crate::git::store::init_bare(repo_path).expect("init bare repo");
        (0..n)
            .map(|i| {
                let mut cmd = std::process::Command::new("git");
                cmd.args(["hash-object", "-w", "--stdin"])
                    .current_dir(repo_path)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped());
                let mut child = cmd.spawn().expect("spawn git hash-object");
                {
                    use std::io::Write;
                    child
                        .stdin
                        .as_mut()
                        .expect("stdin")
                        .write_all(format!("pinata loop object {i}\n").as_bytes())
                        .expect("write stdin");
                }
                let out = child.wait_with_output().expect("hash-object output");
                assert!(
                    out.status.success(),
                    "git hash-object: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            })
            .collect()
    }

    /// A live Pinata-shaped endpoint that answers each upload with a v3 `data.cid`
    /// body after `delays[i]` for the i-th request it accepts (the last entry
    /// repeats), counting the requests it received.
    ///
    /// Hand rolled rather than driven with `mockito` like the `pin_object` tests
    /// above: mockito has no per-response delay primitive, and the batch-budget test
    /// needs uploads that are slow enough to exhaust the budget partway. Drains the
    /// full request, headers plus the declared `Content-Length` body, before
    /// sleeping: answering early and closing would surface as a write failure on the
    /// client and turn a slow-but-healthy upload into a different failure shape.
    /// Same fixture shape as `ipfs_pin.rs`'s `delaying_endpoint`.
    async fn delaying_pinata_endpoint(
        delays: Vec<Duration>,
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut seen = 0usize;
            while let Ok((mut sock, _)) = listener.accept().await {
                let delay = *delays
                    .get(seen)
                    .or_else(|| delays.last())
                    .unwrap_or(&Duration::ZERO);
                seen += 1;
                requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut acc = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        acc.extend_from_slice(&buf[..n]);
                        if let Some(hdr_end) =
                            acc.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
                        {
                            let headers = String::from_utf8_lossy(&acc[..hdr_end]).to_lowercase();
                            let len: usize = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse().ok())
                                .unwrap_or(0);
                            if acc.len() >= hdr_end + len {
                                break;
                            }
                        }
                    }
                    tokio::time::sleep(delay).await;
                    let body = br#"{"data":{"cid":"QmPinataBatchTestCid","name":"git.bin"}}"#;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.flush().await;
                });
            }
        });
        endpoint
    }

    /// A `tracing` sink a test can read back, so the truncation warn and its sink
    /// label can be asserted on rather than assumed. Installed with `set_default`,
    /// which is thread-local and scoped to the guard, so it cannot bleed into any
    /// other test in the binary.
    #[derive(Clone, Default)]
    struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLogs {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
        }
    }

    impl std::io::Write for CapturedLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogs;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (logs, guard)
    }

    /// Write an executable `/bin/sh` script. Copied per module rather than shared:
    /// `store.rs`, `visibility_pack.rs` and `ipfs_pin.rs` each keep their own, since
    /// their test mods are private and not reachable from here.
    #[cfg(unix)]
    fn write_script(path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).expect("write fake git");
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }

    /// The permit-hold bound on this branch. `pin_new_objects` runs under the same
    /// deferring `pin_semaphore` as the IPFS loop, so without a batch deadline the
    /// hold is O(N) with N chosen by the pusher. Five objects against an endpoint
    /// that takes 2s each, under a 5.5s budget, must stop partway: the batch is
    /// truncated and the remainder is left unattempted with exactly one warn naming
    /// how many, labelled for this sink.
    ///
    /// The windows are deliberately loose. Four pins would need every upload to
    /// answer in under 1.4s, which the endpoint's own 2s sleep forbids, and one pin
    /// needs only the first upload to land inside 5.5s, so both bounds hold with
    /// more than a second of slack on a loaded box.
    #[sqlx::test]
    async fn pin_new_objects_stops_the_batch_at_its_deadline(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("slow.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint = delaying_pinata_endpoint(
            vec![Duration::from_secs(2)],
            std::sync::Arc::clone(&requests),
        )
        .await;

        let (logs, _guard) = capture_logs();
        let client = reqwest::Client::new();
        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_millis(5500),
            ),
        )
        .await
        .expect("wedge guard: a 5.5s budget cannot take 30s");

        assert!(
            (1..=3).contains(&pinned.len()),
            "the batch must stop partway, not pin all five and not stall on the first: pinned {}",
            pinned.len()
        );
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            pinned.len(),
            "no upload may be issued for an object the budget stopped short of"
        );
        let text = logs.text();
        let warns: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("pin batch deadline reached"))
            .collect();
        assert_eq!(
            warns.len(),
            1,
            "the deadline must be reported exactly once for the batch, not per object: {text}"
        );
        assert!(
            warns[0].contains("Pinata"),
            "the truncation warn must name this sink, not the twin's: {}",
            warns[0]
        );
        let unattempted: usize = warns[0]
            .split("unattempted=")
            .nth(1)
            .and_then(|s| {
                s.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|d| d.parse().ok())
            })
            .unwrap_or_else(|| panic!("the deadline warn must name the unattempted count: {text}"));
        assert!(
            unattempted >= 1 && unattempted + pinned.len() <= 5,
            "unattempted={unattempted} with {} pinned is not a partial batch of five",
            pinned.len()
        );
    }

    /// #174 F3 on this branch: the git read runs while the `pin_semaphore` permit is
    /// held, so a wedged `git cat-file` used to hold that permit for as long as the
    /// child lived, with no deadline and no reaping, on a path a pusher drives. With
    /// the read bounded, a git that never answers costs the batch its budget plus one
    /// watchdog teardown and no more.
    ///
    /// The fake traps SIGTERM and sleeps a BOUNDED 30s, following the fixture in
    /// `visibility_pack.rs`: with the deadline neutralized the read would otherwise
    /// leave the blocking closure and its child alive long after the test-level
    /// timeout fires, wedging the run instead of reporting a failure. The endpoint is
    /// never reached, since no object's bytes are ever produced.
    ///
    /// The batch ends on the BUDGET, not on the fault arm: the repo is a healthy bare
    /// store, so the timeout's `Transient` verdict is object-scoped and the loop moves on,
    /// only to find the budget spent. Capturing that warn is not decoration. `tracing`
    /// caches a callsite's interest globally the first time it is hit, and a hit from a
    /// thread with no subscriber caches it as never-interested for the whole binary, which
    /// silently blinds the deadline tests running beside this one.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_returns_by_budget_with_a_hung_git(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("wedged.git");
        let oids = seed_loose_blobs(&repo_path, 3);
        let fake = tmp.path().join("hanging-git");
        write_script(&fake, "#!/bin/sh\ntrap '' TERM\necho $$ > pid\nsleep 30\n");

        let (logs, _guard) = capture_logs();
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(25),
            pin_new_objects(
                &client,
                "http://127.0.0.1:9",
                "test-jwt",
                &repo_path,
                fake.to_str().unwrap(),
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(2),
            ),
        )
        .await
        .expect(
            "a wedged git must not hold the pin permit past the batch budget: the read is \
             bounded and reaped, so this cannot reach the outer timeout",
        );
        let elapsed = started.elapsed();

        assert!(
            pinned.is_empty(),
            "a git that never answers cannot produce a pinned object: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(20),
            "elapsed {elapsed:?} must stay inside the budget plus one watchdog teardown"
        );
        let text = logs.text();
        assert_eq!(
            text.lines()
                .filter(|l| l.contains("pin batch deadline reached"))
                .count(),
            1,
            "one wedged read must spend the whole budget and stop the batch there, exactly \
             once: {text}"
        );

        // The child's process group must be gone once the call returns; a bounded read
        // that leaves the child running has only moved the hold somewhere else.
        let pid: i32 = std::fs::read_to_string(repo_path.join("pid"))
            .expect("the fake git must have recorded its pid, or it was never on the read path")
            .trim()
            .parse()
            .unwrap();
        let mut gone = false;
        for _ in 0..200 {
            // SAFETY: kill(2) with signal 0 only probes existence; ESRCH means gone.
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            gone,
            "the reaped fake git ({pid}) must not outlive the call"
        );
    }

    /// U3 scenario 5 (#173): the read is bounded by the EARLIER of the batch deadline and
    /// this object's own `git_timeout`, the same pair the ipfs_pin twin uses. The batch
    /// budget here is generous (60s) so the budget gate cannot be what ends the call: only
    /// the 1s `git_timeout` can. A wedged `git cat-file` that traps SIGTERM and sleeps 30s
    /// must therefore be reaped in the `git_timeout` order and the call must return, rather
    /// than holding the pin permit for the whole budget.
    ///
    /// RED with `let read_deadline = deadline;` (the pre-U3 bare batch deadline): the read
    /// waits out the wedged child, the call runs ~30s, and the outer 20s timeout fires.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_bounds_the_read_by_git_timeout_not_the_batch_budget(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("git-timeout.git");
        let oids = seed_loose_blobs(&repo_path, 1);
        let fake = tmp.path().join("hanging-git");
        write_script(&fake, "#!/bin/sh\ntrap '' TERM\necho $$ > pid\nsleep 30\n");

        let (_logs, _guard) = capture_logs();
        let client = reqwest::Client::new();
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(20),
            pin_new_objects(
                &client,
                "http://127.0.0.1:9",
                "test-jwt",
                &repo_path,
                fake.to_str().unwrap(),
                // The bound under test.
                Duration::from_secs(1),
                oids,
                &db,
                "repo-git-timeout",
                // Generous, so a call that ends on time ended on `git_timeout`.
                Duration::from_secs(60),
            ),
        )
        .await
        .expect(
            "the read must be bounded by git_timeout, not by the batch budget: a wedged git \
             cannot hold the pin permit for the whole 60s budget",
        );
        let elapsed = started.elapsed();

        assert!(
            pinned.is_empty(),
            "a git that never answers cannot produce a pinned object: {pinned:?}"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "elapsed {elapsed:?} must stay in the git_timeout order (1s plus one watchdog \
             teardown), not the 60s batch budget"
        );
    }

    /// A `git_bin` wrapper that records every invocation's arguments and then execs the
    /// real git, so a test can tell which objects the loop actually attempted. The returned
    /// pin list cannot: it is empty both when the loop broke after one object and when it
    /// continued past all of them. Copied from `ipfs_pin.rs`'s test mod, like the fixtures
    /// above, since test mods are private.
    #[cfg(unix)]
    fn counting_git(dir: &std::path::Path, log: &std::path::Path) -> String {
        let fake = dir.join("counting-git");
        write_script(
            &fake,
            &format!(
                "#!/bin/sh\necho \"$*\" >> {}\nexec git \"$@\"\n",
                log.display()
            ),
        );
        fake.to_str().unwrap().to_string()
    }

    /// How many objects the loop actually attempted, read off the invocation log.
    ///
    /// Counts `--batch-check` invocations, not log lines and not oid occurrences: the type
    /// probe carries its oid on stdin rather than in argv, so an oid appears in the log only
    /// once an object has already got past its probe, and a healthy object costs two
    /// invocations to a faulting one's one.
    fn objects_attempted(log: &std::path::Path) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("--batch-check"))
            .count()
    }

    /// The store-wide fault arm, the twin of the IPFS loop's. When the object store cannot
    /// be read at all every remaining object fails identically, so continuing would spawn
    /// one doomed bounded child per object and burn the batch budget on reaping them.
    ///
    /// The fixture looks wrong and is not: with the objects LOOSE and only `objects/pack`
    /// unreadable, git still resolves each object, but it prints an `error:` diagnostic
    /// that the probe routes to a fault before the present/missing parse, so the read
    /// reaches the fault classification and (the store being unreadable) returns
    /// `Transient`, which the store-wide re-check then confirms really is store-wide.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_breaks_the_batch_on_an_unreadable_store(pool: sqlx::PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("unreadable.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

        let pack_dir = repo_path.join("objects").join("pack");
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&pack_dir).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&pack_dir, perms).unwrap();
        };
        chmod(0o000);
        // Root bypasses permission bits, so witness the exact operation the probe performs
        // and skip rather than falsely fail.
        let genuinely_unreadable = std::fs::read_dir(&pack_dir).is_err();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                &git_bin,
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an immediately-faulting store cannot take 30s");
        let attempted = objects_attempted(&log);
        chmod(0o755); // restore BEFORE any assertion that can panic, so TempDir cleans up

        if genuinely_unreadable {
            assert!(
                pinned.is_empty(),
                "nothing can be pinned through a store that cannot be read: {pinned:?}"
            );
            assert_eq!(
                attempted, 1,
                "a store-wide fault must break the batch after the first object, not spawn \
                 one doomed bounded child per object: {attempted} of 5 objects were read"
            );
            assert_eq!(
                requests.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "no upload may be issued for an object whose bytes were never read"
            );
        }
    }

    /// The must-not direction of the arm above, the twin of the IPFS loop's. One corrupt
    /// loose object among healthy ones is a `Deterministic` fault (the store is readable,
    /// git still fails), and the documented recovery path cannot repair it: a later
    /// full-scan push re-offers the same object and would break at the same place, so
    /// breaking here stops the repo replicating permanently.
    ///
    /// Deliberately not the bad-config corruption, which is repo-wide: all five objects
    /// would fault and the test would pin the store-wide case rather than the object-scoped
    /// one this arm rests on.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_continues_past_a_deterministic_fault(pool: sqlx::PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("corrupt.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

        // Overwrite exactly one loose object with non-zlib garbage (0o444 by default).
        let victim = repo_path
            .join("objects")
            .join(&oids[0][0..2])
            .join(&oids[0][2..]);
        assert!(victim.is_file(), "fixture must leave the blob loose");
        let mut perms = std::fs::metadata(&victim).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&victim, perms).unwrap();
        std::fs::write(&victim, b"garbage not a zlib stream").unwrap();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                &git_bin,
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an immediate endpoint and four healthy objects cannot take 30s");

        assert_eq!(
            objects_attempted(&log),
            5,
            "an object-scoped fault must not stop the batch: every object must be read"
        );
        assert_eq!(
            pinned.len(),
            4,
            "one corrupt object must cost only itself: the other four must still pin"
        );
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "exactly the readable objects may reach the endpoint"
        );
    }

    /// The normal direction, and the dedup branch driven both ways: on a healthy
    /// store with a healthy endpoint and a generous budget every object pins and the
    /// CID is recorded, and a second call over the same list uploads nothing because
    /// `has_pinata_cid` now answers true for all of them.
    #[sqlx::test]
    async fn pin_new_objects_pins_every_object_then_skips_the_recorded_ones(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("healthy.git");
        let oids = seed_loose_blobs(&repo_path, 3);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(60),
                oids.clone(),
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an immediate endpoint and three healthy objects cannot take 30s");

        assert_eq!(pinned.len(), 3, "every healthy object must pin: {pinned:?}");
        for (i, (sha, cid)) in pinned.iter().enumerate() {
            assert_eq!(sha, &oids[i], "the pairs must carry the objects' own oids");
            assert_eq!(cid, "QmPinataBatchTestCid");
            assert!(
                db.has_pinata_cid(sha).await.unwrap(),
                "a pinned object must be recorded so the next batch skips it"
            );
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 3);

        let again = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "test-jwt",
                &repo_path,
                "git",
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("a fully deduped batch cannot take 30s");
        assert!(again.is_empty(), "already-recorded objects must be skipped");
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "the skip must happen before the upload, not after it"
        );
    }

    /// The no-op configuration still short-circuits with the budgeted signature: an
    /// empty JWT must return before any git child is spawned and before any request
    /// is issued. The `git_bin` here records every invocation, so "git was never
    /// touched" is observed rather than assumed.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_with_an_empty_jwt_touches_neither_git_nor_the_endpoint(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("unconfigured.git");
        let oids = seed_loose_blobs(&repo_path, 2);
        let log = tmp.path().join("calls.log");
        let fake = tmp.path().join("counting-git");
        write_script(
            &fake,
            &format!(
                "#!/bin/sh\necho \"$*\" >> {}\nexec git \"$@\"\n",
                log.display()
            ),
        );
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint =
            delaying_pinata_endpoint(vec![Duration::ZERO], std::sync::Arc::clone(&requests)).await;
        let client = reqwest::Client::new();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &client,
                &endpoint,
                "",
                &repo_path,
                fake.to_str().unwrap(),
                Duration::from_secs(60),
                oids,
                &db,
                "repo-merge-test",
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an unconfigured sink returns immediately");

        assert!(pinned.is_empty(), "an empty JWT pins nothing");
        assert!(
            !log.exists(),
            "no git child may be spawned when the sink is not configured"
        );
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_pin_skipped_when_jwt_empty() {
        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            "https://uploads.pinata.cloud/v3/files",
            "",
            "deadbeef",
            b"data",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "", "empty JWT must return empty CID");
    }

    #[tokio::test]
    async fn test_pin_success() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"cid":"QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG","name":"git-deadbeef.bin","size":20}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "test-jwt",
            "deadbeef00000000",
            b"raw git object bytes",
        )
        .await;

        assert!(result.is_ok(), "pin should succeed: {result:?}");
        assert_eq!(
            result.unwrap(),
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        );
        _mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_pin_auth_failure_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(401)
            .with_body(r#"{"error":"UNAUTHORIZED"}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "bad-jwt",
            "deadbeef00000000",
            b"data",
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }

    #[tokio::test]
    async fn test_pin_server_error_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(&client, &server.url(), "jwt", "deadbeef00000000", b"data").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    #[tokio::test]
    async fn test_pin_missing_cid_returns_err() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"name":"git-deadbeef.bin"}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(&client, &server.url(), "jwt", "deadbeef00000000", b"data").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no 'data.cid'"));
    }

    #[tokio::test]
    async fn test_pin_uses_bearer_auth() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("POST", "/")
            .match_header("authorization", "Bearer my-pinata-jwt")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"data":{"cid":"QmTest","name":"git-deadbeef.bin","size":4}}"#)
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let result = pin_object(
            &client,
            &server.url(),
            "my-pinata-jwt",
            "deadbeef00000000",
            b"data",
        )
        .await;

        assert!(result.is_ok());
        _mock.assert_async().await;
    }
}
