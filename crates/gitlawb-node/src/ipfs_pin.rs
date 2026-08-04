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
use std::time::{Duration, Instant};

/// Wall-clock ceiling on one [`pin_new_objects`] batch.
///
/// The loop runs under a `pin_semaphore` permit and that pool defers rather than
/// sheds, so without a ceiling the hold is O(N) with N (the push's object count)
/// chosen by the pusher. This bounds the drain of a saturated pool instead.
///
/// 120s is 12x the shared client's 10s whole-request ceiling, so a single large
/// healthy upload that needs more than the client default still has room to
/// finish (the per-request timeout is set to the remainder, not the default),
/// while a batch of them still cannot hold the permit indefinitely. Deliberately
/// a constant and not a config knob: the value only has to be large enough to be
/// uninteresting on a healthy node, and a knob is operator surface that would
/// have to be documented, validated, and kept meaningful.
pub const PIN_BATCH_BUDGET: Duration = Duration::from_secs(120);

/// The smallest remainder worth starting a bounded git read (or an add) with.
///
/// A 1ms remainder otherwise buys a child spawned already past its deadline, which
/// can only be reaped: the watchdog's SIGTERM grace plus its post-SIGKILL settle are
/// paid in full for work that produces nothing, once per remaining object. Breaking
/// the batch instead is the same spawn-to-reap amplification the bounded type probe
/// already refuses when it declines a confirming re-probe it cannot afford.
///
/// ~1100ms tracks `visibility_pack`'s 1s SIGTERM grace plus its 20ms settle plus
/// margin. Both of those are private to that module, so the value is named once here
/// and documented rather than guessed separately in each loop.
pub(crate) const PIN_READ_FLOOR: Duration = Duration::from_millis(1100);

/// The shared outbound client for both IPFS sinks.
///
/// `pin_new_objects` runs while holding a `pin_semaphore` permit and that pool
/// defers rather than sheds, so an unbounded await here parks the pool. A bare
/// `reqwest::Client::new()` has no timeout, which is exactly that. Built from
/// `crate::build_http_client` rather than a local builder: its docstring forbids
/// hand-rolling an equivalent, so that the redirect and timeout guarantees the
/// node's tests bind stay bound to the client every outbound path actually uses.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| crate::build_http_client().expect("failed to build production http client"))
}

/// Pin a single git object to the local IPFS/Kubo node.
///
/// - `ipfs_api`: base URL of the Kubo HTTP API, e.g. `http://127.0.0.1:5001`.
///   If empty the function returns `Ok("")` immediately.
/// - `sha256_hex`: the git SHA-256 hex object ID (used only for logging).
/// - `data`: raw git object content bytes (same bytes used for CID computation).
/// - `request_timeout`: overrides the shared client's whole-request timeout for
///   THIS request only. `RequestBuilder::timeout` replaces the client-level value
///   per request and leaks nothing to other calls on the same client, so the
///   batch loop can hand each add whatever is left of its budget without
///   loosening or tightening any other outbound path. `None` keeps the client's
///   own ceiling.
///
/// Returns the CID string on success, or `""` when IPFS is not configured.
pub async fn pin_git_object(
    ipfs_api: &str,
    sha256_hex: &str,
    data: &[u8],
    request_timeout: Option<Duration>,
) -> Result<String> {
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

    let mut req = http_client().post(&url).multipart(form);
    if let Some(t) = request_timeout {
        req = req.timeout(t);
    }

    let resp = req
        .send()
        .await
        // Keep the `reqwest::Error` as this error's source rather than
        // formatting it away. Operators reading a pin failure want the concrete
        // transport cause in the logged chain, not a single flattened line, and
        // this module's tests downcast to it to prove a silent endpoint really
        // surfaces as a timeout rather than as some other failure that happens
        // to arrive in time.
        // The context keeps the old message verbatim so the callers that log
        // this at `%e` (here, `sync.rs`, `encrypted_pin.rs`) read the same.
        .map_err(|e| {
            let msg = format!("IPFS add request failed: {e}");
            anyhow::Error::new(e).context(msg)
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "IPFS /api/v0/add returned {status}: {body}"
        ));
    }

    // Kubo returns newline-delimited JSON; we only care about the last object
    // (there's typically just one for a single-file add).
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow::anyhow!("IPFS add response body read failed: {e}"))?;
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
    let resp = http_client().post(&url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("ipfs cat {cid}: {}", resp.status()));
    }
    Ok(resp.bytes().await?.to_vec())
}

/// The batch's remaining wall-clock, or `None` once too little is left to be worth
/// starting an object's work with, after logging the truncation exactly once.
///
/// "Too little" is [`PIN_READ_FLOOR`], not zero: a remainder that cannot cover a
/// bounded git read's teardown buys a child spawned already past its deadline, and a
/// sub-millisecond per-request timeout buys a doomed add whose failure reads as an
/// endpoint fault rather than as budget truncation.
///
/// Shaped like `api::ipfs`'s `budget_gate` on purpose: the nonzero-ness rides in
/// the returned value, so every call site must consume it as
/// `let Some(x) = ... else { break }` and a zero `Duration` can never reach a
/// request as its timeout.
///
/// `sink` labels the backend in the truncation warn ("IPFS" or "Pinata"). The gate
/// is shared by both pin loops rather than copied per loop, so the two cannot drift
/// apart in how they report a truncated batch.
pub(crate) fn batch_budget_gate(
    sink: &str,
    deadline: Instant,
    pinned: usize,
    unattempted: usize,
) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left < PIN_READ_FLOOR {
        tracing::warn!(
            sink,
            pinned,
            unattempted,
            "pin batch deadline reached; the remaining objects are left unpinned"
        );
        return None;
    }
    Some(left)
}

/// Pin any of the given candidate git objects that are not yet recorded in
/// `pinned_cids`.
///
/// `object_list` is the already-withheld-filtered OID set to pin: the caller
/// applies `visibility_pack::replicable_objects` on the delta path or the
/// `..._fail_closed` filter on the full-scan path before calling, so this
/// function never sees a withheld blob. `repo_path` is still needed to read each
/// object's bytes, and `git_bin` names the binary those reads run: the production
/// callers pass the literal `"git"`, and a test passes a fake so the loop's own bound
/// can be driven with a git that never answers.
///
/// # What `batch_budget` does and does not bound
///
/// The loop holds a `pin_semaphore` permit and that pool defers rather than
/// sheds, so the hold has to be bounded by something other than the pusher's
/// object count. Three things here are:
///
/// - this loop's own wall-clock: the deadline is taken once at loop start and
///   checked at the top of every iteration, so no object's work begins with less
///   than [`PIN_READ_FLOOR`] left. It is a gate, not a hard ceiling, since a started
///   iteration still runs to completion;
/// - the git read: `store::read_object_bounded` runs under `spawn_blocking` against the
///   ABSOLUTE batch deadline (not the loop-top remainder, which the `is_pinned` round-trip
///   sitting between the two would push past it), with SIGTERM-then-SIGKILL
///   process-group teardown, so a hung `git cat-file` costs this batch its remaining
///   budget plus one watchdog teardown instead of holding the permit for the child's
///   whole lifetime and blocking a runtime worker while it does;
/// - each HTTP add: `pin_git_object` is handed the remainder measured AFTER the read
///   as its per-request timeout, which is what lets one large healthy upload run past
///   the shared client's 10s default without letting the batch run forever. Measuring
///   it after the read is what keeps the read-plus-add pair inside one budget rather
///   than up to two of them.
///
/// So the LOOP's hold is bounded by roughly `batch_budget` plus one teardown. Two
/// things inside that region still are not, and the gate cannot fix either:
///
/// - the DB round-trips (`is_pinned`, `record_pinned_cid`).
/// - the pool. `api::repos` acquires the same `pin_semaphore` for the Pinata
///   replication task and holds it across `pinata_object_list_for_refs`, a full git
///   re-derivation that runs BEFORE `pinata::pin_new_objects` is entered and whose
///   per-child timeouts carry no aggregate deadline. What is bounded is each pin
///   loop's own hold, not the permit's total hold and not the semaphore's worst-case
///   queue.
///
/// # Truncation semantics
///
/// A batch stopped at the deadline leaves its remaining objects unpinned, and
/// nothing sweeps them up afterwards. There is no reconciliation pass over
/// `pinned_cids`; recovery is opportunistic, happening only if some later push
/// on the repo takes the full-scan fallback (`push_delta::list_all_objects`) and
/// re-derives the whole object set, which then re-offers the skipped OIDs.
///
/// The twin in `pinata.rs` is back at parity on the two things that bound a
/// batch: it runs the same shared budget gate at the top of every iteration and
/// the same bounded, reaped git read. It still has no per-request override, since
/// `pinata::pin_object` takes no timeout argument and its uploads are bounded by
/// the shared client's own ceiling. Everything else about the shape (the
/// skip-if-pinned check, the fault arms, the returned pairs) changes in lockstep.
///
/// Returns a list of `(sha256_hex, cid)` pairs for objects pinned this call.
pub async fn pin_new_objects(
    ipfs_api: &str,
    repo_path: &std::path::Path,
    git_bin: &str,
    object_list: Vec<String>,
    db: &crate::db::Db,
    batch_budget: Duration,
) -> Vec<(String, String)> {
    if ipfs_api.is_empty() {
        return vec![];
    }

    let deadline = Instant::now() + batch_budget;
    let total = object_list.len();
    let mut pinned = Vec::new();

    for (attempted, sha) in object_list.into_iter().enumerate() {
        // Top of the iteration, before any of this object's work: an object is
        // never started with a remainder too small to cover a bounded read's
        // teardown. Consumed as a guard only: the read below runs against the
        // absolute batch deadline, and the add's timeout is measured again after
        // the read, so this remainder has no other consumer here.
        if batch_budget_gate("IPFS", deadline, pinned.len(), total - attempted).is_none() {
            break;
        }
        // Skip if already pinned
        match db.is_pinned(&sha).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "DB error checking pinned status");
                continue;
            }
        }

        // Read raw object content, bounded and reaped, under `spawn_blocking`: this is
        // synchronous blocking work (child spawn, pipe drain, watchdog join), so
        // calling it from the runtime task would block a worker thread for its whole
        // duration. Placement mirrors the `/ipfs` serve path; the admission guard is
        // deliberately NOT moved into the closure there, since the pin permit is not
        // held by a future a client disconnect can drop and the child is reaped on its
        // own deadline regardless.
        //
        // The read runs against the ABSOLUTE batch deadline, not against the remainder
        // measured at the top of the iteration: the `is_pinned` round-trip above sits
        // between the two, so `Instant::now() + budget_left` would land past `deadline`
        // by however long the DB took, and under a saturated pool that is the dominant
        // term. A slow DB check must not push the read's own bound out.
        let read_deadline = deadline;
        let read_path = repo_path.to_path_buf();
        let read_sha = sha.clone();
        let read_git = git_bin.to_string();
        let read = tokio::task::spawn_blocking(move || {
            crate::git::store::read_object_bounded(&read_git, &read_path, &read_sha, read_deadline)
        })
        .await;
        let data = match read {
            Ok(Ok(Some((_obj_type, bytes)))) => bytes,
            // A verified absence, and the only outcome that is not a fault.
            Ok(Ok(None)) => continue,
            // A Transient fault does NOT by itself mean the store is gone. It also
            // covers a spawn or watchdog-timeout failure of the reaped child, an
            // unaffordable confirming re-probe, and, because readability is judged FOR
            // one oid, a single unreadable `objects/<xx>` fan-out, which is 1/256 of the
            // store. So re-check store-wide before deciding what the fault costs.
            Ok(Err(e @ crate::git::store::ProbeError::Transient(_))) => {
                if !crate::git::store::object_store_readable_store_wide(repo_path) {
                    // Genuinely store-wide: every remaining object fails identically, and
                    // continuing would spawn one doomed bounded child per object and spend
                    // the batch budget reaping them.
                    tracing::warn!(
                        sha = %sha,
                        err = %e,
                        unattempted = total - attempted,
                        "object store unreadable while pinning; stopping the batch"
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
                    "transient fault reading git object for pinning; the object store is \
                     still readable store-wide, so this costs only this object"
                );
                continue;
            }
            // The store is readable and git still failed: a corrupt object, or a
            // repo-wide fault git reports immediately. Either way it is per-object
            // work that stays inside the budget, and breaking would forfeit a healthy
            // store's remaining objects over one bad one, permanently (a later
            // full-scan push re-offers the same object and breaks in the same place).
            Ok(Err(e)) => {
                tracing::warn!(sha = %sha, err = %e, "failed to read git object for pinning");
                continue;
            }
            // A panic in the read closure leaves no evidence that the failure is
            // object-scoped, so fail toward the conservative arm.
            Err(e) => {
                tracing::warn!(sha = %sha, err = %e, "bounded git read task failed; stopping the batch");
                break;
            }
        };

        // Recompute the remainder AFTER the read rather than reusing `budget_left`:
        // the read is now allowed to spend the whole remainder, so handing the add the
        // loop-top value would make the pair a hold of up to 2x the batch budget. The
        // same gate, so a remainder too small to be worth a request truncates the batch
        // with one warn instead of shedding a doomed add that logs as an endpoint fault.
        let Some(add_timeout) =
            batch_budget_gate("IPFS", deadline, pinned.len(), total - attempted)
        else {
            break;
        };

        // Pin to IPFS
        match pin_git_object(ipfs_api, &sha, &data, Some(add_timeout)).await {
            Ok(cid) if !cid.is_empty() => {
                if let Err(e) = db.record_pinned_cid(&sha, &cid).await {
                    tracing::warn!(sha = %sha, err = %e, "failed to record pinned CID in DB");
                }
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
    use std::time::Duration;

    /// Write `n` loose blobs into a fresh bare repo and return their oids.
    /// `read_object` shells to `git cat-file`, so the objects must genuinely
    /// exist on disk — a fabricated oid would `continue` past the pin call and
    /// the loop scenario below would prove nothing.
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
                        .write_all(format!("pin loop object {i}\n").as_bytes())
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

    /// A live endpoint that answers every add with `500`. Counts the requests it
    /// received so a test can tell "the loop kept going" from "the loop stopped",
    /// which the returned pin list cannot (it is empty either way). Reads the
    /// full request, headers plus the `Content-Length` body, before answering:
    /// responding early and closing would surface as a write failure on the
    /// client and turn a rejection into something else.
    async fn rejecting_endpoint(
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
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
                        // Once the headers are complete, keep reading until the
                        // declared body has arrived.
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
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                    let _ = sock.flush().await;
                });
            }
        });
        endpoint
    }

    /// A sleeping-but-live endpoint. Answers `200` with an empty body after
    /// `delays[i]` for the i-th request it accepts (the last entry repeats), so
    /// a test can make one add slow and the next fast. Drains the full request,
    /// headers plus the declared `Content-Length` body, before sleeping: exactly
    /// as in `rejecting_endpoint`, answering early and closing would surface as
    /// a write failure on the client and turn a slow-but-healthy add into a
    /// different failure shape.
    ///
    /// An empty body is a successful pin: `pin_git_object` falls back to the CID
    /// it computed from the bytes when the response carries no `Hash`.
    async fn delaying_endpoint(delays: Vec<Duration>) -> String {
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
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = sock.flush().await;
                });
            }
        });
        endpoint
    }

    /// A `tracing` sink a test can read back, so the deadline warn can be
    /// asserted on rather than assumed. Installed with `set_default`, which is
    /// thread-local and scoped to the guard, so it cannot bleed into any other
    /// test in the binary.
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

    /// The add sink must be built from the shared no-redirect client, and the
    /// per-request override must actually reach the request. Against a silent
    /// endpoint (accept succeeds, no response ever written) a bare
    /// `reqwest::Client::new()` blocks forever. With `Some(2s)` the call must
    /// come back well inside that, and as a reqwest timeout: the elapsed
    /// assertion is the real RED signal, and the outer `tokio::time::timeout`
    /// is only a wedge guard so a regression fails the suite instead of hanging
    /// it (`cargo test` has no per-test timeout). The old "no elapsed assertion
    /// because the timeout is a process-global `OnceLock`" caveat no longer
    /// holds now that `request_timeout` overrides it per call.
    #[tokio::test]
    async fn pin_git_object_against_silent_endpoint_errors_within_its_own_timeout() {
        let endpoint = crate::test_support::silent_http_endpoint().await;
        let started = std::time::Instant::now();
        let inner = tokio::time::timeout(
            Duration::from_secs(30),
            pin_git_object(
                &endpoint,
                "deadbeef",
                b"some object bytes\n",
                Some(Duration::from_secs(2)),
            ),
        )
        .await
        .expect("wedge guard: pin_git_object must return long before 30s");
        let elapsed = started.elapsed();
        let err = inner.expect_err("a silent endpoint must not surface as a successful pin");
        assert!(
            elapsed < Duration::from_secs(5),
            "the 2s per-request override must bound this call, not the client's own ceiling (took {elapsed:?})"
        );
        assert!(
            err.downcast_ref::<reqwest::Error>()
                .is_some_and(|e| e.is_timeout()),
            "a silent endpoint must surface as a reqwest timeout, preserved as the error's source: {err:#}"
        );
    }

    /// The second unhardened sink, reached from `sync.rs`. Same shape as above.
    #[tokio::test]
    async fn cat_against_silent_endpoint_errors_within_its_own_timeout() {
        let endpoint = crate::test_support::silent_http_endpoint().await;
        let inner = tokio::time::timeout(Duration::from_secs(30), cat(&endpoint, "bafkqaaa"))
            .await
            .expect(
                "cat must return before the outer 30s timeout — an unbounded client hangs here",
            );
        assert!(
            inner.is_err(),
            "a silent endpoint must surface as a transport error, not successful bytes"
        );
    }

    /// The permit-hold bound. `pin_new_objects` runs under a deferring
    /// `pin_semaphore`, so without a batch deadline the hold is O(N) with N
    /// chosen by the pusher. Five objects against an endpoint that takes 2s
    /// each, under a 5.5s budget, must stop partway: only the first two can
    /// finish inside the budget, so the batch is truncated and the remainder is
    /// left unattempted with one warn naming how many.
    ///
    /// The windows are deliberately loose. Three pins would need every add to
    /// answer in under 1.83s, which the endpoint's own 2s sleep forbids, and one
    /// pin needs only the first add to land inside 5.5s, so both bounds hold
    /// with more than a second of slack on a loaded box.
    #[sqlx::test]
    async fn pin_new_objects_stops_the_batch_at_its_deadline(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("slow.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let endpoint = delaying_endpoint(vec![Duration::from_secs(2)]).await;

        let (logs, _guard) = capture_logs();
        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                oids,
                &db,
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

    /// The must-not case, and the regression that killed the old transport
    /// classifier: an endpoint that is slow but genuinely alive must NOT cost
    /// the rest of the batch. The first add takes 13s, past the shared client's
    /// 10s ceiling, which is exactly what the classifier used to read as a dead
    /// endpoint; the second is immediate. Under a 90s budget both must pin, so
    /// this fails if the per-request timeout is left at the client default and
    /// fails if any error arm breaks the loop. Two objects, not one, because
    /// with one object "did not abandon the rest" would be vacuous.
    #[sqlx::test]
    async fn pin_new_objects_does_not_abandon_the_batch_on_a_slow_but_alive_endpoint(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("slow_alive.git");
        let oids = seed_loose_blobs(&repo_path, 2);
        let endpoint =
            delaying_endpoint(vec![Duration::from_secs(13), Duration::from_millis(0)]).await;

        let pinned = tokio::time::timeout(
            Duration::from_secs(60),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                oids,
                &db,
                Duration::from_secs(90),
            ),
        )
        .await
        .expect("wedge guard: a 13s add plus an immediate one cannot take 60s");
        assert_eq!(
            pinned.len(),
            2,
            "a slow but progressing endpoint must pin both objects: an upload past the client's \
             10s default is not a dead endpoint"
        );
    }

    /// The must-not case for the warn-and-continue arm: a live endpoint
    /// rejecting each object with `500` is a per-object failure, so the loop
    /// must still warn and continue and every object must be attempted. Without
    /// this, a `break` arm could be reintroduced and the deadline test above
    /// would not notice.
    #[sqlx::test]
    async fn pin_new_objects_continues_past_a_per_object_rejection(pool: sqlx::PgPool) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("rejecting.git");
        let oids = seed_loose_blobs(&repo_path, 4);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let endpoint = rejecting_endpoint(std::sync::Arc::clone(&requests)).await;

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                "git",
                oids,
                &db,
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("a rejecting endpoint answers immediately, so this cannot take 30s");
        assert!(pinned.is_empty(), "every add was rejected");
        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "a non-2xx rejection is per-object: all four objects must still be attempted"
        );
    }

    /// Write an executable `/bin/sh` script. Copied per module rather than shared:
    /// `store.rs` and `visibility_pack.rs` each keep their own, since their test mods
    /// are private and not reachable from here.
    #[cfg(unix)]
    fn write_script(path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).expect("write fake git");
        let mut perm = std::fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm).unwrap();
    }

    /// A `git_bin` wrapper that records every invocation's arguments and then execs
    /// the real git, so a test can tell which objects the loop actually attempted.
    /// The returned pin list cannot: it is empty both when the loop broke after one
    /// object and when it continued past all of them.
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
    /// Counts `--batch-check` invocations, not log lines and not oid occurrences: the
    /// type probe carries its oid on stdin rather than in argv, so an oid appears in
    /// the log only once an object has already got past its probe, and a healthy
    /// object costs two invocations to a faulting one's one.
    fn objects_attempted(log: &std::path::Path) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("--batch-check"))
            .count()
    }

    /// #174 F3, the finding itself: the git read runs while the `pin_semaphore`
    /// permit is held, so a wedged `git cat-file` used to hold that permit for as
    /// long as the child lived, with no deadline and no reaping, on a path a pusher
    /// drives. With the read bounded, a git that never answers costs the batch its
    /// budget plus one watchdog teardown and no more.
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
        let started = std::time::Instant::now();
        let pinned = tokio::time::timeout(
            Duration::from_secs(25),
            pin_new_objects(
                "http://127.0.0.1:9",
                &repo_path,
                fake.to_str().unwrap(),
                oids,
                &db,
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

    /// [`PIN_READ_FLOOR`] itself, which nothing else in the suite makes load-bearing: with
    /// the floor at zero every test here still passes, because they all either finish
    /// inside their budget or run it down to nothing. The dead zone is the interesting
    /// region, a remainder that is nonzero but too small to cover a bounded read's
    /// teardown, and it takes a fixture built to land in it.
    ///
    /// The arithmetic, with `r` the time one healthy read costs: a 1500ms budget and a
    /// 700ms upload leave `800 - r` at the top of the second iteration, which is below the
    /// 1100ms floor for every `r`, while the first iteration's post-read gate needs only
    /// `r <= 400ms`. So the batch must stop after exactly one object, and it stops on the
    /// FLOOR rather than on exhaustion: 800ms is still a perfectly nonzero remainder, and a
    /// zero-floor gate would happily spend it spawning a child it cannot afford to reap.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_stops_when_the_remainder_falls_below_the_read_floor(
        pool: sqlx::PgPool,
    ) {
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("floor.git");
        let oids = seed_loose_blobs(&repo_path, 3);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let endpoint = delaying_endpoint(vec![Duration::from_millis(700)]).await;

        let (logs, _guard) = capture_logs();
        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                &git_bin,
                oids,
                &db,
                Duration::from_millis(1500),
            ),
        )
        .await
        .expect("wedge guard: a 1.5s budget cannot take 30s");

        // The named property first, so a regression reddens on it rather than on a
        // downstream count that a zero floor also happens to change.
        assert_eq!(
            objects_attempted(&log),
            1,
            "a remainder below the read floor must stop the batch, not buy a bounded child \
             that can only be spawned and reaped"
        );
        assert_eq!(
            pinned.len(),
            1,
            "the first object is inside the budget and must pin: {pinned:?}"
        );
        let text = logs.text();
        assert_eq!(
            text.lines()
                .filter(|l| l.contains("pin batch deadline reached"))
                .count(),
            1,
            "the truncation must be reported exactly once: {text}"
        );
    }

    /// A store-wide fault breaks the batch instead of amplifying it. When the object
    /// store itself cannot be read every remaining object fails identically, so
    /// continuing would spawn one doomed bounded child per object and burn the budget
    /// on reaping them.
    ///
    /// The fixture looks wrong and is not: with the objects LOOSE and only
    /// `objects/pack` unreadable, git still resolves each object, but it prints an
    /// `error:` diagnostic that the probe routes to a fault before the present/missing
    /// parse, so the read reaches `classify_store_fault` and (the store being
    /// unreadable) returns `Transient`.
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
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;

        let pack_dir = repo_path.join("objects").join("pack");
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&pack_dir).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&pack_dir, perms).unwrap();
        };
        chmod(0o000);
        // Root bypasses permission bits, so witness the exact operation the probe
        // performs and skip rather than falsely fail.
        let genuinely_unreadable = std::fs::read_dir(&pack_dir).is_err();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                &git_bin,
                oids.clone(),
                &db,
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
        }
    }

    /// The failure mode the store-wide re-check exists for. A `Transient` fault does not
    /// prove the store is gone: the readability verdict is judged FOR one oid, so a single
    /// unreadable `objects/<xx>` fan-out (1/256 of the store) taints only the objects that
    /// live in it. Breaking there forfeits every remaining object over a fault that costs
    /// at most a few of them, and permanently: the documented recovery re-derives the same
    /// list and breaks at the same index.
    ///
    /// Exactly ONE fan-out dir is chmod'd, and the expected pin count is derived from the
    /// oids that actually land in it rather than assumed to be one: two seeded blobs can
    /// share a fan-out prefix, and hardcoding "four must pin" would make this test flap on
    /// a collision instead of reporting it.
    #[cfg(unix)]
    #[sqlx::test]
    async fn pin_new_objects_continues_past_one_unreadable_fanout_dir(pool: sqlx::PgPool) {
        use std::os::unix::fs::PermissionsExt;
        let db = crate::db::Db::for_testing(pool);
        db.run_migrations().await.expect("migrations");
        let tmp = tempfile::TempDir::new().unwrap();
        let repo_path = tmp.path().join("one_bad_fanout.git");
        let oids = seed_loose_blobs(&repo_path, 5);
        let log = tmp.path().join("calls.log");
        let git_bin = counting_git(tmp.path(), &log);
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;

        let prefix = oids[0][0..2].to_string();
        let tainted: Vec<String> = oids.iter().filter(|o| o[0..2] == prefix).cloned().collect();
        assert!(
            tainted.len() < oids.len(),
            "the fixture must leave healthy objects outside the tainted fan-out, or this \
             test cannot tell an object-scoped fault from a store-wide one"
        );

        let fanout = repo_path.join("objects").join(&prefix);
        let chmod = |mode: u32| {
            let mut perms = std::fs::metadata(&fanout).unwrap().permissions();
            perms.set_mode(mode);
            std::fs::set_permissions(&fanout, perms).unwrap();
        };
        chmod(0o000);
        // Root bypasses permission bits, so witness the exact operation the probe performs
        // (an open of this oid's loose path) and skip rather than falsely fail.
        let genuinely_unreadable = std::fs::File::open(fanout.join(&oids[0][2..])).is_err();

        let pinned = tokio::time::timeout(
            Duration::from_secs(30),
            pin_new_objects(
                &endpoint,
                &repo_path,
                &git_bin,
                oids.clone(),
                &db,
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("an immediate endpoint and four healthy objects cannot take 30s");
        let attempted = objects_attempted(&log);
        chmod(0o755); // restore BEFORE any assertion that can panic, so TempDir cleans up

        if genuinely_unreadable {
            assert_eq!(
                attempted,
                oids.len(),
                "one unreadable fan-out is 1/256 of the store, not the store: every object \
                 must still be attempted, got {attempted} of {}",
                oids.len()
            );
            let pinned_shas: Vec<&String> = pinned.iter().map(|(sha, _)| sha).collect();
            let expected: Vec<&String> = oids.iter().filter(|o| !tainted.contains(o)).collect();
            assert_eq!(
                pinned_shas, expected,
                "every object outside the tainted fan-out must pin, and only those"
            );
        }
    }

    /// The must-not direction of the arm above: an object-scoped fault must NOT break
    /// the batch. One corrupt loose object among healthy ones is a `Deterministic`
    /// fault (the store is readable, git still fails), and the documented recovery path
    /// cannot repair it: a later full-scan push re-offers the same object and would
    /// break at the same place, so breaking here stops the repo pinning permanently.
    ///
    /// Deliberately not the bad-config corruption, which is repo-wide: all five objects
    /// would fault and the test would pin the store-wide case rather than the
    /// object-scoped one this arm rests on.
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
        let endpoint = delaying_endpoint(vec![Duration::ZERO]).await;

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
                &endpoint,
                &repo_path,
                &git_bin,
                oids.clone(),
                &db,
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
    }
}
