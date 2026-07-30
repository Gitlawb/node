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

/// The batch's remaining wall-clock, or `None` once it is spent, after logging
/// the truncation exactly once.
///
/// Shaped like `api::ipfs`'s `budget_gate` on purpose: the nonzero-ness rides in
/// the returned value, so every call site must consume it as
/// `let Some(x) = ... else { break }` and a zero `Duration` can never reach a
/// request as its timeout.
fn batch_budget_gate(deadline: Instant, pinned: usize, unattempted: usize) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        tracing::warn!(
            pinned,
            unattempted,
            "IPFS pin batch deadline reached; the remaining objects are left unpinned"
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
/// object's bytes.
///
/// # What `batch_budget` does and does not bound
///
/// The loop holds a `pin_semaphore` permit and that pool defers rather than
/// sheds, so the hold has to be bounded by something other than the pusher's
/// object count. Two things here are:
///
/// - this loop's own wall-clock: the deadline is taken once at loop start and
///   checked at the top of every iteration, so no object's work begins with zero
///   budget left. It is a gate, not a hard ceiling, since a started iteration
///   still runs to completion;
/// - each HTTP add: `pin_git_object` is handed the remainder measured at the top
///   of the iteration as its per-request timeout, which is what lets one large
///   healthy upload run past the shared client's 10s default without letting the
///   batch run forever. The DB check and the git read spend a little of that
///   remainder before the request starts, so the add can finish marginally after
///   the deadline.
///
/// Three things are NOT bounded, and the gate cannot fix any of them:
///
/// - the git read. `store::read_object` composes two bare
///   `std::process::Command::output()` calls with no timeout and no
///   process-group reaping, and this loop does not run it under
///   `spawn_blocking`, so one hung `git cat-file` overruns the deadline and
///   blocks a runtime worker thread while it does.
/// - the DB round-trips (`is_pinned`, `record_pinned_cid`).
/// - the pool. `api::repos` acquires the same `pin_semaphore` for the Pinata
///   replication task and holds it across a full git re-derivation plus
///   `pinata::pin_new_objects`, neither of which has a deadline. This change
///   bounds this loop's hold, not the semaphore's worst-case queue.
///
/// # Truncation semantics
///
/// A batch stopped at the deadline leaves its remaining objects unpinned, and
/// nothing sweeps them up afterwards. There is no reconciliation pass over
/// `pinned_cids`; recovery is opportunistic, happening only if some later push
/// on the repo takes the full-scan fallback (`push_delta::list_all_objects`) and
/// re-derives the whole object set, which then re-offers the skipped OIDs.
///
/// The twin in `pinata.rs` mirrors this loop's shape but NOT its bound: it has
/// no batch deadline and no per-request override, so the two are no longer at
/// parity here. Everything else about the shape (the skip-if-pinned check, the
/// warn-and-continue arm, the returned pairs) still changes in lockstep.
///
/// Returns a list of `(sha256_hex, cid)` pairs for objects pinned this call.
pub async fn pin_new_objects(
    ipfs_api: &str,
    repo_path: &std::path::Path,
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
        // never started with zero budget left. The remainder becomes this add's
        // request timeout below.
        let Some(budget_left) = batch_budget_gate(deadline, pinned.len(), total - attempted) else {
            break;
        };
        // Skip if already pinned
        match db.is_pinned(&sha).await {
            Ok(true) => continue,
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
        match pin_git_object(ipfs_api, &sha, &data, Some(budget_left)).await {
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
            pin_new_objects(&endpoint, &repo_path, oids, &db, Duration::from_secs(90)),
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
            pin_new_objects(&endpoint, &repo_path, oids, &db, Duration::from_secs(60)),
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
}
