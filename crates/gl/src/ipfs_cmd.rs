//! `gl ipfs` — IPFS pin management commands.
//!
//! Communicates with the gitlawb node to list pinned CIDs and retrieve git
//! objects by their content-addressed CID.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::http::{read_body_capped, sanitize_node_msg, NodeClient};

#[derive(Args)]
pub struct IpfsArgs {
    #[command(subcommand)]
    pub cmd: IpfsCmd,
}

#[derive(Subcommand)]
pub enum IpfsCmd {
    /// List all CIDs pinned to the node's local IPFS daemon
    List {
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        /// Identity directory (default: ~/.gitlawb)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Retrieve and display a git object from the node by its CIDv1
    ///
    /// Object bytes go to stdout so the command pipes; diagnostics go to stderr.
    ///
    /// Objects pinned before the node started recording which repo they came from
    /// are found by scanning its repo inventory, and that scan stops at the node's
    /// per-request ceilings. When it stops the node answers 503 with a resume token
    /// rather than a false "not found", and this command follows it automatically:
    /// up to 8 resumes after the first request, so at most 9 calls to the node,
    /// waiting between attempts for as long as the node's Retry-After asks and never
    /// longer than 5 seconds.
    ///
    /// The whole ladder runs under a 60 second wall-clock deadline. That deadline
    /// bounds the search: each attempt gets only the time left on it to produce
    /// response headers, and it deliberately does not cover the download of an
    /// object once found. The download is not unbounded, though. The client's 30
    /// second HTTP timeout is a TOTAL request timeout, running from the moment a
    /// request starts connecting until its body has finished, so a transfer still
    /// going 30 seconds after its own request began is cut off. Waits between
    /// attempts are bounded by the time left on the deadline as well as by the 5
    /// second clamp, so the longest a run can spend on the network is about 90
    /// seconds: the deadline, plus the 30 second timeout covering the last attempt.
    /// Writing the object out is not covered by either bound, so piping into a reader
    /// that stops reading can hold the command open past that.
    ///
    /// A 429 ends the ladder immediately: the node's rate-limit window is an hour,
    /// so the wait it asks for cannot be honored inside one invocation. A transient
    /// overload (a 503 that carries no incomplete-scan code) is retried on the token
    /// already held, under the same cap, clamp and deadline. The node's per-IP
    /// fanout brake can also end a ladder well short of the cap, so automatic
    /// resumption is not a guarantee that the object will be reached.
    ///
    /// Whenever one of those bounds stops the ladder with a usable token still in
    /// hand, the command prints the token and the exact invocation that continues
    /// from it, `gl ipfs get <cid> --scan <token>`, and exits nonzero. Re-running
    /// without the token restarts the scan at the first row, reproduces the same
    /// truncation and spends the node's per-IP budget again, so the token is the
    /// only thing that makes progress. Tokens are valid for an hour.
    Get {
        /// The CIDv1 string (e.g. bafkrei...)
        cid: String,
        #[arg(long, default_value = "https://node.gitlawb.com", env = "GITLAWB_NODE")]
        node: String,
        /// Identity directory (default: ~/.gitlawb)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Resume token from a scan that stopped at a bound, as printed by a
        /// previous run that gave up with the result incomplete
        #[arg(long, value_name = "TOKEN")]
        scan: Option<String>,
    },
}

pub async fn run(args: IpfsArgs) -> Result<()> {
    match args.cmd {
        IpfsCmd::List { node, dir } => cmd_list(node, dir).await,
        IpfsCmd::Get {
            cid,
            node,
            dir,
            scan,
        } => cmd_get(cid, node, dir, scan).await,
    }
}

async fn cmd_list(node: String, dir: Option<PathBuf>) -> Result<()> {
    // #134 gates /api/v1/ipfs/pins behind auth: sign the request with the
    // caller's identity. On no identity, propagate load_keypair_from_dir's
    // error (it already names `gl identity new`) rather than a bare 401.
    let keypair = crate::identity::load_keypair_from_dir(dir.as_deref())?;
    let client = NodeClient::new(&node, Some(keypair));
    let resp = client.get_signed("/api/v1/ipfs/pins").await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("node returned {status} for pins listing: {body}");
    }
    let resp: Value = resp.json().await.context("failed to parse pins response")?;

    let pins = resp["pins"].as_array().cloned().unwrap_or_default();
    let count = resp["count"].as_u64().unwrap_or(pins.len() as u64);

    if pins.is_empty() {
        println!("No IPFS pins recorded on {node}");
        println!("(Push to a repo with GITLAWB_IPFS_API set to start pinning)");
        return Ok(());
    }

    println!("IPFS pins ({count}) on {node}");
    println!();
    for pin in &pins {
        let cid = pin["cid"].as_str().unwrap_or("?");
        let sha = pin["sha256_hex"].as_str().unwrap_or("?");
        let pinned_at = pin["pinned_at"].as_str().unwrap_or("?");
        // Trim pinned_at to date+time without subseconds
        let ts = if pinned_at.len() >= 19 {
            &pinned_at[..19]
        } else {
            pinned_at
        };
        println!("  {cid}");
        println!("    sha256: {sha}");
        println!("    pinned: {ts}");
        println!();
    }
    Ok(())
}

/// Automatic resumes attempted after the initial request when the node reports a
/// truncated legacy scan, so at most `MAX_SCAN_RESUMES + 1` node calls per invocation.
const MAX_SCAN_RESUMES: usize = 8;

/// Wall-clock budget for a whole `gl ipfs get`, resumes included.
const SCAN_DEADLINE: Duration = Duration::from_secs(60);

/// Longest single wait honored between attempts, whatever `Retry-After` asks for.
/// The node picks that number, so an unclamped sleep would let a hostile one stall
/// the client for as long as it likes.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(5);

/// Wait used when a retryable response carries no usable `Retry-After`.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(1);

/// Generous ceiling on a continuation token. Real tokens are fixed-width (668
/// base64url characters today), but the sealed layout has already changed once and
/// a rejected token is terminal, so a tight bound would silently kill resume on a
/// future version bump.
const MAX_CONTINUATION_LEN: usize = 2048;

/// Mirror a stderr diagnostic into a per-thread buffer under `cfg(test)` so the
/// command-level tests can assert on what the caller is actually told. Callers
/// see the same line either way; only the test-visible copy is conditional.
fn diag(msg: &str) {
    eprintln!("{msg}");
    #[cfg(test)]
    tests::record_diag(msg);
}

async fn cmd_get(
    cid: String,
    node: String,
    dir: Option<PathBuf>,
    scan: Option<String>,
) -> Result<()> {
    cmd_get_inner(cid, node, dir, scan, SCAN_DEADLINE, MAX_SCAN_RESUMES).await
}

/// The body of `gl ipfs get`, with the bounds and the starting continuation as
/// parameters so tests can drive the resume ladder without waiting out the shipped
/// defaults. `cmd_get` supplies those defaults.
async fn cmd_get_inner(
    cid: String,
    node: String,
    dir: Option<PathBuf>,
    continuation: Option<String>,
    deadline: Duration,
    cap: usize,
) -> Result<()> {
    // #173 (F5): the resolver now serves path-scoped objects to authorized readers,
    // so sign with an available identity like `gl ipfs list` — otherwise an owner or
    // listed reader gets the opaque anonymous 404 for content they can read.
    // `get_authed` signs when a keypair is present and falls back to unsigned.
    //
    // An explicit `--dir` is a request to use THAT identity: propagate a
    // missing/corrupt-keystore error (like `list`) instead of silently sending an
    // anonymous request the authorized reader would see as the node's opaque 404
    // (#173 review). Only the default (no `--dir`) keeps the best-effort unsigned
    // fallback, so `get` stays usable for genuinely public content.
    let keypair = match dir.as_deref() {
        Some(dir) => Some(crate::identity::load_keypair_from_dir(Some(dir))?),
        None => crate::identity::load_keypair_from_dir(None).ok(),
    };
    let client = NodeClient::new(&node, keypair);
    // #173 review (F1): the node now accepts equivalent multibase spellings,
    // including base64 CIDs (prefix 'm'), whose alphabet contains '/', '+', '='.
    // Interpolating the CID raw would make the client request (and sign)
    // `/ipfs/<prefix>/<suffix>`, which neither matches the single-segment Axum
    // route nor points at the intended target. Percent-encode the CID as exactly
    // one path segment so the signed and sent target agree and the server's
    // `Path` extractor decodes it back to the original CID.
    let encoded_cid = encode_cid_segment(&cid);

    // A caller-supplied continuation reaches the same signed target as a node-chosen
    // one, so it clears the same bar before the first request.
    let mut token = match continuation {
        Some(t) if valid_continuation(&t) => Some(t),
        Some(_) => anyhow::bail!(
            "the supplied continuation is not a resume token: \
             expected 1 to {MAX_CONTINUATION_LEN} base64url characters"
        ),
        None => None,
    };

    // One deadline for the whole ladder, captured before the first request and used
    // both as the loop's bound and as each attempt's own timeout, so no attempt can
    // start just under the deadline and then run a fresh unbounded 30s of its own.
    // That wrap covers `get_authed` only, which resolves on the response HEADERS: the
    // deadline is here to stop a slow legacy SEARCH, and extending it over the body
    // read would abort a legitimate large download whose bytes are already flowing.
    // reqwest's blanket 30s is what bounds the download instead; it is a TOTAL request
    // timeout, from the start of the request through the end of its body, so a transfer
    // slower than that from its own request's start IS cut off.
    // The composed bound that follows. The last attempt of any run starts strictly
    // before the deadline, since both checks above run first, and that same blanket 30s
    // covers its whole request, so it is over by deadline + 30s. Two reads sit under the
    // 30s and not under the deadline: `write_object`'s success read, which ends the run,
    // and `read_body_capped`'s error read, which on a retryable arm is followed by one
    // wait. That wait adds no term of its own, because it is bounded by the time LEFT on
    // the deadline as well as by the clamp. So the worst case ON THE NETWORK is
    // deadline + 30s, about 90s at the shipped defaults. `write_object`'s writes to
    // stdout are blocking and under neither bound, so a stalled consumer on the other
    // end of the pipe can outlast that; nothing here can bound a caller's own reader.
    let start = tokio::time::Instant::now();
    let mut requests = 0usize;
    loop {
        if requests > cap {
            diag(&format!(
                "warning: the node's legacy scan is still incomplete after {cap} automatic \
                 resumes; the object may sit beyond the rows scanned so far"
            ));
            surface_resume(&cid, token.as_deref());
            anyhow::bail!(
                "gave up on an incomplete scan for CID {cid} after {requests} node calls"
            );
        }
        let remaining = deadline.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(deadline_reached(&cid, token.as_deref(), deadline));
        }

        // The token joins the single `path` binding BEFORE `get_authed` signs, so the
        // signature covers the query string and the bytes signed are the bytes sent.
        // Percent-encoding is the identity over the accepted alphabet; it is here for
        // the value that is not.
        let path = match &token {
            Some(t) => format!("/ipfs/{encoded_cid}?scan={}", urlencoding::encode(t)),
            None => format!("/ipfs/{encoded_cid}"),
        };
        let resp = match tokio::time::timeout(remaining, client.get_authed(&path)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                // A transport failure ends the ladder with the held token still
                // pointing at a real position, so hand it back before propagating:
                // otherwise a connection reset mid-ladder loses the only thing that
                // makes progress on a re-run.
                surface_resume(&cid, token.as_deref());
                return Err(e).with_context(|| format!("failed to fetch CID {cid} from {node}"));
            }
            Err(_) => return Err(deadline_reached(&cid, token.as_deref(), deadline)),
        };
        requests += 1;

        // Status first, before any body read.
        let status = resp.status();
        if status.is_success() {
            return write_object(resp).await;
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // Terminal on the status alone: the fanout limiter's window is an hour, so
            // the wait it advertises cannot be honored inside one invocation, and
            // retrying only deepens the shedding the ladder itself caused.
            diag(
                "warning: the node is rate limiting this scan, so the result is incomplete; \
                 its limit window outlasts a single invocation",
            );
            surface_resume(&cid, token.as_deref());
            anyhow::bail!("node returned {status}: rate limited");
        }

        let retry_after = parse_retry_after(resp.headers());
        let body = read_body_capped(resp, 8 * 1024).await;
        let (raw, truncated) = (body.text, body.truncated);
        let read_failed = body.read_failed;
        let parsed = serde_json::from_str::<Value>(&raw).ok();
        let code = parsed.as_ref().and_then(|v| v["error"].as_str());
        let node_msg = parsed
            .as_ref()
            .and_then(|v| v["message"].as_str())
            .unwrap_or(raw.as_str());
        let offered = parsed.as_ref().and_then(|v| v["continuation"].as_str());

        // The one classification site. The node's error code picks the arm and the
        // default is terminal, so an unrecognized code can never resolve to a retry.
        let resume_with = match code {
            Some("search_incomplete") => offered
                .filter(|t| valid_continuation(t))
                .map(str::to_string),
            // A mid-ladder overload sheds a request whose permit is released at request
            // end and asks the caller back shortly, so the ladder continues on the token
            // it already holds. With no token there is nothing to resume, which falls to
            // the default arm below.
            //
            // A body that did not arrive whole is excluded from this arm, whether the
            // cap CUT it short or the read FAILED part-way. Either way it cannot parse,
            // so its code reads as absent and an oversized or broken `search_incomplete`
            // would land here and be retried on the OLD token, replaying one position
            // for every rung while the fresh continuation it offered goes unread.
            // Unclassifiable is terminal, like any unrecognized code.
            Some(_) | None
                if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    && !truncated
                    && !read_failed =>
            {
                token.clone()
            }
            _ => None,
        };

        let Some(next) = resume_with else {
            let msg = node_tail(node_msg, read_failed);
            if code == Some("search_incomplete") {
                // Naming the bound, never echoing the value: a rejected token is
                // node-chosen text and has no business in a terminal message.
                let why = if offered.is_some() {
                    // The OFFERED token is unusable, but the one already held still
                    // points at a real position, so the ladder ends with something to
                    // resume from. Surface ours, never theirs.
                    surface_resume(&cid, token.as_deref());
                    format!(
                        "the continuation it offered is not a resume token \
                         (expected 1 to {MAX_CONTINUATION_LEN} base64url characters)"
                    )
                } else {
                    // No continuation at all is the node's deliberate "the scan wrapped
                    // and finished" signal, so a resume hint here would invite a re-run
                    // that cannot find more than this one did.
                    "it offered no continuation token".to_string()
                };
                anyhow::bail!("node returned {status} with the scan incomplete and {why}: {msg}");
            }
            // Anything else stops the ladder with the held token still usable, so hand
            // it back. The exception is a definitive 404: that is an answer, and a
            // resume hint beside it would contradict it.
            if status != reqwest::StatusCode::NOT_FOUND {
                surface_resume(&cid, token.as_deref());
            }
            anyhow::bail!("node returned {status}: {msg}");
        };

        // Bounded three ways, and the deadline is the term that stops the give-up from
        // overshooting: the loop only re-checks it at the top, so a wait longer than
        // what is left would run past the deadline before anything noticed.
        let left = deadline.saturating_sub(start.elapsed());
        tokio::time::sleep(retry_after.min(MAX_RETRY_AFTER).min(left)).await;
        token = Some(next);
    }
}

/// Write a successful response: diagnostics to stderr, raw bytes to stdout so the
/// output stays pipeable.
async fn write_object(resp: reqwest::Response) -> Result<()> {
    write_object_to(resp, &mut std::io::stdout()).await
}

/// `write_object` with the sink as a parameter, so a test can read back what a
/// caller would have received on stdout. `write_object` supplies the real one.
///
/// The body is STREAMED. `resp.bytes()` buffers the whole object first, so a node
/// answering 200 with a very large body delivered fast made the client allocate all
/// of it before a byte reached stdout; the 30 second client timeout bounds how long
/// that takes, not how much it costs. Chunk-at-a-time the peak is one chunk, and the
/// sibling error read is already capped at 8 KiB.
async fn write_object_to<W: std::io::Write>(
    mut resp: reqwest::Response,
    out: &mut W,
) -> Result<()> {
    let headers = resp.headers().clone();
    if let Some(git_hash) = headers.get("x-git-hash") {
        diag(&format!(
            "x-git-hash:   {}",
            git_hash.to_str().unwrap_or("?")
        ));
    }
    if let Some(content_cid) = headers.get("x-content-cid") {
        diag(&format!(
            "x-content-cid: {}",
            content_cid.to_str().unwrap_or("?")
        ));
    }

    while let Some(chunk) = resp.chunk().await.context("failed to read response body")? {
        out.write_all(&chunk).context("failed to write to stdout")?;
    }
    // Flush explicitly rather than leaving the tail to the process-exit flush, which
    // discards its error: `gl ipfs get <cid> > object.bin` onto a full disk or a
    // closed pipe would otherwise leave a TRUNCATED file behind exit status 0, and on
    // a content-addressed fetch a silently short object is the worst possible answer.
    out.flush().context("failed to flush stdout")?;

    Ok(())
}

/// Report the wall-clock give-up and hand the caller their token back.
fn deadline_reached(cid: &str, token: Option<&str>, deadline: Duration) -> anyhow::Error {
    diag(&format!(
        "warning: the node's legacy scan is still incomplete at the {}s deadline; \
         the object may sit beyond the rows scanned so far",
        deadline.as_secs_f32()
    ));
    surface_resume(cid, token);
    anyhow::anyhow!("gave up on an incomplete scan for CID {cid} at the wall-clock deadline")
}

/// Hand back the token that still points at where the scan stopped, together with
/// the invocation that resumes from it. A bare re-run restarts at row 0, reproduces
/// the same truncation, and re-spends the caller's per-IP budget, so the token is
/// the only thing that makes progress.
fn surface_resume(cid: &str, token: Option<&str>) {
    if let Some(t) = token {
        diag(&format!(
            "resume from where this stopped: gl ipfs get {cid} --scan {t}"
        ));
    }
}

/// Render the tail of a terminal message: what the node said, sanitized, plus the
/// fact that its body did not finish arriving when that is what happened.
///
/// A read that fails mid-body is not the same as a node with nothing to say, and the
/// two used to render identically. A 500 whose body died in transit produced an empty
/// message and the terminal read `node returned 500: `, which reports the node as
/// silent when the truth is that the connection broke before it could be heard.
fn node_tail(node_msg: &str, read_failed: bool) -> String {
    let msg = sanitize_node_msg(node_msg);
    match (read_failed, msg.is_empty()) {
        (false, _) => msg,
        (true, true) => "the response body could not be read".to_string(),
        (true, false) => format!("{msg} (the response body could not be read in full)"),
    }
}

/// `Retry-After` in delta-seconds. Absent, non-numeric, or an HTTP-date all fall
/// back to one second; the caller clamps whatever comes back.
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_RETRY_AFTER)
}

/// A continuation is node-chosen and goes straight into a signed request target, so
/// accept only the alphabet the node's sealer emits. A value carrying `#`, `&`, `?`,
/// `/`, whitespace, or control bytes could make the URL reqwest parses differ from
/// the bytes signed.
fn valid_continuation(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_CONTINUATION_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Percent-encode a CID so it occupies exactly one path segment of `/ipfs/<cid>`.
/// `urlencoding::encode` escapes every byte outside the RFC 3986 unreserved set
/// (ALPHA / DIGIT / `-._~`), so the base64-CID characters that would otherwise
/// break the single-segment route — `/`, `+`, `=` — are all escaped, and the
/// server's `Path` extractor decodes the result back to the original CID (#173
/// review, F1).
fn encode_cid_segment(cid: &str) -> String {
    urlencoding::encode(cid).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    thread_local! {
        /// Test-visible copy of the stderr diagnostics `diag` emits. `#[tokio::test]`
        /// runs the future on the test's own thread, so a thread-local is enough.
        static DIAG: RefCell<String> = const { RefCell::new(String::new()) };
    }

    pub(super) fn record_diag(msg: &str) {
        DIAG.with(|d| {
            let mut d = d.borrow_mut();
            d.push_str(msg);
            // A space, not a newline: the `has_control_or_bidi` assertions run over the
            // whole telling, so a newline the harness inserts itself would make them
            // fire on ANY stderr diagnostic and turn "node text is sanitized" into
            // "nothing was printed to stderr", which R21 requires. A node-supplied
            // control character is still caught.
            d.push(' ');
        });
    }

    fn reset_diag() {
        DIAG.with(|d| d.borrow_mut().clear());
    }

    fn diag_text() -> String {
        DIAG.with(|d| d.borrow().clone())
    }

    /// Everything the caller is told about a failed get: the stderr diagnostics plus
    /// the error itself (main renders both). `{:#}` flattens the anyhow context chain
    /// onto one line, so a message carried in a context layer is still covered.
    fn told(err: &anyhow::Error) -> String {
        format!("{}{err:#}", diag_text())
    }

    /// Width of a real continuation today (see the node's scan_token module): 668
    /// base64url-no-pad characters. The tests build tokens of that width so the
    /// fixtures look like the wire, not like a placeholder.
    const TOKEN_LEN: usize = 668;

    fn token_of_len(seed: &str, len: usize) -> String {
        let mut t = String::from(seed);
        while t.len() < len {
            t.push('A');
        }
        t.truncate(len);
        t
    }

    fn make_token(seed: &str) -> String {
        token_of_len(seed, TOKEN_LEN)
    }

    /// The `scan` query value of an incoming request, if it carries one.
    fn scan_of(path_and_query: &str) -> Option<String> {
        let (_, query) = path_and_query.split_once('?')?;
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix("scan="))
            .map(str::to_string)
    }

    /// Derive the NEXT continuation from the one the client just echoed, so every
    /// response on a ladder carries a different token (a real node re-seals with a
    /// fresh nonce every time, and a fixed replayed body would hide that).
    fn next_token(echoed: Option<&str>) -> String {
        let n = echoed
            .map(|t| {
                t.trim_end_matches('A')
                    .trim_start_matches('t')
                    .parse::<usize>()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        make_token(&format!("t{}", n + 1))
    }

    /// A node message crafted to reach the terminal: a raw DEL (a control character
    /// JSON permits unescaped), a JSON-escaped ESC/CSI sequence, a raw bidi override,
    /// and a long tail so a missing length cap shows up.
    fn hostile_msg() -> String {
        format!("boom \u{7f} \\u001b[31m \u{202e} {}", "x".repeat(5000))
    }

    fn incomplete_body(continuation: Option<&str>, msg: &str) -> String {
        match continuation {
            Some(t) => {
                format!(r#"{{"error":"search_incomplete","message":"{msg}","continuation":"{t}"}}"#)
            }
            None => format!(r#"{{"error":"search_incomplete","message":"{msg}"}}"#),
        }
    }

    fn has_control_or_bidi(s: &str) -> bool {
        s.chars()
            .any(|c| c.is_control() || gitlawb_core::sanitize::is_bidi_format(c))
    }

    /// A bare re-run restarts the scan at row 0 and re-spends the caller's per-IP
    /// budget, so any "run it again" phrasing is only honest when the token that
    /// makes progress is right there with it.
    fn implies_bare_rerun(text: &str, token: &str) -> bool {
        let lower = text.to_lowercase();
        [
            "try again",
            "re-run",
            "rerun",
            "run it again",
            "retry the command",
        ]
        .iter()
        .any(|p| lower.contains(p))
            && !text.contains(token)
    }

    /// Seed a keypair into a temp dir the way `load_keypair_from_dir` expects,
    /// then return the dir handle (keeps it alive for the test's duration).
    fn seed_keystore() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let kp = gitlawb_core::identity::Keypair::generate();
        std::fs::write(
            dir.path().join("identity.pem"),
            kp.to_pem().unwrap().as_bytes(),
        )
        .unwrap();
        dir
    }

    #[tokio::test]
    async fn test_cmd_list_signs_request_and_renders_pins() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        // Happy path: signed GET to /api/v1/ipfs/pins carrying the RFC 9421
        // signature headers, node returns a populated pins body.
        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .match_header("content-digest", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"pins":[{"cid":"bafyone","sha256_hex":"abc123","pinned_at":"2026-07-02T12:00:00.123456Z"}],"count":1}"#,
            )
            .create_async()
            .await;

        cmd_list(server.url(), Some(keystore.path().to_path_buf()))
            .await
            .unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_empty_pins() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .match_header("signature", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"pins":[],"count":0}"#)
            .create_async()
            .await;

        cmd_list(server.url(), Some(keystore.path().to_path_buf()))
            .await
            .unwrap();

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_no_identity_errors_without_request() {
        let mut server = mockito::Server::new_async().await;
        // Empty keystore dir: no identity.pem present.
        let empty = tempfile::TempDir::new().unwrap();

        // The endpoint must never be hit when there is no identity.
        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .expect(0)
            .create_async()
            .await;

        let err = cmd_list(server.url(), Some(empty.path().to_path_buf()))
            .await
            .expect_err("no identity should be an error");
        assert!(
            err.to_string().contains("gl identity new")
                || err.to_string().contains("no identity found"),
            "error should name `gl identity new`, got: {err}"
        );

        m.assert_async().await;
    }

    #[tokio::test]
    async fn test_cmd_list_non_success_status_is_error_not_empty() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        // A signed request the node rejects (401) must surface as an error,
        // not be silently parsed into an empty pin list.
        let m = server
            .mock("GET", "/api/v1/ipfs/pins")
            .match_header("signature", mockito::Matcher::Any)
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"unauthorized"}"#)
            .create_async()
            .await;

        let err = cmd_list(server.url(), Some(keystore.path().to_path_buf()))
            .await
            .expect_err("non-2xx status should be an error");
        assert!(
            err.to_string().contains("401"),
            "error should mention the status, got: {err}"
        );

        m.assert_async().await;
    }

    /// #173 (F5): `gl ipfs get` must SIGN with an available identity, like
    /// `gl ipfs list`, so an owner/reader can retrieve a path-scoped object the node
    /// now resolves by CID. RED before the fix: cmd_get ignores the identity dir and
    /// sends an unsigned request, so the signature-matching mock is never hit
    /// (cmd_get errors on the unmatched 501, and m.assert fails). GREEN after: the
    /// signed request carries the RFC 9421 headers and is served 200.
    #[tokio::test]
    async fn test_cmd_get_signs_when_identity_present() {
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();

        let m = server
            .mock("GET", "/ipfs/bafkreitestcid")
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_header("x-git-hash", "abc123")
            .with_body("object bytes")
            .create_async()
            .await;

        cmd_get(
            "bafkreitestcid".to_string(),
            server.url(),
            Some(keystore.path().to_path_buf()),
            None,
        )
        .await
        .expect("signed get of a resolvable object should succeed");

        m.assert_async().await;
    }

    /// #173 (F5) must-not: a genuine anonymous denial must surface as an error, not
    /// be masked as success. With no identity dir the request is unsigned; a 404
    /// from the node must produce an Err mentioning the status.
    #[tokio::test]
    async fn test_cmd_get_anonymous_denial_is_error() {
        let mut server = mockito::Server::new_async().await;

        let m = server
            .mock("GET", "/ipfs/bafkreidenied")
            .with_status(404)
            .with_header("content-type", "text/plain")
            .with_body("no git object found")
            .create_async()
            .await;

        let err = cmd_get("bafkreidenied".to_string(), server.url(), None, None)
            .await
            .expect_err("a 404 denial must be an error, not masked success");
        assert!(
            err.to_string().contains("404"),
            "error should mention the status, got: {err}"
        );

        m.assert_async().await;
    }

    // #173 (F3): a truncated legacy scan comes back as 503 `search_incomplete` with a
    // sealed continuation token. The command must follow that token instead of
    // dead-ending, under an attempt cap, a wall-clock deadline, and a clamped
    // Retry-After, and every terminal that still holds a token must hand it back with
    // the invocation that resumes from it. The ladder fixtures answer with
    // `Retry-After: 0` so the clamped sleeps are zero and a nine-call ladder stays
    // sub-second in real time.

    /// Scenario 1. A `search_incomplete` 503 carrying a valid continuation is resumed:
    /// the second request repeats the CID with `?scan=<token>` (percent-encoding is the
    /// identity over the base64url alphabet, so the echo is byte-identical) and the
    /// content it returns is written.
    #[tokio::test]
    async fn test_cmd_get_resumes_search_incomplete_with_continuation() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");

        let m1 = server
            .mock("GET", "/ipfs/bafkreiresume")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/ipfs/bafkreiresume")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body("object bytes")
            .expect(1)
            .create_async()
            .await;

        cmd_get("bafkreiresume".to_string(), server.url(), None, None)
            .await
            .expect("a search_incomplete 503 carrying a continuation must resume, not bail");

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 2. A node that keeps truncating stops at the attempt cap: 8 automatic
    /// resumes after the initial request, 9 node calls in all. The give-up names the
    /// incomplete result and the cap, and hands back the token still held with the
    /// invocation that resumes from it.
    #[tokio::test]
    async fn test_cmd_get_resume_ladder_stops_at_attempt_cap() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();

        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body_from_request(move |req| {
                c.fetch_add(1, Ordering::SeqCst);
                let next = next_token(scan_of(req.path_and_query()).as_deref());
                incomplete_body(Some(&next), "scan truncated").into_bytes()
            })
            .expect(9)
            .create_async()
            .await;

        let err = cmd_get("bafkreicap".to_string(), server.url(), None, None)
            .await
            .expect_err("a ladder that never completes must end in an error");
        let told = told(&err);
        let held = make_token("t9");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            9,
            "cap is 8 resumes after the initial request, so exactly 9 node calls"
        );
        assert!(
            told.to_lowercase().contains("incomplete"),
            "the give-up must name the incomplete result, got: {told}"
        );
        assert!(
            told.contains(&format!("after {MAX_SCAN_RESUMES} automatic resumes")),
            "the give-up must name the resume cap in words, got: {told}"
        );
        assert!(
            told.contains(&held),
            "the still-held continuation must be surfaced, got: {told}"
        );
        assert!(
            told.contains(&format!("--scan {held}")),
            "the exact resuming invocation must be surfaced, got: {told}"
        );
        assert!(
            !implies_bare_rerun(&told, &held),
            "a bare re-run restarts at row 0, so the wording must not imply it helps: {told}"
        );

        m.assert_async().await;
    }

    /// Scenario 3. A wedged node (every response a fresh token for the same position)
    /// is indistinguishable from slow progress at the client, because tokens are
    /// nonce-randomized ciphertext. The cap is what ends it, and that is the whole
    /// assertion: the ladder stops at 9 calls with the explicit incomplete report.
    #[tokio::test]
    async fn test_cmd_get_wedged_ladder_still_stops_at_attempt_cap() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();

        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body_from_request(move |_req| {
                let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                // A distinct token every time, none of them advancing the cursor.
                incomplete_body(Some(&make_token(&format!("w{n}"))), "scan truncated").into_bytes()
            })
            .expect(9)
            .create_async()
            .await;

        let err = cmd_get("bafkreiwedged".to_string(), server.url(), None, None)
            .await
            .expect_err("a wedged ladder must end in an error");
        let told = told(&err);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            9,
            "the cap is the only bound on a wedged ladder, so exactly 9 node calls"
        );
        assert!(
            told.to_lowercase().contains("incomplete"),
            "the give-up must name the incomplete result, got: {told}"
        );

        m.assert_async().await;
    }

    /// Scenario 4. A `search_incomplete` 503 with no continuation is terminal: there is
    /// nothing to resume from, and the message says so rather than reporting a bare
    /// status. Exactly one node call.
    #[tokio::test]
    async fn test_cmd_get_search_incomplete_without_continuation_is_terminal() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;

        let m1 = server
            .mock("GET", "/ipfs/bafkreinotoken")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(incomplete_body(None, "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", mockito::Matcher::Regex("scan=".to_string()))
            .expect(0)
            .create_async()
            .await;

        let err = cmd_get("bafkreinotoken".to_string(), server.url(), None, None)
            .await
            .expect_err("a truncation with no continuation must be an error");
        let told = told(&err);

        assert!(
            told.to_lowercase().contains("continuation"),
            "the terminal must name the missing continuation, got: {told}"
        );
        assert!(
            told.contains("503"),
            "the terminal must still name the status, got: {told}"
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 5. An overload 503 on the FIRST request holds no token, so there is
    /// nothing to resume: terminal, one call, and the node's text reaches the terminal
    /// sanitized and length-capped rather than verbatim.
    #[tokio::test]
    async fn test_cmd_get_first_request_overload_503_is_terminal_and_sanitized() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;

        let m1 = server
            .mock("GET", "/ipfs/bafkreioverload")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(format!(
                r#"{{"error":"overloaded","message":"{}"}}"#,
                hostile_msg()
            ))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", mockito::Matcher::Regex("scan=".to_string()))
            .expect(0)
            .create_async()
            .await;

        let err = cmd_get("bafkreioverload".to_string(), server.url(), None, None)
            .await
            .expect_err("a first-request overload must be an error");
        let told = told(&err);

        assert!(
            !has_control_or_bidi(&told),
            "node text must be sanitized before it reaches the terminal, got: {told:?}"
        );
        assert!(
            told.chars().count() < 600,
            "node text must be length-capped, got {} chars",
            told.chars().count()
        );
        assert!(
            told.contains("503"),
            "the terminal must name the status, got: {told}"
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 6. The resumed request is signed like the first one, and the signature
    /// covers the query: the token joins the path binding before signing, so the mock
    /// matching both the `scan=` query and the RFC 9421 headers is the one served.
    #[tokio::test]
    async fn test_cmd_get_resumed_request_is_signed() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let keystore = seed_keystore();
        let t = make_token("t1");

        let m1 = server
            .mock("GET", "/ipfs/bafkreisigned")
            .match_header("signature", mockito::Matcher::Any)
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/ipfs/bafkreisigned")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .match_header("signature", mockito::Matcher::Any)
            .match_header("signature-input", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body("object bytes")
            .expect(1)
            .create_async()
            .await;

        cmd_get(
            "bafkreisigned".to_string(),
            server.url(),
            Some(keystore.path().to_path_buf()),
            None,
        )
        .await
        .expect("the resumed request must be signed and served");

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 7. An oversized, hostile `search_incomplete` body still terminates
    /// cleanly: the surfaced message is capped and free of control and bidi characters.
    #[tokio::test]
    async fn test_cmd_get_hostile_incomplete_body_is_capped_and_sanitized() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;

        let m = server
            .mock("GET", "/ipfs/bafkreihostilebody")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(incomplete_body(None, &hostile_msg()))
            .expect(1)
            .create_async()
            .await;

        let err = cmd_get("bafkreihostilebody".to_string(), server.url(), None, None)
            .await
            .expect_err("a hostile truncation body must still be an error");
        let told = told(&err);

        assert!(
            !has_control_or_bidi(&told),
            "node text must be sanitized before it reaches the terminal, got: {told:?}"
        );
        assert!(
            told.chars().count() < 600,
            "node text must be length-capped, got {} chars",
            told.chars().count()
        );

        m.assert_async().await;
    }

    /// Scenario 8. A continuation the node chose but that fails validation (`#`, a
    /// newline, `&`) never enters the signed path: terminal exactly like a missing
    /// token, no second request, and the rejected token is never echoed into the
    /// message (the bound is named instead).
    #[tokio::test]
    async fn test_cmd_get_hostile_continuation_token_is_rejected() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;

        let m1 = server
            .mock("GET", "/ipfs/bafkreihostiletoken")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"error":"search_incomplete","message":"{}","continuation":"abc#\ndef&ghi"}}"#,
                hostile_msg()
            ))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", mockito::Matcher::Regex("scan=".to_string()))
            .expect(0)
            .create_async()
            .await;

        let err = cmd_get("bafkreihostiletoken".to_string(), server.url(), None, None)
            .await
            .expect_err("a malformed continuation must be terminal");
        let told = told(&err);

        assert!(
            !told.contains("abc#") && !told.contains("def&ghi"),
            "a rejected token must never be echoed into the message, got: {told}"
        );
        assert!(
            !has_control_or_bidi(&told),
            "node text must be sanitized before it reaches the terminal, got: {told:?}"
        );
        assert!(
            told.chars().count() < 600,
            "node text must be length-capped, got {} chars",
            told.chars().count()
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 9. A mid-ladder 429 is terminal: the fanout limiter's window is an
    /// hour, so its Retry-After cannot be honored inside one invocation. The message
    /// names rate limiting (not truncation), is sanitized and capped, and the token
    /// still held comes back with the invocation that resumes from it.
    #[tokio::test]
    async fn test_cmd_get_mid_ladder_429_is_terminal_and_surfaces_token() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");

        let m1 = server
            .mock("GET", "/ipfs/bafkreithrottled")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/ipfs/bafkreithrottled")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(429)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "3600")
            .with_body(format!(
                r#"{{"error":"rate_limited","message":"{}"}}"#,
                hostile_msg()
            ))
            .expect(1)
            .create_async()
            .await;

        let err = cmd_get("bafkreithrottled".to_string(), server.url(), None, None)
            .await
            .expect_err("a mid-ladder 429 must be an error");
        let told = told(&err);

        assert!(
            told.to_lowercase().contains("rate limit"),
            "the terminal must name rate limiting, distinct from the truncation wording, got: {told}"
        );
        assert!(
            !has_control_or_bidi(&told),
            "node text must be sanitized before it reaches the terminal, got: {told:?}"
        );
        // The length bound is scoped to the error text, not to `told`: R21 requires a
        // stderr line carrying the still-held 668-character token, so no implementation
        // can keep the whole telling under 600 characters. The error text is where an
        // uncapped node body would land on this path, so the property still binds.
        let reported = format!("{err:#}");
        assert!(
            reported.chars().count() < 600,
            "node text must be length-capped, got {} chars",
            reported.chars().count()
        );
        assert!(
            told.contains(&t) && told.contains(&format!("--scan {t}")),
            "the still-held continuation and its resuming invocation must be surfaced, got: {told}"
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 10. A mid-ladder overload 503 (no `search_incomplete` code, token still
    /// held) is retried, not terminal: its three sources are transient, the node itself
    /// says to retry shortly, and nothing accumulates per IP on that path. The ladder
    /// continues on the same token and completes in three calls.
    #[tokio::test]
    async fn test_cmd_get_mid_ladder_overload_503_is_retried() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");

        let m1 = server
            .mock("GET", "/ipfs/bafkreimidoverload")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        // Both of the next two match `scan=T`; mockito serves the first one that still
        // has hits outstanding, so registration order sequences the overload then the
        // success.
        let m2 = server
            .mock("GET", "/ipfs/bafkreimidoverload")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(r#"{"error":"overloaded","message":"busy, retry shortly"}"#)
            .expect(1)
            .create_async()
            .await;
        let m3 = server
            .mock("GET", "/ipfs/bafkreimidoverload")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body("object bytes")
            .expect(1)
            .create_async()
            .await;

        cmd_get("bafkreimidoverload".to_string(), server.url(), None, None)
            .await
            .expect("a mid-ladder overload must be retried on the held token, not terminal");

        m1.assert_async().await;
        m2.assert_async().await;
        m3.assert_async().await;
    }

    /// Scenario 10b. The classification default arm with a token ALREADY HELD. Every
    /// other fixture reaches that arm token-less (scenario 5's first-request overload)
    /// or never reaches it at all (scenario 9's 429 short-circuits on the status), so
    /// the arm's terminality was certified only for the case where there was nothing
    /// to resume with anyway. Here an unknown code arrives mid-ladder on a 500, which
    /// is not the overload status, with a valid token in hand: it must still be
    /// terminal. Two calls, and the fixture stops well short of the cap so a
    /// misclassified retry shows up as a call count rather than a cap give-up.
    #[tokio::test]
    async fn test_cmd_get_mid_ladder_unknown_code_is_terminal_with_token_held() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");
        let calls = Arc::new(AtomicUsize::new(0));
        let c1 = calls.clone();
        let c2 = calls.clone();

        let m1 = server
            .mock("GET", "/ipfs/bafkreiunknowncode")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body_from_request({
                let t = t.clone();
                move |_req| {
                    c1.fetch_add(1, Ordering::SeqCst);
                    incomplete_body(Some(&t), "scan truncated").into_bytes()
                }
            })
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/ipfs/bafkreiunknowncode")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_req| {
                c2.fetch_add(1, Ordering::SeqCst);
                br#"{"error":"index_corrupt","message":"scan index unreadable"}"#.to_vec()
            })
            .expect(1)
            .create_async()
            .await;

        let err = cmd_get("bafkreiunknowncode".to_string(), server.url(), None, None)
            .await
            .expect_err("an unknown code mid-ladder must be an error");
        let told = told(&err);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "an unrecognized code with a token held must be terminal, not retried"
        );
        assert!(
            told.contains("500"),
            "the terminal must name the status, got: {told}"
        );
        // Terminal is only half of it. The ladder stopped holding a token that still
        // points at a real position, and without it the caller's only recourse is a
        // bare re-run that restarts at row 0 and re-spends the per-IP budget. Every
        // terminal that holds a usable token must hand it back.
        assert!(
            told.contains(&t) && told.contains(&format!("--scan {t}")),
            "the still-held continuation and its resuming invocation must be surfaced \
             on a mid-ladder terminal, got: {told}"
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 10c, the other reachable terminal that holds a token: rung 1 offers a
    /// valid continuation, rung 2 answers `search_incomplete` with a MALFORMED one.
    ///
    /// The offered token is unusable and must never be echoed, but the token the client
    /// already HOLDS is untouched by that rejection and still points at where the scan
    /// stopped, so it is what must come back. Distinct from scenario 4, where the node
    /// offers nothing at all: that is its deliberate "the scan wrapped and finished"
    /// signal and carries no resume hint.
    #[tokio::test]
    async fn test_cmd_get_rejected_offered_token_still_surfaces_the_held_one() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");
        let malformed = "abc#def&ghi";
        let calls = Arc::new(AtomicUsize::new(0));
        let c1 = calls.clone();
        let c2 = calls.clone();

        let m1 = server
            .mock("GET", "/ipfs/bafkreirejectedoffer")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body_from_request({
                let t = t.clone();
                move |_req| {
                    c1.fetch_add(1, Ordering::SeqCst);
                    incomplete_body(Some(&t), "scan truncated").into_bytes()
                }
            })
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/ipfs/bafkreirejectedoffer")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body_from_request(move |_req| {
                c2.fetch_add(1, Ordering::SeqCst);
                incomplete_body(Some(malformed), "scan truncated").into_bytes()
            })
            .expect(1)
            .create_async()
            .await;

        let err = cmd_get("bafkreirejectedoffer".to_string(), server.url(), None, None)
            .await
            .expect_err("a malformed offered continuation must be terminal");
        let told = told(&err);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a rejected offer is terminal, so exactly two node calls"
        );
        assert!(
            told.contains(&t) && told.contains(&format!("--scan {t}")),
            "the still-held continuation and its resuming invocation must be surfaced, \
             got: {told}"
        );
        assert!(
            !told.contains("abc#") && !told.contains("def&ghi"),
            "a rejected token must never be echoed into the message, got: {told}"
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 11. The wall-clock deadline bounds the whole loop, and it bounds each
    /// attempt's own timeout. This drives the give-up tail, where the ladder never
    /// reaches a body read, so its bound is the deadline plus one clamped wait (a
    /// stalled body composes differently; see the note in `cmd_get_inner`). Injected
    /// through the seam because the shipped 60s is unreachable
    /// under the 5s clamp and 8 resumes.
    #[tokio::test]
    async fn test_cmd_get_resume_ladder_stops_at_wall_clock_deadline() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let last = Arc::new(Mutex::new(String::new()));
        let c = calls.clone();
        let l = last.clone();

        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "1")
            .with_body_from_request(move |req| {
                c.fetch_add(1, Ordering::SeqCst);
                let next = next_token(scan_of(req.path_and_query()).as_deref());
                *l.lock().unwrap() = next.clone();
                incomplete_body(Some(&next), "scan truncated").into_bytes()
            })
            .expect_at_least(2)
            .create_async()
            .await;

        let started = Instant::now();
        let err = cmd_get_inner(
            "bafkreislowscan".to_string(),
            server.url(),
            None,
            None,
            Duration::from_millis(2500),
            MAX_SCAN_RESUMES,
        )
        .await
        .expect_err("a ladder that outruns the deadline must end in an error");
        let elapsed = started.elapsed();
        let told = told(&err);
        let held = last.lock().unwrap().clone();

        assert!(
            told.to_lowercase().contains("deadline"),
            "the give-up must name the deadline, not the cap, got: {told}"
        );
        let calls = calls.load(Ordering::SeqCst);
        // The lower bound is 1, not 2. What this scenario proves is that the DEADLINE,
        // not the cap, is what ends the ladder, and one call satisfies that as well as
        // three do; requiring a resume as well made the test depend on a loaded runner
        // fitting two round trips inside 2.5s, which is the likeliest flake in the
        // suite. That a valid continuation is actually resumed with is scenario 1's job.
        assert!(
            (1..9).contains(&calls),
            "the deadline must stop the ladder before the cap, made {calls} calls"
        );
        assert!(
            elapsed < Duration::from_secs(9),
            "the ladder never reaches a body read here, and every wait is bounded by the \
             time left on the 2.5s deadline, so the run is over near the deadline itself; \
             took {elapsed:?}"
        );
        assert!(
            told.contains(&held) && told.contains(&format!("--scan {held}")),
            "the still-held continuation and its resuming invocation must be surfaced, got: {told}"
        );

        m.assert_async().await;
    }

    /// Scenario 12, lower half of the boundary pair: a 2048-character token is inside
    /// the accepted bound and is resumed with.
    #[tokio::test]
    async fn test_cmd_get_accepts_2048_char_continuation() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = token_of_len("t1", 2048);

        let m1 = server
            .mock("GET", "/ipfs/bafkreibound")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", "/ipfs/bafkreibound")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body("object bytes")
            .expect(1)
            .create_async()
            .await;

        cmd_get("bafkreibound".to_string(), server.url(), None, None)
            .await
            .expect("a 2048-character token is within the bound and must be resumed with");

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 12, upper half: one character past the bound is rejected, terminal
    /// exactly like a missing token, and never echoed back.
    #[tokio::test]
    async fn test_cmd_get_rejects_2049_char_continuation() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = token_of_len("t1", 2049);

        let m1 = server
            .mock("GET", "/ipfs/bafkreioverbound")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let m2 = server
            .mock("GET", mockito::Matcher::Regex("scan=".to_string()))
            .expect(0)
            .create_async()
            .await;

        let err = cmd_get("bafkreioverbound".to_string(), server.url(), None, None)
            .await
            .expect_err("an over-bound token must be terminal");
        let told = told(&err);

        assert!(
            !told.contains(&t),
            "a rejected token must never be echoed into the message, got: {told}"
        );
        assert!(
            told.chars().count() < 600,
            "node text must be length-capped, got {} chars",
            told.chars().count()
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// Scenario 13. A caller-supplied continuation is a resume INPUT: the very first
    /// request carries `?scan=<token>`, so an invocation picked up from a previous
    /// terminal starts where that one stopped instead of walking from row 0 again.
    #[tokio::test]
    async fn test_cmd_get_caller_supplied_continuation_starts_from_token() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t7");

        let front = server
            .mock("GET", "/ipfs/bafkreisupplied")
            .expect(0)
            .create_async()
            .await;
        let resumed = server
            .mock("GET", "/ipfs/bafkreisupplied")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body("object bytes")
            .expect(1)
            .create_async()
            .await;

        let res = cmd_get_inner(
            "bafkreisupplied".to_string(),
            server.url(),
            None,
            Some(t.clone()),
            SCAN_DEADLINE,
            MAX_SCAN_RESUMES,
        )
        .await;

        front.assert_async().await;
        resumed.assert_async().await;
        res.expect("a supplied continuation must be used, not ignored");
    }

    /// R21, the wired half. The scenario above drives `cmd_get_inner` directly, so
    /// it proves the resume INPUT works but says nothing about the `--scan` arg
    /// reaching it. This one goes through `cmd_get`, the function clap dispatches
    /// to, so a rewiring that drops the argument on the floor turns it red. Without
    /// it the flag can be silently disconnected while every other resume test stays
    /// green, and the invocation this command prints at a bound would be advice the
    /// binary does not honor.
    #[tokio::test]
    async fn test_cmd_get_passes_the_scan_arg_through_to_the_resume_input() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t14");

        let front = server
            .mock("GET", "/ipfs/bafkreiwired")
            .expect(0)
            .create_async()
            .await;
        let resumed = server
            .mock("GET", "/ipfs/bafkreiwired")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body("object bytes")
            .expect(1)
            .create_async()
            .await;

        let res = cmd_get(
            "bafkreiwired".to_string(),
            server.url(),
            None,
            Some(t.clone()),
        )
        .await;

        front.assert_async().await;
        resumed.assert_async().await;
        res.expect("the --scan argument must reach the resume input through cmd_get");
    }

    /// #173 review (F1): a base64 CID (multibase prefix 'm') can contain '/', '+',
    /// and '='. The client must percent-encode it into ONE path segment before
    /// building and signing `/ipfs/<cid>`; otherwise the '/' splits the target so
    /// it misses the single-segment Axum route and the signature covers the wrong
    /// path. Assert the encoded segment carries no raw '/', '+', or '=', and that
    /// it decodes back to the original CID (the server's `Path` extractor performs
    /// that same decode). RED with the old raw `format!("/ipfs/{cid}")`: the
    /// segment still contains '/'.
    #[test]
    fn test_encode_cid_segment_escapes_base64_alphabet() {
        let cid = "mFoo/Bar+baz==";
        let encoded = encode_cid_segment(cid);

        assert!(
            !encoded.contains('/'),
            "encoded CID must be a single path segment (no raw '/'), got: {encoded}"
        );
        assert!(
            !encoded.contains('+'),
            "encoded CID must escape '+', got: {encoded}"
        );
        assert!(
            !encoded.contains('='),
            "encoded CID must escape '=', got: {encoded}"
        );

        let decoded = urlencoding::decode(&encoded).expect("encoded CID must decode");
        assert_eq!(
            decoded, cid,
            "encoding must round-trip back to the original CID"
        );
    }

    /// #173 review: `gl ipfs get --dir <path>` must PROPAGATE a missing/corrupt
    /// identity-load error like `gl ipfs list`, not silently fall back to an anonymous
    /// request — otherwise an authorized reader pointing `--dir` at a broken keystore
    /// gets the node's opaque 404 instead of the actionable key-load error. The
    /// unsigned fallback is preserved only when NO `--dir` is given (covered by
    /// `test_cmd_get_anonymous_denial_is_error`). RED before the fix (`.ok()` swallows
    /// the error, an anonymous request is sent, and the `.expect(0)` mock is hit),
    /// GREEN after.
    #[tokio::test]
    async fn test_cmd_get_explicit_dir_no_identity_errors_without_request() {
        let mut server = mockito::Server::new_async().await;
        // Empty keystore dir passed explicitly via --dir: no identity.pem present.
        let empty = tempfile::TempDir::new().unwrap();

        // The endpoint must never be hit when an explicit --dir fails to load.
        let m = server
            .mock("GET", "/ipfs/bafkreitestcid")
            .expect(0)
            .create_async()
            .await;

        let err = cmd_get(
            "bafkreitestcid".to_string(),
            server.url(),
            Some(empty.path().to_path_buf()),
            None,
        )
        .await
        .expect_err("an explicit --dir that fails to load must be an error");
        assert!(
            err.to_string().contains("gl identity new")
                || err.to_string().contains("no identity found")
                || err.to_string().contains("failed to load keypair"),
            "error should name the key-load failure, got: {err}"
        );

        m.assert_async().await;
    }

    /// #173 review (F4): a caller-supplied `--scan` value clears the same bar as a
    /// node-offered one, BEFORE any request is signed. Both existing caller-supplied
    /// scenarios pass a valid token, so the reject arm of that match was uncovered and
    /// deleting the check left every test green even though the identical property is
    /// covered on the node-offered side. A malformed value must fail with no node call
    /// at all, and the rejection names the bound rather than echoing the value.
    #[tokio::test]
    async fn test_cmd_get_rejects_a_malformed_caller_supplied_continuation() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let bad = "abc#def&ghi";

        // Nothing may be sent: the value would otherwise reach a signed target.
        let m = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let err = cmd_get_inner(
            "bafkreibadinput".to_string(),
            server.url(),
            None,
            Some(bad.to_string()),
            SCAN_DEADLINE,
            MAX_SCAN_RESUMES,
        )
        .await
        .expect_err("a malformed --scan value must be rejected");
        let told = told(&err);

        assert!(
            told.contains(&MAX_CONTINUATION_LEN.to_string())
                && told.to_lowercase().contains("base64url"),
            "the rejection must name the bound, got: {told}"
        );
        assert!(
            !told.contains("abc#") && !told.contains("def&ghi"),
            "a rejected value must never be echoed back, got: {told}"
        );

        m.assert_async().await;
    }

    /// #173 review (F3): the `Retry-After` clamp must actually bind somewhere. Every
    /// other retryable fixture answers `Retry-After: 0` or `1`, both already under the
    /// 5 second clamp, and the one 3600 in the suite rides a 429 that returns before
    /// the header is ever parsed. So deleting `.min(MAX_RETRY_AFTER)` left the whole
    /// suite green.
    ///
    /// Here a retryable 503 asks for an hour, with a valid continuation, under a
    /// deadline set a little wider than the clamp. Clamped, the first wait is 5
    /// seconds and the deadline still has room for a second attempt. Unclamped, that
    /// one wait consumes the whole deadline and the run ends after a single call. The
    /// call count is what separates them, and it fails fast rather than hanging,
    /// because the wait is also bounded by the time left on the deadline.
    #[tokio::test]
    async fn test_cmd_get_clamps_a_hostile_retry_after_below_the_deadline() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();

        let m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "3600")
            .with_body_from_request(move |req| {
                c.fetch_add(1, Ordering::SeqCst);
                let next = next_token(scan_of(req.path_and_query()).as_deref());
                incomplete_body(Some(&next), "scan truncated").into_bytes()
            })
            .expect_at_least(1)
            .create_async()
            .await;

        let started = Instant::now();
        let err = cmd_get_inner(
            "bafkreihostileretry".to_string(),
            server.url(),
            None,
            None,
            Duration::from_secs(6),
            MAX_SCAN_RESUMES,
        )
        .await
        .expect_err("a ladder that outruns the deadline must end in an error");
        let elapsed = started.elapsed();
        let calls = calls.load(Ordering::SeqCst);

        assert!(
            calls >= 2,
            "the clamp caps a single wait at {}s, well under the 6s deadline, so one \
             hostile Retry-After must not swallow the run: made {calls} calls",
            MAX_RETRY_AFTER.as_secs()
        );
        // Tight enough to bind. The waits are also clamped by the time LEFT on the
        // deadline, and at 12s that term was free: dropping `.min(left)` let the run
        // overshoot to 10.04s and still pass, so the doc claim that waits never run
        // past the deadline rested on a term no test could see. With a 6s deadline
        // and a 5s clamp the bounded run lands near 6s and the unbounded one near
        // 10s, and 8s separates them.
        assert!(
            elapsed < Duration::from_secs(8),
            "a wait is bounded by the time LEFT on the 6s deadline as well as by the \
             {}s clamp, so the run ends near the deadline rather than a full clamp \
             past it; took {elapsed:?}",
            MAX_RETRY_AFTER.as_secs()
        );
        assert!(
            told(&err).to_lowercase().contains("deadline"),
            "the give-up must name the deadline, got: {}",
            told(&err)
        );

        m.assert_async().await;
    }

    /// The transport-error terminal, which is the one arm of the token surfacing that
    /// mockito cannot reach: its server outlives the call, and an unmatched route
    /// answers 501, so a request always gets a response.
    ///
    /// A raw listener is what reproduces it. Rung 1 is a real `search_incomplete` 503
    /// carrying a valid continuation, answered with `Connection: close` so reqwest
    /// opens a fresh connection for rung 2. Rung 2 is ACCEPTED and then dropped
    /// without a byte written, which is what a reset mid-ladder looks like to the
    /// client. The ladder ends holding a token that still points at a real position,
    /// and losing it there means the only way forward is a bare re-run that restarts
    /// at row 0 and re-spends the caller's per-IP budget.
    ///
    /// MUTATION (RED): drop the `surface_resume` call in the transport-error arm.
    #[tokio::test]
    async fn test_cmd_get_transport_failure_mid_ladder_surfaces_the_held_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        reset_diag();
        let t = make_token("t1");
        let body = incomplete_body(Some(&t), "scan truncated");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = connections.clone();

        tokio::spawn(async move {
            // Rung 1: a complete 503 with a continuation, then close the connection so
            // rung 2 has to dial again.
            let (mut sock, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            let mut scratch = [0u8; 2048];
            let _ = sock.read(&mut scratch).await;
            let resp = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n\
                 Retry-After: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
            drop(sock);

            // Rung 2: accept and hang up without a response.
            let (sock, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            drop(sock);
        });

        let err = cmd_get(
            "bafkreireset".to_string(),
            format!("http://{addr}"),
            None,
            None,
        )
        .await
        .expect_err("a connection dropped mid-ladder must be an error");
        let told = told(&err);

        assert_eq!(
            connections.load(Ordering::SeqCst),
            2,
            "the fixture must actually reach rung 2, or the transport arm was never \
             exercised"
        );
        assert!(
            told.contains(&t) && told.contains(&format!("--scan {t}")),
            "a transport failure ends the ladder still holding a usable token, so it \
             must come back with the invocation that resumes from it, got: {told}"
        );
        assert!(
            told.contains("bafkreireset"),
            "the failure must still name the CID it was fetching, got: {told}"
        );
    }

    /// A terminal whose body FAILED to arrive must say so, not report the node as
    /// silent.
    ///
    /// The listener answers 500, promises 512 bytes, writes none, and hangs up. The
    /// read comes back empty, and the terminal used to render that as
    /// `node returned 500: ` with nothing after the colon, which reads as a node that
    /// sent no message at all. MUTATION (RED): render the tail with
    /// `sanitize_node_msg` again and the message ends at the colon.
    #[tokio::test]
    async fn test_cmd_get_reports_a_body_that_could_not_be_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        reset_diag();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 2048];
            let _ = sock.read(&mut scratch).await;
            let _ = sock
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\
                      Content-Length: 512\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = sock.flush().await;
        });

        let err = cmd_get(
            "bafkreicutread".to_string(),
            format!("http://{addr}"),
            None,
            None,
        )
        .await
        .expect_err("a 500 is an error whatever became of its body");
        let told = told(&err);

        assert!(
            told.contains("500"),
            "the terminal must still name the status, got: {told}"
        );
        assert!(
            told.to_lowercase().contains("could not be read"),
            "a body that failed mid-read must be reported as unread rather than as an \
             empty message, got: {told}"
        );
        assert!(
            !told.contains("500: \n") && !told.ends_with("500: "),
            "the terminal must not trail off after the colon, got: {told}"
        );
    }

    /// #173 review (F9): a `search_incomplete` body the 8 KiB read cap CUT SHORT must
    /// be terminal, not retried.
    ///
    /// A cut body cannot parse, so its `error` code reads as absent, and on a 503 that
    /// used to fall through to the generic overload arm, which resumes on the token
    /// ALREADY HELD. The fresh continuation the node offered is inside the part that
    /// was never read, so the ladder replays one position for every remaining rung: a
    /// 9000-character body drove eight requests carrying the old token. Unclassifiable
    /// is terminal, like any unrecognized code.
    #[tokio::test]
    async fn test_cmd_get_truncated_incomplete_body_is_terminal_not_a_replay() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");
        let calls = Arc::new(AtomicUsize::new(0));
        let c1 = calls.clone();
        let c2 = calls.clone();

        let m1 = server
            .mock("GET", "/ipfs/bafkreicutbody")
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body_from_request({
                let t = t.clone();
                move |_req| {
                    c1.fetch_add(1, Ordering::SeqCst);
                    incomplete_body(Some(&t), "scan truncated").into_bytes()
                }
            })
            .expect(1)
            .create_async()
            .await;
        // Well past the 8 KiB cap, with the fresh continuation behind the cut.
        let m2 = server
            .mock("GET", "/ipfs/bafkreicutbody")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body_from_request(move |_req| {
                c2.fetch_add(1, Ordering::SeqCst);
                incomplete_body(Some(&make_token("t2")), &"x".repeat(9000)).into_bytes()
            })
            .expect(1)
            .create_async()
            .await;

        let err = cmd_get("bafkreicutbody".to_string(), server.url(), None, None)
            .await
            .expect_err("an unclassifiable 503 body must be an error");
        let told = told(&err);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a body cut by the read cap must end the ladder, not replay the held token \
             for every remaining rung"
        );
        assert!(
            told.contains(&t) && told.contains(&format!("--scan {t}")),
            "the still-held continuation and its resuming invocation must be surfaced, \
             got: {told}"
        );

        m1.assert_async().await;
        m2.assert_async().await;
    }

    /// The other half of the same defect: a `search_incomplete` 503 whose body read
    /// FAILED part-way is just as unparseable as one the cap cut short, and it used to
    /// fall through to the generic overload arm and be retried on the token ALREADY
    /// HELD. Measured before the fix: rung 1 hands back t1, every later rung answers
    /// headers plus a cut body, and the ladder made 9 calls with calls 2 through 9 all
    /// carrying the identical `?scan=t1`, ending at the cap. That is the replay the
    /// truncation exclusion exists to prevent, reached by the other door.
    ///
    /// mockito cannot express it: it always finishes the response it advertises. The
    /// listener promises 512 bytes, writes a handful, and hangs up.
    ///
    /// MUTATION (RED): drop `&& !read_failed` from the retry arm and the count is 9.
    #[tokio::test]
    async fn test_cmd_get_unreadable_incomplete_body_is_terminal_not_a_replay() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        reset_diag();
        let t = make_token("t1");
        let complete = incomplete_body(Some(&t), "scan truncated");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let scans = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = scans.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let n = seen.fetch_add(1, Ordering::SeqCst);
                let mut scratch = [0u8; 4096];
                let read = sock.read(&mut scratch).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&scratch[..read]).into_owned();
                if let Some(line) = request.lines().next() {
                    if let Some(target) = line.split_whitespace().nth(1) {
                        recorded
                            .lock()
                            .unwrap()
                            .push(scan_of(target).unwrap_or_default());
                    }
                }
                let resp = if n == 0 {
                    // Rung 1: a complete 503 offering a continuation.
                    format!(
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n\
                         Retry-After: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{complete}",
                        complete.len()
                    )
                } else {
                    // Every later rung: headers, then a body that stops part-way.
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n\
                     Retry-After: 0\r\nContent-Length: 512\r\nConnection: close\r\n\r\n\
                     {\"error\":\"search_inc"
                        .to_string()
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
                drop(sock);
            }
        });

        let err = cmd_get_inner(
            "bafkreiunreadable".to_string(),
            format!("http://{addr}"),
            None,
            None,
            SCAN_DEADLINE,
            MAX_SCAN_RESUMES,
        )
        .await
        .expect_err("an unclassifiable 503 body must be an error");
        let told = told(&err);

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a body whose read failed must end the ladder, not replay the held token \
             for every remaining rung; the scans seen were {:?}",
            scans.lock().unwrap()
        );
        assert_eq!(
            scans.lock().unwrap().as_slice(),
            [String::new(), t.clone()],
            "rung 1 carries no token and rung 2 carries the one it was handed"
        );
        assert!(
            told.contains(&t) && told.contains(&format!("--scan {t}")),
            "the still-held continuation and its resuming invocation must be \
             surfaced, got: {told}"
        );
    }

    /// A 404 after a resume is an ANSWER, so it must not come with a resume hint that
    /// contradicts it. Deleting the `status != NOT_FOUND` guard (replacing it with
    /// `if true`) left the suite green, because no test had ever reached that arm
    /// holding a token, which is the only state in which the guard does anything.
    ///
    /// Rung 1 hands back a valid continuation, rung 2 answers 404.
    ///
    /// MUTATION (RED): replace the guard with `if true`.
    #[tokio::test]
    async fn test_cmd_get_a_404_after_a_resume_offers_no_hint() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");

        let rung1 = server
            .mock("GET", "/ipfs/bafkreignotfound")
            .match_query(mockito::Matcher::Missing)
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let rung2 = server
            .mock("GET", "/ipfs/bafkreignotfound")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"not_found","message":"no such object"}"#)
            .expect(1)
            .create_async()
            .await;

        let err = cmd_get("bafkreignotfound".to_string(), server.url(), None, None)
            .await
            .expect_err("a 404 is still an error exit");
        let told = told(&err);

        assert!(
            told.contains("404"),
            "the terminal must name the status, got: {told}"
        );
        assert!(
            !told.contains("--scan") && !told.contains(&t),
            "a definitive 404 is an answer; a resume hint beside it would invite a \
             re-run that cannot do better, got: {told}"
        );

        rung1.assert_async().await;
        rung2.assert_async().await;
    }

    /// `search_incomplete` with NO continuation is the node's "the scan wrapped and
    /// finished" signal, so that arm deliberately withholds the hint too. Adding a
    /// `surface_resume` call to it left the suite green for the same reason: nothing
    /// reached it holding a token.
    ///
    /// MUTATION (RED): add `surface_resume(&cid, token.as_deref());` to the
    /// no-continuation branch.
    #[tokio::test]
    async fn test_cmd_get_a_wrapped_scan_after_a_resume_offers_no_hint() {
        reset_diag();
        let mut server = mockito::Server::new_async().await;
        let t = make_token("t1");

        let rung1 = server
            .mock("GET", "/ipfs/bafkreigwrapped")
            .match_query(mockito::Matcher::Missing)
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(Some(&t), "scan truncated"))
            .expect(1)
            .create_async()
            .await;
        let rung2 = server
            .mock("GET", "/ipfs/bafkreigwrapped")
            .match_query(mockito::Matcher::Exact(format!("scan={t}")))
            .with_status(503)
            .with_header("content-type", "application/json")
            .with_header("retry-after", "0")
            .with_body(incomplete_body(None, "the scan wrapped"))
            .expect(1)
            .create_async()
            .await;

        let err = cmd_get("bafkreigwrapped".to_string(), server.url(), None, None)
            .await
            .expect_err("an incomplete scan with nothing to resume from is an error");
        let told = told(&err);

        assert!(
            told.contains("offered no continuation token"),
            "the terminal must say why it stopped, got: {told}"
        );
        assert!(
            !told.contains("--scan") && !told.contains(&t),
            "a wrapped scan has nowhere further to go, so a resume hint here would \
             invite a re-run that cannot find more, got: {told}"
        );

        rung1.assert_async().await;
        rung2.assert_async().await;
    }

    /// The success path streams. `resp.bytes()` buffered the whole object first, so a
    /// hostile node answering 200 with a very large body delivered fast made the
    /// client allocate all of it before a byte reached stdout, while the sibling error
    /// read was capped at 8 KiB.
    ///
    /// What is asserted here is the CORRECTNESS of streaming, not the allocation: a
    /// body far larger than one chunk must arrive at the sink whole, in order, byte
    /// for byte. A chunk loop that dropped or reordered a chunk would be the obvious
    /// way to get the memory right and the object wrong, and on a content-addressed
    /// fetch that is the worse failure.
    #[tokio::test]
    async fn write_object_streams_a_large_body_through_intact() {
        reset_diag();
        // 4 MiB of a non-repeating pattern, well past any single chunk.
        let payload: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();

        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/ipfs/bafkreibig")
            .with_status(200)
            .with_header("x-git-hash", "deadbeef")
            .with_body(payload.clone())
            .create_async()
            .await;

        let resp = reqwest::get(format!("{}/ipfs/bafkreibig", server.url()))
            .await
            .unwrap();
        let mut sink: Vec<u8> = Vec::new();
        write_object_to(resp, &mut sink).await.unwrap();

        assert_eq!(
            sink.len(),
            payload.len(),
            "a streamed body must arrive whole"
        );
        assert!(sink == payload, "a streamed body must arrive unaltered");
        assert!(
            diag_text().contains("deadbeef"),
            "the header diagnostics still go to stderr, got: {}",
            diag_text()
        );
        m.assert_async().await;
    }

    /// `node_tail`'s partial-body arm: a body that arrived part-way and then failed.
    /// The other three `(read_failed, msg.is_empty())` combinations were covered; this
    /// one, the shape a real broken connection most often produces, was not, because
    /// the existing fixture writes zero body bytes. It is also the only arm where
    /// node-supplied partial text reaches the terminal.
    ///
    /// The listener promises 512 bytes, writes a few, and hangs up. The terminal must
    /// carry BOTH what did arrive and the fact that the rest did not.
    #[tokio::test]
    async fn test_cmd_get_reports_partial_text_and_the_unfinished_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        reset_diag();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 2048];
            let _ = sock.read(&mut scratch).await;
            let _ = sock
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\
                      Content-Length: 512\r\nConnection: close\r\n\r\n\
                      {\"error\":\"boom\",\"message\":\"half a sen",
                )
                .await;
            let _ = sock.flush().await;
        });

        let err = cmd_get(
            "bafkreipartial".to_string(),
            format!("http://{addr}"),
            None,
            None,
        )
        .await
        .expect_err("a 500 is an error whatever became of its body");
        let told = told(&err);

        assert!(
            told.contains("half a sen"),
            "the text that DID arrive must reach the caller, got: {told}"
        );
        assert!(
            told.contains("could not be read in full"),
            "and it must be marked as unfinished, or partial node text reads as the \
             node's whole answer, got: {told}"
        );
    }
}
