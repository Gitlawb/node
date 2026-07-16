//! git-remote-gitlawb — git remote helper for gitlawb:// URLs
//!
//! Git calls this binary when it encounters a remote URL with the "gitlawb://" scheme.
//! It implements the git remote helper protocol, translating gitlawb:// URLs into
//! HTTP smart-protocol requests against a gitlawb-node.
//!
//! # URL format
//!   gitlawb://did:key:z6Mk.../repo-name
//!
//! # v0.1 resolution
//!   DID → http://127.0.0.1:7545  (hardcoded; v0.2 will use DHT)
//!   Override with: GITLAWB_NODE=http://my-node:7545
//!
//! # Protocol flow (connect capability)
//!   capabilities → "connect\n\n"
//!   connect git-upload-pack  → GET /info/refs | POST /git-upload-pack
//!   connect git-receive-pack → GET /info/refs | POST /git-receive-pack
//! Push (git-receive-pack) is RFC-9421 signed from the first request when an
//! identity keypair is present, since a push can never be anonymous. Fetch
//! (git-upload-pack) stays anonymous and is signed only on a single retry, after
//! the node denies the anonymous advertisement with 404 — so a public clone never
//! discloses the caller's DID, while a private repo's owner (or an authorized
//! reader) still authenticates when the node demands it.

use anyhow::{bail, Context, Result};
use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;
use std::io::{self, BufRead, Read, Write};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Handle informational flags before anything else. Git always invokes a
    // remote helper as `git-remote-gitlawb <remote-name> <url>`, so these flags
    // only ever appear on direct user or release-smoke-test invocations. Print
    // to stdout and exit before tracing init so the output stays clean.
    match classify_args(&args) {
        Invocation::Version => {
            println!("{}", version_line());
            return Ok(());
        }
        Invocation::Help => {
            print!("{}", help_text());
            return Ok(());
        }
        Invocation::Helper => {}
    }

    // All logging goes to stderr so it doesn't corrupt the git protocol on stdout
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(std::env::var("GITLAWB_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    if args.len() < 3 {
        eprintln!("usage: git-remote-gitlawb <remote-name> <url>");
        eprintln!("try 'git-remote-gitlawb --help' for more information");
        std::process::exit(1);
    }

    let url = &args[2];
    tracing::debug!("remote url: {url}");

    let (_, short_owner, repo_name) = parse_gitlawb_url(url)?;

    // v0.1: default to localhost. Override with GITLAWB_NODE env var.
    let node_base =
        std::env::var("GITLAWB_NODE").unwrap_or_else(|_| "http://127.0.0.1:7545".to_string());
    let repo_base = format!("{}/{}/{}", node_base, short_owner, repo_name);
    tracing::debug!("repo_base: {repo_base}");

    // Load keypair for signing requests (optional). Push always signs when a key is
    // present; fetch signs only if the node 404s the anonymous advertisement, so
    // public fetches stay anonymous. Absent a key, public fetch still works and push
    // falls back to unsigned (v0.1 local alpha only).
    let keypair = load_keypair();

    run_helper(&repo_base, keypair.as_ref())
}

// ── CLI argument handling ──────────────────────────────────────────────────────

/// How the binary was invoked, derived from its CLI arguments.
#[derive(Debug, PartialEq, Eq)]
enum Invocation {
    /// `--version` / `-V`: print the version line and exit.
    Version,
    /// `--help` / `-h`: print usage and exit.
    Help,
    /// Normal git remote-helper invocation: `<remote-name> <url>`.
    Helper,
}

/// Classify the process arguments.
///
/// Git always calls a remote helper as `git-remote-gitlawb <remote-name> <url>`,
/// so the informational flags are only recognized as the first argument; this
/// keeps the remote-helper protocol path untouched for git's own invocations.
fn classify_args(args: &[String]) -> Invocation {
    match args.get(1).map(String::as_str) {
        Some("--version") | Some("-V") => Invocation::Version,
        Some("--help") | Some("-h") => Invocation::Help,
        _ => Invocation::Helper,
    }
}

/// The version line, matching the `<bin> <version>` format that the clap-based
/// `gl` and `gitlawb-node` binaries emit, so release smoke tests can treat all
/// three binaries uniformly.
fn version_line() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

/// Usage text for `--help`.
fn help_text() -> String {
    format!(
        "{}\n\
         \n\
         Git remote helper for gitlawb:// URLs. Git invokes this automatically\n\
         when it encounters a gitlawb:// remote; you normally do not run it directly.\n\
         \n\
         USAGE:\n\
         \x20   git clone gitlawb://did:key:z6Mk.../<repo>\n\
         \n\
         ENVIRONMENT:\n\
         \x20   GITLAWB_NODE   Node base URL (default: http://127.0.0.1:7545)\n\
         \x20   GITLAWB_KEY    Identity PEM path for signed fetch/push (default: ~/.gitlawb/identity.pem)\n\
         \x20   GITLAWB_LOG    Log filter (default: warn)\n\
         \n\
         FLAGS:\n\
         \x20   -V, --version   Print version and exit\n\
         \x20   -h, --help      Print this help and exit\n",
        version_line()
    )
}

// ── Remote helper protocol loop ───────────────────────────────────────────────

fn run_helper(repo_base: &str, keypair: Option<&Keypair>) -> Result<()> {
    let stdin = io::stdin();
    let mut stdin_buf = io::BufReader::new(stdin);
    let mut stdout = io::stdout();

    loop {
        let mut line = String::new();
        let n = stdin_buf
            .read_line(&mut line)
            .context("reading command from git")?;
        if n == 0 {
            break; // EOF
        }

        let cmd = line.trim_end_matches('\n').trim_end_matches('\r');
        tracing::debug!("← git: {:?}", cmd);

        match cmd {
            "capabilities" => {
                // Advertise a single capability: connect
                // This tells git we can proxy any git service bidirectionally
                write!(stdout, "connect\n\n")?;
                stdout.flush()?;
                tracing::debug!("→ advertised: connect");
            }
            s if s.starts_with("connect ") => {
                let service = s["connect ".len()..].trim().to_string();
                tracing::debug!("→ connecting to service: {service}");

                // Confirm the connection with a blank line
                writeln!(stdout)?;
                stdout.flush()?;

                // Proxy the git smart HTTP protocol
                handle_connect(repo_base, &service, keypair, &mut stdin_buf)?;
                // After connect completes, exit immediately. Git may not close
                // our stdin pipe promptly after a push, causing the helper to
                // hang if we return to the read_line loop.
                std::process::exit(0);
            }
            "" => break, // git signals end of commands with a blank line
            other => {
                tracing::warn!("unknown remote helper command: {other:?}");
            }
        }
    }

    Ok(())
}

// ── HTTP proxy for git smart protocol ────────────────────────────────────────

fn handle_connect<R: Read>(
    repo_base: &str,
    service: &str,
    keypair: Option<&Keypair>,
    stdin: &mut R,
) -> Result<()> {
    match service {
        "git-upload-pack" | "git-receive-pack" => {}
        other => bail!("unsupported git service: {other}"),
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;

    // ── Phase 1: ref advertisement (GET /info/refs?service=<service>) ─────────
    //
    // The server advertises its refs. git reads this to decide what to fetch/push.

    // Signing policy for this exchange, carried through to the Phase-2 POST:
    //  - git-receive-pack (push): sign from the first request; a push is
    //    signature-gated and can never be anonymous.
    //  - git-upload-pack (fetch): start anonymous so a public clone never discloses
    //    the caller's DID, then escalate to a single signed retry only if the node
    //    denies the anonymous advertisement with 404 (how it withholds a private
    //    repo from an unauthenticated reader).
    let mut signing_key = if service == "git-receive-pack" {
        keypair
    } else {
        None
    };

    let refs_url = format!("{}/info/refs?service={}", repo_base, service);
    tracing::debug!("GET {refs_url}");

    let mut refs_resp = build_advertisement_request(&client, &refs_url, signing_key)
        .send()
        .with_context(|| format!("GET {refs_url}"))?;

    // Fetch escalation: retry the advertisement signed once when the anonymous try
    // is denied and we hold an identity. A public repo answers 200 on the first
    // (anonymous) request and never reaches here, so it stays DID-private.
    if service == "git-upload-pack"
        && refs_resp.status() == reqwest::StatusCode::NOT_FOUND
        && keypair.is_some()
    {
        tracing::debug!("anonymous info/refs returned 404; retrying signed");
        signing_key = keypair;
        refs_resp = build_advertisement_request(&client, &refs_url, signing_key)
            .send()
            .with_context(|| format!("GET {refs_url} (signed retry)"))?;
    }

    if !refs_resp.status().is_success() {
        let status = refs_resp.status();
        let body = read_error_body(refs_resp);
        bail!(
            "{}",
            http_error_message(
                "GET",
                "/info/refs",
                status,
                &body,
                Some("— is the repo registered on this node?")
            )
        );
    }

    let refs_bytes = refs_resp.bytes().context("reading info/refs body")?;
    tracing::debug!("ref advertisement: {} bytes (raw)", refs_bytes.len());

    // The HTTP smart protocol wraps the ref advertisement in:
    //   <pkt-line "# service=git-upload-pack\n"> + "0000" + <actual advertisement>
    //
    // But git's `connect` protocol expects raw git-upload-pack output (no HTTP wrapper).
    // Strip the service-line pkt-line + flush before forwarding.
    let advertisement = strip_service_announcement(&refs_bytes);
    tracing::debug!(
        "ref advertisement: {} bytes (stripped)",
        advertisement.len()
    );

    let mut stdout = io::stdout();
    stdout.write_all(advertisement)?;
    stdout.flush()?;

    // ── Phase 2: pack exchange (POST /<service>) ──────────────────────────────
    //
    // The two services frame Phase 2 differently:
    //
    //  git-upload-pack (clone/fetch):
    //    Git speaks the stateful native protocol over `connect`: it sends its
    //    wants, a flush, then have-batches each terminated by a flush, and blocks
    //    for the server's ACK/NAK after every flush before it sends more haves or
    //    the terminal "done\n". The node serves `git upload-pack --stateless-rpc`,
    //    which keeps no state between POSTs, so we run a per-round loop: POST a
    //    self-contained request once per flush-terminated batch and stream each
    //    response back to git, until the "done" round returns the pack. Collapsing
    //    this into one POST deadlocks a multi-round fetch (#117).
    //
    //  git-receive-pack (push):
    //    Git sends ref-update commands + the complete PACK blob, then closes its
    //    write pipe. read_to_end is safe and correct here, a single POST.

    let post_url = format!("{}/{}", repo_base, service);

    if service == "git-upload-pack" {
        return negotiate_upload_pack(&client, &post_url, service, signing_key, stdin, &mut stdout);
    }

    let mut request_body = Vec::new();
    stdin
        .read_to_end(&mut request_body)
        .context("reading receive-pack request")?;
    tracing::debug!("pack request: {} bytes from git", request_body.len());

    if request_body.is_empty() {
        // e.g., already up-to-date — nothing to send
        tracing::debug!("empty request body — skipping POST");
        return Ok(());
    }

    post_pack_round(
        &client,
        &post_url,
        service,
        signing_key,
        request_body,
        &mut stdout,
    )
}

// ── Smart-protocol request builders ───────────────────────────────────────────

const USER_AGENT: &str = "git/2.0 git-remote-gitlawb/0.1.0";

/// Build the Phase-1 ref-advertisement GET, signing it when an identity is
/// present. The node gates the ref advertisement on read visibility for BOTH
/// services, so a private repo's advertisement is denied (404) to an
/// unauthenticated caller; without this signature the repo's own owner can
/// neither fetch (upload-pack) nor push (receive-pack) it. Public repos still
/// work anonymously (no keypair present, or the gate admits anonymous). Sign over
/// the path *and* query (?service=...) because the node verifies the signature
/// over its path_and_query.
fn build_advertisement_request(
    client: &reqwest::blocking::Client,
    refs_url: &str,
    keypair: Option<&Keypair>,
) -> reqwest::blocking::RequestBuilder {
    let mut req = client.get(refs_url).header("User-Agent", USER_AGENT);
    if let Some(kp) = keypair {
        let signed = sign_request(kp, "GET", &url_path(refs_url), b"");
        req = req
            .header("Content-Digest", signed.content_digest)
            .header("Signature-Input", signed.signature_input)
            .header("Signature", signed.signature);
        tracing::debug!("signed info/refs advertisement (DID: {})", kp.did());
    }
    req
}

/// Build the Phase-2 pack POST, signing it when an identity is present, for BOTH
/// services. The node read-gates the git-upload-pack POST with visibility_check
/// at "/", and separately owner-gates the git-receive-pack POST (signature
/// required, enforced by middleware). The Phase-1 advertisement signature does
/// not carry to this separate request, so a private repo's owner must
/// authenticate here too or their fetch/push is denied.
/// Public-repo fetch still works anonymously when no keypair is present. The body
/// is signed (content-digest) but NOT attached here, so the caller can move the
/// (possibly large) pack bytes into `.body()` rather than clone them.
fn build_pack_post_request(
    client: &reqwest::blocking::Client,
    post_url: &str,
    service: &str,
    body: &[u8],
    keypair: Option<&Keypair>,
) -> reqwest::blocking::RequestBuilder {
    let mut req = client
        .post(post_url)
        .header("Content-Type", format!("application/x-{}-request", service))
        .header("User-Agent", USER_AGENT);
    if let Some(kp) = keypair {
        let signed = sign_request(kp, "POST", &url_path(post_url), body);
        req = req
            .header("Content-Digest", signed.content_digest)
            .header("Signature-Input", signed.signature_input)
            .header("Signature", signed.signature);
        tracing::debug!("signed {service} POST (DID: {})", kp.did());
    } else if service == "git-receive-pack" {
        tracing::warn!("no identity keypair found, push will be unsigned (v0.1 local alpha only)");
    }
    req
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/// Parse a `gitlawb://did:key:z6Mk.../repo-name` URL.
///
/// Returns `(did_string, short_owner, repo_name)`.
fn parse_gitlawb_url(url: &str) -> Result<(String, String, String)> {
    let without_scheme = url
        .strip_prefix("gitlawb://")
        .ok_or_else(|| anyhow::anyhow!("not a gitlawb:// URL: {url}"))?;

    // without_scheme = "did:key:z6Mk.../repo-name"
    let (did_string, repo_name) = without_scheme
        .rsplit_once('/')
        .ok_or_else(|| anyhow::anyhow!("gitlawb:// URL must be did:.../repo-name, got: {url}"))?;

    // short_owner = last colon-delimited segment, e.g. "z6Mk..."
    // The node's DB uses a LIKE '%<short_owner>' query to match the full DID.
    let short_owner = did_string
        .split(':')
        .next_back()
        .unwrap_or(did_string)
        .to_string();

    let repo_name = repo_name.trim_end_matches(".git").to_string();

    tracing::debug!("parsed URL → did={did_string}, owner={short_owner}, repo={repo_name}");
    Ok((did_string.to_string(), short_owner, repo_name))
}

/// How a single upload-pack negotiation round ended.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum RoundEnd {
    /// A flush pkt (`0000`) ended the round; more negotiation may follow.
    Flush,
    /// The terminal `done\n` pkt ended the round; the pack follows.
    Done,
    /// The stream ended (git closed its write pipe).
    Eof,
}

/// Read ONE round of git's upload-pack request from the pkt-line stream.
///
/// Git speaks the stateful native protocol over the `connect` capability: it
/// sends its `want` lines, a flush, then `have` batches each terminated by a
/// flush, and blocks for the server's ACK/NAK after every flush before sending
/// more haves or the terminal `done\n`. Each call returns one such round: the
/// pkt-lines up to (but not including) the terminating flush or `done`, plus
/// which terminator ended it. `negotiate_upload_pack` reassembles these into
/// self-contained stateless-RPC POST bodies. Returning at the flush, instead of
/// buffering past it waiting for `done`, is what lets a multi-round fetch make
/// progress rather than deadlock (#117).
fn read_upload_pack_round<R: Read>(stdin: &mut R) -> Result<(Vec<u8>, RoundEnd)> {
    let mut content = Vec::new();

    loop {
        // Read the 4-byte hex pkt-line length prefix.
        let mut len_bytes = [0u8; 4];
        match stdin.read_exact(&mut len_bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok((content, RoundEnd::Eof));
            }
            Err(e) => return Err(e.into()),
        }

        let len_hex = std::str::from_utf8(&len_bytes).unwrap_or("0000");
        let pkt_len = usize::from_str_radix(len_hex, 16).unwrap_or(0);

        if pkt_len == 0 {
            // Flush pkt "0000": this round is complete.
            return Ok((content, RoundEnd::Flush));
        }

        if pkt_len < 4 {
            bail!("invalid pkt-line length: {pkt_len}");
        }

        let data_len = pkt_len - 4;
        let mut data = vec![0u8; data_len];
        stdin
            .read_exact(&mut data)
            .context("reading pkt-line data")?;

        // "done\n" ends the negotiation; the pack follows. The terminator is
        // reported out-of-band and re-emitted by the caller, so it is not
        // appended to `content`.
        if data == b"done\n" {
            tracing::debug!("upload-pack: got 'done', round complete");
            return Ok((content, RoundEnd::Done));
        }

        content.extend_from_slice(&len_bytes);
        content.extend_from_slice(&data);
    }
}

/// POST one self-contained stateless-RPC request body and stream the response to
/// `stdout`. Signs the request when `signing_key` is present, so every round of a
/// private-repo fetch carries the caller's signature (the node visibility-gates
/// each POST at "/"). A non-2xx status surfaces through the sanitized error path
/// rather than being rendered as an empty or successful fetch (INV-6/INV-8).
fn post_pack_round(
    client: &reqwest::blocking::Client,
    post_url: &str,
    service: &str,
    signing_key: Option<&Keypair>,
    body: Vec<u8>,
    stdout: &mut impl Write,
) -> Result<()> {
    tracing::debug!("POST {post_url} ({} bytes)", body.len());
    let req = build_pack_post_request(client, post_url, service, &body, signing_key);
    // Attach the body after signing so the bytes are moved, not cloned.
    let resp = req
        .body(body)
        .send()
        .with_context(|| format!("POST {post_url}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_body = read_error_body(resp);
        let path = format!("/{service}");
        bail!(
            "{}",
            http_error_message("POST", &path, status, &err_body, None)
        );
    }

    let bytes = resp.bytes().context("reading pack response")?;
    tracing::debug!("pack response: {} bytes from node", bytes.len());
    stdout.write_all(&bytes)?;
    stdout.flush()?;
    Ok(())
}

/// Drive a git-upload-pack fetch as a v0 smart-HTTP stateless-RPC client.
///
/// Git (over `connect`) speaks the stateful native protocol; the node serves
/// `git upload-pack --stateless-rpc`, which keeps no state between POSTs. Bridge
/// the two: capture the want block once, then for each flush-terminated have
/// batch POST a self-contained request (the wants plus every have accumulated so
/// far, then exactly one terminator) and stream the ACK/NAK back to git so it can
/// continue. The `done` round returns the pack. Every POST re-sends the wants and
/// all prior haves because the server is stateless; leaving an intermediate flush
/// in the body would truncate the negotiation, so each body carries exactly one
/// terminator.
fn negotiate_upload_pack<R: Read>(
    client: &reqwest::blocking::Client,
    post_url: &str,
    service: &str,
    signing_key: Option<&Keypair>,
    stdin: &mut R,
    stdout: &mut impl Write,
) -> Result<()> {
    // Opening round: the want block, a bare `done`, or an empty/flush-only
    // request from an up-to-date or aborted fetch.
    let (wants, wend) = read_upload_pack_round(stdin)?;
    match wend {
        // Up-to-date with an empty request, truncated, or aborted before a
        // terminator: nothing safe to POST.
        RoundEnd::Eof => return Ok(()),
        // A `done` with no preceding want-section flush: the bare-`done` request
        // the single-round tests feed. Forward it verbatim as one POST.
        RoundEnd::Done => {
            let mut body = wants;
            body.extend_from_slice(b"0009done\n");
            return post_pack_round(client, post_url, service, signing_key, body, stdout);
        }
        // Normal: the want section ended with its flush; negotiate the haves.
        // (An empty want block here is a flush-only opener and falls through to
        // the loop, which POSTs nothing and returns at EOF.)
        RoundEnd::Flush => {}
    }

    // The node is stateless between POSTs, so re-send the wants and every have so
    // far in each round.
    let mut acc_haves: Vec<u8> = Vec::new();
    loop {
        let (batch, bend) = read_upload_pack_round(stdin)?;

        // Only POST when a round carries new haves or a terminator. A round with no
        // new haves needs no request: an empty EOF ends the fetch, and a bare flush
        // (git never sends a content-free flush mid-negotiation, but a malformed
        // stream could) is skipped so a run of empty flushes cannot amplify into one
        // signed POST each. A `done` round with no haves still POSTs (the fresh-clone
        // case), handled by the terminator match below.
        match (batch.is_empty(), bend) {
            (true, RoundEnd::Eof) => return Ok(()),
            (true, RoundEnd::Flush) => continue,
            _ => {}
        }

        acc_haves.extend_from_slice(&batch);

        // Compose a self-contained stateless-RPC request: wants + one flush + all
        // accumulated haves + exactly one terminator. No intermediate flush
        // survives into the body, or the stateless server treats the first flush
        // after the haves as end-of-request and truncates the negotiation.
        let mut body = wants.clone();
        body.extend_from_slice(b"0000");
        body.extend_from_slice(&acc_haves);

        let final_round = match bend {
            RoundEnd::Flush => {
                body.extend_from_slice(b"0000");
                false
            }
            // Only a real `done` pkt finalizes the stateless request.
            RoundEnd::Done => {
                body.extend_from_slice(b"0009done\n");
                true
            }
            // A nonempty batch terminated by EOF (no flush, no done) means git
            // ABORTED mid-negotiation (#192, F1). Terminate WITHOUT POSTing:
            // synthesizing a `done` here would make the node generate and stream a
            // full pack — signed, for a private fetch — to a client that has gone
            // away. The accumulated haves are discarded; there is no one to serve.
            RoundEnd::Eof => return Ok(()),
        };

        post_pack_round(client, post_url, service, signing_key, body, stdout)?;

        if final_round {
            return Ok(());
        }
    }
}

/// Strip the HTTP smart-protocol service announcement from a GET /info/refs response.
///
/// The HTTP smart protocol prepends:
///   `<pkt-line("# service=git-{upload,receive}-pack\n")>` + `0000` (flush)
///
/// When forwarding through the git remote helper `connect` protocol, git expects
/// raw git-daemon output (no wrapper), so we discard the first two pkt-lines.
fn strip_service_announcement(bytes: &[u8]) -> &[u8] {
    if bytes.len() < 4 {
        return bytes;
    }

    // Parse the first pkt-line length (4-byte hex)
    let Ok(len_hex) = std::str::from_utf8(&bytes[..4]) else {
        return bytes;
    };
    let Ok(line_len) = usize::from_str_radix(len_hex, 16) else {
        return bytes;
    };

    // line_len == 0 means flush pkt; an unexpected prefix means pass through as-is
    if line_len < 4 || line_len > bytes.len() {
        return bytes;
    }

    let after_first = &bytes[line_len..];

    // Skip the flush packet "0000" that follows the service announcement
    if after_first.starts_with(b"0000") {
        &after_first[4..]
    } else {
        after_first
    }
}

/// Extract the path component from an absolute URL.
/// `http://127.0.0.1:7545/z6Mk.../repo/git-receive-pack` → `/z6Mk.../repo/git-receive-pack`
fn url_path(url: &str) -> String {
    url.split_once("://")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map(|(_, path)| format!("/{}", path))
        .unwrap_or_else(|| "/".to_string())
}

const MAX_ERROR_BODY_BYTES: u64 = 4096;
const MAX_ERROR_BODY_CHARS: usize = 2000;

fn read_error_body(mut response: reqwest::blocking::Response) -> String {
    let mut body = Vec::new();
    let mut limited = (&mut response).take(MAX_ERROR_BODY_BYTES);

    if limited.read_to_end(&mut body).is_err() {
        return String::new();
    }

    String::from_utf8_lossy(&body).into_owned()
}

fn http_error_message(
    method: &str,
    path: &str,
    status: reqwest::StatusCode,
    body: &str,
    empty_body_hint: Option<&str>,
) -> String {
    let mut message = format!("{method} {path} returned {status}");
    let body = safe_error_body_excerpt(body);

    if !body.is_empty() {
        message.push_str(": ");
        message.push_str(&body);
    } else if let Some(hint) = empty_body_hint {
        message.push(' ');
        message.push_str(hint);
    }

    message
}

fn safe_error_body_excerpt(body: &str) -> String {
    let mut excerpt = String::new();
    let mut pending_space = false;
    let mut kept_chars = 0;

    for ch in body.trim().chars() {
        if kept_chars >= MAX_ERROR_BODY_CHARS {
            break;
        }

        if ch.is_control() {
            if matches!(ch, '\n' | '\r' | '\t') {
                pending_space = true;
            }
            continue;
        }

        if ch.is_whitespace() {
            pending_space = true;
            continue;
        }

        if pending_space && !excerpt.is_empty() {
            excerpt.push(' ');
            kept_chars += 1;
            if kept_chars >= MAX_ERROR_BODY_CHARS {
                break;
            }
        }
        excerpt.push(ch);
        kept_chars += 1;
        pending_space = false;
    }

    excerpt
}

// ── Keypair loading ───────────────────────────────────────────────────────────

fn load_keypair() -> Option<Keypair> {
    let key_path = resolve_key_path();
    if !key_path.exists() {
        tracing::debug!("no keypair found at {key_path:?}");
        return None;
    }
    match std::fs::read_to_string(&key_path) {
        Ok(pem) => match Keypair::from_pem(&pem) {
            Ok(kp) => {
                tracing::debug!("loaded keypair — DID: {}", kp.did());
                Some(kp)
            }
            Err(e) => {
                tracing::warn!("failed to parse keypair at {key_path:?}: {e}");
                None
            }
        },
        Err(e) => {
            tracing::warn!("failed to read {key_path:?}: {e}");
            None
        }
    }
}

fn resolve_key_path() -> std::path::PathBuf {
    let path_str =
        std::env::var("GITLAWB_KEY").unwrap_or_else(|_| "~/.gitlawb/identity.pem".to_string());

    if let Some(stripped) = path_str.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(home).join(stripped)
    } else {
        std::path::PathBuf::from(path_str)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;

    struct TestResponse {
        request_line: &'static str,
        status: &'static str,
        body: &'static str,
    }

    fn serve_http(responses: Vec<TestResponse>) -> (String, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();

            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                assert!(
                    request.starts_with(response.request_line),
                    "unexpected request:\n{request}"
                );

                let response_text = format!(
                    "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.status,
                    response.body.len(),
                    response.body
                );
                stream.write_all(response_text.as_bytes()).unwrap();
                requests.push(request);
            }

            requests
        });

        (base_url, handle)
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        let mut header_len = None;

        loop {
            let n = stream.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);

            if header_len.is_none() {
                header_len = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
            }

            if let Some(header_len) = header_len {
                let header = String::from_utf8_lossy(&buf[..header_len]);
                let content_len = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);

                if buf.len() >= header_len + content_len {
                    break;
                }
            }
        }

        String::from_utf8_lossy(&buf).into_owned()
    }

    /// The regression that round-1 missed: the Phase-2 `git-upload-pack` POST was
    /// left unsigned, so an owner's fetch of a private repo cleared the (now signed)
    /// advertisement and then 404'd on the pack POST. Drive BOTH request builders
    /// against a mock node and assert the RFC-9421 headers actually go out on the
    /// wire for BOTH services when a keypair is present (the mock only matches when
    /// the headers exist, so `.assert()` fails if any are dropped).
    #[test]
    fn advertisement_and_pack_post_are_signed_for_both_services_with_keypair() {
        let kp = Keypair::generate();
        let client = reqwest::blocking::Client::new();
        let body = b"0009done\n".to_vec();

        for service in ["git-upload-pack", "git-receive-pack"] {
            let mut server = mockito::Server::new();
            let repo_base = format!("{}/zOwner/myrepo", server.url());

            let get_mock = server
                .mock("GET", mockito::Matcher::Regex(r"/info/refs".to_string()))
                .match_header("signature", mockito::Matcher::Any)
                .match_header("signature-input", mockito::Matcher::Any)
                .match_header("content-digest", mockito::Matcher::Any)
                .with_status(200)
                .create();
            let refs_url = format!("{repo_base}/info/refs?service={service}");
            let resp = build_advertisement_request(&client, &refs_url, Some(&kp))
                .send()
                .unwrap();
            assert!(resp.status().is_success());
            get_mock.assert();

            let post_mock = server
                .mock("POST", mockito::Matcher::Regex(format!("/{service}$")))
                .match_header("signature", mockito::Matcher::Any)
                .match_header("signature-input", mockito::Matcher::Any)
                .match_header("content-digest", mockito::Matcher::Any)
                .with_status(200)
                .create();
            let post_url = format!("{repo_base}/{service}");
            let resp = build_pack_post_request(&client, &post_url, service, &body, Some(&kp))
                .body(body.clone())
                .send()
                .unwrap();
            assert!(resp.status().is_success());
            post_mock.assert();
        }
    }

    /// Without an identity, the pack POST must go out UNSIGNED so public fetch (and
    /// alpha unsigned push) still work. `Matcher::Missing` matches only when the
    /// header is absent, so the mock is hit only if NO signature was attached, for
    /// BOTH services (the receive-pack iteration also exercises the no-keypair warn
    /// branch and confirms it does not block the request).
    #[test]
    fn pack_post_is_unsigned_without_keypair_for_both_services() {
        let client = reqwest::blocking::Client::new();
        let body = b"0009done\n".to_vec();

        for service in ["git-upload-pack", "git-receive-pack"] {
            let mut server = mockito::Server::new();
            let post_url = format!("{}/zOwner/myrepo/{service}", server.url());

            let post_mock = server
                .mock("POST", mockito::Matcher::Regex(format!("/{service}$")))
                .match_header("signature", mockito::Matcher::Missing)
                .match_header("signature-input", mockito::Matcher::Missing)
                .match_header("content-digest", mockito::Matcher::Missing)
                .with_status(200)
                .create();
            let resp = build_pack_post_request(&client, &post_url, service, &body, None)
                .body(body.clone())
                .send()
                .unwrap();
            assert!(resp.status().is_success());
            post_mock.assert();
        }
    }

    /// Symmetric negative case for Phase 1: with no identity the advertisement GET
    /// carries no signature, so public clones stay anonymous.
    #[test]
    fn advertisement_get_is_unsigned_without_keypair() {
        let client = reqwest::blocking::Client::new();
        let mut server = mockito::Server::new();
        let refs_url = format!(
            "{}/zOwner/myrepo/info/refs?service=git-upload-pack",
            server.url()
        );

        let get_mock = server
            .mock("GET", mockito::Matcher::Regex(r"/info/refs".to_string()))
            .match_header("signature", mockito::Matcher::Missing)
            .match_header("signature-input", mockito::Matcher::Missing)
            .match_header("content-digest", mockito::Matcher::Missing)
            .with_status(200)
            .create();
        let resp = build_advertisement_request(&client, &refs_url, None)
            .send()
            .unwrap();
        assert!(resp.status().is_success());
        get_mock.assert();
    }

    // ── Phase-1 retry-on-404 (P2, #119): fetch stays anonymous until the node
    //    denies it, then escalates to ONE signed retry. Drives handle_connect end to
    //    end against the recording mock, asserting what actually goes on the wire.
    //    A request is "signed" iff it carries the `signature-input` header.

    /// Public fetch: the node serves the anonymous advertisement (200), so the
    /// client never signs — not the advertisement GET, not the upload-pack POST —
    /// even though an identity is present. This is the privacy fix: a public clone
    /// must not disclose the caller's DID.
    #[test]
    fn fetch_public_stays_anonymous_even_with_keypair() {
        let kp = Keypair::generate();
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = std::io::Cursor::new(b"0009done\n".to_vec());
        handle_connect(&repo_base, "git-upload-pack", Some(&kp), &mut stdin)
            .expect("public fetch should succeed");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2, "public fetch must not retry");
        assert!(
            !requests[0].to_lowercase().contains("signature-input"),
            "the advertisement GET must be anonymous for a public fetch"
        );
        assert!(
            !requests[1].to_lowercase().contains("signature-input"),
            "the upload-pack POST must be anonymous for a public fetch"
        );
    }

    /// Private fetch: the anonymous advertisement is denied (404); with an identity
    /// present the client retries the GET signed and — because Phase 1 needed
    /// signing — also signs the Phase-2 upload-pack POST. The FIRST request is still
    /// anonymous: the DID is not disclosed until the node demands authentication.
    #[test]
    fn fetch_private_retries_signed_on_404_and_signs_the_pack_post() {
        let kp = Keypair::generate();
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "404 Not Found",
                body: r#"{"message":"repository is not registered on this node"}"#,
            },
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = std::io::Cursor::new(b"0009done\n".to_vec());
        handle_connect(&repo_base, "git-upload-pack", Some(&kp), &mut stdin)
            .expect("signed retry should succeed");
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            3,
            "expected anon GET, signed GET retry, signed POST"
        );
        assert!(
            !requests[0].to_lowercase().contains("signature-input"),
            "the first advertisement GET must be anonymous"
        );
        assert!(
            requests[1].to_lowercase().contains("signature-input"),
            "the retry advertisement GET must be signed"
        );
        assert!(
            requests[2].to_lowercase().contains("signature-input"),
            "the upload-pack POST must be signed once the fetch needed auth"
        );
    }

    /// Private fetch with no identity: the anonymous advertisement 404s and there is
    /// no keypair to retry with, so the client surfaces the error after exactly one
    /// request — no retry, no hang.
    #[test]
    fn fetch_without_keypair_does_not_retry_on_404() {
        let (base_url, server) = serve_http(vec![TestResponse {
            request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
            status: "404 Not Found",
            body: r#"{"message":"not found"}"#,
        }]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let err = handle_connect(&repo_base, "git-upload-pack", None, &mut stdin).unwrap_err();
        assert!(err.to_string().contains("returned 404 Not Found"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1, "no keypair means no signed retry");
        assert!(!requests[0].to_lowercase().contains("signature-input"));
    }

    /// Private fetch where the SIGNED retry is also denied (caller is not a reader):
    /// the client retries exactly once, then surfaces the 404 rather than looping.
    /// Bounds the escalation to a single signed attempt.
    #[test]
    fn fetch_signed_retry_still_denied_surfaces_error_once() {
        let kp = Keypair::generate();
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "404 Not Found",
                body: r#"{"message":"not found"}"#,
            },
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "404 Not Found",
                body: r#"{"message":"not found"}"#,
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let err = handle_connect(&repo_base, "git-upload-pack", Some(&kp), &mut stdin).unwrap_err();
        assert!(err.to_string().contains("returned 404 Not Found"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2, "exactly one signed retry, then surface");
        assert!(!requests[0].to_lowercase().contains("signature-input"));
        assert!(requests[1].to_lowercase().contains("signature-input"));
    }

    /// Push (git-receive-pack) is unchanged: it signs from the FIRST request — you
    /// cannot push anonymously — so there is no anonymous-first probe for push.
    #[test]
    fn push_advertisement_is_signed_from_the_first_request() {
        let kp = Keypair::generate();
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-receive-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-receive-pack",
                status: "200 OK",
                body: "",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = std::io::Cursor::new(b"0000".to_vec());
        handle_connect(&repo_base, "git-receive-pack", Some(&kp), &mut stdin)
            .expect("push should succeed");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0].to_lowercase().contains("signature-input"),
            "push advertisement must be signed from the first request"
        );
        assert!(
            requests[1].to_lowercase().contains("signature-input"),
            "push POST must be signed"
        );
    }

    /// Cross-crate seam: the signature the CLIENT actually emits (via the real
    /// request builders) verifies under the SAME `gitlawb_core::http_sig`
    /// primitives the node's `require_signature` uses, over the `@path` the client
    /// genuinely transmits (derived from the built reqwest request, exactly as the
    /// node derives it from `uri.path_and_query()`). A tampered `@path` must fail:
    /// this is the byte-match the whole A1 client fix depends on, now executed end
    /// to end (sign here, verify with the node's verifier), not reasoned.
    #[test]
    fn client_signature_verifies_under_node_verification_for_both_services() {
        use gitlawb_core::http_sig::{build_signing_string, compute_content_digest, HttpSignature};
        use gitlawb_core::identity::verify;
        use std::collections::HashMap;

        let kp = Keypair::generate();
        let client = reqwest::blocking::Client::new();
        let body = b"0009done\n".to_vec();

        // Re-implements the node's require_signature verification (auth/mod.rs):
        // parse headers, recompute content-digest from the body, rebuild the signing
        // string over @method/@path/content-digest, Ed25519-verify. Ok iff the node
        // would accept it.
        let node_verifies = |method: &str,
                             path_and_query: &str,
                             body: &[u8],
                             sig_input: &str,
                             sig_header: &str,
                             content_digest: &str|
         -> anyhow::Result<()> {
            let sig = HttpSignature::parse(sig_input, sig_header)?;
            sig.check_created()?;
            assert!(
                sig.missing_components().is_empty(),
                "signature must cover all required components"
            );
            assert_eq!(sig.alg, "ed25519");
            assert_eq!(
                content_digest,
                compute_content_digest(body),
                "content-digest must match the body"
            );
            let vk = sig.key_id.to_verifying_key()?;
            let mut values = HashMap::new();
            values.insert("@method".to_string(), method.to_uppercase());
            values.insert("@path".to_string(), path_and_query.to_string());
            values.insert("content-digest".to_string(), content_digest.to_string());
            let sig_params_value = sig_input.strip_prefix("sig1=").unwrap_or(sig_input);
            let components: Vec<&str> = sig.components.iter().map(String::as_str).collect();
            let signing_string = build_signing_string(&components, sig_params_value, &values)?;
            let sig_array: [u8; 64] = sig.signature_bytes.as_slice().try_into()?;
            verify(&vk, signing_string.as_bytes(), &sig_array)?;
            Ok(())
        };
        // @path exactly as the node reconstructs it from the request it receives.
        let path_and_query = |req: &reqwest::blocking::Request| match req.url().query() {
            Some(q) => format!("{}?{}", req.url().path(), q),
            None => req.url().path().to_string(),
        };
        let header = |req: &reqwest::blocking::Request, name: &str| {
            req.headers()
                .get(name)
                .unwrap_or_else(|| panic!("missing {name}"))
                .to_str()
                .unwrap()
                .to_string()
        };

        for service in ["git-upload-pack", "git-receive-pack"] {
            // Phase-1 advertisement GET (empty body).
            let refs_url = format!("http://node.example/zOwner/myrepo/info/refs?service={service}");
            let req = build_advertisement_request(&client, &refs_url, Some(&kp))
                .build()
                .unwrap();
            node_verifies(
                "GET",
                &path_and_query(&req),
                b"",
                &header(&req, "signature-input"),
                &header(&req, "signature"),
                &header(&req, "content-digest"),
            )
            .expect("client GET signature must verify under the node's verifier");

            // Phase-2 pack POST (real body).
            let post_url = format!("http://node.example/zOwner/myrepo/{service}");
            let req = build_pack_post_request(&client, &post_url, service, &body, Some(&kp))
                .body(body.clone())
                .build()
                .unwrap();
            let pq = path_and_query(&req);
            node_verifies(
                "POST",
                &pq,
                &body,
                &header(&req, "signature-input"),
                &header(&req, "signature"),
                &header(&req, "content-digest"),
            )
            .expect("client POST signature must verify under the node's verifier");

            // Negative: a tampered @path (the A1 attack surface) must NOT verify.
            let tampered = pq.replace(service, "git-evil");
            assert!(
                node_verifies(
                    "POST",
                    &tampered,
                    &body,
                    &header(&req, "signature-input"),
                    &header(&req, "signature"),
                    &header(&req, "content-digest"),
                )
                .is_err(),
                "a tampered @path must fail verification"
            );
        }

        // #117: a multi-round POST body (wants + flush + accumulated haves + done)
        // signs and verifies over its EXACT bytes. Each per-round POST a private
        // fetch emits is a different accumulated body, and build_pack_post_request
        // signs the same bytes it sends, so every round is independently accepted
        // by the node verifier, not just the single-round `done` body.
        let mut acc = Vec::new();
        acc.extend_from_slice(&pkt(&format!(
            "want {} multi_ack_detailed side-band-64k\n",
            "a".repeat(40)
        )));
        acc.extend_from_slice(b"0000");
        acc.extend_from_slice(&pkt(&format!("have {}\n", "1".repeat(40))));
        acc.extend_from_slice(&pkt(&format!("have {}\n", "2".repeat(40))));
        acc.extend_from_slice(&pkt("done\n"));
        let post_url = "http://node.example/zOwner/myrepo/git-upload-pack";
        let req = build_pack_post_request(&client, post_url, "git-upload-pack", &acc, Some(&kp))
            .body(acc.clone())
            .build()
            .unwrap();
        node_verifies(
            "POST",
            &path_and_query(&req),
            &acc,
            &header(&req, "signature-input"),
            &header(&req, "signature"),
            &header(&req, "content-digest"),
        )
        .expect("a multi-round accumulated POST body must verify under the node's verifier");
    }

    #[test]
    fn parse_standard_url() {
        let (did, owner, repo) = parse_gitlawb_url("gitlawb://did:key:z6MkFoo123/my-repo").unwrap();
        assert_eq!(did, "did:key:z6MkFoo123");
        assert_eq!(owner, "z6MkFoo123");
        assert_eq!(repo, "my-repo");
    }

    #[test]
    fn parse_url_strips_dot_git() {
        let (_, _, repo) = parse_gitlawb_url("gitlawb://did:key:z6MkFoo123/my-repo.git").unwrap();
        assert_eq!(repo, "my-repo");
    }

    #[test]
    fn parse_url_requires_scheme() {
        assert!(parse_gitlawb_url("http://example.com/repo").is_err());
    }

    #[test]
    fn parse_url_requires_repo_segment() {
        assert!(parse_gitlawb_url("gitlawb://did:key:z6MkFoo123").is_err());
    }

    #[test]
    fn strip_service_line() {
        // Simulate: pkt-line("# service=git-upload-pack\n") + "0000" + b"actual-refs"
        let service_line = "# service=git-upload-pack\n";
        let pkt_len = service_line.len() + 4;
        let header = format!("{:04x}{}", pkt_len, service_line);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(b"0000");
        bytes.extend_from_slice(b"actual-refs");

        let stripped = strip_service_announcement(&bytes);
        assert_eq!(stripped, b"actual-refs");
    }

    #[test]
    fn extract_url_path() {
        assert_eq!(
            url_path("http://127.0.0.1:7545/z6Mk/myrepo/git-receive-pack"),
            "/z6Mk/myrepo/git-receive-pack"
        );
    }

    #[test]
    fn http_error_message_sanitizes_response_body_controls() {
        let message = http_error_message(
            "GET",
            "/info/refs",
            reqwest::StatusCode::BAD_GATEWAY,
            "\u{1b}[2Jrepository\r\nis\tblocked\u{7}",
            None,
        );

        assert!(message.contains("repository is blocked"));
        assert!(!message.contains('\u{1b}'));
        assert!(!message.contains('\u{7}'));
        assert!(!message.contains('\r'));
        assert!(!message.contains('\n'));
    }

    #[test]
    fn http_error_message_truncates_long_response_body() {
        let body = "x".repeat(MAX_ERROR_BODY_CHARS + 100);
        let message = http_error_message(
            "POST",
            "/git-receive-pack",
            reqwest::StatusCode::FORBIDDEN,
            &body,
            None,
        );
        let prefix = "POST /git-receive-pack returned 403 Forbidden: ";

        assert_eq!(message.len(), prefix.len() + MAX_ERROR_BODY_CHARS);
        assert!(message.starts_with(prefix));
    }

    #[test]
    fn connect_get_error_includes_response_body() {
        let (base_url, server) = serve_http(vec![TestResponse {
            request_line: "GET /z6Mk/myrepo/info/refs?service=git-upload-pack HTTP/1.1",
            status: "404 Not Found",
            body: r#"{"message":"repository is not registered on this node"}"#,
        }]);

        let repo_base = format!("{base_url}/z6Mk/myrepo");
        let mut stdin = std::io::Cursor::new(Vec::<u8>::new());
        let err = handle_connect(&repo_base, "git-upload-pack", None, &mut stdin).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("GET /info/refs returned 404 Not Found"));
        assert!(message.contains("repository is not registered on this node"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn connect_post_error_includes_response_body() {
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /z6Mk/myrepo/info/refs?service=git-receive-pack HTTP/1.1",
                status: "200 OK",
                body: "",
            },
            TestResponse {
                request_line: "POST /z6Mk/myrepo/git-receive-pack HTTP/1.1",
                status: "403 Forbidden",
                body: r#"{"error":"forbidden","message":"push rejected: only the repo owner may push"}"#,
            },
        ]);

        let repo_base = format!("{base_url}/z6Mk/myrepo");
        let mut stdin = std::io::Cursor::new(b"0000".to_vec());
        let err = handle_connect(&repo_base, "git-receive-pack", None, &mut stdin).unwrap_err();
        let message = err.to_string();

        assert!(message.contains("POST /git-receive-pack returned 403 Forbidden"));
        assert!(message.contains("push rejected: only the repo owner may push"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("\r\n\r\n0000"));
    }

    #[test]
    fn url_path_preserves_query_for_signed_advertisement() {
        // The Phase-1 advertisement GET is signed over url_path(refs_url), and the
        // node verifies the signature over its path_and_query, so the ?service=
        // query MUST survive verbatim or the signatures will not byte-match.
        assert_eq!(
            url_path("http://127.0.0.1:7545/z6Mk/myrepo/info/refs?service=git-upload-pack"),
            "/z6Mk/myrepo/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            url_path("http://127.0.0.1:7545/z6Mk/myrepo/info/refs?service=git-receive-pack"),
            "/z6Mk/myrepo/info/refs?service=git-receive-pack"
        );
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn classify_version_flags() {
        assert_eq!(
            classify_args(&args(&["git-remote-gitlawb", "--version"])),
            Invocation::Version
        );
        assert_eq!(
            classify_args(&args(&["git-remote-gitlawb", "-V"])),
            Invocation::Version
        );
    }

    #[test]
    fn classify_help_flags() {
        assert_eq!(
            classify_args(&args(&["git-remote-gitlawb", "--help"])),
            Invocation::Help
        );
        assert_eq!(
            classify_args(&args(&["git-remote-gitlawb", "-h"])),
            Invocation::Help
        );
    }

    #[test]
    fn classify_normal_helper_invocation() {
        // How git actually calls us: `<remote-name> <url>`.
        assert_eq!(
            classify_args(&args(&[
                "git-remote-gitlawb",
                "origin",
                "gitlawb://did:key:z6MkFoo123/my-repo",
            ])),
            Invocation::Helper
        );
    }

    #[test]
    fn classify_no_args_is_helper() {
        // No flag → falls through to the helper path, which reports its own
        // usage error. `--version`/`--help` must not be inferred from emptiness.
        assert_eq!(
            classify_args(&args(&["git-remote-gitlawb"])),
            Invocation::Helper
        );
    }

    #[test]
    fn classify_flag_only_in_first_position() {
        // A remote literally named "--version" must not be treated as the flag.
        assert_eq!(
            classify_args(&args(&["git-remote-gitlawb", "origin", "--version",])),
            Invocation::Helper
        );
    }

    #[test]
    fn version_line_matches_package_metadata() {
        let line = version_line();
        assert_eq!(
            line,
            format!("git-remote-gitlawb {}", env!("CARGO_PKG_VERSION"))
        );
        // Single line, no trailing newline (println! adds the newline).
        assert!(!line.contains('\n'));
    }

    #[test]
    fn help_text_includes_version_and_flags() {
        let help = help_text();
        assert!(help.starts_with(&version_line()));
        assert!(help.contains("--version"));
        assert!(help.contains("--help"));
        assert!(help.contains("GITLAWB_NODE"));
        assert!(help.ends_with('\n'));
    }

    // ── #117 multi-round fetch negotiation ───────────────────────────────────

    /// Encode a git pkt-line: 4-byte hex length (incl. the 4 bytes) + data.
    fn pkt(data: &str) -> Vec<u8> {
        format!("{:04x}{}", data.len() + 4, data).into_bytes()
    }

    /// A realistic capability-bearing opening want line (git puts its capability
    /// list on the first want), so the multi-round tests exercise the want shape
    /// real git actually sends, not a bare `want <sha>`.
    fn want_line(sha: &str) -> Vec<u8> {
        pkt(&format!(
            "want {sha} multi_ack_detailed side-band-64k ofs-delta agent=git/2.43\n"
        ))
    }

    /// A reader that yields `seed`, then BLOCKS until `gate` fires. Models git
    /// holding the upload-pack pipe open after a have-batch flush, waiting for the
    /// server's ACK/NAK before it sends more. A real pipe blocks here; an in-memory
    /// Cursor would EOF and hide the bug, which is why the pre-#117 tests missed it.
    struct BlockAfterSeed {
        seed: io::Cursor<Vec<u8>>,
        gate: std::sync::mpsc::Receiver<()>,
    }
    impl Read for BlockAfterSeed {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.seed.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            let _ = self.gate.recv(); // block like a live pipe; unblock -> EOF
            Ok(0)
        }
    }

    /// #117 primitive contract (matrix item 1): `read_upload_pack_round` returns at
    /// a flush-terminated batch instead of buffering past it waiting for `done`.
    /// The pre-#117 `read_upload_pack_request` blocked here (the deadlock). A
    /// blocking reader proves the return under live-pipe semantics: if the reader
    /// buffered past the flush it would block on the gate and the test would time out.
    #[test]
    fn read_upload_pack_round_returns_on_flush_without_done() {
        let mut seed = Vec::new();
        seed.extend_from_slice(&want_line(&"a".repeat(40)));
        seed.extend_from_slice(b"0000"); // end of wants
        for i in 0..32u32 {
            seed.extend_from_slice(&pkt(&format!("have {:040x}\n", i)));
        }
        seed.extend_from_slice(b"0000"); // have-batch flush; git awaits ACK, sends NO done

        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let mut reader = BlockAfterSeed {
            seed: io::Cursor::new(seed),
            gate: rx,
        };

        let (done_tx, done_rx) = std::sync::mpsc::channel::<(Vec<u8>, RoundEnd)>();
        let handle = std::thread::spawn(move || {
            // Opening round (wants) returns at the first flush; the have batch
            // returns at the second flush. Neither may block for a `done`.
            let _wants = read_upload_pack_round(&mut reader).unwrap();
            let haves = read_upload_pack_round(&mut reader).unwrap();
            let _ = done_tx.send(haves);
        });

        let got = done_rx.recv_timeout(std::time::Duration::from_secs(2));
        let _ = tx.send(()); // unblock the reader so the thread can exit
        let _ = handle.join();

        let (batch, end) = got.expect(
            "read_upload_pack_round blocked past a flush-terminated have-batch \
             waiting for `done` (multi-round fetch deadlock #117)",
        );
        assert_eq!(end, RoundEnd::Flush, "a flush terminates the round");
        assert!(
            batch.windows(4).any(|w| w == b"have"),
            "the have batch content is returned to the caller"
        );
    }

    /// #117 core (matrix item 2): a multi-round negotiation issues MORE THAN ONE
    /// POST, and each POST body is a self-contained stateless-RPC request: wants +
    /// one flush + every have accumulated so far + exactly one terminator. The
    /// round-2 body is asserted byte-for-byte, which pins both accumulation (round
    /// 1's have is present) and the one-terminator invariant (no intermediate flush
    /// survives). Pre-#117 this was a single POST.
    #[test]
    fn multi_round_fetch_posts_each_round_with_accumulated_wants_and_haves() {
        let want_sha = "a".repeat(40);
        let have1 = "1".repeat(40);
        let have2 = "2".repeat(40);
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            // Round 1 (flush-terminated): an ACK/NAK continuation, no pack yet.
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\n",
            },
            // Round 2 (done): final response plus the (fake) pack.
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\nPACKfake",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");

        let wants = want_line(&want_sha);
        let mut stdin_bytes = Vec::new();
        stdin_bytes.extend_from_slice(&wants);
        stdin_bytes.extend_from_slice(b"0000"); // end of wants
        stdin_bytes.extend_from_slice(&pkt(&format!("have {have1}\n")));
        stdin_bytes.extend_from_slice(b"0000"); // round-1 flush: git awaits ACK
        stdin_bytes.extend_from_slice(&pkt(&format!("have {have2}\n")));
        stdin_bytes.extend_from_slice(&pkt("done\n")); // round-2 terminator

        let mut stdin = io::Cursor::new(stdin_bytes);
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("multi-round fetch should complete");

        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            3,
            "GET + two POSTs, one per negotiation round"
        );
        assert!(
            request_body(&requests[1])
                .windows(want_sha.len())
                .any(|w| w == want_sha.as_bytes()),
            "round-1 POST must carry the wants"
        );

        // Round-2 body: wants + one flush + BOTH haves + done, with no flush
        // between the haves (the accumulation + one-terminator invariant).
        let mut expected = Vec::new();
        expected.extend_from_slice(&wants);
        expected.extend_from_slice(b"0000");
        expected.extend_from_slice(&pkt(&format!("have {have1}\n")));
        expected.extend_from_slice(&pkt(&format!("have {have2}\n")));
        expected.extend_from_slice(&pkt("done\n"));
        assert_eq!(
            request_body(&requests[2]),
            expected,
            "round-2 POST body must be wants + flush + all accumulated haves + one done terminator"
        );
    }

    /// Extract the HTTP request body (bytes after the header/body separator) from a
    /// captured request string. pkt-lines are ASCII, so the lossy round-trip is exact.
    fn request_body(request: &str) -> Vec<u8> {
        match request.split_once("\r\n\r\n") {
            Some((_, body)) => body.as_bytes().to_vec(),
            None => Vec::new(),
        }
    }

    /// U4 / INV-8 / INV-12: a private-repo multi-round fetch escalates on the 404
    /// exactly once, then EVERY per-round POST carries the signature. Must-not: no
    /// round goes out unsigned (an unsigned round 2 would 404 the owner's own fetch).
    #[test]
    fn private_multi_round_signs_every_post() {
        let kp = Keypair::generate();
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "404 Not Found",
                body: r#"{"message":"not found"}"#,
            },
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\n",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\nPACKfake",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = io::Cursor::new(two_round_stdin());
        handle_connect(&repo_base, "git-upload-pack", Some(&kp), &mut stdin)
            .expect("private multi-round fetch should complete");

        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            4,
            "anon GET, signed GET retry, then two signed POSTs"
        );
        assert!(
            !requests[0].to_lowercase().contains("signature-input"),
            "first GET is anonymous"
        );
        assert!(
            requests[1].to_lowercase().contains("signature-input"),
            "GET retry is signed"
        );
        assert!(
            requests[2].to_lowercase().contains("signature-input"),
            "round-1 POST is signed"
        );
        assert!(
            requests[3].to_lowercase().contains("signature-input"),
            "round-2 POST is signed: no per-round POST may go out unsigned for a private repo"
        );
    }

    /// U4: a public multi-round fetch stays anonymous on EVERY round even with a
    /// keypair present. Must-not: no round signs (no DID disclosure on a public fetch).
    #[test]
    fn public_multi_round_stays_anonymous_every_post() {
        let kp = Keypair::generate();
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\n",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\nPACKfake",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = io::Cursor::new(two_round_stdin());
        handle_connect(&repo_base, "git-upload-pack", Some(&kp), &mut stdin)
            .expect("public multi-round fetch should complete");

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 3, "GET + two POSTs, no retry");
        for (i, r) in requests.iter().enumerate() {
            assert!(
                !r.to_lowercase().contains("signature-input"),
                "request {i} must stay anonymous on a public fetch"
            );
        }
    }

    /// U4 / INV-8 / INV-12: a denial mid-negotiation (round-2 POST 404) surfaces as
    /// an error, not a silent empty/successful fetch, and does NOT re-trigger the
    /// Phase-1 signed-retry escalation (that is a GET-only, Phase-1-only behavior).
    #[test]
    fn mid_negotiation_post_denial_surfaces_without_reescalation() {
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\n",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "404 Not Found",
                body: r#"{"message":"repository is no longer readable"}"#,
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = io::Cursor::new(two_round_stdin());
        let err = handle_connect(&repo_base, "git-upload-pack", None, &mut stdin).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("POST /git-upload-pack returned 404 Not Found"),
            "the mid-negotiation denial must surface, not read as an empty/successful fetch"
        );
        assert!(message.contains("repository is no longer readable"));
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            3,
            "GET + two POSTs, then bail: a POST denial must not re-run the Phase-1 escalation"
        );
    }

    /// Two-round upload-pack request: wants, flush, have1, flush (round 1), have2,
    /// done (round 2). Shared by the U4 signing/denial tests.
    fn two_round_stdin() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&want_line(&"a".repeat(40)));
        v.extend_from_slice(b"0000");
        v.extend_from_slice(&pkt(&format!("have {}\n", "1".repeat(40))));
        v.extend_from_slice(b"0000");
        v.extend_from_slice(&pkt(&format!("have {}\n", "2".repeat(40))));
        v.extend_from_slice(&pkt("done\n"));
        v
    }

    /// U5 (matrix item 5, plumbing only): the node's withheld-blob path
    /// (`upload_pack_excluding`) ignores negotiation and answers the first POST
    /// with NAK plus a full self-contained pack. The helper must forward that
    /// response and terminate without hanging. Whether REAL git accepts a pack
    /// where it expected an ACK continuation is U7's real-git scenario, not this
    /// mock (a Cursor never reacts to the response).
    #[test]
    fn withheld_shaped_response_is_forwarded_without_hanging() {
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            // Withheld shape: NAK + full pack on the FIRST POST, negotiation ignored.
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\nPACKfullselfcontainedpack",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        // A single flush-terminated round then EOF: the helper POSTs once, forwards
        // the NAK+pack, and terminates at EOF rather than looping forever.
        let mut stdin_bytes = Vec::new();
        stdin_bytes.extend_from_slice(&want_line(&"a".repeat(40)));
        stdin_bytes.extend_from_slice(b"0000");
        stdin_bytes.extend_from_slice(&pkt(&format!("have {}\n", "1".repeat(40))));
        stdin_bytes.extend_from_slice(b"0000");
        let mut stdin = io::Cursor::new(stdin_bytes);
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("withheld-shaped fetch should forward the pack and terminate");
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "GET + one POST; the forwarded pack does not hang the helper"
        );
    }

    /// U6 (matrix item 6): a fresh clone (wants, flush, done) issues exactly ONE POST.
    #[test]
    fn fresh_clone_issues_single_post() {
        let want_sha = "a".repeat(40);
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\nPACKfake",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin_bytes = Vec::new();
        stdin_bytes.extend_from_slice(&want_line(&want_sha));
        stdin_bytes.extend_from_slice(b"0000");
        stdin_bytes.extend_from_slice(&pkt("done\n"));
        let mut stdin = io::Cursor::new(stdin_bytes);
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("clone should complete");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 2, "fresh clone is exactly one POST");
        assert!(request_body(&requests[1])
            .windows(want_sha.len())
            .any(|w| w == want_sha.as_bytes()));
    }

    /// U6 (matrix item 6): an up-to-date / flush-only opener issues ZERO POSTs and
    /// completes without entering an ACK wait.
    #[test]
    fn flush_only_opener_skips_post() {
        let (base_url, server) = serve_http(vec![TestResponse {
            request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
            status: "200 OK",
            body: "0000",
        }]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = io::Cursor::new(b"0000".to_vec()); // flush only, nothing to fetch
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("up-to-date fetch should complete");
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1, "flush-only opener issues no POST");
    }

    /// U6 (matrix item 6): a single-shot fetch git resolved in one round (wants,
    /// flush, haves, done, no intermediate flush) issues exactly ONE POST. Must-not:
    /// the fix must not split a single-shot negotiation into multiple POSTs.
    #[test]
    fn single_shot_fetch_is_one_post() {
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\nPACKfake",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin_bytes = Vec::new();
        stdin_bytes.extend_from_slice(&want_line(&"a".repeat(40)));
        stdin_bytes.extend_from_slice(b"0000");
        stdin_bytes.extend_from_slice(&pkt(&format!("have {}\n", "1".repeat(40))));
        stdin_bytes.extend_from_slice(&pkt(&format!("have {}\n", "2".repeat(40))));
        stdin_bytes.extend_from_slice(&pkt("done\n")); // done with no intermediate flush
        let mut stdin = io::Cursor::new(stdin_bytes);
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("fetch should complete");
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "a single-shot negotiation must be exactly one POST, not split"
        );
    }

    /// Hardening: content-free flush pkts between the wants and the first haves do
    /// not each fire a POST. Real git never sends a bare mid-negotiation flush, but
    /// a malformed stream must not amplify into one signed POST per empty flush; the
    /// loop skips them and POSTs only the round that carries haves + done.
    #[test]
    fn repeated_bare_flushes_do_not_amplify_posts() {
        let (base_url, server) = serve_http(vec![
            TestResponse {
                request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
                status: "200 OK",
                body: "0000",
            },
            TestResponse {
                request_line: "POST /zOwner/myrepo/git-upload-pack",
                status: "200 OK",
                body: "0008NAK\nPACKfake",
            },
        ]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin_bytes = Vec::new();
        stdin_bytes.extend_from_slice(&want_line(&"a".repeat(40)));
        stdin_bytes.extend_from_slice(b"0000");
        stdin_bytes.extend_from_slice(b"0000"); // bare flush, no haves
        stdin_bytes.extend_from_slice(b"0000"); // bare flush, no haves
        stdin_bytes.extend_from_slice(&pkt(&format!("have {}\n", "1".repeat(40))));
        stdin_bytes.extend_from_slice(&pkt("done\n"));
        let mut stdin = io::Cursor::new(stdin_bytes);
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("fetch with stray flushes should complete");
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            2,
            "content-free flushes must not each produce a POST"
        );
    }

    // ── Branch-coverage closure: exercise the remaining changed arms ─────────

    /// A reader that fails with a non-EOF io error, to exercise the error
    /// propagation arm of `read_upload_pack_round` (distinct from a clean EOF).
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("simulated read failure"))
        }
    }

    /// G4: a non-EOF read error propagates; it is not swallowed as end-of-stream.
    #[test]
    fn read_upload_pack_round_propagates_read_error() {
        let mut r = FailingReader;
        assert!(read_upload_pack_round(&mut r).is_err());
    }

    /// G1: an invalid pkt-line length (1..=3) is rejected rather than underflowing
    /// `pkt_len - 4`.
    #[test]
    fn read_upload_pack_round_rejects_invalid_pkt_length() {
        let mut r = io::Cursor::new(b"0001".to_vec()); // pkt_len 1, < 4
        let err = read_upload_pack_round(&mut r).unwrap_err();
        assert!(
            err.to_string().contains("invalid pkt-line length"),
            "unexpected error: {err}"
        );
    }

    /// G2: an immediately-empty upload-pack request (EOF at the opening round, with
    /// a 200 advertisement) skips the POST entirely.
    #[test]
    fn upload_pack_empty_request_skips_post() {
        let (base_url, server) = serve_http(vec![TestResponse {
            request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
            status: "200 OK",
            body: "0000",
        }]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = io::Cursor::new(Vec::<u8>::new()); // immediate EOF
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("empty upload-pack request should skip the POST");
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "empty request must issue the GET only, no POST"
        );
    }

    /// G3 (#192, F1): a nonempty have-batch terminated by EOF (no flush, no done)
    /// means git ABORTED mid-negotiation. The helper must terminate WITHOUT POSTing
    /// — synthesizing a `done` and sending it would make the node generate and
    /// stream a full pack (signed, for a private fetch) to a client that has gone
    /// away. Only a real `done` pkt finalizes the stateless request. RED before the
    /// fix (the folded `Done | Eof` arm POSTs a synthetic done → 2 requests), GREEN
    /// after (only the info/refs GET, no upload-pack POST).
    #[test]
    fn nonempty_eof_batch_aborts_without_posting() {
        // Only the info/refs GET is served (serve_http accepts exactly N conns). The
        // fixed helper makes exactly that one request and stops. The pre-fix code
        // additionally POSTs the synthetic done; that POST hits the now-closed
        // listener and errors, so handle_connect returns Err and the `.expect` below
        // fires — the RED. The fixed code returns Ok with one recorded request.
        let (base_url, server) = serve_http(vec![TestResponse {
            request_line: "GET /zOwner/myrepo/info/refs?service=git-upload-pack",
            status: "200 OK",
            body: "0000",
        }]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin_bytes = Vec::new();
        stdin_bytes.extend_from_slice(&want_line(&"a".repeat(40)));
        stdin_bytes.extend_from_slice(b"0000");
        stdin_bytes.extend_from_slice(&pkt(&format!("have {}\n", "1".repeat(40))));
        // No trailing flush or done: the stream just ends (EOF) after the have —
        // git aborted the negotiation.
        let mut stdin = io::Cursor::new(stdin_bytes);
        handle_connect(&repo_base, "git-upload-pack", None, &mut stdin)
            .expect("an aborted (EOF) negotiation is a clean no-op, not an error");
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "an aborted EOF must NOT trigger an upload-pack POST (only the info/refs GET)"
        );
    }

    /// G5: an empty receive-pack (push) body skips the POST, unchanged from before.
    #[test]
    fn receive_pack_empty_body_skips_post() {
        let (base_url, server) = serve_http(vec![TestResponse {
            request_line: "GET /zOwner/myrepo/info/refs?service=git-receive-pack",
            status: "200 OK",
            body: "0000",
        }]);
        let repo_base = format!("{base_url}/zOwner/myrepo");
        let mut stdin = io::Cursor::new(Vec::<u8>::new()); // empty push
        handle_connect(&repo_base, "git-receive-pack", None, &mut stdin)
            .expect("empty receive-pack should skip the POST");
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "empty push must issue the GET only, no POST"
        );
    }
}
