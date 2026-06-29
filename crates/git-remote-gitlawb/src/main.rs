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
//! When an identity keypair is present, both the advertisement GET and the pack
//! POST are RFC-9421 signed for BOTH services, so the node authorizes the owner on
//! visibility-gated private repos (fetch and push); public repos work anonymously.

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

    // Load keypair for signing requests (optional). When present, the helper signs
    // both fetch and push so a private repo's owner is authorized; absent, public
    // repos still work and push falls back to unsigned (v0.1 local alpha only).
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

    let refs_url = format!("{}/info/refs?service={}", repo_base, service);
    tracing::debug!("GET {refs_url}");

    let refs_resp = build_advertisement_request(&client, &refs_url, keypair)
        .send()
        .with_context(|| format!("GET {refs_url}"))?;

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
    // The two services behave differently with their write pipe:
    //
    //  git-upload-pack (clone/fetch):
    //    Client sends pkt-line want/have negotiation ending with "done\n",
    //    but does NOT close its write pipe — it waits for the pack response.
    //    We must detect the terminal "done\n" pkt-line to know when to POST.
    //
    //  git-receive-pack (push):
    //    Client sends ref-update commands + complete PACK blob, then closes
    //    its write pipe.  read_to_end is safe and correct here.

    let request_body = if service == "git-upload-pack" {
        read_upload_pack_request(stdin).context("reading upload-pack request")?
    } else {
        let mut buf = Vec::new();
        stdin
            .read_to_end(&mut buf)
            .context("reading receive-pack request")?;
        buf
    };

    tracing::debug!("pack request: {} bytes from git", request_body.len());

    if request_body.is_empty() {
        // e.g., already up-to-date — nothing to send
        tracing::debug!("empty request body — skipping POST");
        return Ok(());
    }

    let post_url = format!("{}/{}", repo_base, service);
    tracing::debug!("POST {post_url} ({} bytes)", request_body.len());

    let req = build_pack_post_request(&client, &post_url, service, &request_body, keypair);

    // Attach the body after signing so the pack bytes are moved, not cloned —
    // packs can be large and the clone doubled peak memory on push.
    let pack_resp = req
        .body(request_body)
        .send()
        .with_context(|| format!("POST {post_url}"))?;

    if !pack_resp.status().is_success() {
        let status = pack_resp.status();
        let body = read_error_body(pack_resp);
        let path = format!("/{service}");
        bail!("{}", http_error_message("POST", &path, status, &body, None));
    }

    let pack_bytes = pack_resp.bytes().context("reading pack response")?;
    tracing::debug!("pack response: {} bytes from node", pack_bytes.len());

    stdout.write_all(&pack_bytes)?;
    stdout.flush()?;

    Ok(())
}

// ── Smart-protocol request builders ───────────────────────────────────────────

const USER_AGENT: &str = "git/2.0 git-remote-gitlawb/0.1.0";

/// Build the Phase-1 ref-advertisement GET, signing it when an identity is
/// present. The node gates the ref advertisement on read visibility for BOTH
/// services, so a private repo's advertisement is denied (404) to an
/// unauthenticated caller — without this signature the repo's own owner can
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
        tracing::warn!("no identity keypair found — push will be unsigned (v0.1 local alpha only)");
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

/// Read a complete git-upload-pack request from the pkt-line stream.
///
/// For upload-pack, git sends its want/have negotiation ending with the pkt-line
/// `"done\n"` but does NOT close its write pipe afterwards — it waits for the
/// server's pack response.  We detect the terminal "done\n" and stop reading.
///
/// We also handle the flush-only case (`"0000"`) that git sends when it already
/// has everything it needs (up-to-date clone).
fn read_upload_pack_request<R: Read>(stdin: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();

    loop {
        // Read the 4-byte hex pkt-line length prefix
        let mut len_bytes = [0u8; 4];
        match stdin.read_exact(&mut len_bytes) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        buf.extend_from_slice(&len_bytes);

        let len_hex = std::str::from_utf8(&len_bytes).unwrap_or("0000");
        let pkt_len = usize::from_str_radix(len_hex, 16).unwrap_or(0);

        if pkt_len == 0 {
            // Flush pkt "0000" — keep buffering (more pkt-lines may follow)
            continue;
        }

        if pkt_len < 4 {
            bail!("invalid pkt-line length: {pkt_len}");
        }

        let data_len = pkt_len - 4;
        let mut data = vec![0u8; data_len];
        stdin
            .read_exact(&mut data)
            .context("reading pkt-line data")?;
        buf.extend_from_slice(&data);

        // "done\n" signals the end of the want/have negotiation
        if data == b"done\n" {
            tracing::debug!("upload-pack: got 'done', request complete");
            break;
        }
    }

    Ok(buf)
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
    /// header is absent, so the mock is hit only if NO signature was attached — for
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

    /// Cross-crate seam: the signature the CLIENT actually emits (via the real
    /// request builders) verifies under the SAME `gitlawb_core::http_sig`
    /// primitives the node's `require_signature` uses, over the `@path` the client
    /// genuinely transmits (derived from the built reqwest request, exactly as the
    /// node derives it from `uri.path_and_query()`). A tampered `@path` must fail —
    /// this is the byte-match the whole A1 client fix depends on, now executed end
    /// to end (sign here, verify with the node's verifier), not reasoned.
    #[test]
    fn client_signature_verifies_under_node_verification_for_both_services() {
        use gitlawb_core::http_sig::{
            build_signing_string, compute_content_digest, HttpSignature, COVERED_COMPONENTS,
        };
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
            let _ = COVERED_COMPONENTS;
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
        // node verifies the signature over its path_and_query — so the ?service=
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
}
