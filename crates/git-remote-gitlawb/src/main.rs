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
//!   connect git-receive-pack → GET /info/refs | POST /git-receive-pack (+ auth header)

use anyhow::{bail, Context, Result};
use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;
use std::io::{self, BufRead, Read, Write};

fn main() -> Result<()> {
    // All logging goes to stderr so it doesn't corrupt the git protocol on stdout
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(std::env::var("GITLAWB_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: git-remote-gitlawb <remote-name> <url>");
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

    // Load keypair for signing push requests (optional — push still works unsigned in v0.1)
    let keypair = load_keypair();

    run_helper(&repo_base, keypair.as_ref())
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

fn handle_connect(
    repo_base: &str,
    service: &str,
    keypair: Option<&Keypair>,
    stdin: &mut io::BufReader<io::Stdin>,
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

    let refs_resp = client
        .get(&refs_url)
        .header("User-Agent", "git/2.0 git-remote-gitlawb/0.1.0")
        .send()
        .with_context(|| format!("GET {refs_url}"))?;

    if !refs_resp.status().is_success() {
        bail!(
            "GET /info/refs returned {} — is the repo registered on this node?",
            refs_resp.status()
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

    // Extract the URL path for signing (e.g., "/z6Mk.../my-repo/git-receive-pack")
    let path_for_sig = url_path(&post_url);

    let mut req = client
        .post(&post_url)
        .header("Content-Type", format!("application/x-{}-request", service))
        .header("User-Agent", "git/2.0 git-remote-gitlawb/0.1.0")
        .body(request_body.clone());

    // Add RFC 9421 HTTP Signature auth on push operations
    if service == "git-receive-pack" {
        if let Some(kp) = keypair {
            let signed = sign_request(kp, "POST", &path_for_sig, &request_body);
            req = req
                .header("Content-Digest", signed.content_digest)
                .header("Signature-Input", signed.signature_input)
                .header("Signature", signed.signature);
            tracing::debug!("attached RFC 9421 HTTP Signature (DID: {})", kp.did());
        } else {
            tracing::warn!(
                "no identity keypair found — push will be unsigned (v0.1 local alpha only)"
            );
        }
    }

    let pack_resp = req.send().with_context(|| format!("POST {post_url}"))?;

    if !pack_resp.status().is_success() {
        bail!("POST /{} returned {}", service, pack_resp.status());
    }

    let pack_bytes = pack_resp.bytes().context("reading pack response")?;
    tracing::debug!("pack response: {} bytes from node", pack_bytes.len());

    stdout.write_all(&pack_bytes)?;
    stdout.flush()?;

    Ok(())
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
fn read_upload_pack_request(stdin: &mut io::BufReader<io::Stdin>) -> Result<Vec<u8>> {
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
}
