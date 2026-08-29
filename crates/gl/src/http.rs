//! Signed HTTP client for gitlawb API calls (async).
//!
//! Writes are signed with RFC 9421 HTTP Signatures. When the node gates a write
//! behind iCaptcha (HTTP 403 `icaptcha_proof_required`, advertised via the
//! `x-icaptcha-url` / `x-icaptcha-level` headers), the client transparently
//! solves the challenge and re-signs the write with the `x-icaptcha-proof`
//! header attached (see `crates/icaptcha-client`).

use anyhow::{Context, Result};
use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;
use gitlawb_core::node_denial::NodeDenial;
use icaptcha_client::IcaptchaCfg;

/// Max times we'll fetch a fresh proof and retry a 403-iCaptcha response
/// (absorbs proof expiry / first-seen replay).
const MAX_ICAPTCHA_RETRIES: usize = 2;

/// Max bytes buffered from a denial body before we give up on parsing it. Node
/// error bodies are a few hundred bytes of JSON; anything past this is not one,
/// and reading it unbounded is exactly the allocation a hostile node would aim
/// for.
pub(crate) const DENIAL_BODY_CAP: usize = 64 * 1024;

/// Max bytes read from a git smart-HTTP ref advertisement. Real ads are small;
/// this bounds hostile 200 responses on the MCP `git_refs` path.
pub(crate) const GIT_REFS_BODY_CAP: usize = 256 * 1024;

/// Max characters of a node-supplied message we will echo to the terminal.
const NODE_MSG_CHARS: usize = 200;

/// Total request timeout: from the start of connecting through the end of the
/// response body, so it bounds a slow download and not just a slow handshake.
const TOTAL_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Follow a redirect only when it stays on the origin that issued it AND re-issues the
/// identical request-target, and only for as long as the chain bound allows.
///
/// The decision itself is [`gitlawb_core::redirect::may_follow`], shared with
/// `git-remote-gitlawb` so the two signing clients cannot drift apart on it. Refusal
/// is `stop`, not `error`: the 3xx comes back as an ordinary response and each caller
/// reports it through the status path it already has.
///
/// `Policy::custom` replaces reqwest's built-in limit, so the chain bound is restated
/// here. Same-origin redirects can cycle, and this is what stops a node answering 302
/// to itself from being followed indefinitely. It is not what makes the request
/// finite: `.timeout(...)` on the same builder is a TOTAL request timeout covering the
/// whole chain, so without this bound the worst case is a 30 second spin, not an
/// endless one. The bound is what keeps that spin from costing the node a request per
/// round trip for the full 30 seconds.
///
/// `>` and not `>=`: reqwest pushes the redirecting URL onto `previous` before
/// consulting the policy, so on the first redirect `previous.len()` is already 1, and
/// `>=` would permit `MAX_REDIRECTS - 1` follows. `Policy::limited(max)` refuses at
/// `previous.len() > max`, and matching it is the point of reusing its value.
fn same_origin_redirect(attempt: reqwest::redirect::Attempt<'_>) -> reqwest::redirect::Action {
    let Some(previous) = attempt.previous().last() else {
        // No previous URL to compare against. Unreachable through reqwest, which
        // pushes the redirecting URL before consulting the policy, but the safe
        // reading of "cannot prove same-origin" is to refuse.
        return attempt.stop();
    };
    if attempt.previous().len() > gitlawb_core::redirect::MAX_REDIRECTS {
        return attempt.stop();
    }
    if gitlawb_core::redirect::may_follow(previous, attempt.url()) {
        attempt.follow()
    } else {
        attempt.stop()
    }
}

pub struct NodeClient {
    inner: reqwest::Client,
    pub node_url: String,
    keypair: Option<Keypair>,
}

impl NodeClient {
    pub fn new(node_url: impl Into<String>, keypair: Option<Keypair>) -> Self {
        Self::with_timeout(node_url, keypair, TOTAL_REQUEST_TIMEOUT)
    }

    /// `new` with the total request timeout as a parameter, so a test can drive the
    /// timeout's behaviour without waiting out the shipped value. `new` supplies the
    /// shipped one, which is what makes the scaled-down test cover the real client.
    fn with_timeout(
        node_url: impl Into<String>,
        keypair: Option<Keypair>,
        timeout: std::time::Duration,
    ) -> Self {
        let inner = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::custom(same_origin_redirect))
            .user_agent(format!("gl/{} gitlawb-cli", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("failed to build HTTP client");
        Self {
            inner,
            node_url: node_url.into(),
            keypair,
        }
    }

    /// GET request — no auth (public read endpoints).
    pub async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        self.inner
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))
    }

    /// GET that signs when a keypair is available; falls back to unsigned for public repos.
    pub async fn get_authed(&self, path: &str) -> Result<reqwest::Response> {
        if self.keypair.is_some() {
            self.get_signed(path).await
        } else {
            self.get(path).await
        }
    }

    /// GET with RFC 9421 HTTP Signature auth, for owner-only read endpoints.
    /// Signs over the empty body (same shape the node verifies for signed reads).
    pub async fn get_signed(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        let kp = self
            .keypair
            .as_ref()
            .context("get_signed requires an identity keypair")?;
        let signed = sign_request(kp, "GET", path, b"");
        let req = self
            .inner
            .get(&url)
            .header("Content-Digest", signed.content_digest)
            .header("Signature-Input", signed.signature_input)
            .header("Signature", signed.signature);
        req.send().await.with_context(|| format!("GET {url}"))
    }

    /// GET that signs when an identity keypair is present and falls back to an
    /// anonymous GET otherwise — for read-visibility endpoints, where a public
    /// repo is readable anonymously but a private repo requires the owner/reader
    /// to be authenticated. Mirrors the conditional signing of post/put/delete.
    pub async fn get_maybe_signed(&self, path: &str) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        let mut req = self.inner.get(&url);
        if let Some(kp) = &self.keypair {
            let signed = sign_request(kp, "GET", path, b"");
            req = req
                .header("Content-Digest", signed.content_digest)
                .header("Signature-Input", signed.signature_input)
                .header("Signature", signed.signature);
        }
        req.send().await.with_context(|| format!("GET {url}"))
    }

    /// POST with JSON body + RFC 9421 signing + transparent iCaptcha solve/retry.
    pub async fn post(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        self.send_signed("POST", path, body).await
    }

    /// PUT with RFC 9421 signing + transparent iCaptcha solve/retry.
    pub async fn put(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        self.send_signed("PUT", path, body).await
    }

    /// DELETE with RFC 9421 signing + transparent iCaptcha solve/retry.
    pub async fn delete(&self, path: &str, body: &[u8]) -> Result<reqwest::Response> {
        self.send_signed("DELETE", path, body).await
    }

    /// Sign + send a write. On a 403 iCaptcha challenge (detected via the
    /// `x-icaptcha-*` headers) attach the proof and send the write again, up to
    /// [`MAX_ICAPTCHA_RETRIES`]. Each attempt goes through `send_once`, which
    /// signs afresh, so the retry is a new signature over the same bytes, not a
    /// resend of the original one. Emits an actionable hint on a 401 "not an
    /// agent" (the old-CLI / unregistered failure mode), and converts every
    /// denial the node names in `x-gitlawb-error` into an error.
    async fn send_signed(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<reqwest::Response> {
        let mut proof: Option<String> = None;
        let mut attempts = 0;
        loop {
            let resp = self.send_once(method, path, body, proof.as_deref()).await?;
            let status = resp.status();

            if status == reqwest::StatusCode::UNAUTHORIZED
                && resp
                    .headers()
                    .get("x-gitlawb-error")
                    .and_then(|v| v.to_str().ok())
                    == Some("human_detected")
            {
                eprintln!(
                    "note: this node requires signed requests (RFC 9421). If writes keep \
                     failing, your `gl` may be too old — upgrade it — or you're not registered: \
                     run `gl register`."
                );
            }

            if status == reqwest::StatusCode::FORBIDDEN && attempts < MAX_ICAPTCHA_RETRIES {
                if let Some(cfg) = self.icaptcha_cfg(resp.headers())? {
                    attempts += 1;
                    proof = Some(obtain_proof(cfg).await?);
                    continue;
                }
            }

            if let Some(rejection) = signature_rejection(&resp) {
                return Err(rejection.into_error(method, path, resp).await);
            }
            return Ok(resp);
        }
    }

    /// Build, sign, and send one request, optionally attaching a proof header.
    async fn send_once(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        proof: Option<&str>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.node_url, path);
        let mut req = self
            .inner
            .request(method.parse().expect("valid HTTP method"), &url)
            .header("Content-Type", "application/json")
            .body(body.to_vec());

        if let Some(kp) = &self.keypair {
            let signed = sign_request(kp, method, path, body);
            req = req
                .header("Content-Digest", signed.content_digest)
                .header("Signature-Input", signed.signature_input)
                .header("Signature", signed.signature);
        }
        if let Some(p) = proof {
            req = req.header(icaptcha_client::PROOF_HEADER, p);
        }

        req.send().await.with_context(|| format!("{method} {url}"))
    }

    /// If `headers` describe an iCaptcha 403, build the solve config (binding the
    /// proof's `sub` to our DID). Returns `None` for a non-iCaptcha 403.
    fn icaptcha_cfg(&self, headers: &reqwest::header::HeaderMap) -> Result<Option<IcaptchaCfg>> {
        let url = headers.get("x-icaptcha-url").and_then(|v| v.to_str().ok());
        let level = headers
            .get("x-icaptcha-level")
            .and_then(|v| v.to_str().ok());
        if url.is_none() && level.is_none() {
            return Ok(None); // not an iCaptcha challenge
        }
        let kp = self
            .keypair
            .as_ref()
            .context("iCaptcha challenge requires an identity keypair (run `gl identity new`)")?;
        Ok(Some(IcaptchaCfg::new(
            kp.did().to_string(),
            url.map(str::to_string),
            level.and_then(|l| l.parse().ok()),
        )))
    }
}

/// A write the node refused with a code this build recognises.
struct SignatureRejection {
    /// Which denial it was. Its `as_str` is the `x-gitlawb-error` code, printed
    /// verbatim so scripts can match on it.
    denial: NodeDenial,
    /// What the user should actually do next.
    hint: &'static str,
}

impl SignatureRejection {
    /// Consume the response to fold the node's own message into the error.
    /// Called only after [`signature_rejection`] has decided from the status and
    /// header, since reading the body takes the response by value.
    ///
    /// The message is attacker controlled (any node the user points `gl` at
    /// wrote it), so the read is capped and the string is stripped of control
    /// characters and bidi overrides before it can reach a terminal: without
    /// that, the text whose whole job is to say "your write was REFUSED" can
    /// clear the screen and print a fake success line.
    async fn into_error(self, method: &str, path: &str, resp: reqwest::Response) -> anyhow::Error {
        let status = resp.status();
        let capped = read_body_capped(resp, DENIAL_BODY_CAP).await;
        let node_msg = serde_json::from_str::<serde_json::Value>(&capped.text)
            .ok()
            .and_then(|b| b["message"].as_str().map(sanitize_node_msg))
            .filter(|m| !m.is_empty());
        let Self { denial, hint } = self;
        let code = denial.as_str();
        match node_msg {
            Some(m) => anyhow::anyhow!("{method} {path} rejected ({status} {code}): {hint} ({m})"),
            None => anyhow::anyhow!("{method} {path} rejected ({status} {code}): {hint}"),
        }
    }
}

/// Recognise a node rejection from the status and the
/// `x-gitlawb-error` header, before anything reads the body.
///
/// Known limit: the node also puts the same code in the body's `error` field,
/// and this does not look at it, so a proxy or CDN that strips unknown `X-`
/// headers switches the detection off. Reading the body to recover the second
/// signal is destructive, and handing the caller back a response it can still
/// parse needs `http::Response::builder` (the only constructor
/// `reqwest::Response::from` takes), which is a dependency this crate does not
/// carry. The commands that must not mistake a denial for a success do not rely
/// on this alone: `gl init` compares the structured error code from the body,
/// and the `gl task` writes check the status before parsing.
///
/// None of these is ever retried. A `signature_replayed` 409 means the node
/// already admitted a request carrying this signature, so re-sending the same
/// bytes risks applying the mutation twice, which is the duplicate write the
/// ledger exists to prevent. (The iCaptcha 403 retry above does not have that
/// problem: `verify_request` runs inside the handler, so the ledger has already
/// been charged by the time the challenge is returned, but `send_once` signs
/// every attempt afresh and each signature carries its own nonce, so the retry
/// arrives under a ledger key the node has never seen.) The 400, 429, 500 and
/// 503 cases did not apply the write; 429 and 503 are retryable, but doing it
/// automatically would only hammer a node that is already saying "not now", so
/// they surface to the user instead.
///
/// The set of codes is [`NodeDenial`], shared with the node so both halves
/// spell them the same way. The `match` below has no wildcard arm on purpose:
/// adding a denial to the node stops this crate compiling until someone writes
/// the caller's instructions for it. That is the whole point of the type, since
/// the previous arrangement (a list of literals in each crate) silently missed
/// `signature_nonce_too_short` for several commits and returned `Ok(400)` for it.
fn signature_rejection(resp: &reqwest::Response) -> Option<SignatureRejection> {
    let code = resp.headers().get("x-gitlawb-error")?.to_str().ok()?;
    // A code this build does not know: not our denial to describe. The header
    // came from a node the user chose, which may be newer, older, or hostile,
    // so the response goes back to the caller untouched.
    let denial = NodeDenial::from_code(code)?;
    // The status has to agree with the code, so a stray header on a 200 cannot
    // turn a success into a refusal.
    if resp.status().as_u16() != denial.status() {
        return None;
    }
    let hint = match denial {
        NodeDenial::NonceRequired => {
            "this node requires a nonce in the request signature and the request did not carry \
             one. The write did not happen; upgrade `gl` and run the command again"
        }
        NodeDenial::NonceTooShort => {
            "this node rejected the nonce in the request signature as too short to be unique. \
             The write did not happen; upgrade `gl` and run the command again"
        }
        NodeDenial::Replayed => {
            "the node already admitted a request with this signature and will not take it twice. \
             Do not resend: check whether the change took effect before running the command again"
        }
        NodeDenial::LedgerFull => {
            "this identity has too many unexpired signatures on the node, so it is refusing more \
             signed writes for now. The write did not happen; wait a moment and run the command \
             again"
        }
        NodeDenial::IdentityMissing => {
            "the node reached its signature ledger without a verified identity and refused the \
             write. The write did not happen; this is a fault on the node, so report it to the \
             operator"
        }
        NodeDenial::LedgerUnavailable => {
            "the node's signature ledger is unavailable, so it is refusing signed writes. \
             The write did not happen; retry later or ask the node operator to check the node"
        }
        NodeDenial::RateLimited => {
            "the node is throttling requests from your network address, so it refused this one \
             before running it. The write did not happen; this is not about your identity or \
             your signature, so re-running immediately will not help — wait and try again"
        }
    };
    Some(SignatureRejection { denial, hint })
}

/// Read a node reply, turning a non-2xx into an error instead of handing the
/// caller an error body that pretty-prints like a success. The message is read
/// under a cap and sanitized, same as a signature denial.
pub(crate) async fn json_or_denial<T: serde::de::DeserializeOwned>(
    what: &str,
    resp: reqwest::Response,
) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let capped = read_body_capped(resp, DENIAL_BODY_CAP).await;
        let msg = serde_json::from_str::<serde_json::Value>(&capped.text)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            })
            .unwrap_or(capped.text);
        anyhow::bail!("{what} failed ({status}): {}", sanitize_node_msg(&msg));
    }
    resp.json::<T>()
        .await
        .with_context(|| format!("invalid JSON response from {what}"))
}

/// Run the (blocking) iCaptcha solve loop off the async runtime.
async fn obtain_proof(cfg: IcaptchaCfg) -> Result<String> {
    tokio::task::spawn_blocking(move || icaptcha_client::obtain_proof(&cfg, None))
        .await
        .context("iCaptcha solver task panicked")?
}

/// What a capped body read produced. `text` is the bytes that arrived; the two flags
/// say why the read stopped where it did, which a caller that CLASSIFIES on the body
/// cannot work out from the text alone.
pub(crate) struct CappedBody {
    /// The bytes read, lossily decoded.
    pub(crate) text: String,
    /// The cap cut the body short.
    pub(crate) truncated: bool,
    /// A chunk read FAILED part-way through, so the body is not merely short, it is
    /// unfinished and the node may have had more to say.
    pub(crate) read_failed: bool,
}

/// Read at most `cap` bytes of a response body. Bounds the allocation from a
/// hostile or broken node returning a huge error body — the display is capped
/// separately, but the read itself must not be unbounded (INV-6, read half).
///
/// `truncated` reports whether the cap cut the body short. A caller that CLASSIFIES
/// on the body needs it: a cut body fails JSON parse, and a parse failure is
/// indistinguishable from a node that sent no code at all, so without this flag an
/// oversized body silently picks a different arm.
///
/// `read_failed` reports the other way a body can end early. A mid-body read error
/// used to leave through the same exit as a clean end of stream, so a 500 whose body
/// died in transit surfaced as an empty message and the caller was told
/// `node returned 500: ` with nothing after the colon. That is a report of what the
/// node said, and the node never got to say it.
pub(crate) async fn read_body_capped(mut resp: reqwest::Response, cap: usize) -> CappedBody {
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut read_failed = false;
    while buf.len() < cap {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = (cap - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    truncated = true;
                    break; // hit the cap mid-chunk
                }
            }
            Ok(None) => break, // clean end of body
            Err(_) => {
                read_failed = true;
                break;
            }
        }
    }
    // A body that lands exactly on the cap may or may not have more behind it;
    // report it as cut, since the classification that follows cannot tell either.
    if buf.len() >= cap {
        truncated = true;
    }
    CappedBody {
        text: String::from_utf8_lossy(&buf).into_owned(),
        truncated,
        read_failed,
    }
}

/// Strip terminal-dangerous characters from (and cap the length of) a
/// node-supplied error string before surfacing it. The node a caller talks to
/// could be hostile and embed escape sequences in its error body; those must not
/// reach the terminal verbatim (INV-6). We drop the C0/C1 control bytes (which
/// defangs ANSI/OSC escapes) AND the Unicode bidi/format controls (which
/// `char::is_control` does not cover — they can reorder the displayed line).
pub(crate) fn sanitize_node_msg(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !gitlawb_core::sanitize::is_bidi_format(*c))
        .take(NODE_MSG_CHARS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitlawb_core::identity::Keypair;
    use mockito::Server;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes the two integration tests that touch the process-global
    /// `GITLAWB_ICAPTCHA_URL` / `GITLAWB_ICAPTCHA_INSECURE` env vars so they
    /// never race.
    static ICAPTCHA_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn headers_from_pairs(pairs: &[(&str, &str)]) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                k.parse::<reqwest::header::HeaderName>().unwrap(),
                v.parse::<reqwest::header::HeaderValue>().unwrap(),
            );
        }
        h
    }

    // ── icaptcha_cfg ────────────────────────────────────────────────────

    #[test]
    fn icaptcha_cfg_returns_some_when_both_headers_present() {
        let kp = test_keypair();
        let client = NodeClient::new("http://localhost", Some(kp.clone()));
        let headers = headers_from_pairs(&[
            ("x-icaptcha-url", "https://icaptcha.gitlawb.com"),
            ("x-icaptcha-level", "3"),
        ]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.did, kp.did().to_string());
        assert_eq!(cfg.level, 3);
    }

    #[test]
    fn icaptcha_cfg_defaults_level_when_only_url_present() {
        let kp = test_keypair();
        let client = NodeClient::new("http://localhost", Some(kp));
        let headers = headers_from_pairs(&[("x-icaptcha-url", "https://icaptcha.gitlawb.com")]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.level, icaptcha_client::DEFAULT_LEVEL);
    }

    #[test]
    fn icaptcha_cfg_defaults_url_when_only_level_present() {
        let kp = test_keypair();
        let client = NodeClient::new("http://localhost", Some(kp));
        let headers = headers_from_pairs(&[("x-icaptcha-level", "5")]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.level, 5);
    }

    #[test]
    fn icaptcha_cfg_returns_none_without_icaptcha_headers() {
        let client = NodeClient::new("http://localhost", Some(test_keypair()));
        let headers = reqwest::header::HeaderMap::new();
        assert!(client.icaptcha_cfg(&headers).unwrap().is_none());
    }

    #[test]
    fn icaptcha_cfg_returns_none_with_unrelated_headers() {
        let client = NodeClient::new("http://localhost", Some(test_keypair()));
        let headers = headers_from_pairs(&[("content-type", "application/json")]);
        assert!(client.icaptcha_cfg(&headers).unwrap().is_none());
    }

    #[test]
    fn icaptcha_cfg_errors_when_no_keypair() {
        let client = NodeClient::new("http://localhost", None);
        let headers = headers_from_pairs(&[("x-icaptcha-level", "3")]);
        let err = client.icaptcha_cfg(&headers).unwrap_err();
        assert!(err.to_string().contains("identity keypair"));
    }

    #[test]
    fn icaptcha_cfg_ignores_unparseable_level() {
        let client = NodeClient::new("http://localhost", Some(test_keypair()));
        let headers = headers_from_pairs(&[
            ("x-icaptcha-url", "https://icaptcha.gitlawb.com"),
            ("x-icaptcha-level", "not-a-number"),
        ]);
        let cfg = client.icaptcha_cfg(&headers).unwrap().unwrap();
        assert_eq!(cfg.level, icaptcha_client::DEFAULT_LEVEL);
    }

    // ── send_once ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn send_once_attaches_proof_header_when_provided() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("x-icaptcha-proof", "test.proof.token")
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_once("POST", "/api/test", b"{}", Some("test.proof.token"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    #[tokio::test]
    async fn send_once_omits_proof_header_when_not_provided() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("x-icaptcha-proof", mockito::Matcher::Missing)
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_once("POST", "/api/test", b"{}", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    #[tokio::test]
    async fn send_once_signs_request_when_keypair_present() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("Signature", mockito::Matcher::Any)
            .match_header("Signature-Input", mockito::Matcher::Any)
            .match_header("Content-Digest", mockito::Matcher::Any)
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_once("POST", "/api/test", b"{}", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    #[tokio::test]
    async fn send_once_does_not_sign_when_no_keypair() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/test")
            .match_header("Signature", mockito::Matcher::Missing)
            .match_header("Signature-Input", mockito::Matcher::Missing)
            .match_header("Content-Digest", mockito::Matcher::Missing)
            .with_status(200)
            .with_body("ok")
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_once("POST", "/api/test", b"{}", None)
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        m.assert();
    }

    // ── send_signed ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn send_signed_returns_non_icaptcha_403_without_retry() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"forbidden"}"#)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        m.assert();
    }

    #[tokio::test]
    async fn send_signed_returns_first_response_on_success() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/register")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"created"}"#)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        m.assert();
    }

    #[tokio::test]
    async fn send_signed_handles_405_not_icaptcha() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/register")
            .with_status(405)
            .with_body(r#"{"error":"method not allowed"}"#)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 405);
        m.assert();
    }

    // ── send_signed signature-ledger rejections ─────────────────────────

    /// Mock one node reply and send a signed POST through `send_signed`,
    /// asserting the node was called exactly once (i.e. nothing retried).
    async fn send_signed_once(
        status: usize,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (Result<reqwest::Response>, mockito::ServerGuard) {
        let mut server = Server::new_async().await;
        let mut m = server
            .mock("POST", "/api/v1/repos")
            .with_status(status)
            .with_header("content-type", "application/json");
        for (k, v) in headers {
            m = m.with_header(*k, v);
        }
        let m = m.with_body(body).expect(1).create_async().await;
        let client = NodeClient::new(server.url(), Some(test_keypair()));
        let resp = client.send_signed("POST", "/api/v1/repos", b"{}").await;
        m.assert_async().await;
        (resp, server)
    }

    #[tokio::test]
    async fn send_signed_errors_on_replayed_signature_and_never_retries() {
        let (resp, _server) = send_signed_once(
            409,
            &[("x-gitlawb-error", "signature_replayed")],
            r#"{"error":"signature_replayed","message":"this signature was already used"}"#,
        )
        .await;
        let err = resp
            .expect_err("a replayed signature must surface as an error, not Ok(409)")
            .to_string();
        assert!(err.contains("signature_replayed"), "got: {err}");
        assert!(
            err.contains("already"),
            "message must tell the user the node already applied it, got: {err}"
        );
        assert!(
            err.contains("this signature was already used"),
            "must surface the node's message, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_ledger_full_and_never_retries() {
        let (resp, _server) = send_signed_once(
            429,
            &[("x-gitlawb-error", "signature_ledger_full")],
            r#"{"error":"signature_ledger_full","message":"ledger at capacity"}"#,
        )
        .await;
        let err = resp
            .expect_err("a full ledger must surface as an error")
            .to_string();
        assert!(err.contains("signature_ledger_full"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_ledger_unavailable_and_never_retries() {
        let (resp, _server) = send_signed_once(
            503,
            &[("x-gitlawb-error", "signature_ledger_unavailable")],
            r#"{"error":"signature_ledger_unavailable","message":"ledger down"}"#,
        )
        .await;
        let err = resp
            .expect_err("an unavailable ledger must surface as an error")
            .to_string();
        assert!(err.contains("signature_ledger_unavailable"), "got: {err}");
    }

    #[tokio::test]
    async fn send_signed_errors_on_nonce_required_and_never_retries() {
        let (resp, _server) = send_signed_once(
            400,
            &[("x-gitlawb-error", "signature_nonce_required")],
            r#"{"error":"signature_nonce_required","message":"this node requires a nonce"}"#,
        )
        .await;
        let err = resp
            .expect_err("a nonce-less signature must surface as an error, not Ok(400)")
            .to_string();
        assert!(err.contains("signature_nonce_required"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_identity_missing_and_never_retries() {
        let (resp, _server) = send_signed_once(
            500,
            &[("x-gitlawb-error", "signature_identity_missing")],
            r#"{"error":"signature_identity_missing","message":"no verified identity"}"#,
        )
        .await;
        let err = resp
            .expect_err("a missing signature identity must surface as an error, not Ok(500)")
            .to_string();
        assert!(err.contains("signature_identity_missing"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_signed_errors_on_nonce_too_short_and_never_retries() {
        let (resp, _server) = send_signed_once(
            400,
            &[("x-gitlawb-error", "signature_nonce_too_short")],
            r#"{"error":"signature_nonce_too_short","message":"the nonce must be at least 16 characters"}"#,
        )
        .await;
        let err = resp
            .expect_err("a too-short nonce must surface as an error, not Ok(400)")
            .to_string();
        assert!(err.contains("signature_nonce_too_short"), "got: {err}");
        assert!(
            !err.contains("already"),
            "must not claim the write was applied, got: {err}"
        );
        assert!(
            err.contains("the nonce must be at least 16 characters"),
            "must surface the node's message, got: {err}"
        );
    }

    /// Two unrelated conditions now share 429: the node's per-client flood
    /// brake and the spent-signature ledger's per-identity cap. They must reach
    /// the user as different errors, and neither may be retried.
    #[tokio::test]
    async fn send_signed_tells_a_rate_limit_brake_apart_from_a_full_ledger() {
        let (brake, _s1) = send_signed_once(
            429,
            &[("x-gitlawb-error", "rate_limited")],
            r#"{"error":"rate_limited","message":"rate limit exceeded — try again later"}"#,
        )
        .await;
        let brake = brake
            .expect_err("a rate-limit brake must surface as an error, not Ok(429)")
            .to_string();

        let (ledger, _s2) = send_signed_once(
            429,
            &[("x-gitlawb-error", "signature_ledger_full")],
            r#"{"error":"signature_ledger_full","message":"ledger at capacity"}"#,
        )
        .await;
        let ledger = ledger
            .expect_err("a full ledger must surface as an error")
            .to_string();

        assert!(brake.contains("rate_limited"), "got: {brake}");
        assert!(
            !brake.contains("signature_ledger_full"),
            "a brake must not be described as a ledger denial: {brake}"
        );
        assert!(
            brake.contains("network address"),
            "the brake hint must say it is keyed on the client address: {brake}"
        );
        assert!(ledger.contains("signature_ledger_full"), "got: {ledger}");
        assert!(
            !ledger.contains("rate_limited"),
            "a ledger denial must not be described as a brake: {ledger}"
        );
        assert!(
            ledger.contains("unexpired signatures"),
            "the ledger hint must say it is keyed on the identity: {ledger}"
        );
        assert_ne!(brake, ledger);
    }

    /// Every signature denial the node can return, as (status, code). Derived
    /// from the shared enum rather than retyped, so it cannot drift from what
    /// the node emits.
    fn all_denials() -> Vec<(usize, &'static str)> {
        NodeDenial::ALL
            .iter()
            .map(|d| (d.status() as usize, d.as_str()))
            .collect()
    }

    #[tokio::test]
    async fn send_signed_errors_on_every_denial_carrying_the_header() {
        for (status, code) in all_denials() {
            let body = format!(r#"{{"error":"{code}","message":"node says no"}}"#);
            let (resp, _server) =
                send_signed_once(status, &[("x-gitlawb-error", code)], &body).await;
            let err = match resp {
                Ok(r) => panic!("{code} returned Ok({}) instead of an error", r.status()),
                Err(e) => e.to_string(),
            };
            assert!(err.contains(code), "wrong code surfaced for {code}: {err}");
            assert!(
                err.contains("node says no"),
                "node message dropped for {code}: {err}"
            );
        }
    }

    #[tokio::test]
    async fn send_signed_does_not_see_a_denial_carried_only_in_the_body() {
        // Documents a known limit rather than a wanted behaviour: detection is
        // header-keyed, so a proxy stripping `x-gitlawb-error` leaves the denial
        // to the caller (see `signature_rejection`). The callers that must not
        // read one as a success handle it themselves: `gl init` compares
        // `error` from the body, `gl task` checks the status before parsing.
        for (status, code) in all_denials() {
            let body = format!(r#"{{"error":"{code}","message":"node says no"}}"#);
            let (resp, _server) = send_signed_once(status, &[], &body).await;
            let resp = resp.unwrap_or_else(|e| panic!("{code} without the header: {e}"));
            assert_eq!(resp.status().as_u16(), status as u16);
            // The body is untouched, which is what lets the caller decide.
            let payload: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(payload["error"], code);
        }
    }

    #[tokio::test]
    async fn send_signed_sanitizes_and_caps_a_hostile_denial_message() {
        // The message that exists to say "your write was REFUSED" must not be
        // able to clear the screen and print a fake success line.
        let hostile = format!(
            "\u{1b}[2J\u{1b}[31mSUCCESS: task created\u{202e}{}",
            "A".repeat(5000)
        );
        let body = serde_json::json!({
            "error": "signature_replayed",
            "message": hostile,
        })
        .to_string();
        let (resp, _server) =
            send_signed_once(409, &[("x-gitlawb-error", "signature_replayed")], &body).await;
        let err = resp.expect_err("a replay must error").to_string();
        assert!(
            !err.contains('\u{1b}'),
            "ESC leaked to the terminal: {err:?}"
        );
        assert!(
            !err.contains('\u{202e}'),
            "RLO bidi override leaked: {err:?}"
        );
        assert!(err.contains("signature_replayed"), "got: {err}");
        assert!(
            err.chars().count() < 600,
            "denial message not bounded: {} chars",
            err.chars().count()
        );
    }

    #[tokio::test]
    async fn send_signed_returns_repo_exists_409_unchanged() {
        // The pre-existing 409. Callers (`gl init`, `gl repo create`) inspect the
        // status themselves, so it must keep returning Ok(resp).
        let (resp, _server) = send_signed_once(
            409,
            &[("x-node-marker", "kept")],
            r#"{"error":"repo_exists","message":"already exists"}"#,
        )
        .await;
        let resp = resp.expect("a non-replay 409 must still return Ok");
        assert_eq!(resp.status(), 409);
        // Status, headers and body must all survive the denial check: `gl init`
        // reads the code out of the body to decide "already exists, continue".
        assert_eq!(resp.headers().get("x-node-marker").unwrap(), "kept");
        let payload: serde_json::Value = resp.json().await.expect("body must survive intact");
        assert_eq!(payload["error"], "repo_exists");
        assert_eq!(payload["message"], "already exists");
    }

    #[tokio::test]
    async fn send_signed_returns_409_with_other_error_header_unchanged() {
        // Only the three signature_* codes are converted; any other
        // x-gitlawb-error on a 409 is left to the caller.
        let (resp, _server) = send_signed_once(
            409,
            &[("x-gitlawb-error", "repo_exists")],
            r#"{"error":"repo_exists"}"#,
        )
        .await;
        let resp = resp.expect("an unrelated 409 error code must still return Ok");
        assert_eq!(resp.status(), 409);
    }

    #[tokio::test]
    async fn send_signed_returns_401_invalid_signature_unchanged() {
        let (resp, _server) = send_signed_once(
            401,
            &[("x-gitlawb-error", "invalid_signature")],
            r#"{"error":"invalid_signature"}"#,
        )
        .await;
        let resp = resp.expect("a 401 must still return Ok, distinct from a replay error");
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn send_signed_returns_401_unsigned_request_unchanged() {
        // An unsigned write is rejected with human_detected; the client prints a
        // hint and returns the response, and must not be mistaken for a replay.
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/api/v1/repos")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_header("x-gitlawb-error", "human_detected")
            .with_body(r#"{"error":"human_detected"}"#)
            .expect(1)
            .create_async()
            .await;
        let client = NodeClient::new(server.url(), None);
        let resp = client
            .send_signed("POST", "/api/v1/repos", b"{}")
            .await
            .expect("an unsigned-request rejection must still return Ok");
        assert_eq!(resp.status(), 401);
        m.assert_async().await;
    }

    #[tokio::test]
    async fn send_signed_does_not_convert_a_409_on_another_status() {
        // The header alone must not trigger the conversion: the status has to
        // match too, so a 200 carrying a stray header stays a success.
        let (resp, _server) = send_signed_once(
            200,
            &[("x-gitlawb-error", "signature_replayed")],
            r#"{"ok":true}"#,
        )
        .await;
        let resp = resp.expect("a 200 must stay Ok regardless of headers");
        assert_eq!(resp.status(), 200);
    }

    // ── send_signed iCaptcha retry (full integration) ────────────────────

    /// Set GITLAWB_ICAPTCHA_URL and GITLAWB_ICAPTCHA_INSECURE so the iCaptcha
    /// client trusts a local mockito HTTP server, restoring any prior values on
    /// drop so a test run launched with those variables keeps working.
    /// Holds [`ICAPTCHA_ENV_LOCK`] for its lifetime so concurrent tests don't
    /// race on the process-global env vars.
    struct IcaptchaEnv {
        _lock: MutexGuard<'static, ()>,
        prev_url: Option<OsString>,
        prev_insecure: Option<OsString>,
    }

    impl IcaptchaEnv {
        fn new(url: &str) -> Self {
            let lock = ICAPTCHA_ENV_LOCK.lock().unwrap();
            let prev_url = std::env::var_os("GITLAWB_ICAPTCHA_URL");
            let prev_insecure = std::env::var_os("GITLAWB_ICAPTCHA_INSECURE");
            std::env::set_var("GITLAWB_ICAPTCHA_URL", url);
            std::env::set_var("GITLAWB_ICAPTCHA_INSECURE", "1");
            IcaptchaEnv {
                _lock: lock,
                prev_url,
                prev_insecure,
            }
        }
    }

    impl Drop for IcaptchaEnv {
        fn drop(&mut self) {
            match self.prev_url.take() {
                Some(v) => std::env::set_var("GITLAWB_ICAPTCHA_URL", v),
                None => std::env::remove_var("GITLAWB_ICAPTCHA_URL"),
            }
            match self.prev_insecure.take() {
                Some(v) => std::env::set_var("GITLAWB_ICAPTCHA_INSECURE", v),
                None => std::env::remove_var("GITLAWB_ICAPTCHA_INSECURE"),
            }
        }
    }

    /// Set up a mock iCaptcha server that responds to challenge + answer.
    /// `hits` sets the expected call count for both endpoints so the test can
    /// verify the solve loop was entered the correct number of times.
    struct MockIcaptcha {
        challenge: mockito::Mock,
        answer: mockito::Mock,
        _guard: IcaptchaEnv,
        url: String,
    }

    impl MockIcaptcha {
        async fn new(server: &mut mockito::ServerGuard, hits: usize) -> Self {
            let url = server.url();
            let guard = IcaptchaEnv::new(&url);
            let challenge = server
                .mock("POST", "/v1/challenge")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"challengeId":"c1","type":"arithmetic","difficulty":1,"prompt":"What is 1 + 1?","token":"tk1"}"#,
                )
                .expect(hits)
                .create_async()
                .await;
            let answer = server
                .mock("POST", "/v1/answer")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"status":"passed","proof":"mock.proof"}"#)
                .expect(hits)
                .create_async()
                .await;
            Self {
                challenge,
                answer,
                _guard: guard,
                url,
            }
        }
    }

    #[tokio::test]
    async fn send_signed_solves_icaptcha_and_retries_to_success() {
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        let ic = MockIcaptcha::new(&mut icaptcha, 1).await;

        let n1 = node
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .expect(1)
            .create_async()
            .await;
        let n2 = node
            .mock("POST", "/api/register")
            .match_header("x-icaptcha-proof", "mock.proof")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"created"}"#)
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        n1.assert();
        n2.assert();
        ic.challenge.assert();
        ic.answer.assert();
    }

    #[tokio::test]
    async fn send_signed_signs_the_icaptcha_retry_afresh() {
        // What makes the 403 retry safe is that it is a NEW signature, not a
        // resend: `verify_request` runs inside the handler, so the ledger was
        // already charged for the first attempt. Each `send_once` signs again
        // and `sign_request` draws a fresh nonce, so the retry lands on a ledger
        // key the node has not seen. Pin that: the two attempts must not carry
        // the same `Signature-Input`.
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        let ic = MockIcaptcha::new(&mut icaptcha, 1).await;

        let seen: std::sync::Arc<Mutex<Vec<String>>> = Default::default();
        let record = {
            let seen = seen.clone();
            move |req: &mockito::Request| {
                let v = req
                    .header("signature-input")
                    .first()
                    .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned())
                    .unwrap_or_default();
                seen.lock().unwrap().push(v);
                true
            }
        };

        let n1 = node
            .mock("POST", "/api/register")
            .match_header("x-icaptcha-proof", mockito::Matcher::Missing)
            .match_request(record.clone())
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .expect(1)
            .create_async()
            .await;
        let n2 = node
            .mock("POST", "/api/register")
            .match_header("x-icaptcha-proof", "mock.proof")
            .match_request(record)
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"created"}"#)
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        n1.assert();
        n2.assert();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "expected two attempts, got {seen:?}");
        assert!(
            !seen[0].is_empty() && !seen[1].is_empty(),
            "both attempts must be signed: {seen:?}"
        );
        assert_ne!(
            seen[0], seen[1],
            "the retry reused the first signature, so it would land on the same \
             ledger key the node already spent"
        );
    }

    #[tokio::test]
    async fn send_signed_returns_403_after_icaptcha_retries_exhausted() {
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        // MAX_ICAPTCHA_RETRIES = 2, so with every call returning 403 with
        // iCaptcha headers the solve loop runs twice (2 challenge + 2 answer).
        let ic = MockIcaptcha::new(&mut icaptcha, 2).await;

        // The original + 2 retries = 3 node calls before the loop gives up.
        let n = node
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .expect(3)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        n.assert();
        ic.challenge.assert();
        ic.answer.assert();
    }

    // ── redirect policy ─────────────────────────────────────────────────

    /// The signed headers must not survive a redirect off the node's origin.
    ///
    /// reqwest strips only `Authorization`, `Cookie`, `Proxy-Authorization` and
    /// `WWW-Authenticate` across hosts, so `Signature` and `Signature-Input` used to
    /// ride a 302 straight to whatever origin the node named. The signature binds
    /// `@method`, `@path` and `content-digest` and nothing about the authority, so the
    /// receiving host holds a credential that reads path-scoped objects as the caller
    /// at any node until the clock-skew window closes.
    ///
    /// Two mockito servers are two ports on one host, which is exactly the boundary
    /// this policy draws (and the one reqwest's own header stripping draws). The
    /// second server answers everything and expects nothing: a followed redirect
    /// fails the expectation whether or not the signature came with it. MUTATION
    /// (RED): drop the `.redirect(...)` line and the second server is hit.
    #[tokio::test]
    async fn cross_origin_redirect_is_not_followed() {
        let mut elsewhere = Server::new_async().await;
        let never = elsewhere
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("bytes from the redirect target")
            .expect(0)
            .create_async()
            .await;
        let signature_seen = elsewhere
            .mock("GET", mockito::Matcher::Any)
            .match_header("signature", mockito::Matcher::Any)
            .with_status(200)
            .expect(0)
            .create_async()
            .await;

        let mut node = Server::new_async().await;
        let bounce = node
            .mock("GET", "/api/v1/thing")
            .with_status(302)
            .with_header("location", &format!("{}/api/v1/thing", elsewhere.url()))
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client.get_signed("/api/v1/thing").await.unwrap();

        assert_eq!(
            resp.status(),
            302,
            "a refused redirect stops rather than errors, so the caller sees the 3xx \
             and reports it through the status path it already has"
        );
        let body = resp.text().await.unwrap();
        assert!(
            !body.contains("bytes from the redirect target"),
            "the redirect target's bytes must never reach the caller, got: {body}"
        );
        bounce.assert_async().await;
        never.assert_async().await;
        signature_seen.assert_async().await;
    }

    /// A node redirecting to itself is same-origin, so the origin predicate follows it
    /// every time and only the chain bound ends the loop. Deleting the bound left the
    /// whole suite green, because nothing here had ever built a cycle.
    ///
    /// It has a second job now. A redirect back to the identical path and query is the
    /// only same-origin hop the predicate still follows, so the eleven hits below are
    /// also this crate's executed proof that such a hop IS followed. The old positive
    /// fixture drove a trailing-slash rewrite, which the request-target rule refuses,
    /// and an http-to-https upgrade cannot be mocked over mockito's plain http.
    ///
    /// The route answers 301 pointing back at itself. Bounded, the handler is hit
    /// once for the original request plus `MAX_REDIRECTS` follows and the call returns
    /// the 301 (a refused redirect stops rather than errors). Unbounded, it runs until
    /// the client's total request timeout cuts it off, which is a 30 second spin at the
    /// shipped value and a request per round trip for the node.
    ///
    /// MUTATION (RED): delete the `previous().len()` check.
    #[tokio::test]
    async fn a_self_redirect_stops_at_the_chain_bound() {
        let mut node = Server::new_async().await;
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        let loop_route = node
            .mock("GET", "/api/v1/loop")
            .with_status(301)
            .with_header("location", "/api/v1/loop")
            .with_body_from_request(move |_req| {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Vec::new()
            })
            .expect_at_least(1)
            .create_async()
            .await;

        let client = NodeClient::with_timeout(
            node.url(),
            Some(test_keypair()),
            std::time::Duration::from_secs(5),
        );
        let resp = client
            .get_signed("/api/v1/loop")
            .await
            .expect("the bound must end the chain, not the timeout");

        assert_eq!(
            resp.status(),
            301,
            "the chain ends by refusing the next hop, so the last 3xx is what comes back"
        );
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            gitlawb_core::redirect::MAX_REDIRECTS + 1,
            "one original request plus MAX_REDIRECTS follows, matching what \
             Policy::limited(MAX_REDIRECTS) would have permitted"
        );
        loop_route.assert_async().await;
    }

    /// A same-origin hop that REWRITES the request-target is refused, even though the
    /// origin never changes.
    ///
    /// The signature binds `@path` as the literal path-and-query the client signed, and
    /// the node rebuilds it from the URI it received. A `/api/v1/thing` to
    /// `/api/v1/thing/` bounce therefore presents a signature over a target the node
    /// never saw, and every signed read behind such a proxy 401s. Refusing the hop
    /// hands the caller the 3xx that names what happened instead.
    ///
    /// The target mock expects zero hits and is asserted: mockito only checks
    /// `.expect(N)` when `.assert()` runs, so an unbound or unasserted mock passes
    /// vacuously.
    #[tokio::test]
    async fn same_origin_path_changing_redirect_is_refused() {
        let mut node = Server::new_async().await;
        let bounce = node
            .mock("GET", "/api/v1/thing")
            .with_status(301)
            .with_header("location", "/api/v1/thing/")
            .expect(1)
            .create_async()
            .await;
        let target = node
            .mock("GET", "/api/v1/thing/")
            .with_status(200)
            .with_body("bytes from the rewritten target")
            .expect(0)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client.get_signed("/api/v1/thing").await.unwrap();

        assert_eq!(
            resp.status(),
            301,
            "a refused redirect stops rather than errors, so the caller sees the 3xx \
             and reports it through the status path it already has"
        );
        let body = resp.text().await.unwrap();
        assert!(
            !body.contains("bytes from the rewritten target"),
            "the rewritten target's bytes must never reach the caller, got: {body}"
        );
        bounce.assert_async().await;
        target.assert_async().await;
    }

    // ── the node's own verification, run over what the client actually sent ──

    /// What the verifying mock made of a request that reached it.
    ///
    /// The empty slot (`None`) is its own state and means the mock was never hit at
    /// all, which is what the refusal test asserts. It must stay distinguishable from
    /// [`Verdict::WrongIdentity`], because "nobody verified anything" and "something
    /// verified against the wrong key" are opposite findings.
    ///
    /// The payloads are read through `Debug` in the assertion messages and nowhere
    /// else, which the dead-code pass does not count; they carry the detail that makes
    /// a failure legible, so they stay.
    #[derive(Debug)]
    #[allow(dead_code)]
    enum Verdict {
        /// The chain accepted the signature AND the key it resolved is the test's DID.
        Accepted,
        /// The chain refused it. Carries the error so a failure reads as the actual
        /// rejection rather than a bare hit count.
        Rejected(String),
        /// The chain accepted a signature made by somebody else. A key resolved from
        /// the parsed `key_id` is read out of the artifact under verification, so an
        /// accept on it alone proves consistency, never authenticity.
        WrongIdentity { expected: String, got: String },
    }

    /// The node's `require_signature` verification, over a request this crate did not
    /// build: parse the headers, recompute the content-digest from the body, rebuild
    /// the signing string over `@method`/`@path`/`content-digest`, Ed25519-verify.
    /// Returns the DID the signature resolved to, so a caller can pin the identity.
    ///
    /// A hand-copy of its twin in `crates/git-remote-gitlawb/src/main.rs`, which gl
    /// cannot import (`git-remote-gitlawb` is a binary crate and this is its test
    /// module). Keep the two textually identical apart from the mockito seam around
    /// them, so an edit to one is visibly an edit to both.
    ///
    /// The production verifier both copies mirror is `crate::auth::require_signature` in
    /// `crates/gitlawb-node/src/auth/mod.rs`. This is a re-implementation, not a call, so
    /// an edit to that middleware has to land here too: otherwise the copies drift and
    /// this test keeps passing against a rule the node has stopped applying.
    ///
    /// It asserts internally, which is deliberate but constrains its callers: inside
    /// `with_body_from_request` those assertions fire on the server thread and reach
    /// the client as a transport error, not as a recorded verdict. So the identity
    /// check lives in the caller as a [`Verdict`] variant, never as an assert in here.
    fn node_verifies(
        method: &str,
        path_and_query: &str,
        body: &[u8],
        sig_input: &str,
        sig_header: &str,
        content_digest: &str,
    ) -> anyhow::Result<String> {
        use gitlawb_core::http_sig::{build_signing_string, compute_content_digest, HttpSignature};
        use gitlawb_core::identity::verify;
        use std::collections::HashMap;

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
        Ok(sig.key_id.to_string())
    }

    /// Pull a header value off a received mockito request, or explain which one the
    /// client failed to send.
    fn received_header(req: &mockito::Request, name: &str) -> String {
        req.header(name)
            .first()
            .unwrap_or_else(|| panic!("the client sent no {name} header"))
            .to_str()
            .unwrap()
            .to_string()
    }

    /// Run [`node_verifies`] over a GET that arrived at the mock and record what the
    /// node would have made of it, pinned to `expected_did`.
    fn record_get_verdict(
        req: &mockito::Request,
        expected_did: &str,
        slot: &std::sync::Arc<std::sync::Mutex<Option<Verdict>>>,
    ) {
        let verdict = match node_verifies(
            "GET",
            req.path_and_query(),
            b"",
            &received_header(req, "signature-input"),
            &received_header(req, "signature"),
            &received_header(req, "content-digest"),
        ) {
            Ok(did) if did == expected_did => Verdict::Accepted,
            Ok(did) => Verdict::WrongIdentity {
                expected: expected_did.to_string(),
                got: did,
            },
            Err(e) => Verdict::Rejected(e.to_string()),
        };
        *slot.lock().unwrap() = Some(verdict);
    }

    /// The finding's repro, now a guard: a rewritten same-origin target must never
    /// receive the signature, and the proof is the node's own verification, not a hit
    /// count.
    ///
    /// The target mock runs the full `require_signature` chain over the request it
    /// receives. Post-fix the hop is refused, so the slot stays empty. Pre-fix the hop
    /// is followed and the slot records the Ed25519 rejection of a signature made over
    /// `/api/v1/thing` and presented at `/api/v1/thing/`, which is the 401 an operator
    /// behind such a proxy actually sees. The verdict is asserted first, so a failure
    /// speaks about verification rather than about reachability.
    ///
    /// Its paired positive control is
    /// `a_direct_signed_get_verifies_under_the_node_verifier`: without it, an empty
    /// slot would be satisfied just as well by a harness that can never record
    /// anything.
    #[tokio::test]
    async fn a_rewritten_target_never_receives_the_signature() {
        let kp = test_keypair();
        let expected_did = kp.did().to_string();
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<Verdict>));

        let mut node = Server::new_async().await;
        let bounce = node
            .mock("GET", "/api/v1/thing")
            .with_status(301)
            .with_header("location", "/api/v1/thing/")
            .expect(1)
            .create_async()
            .await;
        let recorder = slot.clone();
        let did_for_target = expected_did.clone();
        let target = node
            .mock("GET", "/api/v1/thing/")
            .with_status(200)
            .with_body_from_request(move |req| {
                record_get_verdict(req, &did_for_target, &recorder);
                Vec::new()
            })
            .expect(0)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(kp));
        let resp = client.get_signed("/api/v1/thing").await.unwrap();

        let verdict = slot.lock().unwrap().take();
        assert!(
            verdict.is_none(),
            "the node's own verifier must never see this request: the signature covers \
             /api/v1/thing and the rewritten target is /api/v1/thing/, so what arrives \
             there is a stale request-target; recorded verdict: {verdict:?}"
        );
        assert_eq!(
            resp.status(),
            301,
            "the caller sees the 3xx, not the rewritten target's answer"
        );
        bounce.assert_async().await;
        target.assert_async().await;
    }

    /// The positive control for the test above, and the proof that the client signs
    /// the query it sends.
    ///
    /// A direct signed GET, no redirect anywhere, through the same verifying mock. The
    /// verdict must be `Accepted`, which is what makes the refusal test's empty slot
    /// attributable to the refusal rather than to a harness that cannot record. The
    /// path carries a query, so a client that signed the bare path would land here as
    /// `Rejected`.
    #[tokio::test]
    async fn a_direct_signed_get_verifies_under_the_node_verifier() {
        let kp = test_keypair();
        let expected_did = kp.did().to_string();
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<Verdict>));

        let mut node = Server::new_async().await;
        let recorder = slot.clone();
        let did_for_target = expected_did.clone();
        let route = node
            .mock("GET", "/api/v1/thing?x=1")
            .with_status(200)
            .with_body_from_request(move |req| {
                record_get_verdict(req, &did_for_target, &recorder);
                Vec::new()
            })
            .expect(1)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(kp));
        let resp = client.get_signed("/api/v1/thing?x=1").await.unwrap();
        assert_eq!(resp.status(), 200);

        let verdict = slot.lock().unwrap().take();
        assert!(
            matches!(verdict, Some(Verdict::Accepted)),
            "a direct signed GET must verify under the node's own chain and resolve to \
             {expected_did}, or the refusal test's empty slot proves nothing; recorded \
             verdict: {verdict:?}"
        );
        route.assert_async().await;
    }

    // ── read_body_capped ────────────────────────────────────────────────

    /// A body whose read FAILS mid-stream must be distinguishable from a body that
    /// ended. Both used to leave through the same `_ => break`, so a 500 whose body
    /// died in transit produced an empty message and the caller was told
    /// `node returned 500: ` with nothing after the colon.
    ///
    /// The fixture is a raw listener that promises 64 bytes in `Content-Length`,
    /// writes 5, and closes. mockito cannot express that: it always completes the
    /// response it advertises. MUTATION (RED): restore the single `_ => break` arm
    /// (or hard-code `read_failed: false`) and the flag reads false.
    #[tokio::test]
    async fn read_body_capped_flags_a_mid_body_read_failure() {
        let addr = spawn_short_body_listener().await;
        let resp = reqwest::get(format!("http://{addr}/truncated"))
            .await
            .expect("headers arrive before the body is cut");
        let body = read_body_capped(resp, 8192).await;

        assert!(
            body.read_failed,
            "a body cut off mid-stream must be reported as a failed read, not as a \
             body that ended: got {:?}",
            body.text
        );
        assert!(
            !body.truncated,
            "the cap did not cut this one; 5 bytes are nowhere near 8 KiB"
        );
    }

    /// The must-not half: a body that ends cleanly must NOT be flagged, or the flag
    /// means nothing and every terminal starts claiming the node went quiet.
    #[tokio::test]
    async fn read_body_capped_does_not_flag_a_clean_body() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/ok")
            .with_status(500)
            .with_body("node said this")
            .create_async()
            .await;
        let resp = reqwest::get(format!("{}/ok", server.url())).await.unwrap();
        let body = read_body_capped(resp, 8192).await;

        assert_eq!(body.text, "node said this");
        assert!(!body.read_failed, "a complete body is not a failed read");
        assert!(!body.truncated, "a complete body is not a truncated one");
    }

    /// Answer one request with headers promising more body than gets written, then
    /// close the connection. Returns the listener's address.
    async fn spawn_short_body_listener() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await;
            let _ = sock
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 64\r\n\r\nshort")
                .await;
            let _ = sock.flush().await;
            // Drop closes the socket with 59 of the promised bytes never sent.
        });
        addr
    }

    // ── total request timeout ───────────────────────────────────────────

    /// The client's timeout is a TOTAL request timeout, so it bounds a download and
    /// not just the handshake. `gl ipfs get`'s documentation leans on exactly that:
    /// the wall-clock deadline covers the search and deliberately stops at the
    /// response headers, and this timeout is the only thing left bounding the body.
    ///
    /// Driven at 250ms through `with_timeout`, the seam `new` itself calls with
    /// `TOTAL_REQUEST_TIMEOUT`, because a test at the shipped 30s has no place in this
    /// suite. What that costs is the value; what it proves is the SHAPE, which is the
    /// part in doubt: that the deadline keeps running once the headers have landed. A
    /// timeout that covered only the handshake would let this request hang until the
    /// listener gives up.
    #[tokio::test]
    async fn total_timeout_cuts_off_a_body_that_outruns_it() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = sock.read(&mut scratch).await;
            // Headers land immediately, then the body stalls indefinitely.
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\nfirst")
                .await;
            let _ = sock.flush().await;
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });

        let client = NodeClient::with_timeout(
            format!("http://{addr}"),
            None,
            std::time::Duration::from_millis(250),
        );
        let started = std::time::Instant::now();
        let resp = client.get("/slow").await.expect("headers arrive promptly");
        assert_eq!(
            resp.status(),
            200,
            "the stall is in the body, not the status"
        );
        let err = resp
            .bytes()
            .await
            .expect_err("a body still arriving past the total timeout must be cut off");
        let elapsed = started.elapsed();

        assert!(
            err.is_timeout(),
            "the body read must end in a timeout, got: {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the timeout must fire on its own schedule, not wait out the listener; \
             took {elapsed:?}"
        );
    }

    #[test]
    fn shipped_client_uses_the_documented_total_timeout() {
        // The scaled-down test above proves the shape at 250ms. This pins the value
        // `new` actually ships, so the two together cover the documented behaviour.
        assert_eq!(TOTAL_REQUEST_TIMEOUT, std::time::Duration::from_secs(30));
    }

    #[test]
    fn sanitize_strips_controls_bidi_and_caps_length() {
        // C0 (ESC/BEL) and the Cf bidi override (U+202E) are both removed; the
        // printable text survives. (Note: a stripped ESC leaves any following
        // "[31m" as inert literal text — that is the point, so the input here
        // avoids that residue to keep the expectation unambiguous.)
        let out = sanitize_node_msg("a\u{1b}\u{07}b\u{202e}c");
        assert!(
            !out.chars().any(|c| c.is_control()),
            "control char leaked: {out:?}"
        );
        assert!(
            !out.contains('\u{202e}'),
            "RLO bidi override leaked: {out:?}"
        );
        assert_eq!(out, "abc");
        // Length is capped at 200 chars regardless of input size.
        let long = "x".repeat(250);
        assert_eq!(sanitize_node_msg(&long).chars().count(), 200);
    }

    #[test]
    fn sanitize_preserves_legitimate_and_rtl_text() {
        // Must not over-strip: a plain word, a genuine RTL SCRIPT letter (Arabic
        // U+0627, category Lo — NOT a format char), and ZWJ (U+200D, a legitimate
        // Cf char, e.g. emoji sequences) all survive. Guards the shared predicate
        // against being widened into a blanket Cf stripper.
        let out = sanitize_node_msg("ok \u{0627}\u{200D}b");
        assert_eq!(out, "ok \u{0627}\u{200D}b");
    }
}
