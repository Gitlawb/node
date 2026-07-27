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
use icaptcha_client::IcaptchaCfg;

/// Max times we'll fetch a fresh proof and retry a 403-iCaptcha response
/// (absorbs proof expiry / first-seen replay).
const MAX_ICAPTCHA_RETRIES: usize = 2;

/// Max bytes buffered from a denial body before we give up on parsing it. Node
/// error bodies are a few hundred bytes of JSON; anything past this is not one,
/// and reading it unbounded is exactly the allocation a hostile node would aim
/// for.
const DENIAL_BODY_CAP: usize = 64 * 1024;

/// Max characters of a node-supplied message we will echo to the terminal.
const NODE_MSG_CHARS: usize = 200;

pub struct NodeClient {
    inner: reqwest::Client,
    pub node_url: String,
    keypair: Option<Keypair>,
}

impl NodeClient {
    pub fn new(node_url: impl Into<String>, keypair: Option<Keypair>) -> Self {
        let inner = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
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
    /// signature-ledger denial into an error.
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

/// A write the node refused because of the spent-signature ledger.
struct SignatureRejection {
    /// The `x-gitlawb-error` code, kept verbatim so scripts can match on it.
    code: &'static str,
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
    async fn into_error(
        self,
        method: &str,
        path: &str,
        mut resp: reqwest::Response,
    ) -> anyhow::Error {
        let status = resp.status();
        let raw = read_body_capped(&mut resp, DENIAL_BODY_CAP).await;
        let node_msg = serde_json::from_slice::<serde_json::Value>(&raw)
            .ok()
            .and_then(|b| b["message"].as_str().map(sanitize_node_msg))
            .filter(|m| !m.is_empty());
        let Self { code, hint } = self;
        match node_msg {
            Some(m) => anyhow::anyhow!("{method} {path} rejected ({status} {code}): {hint} ({m})"),
            None => anyhow::anyhow!("{method} {path} rejected ({status} {code}): {hint}"),
        }
    }
}

/// Recognise a spent-signature-ledger rejection from the status and the
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
fn signature_rejection(resp: &reqwest::Response) -> Option<SignatureRejection> {
    let code = resp.headers().get("x-gitlawb-error")?.to_str().ok()?;
    let (code, hint) = match (resp.status().as_u16(), code) {
        (400, "signature_nonce_required") => (
            "signature_nonce_required",
            "this node requires a nonce in the request signature and the request did not carry \
             one. The write did not happen; upgrade `gl` and run the command again",
        ),
        (409, "signature_replayed") => (
            "signature_replayed",
            "the node already admitted a request with this signature and will not take it twice. \
             Do not resend: check whether the change took effect before running the command again",
        ),
        (429, "signature_ledger_full") => (
            "signature_ledger_full",
            "this identity has too many unexpired signatures on the node, so it is refusing more \
             signed writes for now. The write did not happen; wait a moment and run the command \
             again",
        ),
        (500, "signature_identity_missing") => (
            "signature_identity_missing",
            "the node reached its signature ledger without a verified identity and refused the \
             write. The write did not happen; this is a fault on the node, so report it to the \
             operator",
        ),
        (503, "signature_ledger_unavailable") => (
            "signature_ledger_unavailable",
            "the node's signature ledger is unavailable, so it is refusing signed writes. \
             The write did not happen; retry later or ask the node operator to check the node",
        ),
        _ => return None,
    };
    Some(SignatureRejection { code, hint })
}

/// Read at most `cap` bytes of a response body. Bounds the allocation from a
/// hostile or broken node returning a huge error body: the display is capped
/// separately, but the read itself must not be unbounded (INV-6, read half).
/// Takes the response by reference so the caller keeps the status and headers.
pub(crate) async fn read_body_capped(resp: &mut reqwest::Response, cap: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < cap {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = (cap - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break; // hit the cap mid-chunk
                }
            }
            _ => break, // end of body or read error: return what we have
        }
    }
    buf
}

/// Strip terminal-dangerous characters from (and cap the length of) a
/// node-supplied error string before surfacing it. The node a caller talks to
/// could be hostile and embed escape sequences in its error body; those must not
/// reach the terminal verbatim (INV-6). We drop the C0/C1 control bytes (which
/// defangs ANSI/OSC escapes) AND the Unicode bidi/format controls (which
/// `char::is_control` does not cover, and they can reorder the displayed line).
pub(crate) fn sanitize_node_msg(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !gitlawb_core::sanitize::is_bidi_format(*c))
        .take(NODE_MSG_CHARS)
        .collect()
}

/// Read a node reply, turning a non-2xx into an error instead of handing the
/// caller an error body that pretty-prints like a success. The message is read
/// under a cap and sanitized, same as a signature denial.
pub(crate) async fn json_or_denial<T: serde::de::DeserializeOwned>(
    what: &str,
    mut resp: reqwest::Response,
) -> Result<T> {
    let status = resp.status();
    if !status.is_success() {
        let raw = read_body_capped(&mut resp, DENIAL_BODY_CAP).await;
        let msg = serde_json::from_slice::<serde_json::Value>(&raw)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("error"))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&raw).into_owned());
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

    /// Every signature denial the node can return, as (status, code).
    const ALL_DENIALS: [(usize, &str); 5] = [
        (400, "signature_nonce_required"),
        (409, "signature_replayed"),
        (429, "signature_ledger_full"),
        (500, "signature_identity_missing"),
        (503, "signature_ledger_unavailable"),
    ];

    #[tokio::test]
    async fn send_signed_errors_on_every_denial_carrying_the_header() {
        for (status, code) in ALL_DENIALS {
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
        for (status, code) in ALL_DENIALS {
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
}
