//! Signed HTTP client for gitlawb API calls (async).
//!
//! Writes are signed with RFC 9421 HTTP Signatures. When the node gates a write
//! behind iCaptcha (HTTP 403 `icaptcha_proof_required`, advertised via the
//! `x-icaptcha-url` / `x-icaptcha-level` headers), the client transparently
//! solves the challenge and retries the same signed request with the
//! `x-icaptcha-proof` header — see `crates/icaptcha-client`.

use anyhow::{Context, Result};
use gitlawb_core::http_sig::sign_request;
use gitlawb_core::identity::Keypair;
use icaptcha_client::IcaptchaCfg;
use serde_json::Value;

/// Max times we'll fetch a fresh proof and retry a 403-iCaptcha response
/// (absorbs proof expiry / first-seen replay).
const MAX_ICAPTCHA_RETRIES: usize = 2;

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
    /// `x-icaptcha-*` headers) solve it and retry the same signed request with
    /// the proof header, up to [`MAX_ICAPTCHA_RETRIES`]. Emits an actionable
    /// hint on a 401 "not an agent" (the old-CLI / unregistered failure mode).
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

/// Run the (blocking) iCaptcha solve loop off the async runtime.
async fn obtain_proof(cfg: IcaptchaCfg) -> Result<String> {
    tokio::task::spawn_blocking(move || icaptcha_client::obtain_proof(&cfg, None))
        .await
        .context("iCaptcha solver task panicked")?
}

/// Read a JSON response, surfacing a node denial/error instead of parsing it as
/// the requested resource. On a non-2xx status it returns an `Err` carrying the
/// node's sanitized `message` (INV-6) plus the status; on success it parses the
/// body and propagates a parse error, so a truncated/garbage 2xx body is an error
/// rather than a silently-empty success (the denial-as-success bug #123 fixes).
/// `what` names the resource for the error text (e.g. "repo", "commits").
///
/// Callers must route gated reads through this rather than `resp.json().await?`:
/// the bare parse renders a gated 404/5xx body back as the resource (INV-8).
/// Cap on the error body `read_json` reads before parsing a node's `message`.
/// Matches the capped-read bound used on the sync error path; large enough for any
/// legitimate error, small enough that a hostile node cannot exhaust memory.
const ERROR_BODY_CAP: usize = 8 * 1024;

pub(crate) async fn read_json(resp: reqwest::Response, what: &str) -> Result<Value> {
    let status = resp.status();
    if !status.is_success() {
        // Bound the error read: `resp.json()` would buffer and parse the WHOLE
        // body, so a hostile node could stream an arbitrarily large valid JSON
        // error and exhaust this process's memory (#186). Read a small capped body
        // first, then best-effort extract `message`. The error body may also be
        // non-JSON (503 degraded, 413 body-limit from middleware), so a parse miss
        // falls back to the capped raw text; an empty body to the status alone.
        let raw = crate::sync::read_body_capped(resp, ERROR_BODY_CAP).await;
        // Preserve the prior contract: surface the JSON `message` when present in
        // the capped body, else the status alone ("request failed") — a non-JSON
        // or message-less body (503 degraded, 413 body-limit) never surfaces raw
        // node bytes. A body whose `message` sits past the cap parses as truncated
        // garbage here and correctly falls back rather than being buffered whole.
        let msg = serde_json::from_str::<Value>(&raw)
            .ok()
            .and_then(|b| b.get("message").and_then(|m| m.as_str()).map(str::to_owned))
            .unwrap_or_else(|| "request failed".to_owned());
        anyhow::bail!(
            "{what} failed ({status}): {}",
            crate::sync::sanitize_node_msg(&msg)
        );
    }
    // Success: a truncated/garbage 2xx body must be an `Err`, not `Ok(Null)` that
    // a caller then renders as an empty success.
    resp.json()
        .await
        .with_context(|| format!("invalid JSON in {what} response"))
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

    // ── read_json (status-checked read; #123 / INV-8 / INV-6) ────────────

    /// Drive a real `reqwest::Response` off a mockito mock so `read_json` sees an
    /// actual HTTP status + body, the same shape the gated read arms produce.
    async fn response_for(
        server: &mut Server,
        status: usize,
        body: &str,
        json: bool,
    ) -> reqwest::Response {
        let mut m = server.mock("GET", "/x").with_status(status).with_body(body);
        if json {
            m = m.with_header("content-type", "application/json");
        }
        let _m = m.create_async().await;
        NodeClient::new(server.url(), None).get("/x").await.unwrap()
    }

    #[tokio::test]
    async fn read_json_returns_body_on_2xx() {
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            200,
            r#"{"name":"r","owner_did":"did:gitlawb:z"}"#,
            true,
        )
        .await;
        let v = read_json(resp, "repo").await.unwrap();
        assert_eq!(v["name"], "r");
    }

    #[tokio::test]
    async fn read_json_errs_on_404_surfacing_message_and_status() {
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            404,
            r#"{"message":"repository 'o/r' not found"}"#,
            true,
        )
        .await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("404"), "err={err}");
        assert!(err.contains("not found"), "err={err}");
    }

    #[tokio::test]
    async fn read_json_errs_on_500_surfacing_message() {
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 500, r#"{"message":"internal boom"}"#, true).await;
        let err = read_json(resp, "commits").await.unwrap_err().to_string();
        assert!(err.contains("500"), "err={err}");
        assert!(err.contains("internal boom"), "err={err}");
    }

    #[tokio::test]
    async fn read_json_errs_on_non_json_error_body_with_fallback() {
        // 503 with a plain-text (middleware) body: no `message` field to surface.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 503, "service unavailable", false).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("503"), "err={err}");
        assert!(err.contains("request failed"), "err={err}");
    }

    #[tokio::test]
    async fn read_json_sanitizes_control_and_bidi_in_message() {
        // INV-6: a hostile node embeds ESC, BEL, and a right-to-left override in
        // the error message; none may reach the terminal verbatim.
        let mut server = Server::new_async().await;
        let resp = response_for(
            &mut server,
            404,
            r#"{"message":"a\u001b[31mb\u0007c\u202ed"}"#,
            true,
        )
        .await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(!err.contains('\u{1b}'), "ESC leaked: {err:?}");
        assert!(!err.contains('\u{7}'), "BEL leaked: {err:?}");
        assert!(!err.contains('\u{202e}'), "bidi override leaked: {err:?}");
    }

    #[tokio::test]
    async fn read_json_errs_on_garbage_2xx_body() {
        // The #123 correctness point: a 200 with a non-JSON/truncated body must be
        // an `Err`, NOT `Ok(Null)` that a caller renders as an empty success.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 200, "this is not json", false).await;
        assert!(read_json(resp, "repo").await.is_err());
    }

    #[tokio::test]
    async fn read_json_errs_on_empty_2xx_body() {
        // A zero-byte 200 body must be an `Err`, not a silent `Ok(Null)`.
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 200, "", false).await;
        assert!(read_json(resp, "repo").await.is_err());
    }

    #[tokio::test]
    async fn read_json_errs_on_non_2xx_json_without_message() {
        // A non-2xx JSON body that lacks a `message` key falls back to "request failed".
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 403, r#"{"error":"forbidden"}"#, true).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("403"), "err={err}");
        assert!(err.contains("request failed"), "err={err}");
    }

    /// #186 (F2): the non-2xx error path must read a CAPPED body, not buffer and
    /// parse the whole thing — a hostile node can stream an arbitrarily large valid
    /// JSON error. Place the `message` field AFTER more than the cap of padding: the
    /// bounded read stops before it, so it must be ABSENT from the surfaced error.
    /// RED before the fix (`resp.json()` parses the full body → the far message
    /// appears), GREEN after (capped read truncates → fallback → far message gone).
    /// The status is still surfaced, so a legitimate small error is unaffected.
    #[tokio::test]
    async fn read_json_bounds_the_error_body_read() {
        let mut server = Server::new_async().await;
        // >8 KiB of padding, then the marker message at the very end of the body.
        let big = format!(
            r#"{{"padding":"{}","message":"FARMARKER_BEYOND_CAP"}}"#,
            "A".repeat(16 * 1024)
        );
        let resp = response_for(&mut server, 500, &big, true).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("500"), "bounded read still errors: {err}");
        assert!(
            !err.contains("FARMARKER_BEYOND_CAP"),
            "the error body read must be capped: a message beyond the cap must not be surfaced, err={err}"
        );
    }

    /// #186 (F2): an EMPTY non-2xx body is its own input class — the capped read
    /// yields "", the JSON parse fails, and it falls back to the status alone
    /// ("request failed"), never a panic or a spurious success.
    #[tokio::test]
    async fn read_json_errs_on_empty_non_2xx_body() {
        let mut server = Server::new_async().await;
        let resp = response_for(&mut server, 502, "", false).await;
        let err = read_json(resp, "repo").await.unwrap_err().to_string();
        assert!(err.contains("502"), "err={err}");
        assert!(err.contains("request failed"), "err={err}");
    }
}
