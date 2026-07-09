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

#[cfg(test)]
mod tests {
    use super::*;
    use gitlawb_core::identity::Keypair;
    use mockito::Server;

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

    /// Helper: set GITLAWB_ICAPTCHA_URL so the iCaptcha client trusts the mock
    /// server URL and clean it up on drop.
    struct IcaptchaEnv;

    impl IcaptchaEnv {
        fn new(url: &str) -> Self {
            std::env::set_var("GITLAWB_ICAPTCHA_URL", url);
            IcaptchaEnv
        }
    }

    impl Drop for IcaptchaEnv {
        fn drop(&mut self) {
            std::env::remove_var("GITLAWB_ICAPTCHA_URL");
        }
    }

    /// Helper: set up a mock iCaptcha server that responds to challenge + answer.
    struct MockIcaptcha {
        _c: mockito::Mock,
        _a: mockito::Mock,
        _guard: IcaptchaEnv,
        url: String,
    }

    impl MockIcaptcha {
        async fn new(server: &mut mockito::ServerGuard) -> Self {
            let url = server.url();
            let guard = IcaptchaEnv::new(&url);
            let _c = server
                .mock("POST", "/v1/challenge")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(
                    r#"{"challengeId":"c1","type":"arithmetic","difficulty":1,"prompt":"What is 1 + 1?","token":"tk1"}"#,
                )
                .create_async()
                .await;
            let _a = server
                .mock("POST", "/v1/answer")
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"status":"passed","proof":"mock.proof"}"#)
                .create_async()
                .await;
            Self {
                _c,
                _a,
                _guard: guard,
                url,
            }
        }
    }

    #[tokio::test]
    async fn send_signed_solves_icaptcha_and_retries_to_success() {
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        let _ic = MockIcaptcha::new(&mut icaptcha).await;

        let _n1 = node
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &_ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .create_async()
            .await;
        let _n2 = node
            .mock("POST", "/api/register")
            .match_header("x-icaptcha-proof", mockito::Matcher::Any)
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"status":"created"}"#)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
    }

    #[tokio::test]
    async fn send_signed_returns_403_after_icaptcha_retries_exhausted() {
        let mut node = Server::new_async().await;
        let mut icaptcha = Server::new_async().await;
        let _ic = MockIcaptcha::new(&mut icaptcha).await;

        // Every call to the node returns 403 with iCaptcha headers, exhausting
        // MAX_ICAPTCHA_RETRIES (2). The original + 2 retries = 3 node calls.
        let _n = node
            .mock("POST", "/api/register")
            .with_status(403)
            .with_header("content-type", "application/json")
            .with_header("x-icaptcha-url", &_ic.url)
            .with_header("x-icaptcha-level", "3")
            .with_body(r#"{"error":"icaptcha_proof_required"}"#)
            .create_async()
            .await;

        let client = NodeClient::new(node.url(), Some(test_keypair()));
        let resp = client
            .send_signed("POST", "/api/register", b"{}")
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }
}
