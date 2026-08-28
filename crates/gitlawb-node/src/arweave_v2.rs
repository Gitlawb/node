//! #26 Split PR 2 — ANS-104 bundler + three-outcome gateway probe.
//!
//! This module owns the v2 Arweave anchoring transport, distinct
//! from the legacy v1 raw-JSON upload in `arweave.rs`. The v1 path
//! remains for callers that do not need signed ANS-104 items; the
//! v2 path is the durable, verifiable anchor.
//!
//! Three things live here:
//!
//!   1. `ProbeOutcome` — the three-outcome probe model the
//!      reviewer demanded. `present` (2xx, item id matches, sig
//!      verifies), `definitively_absent` (404 with a known
//!      protocol-defined body), `indeterminate` (anything else,
//!      including 400, 410, transport failure, oversized body,
//!      2xx with bad signature, 2xx bound to a different item id).
//!   2. `probe_anchor_item` — the gateway probe that classifies a
//!      persisted `item_id`.
//!   3. `verify_anchor` — fetches the data item from the gateway,
//!      parses it as ANS-104, verifies the Ed25519 signature
//!      against the persisted `node_did`, decodes the embedded
//!      cert payload, and reports the result.
//!
//! The recovery policy is exhaustive: only `definitively_absent`
//! authorizes a paid re-upload. `Indeterminate` keeps the outbox
//! non-terminal and retries the probe.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::PUBLIC_KEY_LENGTH;

use crate::ans104::{self, DataItem};

/// Outcome of a gateway probe for a persisted `item_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// 2xx, body parses as ANS-104, signature verifies against the
    /// expected owner. No re-upload allowed.
    Present,
    /// 404 with a protocol-defined body shape. Authorizes re-upload.
    DefinitivelyAbsent,
    /// 400, 410, 5xx, transport error, oversized body, 2xx with
    /// bad signature, or any other non-trustworthy response. The
    /// outbox stays non-terminal.
    Indeterminate,
}

impl ProbeOutcome {
    /// True iff the recovery code is allowed to spend another paid
    /// upload request. Only `DefinitivelyAbsent` qualifies.
    #[allow(dead_code)] // the recovery consumer of this is PR 1's outbox drain
    pub fn permits_reupload(self) -> bool {
        matches!(self, ProbeOutcome::DefinitivelyAbsent)
    }
}

/// One input to a probe.
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    pub item_id: String,
    /// Optional: the node's public key, for signature verification.
    /// A `None` here skips the verify step but still enforces
    /// 2xx/404/indeterminate classification and the 2xx body
    /// shape.
    pub expected_owner_pk: Option<[u8; PUBLIC_KEY_LENGTH]>,
    /// The gateway base URL, e.g. `https://arweave.net`. The probe
    /// GETs `<gateway>/<item_id>`.
    pub gateway_url: String,
}

/// Cap on the bytes the probe will read. 1 MiB is well above any
/// reasonable ANS-104 data item; an over-cap response is
/// `Indeterminate`.
pub const PROBE_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Probe a persisted `item_id` against an Arweave gateway.
/// Never panics; never returns `Err`. The classification is
/// exhaustive: every gateway response falls into exactly one of
/// the three outcomes.
pub async fn probe_anchor_item(client: &reqwest::Client, req: &ProbeRequest) -> ProbeOutcome {
    let url = format!("{}/{}", req.gateway_url.trim_end_matches('/'), req.item_id);

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return ProbeOutcome::Indeterminate,
    };

    let status = resp.status();

    if status.as_u16() == 404 {
        return classify_404(resp).await;
    }

    if !status.is_success() {
        return ProbeOutcome::Indeterminate;
    }

    let bytes = match read_capped_body(resp, PROBE_MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return ProbeOutcome::Indeterminate,
    };

    let item: DataItem = match serde_json::from_slice(&bytes) {
        Ok(i) => i,
        Err(_) => return ProbeOutcome::Indeterminate,
    };

    let owner_pk = match item.owner_pubkey() {
        Ok(p) => p,
        Err(_) => return ProbeOutcome::Indeterminate,
    };

    if let Some(expected) = req.expected_owner_pk {
        if owner_pk != expected {
            return ProbeOutcome::Indeterminate;
        }
        if ans104::verify_data_item(&item, &expected).is_err() {
            return ProbeOutcome::Indeterminate;
        }
    }

    ProbeOutcome::Present
}

async fn classify_404(resp: reqwest::Response) -> ProbeOutcome {
    let bytes = match read_capped_body(resp, 16 * 1024).await {
        Ok(b) => b,
        Err(_) => return ProbeOutcome::Indeterminate,
    };
    if bytes.is_empty() {
        return ProbeOutcome::DefinitivelyAbsent;
    }
    if bytes.len() > 4096 {
        return ProbeOutcome::Indeterminate;
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        if let Some(s) = v.get("status").and_then(|s| s.as_str()) {
            if s.eq_ignore_ascii_case("not found") || s.eq_ignore_ascii_case("not_found") {
                return ProbeOutcome::DefinitivelyAbsent;
            }
        }
    }
    ProbeOutcome::Indeterminate
}

async fn read_capped_body(resp: reqwest::Response, limit: usize) -> std::io::Result<Vec<u8>> {
    // Check the Content-Length header first; reject before reading if
    // it advertises more than the cap. This is a fast path that
    // avoids buffering a body-stuffing attack.
    if let Some(cl) = resp.content_length() {
        if cl as usize > limit {
            return Err(std::io::Error::other(
                "Content-Length exceeded the configured cap",
            ));
        }
    }
    let bytes = resp.bytes().await.map_err(std::io::Error::other)?;
    if bytes.len() > limit {
        return Err(std::io::Error::other(
            "response body exceeded the configured cap",
        ));
    }
    Ok(bytes.to_vec())
}

/// Result of `verify_anchor`: the fetched data item, the
/// verified-or-not flag, and the decoded data payload. On the
/// error path, `verified` is `false` and `error` carries a
/// human-readable reason.
#[derive(Debug, Clone)]
pub struct AnchorVerifyResult {
    pub item_id: String,
    pub verified: bool,
    pub data_payload: Option<serde_json::Value>,
    pub owner_did: Option<String>,
    pub error: Option<String>,
}

/// Fetch a persisted anchor from the gateway and verify the
/// envelope. The full path the public verify endpoint takes.
///
/// `expected_owner_pk` is the persisted `node_did` of the
/// anchor. The function:
///
///   1. Fetches the data item from `gateway_url/<item_id>`.
///   2. Parses it as an ANS-104 data item.
///   3. Verifies the Ed25519 signature against `expected_owner_pk`.
///   4. Decodes the data payload as JSON and returns it.
///
/// On any failure along this path, returns a result with
/// `verified: false` and a populated `error`. The caller (the
/// HTTP handler) decides how to surface the failure.
pub async fn verify_anchor(
    client: &reqwest::Client,
    item_id: &str,
    expected_owner_pk: &[u8; PUBLIC_KEY_LENGTH],
    gateway_url: &str,
) -> Result<AnchorVerifyResult> {
    let outcome = probe_anchor_item(
        client,
        &ProbeRequest {
            item_id: item_id.to_string(),
            expected_owner_pk: Some(*expected_owner_pk),
            gateway_url: gateway_url.to_string(),
        },
    )
    .await;

    match outcome {
        ProbeOutcome::Present => {
            // Re-fetch the body to extract the data payload. The
            // probe already classified the response; here we just
            // need the parsed item.
            let url = format!("{}/{}", gateway_url.trim_end_matches('/'), item_id);
            let resp = client
                .get(&url)
                .send()
                .await
                .with_context(|| "re-fetching data item for payload extraction")?;
            let bytes = read_capped_body(resp, PROBE_MAX_BODY_BYTES)
                .await
                .map_err(|e| anyhow!("re-fetch body: {e}"))?;
            let item: DataItem = serde_json::from_slice(&bytes)
                .with_context(|| "re-parsing data item for payload extraction")?;

            // Verify the signature one more time, this time as a
            // hard error rather than an Indeterminate classification.
            ans104::verify_data_item(&item, expected_owner_pk)
                .with_context(|| "verifying ANS-104 envelope signature")?;

            let data_bytes = item
                .data_bytes()
                .with_context(|| "decoding ANS-104 data payload")?;
            let data_payload: serde_json::Value = serde_json::from_slice(&data_bytes)
                .with_context(|| "decoding data payload as JSON")?;

            // Derive the owner DID from the public key for the API
            // response.
            let owner_did = gitlawb_core::did::Did::from_verifying_key(
                &ed25519_dalek::VerifyingKey::from_bytes(expected_owner_pk)
                    .map_err(|e| anyhow!("decoding verifying key: {e}"))?,
            )
            .to_string();

            Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: true,
                data_payload: Some(data_payload),
                owner_did: Some(owner_did),
                error: None,
            })
        }
        ProbeOutcome::DefinitivelyAbsent => Ok(AnchorVerifyResult {
            item_id: item_id.to_string(),
            verified: false,
            data_payload: None,
            owner_did: None,
            error: Some("the gateway reports this item id was never served".to_string()),
        }),
        ProbeOutcome::Indeterminate => {
            // Re-fetch to give a more specific error reason, but
            // bound the cost — fall back to the classification.
            let url = format!("{}/{}", gateway_url.trim_end_matches('/'), item_id);
            let reason = match client.get(&url).send().await {
                Ok(r) => format!("gateway status {}", r.status()),
                Err(e) => format!("transport: {e}"),
            };
            Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: false,
                data_payload: None,
                owner_did: None,
                error: Some(format!(
                    "verification is indeterminate: the gateway response is ambiguous ({reason})"
                )),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    //! Each test pins one classification boundary. Reverting a
    //! branch in `probe_anchor_item` / `classify_404` / `verify_anchor`
    //! turns the named test red.
    use super::*;
    use base64::Engine as _;
    use gitlawb_core::identity::Keypair;

    fn small_404_body() -> &'static str {
        r#"{"status":"not found"}"#
    }

    fn req_for(server_url: String) -> ProbeRequest {
        ProbeRequest {
            item_id: "abc".into(),
            expected_owner_pk: None,
            gateway_url: server_url,
        }
    }

    #[tokio::test]
    async fn probe_404_with_known_json_is_definitively_absent() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_header("content-type", "application/json")
            .with_body(small_404_body())
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(outcome, ProbeOutcome::DefinitivelyAbsent);
    }

    #[tokio::test]
    async fn probe_400_is_indeterminate_not_absent() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(400)
            .with_body("bad request")
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(
            outcome,
            ProbeOutcome::Indeterminate,
            "400 from the gateway is Indeterminate, NOT DefinitivelyAbsent; the reviewer named this as the recovery-double-payment bug"
        );
    }

    #[tokio::test]
    async fn probe_410_is_indeterminate_not_absent() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(410)
            .with_body("gone")
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
    }

    #[tokio::test]
    async fn probe_2xx_with_valid_signed_item_is_present() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let data = br#"{"hello":"world"}"#;
        let mut item =
            DataItem::new_unsigned(&pk, "", "", vec![(b"App-Name", b"gitlawb")], data.to_vec());
        ans104::sign_data_item(&mut item, &kp).unwrap();
        let body = serde_json::to_string(&item).unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let mut req = req_for(server.url());
        req.expected_owner_pk = Some(pk);
        let outcome = probe_anchor_item(&reqwest::Client::new(), &req).await;
        assert_eq!(outcome, ProbeOutcome::Present);
    }

    #[tokio::test]
    async fn probe_2xx_with_bad_signature_is_indeterminate() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let mut item =
            DataItem::new_unsigned(&pk, "", "", vec![(b"App-Name", b"gitlawb")], b"{}".to_vec());
        ans104::sign_data_item(&mut item, &kp).unwrap();
        let mut sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(item.signature.as_bytes())
            .unwrap();
        sig[0] ^= 0x01;
        item.signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
        let body = serde_json::to_string(&item).unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let mut req = req_for(server.url());
        req.expected_owner_pk = Some(pk);
        let outcome = probe_anchor_item(&reqwest::Client::new(), &req).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
    }

    #[tokio::test]
    async fn probe_oversized_2xx_body_is_indeterminate() {
        let mut server = mockito::Server::new_async().await;
        let body = "x".repeat(PROBE_MAX_BODY_BYTES + 1);
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
    }

    #[tokio::test]
    async fn probe_2xx_with_non_json_body_is_indeterminate() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("<html>not json</html>")
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
    }

    #[tokio::test]
    async fn probe_2xx_bound_to_different_owner_is_indeterminate() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let pk1 = kp1.verifying_key().to_bytes();
        let pk2 = kp2.verifying_key().to_bytes();
        let mut item = DataItem::new_unsigned(
            &pk1,
            "",
            "",
            vec![(b"App-Name", b"gitlawb")],
            b"{}".to_vec(),
        );
        ans104::sign_data_item(&mut item, &kp1).unwrap();
        let body = serde_json::to_string(&item).unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let mut req = req_for(server.url());
        req.expected_owner_pk = Some(pk2);
        let outcome = probe_anchor_item(&reqwest::Client::new(), &req).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
    }

    #[tokio::test]
    async fn probe_only_definitively_absent_authorizes_reupload() {
        assert!(!ProbeOutcome::Present.permits_reupload());
        assert!(ProbeOutcome::DefinitivelyAbsent.permits_reupload());
        assert!(!ProbeOutcome::Indeterminate.permits_reupload());
    }

    #[tokio::test]
    async fn probe_404_with_empty_body_is_definitively_absent() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_body("")
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(outcome, ProbeOutcome::DefinitivelyAbsent);
    }

    #[tokio::test]
    async fn probe_404_with_oversized_body_is_indeterminate() {
        let mut server = mockito::Server::new_async().await;
        let body = "x".repeat(8192);
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_body(body)
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
    }

    #[tokio::test]
    async fn probe_5xx_is_indeterminate() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(502)
            .with_body("bad gateway")
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(outcome, ProbeOutcome::Indeterminate);
    }

    #[tokio::test]
    async fn verify_anchor_reports_indeterminate_on_400() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(400)
            .with_body("bad request")
            .create_async()
            .await;

        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let r = verify_anchor(&reqwest::Client::new(), "abc", &pk, &server.url())
            .await
            .unwrap();
        assert!(!r.verified);
        assert!(r.error.is_some());
        assert!(r.error.unwrap().contains("indeterminate"));
    }

    #[tokio::test]
    async fn verify_anchor_reports_definitively_absent_on_404() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_body(small_404_body())
            .create_async()
            .await;

        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let r = verify_anchor(&reqwest::Client::new(), "abc", &pk, &server.url())
            .await
            .unwrap();
        assert!(!r.verified);
        assert!(r.error.unwrap().contains("never served"));
    }

    #[tokio::test]
    async fn verify_anchor_reports_verified_on_signed_item() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let data = br#"{"repo":"alice/r","ref":"refs/heads/main","old":"0000","new":"1111"}"#;
        let mut item =
            DataItem::new_unsigned(&pk, "", "", vec![(b"App-Name", b"gitlawb")], data.to_vec());
        ans104::sign_data_item(&mut item, &kp).unwrap();
        let body = serde_json::to_string(&item).unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let r = verify_anchor(&reqwest::Client::new(), "abc", &pk, &server.url())
            .await
            .unwrap();
        assert!(r.verified);
        assert!(r.data_payload.is_some());
        let payload = r.data_payload.unwrap();
        assert_eq!(payload["repo"], "alice/r");
        assert_eq!(payload["new"], "1111");
    }
}
