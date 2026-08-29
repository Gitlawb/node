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

    // v1 detection: a body carrying `schema: "gitlawb/ref-update/v1"`
    // is the legacy raw-JSON shape the live path on this branch
    // writes. The probe returns Present so the v1 dispatch in
    // `verify_anchor` runs; the field-equality check there is the
    // v1 integrity guarantee. A body that is valid JSON but does
    // not carry that schema falls through to the v2 attempt.
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        if v.get("schema").and_then(|s| s.as_str()) == Some("gitlawb/ref-update/v1") {
            return ProbeOutcome::Present;
        }
    }

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

/// Classify a 404 response from the gateway.
///
/// `DefinitivelyAbsent` is reserved for the protocol-defined 404
/// body shape (`{"status": "not found"}` or `"not_found"`). An
/// empty body is `Indeterminate`: a proxy, CDN, or misconfigured
/// gateway may emit a bodyless 404 for many reasons that do not
/// prove the item was never served, and the recovery policy
/// (`DefinitivelyAbsent.permits_reupload()` → true) authorizes a
/// paid re-upload that is irreversible. The team memory
/// `distinguish-unknown-from-empty.md` is the policy: collapse
/// `unknown` to `absent` only on the recognized JSON shape, never
/// on empty.
async fn classify_404(resp: reqwest::Response) -> ProbeOutcome {
    let bytes = match read_capped_body(resp, 16 * 1024).await {
        Ok(b) => b,
        Err(_) => return ProbeOutcome::Indeterminate,
    };
    // Empty body — bodyless 404 from a proxy or misconfigured
    // gateway. NOT a proof of absence.
    if bytes.is_empty() {
        return ProbeOutcome::Indeterminate;
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
    // JSON body but not the recognized shape. Still not
    // `DefinitivelyAbsent` — proxies can return any JSON for
    // arbitrary reasons; only the protocol shape counts.
    ProbeOutcome::Indeterminate
}

/// Read a response body up to `limit` bytes, aborting as soon as
/// the cumulative size crosses the cap. The cap is enforced WHILE
/// streaming, not after buffering — a chunked response with no
/// `Content-Length` would otherwise force unbounded allocation
/// before the post-buffer length check could reject it.
///
/// `Content-Length`, when present, is used only as a fast path
/// optimization: if it advertises more than `limit`, reject
/// without reading. The streaming loop is the actual enforcement.
async fn read_capped_body(mut resp: reqwest::Response, limit: usize) -> std::io::Result<Vec<u8>> {
    // Fast path: a Content-Length over the cap means the server
    // told us up front the body is too big. Drop the response
    // without reading any bytes.
    if let Some(cl) = resp.content_length() {
        if cl as usize > limit {
            return Err(std::io::Error::other(
                "Content-Length exceeded the configured cap",
            ));
        }
    }

    // Streaming read. Track the cumulative byte count and abort
    // (via the `Err` return) the moment the cap is crossed, so a
    // chunked response that does NOT advertise a Content-Length
    // header still cannot force unbounded allocation.
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(std::io::Error::other)? {
        if buf.len() + chunk.len() > limit {
            return Err(std::io::Error::other(
                "response body exceeded the configured cap while streaming",
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Result of `verify_anchor`: the fetched data item, the
/// verified-or-not flag, and the decoded data payload. On the
/// error path, `verified` is `false` and `error` carries a
/// human-readable reason.
///
/// `outcome` carries the structured [`ProbeOutcome`] classification
/// so the HTTP handler can surface the status without parsing the
/// human-readable `error` string. The team memory
/// `verify-against-artifact-id-not-signer.md` is the policy: the
/// `error` field is for human eyes, never for routing decisions.
#[derive(Debug, Clone)]
pub struct AnchorVerifyResult {
    pub item_id: String,
    pub verified: bool,
    pub data_payload: Option<serde_json::Value>,
    pub owner_did: Option<String>,
    pub error: Option<String>,
    /// The structured classification. `verified: true` is only set
    /// when `outcome == ProbeOutcome::Present`.
    pub outcome: ProbeOutcome,
}

/// Persisted anchor fields used by the dual-format v1 + v2 verify.
/// The HTTP handler fetches the row from `arweave_anchors` and
/// passes these in; the verify path uses them to (a) identify the
/// v1 raw-JSON shape (the live path on this branch writes v1, not
/// v2) and (b) check the v1 fields match what the gateway serves.
#[derive(Debug, Clone)]
pub struct PersistedAnchorFields<'a> {
    pub repo: &'a str,
    pub ref_name: &'a str,
    pub old_sha: &'a str,
    pub new_sha: &'a str,
    pub node_did: &'a str,
}

/// Fetch a persisted anchor from the gateway and verify the
/// envelope. The full path the public verify endpoint takes.
///
/// `expected_owner_pk` is the persisted `node_did` of the anchor,
/// decoded as a 32-byte Ed25519 public key.
///
/// `persisted` carries the row's `repo`, `ref_name`, `old_sha`,
/// `new_sha`, `node_did` so the verify path can match the v1
/// raw-JSON format (the live path on this branch writes v1) and
/// the v2 artifact-identity check.
///
/// The verify path accepts BOTH formats:
///
///   - **v2 (ANS-104)**: parse as `DataItem`, verify the Ed25519
///     signature against `expected_owner_pk`, derive the protocol
///     id via `DataItem::id()` and require equality with `item_id`.
///     A stale or malicious mirror serving a different valid
///     same-owner item is the attack the artifact-id check closes;
///     the team memory `verify-against-artifact-id-not-signer.md`
///     is the policy.
///   - **v1 (raw JSON)**: parse as `serde_json::Value`, require
///     `schema == "gitlawb/ref-update/v1"`, then field-equality
///     check `repo`, `ref_name`, `old_sha`, `new_sha`, `node_did`
///     against the persisted row. v1 has no signature; the Irys
///     storage plus the JSON parse are the integrity guarantee.
///
/// On any failure along either path, returns a result with
/// `verified: false` and a populated `error`. The caller (the
/// HTTP handler) decides how to surface the failure.
pub async fn verify_anchor(
    client: &reqwest::Client,
    item_id: &str,
    expected_owner_pk: &[u8; PUBLIC_KEY_LENGTH],
    persisted: &PersistedAnchorFields<'_>,
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
            // need the parsed body.
            let url = format!("{}/{}", gateway_url.trim_end_matches('/'), item_id);
            let resp = client
                .get(&url)
                .send()
                .await
                .with_context(|| "re-fetching data item for payload extraction")?;
            let bytes = read_capped_body(resp, PROBE_MAX_BODY_BYTES)
                .await
                .map_err(|e| anyhow!("re-fetch body: {e}"))?;

            // Format detection: v1 first, by structural schema field.
            // The v1 raw-JSON shape carries `schema: gitlawb/ref-update/v1`
            // — a field the v2 ANS-104 DataItem projection never
            // includes. A v1 body parses as `serde_json::Value`
            // because DataItem deserialization is lenient about
            // unknown fields; trying v2 first would silently route
            // v1 anchors into the v2 path, which would then fail the
            // signature check (the v1 body has no signature) and
            // classify every v1 anchor as `Indeterminate`. The team
            // memory `self-roundtrip-tests-do-not-prove-interop.md`
            // is the broader reason: format detection is structural
            // and the structural signal must win over the parse
            // convenience.
            let v: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    return Ok(AnchorVerifyResult {
                        item_id: item_id.to_string(),
                        verified: false,
                        data_payload: None,
                        owner_did: None,
                        error: Some("the gateway response is not valid JSON".to_string()),
                        outcome: ProbeOutcome::Indeterminate,
                    });
                }
            };
            if v.get("schema").and_then(|s| s.as_str()) == Some("gitlawb/ref-update/v1") {
                verify_v1(v, item_id, persisted)
            } else if let Ok(item) = serde_json::from_value::<DataItem>(v.clone()) {
                verify_v2(item, item_id, expected_owner_pk, persisted)
            } else {
                // JSON parse failed entirely. Per the team memory
                // `distinguish-unknown-from-empty.md` and
                // `self-roundtrip-tests-do-not-prove-interop.md`,
                // this is Indeterminate — the gateway returned
                // something we cannot classify, NOT a proof of
                // presence.
                Ok(AnchorVerifyResult {
                    item_id: item_id.to_string(),
                    verified: false,
                    data_payload: None,
                    owner_did: None,
                    error: Some(
                        "the gateway response did not parse as an ANS-104 \
                         data item or a recognized v1 raw-JSON payload"
                            .to_string(),
                    ),
                    outcome: ProbeOutcome::Indeterminate,
                })
            }
        }
        ProbeOutcome::DefinitivelyAbsent => Ok(AnchorVerifyResult {
            item_id: item_id.to_string(),
            verified: false,
            data_payload: None,
            owner_did: None,
            error: Some("the gateway reports this item id was never served".to_string()),
            outcome: ProbeOutcome::DefinitivelyAbsent,
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
                outcome: ProbeOutcome::Indeterminate,
            })
        }
    }
}

/// v2 verify path. The item is already parsed as `DataItem`; the
/// signature and id are checked here. Returns a populated
/// `AnchorVerifyResult` with the appropriate `outcome` (Present
/// for full success, Indeterminate for any failure that should
/// not authorize a paid re-upload).
fn verify_v2(
    item: DataItem,
    item_id: &str,
    expected_owner_pk: &[u8; PUBLIC_KEY_LENGTH],
    persisted: &PersistedAnchorFields<'_>,
) -> Result<AnchorVerifyResult> {
    // Verify the signature. Any failure (bad base64, wrong key,
    // malformed signature, Ed25519 mismatch) maps to
    // `Indeterminate` — the team memory
    // `verify-against-artifact-id-not-signer.md` requires
    // structural checks beyond the signature, so the signature
    // alone is not the proof of identity.
    if let Err(e) = ans104::verify_data_item(&item, expected_owner_pk) {
        return Ok(AnchorVerifyResult {
            item_id: item_id.to_string(),
            verified: false,
            data_payload: None,
            owner_did: None,
            error: Some(format!("ANS-104 signature verification failed: {e}")),
            outcome: ProbeOutcome::Indeterminate,
        });
    }

    // Artifact-identity check: derive the protocol id from the
    // item and require equality with the requested `item_id`. A
    // node key signs many data items, so a valid signature only
    // proves who signed the response — not that the served item
    // is the one the caller asked to verify. A stale or malicious
    // mirror serving a different valid same-owner item for
    // `<requested-id>` would otherwise attest that substitute
    // payload as verified.
    let derived_id = match item.id() {
        Ok(id) => id,
        Err(e) => {
            return Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: false,
                data_payload: None,
                owner_did: None,
                error: Some(format!("deriving ANS-104 data item id: {e}")),
                outcome: ProbeOutcome::Indeterminate,
            });
        }
    };
    if derived_id != item_id {
        return Ok(AnchorVerifyResult {
            item_id: item_id.to_string(),
            verified: false,
            data_payload: None,
            owner_did: None,
            error: Some(format!(
                "ANS-104 artifact id mismatch: the gateway served an item \
                 signed by the expected owner but its derived id is {derived_id:?}, \
                 not the requested {item_id:?}; refusing to attest a different item"
            )),
            outcome: ProbeOutcome::Indeterminate,
        });
    }

    // Decode the data payload and return it.
    let data_bytes = match item.data_bytes() {
        Ok(b) => b,
        Err(e) => {
            return Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: false,
                data_payload: None,
                owner_did: None,
                error: Some(format!("decoding ANS-104 data payload: {e}")),
                outcome: ProbeOutcome::Indeterminate,
            });
        }
    };
    let data_payload: serde_json::Value = match serde_json::from_slice(&data_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: false,
                data_payload: None,
                owner_did: None,
                error: Some(format!("decoding data payload as JSON: {e}")),
                outcome: ProbeOutcome::Indeterminate,
            });
        }
    };

    // Derive the owner DID from the public key for the API
    // response. (v2 stores the public key; the persisted
    // `node_did` is a string, but the verify path can reconstruct
    // it from the key.)
    let owner_did = {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(expected_owner_pk)
            .map_err(|e| anyhow!("decoding verifying key: {e}"))?;
        gitlawb_core::did::Did::from_verifying_key(&vk).to_string()
    };

    // Compare the persisted row's `node_did` with the one
    // derived from the verified public key. A mismatch means
    // someone re-keyed and the row is stale; refuse.
    if owner_did != persisted.node_did {
        return Ok(AnchorVerifyResult {
            item_id: item_id.to_string(),
            verified: false,
            data_payload: Some(data_payload),
            owner_did: Some(owner_did.clone()),
            error: Some(format!(
                "persisted node_did {persisted_node_did:?} does not match the \
                 verified item's signer {owner_did:?}",
                persisted_node_did = persisted.node_did,
            )),
            outcome: ProbeOutcome::Indeterminate,
        });
    }

    let _ = persisted; // suppress unused-warning when no other field is read below
    Ok(AnchorVerifyResult {
        item_id: item_id.to_string(),
        verified: true,
        data_payload: Some(data_payload),
        owner_did: Some(owner_did),
        error: None,
        outcome: ProbeOutcome::Present,
    })
}

/// v1 verify path. The v1 raw-JSON shape (used by the live path on
/// this branch) has no signature; the integrity guarantee is the
/// Irys storage plus a field-equality check against the persisted
/// row. A v1 item with all five fields matching the persisted row
/// is `Present`; a missing schema or any field mismatch is
/// `Indeterminate`.
fn verify_v1(
    v: serde_json::Value,
    item_id: &str,
    persisted: &PersistedAnchorFields<'_>,
) -> Result<AnchorVerifyResult> {
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            return Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: false,
                data_payload: None,
                owner_did: None,
                error: Some(
                    "v1 verify failed: gateway response is a JSON value, not an object".to_string(),
                ),
                outcome: ProbeOutcome::Indeterminate,
            });
        }
    };

    // Schema check first: only `gitlawb/ref-update/v1` is a known v1
    // payload. Other JSON shapes (e.g. the v2 DataItem projection
    // parsed as a generic object, or an unrelated body) are
    // `Indeterminate` — we don't recognize them, not "definitively
    // absent".
    let schema = obj.get("schema").and_then(|s| s.as_str());
    if schema != Some("gitlawb/ref-update/v1") {
        return Ok(AnchorVerifyResult {
            item_id: item_id.to_string(),
            verified: false,
            data_payload: None,
            owner_did: None,
            error: Some(format!(
                "v1 verify failed: gateway response is JSON but does not \
                 carry schema=gitlawb/ref-update/v1 (got {schema:?})"
            )),
            outcome: ProbeOutcome::Indeterminate,
        });
    }

    // Field-equality check: each persisted field must match the
    // gateway's payload. A mismatch is `Indeterminate` because the
    // gateway served something that was NOT the anchor the node
    // recorded.
    let checks: &[(&str, &str)] = &[
        ("repo", persisted.repo),
        ("ref_name", persisted.ref_name),
        ("old_sha", persisted.old_sha),
        ("new_sha", persisted.new_sha),
        ("node_did", persisted.node_did),
    ];
    for (key, expected) in checks {
        let actual = obj.get(*key).and_then(|s| s.as_str());
        if actual != Some(*expected) {
            return Ok(AnchorVerifyResult {
                item_id: item_id.to_string(),
                verified: false,
                data_payload: None,
                owner_did: None,
                error: Some(format!(
                    "v1 verify failed: gateway field {key:?} does not match the \
                     persisted row (expected {expected:?}, got {actual:?})"
                )),
                outcome: ProbeOutcome::Indeterminate,
            });
        }
    }

    Ok(AnchorVerifyResult {
        item_id: item_id.to_string(),
        verified: true,
        // The v1 payload IS the data payload the caller wants;
        // surface the parsed JSON so the handler can echo it.
        data_payload: Some(v),
        owner_did: Some(persisted.node_did.to_string()),
        error: None,
        outcome: ProbeOutcome::Present,
    })
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

    /// A bodyless 404 from a proxy or misconfigured gateway is
    /// `Indeterminate`, NOT `DefinitivelyAbsent`. The team memory
    /// `distinguish-unknown-from-empty.md` is the policy: an empty
    /// body does not prove the item was never served, and a paid
    /// re-upload is irreversible.
    #[tokio::test]
    async fn probe_404_with_empty_body_is_indeterminate() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .with_body("")
            .create_async()
            .await;

        let outcome = probe_anchor_item(&reqwest::Client::new(), &req_for(server.url())).await;
        assert_eq!(
            outcome,
            ProbeOutcome::Indeterminate,
            "a bodyless 404 is not a proof of absence; the recovery policy must not authorize re-upload on it"
        );
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
        let persisted = PersistedAnchorFields {
            repo: "alice/r",
            ref_name: "refs/heads/main",
            old_sha: "0000",
            new_sha: "1111",
            node_did: "did:key:z6node",
        };
        let r = verify_anchor(
            &reqwest::Client::new(),
            "abc",
            &pk,
            &persisted,
            &server.url(),
        )
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
        let persisted = PersistedAnchorFields {
            repo: "alice/r",
            ref_name: "refs/heads/main",
            old_sha: "0000",
            new_sha: "1111",
            node_did: "did:key:z6node",
        };
        let r = verify_anchor(
            &reqwest::Client::new(),
            "abc",
            &pk,
            &persisted,
            &server.url(),
        )
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
        // The artifact-identity check requires the URL `item_id` to
        // match the protocol id derived from the item. The id is
        // `base64url(SHA256(signature))`; compute it for the URL.
        let item_id = item.id().unwrap();
        let body = serde_json::to_string(&item).unwrap();

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let persisted = PersistedAnchorFields {
            repo: "alice/r",
            ref_name: "refs/heads/main",
            old_sha: "0000",
            new_sha: "1111",
            // The persisted `node_did` must match the DID derived
            // from the verified public key, so build it from the
            // keypair.
            node_did: &gitlawb_core::did::Did::from_verifying_key(&kp.verifying_key()).to_string(),
        };
        let r = verify_anchor(
            &reqwest::Client::new(),
            &item_id,
            &pk,
            &persisted,
            &server.url(),
        )
        .await
        .unwrap();
        assert!(r.verified);
        assert!(r.data_payload.is_some());
        let payload = r.data_payload.unwrap();
        assert_eq!(payload["repo"], "alice/r");
        assert_eq!(payload["new"], "1111");
    }

    /// A valid signed item whose derived id does NOT match the URL
    /// `item_id` is `Indeterminate` — NOT verified, NOT
    /// `DefinitivelyAbsent`. The team memory
    /// `verify-against-artifact-id-not-signer.md` is the policy: a
    /// node key signs many data items, so a valid signature is
    /// necessary but not sufficient. A stale or malicious mirror
    /// serving a different valid same-owner item for `<requested-id>`
    /// would otherwise attest that substitute payload as verified.
    #[tokio::test]
    async fn verify_anchor_id_mismatch_is_indeterminate() {
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

        // Deliberately request an item_id that does NOT match the
        // derived protocol id. The signature is valid (the item was
        // signed by the expected owner) but the artifact identity
        // does not match.
        let persisted = PersistedAnchorFields {
            repo: "alice/r",
            ref_name: "refs/heads/main",
            old_sha: "0000",
            new_sha: "1111",
            node_did: &gitlawb_core::did::Did::from_verifying_key(&kp.verifying_key()).to_string(),
        };
        let r = verify_anchor(
            &reqwest::Client::new(),
            "this-is-not-the-items-actual-id",
            &pk,
            &persisted,
            &server.url(),
        )
        .await
        .unwrap();
        assert!(!r.verified);
        assert_eq!(r.outcome, ProbeOutcome::Indeterminate);
        assert!(r.data_payload.is_none(), "no payload on Indeterminate");
        let err = r.error.unwrap();
        assert!(
            err.contains("artifact id mismatch"),
            "expected artifact-identity error, got: {err}"
        );
    }

    /// v1 raw-JSON anchor: when the gateway returns the v1 shape
    /// with all five persisted fields matching, the verify is
    /// `Present` and the parsed JSON is the data payload. The
    /// v1 path has no signature — the Irys storage plus the
    /// field-equality check are the integrity guarantee.
    #[tokio::test]
    async fn verify_anchor_v1_recognized_with_matching_fields() {
        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let node_did = gitlawb_core::did::Did::from_verifying_key(&kp.verifying_key()).to_string();
        let v1_body = serde_json::json!({
            "schema": "gitlawb/ref-update/v1",
            "repo": "alice/r",
            "owner_did": node_did,
            "ref_name": "refs/heads/main",
            "old_sha": "0000",
            "new_sha": "1111",
            "cid": "cid-abc",
            "timestamp": "2026-08-30T00:00:00Z",
            "node_did": node_did,
            "network": "alpha",
        });

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_string(&v1_body).unwrap())
            .create_async()
            .await;

        let persisted = PersistedAnchorFields {
            repo: "alice/r",
            ref_name: "refs/heads/main",
            old_sha: "0000",
            new_sha: "1111",
            node_did: &node_did,
        };
        let r = verify_anchor(
            &reqwest::Client::new(),
            "v1-item-id",
            &pk,
            &persisted,
            &server.url(),
        )
        .await
        .unwrap();
        assert!(r.verified, "v1 with matching fields is Present");
        assert_eq!(r.outcome, ProbeOutcome::Present);
        let payload = r.data_payload.unwrap();
        assert_eq!(payload["schema"], "gitlawb/ref-update/v1");
        assert_eq!(payload["repo"], "alice/r");
    }

    /// A v1 payload with a single field mismatch is `Indeterminate`,
    /// not `Present`. The integrity guarantee is the
    /// field-equality check; any mismatch means the gateway served
    /// something that is NOT the anchor the node recorded.
    #[tokio::test]
    async fn verify_anchor_v1_field_mismatch_is_indeterminate() {
        let node_did = "did:key:z6node".to_string();
        let v1_body = serde_json::json!({
            "schema": "gitlawb/ref-update/v1",
            "repo": "ATTACKER/r",  // MISMATCH with persisted
            "owner_did": node_did,
            "ref_name": "refs/heads/main",
            "old_sha": "0000",
            "new_sha": "1111",
            "node_did": node_did,
        });

        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body(serde_json::to_string(&v1_body).unwrap())
            .create_async()
            .await;

        let kp = Keypair::generate();
        let pk = kp.verifying_key().to_bytes();
        let persisted = PersistedAnchorFields {
            repo: "alice/r", // does NOT match v1_body
            ref_name: "refs/heads/main",
            old_sha: "0000",
            new_sha: "1111",
            node_did: &node_did,
        };
        let r = verify_anchor(
            &reqwest::Client::new(),
            "v1-item-id",
            &pk,
            &persisted,
            &server.url(),
        )
        .await
        .unwrap();
        assert!(!r.verified);
        assert_eq!(r.outcome, ProbeOutcome::Indeterminate);
        let err = r.error.unwrap();
        assert!(
            err.contains("repo") && err.contains("does not match"),
            "expected field-equality error mentioning 'repo', got: {err}"
        );
    }
}
